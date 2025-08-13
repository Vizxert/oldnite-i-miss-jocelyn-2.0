import os
import sys
import ctypes
import subprocess
import threading
import time
from flask import Flask, request, jsonify
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog, QMessageBox
from PyQt6.QtCore import Qt
import ssl
import socket
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timezone, timedelta
import asyncio
import websockets
import base64
import json
import ipaddress
# Cache for the calendar timeline endpoint to avoid excessive rebuilds
timeline_cache = None
# Add throttle globals to prevent timeline spamming
LAST_TIMELINE_HIT = None
LONG_POLL_DELAY_SECONDS = 5

SETUP_LOG = "fortnite_launcher_setup.log"

def log(msg: str):
    try:
        with open(SETUP_LOG, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now(timezone.utc).isoformat()} - {msg}\n")
    except Exception:
        pass

# --- Auto-elevate to Administrator ---
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    params = ' '.join([f'"{arg}"' for arg in sys.argv])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    sys.exit(0)

# --- Certificate Files and Generation ---
CERT_PATH = "cert.pem"  # Will contain server cert followed by CA cert (full chain)
KEY_PATH = "key.pem"    # Server private key
CA_CERT_PATH = "ca.pem" # CA certificate used to sign server cert and installed to Root store
EPIC_HOSTS = [
    "localhost",
    "127.0.0.1",
    "account-public-service-prod03.ol.epicgames.com",
    "fortnite-public-service-prod11.ol.epicgames.com",
    "lightswitch-public-service-prod06.ol.epicgames.com"
]

def _get_local_ip_strings() -> list[str]:
    try:
        hostname = socket.gethostname()
        _, _, ips = socket.gethostbyname_ex(hostname)
        # Always include primary interface if available
        if hasattr(socket, 'gethostbyname'):
            try:
                ips.append(socket.gethostbyname(hostname))
            except Exception:
                pass
        # Deduplicate while preserving order
        deduped = []
        for ip in ips:
            if ip and ip not in deduped:
                deduped.append(ip)
        return deduped
    except Exception:
        return []

def generate_ca_and_server_cert():
    try:
        # Generate CA key and certificate
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OGFortnite Local CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "OGFortnite Local CA"),
        ])
        now = datetime.now(timezone.utc)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_subject)
            .issuer_name(ca_subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ), critical=True)
            .sign(ca_key, hashes.SHA256())
        )

        # Generate server key and certificate signed by CA
        server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        server_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OGFortnite"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])

        # Build SANs with both DNS and IP entries
        san_entries = []
        host_candidates = list(EPIC_HOSTS) + _get_local_ip_strings()
        for host in host_candidates:
            try:
                ip_obj = ipaddress.ip_address(host)
                san_entries.append(x509.IPAddress(ip_obj))
            except ValueError:
                san_entries.append(x509.DNSName(host))
        san = x509.SubjectAlternativeName(san_entries)

        server_cert = (
            x509.CertificateBuilder()
            .subject_name(server_subject)
            .issuer_name(ca_subject)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=825))
            .add_extension(san, critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )

        # Write files: server key, server cert (with CA appended), and CA cert
        with open(KEY_PATH, "wb") as f:
            f.write(
                server_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(CERT_PATH, "wb") as f:
            f.write(server_cert.public_bytes(serialization.Encoding.PEM))
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        with open(CA_CERT_PATH, "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

        log("Generated CA and server certificate via cryptography.")
        return True
    except Exception as e:
        log(f"Python cert generation failed: {e}")
        return False

def _cert_has_required_sans(cert_path: str) -> bool:
    try:
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data)
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = san_ext.value
        have_localhost = any(getattr(n, 'value', None) == 'localhost' for n in names)
        have_loopback_ip = any(getattr(n, 'value', None) == ipaddress.ip_address('127.0.0.1') for n in names if hasattr(n, 'value'))
        return bool(have_localhost and have_loopback_ip)
    except Exception:
        return False

if not os.path.exists(CERT_PATH) or not os.path.exists(KEY_PATH) or not _cert_has_required_sans(CERT_PATH):
    if not generate_ca_and_server_cert():
        print(
            "Certificate generation failed. Please install 'cryptography' (pip install cryptography) and rerun.",
            file=sys.stderr
        )
        sys.exit(1)

# Ensure certificates exist and are valid before loading
def ensure_certificates():
    try:
        if (not os.path.exists(CERT_PATH)) or (not os.path.exists(KEY_PATH)) or (not os.path.exists(CA_CERT_PATH)) or (not _cert_has_required_sans(CERT_PATH)):
            generate_ca_and_server_cert()
    except Exception as e:
        log(f"ensure_certificates error: {e}")

# Test certificate loading for SSL
try:
    ensure_certificates()
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(CERT_PATH, KEY_PATH)
    # Do not require client certificates
    ssl_context.verify_mode = ssl.CERT_NONE
    log("Certificate loaded successfully for SSL.")
except Exception as e:
    print(f"Failed to load SSL certificate: {e}", file=sys.stderr)
    sys.exit(1)

# --- Hosts File Editing ---
REQUIRED_HOSTS = [
    "127.0.0.1 account-public-service-prod03.ol.epicgames.com",
    "127.0.0.1 fortnite-public-service-prod11.ol.epicgames.com",
    "127.0.0.1 lightswitch-public-service-prod06.ol.epicgames.com"
]
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"

def update_hosts_file():
    try:
        with open(HOSTS_PATH, 'r', encoding='utf-8') as f:
            lines = f.read().splitlines()
    except Exception:
        lines = []
    changed = False
    for entry in REQUIRED_HOSTS:
        if not any(entry.split()[1] in line for line in lines):
            lines.append(entry)
            changed = True
    if changed:
        try:
            with open(HOSTS_PATH, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines) + '\n')
            return True
        except Exception as e:
            log(f"Hosts update failed: {e}")
            return False
    return True

# --- Install Certificate as Trusted Root CA ---
def install_cert_to_trusted_root():
    try:
        # Install CA cert into Trusted Root Certification Authorities
        ok, out = run_cmd(f'certutil -addstore -f "Root" {CA_CERT_PATH}')
        if ok:
            log("CA certificate installed as trusted root.")
        return ok
    except Exception as e:
        log(f"certutil addstore failed: {e}")
        return False

def run_cmd(cmd: str) -> tuple[bool, str]:
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        out = (p.stdout or "") + (p.stderr or "")
        log(f"$ {cmd}\n{out}")
        return p.returncode == 0, out
    except Exception as e:
        log(f"CMD FAIL {cmd}: {e}")
        return False, str(e)

# --- Flask Emulator Server ---
app = Flask(__name__)

# OAuth Token Response
def oauth_token_response():
    return {
        "access_token": "FAKE_ACCESS_TOKEN",
        "expires_in": 28800,
        "expires_at": "2099-12-31T23:59:59.999Z",
        "token_type": "bearer",
        "refresh_token": "FAKE_REFRESH_TOKEN",
        "refresh_expires": 28800,
        "refresh_expires_at": "2099-12-31T23:59:59.999Z",
        "account_id": "FAKE_ACCOUNT_ID",
        "client_id": "ec684b8c687f479fadea3cb2ad83f5c6",
        "internal_client": True,
        "client_service": "fortnite",
        "displayName": "OGPlayer",
        "app": "fortnite",
        "in_app_id": "FAKE_ACCOUNT_ID"
    }

@app.route('/account/api/oauth/token', methods=['POST'])
def oauth_token():
    return jsonify(oauth_token_response())

@app.route('/account', methods=['POST'])
def account_info_post_root():
    return jsonify(oauth_token_response())

@app.route('/fortnite/api/v2/versioncheck/Windows', methods=['GET'])
def version_check_v2():
    return jsonify({"type": "NO_UPDATE"})

@app.route('/fortnite/api/versioncheck', methods=['GET'])
def version_check_legacy():
    return jsonify({"type": "NO_UPDATE"})

@app.route('/fortnite/api/calendar/v1/timeline', methods=['GET'])
def calendar_timeline():
    global timeline_cache
    # Throttle on frequent timeline polling
    global LAST_TIMELINE_HIT
    now_ts = time.time()
    if LAST_TIMELINE_HIT and now_ts - LAST_TIMELINE_HIT < LONG_POLL_DELAY_SECONDS:
        time.sleep(LONG_POLL_DELAY_SECONDS - (now_ts - LAST_TIMELINE_HIT))
    LAST_TIMELINE_HIT = time.time()
    if timeline_cache is not None:
        return jsonify(timeline_cache)
    current_time = datetime.now(timezone.utc)
    season_begin = "2017-01-01T00:00:00.000Z"
    season_end = "2099-12-31T23:59:59.000Z"
    current_time_str = current_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    # Cache far in the future to stop client spam
    cache_expire_str = (current_time + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    response = {
        "channels": {
            "standalone-store": {"states": [{"validFrom": "2017-01-01T00:00:00.000Z", "activeEvents": [], "state": {}}]},
            "client-events": {
                "states": [{
                    "validFrom": "2017-01-01T00:00:00.000Z",
                    "activeEvents": [{"eventType": "Season3", "activeUntil": season_end, "activeSince": season_begin}],
                    "state": {
                        "activeStorefronts": ["BRDailyStorefront", "BRSeasonStorefront"],
                        "seasonNumber": 3,
                        "seasonTemplateId": "AthenaSeason:athenaseason3",
                        "seasonBegin": season_begin,
                        "seasonEnd": season_end,
                        "seasonDisplayedEnd": season_end,
                        "dailyStoreEnd": season_end,
                        "seasonStoreEnd": season_end,
                        "rmtPromotion": "Season3"
                    }
                }],
                "cacheExpire": cache_expire_str,
                # Add a delay for long polling to avoid client spamming
                "longPollDelaySeconds": 3600
            }
        },
        "eventsTimeOffsetHrs": 0,
        "cacheIntervalMins": 60,
        "currentTime": current_time_str
    }
    timeline_cache = response
    return jsonify(response)

@app.route('/account/api/oauth/sessions/kill', methods=['DELETE'])
def oauth_kill_query():
    return ('', 204)

@app.route('/account/api/oauth/sessions/kill/<string:token>', methods=['DELETE'])
def oauth_kill_token(token: str):
    return ('', 204)

@app.route('/account/api/public/account/<string:account_id>', methods=['GET'])
def public_account(account_id: str):
    return jsonify({
        "id": account_id,
        "displayName": "OGPlayer",
        "name": "OGPlayer",
        "email": "ogplayer@example.com",
        "tfaEnabled": False,
        "emailVerified": True,
        "minorStatus": "NOT_MINOR"
    })

@app.route('/account/api/public/account/<string:account_id>/externalAuths', methods=['GET'])
def public_account_external_auths(account_id: str):
    return jsonify([])

@app.route('/account/api/epicdomains/ssodomains', methods=['GET'])
def epic_ssodomains():
    return jsonify([])

@app.route('/fortnite/api/versioncheck?version=<path:version>', methods=['GET'])
def version_check_query(version):
    return jsonify({"type": "NO_UPDATE"})

@app.route('/fortnite/api/cloudstorage/system', methods=['GET'])
def cloud_storage_system():
    return jsonify({})

@app.route('/fortnite/api/game/v2/tryPlayOnPlatform/account/<string:account_id>', methods=['POST'])
def try_play_on_platform(account_id: str):
    return "true", 200

@app.route('/lightswitch/api/service/bulk/status', methods=['GET'])
def lightswitch_status():
    return jsonify([{
        "serviceInstanceId": "fortnite",
        "status": "UP",
        "message": "Fortnite is online",
        "maintenanceUri": None,
        "allowedActions": ["PLAY", "DOWNLOAD", "PURCHASE"],
        "banned": False
    }])

@app.route('/fortnite/api/matchmaking/session/findPlayer', methods=['POST'])
def find_player_session():
    return jsonify({
        "accountId": "FAKE_ACCOUNT_ID",
        "sessionId": "FAKE_SESSION_ID",
        "status": "FOUND"
    })

@app.route('/fortnite/api/matchmaking/session/<string:session_id>', methods=['GET'])
def get_session(session_id: str):
    return jsonify({
        "id": session_id,
        "ownerId": "FAKE_ACCOUNT_ID",
        "status": "IN_PROGRESS",
        "players": [{"accountId": "FAKE_ACCOUNT_ID", "platform": "Windows"}],
        "created": datetime.now(timezone.utc).isoformat() + "Z",
        "updated": datetime.now(timezone.utc).isoformat() + "Z"
    })

@app.route('/fortnite/api/game/v2/playlist/info', methods=['GET'])
def playlist_info():
    return jsonify({
        "playlists": [{
            "id": "Playlist_DefaultSolo",
            "name": "Solo",
            "description": "Default Solo Match",
            "maxPlayers": 100,
            "isDefault": True
        }]
    })

@app.route('/fortnite/api/game/v2/enabled_features', methods=['GET'])
def enabled_features():
    return jsonify([])

@app.route('/fortnite/api/game/v2/grant_access/<string:account_id>', methods=['POST'])
def grant_access(account_id: str):
    return jsonify({}), 200

# --- Globals ---
receipts_store = {}
# Toggle to auto-unlock Battle Pass (disabled so users can purchase it in-game)
AUTO_UNLOCK_BATTLE_PASS = False

# Helper to get or create receipts list for an account
def _get_receipts(account_id: str):
    return receipts_store.setdefault(account_id, [])

# Global profile state
profiles = {
    'common_public': {'revision': 1, 'command_revision': 1, 'mtx_balance': 999999, 'mtx_platform': 'EpicPC'},
    'common_core': {'revision': 1, 'command_revision': 1, 'mtx_balance': 999999, 'mtx_platform': 'EpicPC'},
    'athena': {
        'revision': 1,
        'command_revision': 1,
        # Start with no rare cosmetics owned to avoid shop items showing as Owned
        'owned_items': [],
        'battle_pass_level': 1,
        'battle_pass_purchased': False
    }
}

# Sample items for shop (templateIds from Fortnite 3.5 era)
shop_items = {
    'skin1': {'offerId': 'offer_skin1', 'devName': 'Renegade Raider', 'price': 1200, 'templateId': 'AthenaCharacter:cid_028_athena_commando_f'},
    'skin2': {'offerId': 'offer_skin2', 'devName': 'Aerial Assault Trooper', 'price': 1200, 'templateId': 'AthenaCharacter:cid_029_athena_commando_m'},
    'emote1': {'offerId': 'offer_emote1', 'devName': 'Dance Moves', 'price': 500, 'templateId': 'AthenaDance:eid_dancemoves'},
    'battle_pass_001': {'offerId': 'battle_pass_001', 'devName': 'Season 3 Battle Pass', 'price': 950, 'templateId': 'AthenaSeason:athenaseason3'}
}

# If enabled, also set BP ownership at startup so all responses are consistent
if 'athena' in profiles:
    try:
        if 'AUTO_UNLOCK_BATTLE_PASS' in globals() and AUTO_UNLOCK_BATTLE_PASS:
            if not profiles['athena'].get('battle_pass_purchased'):
                profiles['athena']['battle_pass_purchased'] = True
                profiles['athena']['battle_pass_level'] = max(1, profiles['athena'].get('battle_pass_level', 1))
            if 'stats' not in profiles['athena']:
                profiles['athena']['stats'] = {}
            profiles['athena']['stats']['book_purchased'] = True
            profiles['athena']['stats']['book_level'] = profiles['athena']['battle_pass_level']
    except Exception:
        pass

@app.route('/fortnite/api/game/v2/profile/<string:account_id>/client/QueryProfile', methods=['POST'])
def query_profile(account_id: str):
    profile_id = request.args.get('profileId', 'common_public')
    requested_rvn = int(request.args.get('rvn', -1))

    if profile_id not in profiles:
        if profile_id == 'athena':
            profiles[profile_id] = {
                'revision': 1, 
                'command_revision': 1, 
                'owned_items': [], 
                'battle_pass_purchased': False, 
                'battle_pass_level': 1, 
                'season': 3,
                'loadouts': [{"loadoutId": "default", "character": "default_character", "backpack": "", "pickaxe": "", "glider": "", "dance": ["eid_dancemoves"], "itemwrap": []}],
                'stats': {
                    "loadouts": [{"loadoutId": "default", "character": "default_character", "backpack": "", "pickaxe": "", "glider": "", "dance": ["eid_dancemoves"], "itemwrap": []}],
                    "use_count": 0,
                    "banner_icon": "defaultbanner",
                    "banner_color": "defaultcolor",
                    "level": 1,
                    "book_level": 1,
                    "book_purchased": False,
                    "lifetime_wins": 0,
                    "favorite_character": "default_character",
                    "favorite_backpack": "",
                    "favorite_pickaxe": "",
                    "favorite_glider": "",
                    "favorite_skydivecontrail": "",
                    "favorite_musicpack": "",
                    "favorite_loadingscreen": "",
                    "favorite_dance": ["eid_dancemoves", "", "", "", "", ""],
                    "favorite_itemwraps": ["", "", "", "", "", "", ""],
                    "season_num": 3,
                    "season": {"numWins": 0, "numHighBracket": 0, "numLowBracket": 0},
                    "xp": 0
                }
            }
        else:
            profiles[profile_id] = {'revision': 1, 'command_revision': 1}

    current = profiles[profile_id]
    is_full = requested_rvn == -2
    base_rvn = 0 if is_full else (requested_rvn if requested_rvn >= 0 else current['revision'] - 1)

    changes = []
    if is_full or base_rvn < current['revision']:
        if profile_id == 'common_core':
            if is_full:
                changes = [{
                    "changeType": "fullProfileUpdate",
                    "profile": {
                        "accountId": account_id,
                        "items": {},
                        "stats": {
                            "current_mtx_balance": current.get('mtx_balance', 1000),
                            "mtx_platform": current.get('mtx_platform', 'EpicPC')
                        }
                    }
                }]
            else:
                changes = [
                    {"changeType": "statModified", "name": "current_mtx_balance", "value": current.get('mtx_balance', 1000)},
                    {"changeType": "statModified", "name": "mtx_platform", "value": current.get('mtx_platform', 'EpicPC')}
                ]
        elif profile_id == 'common_public':
            if is_full:
                changes = [{
                    "changeType": "fullProfileUpdate",
                    "profile": {
                        "accountId": account_id,
                        "items": {},
                        "stats": {
                            "current_mtx_balance": current.get('mtx_balance', 1000),
                            "mtx_platform": current.get('mtx_platform', 'EpicPC')
                        }
                    }
                }]
            else:
                changes = [
                    {"changeType": "statModified", "name": "current_mtx_balance", "value": current.get('mtx_balance', 1000)},
                    {"changeType": "statModified", "name": "mtx_platform", "value": current.get('mtx_platform', 'EpicPC')}
                ]
        elif profile_id == 'athena':
            # Optionally auto-unlock battle pass to avoid disabled purchase UI
            if AUTO_UNLOCK_BATTLE_PASS and not current.get('battle_pass_purchased'):
                current['battle_pass_purchased'] = True
                current['battle_pass_level'] = max(1, current.get('battle_pass_level', 1))
                if 'stats' not in current:
                    current['stats'] = {}
                current['stats']['book_purchased'] = True
                current['stats']['book_level'] = current['battle_pass_level']
            if 'stats' not in current:
                current['stats'] = {
                    "loadouts": current.get('loadouts', [{"loadoutId": "default", "character": "default_character", "backpack": "", "pickaxe": "", "glider": "", "dance": ["eid_dancemoves"], "itemwrap": []}]),
                    "use_count": 0,
                    "banner_icon": "defaultbanner",
                    "banner_color": "defaultcolor",
                    "level": current.get('battle_pass_level', 1),
                    "book_level": current.get('battle_pass_level', 1),
                    "book_purchased": current.get('battle_pass_purchased', False),
                    "lifetime_wins": 0,
                    "favorite_character": "default_character",
                    "favorite_backpack": "",
                    "favorite_pickaxe": "",
                    "favorite_glider": "",
                    "favorite_skydivecontrail": "",
                    "favorite_musicpack": "",
                    "favorite_loadingscreen": "",
                    "favorite_dance": ["eid_dancemoves", "", "", "", "", ""],
                    "favorite_itemwraps": ["", "", "", "", "", "", ""],
                    "season_num": current.get('season', 3),
                    "season": {"numWins": 0, "numHighBracket": 0, "numLowBracket": 0},
                    "xp": 0
                }
            profile_data = {
                "accountId": account_id,
                "items": {
                    **{item: {"templateId": item, "attributes": {"level": 1, "variants": []}, "quantity": 1} for item in current.get('owned_items', [])},
                    "default_character": {"templateId": "AthenaCharacter:cid_001_athena_commando_f_default", "attributes": {"gender": 2, "level": 1, "variants": []}, "quantity": 1}
                },
                "stats": current['stats']
            }
            # Only add the season item if the battle pass has been purchased
            if current.get('battle_pass_purchased'):
                profile_data["items"]["athena_season3"] = {
                    "templateId": "AthenaSeason:athenaseason3",
                    "attributes": {
                        "season_level": current.get('battle_pass_level', 1),
                        "book_purchased": True,
                        "book_level": current.get('battle_pass_level', 1)
                    },
                    "quantity": 1
                }
            profile_data["stats"]["book_purchased"] = current.get('stats', {}).get('book_purchased', current.get('battle_pass_purchased', False))
            profile_data["stats"]["book_level"] = current.get('stats', {}).get('book_level', current.get('battle_pass_level', 1))
            if is_full:
                changes = [{"changeType": "fullProfileUpdate", "profile": profile_data}]
            else:
                changes = [{"changeType": "statModified", "name": k, "value": v} for k, v in profile_data["stats"].items()]

    return jsonify({
        "profileRevision": current['revision'],
        "profileId": profile_id,
        "profileChangesBaseRevision": base_rvn,
        "profileChanges": changes,
        "profileCommandRevision": current['command_revision'],
        "multiUpdate": [],
        "responseVersion": 1
    })

@app.route('/fortnite/api/game/v2/profile/<string:account_id>/client/SetMtxPlatform', methods=['POST'])
def set_mtx_platform(account_id: str):
    profile_id = request.args.get('profileId', 'common_core')
    requested_rvn = int(request.args.get('rvn', -1))

    if profile_id not in profiles:
        profiles[profile_id] = {'revision': 1, 'command_revision': 1, 'mtx_platform': 'EpicPC'}

    current = profiles[profile_id]
    base_rvn = requested_rvn if requested_rvn >= 0 else current['revision']

    if requested_rvn >= 0 and requested_rvn != base_rvn:
        return jsonify({"errorCode": "errors.com.epicgames.common.mismatched_revision", "errorMessage": "Revision mismatch."}), 400

    # Simulate setting platform (from request body perhaps, but for simplicity)
    platform = request.json.get('newPlatform', 'EpicPC')
    current['mtx_platform'] = platform
    current['revision'] += 1
    current['command_revision'] += 1

    changes = [{"changeType": "statModified", "name": "mtx_platform", "value": platform}]

    return jsonify({
        "profileRevision": current['revision'],
        "profileId": profile_id,
        "profileChangesBaseRevision": base_rvn,
        "profileChanges": changes,
        "profileCommandRevision": current['command_revision'],
        "serverTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
        "responseVersion": 1
    })

# --- Purchase Endpoint ---

@app.route('/fortnite/api/game/v2/profile/<string:account_id>/client/PurchaseCatalogEntry', methods=['POST'])
def purchase_catalog_entry(account_id: str):
	profile_id = request.args.get('profileId', 'common_core')
	requested_rvn = int(request.args.get('rvn', -1))
	data = request.json or {}

	# Accept either a single offer or an array of offers
	offers = []
	if 'purchaseOffers' in data and isinstance(data['purchaseOffers'], list):
		offers = data['purchaseOffers']
	else:
		# Map common 3.5 payload keys to our internal representation
		if 'offerId' in data:
			offers = [{
				"offerId": data.get('offerId'),
				"quantity": data.get('purchaseQuantity') or data.get('quantity', 1),
				"expectedTotalPrice": data.get('expectedTotalPrice'),
				"currency": data.get('currency', 'MtxCurrency'),
				"currencySubType": data.get('currencySubType', 'VBucks')
			}]

	if not offers:
		return jsonify({'error': 'No offers specified'}), 400

	# Validate profile
	if profile_id != 'common_core':
		return jsonify({'error': 'Invalid profile'}), 400

	core_prof = profiles['common_core']
	base_rvn = requested_rvn if requested_rvn >= 0 else core_prof['revision']
	if requested_rvn >= 0 and requested_rvn != base_rvn:
		return jsonify({'errorCode': 'errors.com.epicgames.common.mismatched_revision'}), 400

	# Process all offers
	total_cost = 0
	granted_templates = []
	for off in offers:
		offer_id = off.get('offerId')
		quantity = int(off.get('quantity', 1))
		shop_entry = next((item for item in shop_items.values() if item['offerId'] == offer_id), None)
		if not shop_entry:
			return jsonify({'error': f'Offer not found: {offer_id}'}), 404
		price = shop_entry['price'] * quantity
		total_cost += price
		granted_templates.append(shop_entry['templateId'])

	if core_prof['mtx_balance'] < total_cost:
		return jsonify({'errorCode': 'errors.com.epicgames.payment.insufficient_funds'}), 400

	# Deduct VBucks
	core_prof['mtx_balance'] -= total_cost
	core_prof['revision'] += 1
	core_prof['command_revision'] += 1

	core_changes = [{"changeType": "statModified", "name": "current_mtx_balance", "value": core_prof['mtx_balance']}]

	# Grant items into athena profile
	athena_prof = profiles['athena']
	athena_changes = []
	for template_id in granted_templates:
		if template_id not in athena_prof['owned_items']:
			athena_prof['owned_items'].append(template_id)
			athena_changes.append({"changeType": "itemAdded", "itemId": template_id, "item": {"templateId": template_id, "attributes": {"level": 1}, "quantity": 1}})
		if template_id.startswith('AthenaSeason:'):
			athena_prof['battle_pass_purchased'] = True
			athena_changes.append({"changeType": "statModified", "name": "book_purchased", "value": True})
			athena_prof['battle_pass_level'] = athena_prof.get('battle_pass_level', 1)
			athena_changes.append({"changeType": "statModified", "name": "book_level", "value": athena_prof['battle_pass_level']})
	if athena_changes:
		athena_prof['revision'] += 1
		athena_prof['command_revision'] += 1

	# Create receipts
	for off in offers:
		receipt = {
			'receiptId': f"r_{len(_get_receipts(account_id)) + 1}",
			'offerId': off.get('offerId'),
			'price': next((i['price'] for i in shop_items.values() if i['offerId'] == off.get('offerId')), 0) * int(off.get('quantity', 1)),
			'quantity': int(off.get('quantity', 1))
		}
		_get_receipts(account_id).append(receipt)

	return jsonify({
		"profileRevision": core_prof['revision'],
		"profileId": profile_id,
		"profileChangesBaseRevision": base_rvn,
		"profileChanges": core_changes,
		"profileCommandRevision": core_prof['command_revision'],
		"multiUpdate": (
			[{
				"profileRevision": profiles['athena']['revision'],
				"profileId": "athena",
				"profileChangesBaseRevision": profiles['athena']['revision'] - 1 if athena_changes else profiles['athena']['revision'],
				"profileChanges": athena_changes,
				"profileCommandRevision": profiles['athena']['command_revision']
			}] if athena_changes else []
		),
		"serverTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
		"responseVersion": 1
	})

# Update receipts endpoint
@app.route('/fortnite/api/receipts/v1/account/<string:account_id>/receipts', methods=['GET'])
def receipts(account_id: str):
    return jsonify(_get_receipts(account_id))

@app.route('/fortnite/api/cloudstorage/user/<string:account_id>', methods=['GET'])
def cloudstorage_user(account_id: str):
    return jsonify([])

@app.route('/fortnite/api/storefront/v2/catalog', methods=['GET'])
def storefront_catalog():
    rvn = int(request.args.get('rvn', 2))
    daily_entries = []
    for item in shop_items.values():
        daily_entries.append({
            "offerId": item['offerId'],
            "devName": item['devName'],
            "offerType": "StaticPrice",
            "prices": [{"currencyType": "MtxCurrency", "currencySubType": "VBucks", "regularPrice": item['price'], "finalPrice": item['price']}],
            "categories": ["Outfit" if 'Character' in item['templateId'] else "Emote"],
            "dailyLimit": -1,
            "weeklyLimit": -1,
            "monthlyLimit": -1,
            "refundable": True,
            "giftable": True,
            "itemGrants": [{"templateId": item['templateId'], "quantity": 1}]
        })

    return jsonify({
        "refreshIntervalHrs": 24,
        "dailyPurchaseHrs": 24,
        "expiration": (datetime.now(timezone.utc) + timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
        "storefronts": [
            {"name": "BRDailyStorefront", "catalogEntries": daily_entries + [{
                "offerId": "battle_pass_001",
                "devName": "Season 3 Battle Pass",
                "offerType": "StaticPrice",
                "prices": [{"currencyType": "MtxCurrency", "currencySubType": "VBucks", "regularPrice": 950, "finalPrice": 950}],
                "categories": ["BattlePass"],
                "dailyLimit": -1,
                "weeklyLimit": -1,
                "monthlyLimit": -1,
                "refundable": False,
                "giftable": False,
                "itemGrants": [{"templateId": "AthenaSeason:athenaseason3", "quantity": 1}]
            }]},
            {
                "name": "BRSeasonStorefront",
                "catalogEntries": [
                    {
                        "offerId": "battle_pass_001",
                        "devName": "Season 3 Battle Pass",
                        "offerType": "StaticPrice",
                        "prices": [{"currencyType": "MtxCurrency", "currencySubType": "VBucks", "regularPrice": 950, "finalPrice": 950}],
                        "categories": ["BattlePass"],
                        "dailyLimit": -1,
                        "weeklyLimit": -1,
                        "monthlyLimit": -1,
                        "refundable": False,
                        "giftable": False,
                        "itemGrants": [{"templateId": "AthenaSeason:athenaseason3", "quantity": 1}]
                    }
                ]
            }
        ]
    })

@app.route('/fortnite/api/game/v2/profile/<string:account_id>/client/MarkItemSeen', methods=['POST'])
def mark_item_seen(account_id: str):
    profile_id = request.args.get('profileId', 'athena')
    requested_rvn = int(request.args.get('rvn', -1))
    data = request.json
    item_ids = data.get('itemIds', [])

    if profile_id not in profiles:
        return jsonify({"error": "Invalid profile"}), 400

    current = profiles[profile_id]
    base_rvn = requested_rvn if requested_rvn >= 0 else current['revision']

    if requested_rvn >= 0 and requested_rvn != base_rvn:
        return jsonify({"errorCode": "errors.com.epicgames.common.mismatched_revision"}), 400

    changes = []
    for item_id in item_ids:
        changes.append({"changeType": "itemAttrChanged", "itemId": item_id, "attributeName": "item_seen", "attributeValue": True})

    current['revision'] += 1
    current['command_revision'] += 1

    return jsonify({
        "profileRevision": current['revision'],
        "profileId": profile_id,
        "profileChangesBaseRevision": base_rvn,
        "profileChanges": changes,
        "profileCommandRevision": current['command_revision'],
        "serverTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
        "responseVersion": 1
    })

@app.route('/fortnite/api/game/v2/profile/<string:account_id>/client/EquipBattleRoyaleCustomization', methods=['POST'])
def equip_battle_royale_customization(account_id: str):
    profile_id = request.args.get('profileId', 'athena')
    requested_rvn = int(request.args.get('rvn', -1))
    data = request.json
    slot_name = data.get('slotName')
    item_to_slot = data.get('itemToSlot')

    if profile_id != 'athena':
        return jsonify({"error": "Invalid profile"}), 400

    current = profiles[profile_id]
    base_rvn = requested_rvn if requested_rvn >= 0 else current['revision']

    if requested_rvn >= 0 and requested_rvn != base_rvn:
        return jsonify({"errorCode": "errors.com.epicgames.common.mismatched_revision"}), 400

    if 'stats' not in current:
        current['stats'] = {}
    # Update favorite for the slot (simplified)
    if slot_name.lower() == 'character':
        current['stats']['favorite_character'] = item_to_slot
    # Add more slots as needed

    changes = [{"changeType": "statModified", "name": f"favorite_{slot_name.lower()}", "value": item_to_slot}]

    current['revision'] += 1
    current['command_revision'] += 1

    return jsonify({
        "profileRevision": current['revision'],
        "profileId": profile_id,
        "profileChangesBaseRevision": base_rvn,
        "profileChanges": changes,
        "profileCommandRevision": current['command_revision'],
        "serverTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
        "responseVersion": 1
    })

@app.route('/fortnite/api/game/v2/profile/<string:account_id>/client/SetHardcoreModifier', methods=['POST'])  # For BP leveling
def set_hardcore_modifier(account_id: str):
    profile_id = request.args.get('profileId', 'athena')
    requested_rvn = int(request.args.get('rvn', -1))

    if profile_id != 'athena':
        return jsonify({"error": "Invalid profile"}), 400

    current = profiles.get('athena', {'revision': 1, 'command_revision': 1, 'battle_pass_level': 1})
    base_rvn = requested_rvn if requested_rvn >= 0 else current['revision']

    if requested_rvn >= 0 and requested_rvn != base_rvn:
        return jsonify({"errorCode": "errors.com.epicgames.common.mismatched_revision"}), 400

    # Simulate leveling up (e.g., add XP or directly level)
    current['battle_pass_level'] += 1  # Simple increment for demo
    current['revision'] += 1
    current['command_revision'] += 1

    changes = [{"changeType": "statModified", "name": "season_level", "value": current['battle_pass_level']}]

    return jsonify({
        "profileRevision": current['revision'],
        "profileId": profile_id,
        "profileChangesBaseRevision": base_rvn,
        "profileChanges": changes,
        "profileCommandRevision": current['command_revision'],
        "serverTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
        "responseVersion": 1
    })

@app.route('/account/api/oauth/verify', methods=['GET'])
def oauth_verify():
    return jsonify({
        "access_token": "FAKE_ACCESS_TOKEN",
        "expires_in": 28800,
        "expires_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
        "token_type": "bearer",
        "account_id": "FAKE_ACCOUNT_ID",
        "client_id": "ec684b8c687f479fadea3cb2ad83f5c6",
        "displayName": "OGPlayer"
    })

@app.route('/fortnite/api/game/v2/profile/<string:account_id>/client/ClientQuestLogin', methods=['POST'])
def client_quest_login(account_id: str):
    profile_id = request.args.get('profileId', 'athena')
    rvn = int(request.args.get('rvn', 1))

    # Return stub daily challenges
    return jsonify({
        "profileRevision": 1,
        "profileId": profile_id,
        "profileChangesBaseRevision": 1,
        "profileChanges": [],
        "profileCommandRevision": 1,
        "quests": [
            {
                "questId": "daily_play_match",
                "questState": "Active",
                "stats": {"currentCount": 0, "completionCount": 0, "completionMax": 1},
                "displayName": "Play a Match",
                "description": "Complete one match",
                "reward": {"currencyType": "XP", "amount": 500}
            },
            {
                "questId": "daily_get_eliminations",
                "questState": "Active",
                "stats": {"currentCount": 0, "completionCount": 0, "completionMax": 5},
                "displayName": "Get Eliminations",
                "description": "Eliminate 5 opponents",
                "reward": {"currencyType": "XP", "amount": 1000}
            },
            {
                "questId": "daily_deal_damage",
                "questState": "Active",
                "stats": {"currentCount": 0, "completionCount": 0, "completionMax": 200},
                "displayName": "Deal Damage",
                "description": "Deal 200 damage",
                "reward": {"currencyType": "XP", "amount": 1000}
            }
        ],
        "serverTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
        "responseVersion": 1
    })

@app.route('/fortnite/api/game/v2/matchmakingservice/ticket/player/<string:account_id>', methods=['GET'])
def matchmaking_ticket(account_id: str):
    party_player_ids_str = request.args.get('partyPlayerIds', account_id)
    party_player_ids = party_player_ids_str.split(',')
    bucket_id = request.args.get('bucketId', '3991976:0:NAW:2')
    player_platform = request.args.get('player.platform', 'Windows')
    fill_team = request.args.get('player.option.fillTeam', 'false') == 'true'

    inner_payload = {
        "playerId": account_id,
        "partyPlayerIds": party_player_ids,
        "bucketId": bucket_id,
        "attributes": {},
        "playerPlatform": player_platform,
        "playerOption": {"fillTeam": fill_team},
        "public": True
    }

    payload_str = json.dumps(inner_payload)
    encoded_payload = base64.b64encode(payload_str.encode('utf-8')).decode('utf-8')

    # Fortnite 3.5 expects a list of acceptable subprotocols in the URL via Sec-WebSocket-Protocol
    # We suffix them so the server can accept any
    return jsonify({
        "serviceUrl": "ws://127.0.0.1:8080?protocols=v1.mmsp.eos,v1.mmsp,mmsp,matchmaking,com.epicgames.matchmaking,com.epicgames.mmsp,xmpp",
        "ticketType": "mms-player",
        "payload": encoded_payload,
        "signature": "fake_signature"
    })

async def matchmaking_handler(websocket):
    try:
        print("WebSocket connection established for matchmaking.")
        try:
            print("Requested subprotocols:", websocket.request_headers.get('Sec-WebSocket-Protocol'))
        except Exception:
            pass
        
        async def listen():
            try:
                async for message in websocket:
                    print(f"Received from client: {message}")
                    try:
                        msg = json.loads(message)
                        if msg.get('name') == 'Ping':
                            await websocket.send(json.dumps({"name": "Pong"}))
                    except:
                        if isinstance(message, bytes):
                            # Handle binary ping (e.g., b'ping')
                            await websocket.send(b'pong')
                        elif isinstance(message, str) and message.lower() == 'ping':
                            await websocket.send('pong')
            except Exception as e:
                print(f"WebSocket listen error: {e}")

        # Start listener
        asyncio.create_task(listen())

        # Send immediate connect acknowledgment
        await websocket.send(json.dumps({"name": "Connected", "payload": ""}))
        print("Sent connection acknowledgment")
        
        # Send matchmaking events immediately (no delays)
        await websocket.send(json.dumps({"name": "Matchmaking.Started", "payload": ""}))
        print("Sent Matchmaking.Started")
        await websocket.send(json.dumps({"name": "Matchmaking.Searching", "payload": ""}))
        print("Sent Matchmaking.Searching")
        await websocket.send(json.dumps({"name": "Matchmaking.Waiting", "payload": ""}))
        print("Sent Matchmaking.Waiting")
        
        # Send match found
        payload = {
            "matchId": "solo_match_001",
            "sessionId": "session_001",
            "serverAddress": "127.0.0.1",
            "serverPort": 7777,
            "region": "NAE",
            "gameMode": "solo",
            "allowJoinInProgress": False,
            "bucketId": "3991976:0:NAE:2",
            "ticketId": "fake_ticket",
            "partyId": "fake_party",
            "isDedicated": False
        }
        encoded_payload = base64.b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8')
        
        await websocket.send(json.dumps({"name": "Matchmaking.Success", "payload": encoded_payload}))
        print("Sent Matchmaking.Success")

        await asyncio.sleep(0.5)
        await websocket.send(json.dumps({"name": "Play", "payload": encoded_payload}))
        print("Sent Play command")
        
        # Keep open
        await asyncio.Future()
    except Exception as e:
        print(f"WebSocket error: {e}")

def start_websocket_server():
    async def run_server():
        try:
            # Start plain WS server (older clients expect ws:// not wss://)
            log("Starting WebSocket server without SSL...")
            # Accept any subprotocol the client proposes; Fortnite 3.5 expects specific ones
            async with websockets.serve(
                matchmaking_handler,
                "127.0.0.1",
                8080,
                select_subprotocol=lambda connection, subprotocols: (subprotocols[0] if subprotocols else None)
            ):
                log("WebSocket server started on ws://127.0.0.1:8080")
                await asyncio.Future()  # Run forever
        except Exception as e:
            log(f"WebSocket server failed to start: {e}")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(run_server())
    except Exception as e:
        log(f"WebSocket server thread failed: {e}")

def run_emulator():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERT_PATH, keyfile=KEY_PATH)
    context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:AES128-SHA:AES256-SHA')
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    app.run(host='0.0.0.0', port=443, ssl_context=context, threaded=True)


def grant_vbucks_and_season():
    """Utility to programmatically add a large VBucks balance and grant Season 1-3 templates.
    Returns a simple dict with how many VBucks and how many templates were newly granted."""
    core = profiles.setdefault('common_core', {'revision': 1, 'command_revision': 1, 'mtx_balance': 0, 'mtx_platform': 'EpicPC'})
    athena = profiles.setdefault('athena', {'revision': 1, 'command_revision': 1, 'owned_items': [], 'battle_pass_purchased': False, 'battle_pass_level': 1})

    # Ensure lots of VBucks
    core['mtx_balance'] = max(core.get('mtx_balance', 0), 999999)
    core['revision'] += 1
    core['command_revision'] += 1

    preset_templates = [
        "AthenaCharacter:cid_010_athena_commando_m",
        "AthenaCharacter:cid_011_athena_commando_m",
        "AthenaCharacter:cid_012_athena_commando_m",
        "AthenaCharacter:cid_013_athena_commando_f",
        "AthenaCharacter:cid_014_athena_commando_f",
        "AthenaCharacter:cid_015_athena_commando_f",
        "AthenaCharacter:cid_016_athena_commando_f",
        "AthenaCharacter:cid_017_athena_commando_m",
        "AthenaCharacter:cid_018_athena_commando_m",
        "AthenaCharacter:cid_019_athena_commando_m",
        "AthenaCharacter:cid_020_athena_commando_m",
        "AthenaCharacter:cid_021_athena_commando_f",
        "AthenaCharacter:cid_022_athena_commando_f",
        "AthenaCharacter:cid_023_athena_commando_f",
        "AthenaCharacter:cid_024_athena_commando_f",
        "AthenaCharacter:cid_025_athena_commando_m",
        "AthenaCharacter:cid_026_athena_commando_m",
        "AthenaCharacter:cid_027_athena_commando_f",
        "AthenaCharacter:cid_028_athena_commando_f",
        "AthenaCharacter:cid_029_athena_commando_f_halloween",
        "AthenaCharacter:cid_030_athena_commando_m_halloween",
        "AthenaCharacter:cid_031_athena_commando_m_retro",
        "AthenaCharacter:cid_032_athena_commando_m_medieval",
    ]

    newly_granted = 0
    for template_id in preset_templates:
        if template_id not in athena['owned_items']:
            athena['owned_items'].append(template_id)
            newly_granted += 1

    # Mark BP owned as well
    athena['battle_pass_purchased'] = True
    athena['battle_pass_level'] = max(1, athena.get('battle_pass_level', 1))
    athena['revision'] += 1
    athena['command_revision'] += 1

    return {"vbucks": core['mtx_balance'], "granted_count": newly_granted}

# --- PyQt6 GUI ---
class FortniteLauncher(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OG Fortnite 3.5 Launcher (PyQt6)")
        self.setGeometry(200, 200, 560, 360)
        layout = QVBoxLayout()

        self.info_label = QLabel("Auto-setup: hosts update + HTTPS cert. Missing cert.pem/key.pem? Generate manually and restart.")
        self.info_label.setWordWrap(True)
        layout.addWidget(self.info_label)

        self.select_button = QPushButton("Select Fortnite 3.5 Executable and Launch")
        self.select_button.clicked.connect(self.select_and_launch)
        layout.addWidget(self.select_button)

        self.cert_button = QPushButton("Install Certificate as Trusted Root CA (Optional)")
        self.cert_button.clicked.connect(self.install_cert)
        layout.addWidget(self.cert_button)

        self.status_label = QLabel("Preparing environment...")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        # Quick-grant button: call in-process utility so user doesn't need to curl
        self.quick_grant_button = QPushButton("Grant VBucks & Season1-3 Skins (Auto)")
        self.quick_grant_button.clicked.connect(self.quick_grant_ui)
        layout.addWidget(self.quick_grant_button)

        self.setLayout(layout)

    def select_and_launch(self):
        exe_path, _ = QFileDialog.getOpenFileName(self, "Select Fortnite Executable", "", "Executable Files (*.exe)")
        if not exe_path or not os.path.isfile(exe_path):
            QMessageBox.warning(self, "No File Selected", "No valid executable selected. Please try again.")
            return
        if not exe_path.endswith("FortniteClient-Win64-Shipping.exe"):
            QMessageBox.warning(self, "Wrong File", "Please select FortniteClient-Win64-Shipping.exe.")
            return
        args = [
            exe_path,
            "-AUTH_LOGIN=unused",
            "-AUTH_PASSWORD=unused",
            "-AUTH_TYPE=epic",
            "-epicapp=Fortnite",
            "-epicenv=Prod",
            "-epicportal",
            "-epiclocale=en-US",
            "-skippatchcheck",
            "-fromfl=be",
            "-fltoken=notneeded",
            "-platform=Windows" 
        ]
        try:
            subprocess.Popen(args, cwd=os.path.dirname(exe_path))
            self.status_label.setText(f"Game launched from: {exe_path}\nEmulator server is still running.")
            QMessageBox.information(self, "Game Launched", "Fortnite 3.5 launched! Enjoy!\n\nLeave this window open while you play.")
        except Exception as e:
            self.status_label.setText(f"Failed to launch the game: {e}")
            QMessageBox.critical(self, "Launch Failed", f"Failed to launch the game: {e}")

    def install_cert(self):
        reply = QMessageBox.question(self, "Install Certificate", "Install the existing cert.pem as a trusted root CA?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            if install_cert_to_trusted_root():
                QMessageBox.information(self, "Certificate Installed", "Certificate installed as trusted root CA. Restart your system to apply.")
            else:
                QMessageBox.critical(self, "Certificate Install Failed", "Failed to install certificate. See fortnite_launcher_setup.log.")

    def quick_grant_ui(self):
        """UI handler: grant VBucks and season 1-3 templates immediately in the running emulator."""
        try:
            result = grant_vbucks_and_season()
            self.status_label.setText(f"Injected {result['vbucks']} VBucks and {result['granted_count']} items into FAKE_ACCOUNT_ID.")
            QMessageBox.information(self, "Grant Complete", f"Granted {result['vbucks']} VBucks and {result['granted_count']} items.\nOpen the game to see them in Locker/Item Shop.")
        except Exception as e:
            QMessageBox.critical(self, "Grant Failed", f"Failed to grant items: {e}")

# Add UnlockBattlePass endpoint near other profile client endpoints
@app.route('/fortnite/api/game/v2/profile/<string:account_id>/client/UnlockBattlePass', methods=['POST'])
def unlock_battle_pass(account_id: str):
    profile_id = request.args.get('profileId', 'athena')
    requested_rvn = int(request.args.get('rvn', -1))
    if profile_id != 'athena':
        return jsonify({"error": "Invalid profile"}), 400

    current = profiles.get('athena')
    if not current:
        return jsonify({"error": "Profile not found"}), 404

    base_rvn = requested_rvn if requested_rvn >= 0 else current['revision']
    if requested_rvn >= 0 and requested_rvn != base_rvn:
        return jsonify({"errorCode": "errors.com.epicgames.common.mismatched_revision"}), 400

    current['battle_pass_purchased'] = True
    if 'stats' not in current:
        current['stats'] = {}
    current['stats']['book_purchased'] = True
    current['stats']['book_level'] = max(1, current.get('battle_pass_level', 1))

    current['revision'] += 1
    current['command_revision'] += 1

    changes = [
        {"changeType": "statModified", "name": "book_purchased", "value": True},
        {"changeType": "statModified", "name": "book_level", "value": current['stats']['book_level']}
    ]

    return jsonify({
        "profileRevision": current['revision'],
        "profileId": profile_id,
        "profileChangesBaseRevision": base_rvn,
        "profileChanges": changes,
        "profileCommandRevision": current['command_revision'],
        "serverTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
        "responseVersion": 1
    })

# Some older builds call a dedicated battle pass purchase endpoint
@app.route('/fortnite/api/game/v2/profile/<string:account_id>/client/PurchaseBattlePass', methods=['POST'])
def purchase_battle_pass(account_id: str):
    core = profiles.get('common_core')
    athena = profiles.get('athena')
    if not core or not athena:
        return jsonify({"error": "Profiles not initialized"}), 500

    price = 950
    if core.get('mtx_balance', 0) < price:
        return jsonify({'errorCode': 'errors.com.epicgames.payment.insufficient_funds'}), 400

    # Deduct and bump core
    core['mtx_balance'] -= price
    core['revision'] += 1
    core['command_revision'] += 1
    core_changes = [{"changeType": "statModified", "name": "current_mtx_balance", "value": core['mtx_balance']}] 

    # Grant BP in athena
    if 'AthenaSeason:athenaseason3' not in athena['owned_items']:
        athena['owned_items'].append('AthenaSeason:athenaseason3')
    athena['battle_pass_purchased'] = True
    athena['battle_pass_level'] = max(1, athena.get('battle_pass_level', 1))
    athena_changes = [
        {"changeType": "itemAdded", "itemId": "athena_season3", "item": {"templateId": "AthenaSeason:athenaseason3", "attributes": {"season_level": athena['battle_pass_level'], "book_purchased": True, "book_level": athena['battle_pass_level']}, "quantity": 1}},
        {"changeType": "statModified", "name": "book_purchased", "value": True},
        {"changeType": "statModified", "name": "book_level", "value": athena['battle_pass_level']}
    ]
    athena['revision'] += 1
    athena['command_revision'] += 1

    return jsonify({
        "profileRevision": core['revision'],
        "profileId": "common_core",
        "profileChangesBaseRevision": core['revision'] - 1,
        "profileChanges": core_changes,
        "profileCommandRevision": core['command_revision'],
        "multiUpdate": [{
            "profileRevision": athena['revision'],
            "profileId": "athena",
            "profileChangesBaseRevision": athena['revision'] - 1,
            "profileChanges": athena_changes,
            "profileCommandRevision": athena['command_revision']
        }],
        "serverTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
        "responseVersion": 1
    })

# --- Admin utilities (offline QoL) ---
@app.route('/fortnite/api/game/v2/profile/<string:account_id>/client/AdminSetVBucks', methods=['POST'])
def admin_set_vbucks(account_id: str):
    profile_id = request.args.get('profileId', 'common_core')
    amount = int((request.json or {}).get('amount', 999999))
    core = profiles.setdefault('common_core', {'revision': 1, 'command_revision': 1, 'mtx_balance': 0, 'mtx_platform': 'EpicPC'})
    base_rvn = core['revision']
    core['mtx_balance'] = max(0, amount)
    core['revision'] += 1
    core['command_revision'] += 1
    return jsonify({
        "profileRevision": core['revision'],
        "profileId": profile_id,
        "profileChangesBaseRevision": base_rvn,
        "profileChanges": [{"changeType": "statModified", "name": "current_mtx_balance", "value": core['mtx_balance']}],
        "profileCommandRevision": core['command_revision'],
        "serverTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
        "responseVersion": 1
    })

@app.route('/fortnite/api/game/v2/profile/<string:account_id>/client/AdminGrantTemplates', methods=['POST'])
def admin_grant_templates(account_id: str):
    athena = profiles.setdefault('athena', {'revision': 1, 'command_revision': 1, 'owned_items': [], 'battle_pass_purchased': False, 'battle_pass_level': 1})
    data = request.json or {}
    to_grant = data.get('templateIds', [])
    if not isinstance(to_grant, list):
        return jsonify({"error": "templateIds must be an array"}), 400
    changes = []
    for template_id in to_grant:
        if template_id not in athena['owned_items']:
            athena['owned_items'].append(template_id)
            changes.append({
                "changeType": "itemAdded",
                "itemId": template_id,
                "item": {"templateId": template_id, "attributes": {"level": 1}, "quantity": 1}
            })
    if not changes:
        return jsonify({
            "profileRevision": athena['revision'],
            "profileId": "athena",
            "profileChangesBaseRevision": athena['revision'],
            "profileChanges": [],
            "profileCommandRevision": athena['command_revision'],
            "serverTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
            "responseVersion": 1
        })
    base_rvn = athena['revision']
    athena['revision'] += 1
    athena['command_revision'] += 1
    return jsonify({
        "profileRevision": athena['revision'],
        "profileId": "athena",
        "profileChangesBaseRevision": base_rvn,
        "profileChanges": changes,
        "profileCommandRevision": athena['command_revision'],
        "serverTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
        "responseVersion": 1
    })

@app.route('/fortnite/api/game/v2/profile/<string:account_id>/client/AdminGrantSeason123', methods=['POST'])
def admin_grant_season123(account_id: str):
    # Preset list based on early Season 1–3 CIDs provided
    preset_templates = [
        "AthenaCharacter:cid_010_athena_commando_m",
        "AthenaCharacter:cid_011_athena_commando_m",
        "AthenaCharacter:cid_012_athena_commando_m",
        "AthenaCharacter:cid_013_athena_commando_f",
        "AthenaCharacter:cid_014_athena_commando_f",
        "AthenaCharacter:cid_015_athena_commando_f",
        "AthenaCharacter:cid_016_athena_commando_f",
        "AthenaCharacter:cid_017_athena_commando_m",
        "AthenaCharacter:cid_018_athena_commando_m",
        "AthenaCharacter:cid_019_athena_commando_m",
        "AthenaCharacter:cid_020_athena_commando_m",
        "AthenaCharacter:cid_021_athena_commando_f",
        "AthenaCharacter:cid_022_athena_commando_f",
        "AthenaCharacter:cid_023_athena_commando_f",
        "AthenaCharacter:cid_024_athena_commando_f",
        "AthenaCharacter:cid_025_athena_commando_m",
        "AthenaCharacter:cid_026_athena_commando_m",
        "AthenaCharacter:cid_027_athena_commando_f",
        "AthenaCharacter:cid_028_athena_commando_f",
        "AthenaCharacter:cid_029_athena_commando_f_halloween",
        "AthenaCharacter:cid_030_athena_commando_m_halloween",
        "AthenaCharacter:cid_031_athena_commando_m_retro",
        "AthenaCharacter:cid_032_athena_commando_m_medieval",
    ]

    # Reuse AdminGrantTemplates logic
    request_json = {"templateIds": preset_templates}
    with app.test_request_context(json=request_json):
        return admin_grant_templates(account_id)
# Move early checks to main block before QApplication
if __name__ == "__main__":
    # Check port 443 availability
    try:
        check_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        check_sock.bind(('0.0.0.0', 443))
        check_sock.close()
        log("Port 443 is available for binding.")
    except Exception as e:
        print(f"Cannot bind to port 443: {e}", file=sys.stderr)
        app_temp = QApplication(sys.argv)  # Create temp app for QMessageBox
        QMessageBox.critical(None, "Port Bind Error", f"Cannot bind to port 443 (likely in use): {e}\nKill the process using port 443 and try again.")
        sys.exit(1)

    # Update hosts file
    if update_hosts_file():
        log("Hosts file updated!")
    else:
        print(f"Failed to update hosts file at {HOSTS_PATH}. Please edit it manually.", file=sys.stderr)

    # Auto-install CA certificate as trusted root
    if install_cert_to_trusted_root():
        log("Certificate installed as trusted root CA automatically.")
    else:
        log("Automatic certificate installation failed; install certificate manually via GUI.")

    # Start Flask server in background
    server_thread = threading.Thread(target=run_emulator, daemon=True)
    server_thread.start()
    time.sleep(2)
    log("Emulator server running on port 443 (HTTPS).")

    # Start WebSocket server in background
    websocket_thread = threading.Thread(target=start_websocket_server, daemon=True)
    websocket_thread.start()
    time.sleep(1)  # Give it a moment to start
    log("WebSocket matchmaking server running on ws://localhost:8080")

    app_qt = QApplication(sys.argv)
    launcher = FortniteLauncher()
    launcher.show()
    sys.exit(app_qt.exec())