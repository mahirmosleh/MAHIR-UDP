# ==================== STANDARD IMPORTS ====================
import sys
import asyncio
import httpx
import random
import json
import socket
import struct
import time
import os
import uuid
import itertools
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from google_play_scraper import app as play_scraper
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from protobuf_decoder.protobuf_decoder import Parser
from message_ids import MESSAGE_ID_TO_NAME
import thunderFF_pb2

from dashboard_server import bot_state, start_web_dashboard, MAX_ACCOUNTS
import daily_exp_tracker
from daily_exp_tracker import (
    DAILY_EXP_CAP,
    is_cap_reached,
    add_exp as add_daily_exp,
    get_status as get_daily_status,
)

# ==================== CONFIGURATION ====================
WEB_HOST = "0.0.0.0"
WEB_PORT = 9323
ACCOUNTS_FILE = "accounts.json"
TOKEN_CACHE_FILE = "token_cache.json"
DEVICES_FILE = "devices.json"
TOKEN_CACHE_TTL = 1200

START_MATCH_INTERVAL = 3.0
NEW_MATCH_DELAY = 3.0
MAX_MATCH_DURATION = 700
MATCH_IDLE_TIMEOUT = 8.0
NO_MATCH_RESTART_TIMEOUT = 300
PRIORITY_REGIONS = ["BD", "IND", "SG", "TH", "PH", "VN", "MY", "ID", "HK", "TW"]

MAX_CONSECUTIVE_PARSE_FAILURES = 5.0
NON_MATCH_RECONNECT_DELAY = 1.0

FALLBACK_UID = ""
FALLBACK_PASSWORD = ""


# ==================== PER-ACCOUNT PAUSE EVENTS ====================
_account_pause_events: Dict[str, asyncio.Event] = {}


def get_pause_event(uid: str) -> asyncio.Event:
    uid = str(uid)
    ev = _account_pause_events.get(uid)
    if ev is None:
        ev = asyncio.Event()
        ev.set()
        _account_pause_events[uid] = ev
    return ev


# ==================== DEVICE RANDOMIZER ====================
def get_device_for_account(account_identifier: str) -> dict:
    devices = {}
    if os.path.exists(DEVICES_FILE):
        try:
            with open(DEVICES_FILE, "r", encoding="utf-8") as f:
                devices = json.load(f)
        except Exception:
            pass

    acc_key = str(account_identifier)
    if acc_key in devices:
        return devices[acc_key]

    device_list = [
        ("Samsung", "SM-G998B", "Adreno (TM) 660", "Android OS 12 / API-31"),
        ("Xiaomi", "2201122G", "Adreno (TM) 730", "Android OS 13 / API-33"),
        ("Realme", "RMX3700", "Mali-G710", "Android OS 14 / API-34"),
        ("OnePlus", "CPH2451", "Adreno (TM) 740", "Android OS 13 / API-33"),
        ("OPPO", "CPH2611", "Adreno (TM) 720", "Android OS 14 / API-34"),
        ("Vivo", "V2203", "Mali-G710", "Android OS 12 / API-31"),
        ("Poco", "M2102J20SG", "Adreno (TM) 660", "Android OS 13 / API-33"),
    ]
    brand, model, gpu, os_ver = random.choice(device_list)

    new_device = {
        "unique_device_id": f"Google|{str(uuid.uuid4())}",
        "brand": brand,
        "model": model,
        "gpu_renderer": gpu,
        "system_software": os_ver,
        "screen_width": random.choice([1080, 1440, 720, 1280]),
        "screen_height": random.choice([2400, 3200, 1600, 2400]),
        "screen_dpi": str(random.randint(300, 420)),
        "memory": random.randint(2800, 6500),
        "processor_details": f"ARM64 FP ASIMD AES VMH | {random.randint(2200, 3200)} | {random.randint(6, 12)}",
        "client_ip": f"{random.randint(103, 223)}.{random.randint(10, 250)}.{random.randint(10, 250)}.{random.randint(10, 250)}"
    }

    devices[acc_key] = new_device
    try:
        with open(DEVICES_FILE, "w", encoding="utf-8") as f:
            json.dump(devices, f, indent=4)
    except Exception as e:
        print_error(f"Failed to save device mapping: {e}")

    return new_device


# ==================== CLOUDFLARE DNS RESOLVER ====================
CLOUDFLARE_PRIMARY_DNS = "1.1.1.1"
CLOUDFLARE_SECONDARY_DNS = "1.0.0.1"
_DNS_CACHE: Dict[str, Tuple[str, float]] = {}
_DNS_CACHE_TTL = 300.0


async def resolve_host_cloudflare(hostname: str) -> str:
    if not hostname:
        return hostname

    parts = hostname.split('.')
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return hostname

    now = time.time()
    if hostname in _DNS_CACHE:
        ip, exp = _DNS_CACHE[hostname]
        if now < exp:
            return ip

    def _query_cloudflare(server_ip: str) -> Optional[str]:
        s = None
        try:
            tx_id = random.randint(1000, 65535)
            header = struct.pack(">HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
            qname = b"".join(bytes([len(part)]) + part.encode('ascii') for part in hostname.split('.')) + b"\x00"
            query_pkt = header + qname + struct.pack(">HH", 1, 1)

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.2)
            s.sendto(query_pkt, (server_ip, 53))
            resp, _ = s.recvfrom(1024)

            if len(resp) >= 12:
                ancount = struct.unpack(">H", resp[6:8])[0]
                if ancount > 0:
                    offset = 12 + len(qname) + 4
                    for _ in range(ancount):
                        if offset >= len(resp):
                            break
                        if (resp[offset] & 0xC0) == 0xC0:
                            offset += 2
                        else:
                            while offset < len(resp) and resp[offset] != 0:
                                offset += 1 + resp[offset]
                            offset += 1
                        if offset + 10 > len(resp):
                            break
                        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", resp[offset:offset + 10])
                        offset += 10
                        if rtype == 1 and rdlen == 4 and offset + 4 <= len(resp):
                            return socket.inet_ntoa(resp[offset:offset + 4])
                        offset += rdlen
        except Exception:
            pass
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
        return None

    loop = asyncio.get_running_loop()
    ip = await loop.run_in_executor(None, _query_cloudflare, CLOUDFLARE_PRIMARY_DNS)
    if not ip:
        ip = await loop.run_in_executor(None, _query_cloudflare, CLOUDFLARE_SECONDARY_DNS)
    if not ip:
        try:
            ip_info = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
            if ip_info:
                ip = ip_info[0][4][0]
        except Exception:
            ip = hostname

    if ip:
        _DNS_CACHE[hostname] = (ip, now + _DNS_CACHE_TTL)
    return ip or hostname


def optimize_tcp_socket(sock: socket.socket):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
    except Exception:
        pass


def optimize_udp_socket(sock: socket.socket):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 131072)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
        if hasattr(socket, 'SIO_UDP_CONNRESET') and os.name == 'nt':
            try:
                sock.ioctl(socket.SIO_UDP_CONNRESET, False)
            except Exception:
                pass
    except Exception:
        pass


# ==================== NETWORK & CRYPTO ====================
client = httpx.AsyncClient(
    verify=False,
    timeout=10.0,
    limits=httpx.Limits(max_connections=100, max_keepalive_connections=50)
)

# Global headers — X-GA-SV added per-request (must be fresh)
headers = {
    'User-Agent': 'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Expect': '100-continue',
    'X-Unity-Version': '2018.4.12f1',
    'X-GA': 'v1 1',
    'ReleaseVersion': 'OB55',
}


# ==================== X-GA-SV (MUST BE FRESH PER REQUEST) ====================
def _current_xga_sv() -> str:
    """
    X-GA-SV must be the CURRENT Unix timestamp in seconds.
    Server rejects stale values with 'SignError1'.
    """
    return str(int(time.time()))


AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

CRC7_TABLE = bytes([
    0, 9, 18, 27, 36, 45, 54, 63, 72, 65, 90, 83, 108, 101, 126, 119,
    25, 16, 11, 2, 61, 52, 47, 38, 81, 88, 67, 74, 117, 124, 103, 110,
    50, 59, 32, 41, 22, 31, 4, 13, 122, 115, 104, 97, 94, 87, 76, 69,
    43, 34, 57, 48, 15, 6, 29, 20, 99, 106, 113, 120, 71, 78, 85, 92,
    100, 109, 118, 127, 64, 73, 82, 91, 44, 37, 62, 55, 8, 1, 26, 19,
    125, 116, 111, 102, 89, 80, 75, 66, 53, 60, 39, 46, 17, 24, 3, 10,
    86, 95, 68, 77, 114, 123, 96, 105, 30, 23, 12, 5, 58, 51, 40, 33,
    79, 70, 93, 84, 107, 98, 121, 112, 7, 14, 21, 28, 35, 42, 49, 56,
    65, 72, 83, 90, 101, 108, 119, 126, 9, 0, 27, 18, 45, 36, 63, 54,
    88, 81, 74, 67, 124, 117, 110, 103, 16, 25, 2, 11, 52, 61, 38, 47,
    115, 122, 97, 104, 87, 94, 69, 76, 59, 50, 41, 32, 31, 22, 13, 4,
    106, 99, 120, 113, 78, 71, 92, 85, 34, 43, 48, 57, 6, 15, 20, 29,
    37, 44, 55, 62, 1, 8, 19, 26, 109, 100, 127, 118, 73, 64, 91, 82,
    60, 53, 46, 39, 24, 17, 10, 3, 116, 125, 102, 111, 80, 89, 66, 75,
    23, 30, 5, 12, 51, 58, 33, 40, 95, 86, 77, 68, 123, 114, 105, 96,
    14, 7, 28, 21, 42, 35, 56, 49, 70, 79, 84, 93, 98, 107, 112, 121,
])

_DELTA = 0x9E3779B9
_ROUNDS = 16
_FIELD_SIZES = {0: 1, 1: 2, 2: 2, 3: 1, 4: 2}
_FIELD_NAMES = {0: "sendOption", 1: "cmd", 2: "orderId", 3: "flags", 4: "length"}


class Colors:
    HEADER = '\033[95m'
    GREEN = '\033[92m'
    FAIL = '\033[91m'
    WARNING = '\033[93m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    ENDC = '\033[0m'


def print_colored(text, color=Colors.WHITE):
    try:
        print(f"{color}{text}{Colors.ENDC}")
    except Exception:
        try:
            print(f"{color}{text.encode('ascii', errors='replace').decode('ascii')}{Colors.ENDC}")
        except Exception:
            pass


def print_success(text):
    print_colored(f"[+] {text}", Colors.GREEN)
    try:
        bot_state.log(text, "success")
    except Exception:
        pass


def print_error(text):
    print_colored(f"[-] {text}", Colors.FAIL)
    try:
        bot_state.log(text, "error")
    except Exception:
        pass


def print_warning(text):
    print_colored(f"[!] {text}", Colors.WARNING)
    try:
        bot_state.log(text, "warning")
    except Exception:
        pass


def print_info(text):
    print_colored(f"[i] {text}", Colors.CYAN)
    try:
        bot_state.log(text, "info")
    except Exception:
        pass


def get_proto_field(d, key, default=None):
    if not d or not isinstance(d, dict):
        return default
    if key in d:
        val = d[key].get('data')
        return val if val is not None else default
    if str(key) in d:
        val = d[str(key)].get('data')
        return val if val is not None else default
    return default


# ==================== DEBUG HELPERS ====================
DEBUG = True

try:
    import traceback as _tb
except Exception:
    _tb = None


def dbg(tag: str, msg: Any):
    if not DEBUG:
        return
    try:
        print(f"\033[95m[DEBUG][{tag}]\033[0m {msg}")
    except Exception:
        pass


def dbg_req(method: str, url: str, headers: Optional[dict] = None, data: Any = None):
    if not DEBUG:
        return
    try:
        print(f"\033[95m[DEBUG][HTTP →]\033[0m {method} {url}")
        if headers:
            safe = {}
            for k, v in headers.items():
                lk = str(k).lower()
                if lk in ("authorization", "cookie"):
                    safe[k] = (str(v)[:24] + "…") if v else v
                else:
                    safe[k] = v
            print(f"\033[95m[DEBUG][HTTP → HDR]\033[0m {safe}")
        if data is not None:
            if isinstance(data, (bytes, bytearray)):
                print(f"\033[95m[DEBUG][HTTP → BODY]\033[0m <bytes len={len(data)}> "
                      f"hex[:96]={bytes(data[:96]).hex()}")
            elif isinstance(data, dict):
                safe_data = {k: (str(v)[:40] + "…" if len(str(v)) > 40 else v)
                             for k, v in data.items()}
                print(f"\033[95m[DEBUG][HTTP → BODY]\033[0m {safe_data}")
            else:
                s = str(data)
                print(f"\033[95m[DEBUG][HTTP → BODY]\033[0m {s[:400]}")
    except Exception as e:
        print(f"\033[95m[DEBUG][HTTP → ERR]\033[0m {e}")


def dbg_resp(response):
    if not DEBUG or response is None:
        return
    try:
        try:
            size = len(response.content) if response.content is not None else 0
        except Exception:
            size = -1
        print(f"\033[95m[DEBUG][HTTP ←]\033[0m status={response.status_code} "
              f"len={size} ct={response.headers.get('content-type', '?')}")
        try:
            text = response.text
            if text and len(text) < 600:
                print(f"\033[95m[DEBUG][HTTP ← BODY]\033[0m {text[:1500]}")
            elif text:
                print(f"\033[95m[DEBUG][HTTP ← BODY]\033[0m {text[:400]}… <truncated>")
        except Exception:
            try:
                print(f"\033[95m[DEBUG][HTTP ← BODY]\033[0m "
                      f"<bytes hex[:128]={response.content[:128].hex()}>")
            except Exception:
                pass
    except Exception as e:
        print(f"\033[95m[DEBUG][HTTP ← ERR]\033[0m {e}")


def dbg_exc(tag: str, e: BaseException):
    print(f"\033[91m[DEBUG][EXC][{tag}]\033[0m {type(e).__name__}: {e}")
    if DEBUG and _tb is not None:
        try:
            print("\033[91m" + _tb.format_exc() + "\033[0m")
        except Exception:
            pass


# ==================== PER-ACCOUNT MATCH COUNTER ====================
_match_counters: Dict[str, int] = {}
_match_counter_lock = asyncio.Lock()


async def _inc_match(uid: str) -> int:
    async with _match_counter_lock:
        _match_counters[uid] = _match_counters.get(uid, 0) + 1
        return _match_counters[uid]


async def _dec_match(uid: str) -> int:
    async with _match_counter_lock:
        if uid in _match_counters and _match_counters[uid] > 0:
            _match_counters[uid] -= 1
        return _match_counters.get(uid, 0)


async def _get_match_count(uid: str) -> int:
    async with _match_counter_lock:
        return _match_counters.get(uid, 0)


async def _get_total_match_count() -> int:
    async with _match_counter_lock:
        return sum(_match_counters.values())


# ==================== TOKEN CACHE ====================
_token_cache_memo: Dict[str, Any] = {}
_token_cache_memo_time: float = 0.0
_TOKEN_CACHE_MEMO_TTL = 5.0


def _json_serializer(obj):
    if isinstance(obj, (bytes, bytearray)):
        return {"__bytes_hex__": bytes(obj).hex()}
    raise TypeError(f"Type {type(obj)} not serializable")


def _json_deserializer(obj):
    if isinstance(obj, dict):
        if "__bytes_hex__" in obj and len(obj) == 1:
            try:
                return bytes.fromhex(obj["__bytes_hex__"])
            except Exception:
                return b""
        return {k: _json_deserializer(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_deserializer(x) for x in obj]
    return obj


def _load_token_cache() -> Dict[str, Any]:
    global _token_cache_memo, _token_cache_memo_time
    now = time.time()
    if _token_cache_memo and (now - _token_cache_memo_time) < _TOKEN_CACHE_MEMO_TTL:
        return _token_cache_memo

    if not os.path.exists(TOKEN_CACHE_FILE):
        return {}
    try:
        with open(TOKEN_CACHE_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()
        if not content:
            return {}
        data = json.loads(content)
        if not isinstance(data, dict):
            raise ValueError("Cache root must be dict")
        parsed = _json_deserializer(data)
        _token_cache_memo = parsed
        _token_cache_memo_time = now
        return parsed
    except Exception as e:
        print_error(f"Token cache corrupt → deleting: {e}")
        try:
            os.remove(TOKEN_CACHE_FILE)
        except Exception:
            pass
        return {}


def _save_token_cache(cache: Dict[str, Any]):
    global _token_cache_memo, _token_cache_memo_time
    try:
        tmp_file = TOKEN_CACHE_FILE + ".tmp"
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, default=_json_serializer)
        os.replace(tmp_file, TOKEN_CACHE_FILE)
        _token_cache_memo = cache
        _token_cache_memo_time = time.time()
    except Exception as e:
        print_error(f"Token cache save error: {e}")


def cache_get(uid: str) -> Optional[Dict]:
    cache = _load_token_cache()
    entry = cache.get(str(uid))
    if not entry:
        return None
    if time.time() - entry.get("cached_at", 0) > TOKEN_CACHE_TTL:
        print_info(f"[CACHE] UID {uid} expired. Re-login needed.")
        cache_invalidate(uid)
        return None
    if str(entry.get("account_id", "")).isdigit():
        entry["account_id"] = int(entry["account_id"])
    if not isinstance(entry.get("login_payload_data"), (bytes, bytearray)):
        print_warning(f"[CACHE] UID {uid} missing payload → invalidating")
        cache_invalidate(uid)
        return None
    return entry


def cache_set(uid: str, account_data: Dict):
    cache = _load_token_cache()
    entry = dict(account_data)
    entry["cached_at"] = time.time()
    cache[str(uid)] = entry
    _save_token_cache(cache)
    print_success(f"[CACHE] Saved credentials for UID {uid}")


def cache_invalidate(uid: str):
    cache = _load_token_cache()
    if str(uid) in cache:
        del cache[str(uid)]
        _save_token_cache(cache)
        print_warning(f"[CACHE] Invalidated: {uid}")


# ==================== ENCRYPTION & PROTOBUF ====================
async def aes_encrypt(payload, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(payload, AES.block_size))


async def get_playstore_version():
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: play_scraper('com.dts.freefireth', lang='hi', country='id')
        )
        ver = result.get("version")
        dbg("playstore", f"version={ver!r}")
        return ver
    except Exception as e:
        dbg_exc("get_playstore_version", e)
        return None


async def version_config():
    app_version = await get_playstore_version()
    dbg("version_config", f"app_version={app_version!r}")

    if not app_version:
        print_error("[version_config] Failed to fetch app version from Play Store")
        return None

    api_url = (
        "https://version.ggwhitehawk.com/live/ver.php"
        f"?version={app_version}"
        "&lang=hi&device=android&channel=android"
        "&appstore=googleplay&region=BD"
        "&whitelist_version=1.7.0&whitelist_sp_version=1.0.0"
    )
    dbg("version_config", f"url={api_url}")
    try:
        dbg_req("GET", api_url)
        response = await client.get(api_url)
        dbg_resp(response)
        response.raise_for_status()
        data = response.json()

        server_url = data.get("server_url")
        remote_version = data.get("remote_version")
        latest_release_version = data.get("latest_release_version")
        device_whitelist_version = data.get("device_whitelist_version", "1.7.0")
        vercfg_sign = data.get("vercfg_sign", "")

        if not server_url or not remote_version or not latest_release_version:
            print_error(
                f"[version_config] missing fields — "
                f"server_url={server_url!r}, remote_version={remote_version!r}, "
                f"latest_release_version={latest_release_version!r}"
            )
            return None

        dbg("version_config",
            f"OK release={latest_release_version} remote_ver={remote_version} "
            f"whitelist_ver={device_whitelist_version} sign={vercfg_sign}")

        return (latest_release_version, remote_version, server_url,
                device_whitelist_version, vercfg_sign)
    except Exception as e:
        dbg_exc("version_config", e)
        return None


async def get_access_token(uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    hdrs = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; SM-G998B Build/SP1A.210812.016)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
        "X-GA-SV": _current_xga_sv(),  # fresh timestamp
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    for attempt in range(5):
        try:
            dbg("get_access_token", f"attempt {attempt+1}/5 for uid={uid}")
            dbg_req("POST", url, hdrs, data)
            response = await client.post(url, headers=hdrs, data=data)
            dbg_resp(response)

            if response.status_code == 200:
                try:
                    response_data = response.json()
                except Exception as pe:
                    dbg_exc("get_access_token.json", pe)
                    return None
                dbg("get_access_token", f"parsed={response_data}")

                open_id = response_data.get("open_id")
                access_token = response_data.get("access_token")
                platform = response_data.get("platform", 4)

                if open_id and access_token:
                    dbg("get_access_token",
                        f"OK open_id={open_id[:12]}… platform={platform}")
                    return open_id, access_token, platform
                else:
                    print_error(
                        f"[get_access_token] Missing fields — "
                        f"open_id={open_id!r}, access_token={'set' if access_token else None}, "
                        f"full={response_data}"
                    )
                    return None

            if response.status_code == 429:
                dbg("get_access_token", "429 rate-limited → sleeping 1s")
                await asyncio.sleep(1)
                continue
        except Exception as e:
            dbg_exc("get_access_token", e)
        await asyncio.sleep(0.5)
    return None


async def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {"wire_type": result.wire_type}
        if result.wire_type == "varint":
            field_data["data"] = result.data
        elif result.wire_type == "string":
            field_data["data"] = result.data
        elif result.wire_type == "bytes":
            field_data["data"] = result.data
        elif result.wire_type == "length_delimited":
            field_data["data"] = await parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict


async def decode_protobuf(data):
    parsed_results = Parser().parse(data)
    parsed_results_dict = await parse_results(parsed_results)
    return json.dumps(parsed_results_dict)


async def build_majorlogin_payload(open_id, access_token, platform, client_version,
                                   device_info, whitelist_version="1.7.0",
                                   vercfg_sign=""):
    try:
        proto = thunderFF_pb2.MajorLoginReq()
        proto.event_time = str(datetime.now())[:-7]
        proto.game_name = "free fire"
        proto.platform_id = int(platform)
        proto.client_version = client_version
        proto.client_version_code = "2025090100"

        proto.system_software = device_info.get("system_software", "Android OS 12 / API-31")
        proto.system_hardware = device_info.get("brand", "Handheld")
        proto.device_type = device_info.get("model", "Handheld")
        proto.screen_width = int(device_info.get("screen_width", 1600))
        proto.screen_height = int(device_info.get("screen_height", 900))
        proto.screen_dpi = str(device_info.get("screen_dpi", "300"))
        proto.processor_details = device_info.get("processor_details",
                                                  "x86-64 SSE3 SSE4.1 SSE4.2 AVX | 2400 | 4")
        proto.memory = int(device_info.get("memory", 5951))
        proto.gpu_renderer = device_info.get("gpu_renderer", "Adreno (TM) 640")
        proto.unique_device_id = device_info.get("unique_device_id",
                                                 "Google|725030d8-6585-4f55-bcca-a6df7e59935b")
        proto.client_ip = device_info.get("client_ip", "103.145.112.210")

        proto.telecom_operator = "Citycell"
        proto.network_operator_a = "Citycell"
        proto.network_type = "WIFI"
        proto.network_type_a = "WIFI"
        proto.cpu_type = 2
        proto.cpu_architecture = "64"
        proto.gpu_version = "OpenGL ES 3.2"
        proto.graphics_api = "OpenGLES2"
        proto.language = "en"
        proto.open_id = open_id
        proto.open_id_type = str(platform)
        proto.login_open_id_type = int(platform)
        proto.access_token = access_token
        proto.login_by = 3
        proto.platform_sdk_id = 2
        proto.origin_platform_type = str(platform)
        proto.primary_platform_type = str(platform)
        proto.reg_avatar = 1
        proto.channel_type = 3

        memory_available = proto.memory_available
        memory_available.version = 55
        memory_available.hidden_value = 81

        proto.external_storage_total = 34308
        proto.external_storage_available = 30777
        proto.internal_storage_total = 2519
        proto.internal_storage_available = 243
        proto.game_disk_storage_total = 34308
        proto.game_disk_storage_available = 32224
        proto.external_sdcard_total_storage = 34308
        proto.external_sdcard_avail_storage = 32224

        proto.library_path = ""
        proto.library_token = ""
        proto.client_using_version = ""
        proto.extra_info = ""
        proto.analytics_detail = b""

        proto.supported_astc_bitset = 4095
        proto.loading_time = 14582
        proto.release_channel = "android"
        proto.android_engine_init_flag = 111207
        proto.if_push = 1
        proto.is_vpn = 0

        payload = proto.SerializeToString()
        encrypted = await aes_encrypt(payload, AES_KEY, AES_IV)
        dbg("build_majorlogin",
            f"payload={len(payload)}B encrypted={len(encrypted)}B "
            f"open_id={str(open_id)[:12]}… platform={platform} "
            f"client_ver={client_version} whitelist={whitelist_version}")
        return encrypted
    except Exception as e:
        dbg_exc("build_majorlogin_payload", e)
        return None


async def send_majorlogin(data, release_version, server_url):
    try:
        url = f"{server_url}MajorLogin"
        req_headers = headers.copy()
        req_headers["ReleaseVersion"] = release_version
        req_headers["X-GA-SV"] = _current_xga_sv()   # ← FRESH timestamp per request

        dbg("majorlogin",
            f"release_version={release_version} url={url} "
            f"X-GA-SV={req_headers['X-GA-SV']}")
        dbg_req("POST", url, req_headers, data)
        response = await client.post(url, headers=req_headers, data=data)
        dbg_resp(response)

        if response.status_code != 200:
            body = response.text[:200]
            print_error(f"[majorlogin] HTTP {response.status_code} — body={body}")
            if "SignError" in body:
                print_error(
                    "[majorlogin] ❌ SIGNATURE/TIMESTAMP REJECTED. "
                    "Check that your system clock is accurate."
                )
            return None

        response_content = response.content
        if len(response_content) < 40:
            print_error(f"[majorlogin] response too short ({len(response_content)}B)")
            return None

        res_proto = thunderFF_pb2.MajorLoginRes()
        try:
            res_proto.ParseFromString(response_content)
            dbg("majorlogin",
                f"parsed[0] region={res_proto.region!r} "
                f"token={'set' if res_proto.token else None} "
                f"account_id={getattr(res_proto,'account_id','?')} url={res_proto.url!r}")
            if res_proto.region and res_proto.token:
                return res_proto
        except Exception as e:
            dbg_exc("majorlogin.parse[0]", e)

        if len(response_content) > 64:
            try:
                res_proto = thunderFF_pb2.MajorLoginRes()
                res_proto.ParseFromString(response_content[64:])
                dbg("majorlogin",
                    f"parsed[64] region={res_proto.region!r} "
                    f"token={'set' if res_proto.token else None}")
                if res_proto.region and res_proto.token:
                    return res_proto
            except Exception as e:
                dbg_exc("majorlogin.parse[64]", e)

        for offset in range(min(128, len(response_content))):
            try:
                candidate = thunderFF_pb2.MajorLoginRes()
                candidate.ParseFromString(response_content[offset:])
                if candidate.region and candidate.token:
                    dbg("majorlogin", f"parsed at offset={offset}")
                    return candidate
            except Exception:
                pass

        print_error(f"[majorlogin] could not parse response; first 200B hex="
                    f"{response_content[:200].hex()}")
        res_proto = thunderFF_pb2.MajorLoginRes()
        res_proto.ParseFromString(response_content)
        return res_proto
    except Exception as e:
        dbg_exc("send_majorlogin", e)
        return None


async def send_getlogin(data, base_url, token, release_version):
    try:
        url = f"{base_url.rstrip('/')}/GetLoginData"
        req_headers = headers.copy()
        req_headers["ReleaseVersion"] = release_version
        req_headers["X-GA-SV"] = _current_xga_sv()   # ← FRESH timestamp
        req_headers['Authorization'] = f"Bearer {token}"
        req_headers['Host'] = "clientbp.ppmainecoonghj.com"

        dbg("getlogin",
            f"url={url} release_version={release_version} "
            f"X-GA-SV={req_headers['X-GA-SV']}")
        dbg_req("POST", url, req_headers, data)
        response = await client.post(url, headers=req_headers, data=data)
        dbg_resp(response)

        if response.status_code != 200:
            print_error(f"[getlogin] HTTP {response.status_code} — "
                        f"body={response.text[:200]}")
            return None

        response_content = response.content

        res_proto = thunderFF_pb2.GetLoginDataRes()
        parsed_successfully = False
        try:
            res_proto.ParseFromString(response_content)
            dbg("getlogin",
                f"parsed[0] nickname={getattr(res_proto,'nickname','')!r} "
                f"functional={'set' if res_proto.functional_addrs else None} "
                f"informational={'set' if res_proto.informational_addrs else None}")
            if res_proto.functional_addrs or res_proto.informational_addrs:
                parsed_successfully = True
        except Exception as e:
            dbg_exc("getlogin.parse[0]", e)

        if not parsed_successfully:
            for offset in range(min(128, len(response_content))):
                try:
                    candidate = thunderFF_pb2.GetLoginDataRes()
                    candidate.ParseFromString(response_content[offset:])
                    if candidate.functional_addrs or candidate.informational_addrs:
                        dbg("getlogin", f"parsed at offset={offset}")
                        res_proto = candidate
                        parsed_successfully = True
                        break
                except Exception:
                    pass

        dict_res = {}
        try:
            parsed = Parser().parse(response_content.hex())
            dict_res = await parse_results(parsed)
            dbg("getlogin", f"dict_res keys={list(dict_res.keys())[:20]}")
        except Exception as e:
            dbg_exc("getlogin.dict_parse", e)

        if not parsed_successfully:
            print_error(f"[getlogin] could not parse protobuf; "
                        f"first 200B hex={response_content[:300].hex()}")

        return res_proto, dict_res
    except Exception as e:
        dbg_exc("send_getlogin", e)
        return None


async def build_tcp_startup_packet(account_id, token, server_time, key, iv,
                                   region="BD", typ='OnLine'):
    uid_hex = f"{int(account_id):016x}"
    timestamp_hex = f"{int(server_time):08x}"
    encode_token = token.encode()
    encrypted_packet = (await aes_encrypt(encode_token, key, iv)).hex()
    encrypted_packet_length = f"{len(encrypted_packet) // 2:08x}"
    reg = str(region).upper() if region else "BD"
    if typ == 'OnLine':
        prefix = '7119' if reg == 'BD' else ('7114' if reg == 'IND' else '7115')
        return f"{prefix}{uid_hex}{timestamp_hex}00000000{encrypted_packet_length}{encrypted_packet}"
    else:
        prefix = '9219' if reg == 'BD' else ('9214' if reg == 'IND' else '9215')
        return f"{prefix}{uid_hex}{timestamp_hex}{encrypted_packet_length}{encrypted_packet}"


async def send_keep_alive(region="BD"):
    try:
        reg = str(region).upper() if region else "BD"
        ka_hex = "0219" if reg == "BD" else ("0214" if reg == "IND" else "0215")
        return bytes.fromhex(ka_hex)
    except Exception:
        return bytes.fromhex("0219")


async def start_game_lone_wolf(region, client_version, writer, key, iv):
    packet = bytes.fromhex("080112800a0a010b102b3a110a044944433110aa011a064555524f50453a100a044944433210311a064555524f504540014a0801090a0b1219202758016291090a8001303838463832424630324139363736373032303130313030303030303030303030303136303030313030313530303032323246393745454530463030303030303436373632353134303030303030303030303030303030303030303030303030303030303030303030303030303066663030303030303030636163666131366410241afb02735d5e571400024a775d45414d1a041b1c001f11010449715f4243481a001e1d071c1703004b1a4066785c524570735c51486775421b5c5a4c07504042685a63610816054e19025e75196001477c015165406370195f5547404e4550640103020f1304064863754268676c755f65576e40467e5f0a417a4701026d675d6e73670b1108495a4c6a0b78470b740065645e525a057258425f584a447d4e6759440c11044e7c596d7f4b625f7d04055a47505c4e1d6b5b4107447d7201057d7f0f14084e430457674f7e517d72015172415d027473577c4d615f79535256780911030f4d5e027a797f614165067806505d53777750475e75064257076500460817014e741e7e5078487e7a7c465e7669767153497064605a7376677773550d160148037e18675966787f4c42607a645f577e7b441b460776026b18685d0b110205490060020f70676175654674706671797f41067346677c4e06585e780f15074c57047b40517075415f6364027259674b5b0166407f7340600407770a22047a5d5c52300b3a0a167305067162727516134208312e3133302e3232480350015ae90403626253513635686e556f4e36416456324b796f566c636f477776484f624e56526c4d727073504b4f43654177616848494176795556497273743752737149734a7a786b3247525268377a2f637664626d504f6a73552f79626d38547a4c69586d2f474351696d494b53486833447955726f39515152756c34545350626d6d624b7949565937545671577059455372323646572f59624578507338514f706d317372785455736c30796a434144444d4f34616a654b615753366361496c554b4963797a494e396d52516f715277687939797257476d337a644345337a6a61436f492f5a585233656f65365a42647a64677654636b6b665733356e4d4c6a6a565072564b6433523172756174394e50514150724a5546627859696c4c5a3859707336654d5447666b6649793574666a526c314d4648706b51774c6373374439656378566c41636f374e664f6d2b30654756466c4434744478706771385533595973587645384842502f70666c767a737138316a32524f4d7857437556445442492f684735625462773166456e4249725162762b636144775147696f74554e316d4c4b77734379456f4766706746614251457645672b736a764c4c78704743334c304a5344532f74526169504354553344374e6249306547516651622f5a466f4c36455630775a324d6f583932414c572f5049752f56634663584e70596b356f7966326151416a536971486a2f363276354843644f525551303578754e6171795251625653704654303137655237675255636b4966366c6f447476342b514e4a4670766d74757077707774396a5a5974437a4b56743657726d6e36785837706658456251555434684f3758a201050803108703a201050804108103a20105080510c001a20105081d10cc01a2010408161078a20105080e10af01a201020815")
    proto = thunderFF_pb2.StartMatch()
    proto.ParseFromString(packet)
    if hasattr(proto.main, 'region_list') and len(proto.main.region_list) > 0:
        proto.main.region_list[0].region = region
        if len(proto.main.region_list) > 1:
            proto.main.region_list[1].region = region
    if hasattr(proto.main, 'client_version'):
        proto.main.client_version.remote_version = client_version
    packet = proto.SerializeToString()
    encrypted_packet = (await aes_encrypt(packet, key, iv)).hex()
    packet_length = len(encrypted_packet) // 2
    hex_length = hex(packet_length)[2:]
    hex_length = hex_length if len(hex_length) > 1 else "0" + hex_length
    final_packet = "031400" + "0" * (6 - len(hex_length)) + hex_length + encrypted_packet
    writer.write(bytes.fromhex(final_packet))
    await writer.drain()


async def has_ssan_zig(n):
    z = (n << 1) & 0xFFFFFFFFFFFFFFFF
    out = bytearray()
    while z >= 0x80:
        out.append((z & 0x7F) | 0x80)
        z >>= 7
    out.append(z)
    return bytes(out)


async def uleb_encode(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        out.append(b)
        if not n:
            break
    return bytes(out)


async def tea_enc(v0, v1, k0, k1, k2, k3):
    s = 0
    for _ in range(_ROUNDS):
        s = (s + _DELTA) & 0xFFFFFFFF
        v0 = (v0 + (((((v1 << 4) & 0xFFFFFFFF) + k0) & 0xFFFFFFFF ^
                      ((v1 + s) & 0xFFFFFFFF) ^
                      (((v1 >> 5) + k1) & 0xFFFFFFFF)))) & 0xFFFFFFFF
        v1 = (v1 + (((((v0 << 4) & 0xFFFFFFFF) + k2) & 0xFFFFFFFF ^
                      ((v0 + s) & 0xFFFFFFFF) ^
                      (((v0 >> 5) + k3) & 0xFFFFFFFF)))) & 0xFFFFFFFF
    return v0, v1


async def tea_dec(v0, v1, k0, k1, k2, k3):
    s = (_DELTA * _ROUNDS) & 0xFFFFFFFF
    for _ in range(_ROUNDS):
        v1 = (v1 - (((((v0 << 4) & 0xFFFFFFFF) + k2) & 0xFFFFFFFF ^
                      ((v0 + s) & 0xFFFFFFFF) ^
                      (((v0 >> 5) + k3) & 0xFFFFFFFF)))) & 0xFFFFFFFF
        v0 = (v0 - (((((v1 << 4) & 0xFFFFFFFF) + k0) & 0xFFFFFFFF ^
                      ((v1 + s) & 0xFFFFFFFF) ^
                      (((v1 >> 5) + k1) & 0xFFFFFFFF)))) & 0xFFFFFFFF
        s = (s - _DELTA) & 0xFFFFFFFF
    return v0, v1


async def tea_cbc_encrypt(padded, key_bytes):
    k0, k1, k2, k3 = (struct.unpack_from("<I", key_bytes, o)[0] for o in (0, 4, 8, 12))
    out = bytearray(len(padded))
    prev_cipher = bytearray(8)
    prev_intermediate = bytearray(8)
    for i in range(0, len(padded), 8):
        xored = bytearray(8)
        for j in range(8):
            xored[j] = padded[i + j] ^ prev_cipher[j]
        e0, e1 = await tea_enc(
            struct.unpack_from("<I", xored, 0)[0],
            struct.unpack_from("<I", xored, 4)[0],
            k0, k1, k2, k3,
        )
        enc = bytearray(8)
        struct.pack_into("<I", enc, 0, e0)
        struct.pack_into("<I", enc, 4, e1)
        for j in range(8):
            out[i + j] = enc[j] ^ prev_intermediate[j]
        prev_cipher[:] = out[i:i + 8]
        prev_intermediate[:] = xored
    return bytes(out)


async def build_padded(content):
    pad_len = (8 - (len(content) + 10) % 8) % 8
    return bytes([pad_len, 0, 0]) + b"\x00" * pad_len + content + b"\x00" * 7


async def encode_header(layout, send_option, cmd, order_id, flags, length, k, v80):
    out = bytearray()
    for code in layout:
        value = {0: send_option, 1: cmd, 2: order_id, 3: flags, 4: length}[code]
        if _FIELD_SIZES[code] == 1:
            out.append((value & 0xFF) ^ k)
        else:
            v = ((value & 0xFFFF) ^ v80) & 0xFFFF
            out.append(v & 0xFF)
            out.append((v >> 8) & 0xFF)
    return bytes(out)


async def crc7_buff(crc, buf):
    c = crc & 0x7F
    for b in buf:
        c = CRC7_TABLE[((2 * (c & 0xFF)) ^ (b & 0xFF)) & 0xFF] & 0x7F
    return c & 0x7F


async def sv_frame(msg_key, layout, send_option, cmd, order_id, flags, content, key, encrypted=True):
    k = key[0]
    v80 = ((k << 8) | k) & 0xFFFF
    body = await tea_cbc_encrypt(await build_padded(content), key) if encrypted else content
    hdr = bytearray([msg_key, 0]) + await encode_header(layout, send_option, cmd, order_id, flags, len(body), k, v80)
    packet = bytearray(hdr + body)
    packet[1] = await crc7_buff(0, bytes(packet[2:])) & 0x7F
    return bytes(packet)


async def build_match_startup_packets(token, udp_key, match_code, account_id, block_val,
                                      server_ip="", region="BD", client_version="1.132.6",
                                      client_version_code="2019121229", access_token=""):
    token = token.strip()
    udp_key = bytes.fromhex(udp_key)
    match_code = [int(ch) for ch in str(match_code).strip()]

    thunder_jwt = token[:660] if len(token) > 660 else token
    sharma_jwt = token[660:] if len(token) > 660 else ""
    encoded_thunder_jwt = thunder_jwt.encode() if isinstance(thunder_jwt, str) else thunder_jwt
    encoded_sharma_jwt = sharma_jwt.encode() if isinstance(sharma_jwt, str) else sharma_jwt

    garena420 = await has_ssan_zig(len(encoded_thunder_jwt)) + encoded_thunder_jwt

    reg = str(region).upper() if region else "BD"
    csoversea_block = bytes.fromhex(
        "ca0163736f7665727365612e7374726f6e67686f6c642e66726565666972656d6f62696c652e636f6d"
        "3b302e302e302e303b33342e3132362e37362e34353b33342e38372e3137372e31343b33342e38372e"
        "3137302e3233303b33352e3138352e3138332e35370000000000000100000000000000000000000001"
        "00000800000100000000000100a8a2d7bebd8d8bdf110200"
    )

    mid = bytes.fromhex('0000000001000102030101') + await has_ssan_zig(len(reg)) + reg.encode()
    mid += bytes.fromhex('0001030003000004')
    mid += await has_ssan_zig(len(client_version)) + client_version.encode()
    mid += await has_ssan_zig(len(client_version_code)) + client_version_code.encode()
    mid += csoversea_block

    clean_ip = server_ip.split(':')[0] if server_ip else "0.0.0.0"
    mid += await has_ssan_zig(len(clean_ip)) + clean_ip.encode()

    clean_acc_tok = access_token.strip() if access_token else ""
    if clean_acc_tok:
        mid += await has_ssan_zig(len(clean_acc_tok)) + clean_acc_tok.encode()

    mid += await has_ssan_zig(len(encoded_sharma_jwt)) + encoded_sharma_jwt

    tg_garena420 = (
        await uleb_encode(int(account_id)) +
        await uleb_encode(int(block_val)) +
        await uleb_encode(1) +
        await uleb_encode(43) +
        await uleb_encode(int(block_val)) +
        await uleb_encode(11) +
        mid
    )

    process = await sv_frame(0x5E, match_code, 2, 447, 0, 1, garena420, udp_key)
    loading = await sv_frame(0x5A, match_code, 2, 448, 1, 1, tg_garena420, udp_key)
    return process.hex(), loading.hex()


async def produce_xor_key(secret_key):
    k = secret_key[0] if secret_key and len(secret_key) > 0 else 10
    return k, ((k << 8) | k) & 0xFFFF


async def parse_layout(layout):
    if isinstance(layout, str):
        return [int(ch) for ch in layout.strip()]
    return list(layout)


async def tea_cbc_decrypt(body, key_bytes):
    k0, k1, k2, k3 = (struct.unpack_from("<I", key_bytes, o)[0] for o in (0, 4, 8, 12))
    out = bytearray(len(body))
    prev_intermediate = bytearray(8)
    prev_cipher = bytearray(8)
    xored = bytearray(8)
    dec = bytearray(8)
    for i in range(0, len(body), 8):
        for j in range(8):
            xored[j] = body[i + j] ^ prev_intermediate[j]
        d0, d1 = await tea_dec(
            struct.unpack_from("<I", xored, 0)[0],
            struct.unpack_from("<I", xored, 4)[0],
            k0, k1, k2, k3
        )
        struct.pack_into("<I", dec, 0, d0)
        struct.pack_into("<I", dec, 4, d1)
        for j in range(8):
            out[i + j] = dec[j] ^ prev_cipher[j]
        prev_cipher[:] = body[i:i + 8]
        prev_intermediate[:] = dec
    return bytes(out)


async def build_hello_packet(text, key, layout):
    data = text.encode("utf-8")
    if len(data) > 25:
        raise ValueError(f"Text is too long ({len(data)} bytes)")
    content = b"\x10\x00\x00\x00" + data + b"\x00" * (29 - 4 - len(data))
    k, v80 = await produce_xor_key(key)
    layout = await parse_layout(layout)
    padded = await build_padded(content)
    enc_body = await tea_cbc_encrypt(padded, key)
    header_bytes = await encode_header(layout, 1, 1, 0, 1, len(enc_body), k, v80)
    packet = bytearray([0x63, 0x00]) + header_bytes + enc_body
    packet[1] = await crc7_buff(0, packet[2:]) & 0x7F
    return bytes(packet).hex()


async def classify(frame):
    cmd = frame["cmd"]
    msg_name = MESSAGE_ID_TO_NAME.get(cmd, f"UNKNOWN_{cmd}")
    if msg_name == "UDP_HELLO":
        return "HELLO"
    if msg_name == "UDP_ACK":
        return "ACK"
    if msg_name == "UDP_PING":
        return "PING"
    if msg_name == "RUDP_JOIN_MATCH":
        return "JOIN_MATCH"
    if msg_name.startswith("RUDP_"):
        return msg_name
    if msg_name.startswith("UDP_"):
        return msg_name
    return "DATA"


async def build_packet(msg_key, layout, send_option, cmd, order_id, flags, content, key, encrypted=True):
    k = key[0]
    v80 = ((k << 8) | k) & 0xFFFF
    body = await tea_cbc_encrypt(await build_padded(content), key) if encrypted else content
    hdr = bytearray([msg_key, 0])
    for code in layout:
        value = {0: send_option, 1: cmd, 2: order_id, 3: flags, 4: len(body)}[code]
        if _FIELD_SIZES[code] == 1:
            hdr.append((value & 0xFF) ^ k)
        else:
            v = ((value & 0xFFFF) ^ v80) & 0xFFFF
            hdr.append(v & 0xFF)
            hdr.append((v >> 8) & 0xFF)
    packet = bytearray(hdr + body)
    packet[1] = await crc7_buff(0, bytes(packet[2:])) & 0x7F
    return bytes(packet)


async def layouts_from_mask(mask):
    ru = [int(c) for c in str(mask).strip()]
    nr = [c for c in ru if c != 2]
    return ru, nr


async def reply_for(frame, key, mask, ack_key=0x68, ping_key=0x6D, hello_key=0x5B, ack_style="short"):
    ru, nr = await layouts_from_mask(mask)
    typ = await classify(frame)
    if typ == "HELLO":
        if ack_style == "echo":
            content = frame["content"] if frame["content"] else b"\x10\x00\x00\x00"
            return typ, await build_packet(hello_key, nr, 1, 1, None, 1, content, key)
        return typ, await build_packet(ack_key, nr, 0, 2, None, 1, b"\x01\x00", key)
    if typ == "ACK":
        content = frame["content"] if frame["content"] else b"\x01\x00"
        return typ, await build_packet(ack_key, nr, 0, 2, None, 1, content, key)
    if typ == "PING":
        c = frame["content"]
        counter = c[:4] if len(c) >= 4 else c
        return typ, await build_packet(ping_key, nr, 0, 3, None, 0, counter + b"\x00\x00\x00", key, encrypted=False)
    if typ == "JOIN_MATCH":
        return typ, await build_packet(ack_key, nr, 0, 2, None, 1, b"\x02\x00", key)
    return typ, None


async def keepalive_ping(sock, ip, port, key_bytes, mask, stop_event):
    nr = (await layouts_from_mask(mask))[1]
    ping_keys = [0x66, 0x6D, 0x69, 0x6C, 0x6B, 0x6E, 0x6F, 0x70]
    loop = asyncio.get_event_loop()
    i = 0
    while not stop_event.is_set():
        pk = ping_keys[i % len(ping_keys)]
        counter = int(time.time() * 1000) & 0xFFFFFFFF
        pkt = await build_packet(pk, nr, 0, 3, None, 0, struct.pack("<I", counter) + b"\x00\x00\x00", key_bytes, encrypted=False)
        try:
            await loop.sock_sendto(sock, pkt, (ip, port))
        except Exception:
            pass
        i += 1
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=3.0)
        except asyncio.TimeoutError:
            pass


async def try_header(buf, layout, k, v80):
    off = 2
    out = {}
    for code in layout:
        size = _FIELD_SIZES[code]
        if off + size > len(buf):
            return None
        out[_FIELD_NAMES[code]] = (buf[off] ^ k) if size == 1 else ((buf[off] | (buf[off + 1] << 8)) ^ v80) & 0xFFFF
        off += size
    out["headerLen"] = off
    return out


async def oicq_unpad(padded):
    if not padded or len(padded) < 8:
        return None
    if not all(padded[-1 - i] == 0 for i in range(7)):
        return None
    pad_len = padded[0] & 0x07
    s = 3 + pad_len
    e = len(padded) - 7
    return padded[s:e] if s < e else b""


async def decode_packet(packet, key, mask=None):
    data = bytes(packet) if isinstance(packet, bytes) else bytes.fromhex(packet)
    if len(data) < 8:
        return None
    k = key[0]
    v80 = ((k << 8) | k) & 0xFFFF
    crc_ok = (data[1] & 0x7F) == await crc7_buff(0, data[2:])
    candidates = []
    if mask:
        ru, nr = await layouts_from_mask(mask)
        layouts = [("RUDP", ru), ("nonRUDP", nr)]
    else:
        layouts = [("RUDP", list(p)) for p in itertools.permutations([0, 1, 2, 3, 4])]
        layouts += [("nonRUDP", list(p)) for p in itertools.permutations([0, 1, 3, 4])]
    for kind, layout in layouts:
        f = await try_header(data, layout, k, v80)
        if not f:
            continue
        if f["flags"] > 7 or f["sendOption"] > 7:
            continue
        if f["length"] != len(data) - f["headerLen"]:
            continue
        body = data[f["headerLen"]:f["headerLen"] + f["length"]]
        content = None
        padded = None
        if f["flags"] & 1:
            if len(body) < 8 or len(body) % 8 != 0:
                continue
            padded = await tea_cbc_decrypt(body, key)
            content = await oicq_unpad(padded)
            if content is None:
                continue
        else:
            content = body
        score = (1 if crc_ok else 0) + (1 if content is not None else 0)
        candidates.append({
            "kind": kind, "layout": layout, "headerLen": f["headerLen"],
            "msgKey": data[0], "cmd": f["cmd"], "flags": f["flags"],
            "sendOption": f["sendOption"], "orderId": f.get("orderId"),
            "length": f["length"], "content": content, "crcOk": crc_ok,
            "padded": padded, "score": score, "total": len(data),
        })
    if not candidates:
        return None
    candidates.sort(key=lambda c: (c["kind"] == "RUDP" or c["kind"] == "nonRUDP", c["score"]), reverse=True)
    return candidates[0]


# ============================================================
# play_game — UDP MATCH
# ============================================================
async def play_game(server_ip_port, thunder, sharma, udp_key, match_code,
                    account_id, player_region, client_version, key, iv,
                    match_index: int, state_uid: Optional[str] = None):
    match_start_time = time.time()
    ping_task = None
    sock = None
    ping_stop = asyncio.Event()
    uid_str = str(state_uid) if state_uid else str(account_id)
    completed_cleanly = False

    try:
        ip, port = server_ip_port.split(":")
        port = int(port)
        resolved_ip = await resolve_host_cloudflare(ip)

        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        optimize_udp_socket(sock)
        sock.setblocking(False)

        udp_key_bytes = bytes.fromhex(udp_key)
        hello_packet = await build_hello_packet(f"{account_id}_2585", udp_key_bytes, match_code)
        await loop.sock_sendto(sock, bytes.fromhex(hello_packet), (resolved_ip, port))

        ack_state = "waiting_for_hello_reply"
        thunder_sent = False
        sharma_sent = False
        join_match_received = False
        local_closed = False
        send_lock = asyncio.Lock()

        ping_task = asyncio.create_task(
            keepalive_ping(sock, resolved_ip, port, udp_key_bytes, match_code, ping_stop)
        )
        last_activity = time.time()
        MAX_IDLE_BEFORE_HELLO_RESEND = 7.0

        print_colored(
            f"🎮 [MATCH #{match_index}] UDP started → {server_ip_port} (DNS: {resolved_ip})",
            Colors.MAGENTA
        )

        async def send_thunder_sharma_inline():
            nonlocal ack_state, thunder_sent, sharma_sent
            if thunder_sent:
                return
            async with send_lock:
                if thunder_sent:
                    return
                try:
                    await loop.sock_sendto(sock, bytes.fromhex(thunder), (resolved_ip, port))
                    thunder_sent = True
                    await asyncio.sleep(0.1)
                    prepare_ack = await build_packet(
                        0x68, (await layouts_from_mask(match_code))[1],
                        0, 2, None, 1, b"\x01\x00", udp_key_bytes
                    )
                    await loop.sock_sendto(sock, prepare_ack, (resolved_ip, port))
                    await asyncio.sleep(0.2)
                    await loop.sock_sendto(sock, bytes.fromhex(sharma), (resolved_ip, port))
                    sharma_sent = True
                    ack_state = "thunder_sharma_sent"
                    print_success(f"[MATCH #{match_index}] Thunder+Sharma sent!")
                except Exception as e:
                    print_error(f"[MATCH #{match_index}] send error: {e}")

        while not local_closed:
            if time.time() - match_start_time > MAX_MATCH_DURATION:
                break
            try:
                response, server_addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 65535), timeout=1.5
                )
                if response:
                    last_activity = time.time()
                    frame = await decode_packet(response, udp_key_bytes, match_code)
                    if frame:
                        ptype = await classify(frame)

                        if frame['cmd'] in [103, 107]:
                            print_success(
                                f"[MATCH #{match_index}] Completed (cmd {frame['cmd']})"
                            )
                            completed_cleanly = True
                            local_closed = True
                            continue

                        if frame['cmd'] == 101:
                            try:
                                ack_pkt = await build_packet(
                                    0x68, (await layouts_from_mask(match_code))[1],
                                    0, 2, None, 1, b"\x01\x00", udp_key_bytes
                                )
                                await loop.sock_sendto(sock, ack_pkt, server_addr)
                            except Exception:
                                pass
                            continue

                        if ptype in ["ACK", "PING", "HELLO", "JOIN_MATCH"]:
                            if ptype == "HELLO" and ack_state == "waiting_for_hello_reply":
                                typ, reply = await reply_for(
                                    frame, udp_key_bytes, match_code, ack_style="short"
                                )
                                if reply:
                                    await loop.sock_sendto(sock, reply, server_addr)
                                ack_state = "ack_sent_waiting"
                            elif ptype == "ACK":
                                if ack_state == "waiting_for_hello_reply":
                                    typ, reply = await reply_for(frame, udp_key_bytes, match_code)
                                    if reply:
                                        await loop.sock_sendto(sock, reply, server_addr)
                                    ack_state = "ready_to_send_thunder"
                                elif ack_state == "ack_sent_waiting":
                                    ack_state = "ready_to_send_thunder"
                                else:
                                    typ, reply = await reply_for(frame, udp_key_bytes, match_code)
                                    if reply:
                                        await loop.sock_sendto(sock, reply, server_addr)
                            elif ptype == "PING":
                                typ, reply = await reply_for(frame, udp_key_bytes, match_code)
                                if reply:
                                    await loop.sock_sendto(sock, reply, server_addr)
                            elif ptype == "JOIN_MATCH" and not join_match_received:
                                typ, reply = await reply_for(frame, udp_key_bytes, match_code)
                                if reply:
                                    await loop.sock_sendto(sock, reply, server_addr)
                                    join_match_received = True
            except asyncio.TimeoutError:
                if ack_state == "ready_to_send_thunder" and not thunder_sent:
                    await send_thunder_sharma_inline()
                elif ack_state == "waiting_for_hello_reply":
                    if (time.time() - last_activity) > MAX_IDLE_BEFORE_HELLO_RESEND:
                        try:
                            pkt = await build_hello_packet(
                                f"{account_id}_2585", udp_key_bytes, match_code
                            )
                            await loop.sock_sendto(sock, bytes.fromhex(pkt), (resolved_ip, port))
                        except Exception:
                            pass
                        last_activity = time.time()
                    if (time.time() - match_start_time) > 25.0:
                        print_warning(f"[MATCH #{match_index}] Handshake timeout")
                        break
                elif ack_state == "thunder_sharma_sent":
                    if (time.time() - last_activity) > MATCH_IDLE_TIMEOUT:
                        print_success(f"[MATCH #{match_index}] Finished naturally")
                        completed_cleanly = True
                        break
                continue
            except BlockingIOError:
                await asyncio.sleep(0.05)
            except OSError:
                await asyncio.sleep(0.5)
                continue
            except Exception:
                await asyncio.sleep(0.5)
                continue

            if ack_state == "ready_to_send_thunder" and not thunder_sent:
                await send_thunder_sharma_inline()

        return f"match #{match_index} finished"
    except Exception as e:
        print_error(f"[MATCH #{match_index}] error: {e}")
        return f"match #{match_index} error"
    finally:
        if completed_cleanly:
            try:
                bot_state.increment_match(uid_str)
            except Exception:
                pass
        ping_stop.set()
        if ping_task:
            ping_task.cancel()
            try:
                await ping_task
            except asyncio.CancelledError:
                pass
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        remaining = await _dec_match(uid_str)
        total = await _get_total_match_count()
        print_info(
            f"[MATCH #{match_index}] Closed. "
            f"UID {uid_str} active: {remaining} | Total active: {total}"
        )
        try:
            bot_state.update_status(uid_str, "IN_MATCH" if remaining > 0 else "ONLINE", remaining)
        except Exception:
            pass


# ============================================================
# functional_lone_wolf
# ============================================================
async def functional_lone_wolf(addrs, starter_packet, account_region, client_version,
                                key, iv, account_id="", account_data=None,
                                max_reconnects=10):
    reconnects = 0
    ip, port = addrs.split(":")
    play_matches: List[asyncio.Task] = []
    no_response_count = 0
    search_attempts = 0
    last_start_time = 0.0
    uid_str = str(account_id)
    pause_ev = get_pause_event(uid_str)

    consecutive_parse_failures = 0
    last_match_found_time = time.time()
    last_keepalive_time = 0.0
    last_stop_reason_logged = ""

    current_token = starter_packet
    current_key = key
    current_iv = iv
    current_account_data = account_data

    try:
        while True:
            writer = None
            try:
                if current_account_data:
                    fresh = None
                    if current_account_data.get('auth_type') == 'guest' and current_account_data.get('auth_uid'):
                        fresh = cache_get(str(current_account_data['auth_uid']))
                    elif current_account_data.get('auth_type') == 'token' and current_account_data.get('auth_token'):
                        fresh = cache_get(f"tok_{current_account_data['auth_token'][:20]}")

                    if fresh:
                        current_account_data = fresh
                        current_key = fresh['aes_ak']
                        current_iv = fresh['iv_i']
                        current_token = await build_tcp_startup_packet(
                            fresh['account_id'],
                            fresh['token'],
                            fresh['server_time'],
                            current_key,
                            current_iv,
                            region=fresh.get('region', account_region),
                            typ='OnLine'
                        )
                    else:
                        print_warning(f"[FUNCTIONAL] Cache miss for {uid_str} → re-login needed")
                        try:
                            if current_account_data.get('auth_uid'):
                                cache_invalidate(str(current_account_data['auth_uid']))
                            if current_account_data.get('auth_token'):
                                cache_invalidate(f"tok_{current_account_data['auth_token'][:20]}")
                        except Exception:
                            pass
                        raise ConnectionError("Cache expired, triggering fresh login")

                resolved_ip = await resolve_host_cloudflare(ip)
                reader, writer = await asyncio.open_connection(resolved_ip, int(port))

                raw_sock = writer.get_extra_info('socket')
                if raw_sock:
                    optimize_tcp_socket(raw_sock)

                writer.write(bytes.fromhex(current_token))
                await writer.drain()

                try:
                    init_ka = await send_keep_alive(account_region)
                    if init_ka and writer and not writer.is_closing():
                        writer.write(init_ka)
                        await asyncio.wait_for(writer.drain(), timeout=3)
                except Exception:
                    pass

                print_success(f"[FUNCTIONAL] TCP Gateway Connected for UID: {uid_str} (DNS: {resolved_ip})")
                reconnects = 0
                no_response_count = 0
                last_start_time = 0.0

                async def send_start_match():
                    nonlocal search_attempts, last_start_time
                    search_attempts += 1
                    current_region = "BD"
                    print_info(f"[LONE WOLF] Sending StartMatch #{search_attempts} region: {current_region}")
                    try:
                        await asyncio.sleep(random.uniform(0.3, 0.6))
                        await start_game_lone_wolf(
                            current_region, client_version, writer,
                            current_key, current_iv
                        )
                        print_success("[LONE WOLF] StartMatch packet sent")
                        active = await _get_match_count(uid_str)
                        try:
                            bot_state.update_status(uid_str, "SEARCHING", active)
                        except Exception:
                            pass
                    except Exception as e:
                        print_error(f"start_game_lone_wolf error: {e}")
                    last_start_time = asyncio.get_running_loop().time()

                await send_start_match()

                while True:
                    play_matches[:] = [m for m in play_matches if not m.done()]
                    active_count = await _get_match_count(uid_str)

                    manual_paused = not pause_ev.is_set()
                    daily_cap = await is_cap_reached(uid_str)

                    acc = bot_state.accounts.get(uid_str, {})
                    target_lvl = int(acc.get('target_level', 0) or 0)
                    cur_lvl = int(acc.get('level', 1) or 1)
                    target_lvl_hit = target_lvl > 0 and cur_lvl >= target_lvl

                    target_mt = int(acc.get('target_matches', 0) or 0)
                    cur_mt = int(acc.get('matches_played', 0) or 0)
                    target_mt_hit = target_mt > 0 and cur_mt >= target_mt

                    stop_new = manual_paused or daily_cap or target_lvl_hit or target_mt_hit

                    if active_count > 0:
                        if stop_new:
                            new_status = "FINISHING"
                            new_reason = (
                                "PAUSED" if manual_paused
                                else "CAPPED" if daily_cap
                                else "TARGET_LV" if target_lvl_hit
                                else "TARGET_MT"
                            )
                        else:
                            new_status = "IN_MATCH"
                            new_reason = ""
                    else:
                        if manual_paused:
                            new_status = "PAUSED";  new_reason = "PAUSED"
                        elif daily_cap:
                            new_status = "CAPPED";  new_reason = "CAPPED"
                        elif target_lvl_hit:
                            new_status = "TARGET_LV"; new_reason = "TARGET_LV"
                        elif target_mt_hit:
                            new_status = "TARGET_MT"; new_reason = "TARGET_MT"
                        else:
                            new_status = "ONLINE"; new_reason = ""

                    try:
                        bot_state.update_status(uid_str, new_status, active_count)
                        if uid_str in bot_state.accounts:
                            bot_state.accounts[uid_str]["stop_reason"] = new_reason
                    except Exception:
                        pass

                    if new_reason != last_stop_reason_logged:
                        if new_reason == "PAUSED":
                            print_warning(f"[PAUSE] {uid_str} manually paused")
                        elif new_reason == "CAPPED":
                            print_warning(
                                f"[CAP] {uid_str} hit daily {DAILY_EXP_CAP} EXP — "
                                f"no new matches, waiting for running to finish"
                            )
                        elif new_reason == "TARGET_LV":
                            print_success(
                                f"[TARGET] {uid_str} reached Level {target_lvl} — "
                                f"no new matches, waiting for running to finish"
                            )
                        elif new_reason == "TARGET_MT":
                            print_success(
                                f"[TARGET] {uid_str} reached {target_mt} matches — "
                                f"no new matches, waiting for running to finish"
                            )
                        last_stop_reason_logged = new_reason

                    if not stop_new and (time.time() - last_match_found_time > NO_MATCH_RESTART_TIMEOUT):
                        print_warning(
                            f"[FUNCTIONAL] No match in {NO_MATCH_RESTART_TIMEOUT}s for {uid_str}. "
                            f"Forcing fresh reconnect..."
                        )
                        raise ConnectionError("No match timeout - forcing restart")

                    now = asyncio.get_running_loop().time()
                    if not stop_new and (now - last_start_time >= START_MATCH_INTERVAL):
                        await send_start_match()

                    if stop_new and (now - last_keepalive_time > 5.0):
                        try:
                            ka = await send_keep_alive(account_region)
                            if ka and writer and not writer.is_closing():
                                writer.write(ka)
                                await writer.drain()
                                last_keepalive_time = now
                        except Exception:
                            pass

                    try:
                        data = await asyncio.wait_for(reader.read(8192), timeout=0.5)
                    except asyncio.TimeoutError:
                        no_response_count += 1
                        if no_response_count > 80:
                            print_warning(f"[FUNCTIONAL] Gateway silent ({uid_str}). Reconnecting...")
                            raise ConnectionError("Gateway idle timeout")
                        continue

                    if not data:
                        raise ConnectionError("Connection closed by server")

                    hex_data = data.hex()
                    packet_length = len(data)
                    no_response_count = 0

                    if hex_data.startswith("0300") and 10 < packet_length < 30:
                        print_info("Match starting, please wait...")
                        continue

                    if hex_data.startswith("0300") and packet_length >= 300:
                        if stop_new:
                            try:
                                writer.close()
                                await writer.wait_closed()
                            except Exception:
                                pass
                            print_info(f"[FUNCTIONAL] Idle — dropping match payload for {uid_str}")
                            await asyncio.sleep(NON_MATCH_RECONNECT_DELAY)
                            break

                        print_colored("=" * 60, Colors.GREEN)
                        print_colored(f"MATCH FOUND! Loading...", Colors.GREEN)
                        print_colored("=" * 60, Colors.GREEN)

                        try:
                            res = json.loads(await decode_protobuf(hex_data[10:]))
                            token = None
                            udp_key = None
                            match_code = None
                            server_ip_port = None
                            match_account_id = None
                            block_val = None

                            if '42' in res and 'data' in res['42']:
                                match_code = res['42']['data']
                            if '5' in res and 'data' in res['5']:
                                res_field5 = res['5']['data']
                                server_ip_port = res_field5.get('2', {}).get('data')
                                udp_key = res_field5.get('3', {}).get('data')
                                token = res_field5.get('4', {}).get('data')
                                if '42' in res_field5:
                                    match_code = res_field5['42']['data']
                            if '1' in res and 'data' in res['1']:
                                match_account_id = res['1']['data']
                            if '5' in res and 'data' in res['5']:
                                block_val = res['5']['data'].get('1', {}).get('data')

                            effective_acc_id = match_account_id or account_id or "BD_BOT"

                            if token and udp_key and match_code and server_ip_port:
                                acc_tok = ""
                                if current_account_data:
                                    acc_tok = current_account_data.get('access_token', '') or ""
                                thunder, sharma = await build_match_startup_packets(
                                    token, udp_key, match_code, effective_acc_id, block_val or 0,
                                    server_ip=server_ip_port,
                                    region=account_region,
                                    client_version=client_version,
                                    access_token=acc_tok
                                )

                                match_index = await _inc_match(uid_str)
                                total = await _get_total_match_count()
                                print_colored(
                                    f"🚀 [MATCH #{match_index}] UDP starting → {server_ip_port} (background)",
                                    Colors.CYAN
                                )
                                print_success(
                                    f"[FUNCTIONAL] UDP task started. "
                                    f"UID active: {match_index} | Total: {total}"
                                )

                                new_match = asyncio.create_task(
                                    play_game(
                                        server_ip_port,
                                        thunder,
                                        sharma,
                                        udp_key,
                                        match_code,
                                        effective_acc_id,
                                        "BD",
                                        client_version,
                                        current_key,
                                        current_iv,
                                        match_index=match_index,
                                        state_uid=uid_str,
                                    )
                                )
                                play_matches.append(new_match)

                                consecutive_parse_failures = 0
                                last_match_found_time = time.time()

                                try:
                                    writer.close()
                                    await writer.wait_closed()
                                except Exception:
                                    pass

                                print_info(
                                    f"[OFFLINE] {NEW_MATCH_DELAY}s offline → "
                                    f"reload token → new StartMatch"
                                )
                                await asyncio.sleep(NEW_MATCH_DELAY)
                                reconnects = 0
                                break

                            else:
                                consecutive_parse_failures += 1
                                print_warning(
                                    f"[FUNCTIONAL] Non-match big packet "
                                    f"(#{consecutive_parse_failures}/{MAX_CONSECUTIVE_PARSE_FAILURES}) "
                                    f"→ reconnecting"
                                )

                                if consecutive_parse_failures >= MAX_CONSECUTIVE_PARSE_FAILURES:
                                    print_error(
                                        f"[FUNCTIONAL] {MAX_CONSECUTIVE_PARSE_FAILURES}x parse failures "
                                        f"→ invalidating cache for fresh login"
                                    )
                                    if current_account_data:
                                        try:
                                            if current_account_data.get('auth_uid'):
                                                cache_invalidate(str(current_account_data['auth_uid']))
                                            if current_account_data.get('auth_token'):
                                                cache_invalidate(f"tok_{current_account_data['auth_token'][:20]}")
                                        except Exception:
                                            pass
                                    consecutive_parse_failures = 0

                                try:
                                    writer.close()
                                    await writer.wait_closed()
                                except Exception:
                                    pass
                                await asyncio.sleep(NON_MATCH_RECONNECT_DELAY)
                                break

                        except Exception as e:
                            print_error(f"[FUNCTIONAL] Match packet error: {e}")
                            consecutive_parse_failures += 1
                            if consecutive_parse_failures >= MAX_CONSECUTIVE_PARSE_FAILURES:
                                if current_account_data:
                                    try:
                                        if current_account_data.get('auth_uid'):
                                            cache_invalidate(str(current_account_data['auth_uid']))
                                        if current_account_data.get('auth_token'):
                                            cache_invalidate(f"tok_{current_account_data['auth_token'][:20]}")
                                    except Exception:
                                        pass
                                consecutive_parse_failures = 0
                            try:
                                writer.close()
                                await writer.wait_closed()
                            except Exception:
                                pass
                            await asyncio.sleep(NON_MATCH_RECONNECT_DELAY)
                            break

                    if 30 <= packet_length <= 40:
                        continue

            except asyncio.CancelledError:
                print_warning(f"[FUNCTIONAL] Cancelled — cancelling {len(play_matches)} UDP matches")
                for m in play_matches:
                    if not m.done():
                        m.cancel()
                if play_matches:
                    await asyncio.gather(*play_matches, return_exceptions=True)
                play_matches.clear()
                raise
            except Exception as e:
                print_error(f"[FUNCTIONAL] TCP state ({uid_str}): {e}")

                play_matches[:] = [m for m in play_matches if not m.done()]

                if writer:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

                if "Cache expired" in str(e):
                    print_warning(f"[FUNCTIONAL] Triggering re-login for {uid_str}")
                    break

                reconnects += 1
                if reconnects > max_reconnects:
                    print_error("[FUNCTIONAL] Max reconnects reached, retrying...")
                    reconnects = 0
                    await asyncio.sleep(3)
                    continue

                await asyncio.sleep(min(reconnects, 2))

    except asyncio.CancelledError:
        print_warning(f"[FUNCTIONAL] Outer cancelled. {len(play_matches)} UDP matches still running.")
        for m in play_matches:
            if not m.done():
                m.cancel()
        if play_matches:
            await asyncio.gather(*play_matches, return_exceptions=True)
        play_matches.clear()
        raise


async def informational(addrs, starter_packet, key, iv, region="BD", max_reconnects=3):
    reconnects = 0
    ip, port = addrs.split(":")
    while True:
        writer = None
        ping_task = None
        try:
            resolved_ip = await resolve_host_cloudflare(ip)
            reader, writer = await asyncio.open_connection(resolved_ip, int(port))

            raw_sock = writer.get_extra_info('socket')
            if raw_sock:
                optimize_tcp_socket(raw_sock)

            writer.write(bytes.fromhex(starter_packet))
            await writer.drain()
            reconnects = 0

            try:
                init_ka = await send_keep_alive(region)
                if init_ka and writer and not writer.is_closing():
                    writer.write(init_ka)
                    await asyncio.wait_for(writer.drain(), timeout=3)
            except Exception:
                pass

            async def info_keepalive():
                ka_bytes = await send_keep_alive(region)
                while True:
                    await asyncio.sleep(5)
                    try:
                        if writer and not writer.is_closing():
                            writer.write(ka_bytes)
                            await writer.drain()
                    except Exception:
                        break

            ping_task = asyncio.create_task(info_keepalive())

            while True:
                data = await reader.read(8192)
                if not data:
                    raise ConnectionError("Connection closed")
        except asyncio.CancelledError:
            if ping_task:
                ping_task.cancel()
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
            raise
        except Exception:
            if ping_task:
                ping_task.cancel()
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
            reconnects += 1
            if reconnects > max_reconnects:
                await asyncio.sleep(3)
                reconnects = 0
            else:
                await asyncio.sleep(1)


# ==================== ACCOUNT PROCESSORS ====================
def _register_credentials(account_data: Dict):
    try:
        acc_id = str(account_data['account_id'])
        bot_state.account_credentials[acc_id] = account_data
        if account_data.get('auth_uid'):
            bot_state.account_credentials[str(account_data['auth_uid'])] = account_data
        if account_data.get('auth_token'):
            bot_state.account_credentials[f"tok_{account_data['auth_token'][:20]}"] = account_data
    except Exception:
        pass


async def refresh_account_profile(account_data_or_uid: Any):
    try:
        if isinstance(account_data_or_uid, str):
            uid = str(account_data_or_uid)
            account_data = bot_state.account_credentials.get(uid)
        else:
            account_data = account_data_or_uid
            uid = str(account_data.get('account_id'))

        if not account_data:
            return

        url = account_data.get('server_url')
        token = account_data.get('token')
        release_version = account_data.get('release_version')
        payload = account_data.get('login_payload_data')

        if not (url and token and release_version and payload):
            return

        res = await send_getlogin(payload, url, token, release_version)
        if res:
            res_proto, dict_res = res
            level = int(get_proto_field(dict_res, 6, 1))
            exp = int(get_proto_field(dict_res, 7, 0))
            likes = int(get_proto_field(dict_res, 8, 0))
            nickname = res_proto.nickname or get_proto_field(dict_res, 4, "")

            acc_id = str(account_data['account_id'])

            acc = bot_state.accounts.get(acc_id)
            if acc:
                old_exp = int(acc.get('current_exp', exp) or 0)
                if exp > old_exp:
                    gained = exp - old_exp
                    try:
                        new_total = await add_daily_exp(acc_id, gained)
                        remaining = max(0, DAILY_EXP_CAP - new_total)
                        if new_total >= DAILY_EXP_CAP:
                            bot_state.log(
                                f"🛑 Daily cap {DAILY_EXP_CAP} reached for {acc_id} "
                                f"(+{gained}) — matches will stop",
                                "warning", acc_id
                            )
                        else:
                            bot_state.log(
                                f"📅 Daily EXP {new_total}/{DAILY_EXP_CAP} "
                                f"(+{gained}, {remaining} left)",
                                "info", acc_id
                            )
                    except Exception as e:
                        print_error(f"daily exp update error: {e}")

            if exp > 0:
                bot_state.update_exp(acc_id, exp, level)
            if likes > 0 and acc_id in bot_state.accounts:
                bot_state.accounts[acc_id]["likes"] = likes
            if nickname and acc_id in bot_state.accounts:
                bot_state.accounts[acc_id]["nickname"] = nickname
            print_info(f"[EXP-REFRESH] UID {acc_id} -> Level: {level}, EXP: {exp}")
    except Exception as e:
        print_error(f"refresh_account_profile error: {e}")


async def process_account_uid_pass(uid: str, password: str, target_level: int = 0,
                                    target_matches: int = 0) -> Optional[Dict]:
    dbg("login_guest", f"START uid={uid} target_lvl={target_level} target_mt={target_matches}")
    cached = cache_get(uid)
    if cached:
        print_success(f"[CACHE HIT] UID {uid} loaded from token_cache.json (no login)")
        acc_id = str(cached['account_id'])
        bot_state.register_account(
            uid=acc_id,
            nickname=cached.get('nickname', f"Player_{acc_id}"),
            region=cached.get('region', 'BD'),
            level=cached.get('level', 1),
            exp=cached.get('exp', 0),
            likes=cached.get('likes', 0),
            target_level=target_level,
            target_matches=target_matches,
        )
        _register_credentials(cached)
        return cached

    print_info(f"[LOGIN] Full login for UID {uid}...")
    try:
        dbg("login_guest", "step 1/5 → version_config")
        verconfig_res = await version_config()
        if verconfig_res is None:
            print_error("[login_guest] version_config FAILED")
            return None
        (release_version, client_version, server_url,
         device_whitelist_version, vercfg_sign) = verconfig_res
        dbg("login_guest",
            f"version_config OK release={release_version} client_ver={client_version} "
            f"server_url={server_url} whitelist={device_whitelist_version} sign={vercfg_sign}")

        dbg("login_guest", "step 2/5 → get_access_token")
        tokengrant_response = await get_access_token(uid, password)
        if tokengrant_response is None:
            print_error("[login_guest] get_access_token FAILED")
            return None
        open_id, access_token, platform = tokengrant_response
        dbg("login_guest", f"access_token OK open_id={open_id[:12]}… platform={platform}")

        dbg("login_guest", "step 3/5 → build_majorlogin_payload")
        device_info = get_device_for_account(uid)
        login_payload_data = await build_majorlogin_payload(
            open_id, access_token, platform, client_version, device_info,
            whitelist_version=device_whitelist_version,
            vercfg_sign=vercfg_sign
        )
        if not login_payload_data:
            print_error("[login_guest] build_majorlogin_payload FAILED")
            return None
        dbg("login_guest", f"majorlogin payload OK len={len(login_payload_data)}")

        dbg("login_guest", "step 4/5 → send_majorlogin")
        majorlogin_response = await send_majorlogin(
            login_payload_data, release_version, server_url
        )
        if majorlogin_response is None:
            print_error("[login_guest] send_majorlogin FAILED")
            return None
        dbg("login_guest",
            f"MajorLogin OK account_id={majorlogin_response.account_id} "
            f"region={majorlogin_response.region} url={majorlogin_response.url}")

        dbg("login_guest", "step 5/5 → send_getlogin")
        getlogin_result = await send_getlogin(
            login_payload_data, majorlogin_response.url,
            majorlogin_response.token, release_version
        )
        if getlogin_result is None:
            print_error("[login_guest] send_getlogin FAILED")
            return None
        res_proto, dict_res = getlogin_result
        dbg("login_guest", f"GetLoginData OK nickname={res_proto.nickname!r}")

        acc_id = str(majorlogin_response.account_id)
        level = int(get_proto_field(dict_res, 6, 1))
        exp = int(get_proto_field(dict_res, 7, 0))
        likes = int(get_proto_field(dict_res, 8, 0))
        nickname = res_proto.nickname or get_proto_field(dict_res, 4, f"Player_{acc_id}")
        region = majorlogin_response.region or get_proto_field(dict_res, 3, "BD")
        dbg("login_guest",
            f"parsed: acc_id={acc_id} nickname={nickname!r} region={region} "
            f"level={level} exp={exp} likes={likes}")

        bot_state.register_account(
            uid=acc_id, nickname=nickname, region=region,
            level=level, exp=exp, likes=likes,
            target_level=target_level, target_matches=target_matches,
        )

        account_data = {
            'account_id': majorlogin_response.account_id,
            'nickname': nickname,
            'region': region,
            'level': level,
            'exp': exp,
            'likes': likes,
            'open_id': open_id,
            'access_token': access_token,
            'platform': str(platform),
            'token': majorlogin_response.token,
            'server_time': majorlogin_response.server_time,
            'aes_ak': majorlogin_response.aes_ak,
            'iv_i': majorlogin_response.iv_i,
            'functional_addrs': res_proto.functional_addrs or get_proto_field(dict_res, 14),
            'informational_addrs': res_proto.informational_addrs or get_proto_field(dict_res, 32),
            'release_version': release_version,
            'client_version': client_version,
            'server_url': majorlogin_response.url,
            'login_payload_data': login_payload_data,
            'auth_type': 'guest',
            'auth_uid': uid,
            'auth_password': password,
        }
        _register_credentials(account_data)
        cache_set(uid, account_data)
        print_success(f"[login_guest] SUCCESS for UID {uid} → {acc_id}")
        return account_data
    except Exception as e:
        dbg_exc("process_account_uid_pass", e)
        print_error(f"process_account_uid_pass error: {e}")
        return None


async def process_account_token(access_token: str, target_level: int = 0,
                                 target_matches: int = 0) -> Optional[Dict]:
    dbg("login_token", f"START token={access_token[:12]}… target_lvl={target_level} target_mt={target_matches}")
    cache_key = f"tok_{access_token[:20]}"
    cached = cache_get(cache_key)
    if cached:
        print_success(f"[CACHE HIT] Token {access_token[:10]}... loaded from cache")
        acc_id = str(cached['account_id'])
        bot_state.register_account(
            uid=acc_id,
            nickname=cached.get('nickname', f"Player_{acc_id}"),
            region=cached.get('region', 'BD'),
            level=cached.get('level', 1),
            exp=cached.get('exp', 0),
            likes=cached.get('likes', 0),
            target_level=target_level,
            target_matches=target_matches,
        )
        _register_credentials(cached)
        return cached

    print_info("[LOGIN] Full login with Access Token...")
    try:
        dbg("login_token", "step 1/5 → version_config")
        verconfig_res = await version_config()
        if verconfig_res is None:
            print_error("[login_token] version_config FAILED")
            return None
        (release_version, client_version, server_url,
         device_whitelist_version, vercfg_sign) = verconfig_res
        dbg("login_token",
            f"version_config OK release={release_version} client_ver={client_version} "
            f"whitelist={device_whitelist_version}")

        dbg("login_token", "step 2/5 → inspect token")
        import requests
        url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
        hdrs = {
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "X-GA-SV": _current_xga_sv(),
        }
        dbg_req("GET", url, hdrs)
        resp = await asyncio.to_thread(requests.get, url, headers=hdrs, timeout=10)
        try:
            dbg("login_token", f"inspect status={resp.status_code} body={resp.text[:500]}")
        except Exception:
            pass
        data = resp.json()
        dbg("login_token", f"inspect json={data}")

        if 'error' in data:
            print_error(f"[login_token] inspect error: {data.get('error')}")
            return None

        open_id = data.get('open_id')
        platform = data.get('platform', 4)
        if not open_id:
            print_error(f"[login_token] no open_id in inspect: {data}")
            return None
        dbg("login_token", f"inspect OK open_id={open_id[:12]}… platform={platform}")

        dbg("login_token", "step 3/5 → build_majorlogin_payload")
        device_info = get_device_for_account(open_id)
        login_payload_data = await build_majorlogin_payload(
            open_id, access_token, str(platform), client_version, device_info,
            whitelist_version=device_whitelist_version,
            vercfg_sign=vercfg_sign
        )
        if not login_payload_data:
            print_error("[login_token] build_majorlogin_payload FAILED")
            return None

        dbg("login_token", "step 4/5 → send_majorlogin")
        majorlogin_response = await send_majorlogin(
            login_payload_data, release_version, server_url
        )
        if majorlogin_response is None:
            print_error("[login_token] send_majorlogin FAILED")
            return None
        dbg("login_token",
            f"MajorLogin OK account_id={majorlogin_response.account_id} "
            f"region={majorlogin_response.region}")

        dbg("login_token", "step 5/5 → send_getlogin")
        getlogin_result = await send_getlogin(
            login_payload_data,
            majorlogin_response.url,
            majorlogin_response.token,
            release_version
        )
        if getlogin_result is None:
            print_error("[login_token] send_getlogin FAILED")
            return None
        res_proto, dict_res = getlogin_result
        dbg("login_token", f"GetLoginData OK nickname={res_proto.nickname!r}")

        acc_id = str(majorlogin_response.account_id)
        level = int(get_proto_field(dict_res, 6, 1))
        exp = int(get_proto_field(dict_res, 7, 0))
        likes = int(get_proto_field(dict_res, 8, 0))
        nickname = res_proto.nickname or get_proto_field(dict_res, 4, f"Player_{acc_id}")
        region = majorlogin_response.region or get_proto_field(dict_res, 3, "BD")
        dbg("login_token",
            f"parsed: acc_id={acc_id} nickname={nickname!r} region={region} "
            f"level={level} exp={exp}")

        bot_state.register_account(
            uid=acc_id, nickname=nickname, region=region,
            level=level, exp=exp, likes=likes,
            target_level=target_level, target_matches=target_matches,
        )

        account_data = {
            'account_id': majorlogin_response.account_id,
            'nickname': nickname,
            'region': region,
            'level': level,
            'exp': exp,
            'likes': likes,
            'open_id': open_id,
            'access_token': access_token,
            'platform': str(platform),
            'token': majorlogin_response.token,
            'server_time': majorlogin_response.server_time,
            'aes_ak': majorlogin_response.aes_ak,
            'iv_i': majorlogin_response.iv_i,
            'functional_addrs': res_proto.functional_addrs or get_proto_field(dict_res, 14),
            'informational_addrs': res_proto.informational_addrs or get_proto_field(dict_res, 32),
            'release_version': release_version,
            'client_version': client_version,
            'server_url': majorlogin_response.url,
            'login_payload_data': login_payload_data,
            'auth_type': 'token',
            'auth_token': access_token,
        }
        _register_credentials(account_data)
        cache_set(cache_key, account_data)
        print_success(f"[login_token] SUCCESS → acc_id={acc_id}")
        return account_data
    except Exception as e:
        dbg_exc("process_account_token", e)
        print_error(f"process_account_token error: {e}")
        return None


async def run_account_worker(account_data: Dict, label: str):
    acc_id = str(account_data['account_id'])
    informational_task = None
    exp_task = None
    functional_task = None
    try:
        reg = account_data.get('region', 'BD')
        tcp_packet_online = await build_tcp_startup_packet(
            account_data['account_id'],
            account_data['token'],
            account_data['server_time'],
            account_data['aes_ak'],
            account_data['iv_i'],
            region=reg,
            typ='OnLine'
        )

        tcp_packet_chat = await build_tcp_startup_packet(
            account_data['account_id'],
            account_data['token'],
            account_data['server_time'],
            account_data['aes_ak'],
            account_data['iv_i'],
            region=reg,
            typ='ChaT'
        )

        informational_task = asyncio.create_task(
            informational(
                account_data['informational_addrs'],
                tcp_packet_chat,
                account_data['aes_ak'],
                account_data['iv_i'],
                region=reg
            )
        )

        async def exp_refresher():
            while True:
                await asyncio.sleep(90)
                fresh = bot_state.account_credentials.get(acc_id)
                if fresh:
                    await refresh_account_profile(fresh)

        exp_task = asyncio.create_task(exp_refresher())

        functional_task = asyncio.create_task(
            functional_lone_wolf(
                account_data['functional_addrs'],
                tcp_packet_online,
                account_data['region'],
                account_data['client_version'],
                account_data['aes_ak'],
                account_data['iv_i'],
                account_id=acc_id,
                account_data=account_data
            )
        )

        await functional_task

    except asyncio.CancelledError:
        raise
    except Exception as e:
        print_error(f"run_account_worker error for {label}: {e}")
    finally:
        for t in (informational_task, exp_task, functional_task):
            if t and not t.done():
                t.cancel()
        for t in (informational_task, exp_task, functional_task):
            if t:
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass


async def account_loop_guest(uid: str, password: str, target_level: int = 0,
                              target_matches: int = 0):
    while True:
        try:
            print_info(
                f"[LOGIN] Starting login for Guest UID: {uid}... "
                f"(Targets: Lv.{target_level or 'MAX'} / {target_matches or '∞'} matches)"
            )
            try:
                bot_state.update_status(str(uid), "CONNECTING")
            except Exception:
                pass
            account_data = await process_account_uid_pass(
                uid, password, target_level, target_matches
            )
            if not account_data:
                print_error(f"Login failed for UID: {uid}. Retrying in 15 seconds...")
                try:
                    bot_state.update_status(str(uid), "ERROR")
                except Exception:
                    pass
                await asyncio.sleep(15)
                continue

            acc_id = str(account_data['account_id'])
            if target_level > 0 and acc_id in bot_state.accounts:
                bot_state.accounts[acc_id]['target_level'] = int(target_level)
            if target_matches > 0 and acc_id in bot_state.accounts:
                bot_state.accounts[acc_id]['target_matches'] = int(target_matches)
            bot_state._check_target(acc_id)

            await run_account_worker(account_data, uid)
            print_warning(f"Session finished for {uid}. Reconnecting in 3s...")
            await asyncio.sleep(3)
        except asyncio.CancelledError:
            print_warning(f"Worker for {uid} stopped.")
            try:
                bot_state.update_status(str(uid), "OFFLINE")
            except Exception:
                pass
            break
        except Exception as e:
            print_error(f"Error for UID {uid}: {e}. Retrying in 10s...")
            await asyncio.sleep(10)


async def account_loop_token(token: str, target_level: int = 0, target_matches: int = 0):
    token_label = token[:10]
    while True:
        try:
            print_info(
                f"[LOGIN] Starting login with Access Token... "
                f"(Targets: Lv.{target_level or 'MAX'} / {target_matches or '∞'} matches)"
            )
            account_data = await process_account_token(token, target_level, target_matches)
            if not account_data:
                print_error("Login failed for Token. Retrying in 15 seconds...")
                await asyncio.sleep(15)
                continue

            acc_id = str(account_data['account_id'])
            if target_level > 0 and acc_id in bot_state.accounts:
                bot_state.accounts[acc_id]['target_level'] = int(target_level)
            if target_matches > 0 and acc_id in bot_state.accounts:
                bot_state.accounts[acc_id]['target_matches'] = int(target_matches)
            bot_state._check_target(acc_id)

            await run_account_worker(account_data, acc_id)
            print_warning("Token session finished. Reconnecting in 3s...")
            await asyncio.sleep(3)
        except asyncio.CancelledError:
            print_warning(f"Worker for token {token_label} stopped.")
            break
        except Exception as e:
            print_error(f"Token error: {e}. Retrying in 10s...")
            await asyncio.sleep(10)


# ==================== ACCOUNTS LOADER ====================
def load_accounts():
    accounts = []
    if os.path.exists(ACCOUNTS_FILE):
        try:
            with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    accounts = data
        except Exception as e:
            print_error(f"Could not load {ACCOUNTS_FILE}: {e}")

    if not accounts and FALLBACK_UID and FALLBACK_PASSWORD:
        accounts.append({"uid": FALLBACK_UID, "password": FALLBACK_PASSWORD})

    return accounts


# ==================== FILE LOCK & HELPER ====================
_file_lock = asyncio.Lock()


async def remove_account_from_file(uid: Optional[str] = None, token: Optional[str] = None):
    async with _file_lock:
        accounts_file = "accounts.json"
        if not os.path.exists(accounts_file):
            return
        try:
            with open(accounts_file, "r", encoding="utf-8") as f:
                existing = json.load(f)
            new_list = []
            for a in existing:
                if uid and str(a.get("uid")) == str(uid):
                    continue
                if token and a.get("token") == token:
                    continue
                new_list.append(a)
            with open(accounts_file, "w", encoding="utf-8") as f:
                json.dump(new_list, f, indent=2)
        except Exception as e:
            print_error(f"remove_account_from_file error: {e}")


# ==================== MAIN ====================
async def main():
    print_colored("=" * 60, Colors.CYAN)
    print_colored("  - FreeFire Level Up Bot", Colors.GREEN)
    print_colored("   Persistent Device + TRUE Parallel + Smart DNS", Colors.WHITE)
    print_colored("=" * 60, Colors.CYAN)
    print_info(f"Max Accounts: {MAX_ACCOUNTS}")
    print_info(f"Daily EXP Cap per account: {DAILY_EXP_CAP:,}")
    print_info(f"Start Match Interval: {START_MATCH_INTERVAL}s")
    print_info(f"Offline Wait: {NEW_MATCH_DELAY}s (after match found)")
    print_info(f"Non-match Reconnect: {NON_MATCH_RECONNECT_DELAY}s")
    print_info(f"No-Match Force Restart: {NO_MATCH_RESTART_TIMEOUT}s ({NO_MATCH_RESTART_TIMEOUT // 60} min)")
    print_info(f"Cache Invalidation Threshold: {MAX_CONSECUTIVE_PARSE_FAILURES}x")
    print_info(f"Parallel Matches: UNLIMITED (background)")
    print_info(f"Cache TTL: {TOKEN_CACHE_TTL}s ({TOKEN_CACHE_TTL // 60} min)")
    print_info("Stop Triggers: Daily Cap / Target Level / Target Matches / Manual Pause")
    print_info("Stop Mode: finish running matches → pause (never auto-delete)")
    print_info(f"DEBUG MODE: {'ON' if DEBUG else 'OFF'} (set DEBUG=False to silence)")
    print_colored("=" * 60, Colors.CYAN)

    try:
        await start_web_dashboard(host=WEB_HOST, port=WEB_PORT)
        print_success(f"Web Dashboard live at http://localhost:{WEB_PORT}")
    except Exception as e:
        print_error(f"Could not start web dashboard: {e}")

    async def on_delete_all_handler():
        print_warning("🗑️ [DELETE ALL] Removing all accounts...")

        all_keys = set(bot_state.account_workers.keys())
        for k, v in list(bot_state.account_credentials.items()):
            all_keys.add(k)
            if v.get('auth_uid'):
                all_keys.add(str(v['auth_uid']))
            if v.get('auth_token'):
                all_keys.add(v['auth_token'][:10])
            if v.get('account_id'):
                all_keys.add(str(v['account_id']))

        tasks = []
        for key in list(all_keys):
            t = bot_state.account_workers.pop(key, None)
            if t and not t.done():
                t.cancel()
                tasks.append(t)

        if tasks:
            try:
                await asyncio.gather(*tasks, return_exceptions=True)
            except Exception:
                pass

        await asyncio.sleep(2.0)

        current_task = asyncio.current_task()
        all_running = [t for t in asyncio.all_tasks()
                       if t is not current_task and not t.done()]
        for t in all_running:
            try:
                coro_name = getattr(t.get_coro(), '__qualname__', '')
                if any(x in coro_name for x in [
                    'functional_lone_wolf', 'play_game', 'informational',
                    'run_account_worker', 'account_loop_'
                ]):
                    t.cancel()
            except Exception:
                pass

        await asyncio.sleep(1.0)

        try:
            with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
                json.dump([], f, indent=2)
            print_success("[DELETE ALL] accounts.json cleared")
        except Exception as e:
            print_error(f"[DELETE ALL] accounts.json clear failed: {e}")

        bot_state.accounts.clear()
        bot_state.account_credentials.clear()
        bot_state._target_triggered.clear()
        bot_state.total_matches = 0
        bot_state.total_gained_exp = 0

        try:
            _match_counters.clear()
        except Exception:
            pass

        try:
            _account_pause_events.clear()
        except Exception:
            pass

        try:
            daily_exp_tracker.clear_all()
        except Exception:
            pass

        try:
            with open(TOKEN_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump({}, f, indent=2)
            global _token_cache_memo, _token_cache_memo_time
            _token_cache_memo = {}
            _token_cache_memo_time = 0.0
        except Exception:
            pass

        bot_state.log("🗑️ All jobs deleted. System cleared.", "warning")
        print_success("✅ [DELETE ALL] All accounts removed & system cleared")

    async def on_restart_all_handler():
        print_warning("🔄 [RESTART ALL] Restarting all accounts...")

        accounts = load_accounts()
        total = len(accounts)

        if total == 0:
            bot_state.log("No accounts to restart", "warning")
            print_warning("[RESTART ALL] No accounts found")
            return

        keys = list(bot_state.account_workers.keys())
        tasks = []
        for key in keys:
            t = bot_state.account_workers.pop(key, None)
            if t and not t.done():
                t.cancel()
                tasks.append(t)

        if tasks:
            try:
                await asyncio.gather(*tasks, return_exceptions=True)
            except Exception:
                pass

        await asyncio.sleep(1.5)

        bot_state._target_triggered.clear()
        _account_pause_events.clear()
        for acc_id, acc in bot_state.accounts.items():
            acc["status"] = "CONNECTING"
            acc["active_matches"] = 0

        launched = 0
        for acc in accounts:
            tgt = int(acc.get("target_level", 0) or 0)
            tgt_m = int(acc.get("target_matches", 0) or 0)
            if "token" in acc and acc["token"]:
                t = asyncio.create_task(account_loop_token(acc["token"], tgt, tgt_m))
                bot_state.account_workers[acc["token"][:10]] = t
                launched += 1
            elif "uid" in acc and "password" in acc and acc["uid"]:
                u = str(acc["uid"])
                t = asyncio.create_task(account_loop_guest(u, acc["password"], tgt, tgt_m))
                bot_state.account_workers[u] = t
                launched += 1

        bot_state.log(f"🔄 All jobs restarted ({launched} accounts)", "success")
        print_success(f"✅ [RESTART ALL] {launched}/{total} accounts restarted")

    async def on_restart_account_handler(uid_str):
        uid_str = str(uid_str)
        print_warning(f"🔄 [RESTART] Manual restart requested for {uid_str}")

        creds = bot_state.account_credentials.get(uid_str, {})
        if not creds:
            for k, v in list(bot_state.account_credentials.items()):
                acc_id = str(v.get('account_id', ''))
                auth_uid = str(v.get('auth_uid', '') or '')
                if acc_id == uid_str or auth_uid == uid_str:
                    creds = v
                    break

        if not creds:
            print_error(f"[RESTART] No credentials found for {uid_str}")
            return

        auth_type = creds.get('auth_type', 'guest')
        auth_uid = str(creds.get('auth_uid', '') or '')
        auth_password = creds.get('auth_password', '') or ''
        auth_token = creds.get('auth_token', '') or ''
        account_id = str(creds.get('account_id', ''))

        target_level = 0
        target_matches = 0
        if os.path.exists(ACCOUNTS_FILE):
            try:
                with open(ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
                    accs = json.load(f)
                for a in accs:
                    if auth_uid and str(a.get('uid')) == auth_uid:
                        target_level = int(a.get('target_level', 0) or 0)
                        target_matches = int(a.get('target_matches', 0) or 0)
                        break
                    if auth_token and a.get('token') == auth_token:
                        target_level = int(a.get('target_level', 0) or 0)
                        target_matches = int(a.get('target_matches', 0) or 0)
                        break
            except Exception:
                pass

        keys_to_cancel = []
        for k in [account_id, auth_uid]:
            if k and k in bot_state.account_workers:
                keys_to_cancel.append(k)
        if auth_token:
            tk = auth_token[:10]
            if tk in bot_state.account_workers:
                keys_to_cancel.append(tk)

        for key in keys_to_cancel:
            try:
                t = bot_state.account_workers.pop(key, None)
                if t:
                    t.cancel()
                    try:
                        await t
                    except (asyncio.CancelledError, Exception):
                        pass
            except Exception:
                pass

        await asyncio.sleep(1.0)

        _account_pause_events.pop(account_id, None)
        _account_pause_events.pop(auth_uid, None)

        if auth_type == 'token' and auth_token:
            task = asyncio.create_task(account_loop_token(auth_token, target_level, target_matches))
            bot_state.account_workers[auth_token[:10]] = task
        elif auth_uid and auth_password:
            task = asyncio.create_task(account_loop_guest(auth_uid, auth_password, target_level, target_matches))
            bot_state.account_workers[auth_uid] = task
        else:
            print_error(f"[RESTART] Cannot restart {uid_str} — missing credentials")
            return

        print_success(f"✅ [RESTART] {uid_str} restarted with fresh connection")

    async def on_delete_account_handler(uid_str):
        uid_str = str(uid_str)
        print_warning(f"🗑️ [DELETE] Removing account task {uid_str}")

        creds = bot_state.account_credentials.get(uid_str, {})
        if not creds:
            for k, v in list(bot_state.account_credentials.items()):
                if (str(v.get('account_id', '')) == uid_str or
                        str(v.get('auth_uid', '') or '') == uid_str):
                    creds = v
                    break

        auth_uid = str(creds.get('auth_uid', '') or '')
        auth_token = creds.get('auth_token', '') or ''
        account_id = str(creds.get('account_id', '') or '')
        auth_password = creds.get('auth_password', '') or ''

        keys_to_cancel = set()
        for k in [uid_str, account_id, auth_uid]:
            if k:
                keys_to_cancel.add(k)
        if auth_token:
            keys_to_cancel.add(auth_token[:10])

        tasks = []
        for key in list(keys_to_cancel):
            t = bot_state.account_workers.pop(key, None)
            if t and not t.done():
                t.cancel()
                tasks.append(t)

        if tasks:
            try:
                await asyncio.gather(*tasks, return_exceptions=True)
            except Exception:
                pass

        for key in list(keys_to_cancel):
            _account_pause_events.pop(key, None)

        for key in list(keys_to_cancel):
            bot_state.accounts.pop(key, None)

        for k in list(bot_state.account_credentials.keys()):
            v = bot_state.account_credentials[k]
            if (str(v.get('account_id', '')) == uid_str or
                    str(v.get('account_id', '')) == account_id or
                    str(v.get('auth_uid', '') or '') == auth_uid):
                del bot_state.account_credentials[k]

        try:
            await remove_account_from_file(
                uid=auth_uid if auth_uid else (uid_str if uid_str.isdigit() else None),
                token=auth_token if auth_token else None,
            )
        except Exception as e:
            print_error(f"[DELETE] accounts.json cleanup: {e}")

        try:
            cache_invalidate(uid_str)
            if account_id:
                cache_invalidate(account_id)
            if auth_uid:
                cache_invalidate(auth_uid)
            if auth_token:
                cache_invalidate(f"tok_{auth_token[:20]}")
        except Exception:
            pass

        try:
            daily_exp_tracker.remove_account(uid_str)
            if account_id and account_id != uid_str:
                daily_exp_tracker.remove_account(account_id)
        except Exception:
            pass

        bot_state.log(f"🗑️ Account {uid_str} deleted", "warning", uid_str)
        print_success(f"✅ Account {uid_str} deleted")

    async def on_toggle_pause_handler(uid_str):
        uid_str = str(uid_str)

        account_id = None
        if uid_str in bot_state.accounts:
            account_id = uid_str
        else:
            creds = bot_state.account_credentials.get(uid_str, {})
            if creds:
                account_id = str(creds.get('account_id', '') or '')
            if not account_id:
                for k, v in bot_state.account_credentials.items():
                    if (str(v.get('account_id', '')) == uid_str or
                            str(v.get('auth_uid', '') or '') == uid_str):
                        account_id = str(v.get('account_id', '') or '')
                        break
            if not account_id:
                account_id = uid_str

        ev = get_pause_event(account_id)

        if ev.is_set():
            ev.clear()
            try:
                bot_state.update_status(account_id, "PAUSED")
            except Exception:
                pass
            bot_state.log(f"⏸ Paused {account_id}", "warning", account_id)
            print_warning(f"[PAUSE] {account_id} paused (running matches will finish)")
            return {"paused": True}
        else:
            ev.set()
            try:
                bot_state.update_status(account_id, "ONLINE")
            except Exception:
                pass
            bot_state.log(f"▶️ Resumed {account_id}", "success", account_id)
            print_success(f"[RESUME] {account_id} resumed")
            return {"paused": False}

    async def on_account_added_handler(data):
        if len(bot_state.accounts) >= MAX_ACCOUNTS:
            print_warning(f"[CAP] Rejected — {len(bot_state.accounts)}/{MAX_ACCOUNTS} reached")
            return {
                "added": False,
                "reason": f"Max {MAX_ACCOUNTS} accounts reached",
            }

        target_level = int(data.get("target_level", 0) or 0)
        target_matches = int(data.get("target_matches", 0) or 0)

        if "uid" in data and data.get("uid") and "password" in data:
            u = str(data["uid"]).strip()
            p = str(data["password"]).strip()
            if not u or not p:
                return {"added": False, "reason": "Missing credentials"}

            pre_data = None
            try:
                pre_data = await process_account_uid_pass(u, p, target_level, target_matches)
            except Exception as e:
                print_error(f"[CHECK] Login failed for {u}: {e}")

            if pre_data and target_level > 0:
                current_level = int(pre_data.get('level', 1) or 1)
                if current_level >= target_level:
                    await remove_account_from_file(uid=u)
                    bot_state.log(
                        f"⏭️ Skipped UID {u} — Level {current_level} already ≥ target {target_level}",
                        "warning", u
                    )
                    print_warning(
                        f"[SKIP] UID {u} Level {current_level} >= target {target_level} → not added"
                    )
                    return {
                        "added": False,
                        "reason": f"Level {current_level} ≥ target {target_level}",
                        "current_level": current_level,
                        "target_level": target_level,
                    }

            task = asyncio.create_task(
                account_loop_guest(u, p, target_level, target_matches)
            )
            bot_state.account_workers[u] = task
            return {"added": True, "type": "guest", "uid": u}

        elif "token" in data and data.get("token"):
            t = str(data["token"]).strip()
            if not t:
                return {"added": False, "reason": "Missing token"}

            pre_data = None
            try:
                pre_data = await process_account_token(t, target_level, target_matches)
            except Exception as e:
                print_error(f"[CHECK] Token login failed: {e}")

            if pre_data and target_level > 0:
                current_level = int(pre_data.get('level', 1) or 1)
                if current_level >= target_level:
                    await remove_account_from_file(token=t)
                    bot_state.log(
                        f"⏭️ Skipped token — Level {current_level} already ≥ target {target_level}",
                        "warning"
                    )
                    print_warning(
                        f"[SKIP] Token Level {current_level} >= target {target_level} → not added"
                    )
                    return {
                        "added": False,
                        "reason": f"Level {current_level} ≥ target {target_level}",
                        "current_level": current_level,
                        "target_level": target_level,
                    }

            task = asyncio.create_task(
                account_loop_token(t, target_level, target_matches)
            )
            bot_state.account_workers[t[:10]] = task
            return {"added": True, "type": "token"}

        return {"added": False, "reason": "Invalid payload"}

    async def on_refresh_account_handler(uid):
        await refresh_account_profile(uid)

    bot_state.refresh_callbacks["on_account_added"] = on_account_added_handler
    bot_state.refresh_callbacks["on_refresh_account"] = on_refresh_account_handler
    bot_state.refresh_callbacks["on_restart_account"] = on_restart_account_handler
    bot_state.refresh_callbacks["on_delete_account"] = on_delete_account_handler
    bot_state.refresh_callbacks["on_toggle_pause"] = on_toggle_pause_handler
    bot_state.refresh_callbacks["on_delete_all"] = on_delete_all_handler
    bot_state.refresh_callbacks["on_restart_all"] = on_restart_all_handler

    async def _auto_loader(acc):
        tgt = int(acc.get("target_level", 0) or 0)
        tgt_m = int(acc.get("target_matches", 0) or 0)
        if acc.get("token"):
            await on_account_added_handler({
                "token": acc["token"].strip(),
                "target_level": tgt,
                "target_matches": tgt_m,
            })
        elif acc.get("uid") and acc.get("password"):
            await on_account_added_handler({
                "uid": str(acc["uid"]).strip(),
                "password": str(acc["password"]).strip(),
                "target_level": tgt,
                "target_matches": tgt_m,
            })
        else:
            raise ValueError("auto.json entry needs token OR uid+password")

    auto_mgr = None
    try:
        from auto_manager import init_auto_manager_if_enabled
        auto_mgr = await init_auto_manager_if_enabled(_auto_loader)
    except Exception as e:
        print_warning(f"[AUTO] auto_manager not loaded: {e}")

    if auto_mgr is None:
        accounts = load_accounts()
        if not accounts:
            print_warning(f"No accounts found in {ACCOUNTS_FILE}! Add accounts from Web Dashboard.")
            print_warning(f"Open: http://localhost:{WEB_PORT}")
        for acc in accounts:
            tgt = int(acc.get("target_level", 0) or 0)
            tgt_m = int(acc.get("target_matches", 0) or 0)
            if "token" in acc and acc["token"]:
                t = asyncio.create_task(account_loop_token(acc["token"], tgt, tgt_m))
                bot_state.account_workers[acc["token"][:10]] = t
            elif "uid" in acc and "password" in acc and acc["uid"]:
                u = str(acc["uid"])
                t = asyncio.create_task(account_loop_guest(u, acc["password"], tgt, tgt_m))
                bot_state.account_workers[u] = t

    try:
        while True:
            await asyncio.sleep(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print_warning("\n[STOP] Shutting down all accounts...")
        if auto_mgr is not None:
            auto_mgr.stop()
        for t in list(bot_state.account_workers.values()):
            t.cancel()
        await asyncio.gather(*bot_state.account_workers.values(), return_exceptions=True)
        print_success("All sessions closed.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print_warning("\nProgram stopped by user.")