#!/usr/bin/env python3
"""
Convert proxy subscription URLs to sing-box outbound configuration or v2ray link list.
Supports multiple subscription URLs (or local file paths), protocol filtering,
per-protocol transport filters, deduplication (by IP:port and optionally by tag),
DNS resolution for domain names (IP used in tags and server field with SNI),
Connectivity testing using sing-box (multi-threaded, with proper port locking), and updating of existing config's selectors.
Supports protocols: Hysteria, Hysteria2.
Optional country resolution for each proxy's incoming IP (server) and outgoing IP (through proxy)
can be used in tags and comments (format: "IN: XX OUT: YY").
Country lookup uses multiple free geolocation APIs (sequentially) via proxy.
If country lookup fails for a proxy, that proxy is automatically excluded from the final output.
Tags can include country flags via placeholders {flag_in}, {flag_out}, {flag_pair}.
Optional speedtest (download & upload) can be performed and results included in tags via {speed_download} and {speed_upload}.
Tags are numbered continuously only for proxies that pass connectivity tests and are included in the final output,
unless the tag format contains both {ip} and {port} (which are assumed unique) or --no-number-tags is used.
Subscription content can be plain text or base64-encoded.
If no subscription URLs are provided but --config is given, the script will process
the existing config's proxy outbounds (test connectivity and update selectors) without adding new ones.
All proxy outbounds (both existing and new) are tested for connectivity; only reachable ones are kept.
Outbound with tag 'TOR' is skipped from testing and always preserved.
Deduplication can be performed globally by IP and port (enabled by default) and within subscriptions.
Optional country filtering: include or exclude proxies based on country codes of IN IP and OUT IP.
If a country code is not determined (lookup failed), the proxy is automatically excluded.
Optional speed filtering: include only proxies with download/upload speed above thresholds (--min-download-speed, --min-upload-speed).
Optional filter: keep only proxies where incoming server IP equals outgoing IP (--same-in-out-ip).

Export formats:
  - sing-box: JSON configuration with outbounds array (default).
  - v2ray: plain text list of URIs (vless://, vmess://, trojan://, ss://, socks://, http://, https://, hysteria://, hysteria2://).

Tag generation (for both sing-box and v2ray):
  By default, tags are generated as "protocol-IP-port" (e.g., "vless-1.2.3.4-443").
  With --keep-original-tags, the fragment part of the URI (after #) is used as the base tag.
  With --tag-format, you can define a custom tag template using placeholders:
    {proto}        - protocol (vless, vmess, trojan, ss, socks, http, hysteria, hysteria2)
    {host}         - original hostname (from URI)
    {ip}           - resolved IP address of the server (same as {in_ip})
    {port}         - port number of the server (same as {in_port})
    {fragment}     - fragment part (after #) after decoding, otherwise empty string
    {country_in}   - two-letter country code of the server (incoming IP), requires --resolve-country
    {country_out}  - two-letter country code of the exit IP (through proxy), requires --resolve-country and sing-box test
    {country_pair} - combined string "IN: {country_in} OUT: {country_out}" (or just the available part)
    {flag_in}      - flag emoji for the server's country (requires --resolve-country)
    {flag_out}     - flag emoji for the exit IP's country (requires --resolve-country and sing-box test)
    {flag_pair}    - combined flag emojis (server flag then exit flag, if available)
    {in_ip}        - resolved IP address of the server
    {in_port}      - port number of the server
    {out_ip}       - external IP address seen through the proxy (requires sing-box test)
    {speed_download} - download speed in Mbps (numeric only, requires --speedtest)
    {speed_upload}   - upload speed in Mbps (numeric only, requires --speedtest)
  If multiple URIs share the same base tag, suffixes _1, _2, ... are added after connectivity testing,
  unless the tag format contains both {ip} and {port} (which are assumed to be unique) or --no-number-tags is used.
  If --tag-format is specified, --keep-original-tags is ignored.

V2ray export with IP resolution:
  --resolve-uris: when exporting to v2ray, replace the original hostname in each URI with the resolved IP address
                  (if resolution was successful). Works for all protocols.

Country resolution:
  --resolve-country: for each proxy that passes connectivity test, determine its incoming country code (server IP)
                     and, if tested with sing-box, also the outgoing country code (exit IP) using multiple free geolocation APIs.
                     The result is cached per IP for 24 hours and can be used in tags ({country_in}, {country_out}, {country_pair}, {flag_in}, {flag_out}, {flag_pair}) or v2ray comments.
                     If country lookup fails for a proxy (either IN or OUT, if expected), that proxy is automatically excluded from the final output.

Country filtering:
  --include-country-in LIST : comma-separated list of country codes (e.g., US,DE) for IN IP. Only proxies with IN country in this list are kept.
  --exclude-country-in LIST : comma-separated list of country codes for IN IP. Proxies with IN country in this list are discarded.
  --include-country-out LIST: similar for OUT IP (requires sing-box test).
  --exclude-country-out LIST: similar for OUT IP.
  If both include and exclude are specified for the same direction, an error is raised.
  If --resolve-country is not enabled, these filters have no effect (but a warning may be issued).
  Proxies with missing country fields are automatically excluded before filtering.

Speedtest:
  --speedtest: enable download and upload speed measurement (requires --test-connect).
  --speedtest-download-url: URL of a file to download for speed test (default: http://cachefly.cachefly.net/1mb.test).
  --speedtest-upload-url: URL to send data to for upload speed test (default: https://httpbin.org/post).
  --speedtest-timeout: timeout in seconds for each speedtest (default: 15).
  The download and upload speeds in Mbps are saved (numeric only) and can be used in tags via {speed_download} and {speed_upload}.
  If a speedtest fails, the corresponding speed is set to 0.0.

Speed filtering (only applies when --speedtest is enabled):
  --min-download-speed: minimum download speed in Mbps (default: 0). Proxies with download speed below this value are excluded.
  --min-upload-speed: minimum upload speed in Mbps (default: 0). Proxies with upload speed below this value are excluded.

Same IN/OUT IP filtering:
  --same-in-out-ip: keep only proxies where the server's resolved IP (IN_IP) equals the external IP seen through the proxy (OUT_IP).
                    Proxies for which OUT_IP could not be determined are also excluded. Requires --test-connect and --resolve-country.

Deduplication:
  --no-deduplicate: disable deduplication by (host, port) within each subscription source.
  --no-deduplicate-ip-port: disable global deduplication by (IP, port) across all sources and existing config.
  By default, both intra-source and global deduplication are enabled.

Filtering:
  - By protocol type (--types)
  - For vless: by transport type (--vless-transport) and TLS type (--vless-tls)
  - For vmess: by transport type (--vmess-transport)
  - For trojan: by transport type (--trojan-transport)
  - Hysteria and Hysteria2 do not support transport filtering (they use fixed QUIC transport).

Transport filter special feature:
  Include an empty string "" in the list to match URIs without an explicit
  transport parameter. Examples:
    --vless-transport "tcp,,"   (match tcp or no explicit transport)
    --vless-transport ""         (match only those with no explicit transport)

DNS resolution:
  Domain names in all protocols are resolved to IP addresses.
  The IP is used in the 'server' field and in the default tag.
  The original domain is preserved in the TLS server_name (SNI) if needed (for vless, vmess, trojan, hysteria, hysteria2).

Connectivity testing (--test-connect):
  Performs connectivity test to each proxy using sing-box. It runs a local sing-box instance with the outbound
  and performs an HTTP request via its proxy – provides both incoming and outgoing countries, plus outgoing IP.
  For sing-box, you need the binary installed and specify its path if not in the default location.
  The test uses the URL specified by --test-url (default: http://cp.cloudflare.com).
  Testing is multi-threaded (--test-threads threads) with proper port locking.
  Only reachable proxies are kept.
  Outbound with tag 'TOR' is always skipped from testing and preserved.

Selector update (with --config):
  - AUTO (urltest) gets only proxy tags (excluding BLOCK, DIRECT).
  - Other selectors (type 'selector') get proxy tags, service tags (BLOCK,
    DIRECT, TOR, etc.) plus AUTO, but never include other selector tags
    (except AUTO). This prevents circular dependencies.
  - TOR-SERVICE additionally excludes the tag TOR.
  - All selectors have outbound lists sorted with custom order:
    BLOCK, DIRECT, AUTO, TOR first, then the rest alphabetically.
  - Own tag is excluded.

If no subscription URLs are provided but --config is given, the script will
process the existing config's proxy outbounds (test connectivity and update
selectors) without adding any new proxies.

If --test-connect is not specified, no connectivity testing is performed, country resolution is skipped,
and all parsed proxies (after deduplication and filters) are included in the output.

Output:
  For sing-box format: JSON file containing the 'outbounds' array. If --config is used,
  the entire config is updated and saved to --output (or default).
  For v2ray format: plain text file with one URI per line. If --output is not specified,
  the URIs are printed to stdout.
"""

import sys
import json
import urllib.request
import urllib.parse
import base64
import re
import socket
import argparse
import time
import html
import tempfile
import subprocess
import os
import signal
import threading
import logging
import atexit
import shutil
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, Optional, List, Set, Tuple, Union
from collections import OrderedDict
from dataclasses import dataclass, field, asdict

# Optional tqdm for progress bars (fallback)
try:
    from tqdm import tqdm as tqdm_lib
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    class tqdm_lib:
        def __init__(self, *args, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def update(self, n=1): pass
        def close(self): pass
        def set_description(self, desc): pass

# Optional rich for advanced progress bars
try:
    from rich.progress import Progress as RichProgress, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn, SpinnerColumn
    from rich.console import Console
    RICH_AVAILABLE = True
    console = Console(stderr=True)
except ImportError:
    RICH_AVAILABLE = False

# ----------------------------------------------------------------------
# Logging setup
# ----------------------------------------------------------------------
logger = logging.getLogger("sub2singbox")
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# ----------------------------------------------------------------------
# Signal handler for graceful shutdown
# ----------------------------------------------------------------------
def signal_handler(sig, frame):
    logger.info("Received interrupt signal, cleaning up...")
    cleanup_processes()
    sys.exit(1)

signal.signal(signal.SIGINT, signal_handler)

# ----------------------------------------------------------------------
# Cache for test results (will be initialized with args.cache_dir later)
# ----------------------------------------------------------------------
CACHE_DIR = None
CACHE_FILE = None

def load_test_cache(cache_dir, cache_ttl):
    cache_file = os.path.join(cache_dir, "cache.json")
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cache = json.load(f)
            now = time.time()
            expired_keys = [k for k, v in cache.items() if now - v.get('timestamp', 0) > cache_ttl]
            for k in expired_keys:
                del cache[k]
            if expired_keys:
                with open(cache_file, 'w') as f:
                    json.dump(cache, f, indent=2)
            return cache
        except Exception:
            return {}
    return {}

def save_test_cache(cache_dir, cache):
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, "cache.json")
    with open(cache_file, 'w') as f:
        json.dump(cache, f, indent=2)

# ----------------------------------------------------------------------
# TTL cache with thread safety
# ----------------------------------------------------------------------
class TTLCache:
    def __init__(self, ttl_seconds: int):
        self.ttl = ttl_seconds
        self.cache = OrderedDict()
        self.timestamps = {}
        self.lock = threading.RLock()

    def get(self, key):
        with self.lock:
            if key in self.cache:
                if time.time() - self.timestamps[key] < self.ttl:
                    return self.cache[key]
                else:
                    del self.cache[key]
                    del self.timestamps[key]
            return None

    def set(self, key, value):
        with self.lock:
            self.cache[key] = value
            self.timestamps[key] = time.time()

# ----------------------------------------------------------------------
# Proxy data structure
# ----------------------------------------------------------------------
@dataclass
class Proxy:
    type: str
    tag: str
    server: str
    server_port: int
    uuid: Optional[str] = None
    password: Optional[str] = None
    method: Optional[str] = None
    security: Optional[str] = None
    alter_id: Optional[int] = None
    flow: Optional[str] = None
    tls: Optional[Dict[str, Any]] = None
    transport: Optional[Dict[str, Any]] = None
    plugin: Optional[str] = None
    username: Optional[str] = None
    version: Optional[str] = None
    up_mbps: Optional[int] = None
    down_mbps: Optional[int] = None
    auth: Optional[str] = None
    auth_str: Optional[str] = None
    obfs: Optional[Union[str, Dict]] = None
    protocol: Optional[str] = None
    peer: Optional[str] = None
    insecure: Optional[bool] = None
    alpn: Optional[List[str]] = None
    original_host: str = ""
    original_uri: str = ""
    fragment: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    vmess_json: Optional[Dict] = None
    parsed_uri: Optional[Any] = None
    base_tag: Optional[str] = None
    no_number: bool = False
    country_in: Optional[str] = None
    country_out: Optional[str] = None
    out_ip: Optional[str] = None
    latency: Optional[float] = None
    speed_download: Optional[float] = None
    speed_upload: Optional[float] = None

    def to_dict(self, remove_metadata: bool = True) -> Dict[str, Any]:
        d = asdict(self)
        if remove_metadata:
            keys_to_remove = [k for k in d if k.startswith(('original_', 'fragment', 'params', 'vmess_json', 'parsed_uri', 'base_tag', 'no_number', 'country_', 'out_ip')) or k in ('latency', 'speed_download', 'speed_upload')]
            for k in keys_to_remove:
                del d[k]
            d = {k: v for k, v in d.items() if v is not None}
        return d

# ----------------------------------------------------------------------
# Country code to flag emoji
# ----------------------------------------------------------------------
def country_code_to_flag(code: Optional[str]) -> str:
    if not code or not isinstance(code, str) or len(code) != 2:
        return ""
    offset = 0x1F1E6 - ord('A')
    flag = chr(ord(code[0]) + offset) + chr(ord(code[1]) + offset)
    return flag

# ----------------------------------------------------------------------
# Global caches
# ----------------------------------------------------------------------
country_cache = TTLCache(86400)  # 24 hours
test_cache = None
test_cache_lock = threading.Lock()

# ----------------------------------------------------------------------
# Utility functions
# ----------------------------------------------------------------------
def split_uri(uri: str):
    if '#' in uri:
        uri, fragment = uri.split('#', 1)
    else:
        fragment = ''
    if '?' in uri:
        uri, query_str = uri.split('?', 1)
        query = urllib.parse.parse_qs(query_str)
    else:
        query = {}
    return uri, fragment, query

def extract_port(hostport: str, default_port: int = 443) -> Tuple[str, int]:
    if ':' in hostport:
        host, port_str = hostport.rsplit(':', 1)
        port_clean = re.sub(r'\D', '', port_str)
        port = int(port_clean) if port_clean else default_port
    else:
        host = hostport
        port = default_port
    host = host.strip()
    return host, port

def maybe_decode_base64(content: str, verbose: bool = False) -> str:
    stripped = content.strip()
    try:
        missing_padding = len(stripped) % 4
        if missing_padding:
            stripped += '=' * (4 - missing_padding)
        decoded_bytes = base64.b64decode(stripped, validate=True)
        decoded = decoded_bytes.decode('utf-8')
        if '://' in decoded and ('\n' in decoded or len(decoded) > 100):
            if verbose:
                logger.info("Detected base64-encoded subscription, decoding...")
            return decoded
    except Exception:
        pass
    return content

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False

# ----------------------------------------------------------------------
# Parser functions (each returns Proxy or None) – полные реализации
# ----------------------------------------------------------------------
def parse_vless(uri: str, fragment: str,
                allowed_transport: Optional[Set[str]] = None,
                allowed_tls: Optional[Set[str]] = None,
                verbose: bool = False) -> Optional[Proxy]:
    try:
        data = uri[8:]
        data, _, params = split_uri(data)

        if not data:
            if verbose:
                logger.warning("vless: empty data after split_uri")
            return None

        if '@' not in data:
            if verbose:
                logger.warning(f"vless: no '@' found in data: {data}")
            return None

        userinfo, hostport = data.split('@', 1)
        if not userinfo or not hostport:
            if verbose:
                logger.warning("vless: empty userinfo or hostport")
            return None

        if '@' in hostport:
            if verbose:
                logger.warning(f"vless: invalid URI (multiple '@' in hostport): {hostport}")
            return None

        original_host, port = extract_port(hostport)
        if not original_host:
            if verbose:
                logger.warning(f"vless: empty host after extract_port from '{hostport}'")
            return None

        has_explicit_type = 'type' in params
        network = params.get('type', ['tcp'])[0]
        if network == 'raw':
            if verbose:
                logger.debug("vless: converting transport 'raw' to 'tcp'")
            network = 'tcp'

        SUPPORTED_TRANSPORT = {'tcp', 'ws', 'http', 'quic', 'grpc', 'httpupgrade', 'raw', 'xhttp', 'h2'}
        if network not in SUPPORTED_TRANSPORT:
            if verbose:
                logger.debug(f"vless: unsupported transport type '{network}', skipping")
            return None

        if allowed_transport is not None:
            transport_match = False
            if has_explicit_type:
                if network in allowed_transport:
                    transport_match = True
            else:
                if '' in allowed_transport:
                    transport_match = True
            if not transport_match:
                if verbose:
                    logger.debug(f"vless: filtered out by transport (explicit={has_explicit_type}, network='{network}', allowed={allowed_transport})")
                return None

        security = params.get('security', [None])[0] or 'none'
        if allowed_tls is not None and security not in allowed_tls:
            if verbose:
                logger.debug(f"vless: filtered out by TLS type '{security}' (allowed: {allowed_tls})")
            return None

        proxy = Proxy(
            type="vless",
            tag=f"vless-{original_host}-{port}",
            server=original_host,
            server_port=port,
            uuid=userinfo,
            original_host=original_host,
            original_uri=uri,
            params=params
        )
        if fragment:
            proxy.fragment = html.unescape(urllib.parse.unquote(fragment)).strip()
        else:
            proxy.fragment = ""

        if flow := params.get('flow', [None])[0]:
            proxy.flow = flow

        tls_obj = {}
        if security == "tls":
            tls_obj["enabled"] = True
            sni = params.get('sni', [None])[0]
            if sni:
                tls_obj["server_name"] = sni
            else:
                tls_obj["server_name"] = original_host
            if fp := params.get('fp', [None])[0]:
                tls_obj["utls"] = {"enabled": True, "fingerprint": fp}
        elif security == "reality":
            tls_obj["enabled"] = True
            tls_obj["reality"] = {"enabled": True}
            sni = params.get('sni', [None])[0]
            if sni:
                tls_obj["server_name"] = sni
            else:
                tls_obj["server_name"] = original_host
            fp = params.get('fp', [None])[0]
            if fp:
                tls_obj["utls"] = {"enabled": True, "fingerprint": fp}
            else:
                tls_obj["utls"] = {"enabled": True, "fingerprint": "chrome"}
            if pbk := params.get('pbk', [None])[0]:
                tls_obj["reality"]["public_key"] = pbk
            if sid := params.get('sid', [None])[0]:
                tls_obj["reality"]["short_id"] = sid
        if tls_obj:
            proxy.tls = tls_obj

        transport = {}
        need_transport = False
        if network != "tcp":
            need_transport = True
            transport["type"] = network
        elif network == "tcp":
            if params.get('headerType', ['none'])[0] == 'http':
                need_transport = True
                transport["type"] = "tcp"
                if host_header := params.get('host', [None])[0]:
                    transport["header"] = {"type": "http", "host": host_header}

        if network == "ws":
            need_transport = True
            transport["type"] = "ws"
            if path := params.get('path', [None])[0]:
                transport["path"] = path
            if host_header := params.get('host', [params.get('headerHost', [None])[0]])[0]:
                transport["headers"] = {"Host": host_header}
        elif network == "grpc":
            need_transport = True
            transport["type"] = "grpc"
            if path := params.get('path', [None])[0]:
                transport["service_name"] = path

        if need_transport:
            proxy.transport = transport

        return proxy
    except Exception as e:
        if verbose:
            logger.exception(f"Error parsing vless URI: {e}")
        return None

def parse_vmess(uri: str, fragment: str,
                allowed_transport: Optional[Set[str]] = None,
                verbose: bool = False) -> Optional[Proxy]:
    try:
        data = uri[8:]
        if '#' in data:
            data, _ = data.split('#', 1)
        data += '=' * (4 - len(data) % 4) if len(data) % 4 else ''
        decoded = base64.urlsafe_b64decode(data).decode('utf-8')
        cfg = json.loads(decoded)

        has_net = 'net' in cfg
        network = cfg.get('net', 'tcp')

        SUPPORTED_TRANSPORT = {'tcp', 'ws', 'http', 'quic', 'grpc', 'httpupgrade', 'h2'}
        if network not in SUPPORTED_TRANSPORT:
            if verbose:
                logger.debug(f"vmess: unsupported transport type '{network}', skipping")
            return None

        if allowed_transport is not None:
            transport_match = False
            if has_net:
                if network in allowed_transport:
                    transport_match = True
            else:
                if '' in allowed_transport:
                    transport_match = True
            if not transport_match:
                if verbose:
                    logger.debug(f"vmess: filtered out by transport (has_net={has_net}, network='{network}', allowed={allowed_transport})")
                return None

        original_host = cfg.get('add', '')
        if not original_host:
            if verbose:
                logger.warning("vmess: empty server address")
            return None
        port = int(cfg.get('port', 0))

        if '@' in original_host:
            if verbose:
                logger.warning(f"vmess: invalid URI (multiple '@' in host): {original_host}")
            return None

        proxy = Proxy(
            type="vmess",
            tag=f"vmess-{original_host}-{port}",
            server=original_host,
            server_port=port,
            uuid=cfg.get('id', ''),
            security=cfg.get('scy', 'auto'),
            alter_id=int(cfg.get('aid', 0)),
            original_host=original_host,
            original_uri=uri,
            vmess_json=cfg
        )
        if fragment:
            proxy.fragment = html.unescape(urllib.parse.unquote(fragment)).strip()
        else:
            proxy.fragment = ""

        if cfg.get('tls') == 'tls':
            tls_obj = {"enabled": True}
            sni = cfg.get('sni')
            if sni:
                tls_obj["server_name"] = sni
            else:
                tls_obj["server_name"] = original_host
            proxy.tls = tls_obj

        transport = {}
        need_transport = False
        if network != "tcp":
            need_transport = True
            transport["type"] = network
        if network == 'ws':
            need_transport = True
            transport["type"] = "ws"
            transport["path"] = cfg.get('path', '')
            if host := cfg.get('host'):
                transport["headers"] = {"Host": host}
        elif network == 'grpc':
            need_transport = True
            transport["type"] = "grpc"
            transport["service_name"] = cfg.get('path', '')

        if need_transport:
            proxy.transport = transport

        return proxy
    except Exception as e:
        if verbose:
            logger.exception(f"Error parsing vmess URI: {e}")
        return None

def parse_trojan(uri: str, fragment: str,
                 allowed_transport: Optional[Set[str]] = None,
                 verbose: bool = False) -> Optional[Proxy]:
    try:
        data = uri[9:]
        data, _, params = split_uri(data)

        if '@' not in data:
            return None
        password, hostport = data.split('@', 1)

        if '@' in hostport:
            if verbose:
                logger.warning(f"trojan: invalid URI (multiple '@' in hostport): {hostport}")
            return None

        original_host, port = extract_port(hostport)

        has_explicit_type = 'type' in params
        network = params.get('type', ['tcp'])[0]

        SUPPORTED_TRANSPORT = {'tcp', 'ws', 'grpc', 'http', 'quic', 'httpupgrade'}
        if network not in SUPPORTED_TRANSPORT:
            if verbose:
                logger.debug(f"trojan: unsupported transport type '{network}', skipping")
            return None

        if allowed_transport is not None:
            transport_match = False
            if has_explicit_type:
                if network in allowed_transport:
                    transport_match = True
            else:
                if '' in allowed_transport:
                    transport_match = True
            if not transport_match:
                if verbose:
                    logger.debug(f"trojan: filtered out by transport (has_explicit_type={has_explicit_type}, network='{network}', allowed={allowed_transport})")
                return None

        proxy = Proxy(
            type="trojan",
            tag=f"trojan-{original_host}-{port}",
            server=original_host,
            server_port=port,
            password=password,
            original_host=original_host,
            original_uri=uri,
            params=params
        )
        if fragment:
            proxy.fragment = html.unescape(urllib.parse.unquote(fragment)).strip()
        else:
            proxy.fragment = ""

        tls_obj = {"enabled": True}
        sni = params.get('sni', [None])[0]
        if sni:
            tls_obj["server_name"] = sni
        else:
            tls_obj["server_name"] = original_host
        if alpn := params.get('alpn', [None])[0]:
            tls_obj["alpn"] = [alpn]
        proxy.tls = tls_obj

        transport = {}
        need_transport = False
        if network != "tcp":
            need_transport = True
            transport["type"] = network
        if network == 'ws':
            need_transport = True
            transport["type"] = "ws"
            if path := params.get('path', [None])[0]:
                transport["path"] = path
            if host_header := params.get('host', [None])[0]:
                transport["headers"] = {"Host": host_header}

        if need_transport:
            proxy.transport = transport

        return proxy
    except Exception as e:
        if verbose:
            logger.exception(f"Error parsing trojan URI: {e}")
        return None

def parse_shadowsocks(uri: str, fragment: str,
                      verbose: bool = False) -> Optional[Proxy]:
    METHOD_ALIASES = {
        'chacha20-poly1305': 'chacha20-ietf-poly1305',
    }
    KNOWN_METHODS = {
        'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
        'chacha20-ietf-poly1305',
        'xchacha20-ietf-poly1305',
        '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
        '2022-blake3-chacha20-poly1305',
        'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
        'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
        'rc4-md5', 'rc4-md5-6',
        'chacha20', 'chacha20-ietf', 'salsa20',
        'camellia-128-cfb', 'camellia-192-cfb', 'camellia-256-cfb',
        'none', 'plain'
    }

    try:
        data = uri[5:]
        data, _, params = split_uri(data)

        if '@' in data:
            userpass, hostport = data.split('@', 1)
            if re.match(r'^[A-Za-z0-9\-_=]+$', userpass):
                try:
                    decoded = base64.urlsafe_b64decode(userpass + '=' * (-len(userpass) % 4)).decode('utf-8')
                    if ':' in decoded:
                        method, password = decoded.split(':', 1)
                    else:
                        method = decoded
                        password = ''
                except Exception:
                    if ':' in userpass:
                        method, password = userpass.split(':', 1)
                    else:
                        method = userpass
                        password = ''
            else:
                if ':' in userpass:
                    method, password = userpass.split(':', 1)
                else:
                    method = userpass
                    password = ''
        else:
            decoded = base64.urlsafe_b64decode(data + '=' * (-len(data) % 4)).decode('utf-8')
            if '@' not in decoded:
                raise ValueError("Invalid SIP002 format: no '@' after base64 decode")
            userpass, hostport = decoded.split('@', 1)
            if ':' in userpass:
                method, password = userpass.split(':', 1)
            else:
                method = userpass
                password = ''

        method = METHOD_ALIASES.get(method, method)

        if method not in KNOWN_METHODS:
            if verbose:
                logger.debug(f"ss: unknown encryption method '{method}', skipping")
            return None

        host, port = extract_port(hostport)

        if '@' in host:
            if verbose:
                logger.warning(f"ss: invalid URI (multiple '@' in host): {host}")
            return None

        proxy = Proxy(
            type="shadowsocks",
            tag=f"ss-{host}-{port}",
            server=host,
            server_port=port,
            method=method,
            password=password,
            original_host=host,
            original_uri=uri,
            params=params
        )
        if fragment:
            proxy.fragment = html.unescape(urllib.parse.unquote(fragment)).strip()
        else:
            proxy.fragment = ""

        if 'plugin' in params:
            proxy.plugin = params['plugin'][0]

        return proxy
    except Exception as e:
        if verbose:
            logger.exception(f"Error parsing ss URI: {e}")
        return None

def parse_socks(uri: str, fragment: str,
                verbose: bool = False) -> Optional[Proxy]:
    try:
        if uri.startswith('socks5://'):
            scheme = 'socks5'
            data = uri[9:]
        elif uri.startswith('socks4://'):
            scheme = 'socks4'
            data = uri[9:]
        else:
            return None

        data, _, params = split_uri(data)

        if '@' in data:
            userpass, hostport = data.split('@', 1)
            if ':' in userpass:
                username, password = userpass.split(':', 1)
            else:
                username, password = userpass, ''
        else:
            username, password = None, None
            hostport = data

        host, port = extract_port(hostport, default_port=1080)

        if '@' in host:
            if verbose:
                logger.warning(f"socks: invalid URI (multiple '@' in host): {host}")
            return None

        proxy = Proxy(
            type="socks",
            tag=f"socks-{host}-{port}",
            server=host,
            server_port=port,
            version="5" if scheme == 'socks5' else "4",
            original_host=host,
            original_uri=uri,
            params=params
        )
        if fragment:
            proxy.fragment = html.unescape(urllib.parse.unquote(fragment)).strip()
        else:
            proxy.fragment = ""

        if username and password:
            proxy.username = username
            proxy.password = password

        return proxy
    except Exception as e:
        if verbose:
            logger.exception(f"Error parsing socks URI: {e}")
        return None

def parse_http(uri: str, fragment: str,
               verbose: bool = False) -> Optional[Proxy]:
    try:
        parsed = urllib.parse.urlparse(uri)
        if parsed.scheme not in ('http', 'https'):
            return None

        host = parsed.hostname
        if '@' in host:
            if verbose:
                logger.warning(f"http: invalid URI (multiple '@' in host): {host}")
            return None

        port = parsed.port or (80 if parsed.scheme == 'http' else 443)

        proxy = Proxy(
            type="http",
            tag=f"http-{host}-{port}",
            server=host,
            server_port=port,
            original_host=host,
            original_uri=uri,
            parsed_uri=parsed
        )
        if fragment:
            proxy.fragment = html.unescape(urllib.parse.unquote(fragment)).strip()
        else:
            proxy.fragment = ""

        if parsed.username and parsed.password:
            proxy.username = parsed.username
            proxy.password = parsed.password

        if parsed.scheme == 'https':
            proxy.tls = {"enabled": True, "server_name": host}

        return proxy
    except Exception as e:
        if verbose:
            logger.exception(f"Error parsing http URI: {e}")
        return None

def parse_hysteria(uri: str, fragment: str,
                   verbose: bool = False) -> Optional[Proxy]:
    try:
        data = uri[11:]  # len('hysteria://') == 11
        data, _, params = split_uri(data)

        original_host, port = extract_port(data, default_port=443)
        if not original_host:
            if verbose:
                logger.warning("hysteria: empty host after extract_port")
            return None

        if '@' in original_host:
            if verbose:
                logger.warning(f"hysteria: invalid host (contains '@'): {original_host}")
            return None

        proxy = Proxy(
            type="hysteria",
            tag=f"hysteria-{original_host}-{port}",
            server=original_host,
            server_port=port,
            original_host=original_host,
            original_uri=uri,
            params=params
        )
        if fragment:
            proxy.fragment = html.unescape(urllib.parse.unquote(fragment)).strip()
        else:
            proxy.fragment = ""

        if up := params.get('upmbps', [None])[0]:
            proxy.up_mbps = int(up)
        if down := params.get('downmbps', [None])[0]:
            proxy.down_mbps = int(down)
        if auth := params.get('auth', [None])[0]:
            proxy.auth_str = auth
        if obfs := params.get('obfs', [None])[0]:
            proxy.obfs = obfs
        if protocol := params.get('protocol', [None])[0]:
            proxy.protocol = protocol
        if peer := params.get('peer', [None])[0]:
            proxy.peer = peer
        if insecure := params.get('insecure', [None])[0]:
            proxy.insecure = insecure.lower() == 'true'
        if alpn := params.get('alpn', [None])[0]:
            proxy.alpn = alpn.split(',')

        tls_obj = {"enabled": True}
        if sni := params.get('sni', [None])[0]:
            tls_obj["server_name"] = sni
        else:
            tls_obj["server_name"] = original_host
        if insecure := params.get('insecure', [None])[0]:
            tls_obj["insecure"] = insecure.lower() == 'true'
        if alpn := params.get('alpn', [None])[0]:
            tls_obj["alpn"] = alpn.split(',')
        proxy.tls = tls_obj

        return proxy
    except Exception as e:
        if verbose:
            logger.exception(f"Error parsing hysteria URI: {e}")
        return None

def parse_hysteria2(uri: str, fragment: str,
                    verbose: bool = False) -> Optional[Proxy]:
    try:
        data = uri[12:]  # len('hysteria2://') == 12
        data, _, params = split_uri(data)

        original_host, port = extract_port(data, default_port=443)
        if not original_host:
            if verbose:
                logger.warning("hysteria2: empty host after extract_port")
            return None

        if '@' in original_host:
            if verbose:
                logger.warning(f"hysteria2: invalid host (contains '@'): {original_host}")
            return None

        proxy = Proxy(
            type="hysteria2",
            tag=f"hysteria2-{original_host}-{port}",
            server=original_host,
            server_port=port,
            original_host=original_host,
            original_uri=uri,
            params=params
        )
        if fragment:
            proxy.fragment = html.unescape(urllib.parse.unquote(fragment)).strip()
        else:
            proxy.fragment = ""

        if up := params.get('upmbps', [None])[0]:
            proxy.up_mbps = int(up)
        if down := params.get('downmbps', [None])[0]:
            proxy.down_mbps = int(down)
        if auth := params.get('auth', [None])[0]:
            proxy.auth = auth
        if obfs_type := params.get('obfs', [None])[0]:
            proxy.obfs = {"type": obfs_type}
            if obfs_pass := params.get('obfs-password', [None])[0]:
                proxy.obfs["password"] = obfs_pass

        tls_obj = {"enabled": True}
        if sni := params.get('sni', [None])[0]:
            tls_obj["server_name"] = sni
        else:
            tls_obj["server_name"] = original_host
        if insecure := params.get('insecure', [None])[0]:
            tls_obj["insecure"] = insecure.lower() == 'true'
        if alpn := params.get('alpn', [None])[0]:
            tls_obj["alpn"] = alpn.split(',')
        proxy.tls = tls_obj

        return proxy
    except Exception as e:
        if verbose:
            logger.exception(f"Error parsing hysteria2 URI: {e}")
        return None

# ----------------------------------------------------------------------
# Subscription processor (only parsing, no DNS resolution)
# ----------------------------------------------------------------------
def process_subscription(source: str,
                         allowed_types: Optional[Set[str]] = None,
                         vless_transport: Optional[Set[str]] = None,
                         vless_tls: Optional[Set[str]] = None,
                         vmess_transport: Optional[Set[str]] = None,
                         trojan_transport: Optional[Set[str]] = None,
                         seen_keys: Optional[Set[str]] = None,
                         deduplicate: bool = True,
                         keep_original_tags: bool = False,
                         tag_format: Optional[str] = None,
                         export_format: str = 'sing-box',
                         no_number_tags: bool = False,
                         verbose: bool = False,
                         progress_ctx=None) -> List[Proxy]:
    raw_proxies = []

    try:
        if source.startswith('http://') or source.startswith('https://'):
            if verbose:
                logger.info(f"Downloading from URL: {source}")
            with urllib.request.urlopen(source, timeout=10) as resp:
                content = resp.read().decode('utf-8')
        else:
            if verbose:
                logger.info(f"Reading local file: {source}")
            with open(source, 'r', encoding='utf-8') as f:
                content = f.read()

        content = maybe_decode_base64(content, verbose)

        lines = content.strip().split('\n')
        parse_task = None
        if progress_ctx:
            parse_task = progress_ctx.add_task(f"[cyan]Parsing {os.path.basename(source)}", total=len(lines))

        for idx, line in enumerate(lines):
            if progress_ctx and idx % 100 == 0:
                progress_ctx.update(parse_task, completed=idx)

            line = line.strip()
            if not line or line.startswith('#'):
                continue

            proto = None
            main_part, fragment, _ = split_uri(line)
            uri_without_frag = main_part
            if uri_without_frag.startswith('vless://'):
                proto = 'vless'
            elif uri_without_frag.startswith('vmess://'):
                proto = 'vmess'
            elif uri_without_frag.startswith('trojan://'):
                proto = 'trojan'
            elif uri_without_frag.startswith('ss://'):
                proto = 'shadowsocks'
            elif uri_without_frag.startswith('socks5://') or uri_without_frag.startswith('socks4://'):
                proto = 'socks'
            elif uri_without_frag.startswith('http://') or uri_without_frag.startswith('https://'):
                proto = 'http'
            elif uri_without_frag.startswith('hysteria://'):
                proto = 'hysteria'
            elif uri_without_frag.startswith('hysteria2://'):
                proto = 'hysteria2'
            else:
                if verbose:
                    logger.debug(f"Unsupported or unknown URI scheme: {line[:50]}...")
                continue

            if allowed_types and proto not in allowed_types:
                continue

            proxy = None
            if proto == 'vless':
                proxy = parse_vless(line, fragment, vless_transport, vless_tls, verbose=verbose)
            elif proto == 'vmess':
                proxy = parse_vmess(line, fragment, vmess_transport, verbose=verbose)
            elif proto == 'trojan':
                proxy = parse_trojan(line, fragment, trojan_transport, verbose=verbose)
            elif proto == 'shadowsocks':
                proxy = parse_shadowsocks(line, fragment, verbose=verbose)
            elif proto == 'socks':
                proxy = parse_socks(line, fragment, verbose=verbose)
            elif proto == 'http':
                proxy = parse_http(line, fragment, verbose=verbose)
            elif proto == 'hysteria':
                proxy = parse_hysteria(line, fragment, verbose=verbose)
            elif proto == 'hysteria2':
                proxy = parse_hysteria2(line, fragment, verbose=verbose)

            if proxy is None:
                if verbose:
                    logger.warning(f"Failed to parse: {line[:50]}...")
                continue

            if deduplicate:
                key = f"{proxy.original_host}:{proxy.server_port}"
                if key in seen_keys:
                    if verbose:
                        logger.debug(f"Deduplicate (host:port): skipping {proto}://{key} (already seen)")
                    continue
                seen_keys.add(key)

            if tag_format is not None:
                proxy.base_tag = tag_format
                if no_number_tags:
                    proxy.no_number = True
                elif '{ip}' in tag_format and '{port}' in tag_format:
                    proxy.no_number = True
            elif keep_original_tags and proxy.fragment:
                proxy.base_tag = proxy.fragment
                if no_number_tags:
                    proxy.no_number = True
            else:
                proxy.base_tag = "{proto}-{ip}-{port}"
                proxy.no_number = True

            raw_proxies.append(proxy)

        if progress_ctx:
            progress_ctx.update(parse_task, visible=False)

    except Exception as e:
        if verbose:
            logger.exception(f"Error processing {source}: {e}")
        return []

    return raw_proxies

# ----------------------------------------------------------------------
# Sing-box test helpers
# ----------------------------------------------------------------------
port_lock = threading.Lock()
active_processes = []
processes_lock = threading.Lock()

@atexit.register
def cleanup_processes():
    with processes_lock:
        for proc in active_processes:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except:
                proc.kill()
        active_processes.clear()

def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def create_temp_config(proxy: Proxy, inbound_port: int, temp_dir: str, verbose: bool = False) -> str:
    ob = proxy.to_dict(remove_metadata=True)
    config = {
        "log": {"level": "error" if not verbose else "info", "output": "/dev/null" if not verbose else None},
        "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": inbound_port}],
        "outbounds": [ob],
        "route": {"rules": [{"inbound": ["socks-in"], "outbound": ob.get("tag", "proxy")}]}
    }
    fd, path = tempfile.mkstemp(suffix='.json', prefix='singbox_test_', dir=temp_dir)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)
    return path

def resolve_domain_via_proxy(domain: str, proxy_port: int, timeout: float, curl_path: str, verbose: bool = False) -> Optional[str]:
    url = f"https://dns.google/resolve?name={domain}&type=A"
    cmd = [curl_path, '--socks5-hostname', f'127.0.0.1:{proxy_port}',
           '--max-time', str(timeout), '--connect-timeout', str(timeout), '--silent', url]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+5)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            answers = data.get('Answer', [])
            for ans in answers:
                if ans.get('type') == 1:
                    return ans.get('data')
        if verbose:
            logger.debug(f"DoH resolution failed for {domain}: {result.stderr}")
    except Exception as e:
        if verbose:
            logger.warning(f"Exception during DoH resolution for {domain}: {e}")
    return None

def get_external_ip_via_proxy(proxy_port: int, timeout: float, curl_path: str, verbose: bool = False) -> Optional[str]:
    """Try multiple services to get external IP through proxy."""
    services = [
        'https://checkip.amazonaws.com',
        'https://api.ipify.org'
    ]
    for url in services:
        try:
            cmd = [curl_path, '--socks5-hostname', f'127.0.0.1:{proxy_port}',
                   '--max-time', str(timeout), '--connect-timeout', str(timeout),
                   '--silent', url]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
            if result.returncode == 0:
                ip = result.stdout.strip()
                if ip and is_valid_ip(ip):
                    if verbose:
                        logger.debug(f"Got external IP {ip} from {url}")
                    return ip
        except Exception as e:
            if verbose:
                logger.debug(f"Failed to get IP from {url}: {e}")
            continue
    return None

# ----------------------------------------------------------------------
# Country code lookup via multiple free APIs (all through proxy)
# ----------------------------------------------------------------------
def get_country_code(ip: str, proxy_port: int, timeout: float, curl_path: str, verbose: bool) -> Optional[str]:
    """
    Try several free IP geolocation APIs sequentially via the proxy.
    Returns the two-letter country code or None if all fail.
    """
    apis = [
        # iplocation.net
        {
            "url": f"https://api.iplocation.net/?ip={ip}",
            "extractor": lambda data: data.get("country_code2") if isinstance(data, dict) else None,
            "is_json": True
        },
        # ip-api.com (free, no key, limited to 45 req/min)
        {
            "url": f"http://ip-api.com/json/{ip}?fields=countryCode",
            "extractor": lambda data: data.get("countryCode") if isinstance(data, dict) else None,
            "is_json": True
        },
        # ipapi.co (free, 1000 req/day, no key)
        {
            "url": f"https://ipapi.co/{ip}/json/",
            "extractor": lambda data: data.get("country_code") if isinstance(data, dict) else None,
            "is_json": True
        }
    ]

    for api in apis:
        try:
            cmd = [
                curl_path, '--socks5-hostname', f'127.0.0.1:{proxy_port}',
                '--max-time', str(timeout), '--connect-timeout', str(timeout),
                '--silent', api["url"]
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
            if result.returncode != 0:
                if verbose:
                    logger.debug(f"Country API {api['url']} failed: curl error {result.returncode}")
                continue

            response = result.stdout.strip()
            if not response:
                continue

            if api["is_json"]:
                try:
                    data = json.loads(response)
                except json.JSONDecodeError:
                    if verbose:
                        logger.debug(f"Country API {api['url']} returned invalid JSON: {response[:100]}")
                    continue
                country = api["extractor"](data)
            else:
                country = api["extractor"](response)

            if country and isinstance(country, str) and len(country) == 2:
                if verbose:
                    logger.debug(f"Got country {country} for IP {ip} from {api['url']}")
                return country.upper()
            else:
                if verbose:
                    logger.debug(f"Country API {api['url']} returned no valid country code (response: {response[:100]})")
        except subprocess.TimeoutExpired:
            if verbose:
                logger.debug(f"Country API {api['url']} timed out")
            continue
        except Exception as e:
            if verbose:
                logger.debug(f"Country API {api['url']} exception: {e}")
            continue

    return None

# ----------------------------------------------------------------------
# Sing-box test with cache, latency, speedtest, DNS, and country (both via proxy)
# ----------------------------------------------------------------------
def test_with_singbox(proxy: Proxy, test_url: str,
                      timeout: float, singbox_path: str,
                      resolve_country: bool,
                      cache_dir: str,
                      speedtest: bool,
                      speedtest_download_url: str,
                      speedtest_upload_url: str,
                      speedtest_timeout: float,
                      cache_ttl: int,
                      ignore_cache: bool,
                      temp_dir: str,
                      country_api_timeout: float,
                      verbose: bool = False) -> bool:
    host = proxy.original_host
    port = proxy.server_port
    key = f"{host}:{port}"

    global test_cache
    if not ignore_cache:
        with test_cache_lock:
            cached = test_cache.get(key)
            if cached and time.time() - cached.get('timestamp', 0) < cache_ttl:
                if cached.get('reachable', False):
                    proxy.server = cached.get('resolved_ip', host)
                    proxy.country_in = cached.get('country_in')
                    proxy.country_out = cached.get('country_out')
                    proxy.out_ip = cached.get('out_ip')
                    proxy.latency = cached.get('latency')
                    proxy.speed_download = cached.get('speed_download')
                    proxy.speed_upload = cached.get('speed_upload')
                    return True
                else:
                    return False

    curl_path = shutil.which('curl')
    if not curl_path:
        if verbose:
            logger.error("curl not found in PATH, required for sing-box test")
        return False

    cmd_base = [singbox_path, 'run', '-c']

    with port_lock:
        inbound_port = find_free_port()
        config_path = create_temp_config(proxy, inbound_port, temp_dir, verbose)
        if verbose:
            logger.debug(f"Starting sing-box for outbound {proxy.tag} on port {inbound_port}")
        proc = subprocess.Popen(cmd_base + [config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with processes_lock:
            active_processes.append(proc)

    # Wait for port ready
    ready = False
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect(('127.0.0.1', inbound_port))
            s.close()
            ready = True
            break
        except:
            time.sleep(0.1)
    if not ready:
        if verbose:
            logger.warning(f"sing-box did not start within timeout")
        with processes_lock:
            if proc in active_processes:
                active_processes.remove(proc)
        proc.terminate()
        try:
            os.unlink(config_path)
        except:
            pass
        return False

    # --- 1. Latency Test ---
    curl_cmd = [
        curl_path, '--socks5-hostname', f'127.0.0.1:{inbound_port}',
        '--max-time', str(timeout), '--connect-timeout', str(timeout),
        '--silent', '--head', '--output', '/dev/null', '--write-out', '%{http_code}', test_url
    ]
    start_curl = time.time()
    try:
        curl_result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=timeout+5)
        latency = time.time() - start_curl
        http_code = curl_result.stdout.strip()
        if verbose:
            logger.debug(f"Latency test returned HTTP {http_code} in {latency:.3f}s")
        success = http_code.startswith(('2', '3'))
    except subprocess.TimeoutExpired:
        if verbose:
            logger.warning(f"Latency test timed out")
        success = False
        latency = timeout
    except Exception as e:
        if verbose:
            logger.exception(f"Latency test exception: {e}")
        success = False
        latency = timeout

    if not success:
        proxy.latency = latency
        with processes_lock:
            if proc in active_processes:
                active_processes.remove(proc)
        proc.terminate()
        try:
            os.unlink(config_path)
        except:
            pass
        return False

    proxy.latency = latency

    # --- 2. DNS resolution via DoH through proxy ---
    resolved_ip = None
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$', proxy.original_host):
        resolved_ip = resolve_domain_via_proxy(proxy.original_host, inbound_port, timeout, curl_path, verbose)
        if resolved_ip:
            proxy.server = resolved_ip
            if verbose:
                logger.debug(f"Resolved {proxy.original_host} -> {resolved_ip} via proxy")
        else:
            if verbose:
                logger.debug(f"Failed to resolve {proxy.original_host} via proxy")
            with processes_lock:
                if proc in active_processes:
                    active_processes.remove(proc)
            proc.terminate()
            try:
                os.unlink(config_path)
            except:
                pass
            return False
    else:
        proxy.server = proxy.original_host
        resolved_ip = proxy.original_host

    # --- 3. Country Resolution (IN and OUT) using multiple APIs ---
    if resolve_country and resolved_ip:
        # IN country
        country_in = get_country_code(resolved_ip, inbound_port, country_api_timeout, curl_path, verbose)
        if country_in:
            proxy.country_in = country_in
            country_cache.set(resolved_ip, country_in)
        else:
            if verbose:
                logger.debug(f"IN country lookup failed for {resolved_ip} (all APIs failed)")
            with processes_lock:
                if proc in active_processes:
                    active_processes.remove(proc)
            proc.terminate()
            try:
                os.unlink(config_path)
            except:
                pass
            return False

        # OUT country: get external IP
        out_ip = get_external_ip_via_proxy(inbound_port, 5, curl_path, verbose)
        if out_ip:
            proxy.out_ip = out_ip
            # Check cache first
            cached_out_country = country_cache.get(out_ip)
            if cached_out_country:
                proxy.country_out = cached_out_country
                if verbose:
                    logger.debug(f"OUT country from cache: {cached_out_country} for {out_ip}")
            else:
                country_out = get_country_code(out_ip, inbound_port, country_api_timeout, curl_path, verbose)
                if country_out:
                    proxy.country_out = country_out
                    country_cache.set(out_ip, country_out)
                    if verbose:
                        logger.debug(f"Outgoing country: {country_out} IP: {out_ip}")
                else:
                    if verbose:
                        logger.debug(f"OUT country lookup failed for {out_ip} (all APIs failed)")
                    with processes_lock:
                        if proc in active_processes:
                            active_processes.remove(proc)
                    proc.terminate()
                    try:
                        os.unlink(config_path)
                    except:
                        pass
                    return False
        else:
            if verbose:
                logger.debug(f"Failed to get external IP via proxy")
            with processes_lock:
                if proc in active_processes:
                    active_processes.remove(proc)
            proc.terminate()
            try:
                os.unlink(config_path)
            except:
                pass
            return False

    # --- 4. Download Speedtest (manual) ---
    if speedtest and speedtest_download_url:
        def get_file_size(url, proxy_port, timeout, curl_path, verbose):
            cmd = [curl_path, '--socks5-hostname', f'127.0.0.1:{proxy_port}',
                   '--max-time', str(timeout), '--connect-timeout', str(timeout),
                   '--silent', '--head', url]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+5)
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if line.lower().startswith('content-length:'):
                            return int(line.split(':')[1].strip())
                if verbose:
                    logger.debug(f"Could not get file size from {url}, using default 1MB")
            except Exception as e:
                if verbose:
                    logger.warning(f"Failed to get file size: {e}")
            return None

        file_size = get_file_size(speedtest_download_url, inbound_port, 5, curl_path, verbose)
        if file_size is None:
            file_size = 1_048_576

        download_cmd = [
            curl_path, '--socks5-hostname', f'127.0.0.1:{inbound_port}',
            '--max-time', str(speedtest_timeout), '--connect-timeout', str(timeout),
            '--silent', '--output', '/dev/null', speedtest_download_url
        ]
        try:
            start = time.time()
            result = subprocess.run(download_cmd, capture_output=True, timeout=speedtest_timeout+5)
            elapsed = time.time() - start
            if result.returncode == 0:
                speed_bps = file_size / elapsed
                speed_mbps = speed_bps * 8 / 1_000_000
                proxy.speed_download = round(speed_mbps, 2)
                if verbose:
                    logger.debug(f"Download speed: {proxy.speed_download} Mbps")
            else:
                if verbose:
                    logger.warning(f"Download speedtest failed, curl exit code {result.returncode}")
        except subprocess.TimeoutExpired:
            if verbose:
                logger.warning("Download speedtest timed out")
        except Exception as e:
            if verbose:
                logger.warning(f"Download speedtest exception: {e}")

    # --- 5. Upload Speedtest (manual) ---
    if speedtest and speedtest_upload_url:
        upload_data_size = 1_048_576
        data_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tmp_file:
                tmp_file.write(os.urandom(upload_data_size))
                data_file = tmp_file.name

            upload_cmd = [
                curl_path, '--socks5-hostname', f'127.0.0.1:{inbound_port}',
                '--max-time', str(speedtest_timeout), '--connect-timeout', str(timeout),
                '--silent', '--output', '/dev/null', '--data-binary', f'@{data_file}',
                speedtest_upload_url
            ]
            start = time.time()
            result = subprocess.run(upload_cmd, capture_output=True, timeout=speedtest_timeout+5)
            elapsed = time.time() - start
            if result.returncode == 0:
                speed_bps = upload_data_size / elapsed
                speed_mbps = speed_bps * 8 / 1_000_000
                proxy.speed_upload = round(speed_mbps, 2)
                if verbose:
                    logger.debug(f"Upload speed: {proxy.speed_upload} Mbps")
            else:
                if verbose:
                    logger.warning(f"Upload speedtest failed, curl exit code {result.returncode}")
        except subprocess.TimeoutExpired:
            if verbose:
                logger.warning("Upload speedtest timed out")
        except Exception as e:
            if verbose:
                logger.warning(f"Upload speedtest exception: {e}")
        finally:
            if data_file and os.path.exists(data_file):
                os.unlink(data_file)

    # Cleanup
    with processes_lock:
        if proc in active_processes:
            active_processes.remove(proc)
    proc.terminate()
    try:
        os.unlink(config_path)
    except:
        pass

    with test_cache_lock:
        test_cache[key] = {
            'timestamp': time.time(),
            'reachable': success,
            'latency': latency,
            'resolved_ip': resolved_ip,
            'country_in': proxy.country_in if resolve_country else None,
            'country_out': proxy.country_out if resolve_country else None,
            'out_ip': proxy.out_ip if resolve_country else None,
            'speed_download': proxy.speed_download if speedtest else None,
            'speed_upload': proxy.speed_upload if speedtest else None
        }

    return success

# ----------------------------------------------------------------------
# Config handling (load_config, custom_sort, update_selectors, create_default_selectors)
# ----------------------------------------------------------------------
def load_config(config_path: str, verbose: bool) -> Optional[Dict]:
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            if verbose:
                logger.warning(f"{config_path} is not valid JSON, attempting to strip comments...")
            lines = content.split('\n')
            cleaned_lines = [line for line in lines if not re.match(r'^\s*//', line)]
            cleaned = '\n'.join(cleaned_lines)
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError as e:
                if verbose:
                    logger.error(f"Still not valid JSON after stripping comments: {e}")
                return None
    except Exception as e:
        if verbose:
            logger.exception(f"Error loading config {config_path}: {e}")
        return None

def custom_sort(tags: Set[str]) -> List[str]:
    priority = ['BLOCK', 'DIRECT', 'AUTO', 'TOR']
    priority_present = [tag for tag in priority if tag in tags]
    others = sorted(tag for tag in tags if tag not in priority)
    return priority_present + others

def update_selectors(config: Dict,
                     proxy_tags: Set[str],
                     service_tags: Set[str],
                     selector_tags: Set[str],
                     verbose: bool) -> int:
    if 'outbounds' not in config or not isinstance(config['outbounds'], list):
        if verbose:
            logger.warning("No outbounds array in config, skipping selector update")
        return 0
    updated = 0
    forbidden_in_auto = {'BLOCK', 'DIRECT'}
    base_allowed = proxy_tags.union(service_tags)
    for ob in config['outbounds']:
        if ob.get('type') not in ('selector', 'urltest'):
            continue
        if 'outbounds' not in ob or not isinstance(ob['outbounds'], list):
            continue
        original = set(ob['outbounds'])
        own_tag = ob.get('tag')
        ob_type = ob.get('type')
        if ob_type == 'urltest':
            allowed = proxy_tags - forbidden_in_auto
        else:
            allowed = base_allowed.union({'AUTO'})
            allowed = (allowed - selector_tags) | {'AUTO'}
            if own_tag == 'TOR-SERVICE':
                allowed.discard('TOR')
        if own_tag:
            allowed.discard(own_tag)
        sorted_list = custom_sort(allowed)
        if sorted_list != ob['outbounds']:
            ob['outbounds'] = sorted_list
            updated += 1
            if verbose:
                added = len(allowed) - len(original)
                logger.info(f"Updated {ob['tag']} ({ob_type}) with {added} new tag(s)")
    return updated

def create_default_selectors(proxy_tags: Set[str], service_tags: Set[str], selector_tags: Set[str]) -> List[Dict]:
    forbidden_in_auto = {'BLOCK', 'DIRECT'}
    auto_allowed = proxy_tags - forbidden_in_auto - {'AUTO'}
    base_allowed = proxy_tags.union(service_tags)
    selectors = []
    if auto_allowed:
        selectors.append({
            "type": "urltest", "tag": "AUTO", "outbounds": custom_sort(auto_allowed),
            "url": "https://cp.cloudflare.com", "interval": "30s", "tolerance": 50,
            "idle_timeout": "30m", "interrupt_exist_connections": False
        })
    if base_allowed:
        global_allowed = base_allowed.union({'AUTO'}) - selector_tags - {'GLOBAL'}
        selectors.append({
            "type": "selector", "tag": "GLOBAL", "outbounds": custom_sort(global_allowed),
            "default": "AUTO", "interrupt_exist_connections": False
        })
    return selectors

# ----------------------------------------------------------------------
# Tag numbering and placeholder substitution
# ----------------------------------------------------------------------
def format_country_pair(proxy: Proxy) -> str:
    parts = []
    if proxy.country_in:
        parts.append(f"IN: {proxy.country_in}")
    if proxy.country_out:
        parts.append(f"OUT: {proxy.country_out}")
    return " ".join(parts) if parts else ""

def substitute_placeholders(text: str, proxy: Proxy) -> str:
    text = text.replace('{proto}', proxy.type)
    text = text.replace('{host}', proxy.original_host)
    text = text.replace('{ip}', proxy.server)
    text = text.replace('{port}', str(proxy.server_port))
    text = text.replace('{fragment}', proxy.fragment)
    text = text.replace('{country_in}', proxy.country_in or '')
    text = text.replace('{country_out}', proxy.country_out or '')
    text = text.replace('{country_pair}', format_country_pair(proxy))
    flag_in = country_code_to_flag(proxy.country_in)
    flag_out = country_code_to_flag(proxy.country_out)
    text = text.replace('{flag_in}', flag_in)
    text = text.replace('{flag_out}', flag_out)
    text = text.replace('{flag_pair}', flag_in + flag_out)
    text = text.replace('{in_ip}', proxy.server)
    text = text.replace('{in_port}', str(proxy.server_port))
    text = text.replace('{out_ip}', proxy.out_ip or '')
    download_str = f"{proxy.speed_download:.1f}" if proxy.speed_download is not None else ""
    upload_str = f"{proxy.speed_upload:.1f}" if proxy.speed_upload is not None else ""
    text = text.replace('{speed_download}', download_str)
    text = text.replace('{speed_upload}', upload_str)
    return text

def renumber_tags(proxies: List[Proxy]) -> None:
    to_number = [p for p in proxies if p.base_tag is not None]
    if not to_number:
        return
    no_number = [p for p in to_number if p.no_number]
    need_number = [p for p in to_number if not p.no_number]
    for p in no_number:
        p.tag = substitute_placeholders(p.base_tag, p)
        p.base_tag = None
    groups = {}
    for p in need_number:
        groups.setdefault(p.base_tag, []).append(p)
    for base, group in groups.items():
        for idx, p in enumerate(group, start=1):
            tag = f"{base}-{idx}"
            p.tag = substitute_placeholders(tag, p)
            p.base_tag = None

def renumber_v2ray_fragments(proxies: List[Proxy], tag_format: str, no_number: bool) -> None:
    for p in proxies:
        if p.original_uri:
            p._base_fragment = tag_format
    skip_number = no_number or ('{ip}' in tag_format and '{port}' in tag_format) or ('{in_ip}' in tag_format and '{in_port}' in tag_format)
    for p in proxies:
        if hasattr(p, '_base_fragment'):
            p.fragment = substitute_placeholders(p._base_fragment, p)
    if skip_number:
        for p in proxies:
            if hasattr(p, '_base_fragment'):
                del p._base_fragment
        return
    groups = {}
    for p in proxies:
        if hasattr(p, '_base_fragment'):
            groups.setdefault(p.fragment, []).append(p)
    for base, group in groups.items():
        for idx, p in enumerate(group, start=1):
            p.fragment = f"{base}-{idx}"
            del p._base_fragment

# ----------------------------------------------------------------------
# Country filtering
# ----------------------------------------------------------------------
def apply_country_filters(proxies: List[Proxy],
                          include_in: Optional[Set[str]],
                          exclude_in: Optional[Set[str]],
                          include_out: Optional[Set[str]],
                          exclude_out: Optional[Set[str]],
                          verbose: bool) -> List[Proxy]:
    filtered = []
    for p in proxies:
        if include_in is not None:
            if p.country_in is None or p.country_in not in include_in:
                if verbose:
                    logger.debug(f"Filtered out by include-country-in: {p.tag} (IN={p.country_in})")
                continue
        if exclude_in is not None and p.country_in is not None and p.country_in in exclude_in:
            if verbose:
                logger.debug(f"Filtered out by exclude-country-in: {p.tag} (IN={p.country_in})")
            continue
        if include_out is not None:
            if p.country_out is None or p.country_out not in include_out:
                if verbose:
                    logger.debug(f"Filtered out by include-country-out: {p.tag} (OUT={p.country_out})")
                continue
        if exclude_out is not None and p.country_out is not None and p.country_out in exclude_out:
            if verbose:
                logger.debug(f"Filtered out by exclude-country-out: {p.tag} (OUT={p.country_out})")
            continue
        filtered.append(p)
    return filtered

# ----------------------------------------------------------------------
# Speed filtering function
# ----------------------------------------------------------------------
def apply_speed_filters(proxies: List[Proxy],
                        min_download: Optional[float],
                        min_upload: Optional[float],
                        verbose: bool) -> List[Proxy]:
    if min_download is None and min_upload is None:
        return proxies
    filtered = []
    for p in proxies:
        if min_download is not None:
            speed_d = p.speed_download if p.speed_download is not None else 0.0
            if speed_d < min_download:
                if verbose:
                    logger.debug(f"Filtered out by min-download-speed: {p.tag} (download={speed_d:.1f} < {min_download:.1f})")
                continue
        if min_upload is not None:
            speed_u = p.speed_upload if p.speed_upload is not None else 0.0
            if speed_u < min_upload:
                if verbose:
                    logger.debug(f"Filtered out by min-upload-speed: {p.tag} (upload={speed_u:.1f} < {min_upload:.1f})")
                continue
        filtered.append(p)
    return filtered

# ----------------------------------------------------------------------
# Same IN/OUT IP filtering
# ----------------------------------------------------------------------
def apply_same_in_out_ip_filter(proxies: List[Proxy], verbose: bool) -> List[Proxy]:
    filtered = []
    for p in proxies:
        if p.out_ip is None:
            if verbose:
                logger.debug(f"Filtered out by --same-in-out-ip: no OUT_IP for {p.tag}")
            continue
        if p.server != p.out_ip:
            if verbose:
                logger.debug(f"Filtered out by --same-in-out-ip: IN={p.server} OUT={p.out_ip} for {p.tag}")
            continue
        filtered.append(p)
    return filtered

# ----------------------------------------------------------------------
# V2ray export
# ----------------------------------------------------------------------
def rebuild_uri(proxy: Proxy, new_host: str, remove_ps: bool = False) -> str:
    if proxy.type == 'vmess':
        cfg = proxy.vmess_json.copy()
        cfg['add'] = new_host
        if remove_ps and 'ps' in cfg:
            del cfg['ps']
        json_str = json.dumps(cfg, separators=(',', ':'))
        b64 = base64.urlsafe_b64encode(json_str.encode()).decode().rstrip('=')
        uri = f"vmess://{b64}"
        if proxy.fragment:
            uri += f"#{proxy.fragment}"
        return uri
    elif proxy.type in ('vless', 'trojan', 'shadowsocks', 'socks', 'http', 'hysteria', 'hysteria2'):
        uri = proxy.original_uri
        if '#' in uri:
            base, frag = uri.split('#', 1)
        else:
            base = uri
            frag = ''
        parsed = urllib.parse.urlparse(base)
        if parsed.port:
            netloc = f"{new_host}:{parsed.port}"
        else:
            netloc = new_host
        if parsed.username or parsed.password:
            user_pass = ''
            if parsed.username:
                user_pass = parsed.username
            if parsed.password:
                user_pass += f":{parsed.password}"
            netloc = f"{user_pass}@{netloc}"
        new_base = urllib.parse.urlunparse((
            parsed.scheme,
            netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            ''
        ))
        if frag:
            return f"{new_base}#{frag}"
        else:
            return new_base
    else:
        return proxy.original_uri

def export_v2ray(proxies: List[Proxy], tag_format: Optional[str], resolve_uris: bool, no_number: bool, output_file: Optional[str], verbose: bool, progress_ctx=None) -> None:
    if tag_format is not None:
        renumber_v2ray_fragments(proxies, tag_format, no_number)
    export_task = None
    if progress_ctx:
        export_task = progress_ctx.add_task("[magenta]Exporting URIs", total=len(proxies))
    lines = []
    for idx, p in enumerate(proxies):
        if progress_ctx and idx % 100 == 0:
            progress_ctx.update(export_task, completed=idx)
        if not p.original_uri:
            continue
        if tag_format is not None and p.type == 'vmess':
            new_host = p.server if resolve_uris else p.original_host
            final_uri = rebuild_uri(p, new_host, remove_ps=True)
        else:
            if resolve_uris and p.server and p.original_host and p.server != p.original_host:
                final_uri = rebuild_uri(p, p.server, remove_ps=False)
            else:
                final_uri = p.original_uri
        if tag_format is not None:
            if '#' in final_uri:
                base, _ = final_uri.split('#', 1)
            else:
                base = final_uri
            if p.fragment:
                final_uri = f"{base}#{p.fragment}"
            else:
                final_uri = base
        lines.append(final_uri)
        if progress_ctx:
            progress_ctx.advance(export_task)
    if progress_ctx:
        progress_ctx.update(export_task, visible=False)
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        if verbose:
            logger.info(f"Exported {len(lines)} URIs to {output_file}")
    else:
        for line in lines:
            print(line)

# ----------------------------------------------------------------------
# Progress adapter for rich/tqdm fallback
# ----------------------------------------------------------------------
class ProgressAdapter:
    def __init__(self, use_rich=True):
        self.use_rich = use_rich
        if use_rich:
            from rich.progress import Progress, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn, SpinnerColumn
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=console,
                transient=False,
            )
            self._progress.__enter__()
        else:
            self._tqdm_bars = {}
            self._tqdm_counts = {}
    def add_task(self, description: str, total: int = None) -> int:
        if self.use_rich:
            return self._progress.add_task(description, total=total)
        else:
            import tqdm
            task_id = len(self._tqdm_bars)
            self._tqdm_bars[task_id] = tqdm.tqdm(
                desc=description, total=total, unit="",
                bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
                leave=False
            )
            self._tqdm_counts[task_id] = 0
            return task_id
    def update(self, task_id: int, completed: int = None, total: int = None, visible: bool = None):
        if self.use_rich:
            self._progress.update(task_id, completed=completed, total=total, visible=visible)
        else:
            if task_id in self._tqdm_bars:
                t = self._tqdm_bars[task_id]
                if total is not None:
                    t.total = total
                if completed is not None:
                    self._tqdm_counts[task_id] = completed
                    t.update(completed - t.n)
                if visible is not None and not visible:
                    t.close()
                    del self._tqdm_bars[task_id]
    def advance(self, task_id: int, advance: int = 1):
        if self.use_rich:
            self._progress.advance(task_id, advance=advance)
        else:
            if task_id in self._tqdm_bars:
                self._tqdm_bars[task_id].update(advance)
                self._tqdm_counts[task_id] += advance
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.use_rich:
            self._progress.__exit__(exc_type, exc_val, exc_tb)
        else:
            for bar in self._tqdm_bars.values():
                bar.close()
            self._tqdm_bars.clear()

# ----------------------------------------------------------------------
# Temporary files cleanup
# ----------------------------------------------------------------------
_temp_dir_for_cleanup = None

def cleanup_temp_files():
    if _temp_dir_for_cleanup and os.path.exists(_temp_dir_for_cleanup):
        for fname in os.listdir(_temp_dir_for_cleanup):
            if fname.startswith('singbox_test_') and fname.endswith('.json'):
                try:
                    os.unlink(os.path.join(_temp_dir_for_cleanup, fname))
                except Exception:
                    pass
        try:
            os.rmdir(_temp_dir_for_cleanup)
        except Exception:
            pass

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main():
    default_config_path = os.path.expanduser("~/.config/sub2singbox/config.json")

    parser = argparse.ArgumentParser(
        description="Convert proxy subscription URLs to sing-box outbound configuration or v2ray link list.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('urls', nargs='*', help='Subscription URLs or local file paths to process (optional if --config is provided).')
    parser.add_argument('--export-format', choices=['sing-box', 'v2ray'], default='sing-box',
                        help='Output format: sing-box (JSON outbounds) or v2ray (list of URIs). Default: sing-box.')
    parser.add_argument('--types', '-t', help='Comma-separated list of protocol types to include.')
    parser.add_argument('--vless-transport', help='Comma-separated list of transport types for vless.')
    parser.add_argument('--vless-tls', help='Comma-separated list of TLS types for vless.')
    parser.add_argument('--vmess-transport', help='Comma-separated list of transport types for vmess.')
    parser.add_argument('--trojan-transport', help='Comma-separated list of transport types for trojan.')
    parser.add_argument('--output', '-o', help='Output file name.')
    parser.add_argument('--config', '-c', help='Path to an existing sing-box configuration file.')
    parser.add_argument('--config-file', default=default_config_path,
                        help=f'JSON configuration file with default settings (all command line options can be set here, using either hyphen or underscore). Default: {default_config_path}')
    parser.add_argument('--log-file', help='Path to log file (optional).')
    parser.add_argument('--no-deduplicate', action='store_true', help='Disable deduplication by (host, port) within each subscription source.')
    parser.add_argument('--no-deduplicate-ip-port', action='store_true', help='Disable global deduplication by (IP, port) across all sources and existing config.')
    parser.add_argument('--keep-original-tags', action='store_true', help='Use the fragment part of URI (after #) as the outbound tag.')
    parser.add_argument('--tag-format', help='Custom tag format with placeholders.')
    parser.add_argument('--resolve-uris', action='store_true', help='When exporting to v2ray, replace the hostname with resolved IP.')
    parser.add_argument('--resolve-country', action='store_true', help='Determine country codes for each working proxy via multiple free geolocation APIs (requires --test-connect).')
    parser.add_argument('--include-country-in', help='Comma-separated list of country codes for IN IP (requires --test-connect and --resolve-country).')
    parser.add_argument('--exclude-country-in', help='Comma-separated list of country codes for IN IP (requires --test-connect and --resolve-country).')
    parser.add_argument('--include-country-out', help='Comma-separated list of country codes for OUT IP (requires sing-box test).')
    parser.add_argument('--exclude-country-out', help='Comma-separated list of country codes for OUT IP (requires sing-box test).')
    parser.add_argument('--same-in-out-ip', action='store_true', help='Keep only proxies where server IP equals external IP seen through proxy (requires --test-connect and --resolve-country).')
    parser.add_argument('--no-number-tags', action='store_true', help='Disable automatic numbering of duplicate tags.')
    parser.add_argument('--test-connect', action='store_true', help='Enable connectivity test using sing-box for each outbound.')
    parser.add_argument('--test-url', default='http://cp.cloudflare.com', help='URL to use for testing with sing-box.')
    parser.add_argument('--sing-box-path', default='/usr/bin/sing-box', help='Path to sing-box executable.')
    parser.add_argument('--test-timeout', type=float, default=5, help='Timeout in seconds for connectivity test.')
    parser.add_argument('--test-threads', type=int, default=100, help='Number of threads for connectivity test.')
    parser.add_argument('--speedtest', action='store_true', help='Enable download and upload speed measurement (requires --test-connect).')
    parser.add_argument('--speedtest-download-url', default='http://cachefly.cachefly.net/1mb.test', help='URL for download speed test (default: http://cachefly.cachefly.net/1mb.test).')
    parser.add_argument('--speedtest-upload-url', default='https://httpbin.org/post', help='URL for upload speed test (default: https://httpbin.org/post).')
    parser.add_argument('--speedtest-timeout', type=float, default=15.0, help='Timeout in seconds for each speedtest (default: 15).')
    parser.add_argument('--min-download-speed', type=float, default=None, help='Minimum download speed in Mbps (only applies when --speedtest is enabled).')
    parser.add_argument('--min-upload-speed', type=float, default=None, help='Minimum upload speed in Mbps (only applies when --speedtest is enabled).')
    parser.add_argument('--cache-ttl', type=int, default=3600, help='Cache TTL in seconds (default: 3600).')
    parser.add_argument('--ignore-cache', action='store_true', help='Ignore cached test results and force re-test.')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress all diagnostic output.')
    parser.add_argument('--create-selectors', action='store_true', help='Create default AUTO and GLOBAL selectors if no --config.')
    parser.add_argument('--no-progress', action='store_true', help='Disable progress bars (tqdm or rich).')
    parser.add_argument('--cache-dir', default=os.path.expanduser("~/.cache/sub2singbox"), help='Directory for test result cache (default: ~/.cache/sub2singbox).')
    parser.add_argument('--country-api-timeout', type=float, default=5.0, help='Timeout in seconds for country lookup API requests (default: 5).')

    args, remaining = parser.parse_known_args()

    config_dict = {}
    if args.config_file and os.path.exists(args.config_file):
        try:
            with open(args.config_file, 'r') as f:
                raw_config = json.load(f)
            for k, v in raw_config.items():
                norm_k = k.replace('-', '_')
                config_dict[norm_k] = v
            if not args.quiet:
                logger.info(f"Loaded config from {args.config_file}")
        except Exception as e:
            logger.error(f"Failed to load config file {args.config_file}: {e}")
            sys.exit(1)
    elif args.config_file != default_config_path and not os.path.exists(args.config_file):
        logger.error(f"Config file {args.config_file} not found")
        sys.exit(1)

    for key, value in config_dict.items():
        if key in parser._defaults or any(action.dest == key for action in parser._actions):
            parser.set_defaults(**{key: value})
        else:
            if not args.quiet:
                logger.warning(f"Unknown config key '{key}' ignored")

    args = parser.parse_args()

    verbose = not args.quiet
    use_progress = not args.no_progress

    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)

    if args.log_file:
        file_handler = logging.FileHandler(args.log_file, encoding='utf-8')
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logger.addHandler(file_handler)

    start_time_total = time.time()

    global CACHE_DIR, CACHE_FILE, test_cache
    CACHE_DIR = args.cache_dir
    CACHE_FILE = os.path.join(CACHE_DIR, "cache.json")
    cache_ttl = args.cache_ttl
    test_cache = load_test_cache(CACHE_DIR, cache_ttl)

    temp_dir = os.path.join(CACHE_DIR, 'temp')
    os.makedirs(temp_dir, exist_ok=True)
    global _temp_dir_for_cleanup
    _temp_dir_for_cleanup = temp_dir
    atexit.register(cleanup_temp_files)

    if args.export_format == 'v2ray' and args.config:
        parser.error("--export-format v2ray cannot be used with --config")
    if args.export_format == 'v2ray' and args.create_selectors:
        parser.error("--create-selectors is only meaningful with sing-box export")
    if args.export_format == 'v2ray' and args.keep_original_tags:
        parser.error("--keep-original-tags is only meaningful with sing-box export")
    if args.export_format != 'v2ray' and args.resolve_uris:
        parser.error("--resolve-uris is only meaningful with --export-format v2ray")
    if not args.urls and not args.config:
        parser.error("At least one subscription URL or --config must be provided")
    if (args.resolve_country or args.include_country_in or args.exclude_country_in or
        args.include_country_out or args.exclude_country_out or args.same_in_out_ip) and not args.test_connect:
        parser.error("--resolve-country, country filters, and --same-in-out-ip require --test-connect (to perform sing-box testing)")
    if args.same_in_out_ip and not args.resolve_country:
        parser.error("--same-in-out-ip requires --resolve-country (to obtain OUT_IP)")
    if args.speedtest and not args.test_connect:
        parser.error("--speedtest requires --test-connect")
    if (args.min_download_speed is not None or args.min_upload_speed is not None) and not args.speedtest:
        logger.warning("Speed filters specified but --speedtest is not enabled. Filters will have no effect.")

    def parse_comma_list(value: Optional[str]) -> Optional[Set[str]]:
        if value is None:
            return None
        if value == '':
            return set()
        parts = value.split(',')
        cleaned = [p.strip() for p in parts]
        return set(cleaned)

    allowed_types = parse_comma_list(args.types)
    vless_transport = parse_comma_list(args.vless_transport)
    vless_tls = parse_comma_list(args.vless_tls)
    vmess_transport = parse_comma_list(args.vmess_transport)
    trojan_transport = parse_comma_list(args.trojan_transport)

    include_in = parse_comma_list(args.include_country_in)
    exclude_in = parse_comma_list(args.exclude_country_in)
    include_out = parse_comma_list(args.include_country_out)
    exclude_out = parse_comma_list(args.exclude_country_out)

    if include_in is not None and exclude_in is not None:
        parser.error("--include-country-in and --exclude-country-in cannot be used together")
    if include_out is not None and exclude_out is not None:
        parser.error("--include-country-out and --exclude-country-out cannot be used together")

    if (include_in or exclude_in or include_out or exclude_out) and not args.resolve_country:
        logger.warning("Country filters specified but --resolve-country is not enabled. Filters will have no effect.")

    existing_config = None
    existing_proxy_outbounds = []
    service_outbounds = []
    selector_outbounds = []
    all_existing_tags = set()
    if args.config:
        existing_config = load_config(args.config, verbose)
        if existing_config is None:
            logger.error(f"Could not load config from {args.config}")
            sys.exit(1)
        if 'outbounds' in existing_config and isinstance(existing_config['outbounds'], list):
            for ob in existing_config['outbounds']:
                if 'tag' in ob:
                    all_existing_tags.add(ob['tag'])
                if 'server' in ob and 'server_port' in ob:
                    existing_proxy_outbounds.append(ob)
                elif ob.get('type') in ('selector', 'urltest'):
                    selector_outbounds.append(ob)
                else:
                    service_outbounds.append(ob)
        if verbose:
            logger.info(f"Loaded config: {len(existing_proxy_outbounds)} proxy outbounds, {len(service_outbounds)} service outbounds, {len(selector_outbounds)} selectors")

    progress_ctx = None
    if use_progress:
        if RICH_AVAILABLE:
            progress_ctx = RichProgress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=console,
                transient=False,
            )
            progress_ctx.__enter__()
        elif TQDM_AVAILABLE:
            progress_ctx = ProgressAdapter(use_rich=False)
        else:
            progress_ctx = None

    try:
        new_proxies = []
        if args.urls:
            seen_keys = set()
            for src in args.urls:
                if verbose and not use_progress:
                    logger.info(f"Processing {src} ...")
                proxies = process_subscription(
                    src, allowed_types, vless_transport, vless_tls,
                    vmess_transport, trojan_transport, seen_keys,
                    deduplicate=not args.no_deduplicate,
                    keep_original_tags=args.keep_original_tags,
                    tag_format=args.tag_format if args.export_format == 'sing-box' else None,
                    export_format=args.export_format,
                    no_number_tags=args.no_number_tags,
                    verbose=verbose,
                    progress_ctx=progress_ctx
                )
                if verbose and not use_progress:
                    logger.info(f"  -> {len(proxies)} new outbound(s) from this source")
                new_proxies.extend(proxies)

        existing_proxies = []
        for ob in existing_proxy_outbounds:
            p = Proxy(
                type=ob.get('type', 'unknown'),
                tag=ob.get('tag', ''),
                server=ob.get('server', ''),
                server_port=ob.get('server_port', 0),
                original_host=ob.get('server', '')
            )
            existing_proxies.append(p)

        all_proxy_candidates = existing_proxies + new_proxies

        SKIP_TEST_TAGS = {'TOR'}
        to_test = []
        skip_test = []
        for p in all_proxy_candidates:
            if p.tag in SKIP_TEST_TAGS:
                skip_test.append(p)
            else:
                to_test.append(p)

        all_proxy_candidates = to_test

        if args.test_connect and all_proxy_candidates:
            if not os.path.exists(args.sing_box_path):
                logger.error(f"sing-box executable not found at {args.sing_box_path}")
                sys.exit(1)
            if verbose:
                logger.info(f"Testing connectivity with sing-box for {len(all_proxy_candidates)} proxies using {args.test_threads} threads...")
            reachable = []
            test_task = None
            if progress_ctx:
                test_task = progress_ctx.add_task("[blue]Sing-box testing", total=len(all_proxy_candidates))

            with ThreadPoolExecutor(max_workers=args.test_threads) as executor:
                future_to_p = {executor.submit(test_with_singbox, p, args.test_url,
                                                args.test_timeout, args.sing_box_path,
                                                args.resolve_country, args.cache_dir,
                                                args.speedtest, args.speedtest_download_url,
                                                args.speedtest_upload_url, args.speedtest_timeout,
                                                cache_ttl, args.ignore_cache,
                                                temp_dir,
                                                args.country_api_timeout,
                                                verbose): p
                               for p in all_proxy_candidates}
                for future in as_completed(future_to_p):
                    p = future_to_p[future]
                    try:
                        if future.result():
                            reachable.append(p)
                        else:
                            if verbose:
                                logger.debug(f"Unreachable: {p.tag}")
                    except Exception as e:
                        if verbose:
                            logger.exception(f"Test exception for {p.tag}: {e}")
                    if test_task and progress_ctx:
                        progress_ctx.advance(test_task)

            if progress_ctx:
                progress_ctx.update(test_task, visible=False)
            all_proxy_candidates = reachable
            if verbose:
                logger.info(f"Reachable: {len(all_proxy_candidates)}")

            save_test_cache(args.cache_dir, test_cache)

            if args.speedtest:
                for p in all_proxy_candidates:
                    if p.speed_download is None:
                        p.speed_download = 0.0
                    if p.speed_upload is None:
                        p.speed_upload = 0.0

            if args.resolve_country:
                filtered = []
                for p in all_proxy_candidates:
                    if p.country_in is None:
                        if verbose:
                            logger.debug(f"Excluding proxy {p.tag} because IN country lookup failed")
                        continue
                    if p.country_out is None:
                        if verbose:
                            logger.debug(f"Excluding proxy {p.tag} because OUT country lookup failed")
                        continue
                    filtered.append(p)
                all_proxy_candidates = filtered

            if args.resolve_country and (include_in or exclude_in or include_out or exclude_out):
                if verbose:
                    logger.info("Applying country filters...")
                all_proxy_candidates = apply_country_filters(all_proxy_candidates, include_in, exclude_in, include_out, exclude_out, verbose)

            if args.speedtest and (args.min_download_speed is not None or args.min_upload_speed is not None):
                if verbose:
                    logger.info("Applying speed filters...")
                all_proxy_candidates = apply_speed_filters(all_proxy_candidates, args.min_download_speed, args.min_upload_speed, verbose)

            if args.same_in_out_ip:
                if verbose:
                    logger.info("Applying same IN/OUT IP filter...")
                all_proxy_candidates = apply_same_in_out_ip_filter(all_proxy_candidates, verbose)

            if not args.no_deduplicate_ip_port:
                unique = {}
                for p in all_proxy_candidates:
                    key = f"{p.server}:{p.server_port}"
                    if key not in unique:
                        unique[key] = p
                    else:
                        if verbose:
                            logger.debug(f"Deduplicate (global IP:port): skipping {key}")
                all_proxy_candidates = list(unique.values())
                if verbose:
                    logger.info(f"After global dedup: {len(all_proxy_candidates)} proxies")

            all_proxy_candidates.sort(key=lambda p: p.latency if p.latency is not None else float('inf'))
        else:
            if args.resolve_country:
                logger.info("--resolve-country ignored because --test-connect is not enabled.")
            if args.speedtest:
                logger.info("--speedtest ignored because --test-connect is not enabled.")
            if args.same_in_out_ip:
                logger.info("--same-in-out-ip ignored because --test-connect is not enabled.")
            if verbose:
                logger.info("Skipping connectivity testing, exporting all parsed proxies.")

        all_proxy_candidates.extend(skip_test)

        if args.export_format == 'sing-box':
            renumber_tags(all_proxy_candidates)
            proxy_dicts = [p.to_dict(remove_metadata=True) for p in all_proxy_candidates]
        else:
            proxy_dicts = []

        if args.export_format == 'v2ray':
            export_v2ray(all_proxy_candidates, args.tag_format, args.resolve_uris, args.no_number_tags, args.output, verbose, progress_ctx)
            if args.quiet:
                elapsed = time.time() - start_time_total
                print(f"Total time: {elapsed:.2f}s, Proxies exported: {len(all_proxy_candidates)}", file=sys.stderr)
            return

        working_proxy_tags = {p.tag for p in all_proxy_candidates if p.tag}
        service_tags = set()
        for ob in service_outbounds:
            if 'tag' in ob:
                service_tags.add(ob['tag'])
        selector_tags = set()
        for ob in selector_outbounds:
            if 'tag' in ob:
                selector_tags.add(ob['tag'])

        final_outbounds = service_outbounds + selector_outbounds + proxy_dicts

        if existing_config is not None:
            existing_config['outbounds'] = final_outbounds
            updated = update_selectors(existing_config, working_proxy_tags, service_tags, selector_tags, verbose)
            if verbose:
                logger.info(f"Updated {updated} selector(s)/urltest(s).")
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(existing_config, f, indent=2, ensure_ascii=False)
            logger.info(f"Updated config saved to {args.output}")
        else:
            if args.create_selectors:
                selectors = create_default_selectors(working_proxy_tags, service_tags, selector_tags)
                final_outbounds = proxy_dicts + selectors
            else:
                final_outbounds = proxy_dicts
            outfile = args.output if args.output else 'sing-box-outbounds.json'
            with open(outfile, 'w', encoding='utf-8') as f:
                json.dump({"outbounds": final_outbounds}, f, indent=2, ensure_ascii=False)
            logger.info(f"Generated {len(final_outbounds)} outbound(s) in {outfile}")

        if args.quiet:
            elapsed = time.time() - start_time_total
            print(f"Total time: {elapsed:.2f}s, Proxies in output: {len(all_proxy_candidates)}", file=sys.stderr)

    finally:
        if progress_ctx:
            progress_ctx.__exit__(None, None, None)

if __name__ == "__main__":
    main()
