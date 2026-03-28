# sub2singbox – Proxy Subscription to sing-box / v2ray Converter

Converts proxy subscriptions (URLs or files) into a configuration for sing-box (outbounds) or a list of URIs for v2ray. Supports filtering by protocol and transport, connectivity testing via sing-box, country detection (IN/OUT), country filtering, speedtest, and deduplication.

<img width="750" height="50" alt="image" src="https://github.com/user-attachments/assets/491d535a-809a-4653-b479-bb3e1de2ef9f" />

## Features

- Protocols: vless, vmess, trojan, shadowsocks, socks, http(s), hysteria, hysteria2.
- DNS resolution: via DoH (Google) through the proxy itself (during testing).
- Country detection: (IN IP) + (OUT IP) via the proxy.
- Tags: flexible templates with placeholders {proto}, {ip}, {country_in}, {flag_out}, {speed_download}, etc.
- Testing: multi-threaded (sing-box + curl), measures latency and speed (download/upload).
- Deduplication: by (host,port) during parsing and by (IP,port) after testing.
- sing-box configuration update: adds new outbounds, automatically updates selectors (AUTO, GLOBAL, etc.).
- Progress bars: rich or tqdm.
- Caching: test results, DNS, country data.

## Requirements

- Python 3.7+
- Installed sing-box (https://sing-box.sagernet.org/)
- curl (for testing and DoH)
- Optional: rich (fancy progress bars), tqdm (fallback)

## Installation

```bash
git clone https://github.com/yourname/sub2singbox.git
cd sub2singbox
pip install -r requirements.txt
```

Contents of requirements.txt (optional):

```bash
requests
tqdm
rich
```

## Usage

### Basic commands

Convert subscription to sing-box outbounds (without testing):

```bash
./sub2singbox.py https://example.com/sub.txt -o outbounds.json
```

With testing and country resolution:

```bash
./sub2singbox.py --test-connect --resolve-country https://example.com/sub.txt -o config.json
```

Export to v2ray (list of URIs):

```bash
./sub2singbox.py --export-format v2ray https://example.com/sub.txt -o proxies.txt
```

Update an existing configuration:

```bash
./sub2singbox.py --config sing-box.json --test-connect https://example.com/sub.txt -o updated.json
```

### Main parameters:

```bash
--export-format  {sing-box,v2ray}	Output format
--types vless,vmess  Only specified protocols
--vless-transport ws,grpc  Transport filter for vless
--tag-format "{flag_in} {proto} {speed_download}M"  Tag template
--keep-original-tags  Use URI fragment (#) as tag
--no-number-tags  Disable numbering of duplicates
--test-connect  Enable testing via sing-box
--test-threads 20  Number of testing threads
--resolve-country  Resolve country (IN/OUT)
--include-country-in US,SE,NL,DE,TW Keep only proxies with IN country in the list
--exclude-country-out RU,UA,BY,KZ,GB,CN,IR Exclude proxies with OUT country in the list
--speedtest Measure download/upload speed
--min-download-speed 10 Minimum speed (Mbps)
--no-deduplicate-ip-port Disable deduplication by IP:port
--config config.json  Existing configuration (will be updated)
--create-selectors  Create AUTO and GLOBAL selectors (without --config)
--output file.json  Output file
--quiet  Errors only
--no-progress  Disable progress bars
--cache-dir ~/.cache/sub2singbox  Cache directory (temporary files also stored there)
```

### Tag template examples

```bash
--tag-format "{flag_in}{flag_out} {proto} {speed_download}Mbps"
--tag-format "{flag_in} {country_in}: {in_ip}:{in_port} ➜ {flag_out} {country_out}: {out_ip} | {speed_download}/{speed_upload} Mbps"
--tag-format "{proto}-{in_ip}:{in_port} [{latency}ms]"
```

Available placeholders: {proto}, {host}, {ip}, {port}, {country_in}, {country_out}, {flag_in}, {flag_out}, {speed_download}, {speed_upload}, {latency}, {fragment}, etc.

### Cache structure

In ~/.cache/sub2singbox/:
```bash
cache.json – test results (TTL default 3600 s)
temp/ – temporary sing-box configurations (automatically cleaned up)
```

## Notes

- For --test-connect to work, sing-box must be in PATH (or specify the path with --sing-box-path).
- OUT IP country detection uses ip-api.com (no API key, up to 45 requests/min). If the limit is exceeded, the script automatically pauses.
- If the country cannot be determined for either IN IP or OUT IP, the proxy is excluded from the final list.
- Deduplication by IP:port works after testing (when the IP is already known).
- All temporary files are removed when the script exits (including on Ctrl+C).

## Disclaimer

- This tool is for personal use only.
- Please do not use it for any illegal activity and follow by your country rules.
- The developers are not responsible for any violations of your county terms of use.
