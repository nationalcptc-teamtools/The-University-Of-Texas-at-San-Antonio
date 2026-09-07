"""Standalone stdlib worker: fd0 is one broker-connected socket, never a network namespace.

Only this file, public runtime/CA files and a memory-backed request are mounted.
No tool execution, browser, callbacks, environment credentials or filesystem reads
other than these fixed inputs are exposed to the remote model.
"""
import hashlib
import http.client
import json
import resource
import socket
import ssl
import sys


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (384 * 1024**2, 384 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    with open("/request.json", "rb") as stream:
        config = json.load(stream)
    sock = socket.socket(fileno=0)
    sock.settimeout(config["timeout_s"])
    if config["tls"]:
        sock = ssl.create_default_context(cafile="/ca.pem").wrap_socket(sock, server_hostname=config["host"])
        if config.get("certificate_sha256") and hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest() != config["certificate_sha256"]:
            raise ValueError("certificate mismatch")
    connection = http.client.HTTPConnection(config["host"], config["port"], timeout=config["timeout_s"])
    connection.sock = sock
    body = json.dumps(config["body"], separators=(",", ":"), ensure_ascii=True).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Connection": "close", **config["headers"]}
    credential = None
    if config.get("has_credential"):
        with open("/credential.txt", "rb") as stream:
            credential = stream.read(8193)
        if not credential or len(credential) > 8192:
            raise ValueError("credential cap")
        headers["Authorization"] = "Bearer " + credential.decode("ascii")
    connection.request("POST", config["path"], body=body, headers=headers)
    response = connection.getresponse()
    raw = response.read(config["max_response_bytes"] + 1)
    if len(raw) > config["max_response_bytes"]:
        raise ValueError("response cap")
    if credential:
        import base64
        if credential in raw or base64.b64encode(credential) in raw:
            raise ValueError("credential reflection is not capturable")
    # Never return cookies, authentication headers, redirects, or arbitrary error text.
    if response.status < 200 or response.status >= 300:
        print(json.dumps({"ok": False, "error": "provider_http_status", "status": response.status}))
    else:
        print(json.dumps({"ok": True, "status": response.status, "body": raw.decode("utf-8"), "bytes": len(raw)}))
    connection.close()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print('{"ok":false,"error":"provider_transport_failed"}')
        sys.exit(1)
