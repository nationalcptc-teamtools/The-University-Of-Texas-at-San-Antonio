"""Offline Nuclei/ZAP analysis of one human-selected response. No target sockets."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time
from urllib.parse import urlsplit
import uuid

from .contracts import OperationResult, PolicyError, canonical_json
from .integrity import verified_executable, verified_worker
from .parsers.common import in_scope
from .policy import parse_target
from .tool_catalog import verified_native_file, verified_resource, verified_java_root

RULES = ("cptc-observe-missing-csp", "cptc-observe-missing-nosniff", "cptc-observe-missing-frame-options")
INPUT_MARKER = "cptc-capture-processed"
ZAP_RULES = frozenset({"10010", "10011", "10020", "10021", "10035", "10038", "10054", "10055"})
ZAP_ADDONS = ("automation-beta-0.58.0.zap", "callhome-release-0.20.0.zap", "commonlib-release-1.39.0.zap", "exim-beta-0.16.0.zap",
              "network-beta-0.25.0.zap", "pscan-alpha-0.6.0.zap", "pscanrules-release-70.zap", "reports-release-0.43.0.zap")


def capture_input(raw: bytes, scope):
    """Reject requests, arbitrary HARs, extra records and unscoped identifiers."""
    try:
        if len(raw) > 49152:
            raise ValueError()
        value = json.loads(raw)
        if set(value) != {"version", "target", "response_base64"} or type(value["version"]) is not int or value["version"] != 1:
            raise ValueError()
        url = value["target"]
        if not isinstance(url, str) or len(url) > 256:
            raise ValueError()
        parsed = urlsplit(url)
        target = parse_target({"target_id": "capture", "canonical_url": url, "scheme": parsed.scheme,
                               "host": parsed.hostname, "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                               "base_path": parsed.path or "/"})
        if not in_scope(url, scope):
            raise ValueError()
        response = base64.b64decode(value["response_base64"], validate=True)
        if len(response) > 32768 or b"\r\n\r\n" not in response:
            raise ValueError()
        head, body = response.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        match = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9]{2}) [\x20-\x7e]*", lines[0])
        if not match or len(head) > 8192 or len(lines) > 65:
            raise ValueError()
        headers = []
        for line in lines[1:]:
            name, content = line.split(b":", 1)
            if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or any(c < 32 and c != 9 or c == 127 for c in content):
                raise ValueError()
            headers.append({"name": name.decode("ascii"), "value": content.strip().decode("latin1")})
        # A stored response must be decoded, complete, and exactly one message.
        lengths = [h["value"] for h in headers if h["name"].lower() == "content-length"]
        if any(h["name"].lower() in {"transfer-encoding", "content-encoding"} for h in headers):
            raise ValueError()
        if len(lengths) > 1 or lengths and (not lengths[0].isdigit() or int(lengths[0]) != len(body)):
            raise ValueError()
        return target, response, int(match[1]), headers, body
    except (ValueError, TypeError, KeyError, AttributeError, PolicyError):
        raise PolicyError("unsupported response capture; require one complete scoped HTTP response") from None


def to_har(status, headers, body, scheme="http"):
    # ZAP receives a fixed synthetic request and no client request/session data.
    if scheme not in {"http", "https"}: raise PolicyError("invalid passive origin scheme")
    mime = next((h["value"].split(";", 1)[0] for h in headers if h["name"].lower() == "content-type"), "application/octet-stream")
    return canonical_json({"log": {"version": "1.2", "creator": {"name": "CPTC", "version": "1"}, "entries": [{
        "startedDateTime": "2000-01-01T00:00:00Z", "time": 0,
        "request": {"method": "GET", "url": scheme + "://capture.invalid/", "httpVersion": "HTTP/1.1",
                    "cookies": [], "headers": [], "queryString": [], "headersSize": -1, "bodySize": 0},
        "response": {"status": status, "statusText": "Captured", "httpVersion": "HTTP/1.1", "cookies": [],
                     "headers": headers, "content": {"size": len(body), "mimeType": mime, "encoding": "base64",
                     "text": base64.b64encode(body).decode()}, "redirectURL": "", "headersSize": -1, "bodySize": len(body)},
        "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0}}]}})


def parse_output(engine, raw, scheme="http"):
    """Only static rule identities and typed numbers survive native output."""
    rows = []
    issues = []
    try:
        if engine == "nuclei":
            matched = set()
            for line in raw.splitlines():
                record = json.loads(line)
                rule = record["template-id"]
                if rule not in (*RULES, INPUT_MARKER) or rule in matched or record.get("info", {}).get("severity") != "info":
                    raise ValueError()
                matched.add(rule)
            if INPUT_MARKER not in matched:
                raise ValueError()
            for rule in RULES:
                rows.append({"scanner": engine, "rule_id": rule, "severity": "info", "matches": int(rule in matched)})
        else:
            report = json.loads(raw)
            if report.get("@version") != "2.17.0" or not isinstance(report.get("site"), list) or len(report["site"]) != 1:
                raise ValueError()
            for site in report.get("site", []):
                if site.get("@name") != scheme + "://capture.invalid" or site.get("@host") != "capture.invalid" or "alerts" not in site:
                    raise ValueError()
                alerts = site.get("alerts", [])
                if not isinstance(alerts, list) or len(alerts) > 128:
                    raise ValueError()
                for alert in alerts:
                    rule = str(alert["pluginid"])
                    if rule not in ZAP_RULES:
                        raise ValueError()
                    risk, confidence = int(alert["riskcode"]), int(alert["confidence"])
                    count = len(alert.get("instances", []))
                    if risk not in range(5) or confidence not in range(5) or not 0 <= count <= 16:
                        raise ValueError()
                    rows.append({"scanner": engine, "rule_id": rule, "severity": ("info", "low", "medium", "high", "critical")[risk],
                                 "confidence": confidence, "matches": count})
            if not rows:
                rows.append({"scanner": engine, "rule_id": "passive-import", "severity": "info", "matches": 0})
        return rows, sorted(set(issues))
    except (ValueError, TypeError, KeyError, AttributeError):
        raise PolicyError("native passive scanner output failed its schema") from None


def _memfd(name, data):
    import fcntl
    fd = os.memfd_create(name, flags=os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    os.write(fd, data)
    os.lseek(fd, 0, 0)
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
    return fd


def zap_report(stdout):
    try:
        prefix, frame = stdout.rsplit(b"\nCPTC_SCANNER_REPORT_V1:", 1)
        if not frame.endswith(b"\n") or b"\n" in frame[:-1]: raise ValueError()
        report = base64.b64decode(frame[:-1], validate=True)
        if len(report) > 32768: raise ValueError()
        return report
    except ValueError:
        raise PolicyError("native ZAP report completion frame is missing or invalid") from None


def run_native(engine, payload, context, evidence, output_limit):
    scanner = verified_native_file(engine)
    worker, bwrap, python = verified_worker("passive_worker.py"), verified_executable("/usr/bin/bwrap"), verified_executable("/usr/bin/python3")
    verified_executable("/usr/bin/systemd-run")
    verified_executable("/usr/bin/systemctl")
    resources = Path(__file__).parent / "resources"
    rules = [verified_resource("nuclei/" + name + ".yaml") for name in ("csp", "nosniff", "frame-options", "processed")] if engine == "nuclei" else [verified_resource("zap-passive.yaml")]
    if engine == "zap":
        java_root = verified_java_root()
    unit = "cptc-passive-" + uuid.uuid4().hex + ".scope"
    bus = "/run/user/" + str(os.getuid())
    host_env = {"XDG_RUNTIME_DIR": bus, "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + bus + "/bus"}
    fds = []
    process = None
    selector = selectors.DefaultSelector()
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    def event(kind, data):
        if context.network:
            context.network._event(kind, data)
    def kill():
        if process is not None:
            subprocess.run(["/usr/bin/systemctl", "--user", "kill", "--signal=KILL", unit], env=host_env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            if process.poll() is None:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
    try:
        inner = [str(bwrap), "--unshare-all", "--hostname", "cptc-passive", "--die-with-parent", "--new-session",
                 "--clearenv", "--cap-drop", "ALL", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib",
                 "--symlink", "usr/lib", "/lib64", "--symlink", "usr/bin", "/bin", "--proc", "/proc", "--dev", "/dev",
                 "--size", "268435456", "--tmpfs", "/tmp", "--setenv", "HOME", "/tmp", "--setenv", "PATH", "/usr/bin",
                 "--setenv", "TMPDIR", "/tmp", "--chdir", "/tmp", "--ro-bind", str(worker), "/worker.py"]
        for name, data in (("/capture.txt", payload), ("/config.json", canonical_json({"engine": engine})),
                           ("/etc/hosts", b"127.0.0.1 localhost cptc-passive\n")):
            fd = _memfd("cptc-passive", data); fds.append(fd)
            inner += ["--ro-bind-data", str(fd), name]
        for rule in rules:
            inner += ["--ro-bind", str(rule), "/rules/" + rule.name]
        if engine == "nuclei":
            inner += ["--ro-bind", str(scanner), "/scanner"]
        else:
            inner += ["--ro-bind", str(scanner.parent), "/zap", "--ro-bind", str(java_root), "/jre",
                      "--ro-bind", "/etc/java-openjdk", "/etc/java-openjdk"]
            # The full release archive also ships active scanners, browser drivers
            # and scripting add-ons. Expose only the reviewed passive closure.
            inner += ["--size", "1048576", "--tmpfs", "/zap/plugin"]
            for addon in ZAP_ADDONS:
                inner += ["--ro-bind", str(scanner.parent / "plugin" / addon), "/zap/plugin/" + addon]
        inner += ["--", str(python), "-I", "/worker.py"]
        command = ["/usr/bin/systemd-run", "--user", "--scope", "--quiet", "--unit", unit, "-p", "MemoryMax=768M",
                   "-p", "TasksMax=128", "-p", "RuntimeMaxSec=45", "--", *inner]
        event("passive_process_intent", {"scanner": engine, "command": command, "cwd": "/tmp", "environment": {"HOME": "/tmp", "PATH": "/usr/bin"},
              "source_sha256": hashlib.sha256(worker.read_bytes()).hexdigest(), "timeout_s": 40, "output_bytes": output_limit,
              "memory_bytes": 805306368, "tasks": 128, "target_requests": 0})
        if context.stopped(): raise PolicyError("operator stop before passive dispatch")
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=host_env, close_fds=True, pass_fds=tuple(fds), start_new_session=True)
        deadline = time.monotonic() + min(context.spec.bounds.timeout_s, 40)
        applied = False
        for _ in range(30):
            if context.stopped(): raise PolicyError("operator stopped passive scanner admission")
            if time.monotonic() >= deadline: raise PolicyError("passive scanner admission deadline exceeded")
            check = subprocess.run(["/usr/bin/systemctl", "--user", "show", unit, "-p", "ActiveState", "-p", "MemoryMax", "-p", "TasksMax", "-p", "RuntimeMaxUSec"],
                                   env=host_env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=min(.25, max(.01, deadline - time.monotonic())))
            props = dict(line.split("=", 1) for line in check.stdout.decode().splitlines() if "=" in line)
            if props.get("ActiveState") == "active" and props.get("MemoryMax") == "805306368" and props.get("TasksMax") == "128" and props.get("RuntimeMaxUSec") == "45s":
                applied = True; break
            if process.poll() is not None: break
            time.sleep(.03)
        if not applied: raise PolicyError("native scanner cgroup limits were not applied")
        process.stdin.write(b"G"); process.stdin.flush(); process.stdin.close()
        event("passive_process_started", {"scanner": engine, "pid": process.pid, "unit": unit})
        for name in streams:
            fd = getattr(process, name); os.set_blocking(fd.fileno(), False); selector.register(fd, selectors.EVENT_READ, name)
        total = 0
        while selector.get_map():
            if context.stopped(): raise PolicyError("operator stopped passive scanner")
            if time.monotonic() >= deadline: raise PolicyError("passive scanner deadline exceeded")
            for key, _ in selector.select(.05):
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    selector.unregister(key.fileobj); continue
                allowed = max(0, output_limit - total)
                kept = chunk[:allowed]
                if kept:
                    evidence.append(context.capture(key.data, kept, "restricted_raw"))
                    streams[key.data].extend(kept); total += len(kept)
                if len(chunk) > allowed:
                    event("capture_incomplete", {"scanner": engine, "reason": "native output cap exceeded", "captured_bytes": total})
                    raise PolicyError("passive scanner output cap exceeded; incomplete capture")
        process.wait(timeout=2)
        event("passive_process_completed", {"scanner": engine, "exit_code": process.returncode,
              "stdout_bytes": len(streams["stdout"]), "stderr_bytes": len(streams["stderr"])})
        if process.returncode:
            raise PolicyError("passive scanner failed; inspect encrypted execution evidence")
        stdout = bytes(streams["stdout"])
        return zap_report(stdout) if engine == "zap" else stdout
    finally:
        try:
            kill()
            if process is not None:
                process.wait(timeout=3)
                # Failure output is still captured up to the reserved allowance.
                for name in streams:
                    stream = getattr(process, name)
                    if stream:
                        os.set_blocking(stream.fileno(), True)
                        chunk = stream.read(output_limit + 1)
                        remaining = output_limit - sum(map(len, streams.values()))
                        if chunk[:remaining]:
                            evidence.append(context.capture(name, chunk[:remaining], "restricted_raw"))
                            streams[name].extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            event("capture_incomplete", {"scanner": engine, "reason": "failure output exceeded capture cap"})
                        stream.close()
                event("passive_process_closed", {"scanner": engine, "exit_code": process.returncode})
        finally:
            selector.close()
            for fd in fds: os.close(fd)


class PassiveCollector:
    def __init__(self, engine):
        if engine not in {"nuclei", "zap"}: raise ValueError("unreviewed scanner")
        self.engine = engine

    def collect(self, context):
        if context.stopped(): return OperationResult("stopped", reason="operator stop")
        if context.request.source != "operator" or not context.input_bytes or not context.capture:
            return OperationResult("blocked", reason="passive analysis requires a human-selected private capture")
        evidence = []
        try:
            target, response, status, headers, body = capture_input(context.input_bytes, context.policy.scope)
            # Fail before any process is launched if deployment pins are missing.
            verified_native_file(self.engine)
            evidence.append(context.capture("import", context.input_bytes, "client_confidential_human_only"))
            payload = response if self.engine == "nuclei" else to_har(status, headers, body, target.scheme)
            output = run_native(self.engine, payload, context, evidence, context.spec.bounds.output_bytes - len(context.input_bytes))
            rows, issues = parse_output(self.engine, output, target.scheme)
            source = hashlib.sha256(context.input_bytes).hexdigest()
            facts = {"observations": [{"track": "web", "target": target.canonical_url, "check_id": self.engine + ":" + row["rule_id"],
                     "state": "candidate" if row["matches"] else "observed", "facts": row, "source_sha256": source} for row in rows],
                     "issues": issues, "duplicates": 0}
            return OperationResult("complete", facts, tuple(evidence), usage={"request_limit": 0})
        except PolicyError as exc:
            return OperationResult("stopped" if context.stopped() else "failed", evidence=tuple(evidence), reason=str(exc))
