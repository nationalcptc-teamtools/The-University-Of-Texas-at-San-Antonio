#!/usr/bin/env python3
"""Run the full synthetic suite with durable UTC logs and strict completion.

No test selectors, xfail/skip allowance, live targets or model providers are
accepted here. Use the pinned environment. An interrupted run cannot pass.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from testing.acceptance import evaluate

SOURCE_ROOTS = {"cptc_harness", "docs", "human", "scripts", "skills", "testing", "tests", "web"}
SOURCE_FILES = {".gitleaks.toml", "AGENTS.md", "MANIFEST.in", "README.md", "pyproject.toml"}
ROOT_STARTUP_FILES = {"sitecustomize.py", "usercustomize.py", "conftest.py"}
IGNORED_SOURCE_PARTS = {"__pycache__", ".pytest_cache", ".mypy_cache"}
PROTECTED_SOURCE_SUBTREES = {("web", "engagements")}


def _source_bytes(path):
    return path.read_bytes()


def _protected_source(path):
    parts = path.relative_to(ROOT).parts
    return any(parts[:len(protected)] == protected for protected in PROTECTED_SOURCE_SUBTREES)


def source_snapshot():
    entries = []
    if any((ROOT / name).exists() or (ROOT / name).is_symlink() for name in ROOT_STARTUP_FILES):
        raise ValueError("unreviewed root startup file")
    for name in sorted(SOURCE_FILES):
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("test source input is missing or symlinked")
        entries.append((name, hashlib.sha256(_source_bytes(path)).hexdigest()))
    for root_name in sorted(SOURCE_ROOTS):
        source_root = ROOT / root_name
        if source_root.is_symlink() or not source_root.is_dir():
            raise ValueError("test source root is missing or symlinked")
        for directory, dirnames, filenames in os.walk(source_root, followlinks=False):
            directory_path = Path(directory)
            for child in tuple(dirnames):
                candidate = directory_path / child
                if _protected_source(candidate) or child in IGNORED_SOURCE_PARTS:
                    dirnames.remove(child)
                elif candidate.is_symlink():
                    raise ValueError("test source directory is symlinked")
            for filename in filenames:
                if filename.endswith((".pyc", ".pyo")) or filename == ".DS_Store":
                    continue
                path = directory_path / filename
                if path.is_symlink() or not path.is_file():
                    raise ValueError("test source input is missing or symlinked")
                relative = str(path.relative_to(ROOT))
                entries.append((relative, hashlib.sha256(_source_bytes(path)).hexdigest()))
    if not entries:
        raise ValueError("test source snapshot is empty")
    raw = json.dumps(sorted(entries), separators=(",", ":"), ensure_ascii=True).encode()
    return {"files": len(entries), "sha256": hashlib.sha256(raw).hexdigest()}


def clean_environment(output):
    runtime = "/run/user/" + str(os.getuid())
    home = output / "test-home"
    home.mkdir(mode=0o700)
    return {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin",
            "HOME": str(home), "TMPDIR": "/tmp", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "TZ": "UTC", "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "XDG_RUNTIME_DIR": runtime, "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + runtime + "/bus"}


class Journal:
    def __init__(self, root):
        self.root = root; self.sequence = 0; self.chain = "0" * 64
        self.events = self.transcript = None
        try:
            self.events = (root / "audit.jsonl").open("xb")
            self.transcript = (root / "transcript.log").open("xb")
        except BaseException:
            if self.events is not None:
                self.events.close()
            raise

    def emit(self, kind, data):
        self.sequence += 1
        event = {"sequence": self.sequence, "event_id": uuid.uuid4().hex,
                 "utc": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                 "monotonic_ns": time.monotonic_ns(), "kind": kind, "data": data,
                 "previous_sha256": self.chain}
        raw = json.dumps(event, sort_keys=True, ensure_ascii=True, allow_nan=False).encode()
        self.chain = hashlib.sha256(raw).hexdigest()
        self.events.write(raw + b"\n"); self.events.flush(); os.fsync(self.events.fileno())
        rendered = f"{event['utc']} #{self.sequence} {kind} ".encode() + json.dumps(data, ensure_ascii=True).encode() + b"\n"
        self.transcript.write(rendered); self.transcript.flush(); os.fsync(self.transcript.fileno())

    def close(self):
        for stream in (self.events, self.transcript):
            if stream is not None and not stream.closed:
                stream.close()


def write_integrity(root):
    names = ("audit.jsonl", "transcript.log", "stdout.bin", "stderr.bin", "junit.xml", "results.json")
    files = []
    for name in names:
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("test integrity input is missing or symlinked")
        raw = path.read_bytes()
        files.append({"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    payload = {"version": 1, "classification": "synthetic-test-results", "files": files}
    descriptor = os.open(root / "integrity-manifest.json",
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write((json.dumps(payload, sort_keys=True, indent=2) + "\n").encode())
        stream.flush(); os.fsync(stream.fileno())
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return payload


def run(output, timeout, maximum):
    os.umask(0o077)
    if output.exists() or output.is_symlink(): raise ValueError("choose a new output directory")
    output.mkdir(parents=True, mode=0o700)
    journal = Journal(output); process = None; readfd = writefd = None
    streams = {}; reserve = None; events = []; total = 0; pending = b""
    try:
        reserve = (output / ".reserved-space").open("xb")
        os.posix_fallocate(reserve.fileno(), 0, maximum)
        readfd, writefd = os.pipe()
        bootstrap = ("import sys;sys.path.insert(0," + repr(str(ROOT))
                     + ");import pytest;raise SystemExit(pytest.main(sys.argv[1:]))")
        command = [sys.executable, "-B", "-I", "-c", bootstrap, "-q", "--capture=fd", "-rA",
                   "-p", "testing.pytest_plugin", "--junitxml=" + str(output / "junit.xml"), "tests", "web"]
        env = clean_environment(output)
        env["CPTC_TEST_EVENT_FD"] = str(writefd)
        before = source_snapshot()
        journal.emit("intent", {"command": command, "cwd": str(ROOT), "data": "synthetic fixtures only",
                    "timeout_s": timeout, "capture_bytes": maximum, "clock_status": "local test capture; not target-work clock authorization"})
        journal.emit("source_snapshot", before)
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   pass_fds=(writefd,), close_fds=True, start_new_session=True)
        os.close(writefd); writefd = None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        selector.register(readfd, selectors.EVENT_READ, "events")
        for name in ("stdout", "stderr"): streams[name] = (output / (name + ".bin")).open("xb")
        deadline = time.monotonic() + timeout
        try:
            while selector.get_map():
                if time.monotonic() >= deadline: raise TimeoutError("suite deadline")
                for key, _ in selector.select(0.1):
                    descriptor = key.fileobj if isinstance(key.fileobj, int) else key.fileobj.fileno()
                    data = os.read(descriptor, 65536)
                    if not data: selector.unregister(key.fileobj); continue
                    if len(data) > maximum - total:
                        allowed = max(0, maximum - total)
                        if key.data != "events" and allowed:
                            stream = streams[key.data]; offset = stream.tell(); partial = data[:allowed]
                            stream.write(partial); stream.flush(); os.fsync(stream.fileno())
                            journal.emit("output", {"stream": key.data, "offset": offset, "bytes": len(partial),
                                         "sha256": hashlib.sha256(partial).hexdigest(),
                                         "text": partial.decode("utf-8", "backslashreplace")})
                        total += allowed
                        raise ValueError("test collection limit; capture incomplete")
                    total += len(data)
                    if key.data == "events":
                        pending += data
                        while b"\n" in pending:
                            line, pending = pending.split(b"\n", 1); event = json.loads(line)
                            events.append(event); journal.emit("pytest_event", event)
                    else:
                        stream = streams[key.data]; offset = stream.tell(); stream.write(data);stream.flush();os.fsync(stream.fileno())
                        journal.emit("output", {"stream": key.data, "offset": offset, "bytes": len(data),
                                     "sha256": hashlib.sha256(data).hexdigest(), "text": data.decode("utf-8", "backslashreplace")})
            code = process.wait(timeout=5)
            if pending: raise ValueError("truncated structured test report")
        finally:
            selector.close()
        after = source_snapshot()
        if after != before:
            raise ValueError("test source changed while the suite was running")
        journal.emit("source_snapshot_verified", after)
        result = evaluate(events, code)
        result.update({"version": 1, "classification": "synthetic-test-results", "python": sys.version,
                       "process_exit": code, "capture_complete": True, "full_cptc11_accepted": False,
                       "source_snapshot": after, "live_evidence": "not part of the synthetic software suite",
                       "output": str(output)})
        journal.emit("completion", {key: value for key, value in result.items() if key != "tests"})
        result_fd = os.open(output / "results.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(result_fd, "wb") as result_stream:
            result_stream.write((json.dumps(result, indent=2) + "\n").encode())
            result_stream.flush(); os.fsync(result_stream.fileno())
        return 0 if result["software_passed"] else 2
    except BaseException as error:
        if process and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL);process.wait(timeout=5)
        try: journal.emit("interrupted", {"reason": type(error).__name__, "capture_complete": False, "software_passed": False})
        except OSError: pass
        raise
    finally:
        if process:
            for stream in (process.stdout, process.stderr):
                if stream: stream.close()
        for descriptor in (readfd, writefd):
            if descriptor is not None: os.close(descriptor)
        for stream in streams.values(): stream.close()
        if reserve: reserve.close(); (output / ".reserved-space").unlink(missing_ok=True)
        journal.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)
    args = parser.parse_args()
    if not 60 <= args.timeout <= 7200 or not 1024 * 1024 <= args.max_bytes <= 256 * 1024 * 1024:
        parser.error("test runtime or capture allowance outside supported bounds")
    output = (args.output or ROOT / ".tools/test-runs" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")).absolute()
    try:
        code = run(output, args.timeout, args.max_bytes)
        write_integrity(output)
    except (OSError, ValueError, TimeoutError, KeyboardInterrupt) as error:
        print(json.dumps({"software_passed": False, "reason": type(error).__name__, "output": str(output)}));return 2
    result = json.loads((output / "results.json").read_text())
    print(json.dumps({key: value for key, value in result.items() if key != "tests"}));return code


if __name__ == "__main__": raise SystemExit(main())
