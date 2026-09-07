#!/usr/bin/env python3
"""Human-run local Linux inventory collector.

This script emits a reviewed import envelope.  It never contacts a target,
uses a shell, invokes sudo, reads credentials, or changes service state.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import re

SCHEMA = "cptc.linux.inventory.v1"
CONTROLS = {"network_access": False, "sudo_used": False, "service_changes": False}
MAX_RECORDS = 256
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.@:+-]{1,128}$")
SERVICE_ROOTS = (Path("/etc/systemd/system"), Path("/run/systemd/system"))
TASK_ROOTS = (Path("/etc/cron.d"), Path("/etc/cron.daily"), Path("/etc/cron.hourly"))
SUID_ROOTS = (Path("/usr/bin"), Path("/usr/local/bin"), Path("/bin"))


def owner(uid: int) -> str:
    # NSS name lookups can trigger LDAP/SSSD network activity. Numeric ownership
    # is sufficient for this local-only observation profile.
    return str(uid)


def metadata(path: Path) -> tuple[os.stat_result, str] | None:
    try:
        return os.stat(path, follow_symlinks=False), str(path)[:256]
    except (OSError, ValueError):
        return None


def identity() -> dict[str, object]:
    return {"kind": "identity", "uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(),
            "groups": sorted(set(os.getgroups()))[:64]}


def permissions() -> list[dict[str, object]]:
    records = []
    for path in (Path("/etc"), Path("/usr/local/bin"), Path("/tmp")):
        item = metadata(path)
        if not item:
            continue
        info, name = item
        records.append({"kind": "permission", "path": name, "mode": f"{stat.S_IMODE(info.st_mode):04o}",
                        "owner": owner(info.st_uid), "world_writable": bool(info.st_mode & stat.S_IWOTH)})
    return records


def directory_records(roots: tuple[Path, ...], kind: str) -> list[dict[str, object]]:
    records = []
    for root in roots:
        try:
            entries = sorted(root.iterdir(), key=lambda item: item.name)[:96]
        except (OSError, ValueError):
            continue
        for path in entries:
            if not SAFE_NAME.fullmatch(path.name):
                continue
            item = metadata(path)
            if not item:
                continue
            info, _ = item
            records.append({"kind": kind, "name": path.name[:128], "state": "unknown",
                            "owner": owner(info.st_uid), "writable": os.access(path, os.W_OK)})
            if len(records) >= 96:
                return records
    return records


def suid_records() -> list[dict[str, object]]:
    expected = {"ping", "su", "sudo", "passwd", "mount", "umount", "chsh", "chfn", "newgrp"}
    records = []
    seen: set[str] = set()
    for root in SUID_ROOTS:
        if not root.is_dir():
            continue
        for base, dirs, files in os.walk(root, topdown=True, followlinks=False):
            dirs[:] = sorted(dirs)[:32]
            for name in sorted(files):
                path = Path(base) / name
                key = str(path)
                if key in seen or len(records) >= 64:
                    continue
                seen.add(key)
                item = metadata(path)
                if not item:
                    continue
                info, display = item
                if info.st_mode & stat.S_ISUID:
                    records.append({"kind": "suid", "path": display, "owner": owner(info.st_uid),
                                    "expected_binary": name in expected})
            if len(records) >= 64:
                break
    return records


def capability_records() -> tuple[list[dict[str, object]], list[str]]:
    executable = next((candidate for candidate in ("/usr/bin/getcap", "/sbin/getcap") if os.path.isfile(candidate)), None)
    if not executable:
        return [], ["unsupported_capability_inventory"]
    try:
        result = subprocess.run([executable, "-r", "-n", "/usr/bin"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
                                check=False, shell=False)
    except (OSError, subprocess.SubprocessError):
        return [], ["unsupported_capability_inventory"]
    if result.returncode not in (0, 1):
        return [], ["unsupported_capability_inventory"]
    records = []
    for line in result.stdout[:131072].decode("utf-8", "replace").splitlines()[:64]:
        fields = line.split()
        if len(fields) < 2 or len(fields[0]) > 256 or any(ord(char) < 32 for char in fields[0]):
            continue
        caps = []
        for token in " ".join(fields[1:]).split(","):
            token = token.strip().lower()
            if "=" in token:
                name, flags = token.split("=", 1)
                token = name + "+" + flags
            if token.startswith("cap_") and re.fullmatch(r"cap_[a-z0-9_]+(?:\+(?:eip|ep|ei|p))?", token):
                caps.append(token)
        if caps:
            records.append({"kind": "capability", "path": fields[0][:256], "capabilities": sorted(set(caps))})
    return records, []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="operator-selected local inventory label")
    args = parser.parse_args(argv)
    if not isinstance(args.target, str) or not args.target or len(args.target) > 256 or any(ord(c) < 33 for c in args.target):
        parser.error("target must be a bounded non-empty label")
    records: list[dict[str, object]] = [identity()]
    records.extend(permissions())
    records.extend(directory_records(SERVICE_ROOTS, "service"))
    records.extend(directory_records(TASK_ROOTS, "task"))
    records.extend(suid_records())
    capabilities, issues = capability_records()
    records.extend(capabilities)
    payload = {"schema": SCHEMA, "target": args.target[:256], "controls": CONTROLS,
               "records": records[:MAX_RECORDS], "issues": sorted(set(issues))}
    json.dump(payload, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
