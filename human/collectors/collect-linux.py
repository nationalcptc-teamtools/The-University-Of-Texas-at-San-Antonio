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
PERMISSION_PATHS = tuple(map(Path, (
    "/etc", "/usr/local/bin", "/tmp", "/etc/passwd", "/etc/shadow",
    "/etc/group", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d",
    "/etc/ssh/sshd_config", "/etc/ld.so.preload", "/etc/crontab",
)))


def flag(issues: list[str] | None, code: str) -> None:
    if issues is not None and code not in issues:
        issues.append(code)


def owner(uid: int) -> str:
    # NSS name lookups can trigger LDAP/SSSD network activity. Numeric ownership
    # is sufficient for this local-only observation profile.
    return str(uid)


def writable_basis() -> str:
    return "administrator" if os.geteuid() == 0 else "current_principal"


def metadata(path: Path, issues: list[str] | None = None) -> tuple[os.stat_result, str] | None:
    try:
        display = str(path)
        if len(display) > 256:
            flag(issues, "collector_metadata_unavailable")
            return None
        return os.stat(path, follow_symlinks=False), display
    except (OSError, ValueError):
        flag(issues, "collector_metadata_unavailable")
        return None


def identity(issues: list[str] | None = None) -> dict[str, object]:
    groups = sorted(set(os.getgroups()))
    if len(groups) > 64:
        flag(issues, "collector_group_limit")
    return {"kind": "identity", "uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(),
            "groups": groups[:64]}


def permissions(issues: list[str] | None = None) -> list[dict[str, object]]:
    records = []
    for path in PERMISSION_PATHS:
        item = metadata(path, issues)
        if not item:
            continue
        info, name = item
        # lstat-style metadata cannot establish the permissions of a symlink's
        # destination. Do not label its conventional 0777 mode a vulnerability.
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            flag(issues, "collector_metadata_unavailable")
            continue
        records.append({"kind": "permission", "path": name, "mode": f"{stat.S_IMODE(info.st_mode):04o}",
                        "owner": owner(info.st_uid), "world_writable": bool(info.st_mode & stat.S_IWOTH),
                        "provenance": "os_inventory"})
    return records


def directory_records(roots: tuple[Path, ...], kind: str, issues: list[str] | None = None) -> list[dict[str, object]]:
    records = []
    for root_index, root in enumerate(roots):
        try:
            entries = sorted(root.iterdir(), key=lambda item: item.name)
        except (OSError, ValueError):
            flag(issues, "collector_directory_unreadable")
            continue
        if len(entries) > 96:
            flag(issues, "collector_directory_limit")
        for entry_index, path in enumerate(entries[:96]):
            if not SAFE_NAME.fullmatch(path.name):
                flag(issues, "collector_metadata_unavailable")
                continue
            item = metadata(path, issues)
            if not item:
                continue
            info, _ = item
            try:
                writable = os.access(path, os.W_OK)
            except (OSError, ValueError):
                flag(issues, "collector_metadata_unavailable")
                continue
            records.append({"kind": kind, "name": path.name[:128], "state": "unknown",
                            "owner": owner(info.st_uid), "writable": writable,
                            "writable_basis": writable_basis()})
            if len(records) >= 96:
                if entry_index + 1 < len(entries) or root_index + 1 < len(roots):
                    flag(issues, "collector_directory_limit")
                return records
    return records


def suid_records(issues: list[str] | None = None) -> list[dict[str, object]]:
    expected = {"ping", "su", "sudo", "passwd", "mount", "umount", "chsh", "chfn", "newgrp"}
    records = []
    seen: set[str] = set()
    for root in SUID_ROOTS:
        if not root.is_dir():
            continue
        def walk_error(_error: OSError) -> None:
            flag(issues, "collector_directory_unreadable")

        try:
            for base, dirs, files in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
                sorted_dirs = sorted(dirs)
                if len(sorted_dirs) > 32:
                    flag(issues, "collector_walk_limit")
                dirs[:] = sorted_dirs[:32]
                for name in sorted(files):
                    path = Path(base) / name
                    key = str(path)
                    if key in seen:
                        continue
                    seen.add(key)
                    item = metadata(path, issues)
                    if not item:
                        continue
                    info, display = item
                    if info.st_mode & stat.S_ISUID:
                        records.append({"kind": "suid", "path": display, "owner": owner(info.st_uid),
                                        "expected_binary": name in expected})
                        if len(records) >= 64:
                            flag(issues, "collector_suid_limit")
                            return records
        except (OSError, ValueError):
            flag(issues, "collector_directory_unreadable")
    return records


def capability_records(issues: list[str] | None = None) -> tuple[list[dict[str, object]], list[str]]:
    reported = issues if issues is not None else []
    executable = next((candidate for candidate in ("/usr/bin/getcap", "/sbin/getcap") if os.path.isfile(candidate)), None)
    if not executable:
        flag(reported, "unsupported_capability_inventory")
        return [], reported
    try:
        result = subprocess.run([executable, "-r", "-n", "/usr/bin"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
                                check=False, shell=False)
    except (OSError, subprocess.SubprocessError):
        flag(reported, "unsupported_capability_inventory")
        return [], reported
    if result.returncode not in (0, 1):
        flag(reported, "unsupported_capability_inventory")
        return [], reported
    records = []
    if len(result.stdout) > 131072:
        flag(reported, "collector_capability_limit")
    lines = result.stdout[:131072].decode("utf-8", "replace").splitlines()
    if len(lines) > 64:
        flag(reported, "collector_capability_limit")
    for line in lines[:64]:
        fields = line.split()
        if len(fields) < 2 or len(fields[0]) > 256 or any(ord(char) < 32 for char in fields[0]):
            flag(reported, "collector_metadata_unavailable")
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
        else:
            flag(reported, "collector_metadata_unavailable")
    return records, reported


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="operator-selected local inventory label")
    args = parser.parse_args(argv)
    if not isinstance(args.target, str) or not args.target or len(args.target) > 256 or any(ord(c) < 33 for c in args.target):
        parser.error("target must be a bounded non-empty label")
    issues: list[str] = []
    records: list[dict[str, object]] = [identity(issues)]
    records.extend(permissions(issues))
    records.extend(directory_records(SERVICE_ROOTS, "service", issues))
    records.extend(directory_records(TASK_ROOTS, "task", issues))
    records.extend(suid_records(issues))
    capabilities, _ = capability_records(issues)
    records.extend(capabilities)
    if len(records) > MAX_RECORDS:
        flag(issues, "collector_record_limit")
    payload = {"schema": SCHEMA, "target": args.target[:256], "controls": CONTROLS,
               "records": records[:MAX_RECORDS], "issues": sorted(set(issues))}
    json.dump(payload, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
