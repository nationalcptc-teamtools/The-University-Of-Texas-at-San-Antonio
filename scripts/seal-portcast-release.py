#!/usr/bin/env python3
"""Build or verify the deterministic PortCast release seal.

The default operation is read-only. Admission requires ``--write`` and the
exact seal-plan digest printed by a preceding review. Privileged executable,
worker, launcher, and profile-worker pins are independent code-reviewed inputs;
the command line cannot replace them.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile
from typing import Any, NamedTuple, Sequence


ROOT = Path(__file__).resolve().parents[1]
sys.path[:] = [entry for entry in sys.path if entry != str(ROOT)]
sys.path.insert(0, str(ROOT))

from cptc_harness import integrity


MANIFEST_RELATIVE = "cptc_harness/resources/release-integrity.json"
BOOTSTRAP_RELATIVE = "cptc_harness/resources/portcast-bootstrap-v1.sha256"
PYTHON_LOCK_RELATIVE = "cptc_harness/resources/portcast-python-runtime-v1.json"
CPYTHON_LOCK_RELATIVE = "cptc_harness/resources/portcast-cpython-runtime-v1.json"
LAUNCHER_RELATIVE = "deployment/portcast-bootstrap"
PROFILE_WORKER_RELATIVE = "cptc_harness/profile_runtime/worker.py"
PROFILE_ID = "web.http_jellyfin_public_identity"
SELF_VERIFIED_FILES = frozenset(
    {MANIFEST_RELATIVE, BOOTSTRAP_RELATIVE, LAUNCHER_RELATIVE}
)
HEX = frozenset("0123456789abcdef")
REVIEWED_EXECUTABLES = {
    "/usr/bin/bwrap": "8dea6d013ac3a476f1964ffc6d407a3b6223f43cd4a0c43207146a5cefe59882",
    "/usr/bin/python3": "dd65a07e8f535525443d63e2bd6dd10efbf22bf22e0b6d65e634266acc7ac976",
    "/usr/bin/python3.14": "dd65a07e8f535525443d63e2bd6dd10efbf22bf22e0b6d65e634266acc7ac976",
    "/usr/bin/systemctl": "afe98ef3d55f504b37c6e7eb7da21a639ae7fb558f4c9024c89abb580a703255",
    "/usr/bin/systemd-run": "e14f7e69b1c30ae2135de4abc8df315fe2f23a92ab5ee39d41d4fa5f0b0c6339",
    "/usr/lib/chromium/chromium": "66f5195ba3ee5e250cf1b8b96af9f98528fac6d1454569562998fae4d0b18c47",
    "/usr/sbin/chromium": "3f10e456d0275686e7ed1636f61abf9ce57d479f1290bd70a04937be768523a5",
}
REVIEWED_WORKERS = {
    "audit_worker.py": "226a66596dda9531259e04637dd1ad44dd1933c5cc0a3135e00bab3f06305eb1",
    "browser_worker.py": "578cb2aef094d2963e7bceac1635911c13d11c64afccc1254f818bbd18149d48",
    "passive_worker.py": "358fccf3d32e503cedbed1fd89d1ce98f4a05886c92bf43a7043851a3178c984",
    "provider_worker.py": "88be6b83232a99797a04096f69edbce6ae9492cadc3611dc82436911488c5070",
    "secret_worker.py": "640fcd52bb4026d2b62190b5b427f99dd22a686d00f05b441572b7a70f25260d",
    "signing_worker.py": "dd3ee2b41d36d17a4ebaf2e7c95f683490a7a1e87a803946bcde1f7a5147d9b0",
}
REVIEWED_PROFILE_WORKERS = {
    PROFILE_ID: "472620e6112b00882f480ea4a0209e8dcdab9e0c54ba98ae2bef86c07342f400"
}
PREVIOUS_LAUNCHER_SHA256 = (
    "15deb8743ea56f07d7df0b4f98775ef7f050bf01f7aa15181ee95eaf44bd9fb0"
)
REVIEWED_LAUNCHER_SHA256 = (
    "f43832c3fbca7d0f33f24ce7d6c5f677ea35e73430c8bd75b42f76c053742014"
)


class SealError(ValueError):
    """The reviewed inputs cannot produce a release seal."""


class SealPlan(NamedTuple):
    current_manifest_sha256: str
    bootstrap: bytes
    manifest: bytes
    plan_sha256: str


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SealError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _load_json(raw: bytes, context: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise SealError(f"{context} is invalid") from exc
    if not isinstance(value, dict):
        raise SealError(f"{context} must be an object")
    return value


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and not (set(value) - HEX)
    )


def _safe_relative(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise SealError(f"{context} is not a relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix() or ".." in path.parts:
        raise SealError(f"{context} is unsafe")
    return value


def _read(root: Path, relative: str) -> bytes:
    _safe_relative(relative, "release path")
    try:
        return integrity._read_under_root(
            root,
            relative,
            owner_uid=root.stat().st_uid,
            absolute_components=False,
            allow_empty=True,
        )
    except Exception as exc:
        raise SealError(f"cannot read trusted release input: {relative}") from exc


def _runtime_paths(root: Path, lock: dict[str, Any], context: str) -> set[str]:
    if (
        lock.get("schema_version") != 1
        or not isinstance(lock.get("root"), str)
        or not isinstance(lock.get("files"), dict)
        or not lock["files"]
    ):
        raise SealError(f"{context} schema differs")
    runtime_root = _safe_relative(lock["root"], f"{context} root")
    expected: set[str] = set()
    for relative, digest in lock["files"].items():
        relative = _safe_relative(relative, f"{context} file")
        if not _is_digest(digest):
            raise SealError(f"{context} contains an invalid hash")
        complete = f"{runtime_root}/{relative}"
        if _digest(_read(root, complete)) != digest:
            raise SealError(f"{context} file differs: {relative}")
        expected.add(complete)

    base = root / runtime_root
    if not base.is_dir() or base.is_symlink():
        raise SealError(f"{context} tree is unavailable")
    physical: set[str] = set()
    for path in base.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not (
            stat.S_ISDIR(mode) or stat.S_ISREG(mode)
        ):
            raise SealError(f"{context} contains an unsafe entry")
        if stat.S_ISREG(mode):
            physical.add(path.relative_to(root).as_posix())
    if physical != expected:
        raise SealError(f"{context} physical file set differs")
    return expected


def _check_preserved_approvals(
    root: Path, old: dict[str, Any], section: dict[str, Any]
) -> tuple[str, dict[str, str], dict[str, list[str]]]:
    if (
        set(old) != {"version", "executables", "workers", "portcast-live-v1"}
        or old.get("version") != 2
        or not isinstance(old.get("executables"), dict)
        or not isinstance(old.get("workers"), dict)
    ):
        raise SealError("reviewed release manifest schema differs")
    if old["executables"] != REVIEWED_EXECUTABLES:
        raise SealError("release executable pins differ from independent review")
    if old["workers"] != REVIEWED_WORKERS:
        raise SealError("release worker pins differ from independent review")
    for path, digest in old["executables"].items():
        if not isinstance(path, str) or not Path(path).is_absolute() or not _is_digest(digest):
            raise SealError("reviewed executable pins are invalid")
    for name, digest in old["workers"].items():
        if not isinstance(name, str) or Path(name).name != name or not _is_digest(digest):
            raise SealError("reviewed worker pins are invalid")
        if _digest(_read(root, f"cptc_harness/{name}")) != digest:
            raise SealError(f"reviewed worker approval differs: {name}")

    expected_section = {
        "release_id",
        "files",
        "current_profile_workers",
        "compatible_profile_workers",
        "interpreter",
        "python_runtime",
        "cpython_runtime",
        "launcher",
        "bootstrap_manifest",
    }
    if set(section) != expected_section or section.get("release_id") != "portcast-live-v1":
        raise SealError("reviewed PortCast section schema differs")
    current = section.get("current_profile_workers")
    compatible = section.get("compatible_profile_workers")
    if (
        not isinstance(current, dict)
        or set(current) != {PROFILE_ID}
        or not isinstance(compatible, dict)
        or set(compatible) != {PROFILE_ID}
        or not isinstance(compatible[PROFILE_ID], list)
        or not compatible[PROFILE_ID]
        or len(compatible[PROFILE_ID]) != len(set(compatible[PROFILE_ID]))
        or any(not _is_digest(value) for value in compatible[PROFILE_ID])
    ):
        raise SealError("reviewed profile-worker approvals are invalid")
    if current != REVIEWED_PROFILE_WORKERS or compatible != {
        PROFILE_ID: [REVIEWED_PROFILE_WORKERS[PROFILE_ID]]
    }:
        raise SealError("profile-worker pins differ from independent review")
    worker_hash = _digest(_read(root, PROFILE_WORKER_RELATIVE))
    if current[PROFILE_ID] != worker_hash or worker_hash not in compatible[PROFILE_ID]:
        raise SealError("profile worker changed without a separate approval")

    launcher = section.get("launcher")
    launcher_hash = _digest(_read(root, LAUNCHER_RELATIVE))
    admitted_launcher_records = (
        {"path": LAUNCHER_RELATIVE, "sha256": PREVIOUS_LAUNCHER_SHA256},
        {"path": LAUNCHER_RELATIVE, "sha256": REVIEWED_LAUNCHER_SHA256},
    )
    if (
        launcher_hash != REVIEWED_LAUNCHER_SHA256
        or launcher not in admitted_launcher_records
    ):
        raise SealError("bootstrap launcher changed without a separate approval")
    return worker_hash, dict(current), {
        PROFILE_ID: list(compatible[PROFILE_ID])
    }


def _bootstrap_payload(root: Path, names: set[str]) -> bytes:
    lines = ["PORTCAST-BOOTSTRAP-V1"]
    lines.extend(f"{_digest(_read(root, name))}  {name}" for name in sorted(names))
    return ("\n".join(lines) + "\n").encode("ascii")


def build_plan(root: Path = ROOT) -> SealPlan:
    """Return the exact checked-in bootstrap and release-manifest payloads."""

    root = root.resolve(strict=True)
    old_raw = _read(root, MANIFEST_RELATIVE)
    current_manifest_sha256 = _digest(old_raw)
    old = _load_json(old_raw, "release manifest")
    section = old.get("portcast-live-v1")
    if not isinstance(section, dict):
        raise SealError("reviewed PortCast section is missing")
    worker_hash, current, compatible = _check_preserved_approvals(
        root, old, section
    )

    python_raw = _read(root, PYTHON_LOCK_RELATIVE)
    cpython_raw = _read(root, CPYTHON_LOCK_RELATIVE)
    python_lock = _load_json(python_raw, "Python runtime lock")
    cpython_lock = _load_json(cpython_raw, "CPython runtime lock")
    installed = set(integrity.PORTCAST_RELEASE_FILES) - SELF_VERIFIED_FILES
    installed.update(_runtime_paths(root, python_lock, "Python runtime lock"))
    installed.update(_runtime_paths(root, cpython_lock, "CPython runtime lock"))
    bootstrap = _bootstrap_payload(root, installed)

    file_hashes: dict[str, str] = {}
    for relative in sorted(integrity.PORTCAST_RELEASE_FILES):
        raw = bootstrap if relative == BOOTSTRAP_RELATIVE else _read(root, relative)
        file_hashes[relative] = _digest(raw)

    interpreter_hash = cpython_lock["files"].get("bin/python3.14")
    if not _is_digest(interpreter_hash):
        raise SealError("CPython interpreter pin is missing")
    if file_hashes.get(PROFILE_WORKER_RELATIVE) != worker_hash:
        raise SealError("profile worker is absent from the release surface")

    new_section = {
        "release_id": "portcast-live-v1",
        "files": file_hashes,
        "current_profile_workers": current,
        "compatible_profile_workers": compatible,
        "interpreter": {
            "path": "/app/vendor/portcast-rootfs-runtime/bin/python3.14",
            "sha256": interpreter_hash,
        },
        "python_runtime": python_lock,
        "cpython_runtime": cpython_lock,
        "launcher": {
            "path": LAUNCHER_RELATIVE,
            "sha256": file_hashes[LAUNCHER_RELATIVE],
        },
        "bootstrap_manifest": {
            "path": BOOTSTRAP_RELATIVE,
            "sha256": file_hashes[BOOTSTRAP_RELATIVE],
        },
    }
    manifest = (
        json.dumps(
            {
                "version": 2,
                "executables": old["executables"],
                "workers": old["workers"],
                "portcast-live-v1": new_section,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    plan_hash = _digest(
        b"PORTCAST-SEAL-PLAN-V2\0"
        + current_manifest_sha256.encode("ascii")
        + b"\0"
        + _digest(bootstrap).encode("ascii")
        + b"\0"
        + _digest(manifest).encode("ascii")
    )
    return SealPlan(current_manifest_sha256, bootstrap, manifest, plan_hash)


def _check_directory(descriptor: int, owner_uid: int, context: str) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_mode & 0o022
    ):
        raise SealError(f"{context} directory metadata is unsafe")


def _open_resources_directory(root: Path) -> int:
    try:
        owner_uid = root.stat().st_uid
        if os.geteuid() != owner_uid:
            raise SealError("release sealer must run as the trusted checkout owner")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = os.open(root, flags)
    except OSError as exc:
        raise SealError("release root is unavailable") from exc
    try:
        _check_directory(descriptor, owner_uid, "release root")
        for component in ("cptc_harness", "resources"):
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                raise SealError(
                    f"release directory is unavailable: {component}"
                ) from exc
            try:
                _check_directory(child, owner_uid, component)
            except Exception:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _lock_resources(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise SealError("another release sealer holds the resources lock") from exc
    except OSError as exc:
        raise SealError("cannot lock the release resources directory") from exc


def _atomic_write_at(directory: int, name: str, raw: bytes) -> None:
    if Path(name).name != name or not name:
        raise SealError("release seal filename is unsafe")
    try:
        metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except OSError as exc:
        raise SealError(f"release seal target is unavailable: {name}") from exc
    directory_metadata = os.fstat(directory)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != directory_metadata.st_uid
        or metadata.st_mode & 0o022
    ):
        raise SealError(f"release seal target metadata is unsafe: {name}")
    temporary = name + ".new"
    try:
        os.stat(temporary, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise SealError(f"cannot inspect release-seal staging file: {temporary}") from exc
    else:
        raise SealError(f"stale release-seal staging file exists: {temporary}")
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            stat.S_IMODE(metadata.st_mode),
            dir_fd=directory,
        )
    except OSError as exc:
        raise SealError(f"cannot create release-seal staging file: {temporary}") from exc
    try:
        try:
            os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode))
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise SealError("release seal write failed")
                view = view[written:]
            os.fsync(descriptor)
        except OSError as exc:
            raise SealError(f"cannot persist release-seal staging file: {temporary}") from exc
    finally:
        os.close(descriptor)
    try:
        os.replace(
            temporary,
            name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        os.fsync(directory)
    except OSError as exc:
        raise SealError(f"cannot replace release seal: {name}") from exc


def _verify_written(root: Path, manifest: bytes) -> None:
    with tempfile.TemporaryDirectory(prefix="portcast-seal-anchor-") as directory:
        anchor = Path(directory) / "portcast-live-v1.sha256"
        anchor.write_text(_digest(manifest) + "\n", encoding="ascii")
        anchor.chmod(0o600)
        integrity._verify_portcast_release(
            release_root=root,
            manifest_path=root / MANIFEST_RELATIVE,
            anchor_path=anchor,
            owner_uid=root.stat().st_uid,
        )


def admit(
    root: Path,
    plan: SealPlan,
    expected_plan_sha256: str,
) -> None:
    if expected_plan_sha256 != plan.plan_sha256:
        raise SealError("reviewed release-seal plan digest differs")
    resources = _open_resources_directory(root)
    try:
        _lock_resources(resources)
        if build_plan(root) != plan:
            raise SealError("release inputs changed after plan review")
        _atomic_write_at(resources, Path(BOOTSTRAP_RELATIVE).name, plan.bootstrap)
        _atomic_write_at(resources, Path(MANIFEST_RELATIVE).name, plan.manifest)
        _verify_written(root, plan.manifest)
    finally:
        os.close(resources)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="admit the reviewed exact plan")
    parser.add_argument(
        "--expected-plan-sha256",
        help="exact plan digest printed by a preceding read-only run",
    )
    args = parser.parse_args(argv)
    if args.write != bool(args.expected_plan_sha256):
        parser.error("--write and --expected-plan-sha256 must be used together")

    plan = build_plan(ROOT)
    current = (
        (ROOT / BOOTSTRAP_RELATIVE).read_bytes() == plan.bootstrap
        and (ROOT / MANIFEST_RELATIVE).read_bytes() == plan.manifest
    )
    if args.write:
        admit(
            ROOT,
            plan,
            args.expected_plan_sha256,
        )
        current = True
    elif current:
        _verify_written(ROOT, plan.manifest)

    print(
        json.dumps(
            {
                "bootstrap_sha256": _digest(plan.bootstrap),
                "current": current,
                "manifest_sha256": _digest(plan.manifest),
                "plan_sha256": plan.plan_sha256,
                "reviewed_current_manifest_sha256": plan.current_manifest_sha256,
                "written": args.write,
            },
            sort_keys=True,
        )
    )
    return 0 if current else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SealError as exc:
        print(json.dumps({"error": str(exc), "verified": False}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2) from None
