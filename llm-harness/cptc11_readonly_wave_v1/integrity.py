"""Independent source-only release and process integrity checks."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
from typing import Mapping


class IntegrityError(RuntimeError):
    """A trusted release pin or filesystem property failed."""


_HEX = set("0123456789abcdef")


@dataclass(frozen=True, slots=True)
class VerifiedReadonlyRelease:
    release_id: str
    manifest_sha256: str
    file_sha256: Mapping[str, str]
    catalog_sha256: str


@dataclass(frozen=True, slots=True)
class TrustedReleasePolicy:
    owner_uid: int
    group_gid: int
    trusted_parent: Path
    release_mode: int = 0o750
    file_mode: int = 0o640
    parent_mode: int = 0o750

    def __post_init__(self) -> None:
        if (type(self.owner_uid) is not int or self.owner_uid < 0
                or type(self.group_gid) is not int or self.group_gid < 0):
            raise IntegrityError("trusted owner policy is invalid")
        object.__setattr__(self, "trusted_parent", Path(self.trusted_parent))
        if self.release_mode & 0o022 or self.file_mode & 0o022 or self.parent_mode & 0o022:
            raise IntegrityError("trusted modes permit group or other writes")


def _digest(value: object) -> str:
    if type(value) is not str or len(value) != 64 or set(value) - _HEX: raise IntegrityError("digest is invalid")
    return value


def _relative(name: object) -> str:
    if type(name) is not str or not name or "\x00" in name: raise IntegrityError("release path is invalid")
    if name.startswith(("/", "\\")) or "\\" in name or "//" in name:
        raise IntegrityError("release path is invalid")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} or "/" in part for part in path.parts): raise IntegrityError("release path is invalid")
    return name


def verify_manifest(release_root: str | Path, manifest: Mapping[str, object], policy: TrustedReleasePolicy | None = None) -> VerifiedReadonlyRelease:
    if not isinstance(policy, TrustedReleasePolicy):
        raise IntegrityError("external trusted release policy is required")
    if not isinstance(manifest, Mapping) or set(manifest) != {"schema_version", "release_id", "files", "catalog_sha256"}:
        raise IntegrityError("manifest schema is invalid")
    if manifest["schema_version"] != 1 or type(manifest["release_id"]) is not str or not manifest["release_id"]:
        raise IntegrityError("manifest identity is invalid")
    files = manifest["files"]
    if not isinstance(files, Mapping) or not files: raise IntegrityError("manifest file list is invalid")
    catalog = _digest(manifest["catalog_sha256"])
    root = Path(release_root)
    if root.is_symlink() or not root.is_dir(): raise IntegrityError("release root is invalid")
    root_stat = root.stat()
    if root_stat.st_uid != policy.owner_uid or root_stat.st_gid != policy.group_gid or root_stat.st_mode & 0o777 != policy.release_mode:
        raise IntegrityError("release root ownership or mode differs")
    trusted_parent_input = Path(policy.trusted_parent)
    if trusted_parent_input.is_symlink():
        raise IntegrityError("trusted parent is symlinked")
    trusted_parent = trusted_parent_input.resolve()
    try:
        root.relative_to(trusted_parent)
    except ValueError as exc:
        raise IntegrityError("release root is outside trusted parent") from exc
    current = root
    while current != trusted_parent:
        current_stat = current.stat()
        if (current.is_symlink() or current_stat.st_uid != policy.owner_uid or current_stat.st_gid != policy.group_gid
                or current_stat.st_mode & 0o777 != policy.parent_mode):
            raise IntegrityError("release parent ownership or mode differs")
        current = current.parent
    if trusted_parent.is_symlink() or not trusted_parent.is_dir(): raise IntegrityError("trusted parent is invalid")
    parent_stat = trusted_parent.stat()
    if parent_stat.st_uid != policy.owner_uid or parent_stat.st_gid != policy.group_gid or parent_stat.st_mode & 0o777 != policy.parent_mode:
        raise IntegrityError("trusted parent ownership or mode differs")
    checked: dict[str, str] = {}
    for raw_name, raw_digest in files.items():
        name = _relative(raw_name); expected = _digest(raw_digest); path = root / name
        if path.is_symlink() or not path.is_file(): raise IntegrityError("release file is missing or symlinked")
        for parent in path.parents:
            if parent == root: break
            if parent.is_symlink(): raise IntegrityError("release parent is symlinked")
        mode = path.stat().st_mode
        if mode & 0o022 or mode & 0o777 != policy.file_mode: raise IntegrityError("release file mode differs")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected: raise IntegrityError("release file digest differs")
        checked[name] = expected
    discovered: set[str] = set()
    for child in root.rglob("*"):
        if child.is_symlink(): raise IntegrityError("release contains a symlink")
        if child.is_file(): discovered.add(child.relative_to(root).as_posix())
        elif not child.is_dir(): raise IntegrityError("release contains a special file")
    if discovered != set(checked): raise IntegrityError("manifest does not exactly describe release contents")
    return VerifiedReadonlyRelease(str(manifest["release_id"]), hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), checked, catalog)


def verify_readonly_release(release_root: str | Path, manifest_path: str | Path, policy: TrustedReleasePolicy | None = None, anchor_path: str | Path | None = None) -> VerifiedReadonlyRelease:
    mp = Path(manifest_path)
    if mp.is_symlink() or not mp.is_file(): raise IntegrityError("manifest file is invalid")
    if policy is not None:
        manifest_stat = mp.stat()
        if manifest_stat.st_uid != policy.owner_uid or manifest_stat.st_gid != policy.group_gid or manifest_stat.st_mode & 0o777 != policy.file_mode:
            raise IntegrityError("manifest ownership or mode differs")
    try: manifest = json.loads(mp.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc: raise IntegrityError("manifest JSON is invalid") from exc
    if anchor_path is not None:
        anchor = Path(anchor_path)
        if anchor.is_symlink() or not anchor.is_file(): raise IntegrityError("trust anchor differs")
        anchor_stat = anchor.stat()
        if policy is None or anchor_stat.st_uid != policy.owner_uid or anchor_stat.st_gid != policy.group_gid or anchor_stat.st_mode & 0o777 != policy.file_mode:
            raise IntegrityError("trust anchor ownership or mode differs")
        if anchor.read_text().strip() != hashlib.sha256(mp.read_bytes()).hexdigest(): raise IntegrityError("trust anchor differs")
    return verify_manifest(release_root, manifest, policy)


def _pin(expected: str, actual: str, name: str) -> str:
    try: exp, got = _digest(expected), _digest(actual)
    except IntegrityError as exc: raise IntegrityError(f"{name} pin is invalid") from exc
    if exp != got: raise IntegrityError(f"{name} pin differs")
    return got


def verify_catalog_pin(expected: str, actual: str) -> str: return _pin(expected, actual, "catalog")
def verify_operation_pin(expected: str, actual: str) -> str: return _pin(expected, actual, "operation")
def verify_worker_pin(expected: str, actual: str) -> str: return _pin(expected, actual, "worker")


def verify_runtime_closure(release_root: str | Path, paths: list[str] | tuple[str, ...]) -> bool:
    root = Path(release_root).resolve()
    for raw in paths:
        path = Path(raw)
        if path.is_symlink() or not path.is_file() or root not in path.resolve().parents:
            raise IntegrityError("runtime closure escapes release")
    return True


def verify_process_maps(maps: str, release_root: str | Path) -> bool:
    if type(maps) is not str: raise IntegrityError("process map is invalid")
    root = str(Path(release_root).resolve())
    for line in maps.splitlines():
        fields = line.split()
        if len(fields) >= 6 and "x" in fields[1]:
            mapped = fields[-1]
            if mapped.startswith("/") and not (mapped == root or mapped.startswith(root + "/")):
                raise IntegrityError("executable mapping escapes release")
    return True
