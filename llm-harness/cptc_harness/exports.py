"""Human-reviewed local exports. No uploads, implicit recipients, or record deletion."""
from __future__ import annotations
from dataclasses import asdict, dataclass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import uuid
from .contracts import PolicyError, canonical_json, digest
from .storage import private_directory, read_private, write_json

MAX_BUNDLE_BYTES = 128 * 1024 * 1024
MAX_BUNDLE_FILES = 4096
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
ALLOWED_TOP = {"audit", "results", "policies", "artifacts"}
DERIVED_FILES = {"coverage.json", "reports/observations.json", "reports/observations.md"}
ALLOWED_FILES = {"policy.json", "integrity-manifest.json", "audit.jsonl", "transcript.log", "ai-brief.json"} | DERIVED_FILES
FORBIDDEN_COMPONENTS = {"secrets", "credentials", "browser-profile", "sessions", ".git",
                        "quarantine", ".quarantine", "unaccepted", ".partial"}
FORBIDDEN_AUDIT_INTERNALS = {".audit-failure.json", ".audit-state.json", ".audit.lock",
                             "rotation.pending.json"}


@dataclass(frozen=True)
class ExportReview:
    root: str
    files: tuple[dict, ...]
    operator: str
    classification: str = "client_confidential"
    version: int = 1

    @property
    def review_hash(self):
        return digest(asdict(self))


def _allowed(root: Path, relative: str) -> Path:
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or any(p in (".", "..") for p in path.parts):
        raise PolicyError("export path traversal rejected")
    if path.parts[0] not in ALLOWED_TOP and relative not in ALLOWED_FILES:
        raise PolicyError("export path is outside the artifact allowlist")
    if any(part.lower() in FORBIDDEN_COMPONENTS or part.lower().endswith(".partial")
           for part in path.parts):
        raise PolicyError("secret, session, quarantined or incomplete stores cannot be exported")
    if path.parts[0] == "audit" and (path.name in FORBIDDEN_AUDIT_INTERNALS
                                     or path.name.startswith(".reserve-")):
        raise PolicyError("incomplete audit internals cannot be exported")
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise PolicyError("export symlink rejected")
    if not current.is_file():
        raise PolicyError("export artifact is not a regular file")
    return current


def _accepted(root, getter):
    from .publication import accepted_files
    if getter is None:
        from .audit import verified_events, publication_receipts_from_events
        receipts = publication_receipts_from_events(verified_events(root / "audit"))
    else:
        receipts = getter()
    return accepted_files(root, receipts)


def _check_derived(root, relative, raw, accepted):
    if relative in DERIVED_FILES and accepted.get(relative) != {
            "path": relative, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}:
        raise PolicyError("derived export requires an accepted completion-audited artifact")


def prepare_export(root: Path, relative_paths: tuple[str, ...], *, operator: str, publication_receipts=None) -> ExportReview:
    root = private_directory(root)
    if (not operator or not relative_paths or len(relative_paths) > MAX_BUNDLE_FILES
            or len(set(relative_paths)) != len(relative_paths)):
        raise PolicyError("export requires an operator and unique explicit artifact selection")
    accepted = _accepted(root, publication_receipts) if set(relative_paths) & DERIVED_FILES else {}
    files, size = [], 0
    for relative in sorted(relative_paths):
        path = _allowed(root, relative)
        raw = read_private(path, MAX_BUNDLE_BYTES)
        _check_derived(root, relative, raw, accepted)
        size += len(raw)
        if size > MAX_BUNDLE_BYTES:
            raise PolicyError("export collection allowance exceeded")
        files.append({"path": relative, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})
    return ExportReview(str(root), tuple(files), operator)


def _reviewed_entries(review: ExportReview) -> tuple[dict, ...]:
    if (type(review.version) is not int or review.version != 1
            or not isinstance(review.operator, str) or not review.operator
            or review.classification != "client_confidential"
            or not isinstance(review.files, tuple) or not review.files
            or len(review.files) > MAX_BUNDLE_FILES):
        raise PolicyError("invalid export review")
    seen, total = set(), 0
    for item in review.files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "bytes"}:
            raise PolicyError("invalid export review entry")
        path, checksum, size = item["path"], item["sha256"], item["bytes"]
        if (not isinstance(path, str) or not path or path in seen
                or not isinstance(checksum, str) or len(checksum) != 64
                or any(character not in "0123456789abcdef" for character in checksum)
                or type(size) is not int or size < 0 or size > MAX_BUNDLE_BYTES):
            raise PolicyError("invalid export review entry")
        seen.add(path)
        total += size
        if total > MAX_BUNDLE_BYTES:
            raise PolicyError("export collection allowance exceeded")
    return review.files


def _archive(review: ExportReview, publication_receipts=None) -> bytes:
    # Memory only: no decrypted/raw temporary export files on the host filesystem.
    output = io.BytesIO()
    entries = _reviewed_entries(review)
    accepted = _accepted(Path(review.root), publication_receipts) if {item["path"] for item in entries} & DERIVED_FILES else {}
    with tarfile.open(fileobj=output, mode="w") as archive:
        total = 0
        for item in entries:
            raw = read_private(_allowed(Path(review.root), item["path"]), MAX_BUNDLE_BYTES)
            _check_derived(Path(review.root), item["path"], raw, accepted)
            if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
                raise PolicyError("reviewed export artifact changed")
            total += len(raw)
            if total > MAX_BUNDLE_BYTES:
                raise PolicyError("export collection allowance exceeded")
            info = tarfile.TarInfo(item["path"])
            info.size, info.mode, info.mtime = len(raw), 0o600, 0
            archive.addfile(info, io.BytesIO(raw))
        manifest = canonical_json({"review": asdict(review), "review_hash": review.review_hash})
        if len(manifest) > MAX_MANIFEST_BYTES:
            raise PolicyError("export manifest allowance exceeded")
        info = tarfile.TarInfo("EXPORT-MANIFEST.json")
        info.size, info.mode, info.mtime = len(manifest), 0o600, 0
        archive.addfile(info, io.BytesIO(manifest))
    return output.getvalue()


def verify_archive(raw: bytes, review: ExportReview) -> dict:
    try:
        entries = _reviewed_entries(review)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            expected = {item["path"]: item for item in entries}
            if len(members) != len(expected) + 1 or {m.name for m in members} != {*expected, "EXPORT-MANIFEST.json"} or any(not m.isfile() for m in members):
                raise PolicyError("export archive contains unexpected entries")
            total = 0
            for member in members:
                allowance = MAX_MANIFEST_BYTES if member.name == "EXPORT-MANIFEST.json" else MAX_BUNDLE_BYTES
                if member.size > allowance:
                    raise PolicyError("export archive member exceeds allowance")
                content = archive.extractfile(member).read(allowance + 1)
                if len(content) != member.size:
                    raise PolicyError("export archive member is incomplete")
                if member.name == "EXPORT-MANIFEST.json":
                    manifest = json.loads(content)
                    if manifest["review_hash"] != review.review_hash or digest(manifest["review"]) != review.review_hash:
                        raise PolicyError("export review manifest mismatch")
                elif len(content) != expected[member.name]["bytes"] or hashlib.sha256(content).hexdigest() != expected[member.name]["sha256"]:
                    raise PolicyError("export artifact integrity mismatch")
                else:
                    total += len(content)
                    if total > MAX_BUNDLE_BYTES:
                        raise PolicyError("export collection allowance exceeded")
        return {"verified": True, "files": len(expected), "archive_sha256": hashlib.sha256(raw).hexdigest()}
    except (tarfile.TarError, ValueError, KeyError, OSError):
        raise PolicyError("invalid export archive") from None


def encrypted_export(review: ExportReview, destination: Path, *, approved_hash: str,
                     recipient: str, age: Path, verify_identity: Path | None = None, publication_receipts=None) -> dict:
    if approved_hash != review.review_hash:
        raise PolicyError("export requires the exact reviewed selection hash")
    if not recipient.startswith("age1") or any(c.isspace() for c in recipient) or len(recipient) > 128:
        raise PolicyError("export requires an explicit age recipient")
    destination = Path(destination).absolute()
    if any(part.lower() in FORBIDDEN_COMPONENTS or part.lower().endswith(".partial")
           for part in destination.parts):
        raise PolicyError("export destination cannot use a quarantined or incomplete directory")
    private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise PolicyError("export destination already exists")
    original = _archive(review, publication_receipts)
    result = verify_archive(original, review)
    temporary = destination.with_name("." + destination.name + "." + uuid.uuid4().hex + ".partial")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            completed = subprocess.run([str(age), "-r", recipient], input=original, stdout=stream,
                                       stderr=subprocess.PIPE, timeout=60, env={}, close_fds=True)
            stream.flush()
            os.fsync(stream.fileno())
        if completed.returncode:
            raise PolicyError("age encryption failed; original records preserved")
        if verify_identity is None:
            raise PolicyError("recipient decryption verification is required before finalizing this export")
        # Identity path is a local operator reference. Key contents are read by age,
        # never loaded into prompts, readable logs, argv, or the archive.
        if Path(verify_identity).is_symlink():
            raise PolicyError("identity reference must not be a symlink")
        completed = subprocess.run([str(age), "--decrypt", "-i", str(verify_identity), str(temporary)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, env={}, close_fds=True)
        if completed.returncode:
            raise PolicyError("recipient decryption verification failed; export not finalized")
        verify_archive(completed.stdout, review)
        if completed.stdout != original:
            raise PolicyError("decrypted archive does not match reviewed bytes")
        # Hard-link refuses overwrite even if a destination races the initial check.
        os.link(temporary, destination, follow_symlinks=False)
        temporary.unlink()
        directory = os.open(destination.parent, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return {**result, "encrypted": True, "decryption_verified": True,
                "encrypted_sha256": hashlib.sha256(read_private(destination, MAX_BUNDLE_BYTES * 2)).hexdigest(),
                "review_hash": review.review_hash, "destination": str(destination)}
    except subprocess.TimeoutExpired:
        raise PolicyError("export timed out; original records preserved") from None
    finally:
        temporary.unlink(missing_ok=True)


def offline_timeline(sources: tuple[Path, ...], destination: Path) -> dict:
    from .audit import verified_events
    events = []
    identities = set()
    for source in sources:
        if not source.is_dir():
            raise PolicyError("offline merge requires complete verified audit directories")
        for item in verified_events(source):
            # Keep source events intact. Sorting is presentation, not a claim of
            # exact cross-device causality or synchronized disconnected counters.
            identity = (item.get("device_id"), item.get("event_id", item.get("id")))
            if identity in identities:
                continue
            identities.add(identity)
            events.append(item)
    events.sort(key=lambda x: (x.get("utc", x.get("timestamp", "")), x.get("device_id", ""), x.get("sequence", x.get("seq", 0))))
    write_json(destination, {"classification": "client_confidential", "source_integrity_verified": True,
                            "ordering": "UTC presentation only; original clock uncertainty and device sequences preserved", "events": events}, replace=False)
    return {"events": len(events), "sources": len(sources), "destination": str(destination)}
