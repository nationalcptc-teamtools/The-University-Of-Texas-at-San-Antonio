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
ALLOWED_TOP = {"audit", "results", "reports", "policies", "artifacts"}
ALLOWED_FILES = {"policy.json", "coverage.json", "coverage.md", "integrity-manifest.json", "audit.jsonl", "transcript.log", "ai-brief.json"}


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
    if any(part.lower() in {"secrets", "credentials", "browser-profile", "sessions", ".git"} for part in path.parts):
        raise PolicyError("secret/session stores cannot be exported")
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise PolicyError("export symlink rejected")
    if not current.is_file():
        raise PolicyError("export artifact is not a regular file")
    return current


def prepare_export(root: Path, relative_paths: tuple[str, ...], *, operator: str) -> ExportReview:
    root = private_directory(root)
    if not operator or not relative_paths or len(set(relative_paths)) != len(relative_paths):
        raise PolicyError("export requires an operator and unique explicit artifact selection")
    files, size = [], 0
    for relative in sorted(relative_paths):
        path = _allowed(root, relative)
        raw = read_private(path, MAX_BUNDLE_BYTES)
        size += len(raw)
        if size > MAX_BUNDLE_BYTES:
            raise PolicyError("export collection allowance exceeded")
        files.append({"path": relative, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})
    return ExportReview(str(root), tuple(files), operator)


def _archive(review: ExportReview) -> bytes:
    # Memory only: no decrypted/raw temporary export files on the host filesystem.
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for item in review.files:
            raw = read_private(_allowed(Path(review.root), item["path"]), MAX_BUNDLE_BYTES)
            if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
                raise PolicyError("reviewed export artifact changed")
            info = tarfile.TarInfo(item["path"])
            info.size, info.mode, info.mtime = len(raw), 0o600, 0
            archive.addfile(info, io.BytesIO(raw))
        manifest = canonical_json({"review": asdict(review), "review_hash": review.review_hash})
        info = tarfile.TarInfo("EXPORT-MANIFEST.json")
        info.size, info.mode, info.mtime = len(manifest), 0o600, 0
        archive.addfile(info, io.BytesIO(manifest))
    return output.getvalue()


def verify_archive(raw: bytes, review: ExportReview) -> dict:
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            expected = {item["path"]: item for item in review.files}
            if len(members) != len(expected) + 1 or {m.name for m in members} != {*expected, "EXPORT-MANIFEST.json"} or any(not m.isfile() for m in members):
                raise PolicyError("export archive contains unexpected entries")
            for member in members:
                if member.size > MAX_BUNDLE_BYTES:
                    raise PolicyError("export archive member exceeds allowance")
                content = archive.extractfile(member).read(MAX_BUNDLE_BYTES + 1)
                if member.name == "EXPORT-MANIFEST.json":
                    manifest = json.loads(content)
                    if manifest["review_hash"] != review.review_hash or digest(manifest["review"]) != review.review_hash:
                        raise PolicyError("export review manifest mismatch")
                elif len(content) != expected[member.name]["bytes"] or hashlib.sha256(content).hexdigest() != expected[member.name]["sha256"]:
                    raise PolicyError("export artifact integrity mismatch")
        return {"verified": True, "files": len(expected), "archive_sha256": hashlib.sha256(raw).hexdigest()}
    except (tarfile.TarError, ValueError, KeyError, OSError):
        raise PolicyError("invalid export archive") from None


def encrypted_export(review: ExportReview, destination: Path, *, approved_hash: str,
                     recipient: str, age: Path, verify_identity: Path | None = None) -> dict:
    if approved_hash != review.review_hash:
        raise PolicyError("export requires the exact reviewed selection hash")
    if not recipient.startswith("age1") or any(c.isspace() for c in recipient) or len(recipient) > 128:
        raise PolicyError("export requires an explicit age recipient")
    destination = Path(destination).absolute()
    private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise PolicyError("export destination already exists")
    original = _archive(review)
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
