"""Read-only filesystem worker; launched only explicitly, inside a bounded process group.

No filesystem/network actions occur on import. Extraction never writes archive members.
"""

import fnmatch
import gzip
import hashlib
import json
import os
import re
import stat
import sys
import tarfile
import time
import zipfile
from pathlib import Path

from fieldkit.core.redaction import redact_text
from fieldkit.core.xml import parse_xml

CANDIDATE = re.compile(
    r"(?im)\b(?:[A-Za-z0-9_]{0,64}(?:password|secret|token|api[_-]?key)|"
    r"passwd|passphrase|pwd|credential|connection[_ ]?string)\s*[:=]\s*"
    r"(?:\"([^\"\r\n]{0,8192})\"|'([^'\r\n]{0,8192})'|([^\s\"'<>;,&]+))|"
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|://[^\s/:@]+:([^\s/@]+)@"
)
INTERESTING = re.compile(
    r"(?i)(^\.env($|\.)|^id_(rsa|dsa|ecdsa|ed25519)$|history|"
    r"\.(conf|config|ini|pem|key|pfx|bak|old|backup|kdbx)$|cred|secret|token)"
)


def emit(record):
    print(json.dumps(record), flush=True)


def walk(config):
    roots = [Path(p).expanduser().absolute() for p in config["roots"]]
    boundaries = [p.resolve() for p in roots]
    visited, seen_files = set(), set()
    count = entries = 0
    pending = list(reversed(roots))
    deadline = time.monotonic() + config["budget"]
    while pending:
        if time.monotonic() >= deadline:
            emit({"error": "timeout", "resource": "filesystem", "detail": "Worker deadline"})
            return
        path = pending.pop()
        if any(
            fnmatch.fnmatch(str(path), pattern) or fnmatch.fnmatch(path.name, pattern)
            for pattern in config.get("exclusions", [])
        ):
            continue
        entries += 1
        if entries > config["max_files"] * 20:
            emit({"error": "entry_limit", "resource": str(path)})
            return
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                if not config.get("follow_symlinks"):
                    emit({"kind": "skipped_symlink", "resource": str(path)})
                    continue
                resolved = path.resolve()
                if not any(resolved == root or root in resolved.parents for root in boundaries):
                    emit(
                        {
                            "kind": "skipped_symlink",
                            "resource": str(path),
                            "reason": "outside explicit roots",
                        }
                    )
                    continue
                info = path.stat()
            key = info.st_dev, info.st_ino
            if stat.S_ISDIR(info.st_mode):
                if key in visited:
                    continue
                visited.add(key)
                if config["mode"] == "inventory" and os.access(path, os.W_OK):
                    emit(
                        {
                            "kind": "writable_directory",
                            "resource": str(path),
                            "mode": oct(stat.S_IMODE(info.st_mode)),
                            "uid": info.st_uid,
                            "gid": info.st_gid,
                        }
                    )
                with os.scandir(path) as children:
                    # Bound the queue as well as processed entries.
                    for child in children:
                        if len(pending) > config["max_files"] * 20:
                            emit({"error": "entry_limit", "resource": str(path)})
                            return
                        pending.append(Path(child.path))
                continue
            if key in seen_files:
                continue
            seen_files.add(key)
            if not stat.S_ISREG(info.st_mode):
                emit({"kind": "nonregular", "resource": str(path)})
                continue
            count += 1
            if count > config["max_files"]:
                emit({"error": "file_limit", "resource": str(path)})
                return
            yield path, info
        except OSError as exc:
            emit(
                {
                    "error": "permission_denied"
                    if isinstance(exc, PermissionError)
                    else "io_error",
                    "resource": str(path),
                    "detail": str(exc),
                }
            )


def regular_read(path, maximum, follow=False, boundaries=()):
    # Never open a FIFO/device after a race or follow a newly inserted symlink by default.
    flags = os.O_RDONLY | os.O_NONBLOCK
    if not follow:
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("File changed to a nonregular object")
        # O_NOFOLLOW protects the final component only. A directory ancestor can
        # be replaced with a symlink after traversal, even when following is off.
        if boundaries:
            actual = Path(f"/proc/self/fd/{descriptor}").resolve()
            if not any(actual == root or root in actual.parents for root in boundaries):
                raise ValueError("Symlink/file handle leaves explicit roots")
        return stream.read(maximum + 1)


def extracted(path, data, config):
    """One level of extraction, bounded aggregate bytes and member count."""
    ceiling, count, used = config["max_extract_bytes"], 0, 0
    suffix = path.suffix.lower()
    office = suffix in {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}
    if office and not config["office"]:
        return
    if not office and not config["archives"]:
        return
    import io

    stream = io.BytesIO(data)
    if zipfile.is_zipfile(stream):
        with zipfile.ZipFile(stream) as archive:
            if len(archive.infolist()) > config["max_members"]:
                emit({"error": "extraction_limit", "resource": str(path)})
            for member in archive.infolist()[: config["max_members"]]:
                if member.is_dir() or (office and not member.filename.endswith(".xml")):
                    continue
                count += 1
                with archive.open(member) as handle:
                    content = handle.read(ceiling - used + 1)
                if len(content) + used > ceiling:
                    emit({"error": "extraction_limit", "resource": str(path)})
                    break
                used += len(content)
                if office:
                    root, _ = parse_xml(content, max_bytes=ceiling)
                    content = " ".join(root.itertext()).encode()
                yield member.filename, content
    elif suffix == ".gz" and not path.name.endswith((".tar.gz", ".tgz")):
        with gzip.GzipFile(fileobj=stream) as archive:
            content = archive.read(ceiling + 1)
            if len(content) > ceiling:
                emit({"error": "extraction_limit", "resource": str(path)})
            else:
                yield "gzip-content", content
    elif suffix in {".tar", ".tgz", ".gz"}:
        with tarfile.open(fileobj=stream, mode="r|*") as archive:
            for member in archive:
                count += 1
                if count > config["max_members"]:
                    emit({"error": "extraction_limit", "resource": str(path)})
                    break
                if not member.isfile():
                    continue
                content = archive.extractfile(member).read(ceiling - used + 1)
                if len(content) + used > ceiling:
                    emit({"error": "extraction_limit", "resource": str(path)})
                    break
                used += len(content)
                yield member.name, content


def candidates(path, content, config, member="", sink=None):
    output = sink or emit
    text = content.decode("utf-8", errors="replace")
    resource = str(path) + ("::" + member if member else "")
    for number, line in enumerate(text.splitlines(), 1):
        if not CANDIDATE.search(line):
            continue
        values = [v for match in CANDIDATE.finditer(line) for v in match.groups() if v]
        output(
            {
                "kind": "credential_candidate",
                "resource": resource,
                "line": number,
                "preview": redact_text(line[:500], values),
                "candidate_sha256": hashlib.sha256(line.encode()).hexdigest(),
                "note": "Credential-shaped content; validity was not tested",
            }
        )
    if config.get("raw_dir") and CANDIDATE.search(text):
        name = hashlib.sha256(resource.encode() + b"\0" + content).hexdigest() + ".bin"
        target = Path(config["raw_dir"]) / name
        try:
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            if regular_read(target, len(content)) != content:
                raise ValueError("Private candidate file collision") from None
        else:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
        output(
            {
                "kind": "private_raw",
                "resource": resource,
                "file": "private-raw/" + name,
                "private_raw": True,
                "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )


def main():
    config = json.loads(Path(sys.argv[1]).read_text())
    boundaries = [Path(root).expanduser().resolve() for root in config["roots"]]
    total = scanned = 0
    for path, info in walk(config):
        scanned += 1
        record = {
            "resource": str(path),
            "mode": oct(stat.S_IMODE(info.st_mode)),
            "uid": info.st_uid,
            "gid": info.st_gid,
            "bytes": info.st_size,
        }
        if config["mode"] == "inventory":
            kinds = []
            if info.st_mode & stat.S_ISUID:
                kinds.append("suid_binary")
            if info.st_mode & stat.S_ISGID:
                kinds.append("sgid_binary")
            if os.access(path, os.W_OK):
                kinds.append("writable_file")
            for kind in kinds:
                emit({"kind": kind, **record})
            if path.suffix in {".service", ".timer", ".socket"} or "cron" in str(path):
                try:
                    data = regular_read(
                        path, config["max_bytes"], config.get("follow_symlinks"), boundaries
                    )
                except (OSError, ValueError) as exc:
                    emit({"error": "read_error", "resource": str(path), "detail": str(exc)})
                    continue
                text = data[: config["max_bytes"]].decode(errors="replace")
                if len(data) > config["max_bytes"]:
                    emit({"error": "byte_limit", "resource": str(path)})
                emit(
                    {
                        "kind": "service_configuration",
                        **record,
                        "preview": redact_text(text),
                        "truncated": len(data) > config["max_bytes"],
                    }
                )
                for value in re.findall(r"(?m)^Exec\w+\s*=\s*[-+!:@]*([^\s]+)", text):
                    if value.startswith("/") and os.access(value, os.W_OK):
                        emit(
                            {
                                "kind": "writable_service_executable",
                                "resource": value,
                                "service": str(path),
                            }
                        )
            continue
        if INTERESTING.search(path.name):
            emit(
                {
                    "kind": "sensitive_filename",
                    **record,
                    "note": "Candidate by name; contents/credential validity unverified",
                }
            )
        if total >= config["max_total_bytes"]:
            emit({"error": "byte_limit", "resource": str(path)})
            break
        try:
            ceiling = min(config["max_bytes"], config["max_total_bytes"] - total)
            data = regular_read(path, ceiling, config.get("follow_symlinks"), boundaries)
            if len(data) > ceiling:
                emit(
                    {
                        "error": "byte_limit",
                        "resource": str(path),
                        "detail": "Only a bounded prefix was inspected",
                    }
                )
            data = data[:ceiling]
            total += len(data)
            candidates(path, data, config)
            if path.suffix.lower() == ".pdf":
                if config["pdf"]:
                    emit({"kind": "pdf_candidate", "resource": str(path)})
            else:
                remaining = config["max_total_bytes"] - total
                if remaining <= 0:
                    if config["archives"] or config["office"]:
                        emit({"error": "byte_limit", "resource": str(path)})
                    continue
                extraction_config = {
                    **config,
                    "max_extract_bytes": min(config["max_extract_bytes"], remaining),
                }
                for member, content in extracted(path, data, extraction_config):
                    total += len(content)
                    candidates(path, content, config, member)
        except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError, RuntimeError) as exc:
            emit({"error": "read_or_extract_error", "resource": str(path), "detail": str(exc)})
    emit(
        {
            "kind": "filesystem_summary",
            "files": scanned,
            "bytes_read": total,
            "coverage": "Explicit roots only; excluded/symlink/nonregular paths may be skipped",
        }
    )


if __name__ == "__main__":
    main()
