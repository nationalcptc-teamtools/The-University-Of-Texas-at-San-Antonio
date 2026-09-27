#!/usr/bin/env python3
"""Preparation-only pinned ZAP installation. Never run from an engagement workflow."""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import tarfile
import urllib.request

VERSION = "2.17.0"
ARCHIVE = "ZAP_2.17.0_Linux.tar.gz"
SHA256 = "efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a"
URL = "https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/" + ARCHIVE


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-zap", required=True, action="store_true")
    parser.add_argument("--directory", type=Path, default=Path(__file__).resolve().parents[1] / ".tools")
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        parser.error("This reviewed deployment targets Linux x86_64.")
    root = args.directory.absolute()
    if any(p.is_symlink() for p in (root, *root.parents)):
        parser.error("Preparation directory must not traverse symlinks")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    archive = root / ARCHIVE
    if not archive.exists():
        temporary = root / (ARCHIVE + ".partial")
        try:
            with temporary.open("xb") as output, urllib.request.urlopen(URL, timeout=30) as response:
                count = 0
                while data := response.read(1024 * 1024):
                    count += len(data)
                    if count > 300 * 1024 * 1024:
                        raise ValueError("Archive exceeds pinned preparation limit")
                    output.write(data)
                output.flush(); os.fsync(output.fileno())
            if hashlib.sha256(temporary.read_bytes()).hexdigest() != SHA256:
                raise ValueError("Pinned archive digest mismatch")
            temporary.rename(archive)
        except Exception:
            parser.error("Download was not installed; inspect or remove the local partial artifact before retrying")
    if archive.is_symlink() or hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        parser.error("Existing archive differs from the reviewed official release")
    with tarfile.open(archive, "r:gz") as bundle:
        entries = bundle.getmembers()
        if len(entries) > 1024 or sum(entry.size for entry in entries) > 700 * 1024 * 1024:
            parser.error("Unexpected archive size")
        for entry in entries:
            path = Path(entry.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "ZAP_" + VERSION or not (entry.isdir() or entry.isfile()):
                parser.error("Unexpected archive member")
            destination = root / path
            if any(p.is_symlink() for p in (destination, *destination.parents)):
                parser.error("Installation path traverses a symlink")
            if entry.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            source = bundle.extractfile(entry)
            data = source.read()
            if destination.exists():
                if destination.read_bytes() != data:
                    parser.error("Existing file differs; choose an empty preparation directory")
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, entry.mode & 0o755)
            with os.fdopen(descriptor, "wb") as output:
                output.write(data); output.flush(); os.fsync(output.fileno())
    print("Pinned ZAP 2.17.0 is prepared locally. No runtime pin, PATH, service or engagement policy changed.")
    print("Use the reviewed deployment catalog and acceptance tests before admitting this installation.")


if __name__ == "__main__":
    main()
