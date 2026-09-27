#!/usr/bin/env python3
"""Preparation-only installation of the pinned age binary into local .tools."""
from __future__ import annotations

import argparse
import hashlib
import io
import os
from pathlib import Path
import platform
import tarfile
import urllib.request

VERSION = "1.3.2"
URL = "https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-amd64.tar.gz"
SHA256 = "cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-age", action="store_true", required=True)
    parser.add_argument("--directory", type=Path, default=Path(__file__).resolve().parents[1] / ".tools")
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        parser.error("This pinned bundle supports Linux x86_64; use your approved platform package for age.")
    dest = args.directory.absolute()
    if any(p.is_symlink() for p in (dest, *dest.parents)):
        parser.error("Installation path must not traverse symbolic links")
    dest.mkdir(mode=0o700, parents=True, exist_ok=True)
    with urllib.request.urlopen(URL, timeout=30) as response:
        archive = response.read(32 * 1024 * 1024 + 1)
    if len(archive) > 32 * 1024 * 1024 or hashlib.sha256(archive).hexdigest() != SHA256:
        parser.error("Pinned age archive digest mismatch")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        for name in ("age", "age-keygen"):
            entry = bundle.getmember("age/" + name)
            if not entry.isfile() or entry.size > 32 * 1024 * 1024:
                parser.error("Unexpected archive entry")
            data = bundle.extractfile(entry).read()
            path = dest / name
            if path.exists():
                if path.is_symlink() or path.read_bytes() != data:
                    parser.error("Existing binary differs; choose an empty installation directory")
                continue
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
            with os.fdopen(fd, "wb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
    print(f"Pinned age {VERSION} installed at {dest}. No PATH or global configuration changed.")


if __name__ == "__main__":
    main()
