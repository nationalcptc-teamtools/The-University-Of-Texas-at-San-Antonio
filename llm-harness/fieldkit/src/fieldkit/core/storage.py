"""Collision-resistant local filenames and machine-readable run manifests."""

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote, urlsplit


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def safe_label(value: str, limit: int = 80) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("._")[:limit] or "index"


class ArtifactStore:
    def __init__(self, output: str) -> None:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        self.root = Path(output).expanduser().resolve() / f"{stamp}-{uuid.uuid4().hex[:8]}"
        self.root.mkdir(parents=True, exist_ok=False, mode=0o700)

    def save(self, target: str, url: str, body: bytes) -> dict[str, str | int]:
        target_hash = hashlib.sha256(target.encode()).hexdigest()[:10]
        directory = self.root / f"{safe_label(target)}-{target_hash}"
        directory.mkdir(exist_ok=True, mode=0o700)
        name = safe_label(unquote(urlsplit(url).path).rsplit("/", 1)[-1])
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
        path = directory / f"{name}--{url_hash}"
        with path.open("xb") as stream:
            path.chmod(0o600)
            stream.write(body)
        return {
            "file": str(path.relative_to(self.root)),
            "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        }

    def write_report(self, report: dict) -> Path:
        path = self.root / "report.json"
        temporary = self.root / ".report.json.tmp"
        temporary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(path)
        return path
