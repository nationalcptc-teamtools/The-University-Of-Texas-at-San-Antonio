"""Release-file pins for executable workers. Never silently refresh at runtime."""
import hashlib
import json
from pathlib import Path
from .contracts import PolicyError


def verified_worker(name: str) -> Path:
    root = Path(__file__).parent
    if Path(name).name != name:
        raise PolicyError("invalid worker identifier")
    try:
        manifest = json.loads((root / "resources" / "release-integrity.json").read_text())
        expected = manifest["workers"][name]
        worker = root / name
        if worker.is_symlink() or hashlib.sha256(worker.read_bytes()).hexdigest() != expected:
            raise PolicyError("worker differs from reviewed release hash")
        return worker
    except (OSError, ValueError, KeyError):
        raise PolicyError("reviewed worker integrity manifest unavailable") from None


def verified_executable(path: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise PolicyError("executable path must be absolute")
    try:
        manifest = json.loads((Path(__file__).parent / "resources" / "release-integrity.json").read_text())
        if hashlib.sha256(candidate.read_bytes()).hexdigest() != manifest["executables"][str(candidate)]:
            raise PolicyError("executable differs from reviewed deployment pin")
        return candidate
    except (OSError, ValueError, KeyError):
        raise PolicyError("executable has no reviewed deployment pin") from None
