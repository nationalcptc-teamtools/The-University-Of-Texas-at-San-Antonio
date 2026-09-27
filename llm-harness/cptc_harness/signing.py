"""Operator-only file key references; private bytes are read in a networkless worker."""
from __future__ import annotations
import base64
import hashlib
import os
from pathlib import Path
import stat
import subprocess
from .contracts import PolicyError
from .integrity import verified_executable, verified_worker
from .storage import private_directory, read_private


def public_key(path: Path) -> tuple[str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    raw = read_private(path, 8192)
    try:
        key = serialization.load_pem_public_key(raw)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError()
        raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return base64.b64encode(raw).decode(), hashlib.sha256(raw).hexdigest()
    except ValueError:
        raise PolicyError("operator public key must be Ed25519 PEM") from None


class SigningReference:
    def __init__(self, path: Path):
        self.path = Path(path).absolute()
        private_directory(self.path.parent)

    def __call__(self, payload: bytes) -> bytes:
        if not isinstance(payload, bytes) or len(payload) > 8 * 1024 * 1024:
            raise PolicyError("signed handover exceeds allowance")
        worker = verified_worker("signing_worker.py")
        interpreter = verified_executable("/usr/bin/python3")
        # Pin the opened inode, not a mutable path. The parent never reads it.
        descriptor = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 8192:
                raise PolicyError("signing reference must be a private regular key file")
            command = [str(verified_executable("/usr/bin/bwrap")), "--unshare-all", "--clearenv", "--cap-drop", "ALL", "--die-with-parent",
                       "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64",
                       "--symlink", "usr/bin", "/bin", "--proc", "/proc", "--dev", "/dev",
                       "--ro-bind-data", str(descriptor), "/key.pem", "--ro-bind", str(worker), "/worker.py",
                       str(interpreter), "-I", "/worker.py"]
            result = subprocess.run(command, input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    timeout=10, env={}, close_fds=True, pass_fds=(descriptor,))
            if result.returncode or len(result.stdout) != 64:
                raise PolicyError("isolated operator signing failed")
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            raise PolicyError("operator signing service unavailable") from None
        finally:
            os.close(descriptor)
