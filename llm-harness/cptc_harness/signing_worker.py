"""Fixed Ed25519 signer; stdin is bounded data, the only secret mount is /key.pem."""
import resource
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    payload = sys.stdin.buffer.read(8 * 1024**2 + 1)
    if len(payload) > 8 * 1024**2:
        raise ValueError()
    with open("/key.pem", "rb") as source:
        key = serialization.load_pem_private_key(source.read(8193), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError()
    sys.stdout.buffer.write(key.sign(payload))
except Exception:
    sys.exit(1)
