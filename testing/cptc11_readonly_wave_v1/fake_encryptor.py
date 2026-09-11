"""Deterministic encryption stand-in for synthetic tests only."""

from __future__ import annotations

import hashlib
from cptc11_readonly_wave_v1.audit import SyntheticEncryptedRecord


class FixedEncryptor:
    def __init__(self, prefix: bytes = b"synthetic-ciphertext:", recipient_fingerprint: str = "a" * 64):
        self.prefix = bytes(prefix)
        self.recipient_fingerprint = recipient_fingerprint
        self.calls = 0

    def encrypt(self, data: bytes) -> SyntheticEncryptedRecord:
        self.calls += 1
        return SyntheticEncryptedRecord("synthetic-v1", self.recipient_fingerprint,
                                        hashlib.sha256(data).hexdigest(),
                                        self.prefix + hashlib.sha256(data).hexdigest().encode("ascii"))


class FailingEncryptor:
    def encrypt(self, data: bytes) -> bytes:
        raise OSError("synthetic encryption failure")
