"""Bounded JWT parsing and explicit-key verification, without key discovery."""

import base64
import hashlib
import hmac
import json
import math
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa, utils

ALGORITHMS = {
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
}
HASHES = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}


class JWTError(ValueError):
    """A fixed public diagnostic that never includes token or key material."""


def read_file(filename, maximum, *, private=False):
    try:
        fd = os.open(Path(filename).expanduser(), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise JWTError("JWT inputs must be regular files")
            if (
                private
                and os.name == "posix"
                and (info.st_mode & 0o077 or info.st_uid != os.geteuid())
            ):
                raise JWTError("Credential files must be owner-only (chmod 600)")
            data = stream.read(maximum + 1)
    except OSError as exc:
        raise JWTError("Cannot safely read the selected JWT input file") from exc
    if len(data) > maximum:
        raise JWTError("JWT input exceeds its byte limit")
    return data


def encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode(part):
    if not re.fullmatch(r"[A-Za-z0-9_-]*", part):
        raise JWTError("JWT segments must use unpadded Base64url")
    try:
        decoded = base64.b64decode(part + "=" * (-len(part) % 4), altchars=b"-_", validate=True)
    except ValueError as exc:
        raise JWTError("Malformed JWT Base64url segment") from exc
    if encode(decoded) != part:
        raise JWTError("Noncanonical JWT Base64url segment")
    return decoded


def json_object(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise JWTError("Duplicate JWT JSON member")
            result[key] = value
        return result

    def nonfinite(_value):
        raise JWTError("JWT JSON values must be finite")

    try:
        result = json.loads(data, object_pairs_hook=pairs, parse_constant=nonfinite)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise JWTError("Malformed JWT JSON object") from exc
    if not isinstance(result, dict):
        raise JWTError("JWT header and payload must be JSON objects")
    count, pending = 0, [(result, 0)]
    while pending:
        value, depth = pending.pop()
        count += 1
        if count > 512 or depth > 12:
            raise JWTError("JWT JSON exceeds node or depth limits")
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise JWTError("JWT JSON values must be finite")
    return result


@dataclass(repr=False)
class Token:
    compact: str
    header: dict
    claims: dict
    signature: bytes
    signing_input: bytes

    @property
    def algorithm(self):
        return self.header["alg"]

    def summary(self, issuer="", audience="", now=None):
        now = time.time() if now is None else now
        exp, nbf = self.claims.get("exp"), self.claims.get("nbf")
        aud = self.claims.get("aud")
        return {
            "sha256": hashlib.sha256(self.compact.encode()).hexdigest(),
            "bytes": len(self.compact),
            "algorithm": self.algorithm
            if self.algorithm in ALGORITHMS | {"none"}
            else "unsupported",
            "unsecured": self.algorithm == "none",
            "claim_count": len(self.claims),
            "registered_claims": [
                k for k in ("iss", "sub", "aud", "exp", "nbf", "iat", "jti") if k in self.claims
            ],
            "expiration": "missing" if exp is None else "expired" if exp <= now else "future",
            "not_before": "missing" if nbf is None else "future" if nbf > now else "effective",
            "issuer": "not_requested"
            if not issuer
            else "match"
            if self.claims.get("iss") == issuer
            else "mismatch",
            "audience": "not_requested"
            if not audience
            else "match"
            if audience in ([aud] if isinstance(aud, str) else aud or [])
            else "mismatch",
            "remote_key_reference_ignored": any(
                k in self.header for k in ("jku", "x5u", "jwk", "x5c")
            ),
            "decoded_claims_are_unverified": True,
        }


def parse(compact, maximum=16384):
    if not isinstance(compact, str) or len(compact.encode()) > maximum:
        raise JWTError("JWT exceeds its token byte limit")
    parts = compact.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        raise JWTError("Only compact three-part JWTs are supported")
    header, claims = json_object(decode(parts[0])), json_object(decode(parts[1]))
    if not isinstance(header.get("alg"), str) or not 1 <= len(header["alg"]) <= 32:
        raise JWTError("JWT header requires a bounded algorithm name")
    if "crit" in header or header.get("b64", True) is not True:
        raise JWTError("Critical or unencoded JWS extensions are unsupported")
    for name in ("exp", "nbf", "iat"):
        value = claims.get(name)
        if name in claims and (
            type(value) not in {int, float} or abs(value) > 10**15 or not math.isfinite(value)
        ):
            raise JWTError("JWT time claims must be finite NumericDate values")
    if "iss" in claims and not isinstance(claims["iss"], str):
        raise JWTError("JWT issuer must be a string")
    if "aud" in claims and not (
        isinstance(claims["aud"], str)
        or isinstance(claims["aud"], list)
        and all(isinstance(v, str) for v in claims["aud"])
    ):
        raise JWTError("JWT audience must be a string or list of strings")
    signature = decode(parts[2])
    if header["alg"] == "none" and signature:
        raise JWTError("An unsecured JWT cannot carry a signature")
    return Token(compact, header, claims, signature, (parts[0] + "." + parts[1]).encode())


@dataclass(repr=False)
class VerificationKey:
    algorithm: str
    key: object

    @property
    def strength(self):
        if self.algorithm.startswith("HS"):
            weak = len(self.key) * 8 < int(self.algorithm[-3:])
        elif self.algorithm.startswith(("RS", "PS")):
            weak = self.key.key_size < 2048
        else:
            weak = False
        return "below_recommended" if weak else "standard"

    @property
    def can_sign(self):
        return self.algorithm.startswith("HS") or isinstance(
            self.key,
            (
                rsa.RSAPrivateKey,
                ec.EllipticCurvePrivateKey,
                ed25519.Ed25519PrivateKey,
                ed448.Ed448PrivateKey,
            ),
        )

    def verify(self, token):
        if token.algorithm != self.algorithm:
            return "algorithm_mismatch"
        digest = HASHES[self.algorithm[-3:]]() if self.algorithm != "EdDSA" else None
        key = self.key.public_key() if hasattr(self.key, "public_key") else self.key
        try:
            if self.algorithm.startswith("HS"):
                actual = hmac.digest(self.key, token.signing_input, "sha" + self.algorithm[-3:])
                return "verified" if hmac.compare_digest(actual, token.signature) else "invalid"
            if self.algorithm.startswith("RS"):
                key.verify(token.signature, token.signing_input, padding.PKCS1v15(), digest)
            elif self.algorithm.startswith("PS"):
                key.verify(
                    token.signature,
                    token.signing_input,
                    padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size),
                    digest,
                )
            elif self.algorithm.startswith("ES"):
                width = (key.curve.key_size + 7) // 8
                if len(token.signature) != width * 2:
                    return "invalid"
                signature = utils.encode_dss_signature(
                    int.from_bytes(token.signature[:width], "big"),
                    int.from_bytes(token.signature[width:], "big"),
                )
                key.verify(signature, token.signing_input, ec.ECDSA(digest))
            else:
                key.verify(token.signature, token.signing_input)
        except (InvalidSignature, ValueError):
            return "invalid"
        return "verified"

    def sign(self, header, claims):
        if not self.can_sign or header.get("alg") != self.algorithm:
            raise JWTError("Signed claim probes require a matching operator signing key")
        signing = serialize(header, claims)
        message = signing.encode()
        digest = HASHES[self.algorithm[-3:]]() if self.algorithm != "EdDSA" else None
        if self.algorithm.startswith("HS"):
            signature = hmac.digest(self.key, message, "sha" + self.algorithm[-3:])
        elif self.algorithm.startswith("RS"):
            signature = self.key.sign(message, padding.PKCS1v15(), digest)
        elif self.algorithm.startswith("PS"):
            signature = self.key.sign(
                message,
                padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size),
                digest,
            )
        elif self.algorithm.startswith("ES"):
            r, s = utils.decode_dss_signature(self.key.sign(message, ec.ECDSA(digest)))
            width = (self.key.curve.key_size + 7) // 8
            signature = r.to_bytes(width, "big") + s.to_bytes(width, "big")
        else:
            signature = self.key.sign(message)
        return signing + "." + encode(signature)


def load_key(filename, algorithm):
    if not isinstance(algorithm, str) or algorithm not in ALGORITHMS:
        raise JWTError("KEY_ALGORITHM must select an explicitly supported signature algorithm")
    data = read_file(filename, 65536, private=True)
    if algorithm.startswith("HS"):
        if b"-----BEGIN" in data or not data or len(data) > 4096:
            raise JWTError("HMAC key must be nonempty bounded raw private bytes; PEM is forbidden")
        return VerificationKey(algorithm, data)
    try:
        key = (
            serialization.load_pem_private_key(data, password=None)
            if b"PRIVATE KEY-----" in data
            else serialization.load_pem_public_key(data)
        )
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise JWTError("Key file requires an unencrypted PEM public or private key") from exc
    public = key.public_key() if hasattr(key, "public_key") else key
    if algorithm.startswith(("RS", "PS")):
        valid = isinstance(public, rsa.RSAPublicKey)
    elif algorithm.startswith("ES"):
        curves = {"ES256": ec.SECP256R1, "ES384": ec.SECP384R1, "ES512": ec.SECP521R1}
        valid = isinstance(public, ec.EllipticCurvePublicKey) and isinstance(
            public.curve, curves[algorithm]
        )
    else:
        valid = isinstance(public, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey))
    if not valid:
        raise JWTError("Public key type, strength or curve disagrees with KEY_ALGORITHM")
    return VerificationKey(algorithm, key)


def serialize(header, claims):
    return ".".join(
        encode(json.dumps(value, separators=(",", ":"), sort_keys=True, allow_nan=False).encode())
        for value in (header, claims)
    )


def modified(token, *, header=None, claims=None, key=None, unsigned=False):
    header = token.header if header is None else header
    claims = token.claims if claims is None else claims
    if unsigned:
        return serialize({**header, "alg": "none"}, claims) + "."
    if key is not None:
        return key.sign(header, claims)
    return serialize(header, claims) + "." + encode(token.signature)


def invalid_signature(token):
    if not token.signature or token.algorithm == "none":
        raise JWTError("Signature rejection probe requires a signed baseline token")
    signature = bytes([token.signature[0] ^ 1]) + token.signature[1:]
    return token.signing_input.decode() + "." + encode(signature)
