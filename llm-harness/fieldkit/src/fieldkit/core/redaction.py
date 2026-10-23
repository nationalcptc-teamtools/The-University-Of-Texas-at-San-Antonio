"""Redact credentials from evidence and exports without altering in-memory responses."""

import re
from collections.abc import Mapping

SENSITIVE = re.compile(
    r"authorization|cookie|password|passwd|passphrase|pwd|secret|token|api[_-]?key|credential|csrf|session",
    re.IGNORECASE,
)
CREDENTIAL_KEY = re.compile(
    r"authorization|proxy.authorization|(?:set.)?cookie|password|passwd|secret|"
    r"(?:access.|refresh.|csrf.)?token|api.key|x.api.key|x.auth.token|session(?:id|_id)?|credential|"
    r"[A-Za-z0-9_-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|credential)",
    # Prefixed application fields and CSRF headers still denote credential values.
    re.IGNORECASE,
)
ASSIGNMENT = re.compile(
    r"""(?i)(["']?\b(?:[A-Za-z0-9_]{0,64}(?:password|secret|token|api[_-]?key)|"""
    r"""passwd|passphrase|pwd|credential|connection[_ ]?string|session)["']?\s*[:=]\s*)"""
    r"""(?:"([^"\r\n]{0,8192})"|'([^'\r\n]{0,8192})'|([^\s,"'&<>;]+))"""
)


def redact_text(text: str, secrets=()) -> str:
    for secret in sorted({str(s) for s in secrets if s}, key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    text = re.sub(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", r"\1 [REDACTED]", text)
    text = re.sub(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]+)\b", "[REDACTED]", text
    )
    text = re.sub(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "[REDACTED]", text)
    text = re.sub(
        r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(?![A-Za-z0-9_-])", "[REDACTED]", text
    )

    def assignment(match):
        quote = '"' if match[2] is not None else "'" if match[3] is not None else ""
        return match[1] + quote + "[REDACTED]" + quote

    text = ASSIGNMENT.sub(assignment, text)
    text = re.sub(
        r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?(?:-----END \1-----|$)",
        "[REDACTED PRIVATE KEY]",
        text,
        flags=re.DOTALL,
    )
    text = re.sub(r"(://[^\s/:@]+:)[^\s/@]+(@)", r"\1[REDACTED]\2", text)
    text = re.sub(
        r"(?im)^((?:set-cookie|cookie|x-api-key|x-auth-token)\s*:)\s*[^\r\n]+",
        r"\1 [REDACTED]",
        text,
    )
    return text


def redact(value, secrets=()):
    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]"
            if (CREDENTIAL_KEY.fullmatch(str(key)) and isinstance(item, (str, int, float, bool)))
            else redact(item, secrets)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item, secrets) for item in value]
    if isinstance(value, str):
        return redact_text(value, secrets)
    return value
