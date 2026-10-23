"""Normalize explicit targets; this tool does not expand networks or discover hosts."""

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


def read_targets(values: list[str], filename: str = "") -> list[str]:
    entries = list(values)
    if filename:
        entries.extend(Path(filename).expanduser().read_text(encoding="utf-8").splitlines())
    targets: list[str] = []
    for entry in entries:
        if entry.lstrip().startswith("#"):
            continue
        for token in re.split(r"[\s,]+", entry.strip()):
            if token and token not in targets:
                targets.append(token)
    if not targets:
        raise ValueError("Provide at least one target or a nonempty --targets-file")
    return targets


def target_urls(target: str, scheme: str) -> list[str]:
    """Auto mode tries HTTPS, then HTTP only when HTTPS cannot be reached."""
    explicit = "://" in target
    if not explicit:
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            pass
        else:
            if address.version == 6:
                target = f"[{target}]"
    parsed = urlsplit(target if explicit else f"https://{target}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Invalid HTTP(S) target: {target}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials in target URLs are unsupported")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError(f"Targets must be origins without paths, queries, or fragments: {target}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid port in target: {target}") from exc
    if port == 0:
        raise ValueError(f"Invalid port in target: {target}")
    if any(c.isspace() for c in parsed.netloc) or "\\" in parsed.netloc:
        raise ValueError(f"Invalid hostname: {target}")
    schemes = [parsed.scheme] if explicit else (["https", "http"] if scheme == "auto" else [scheme])
    return [urlunsplit((s, parsed.netloc, "/", "", "")) for s in schemes]
