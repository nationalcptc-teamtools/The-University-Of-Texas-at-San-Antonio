"""Named, origin-bound session profiles. Profile files are never copied into reports."""

import json
from dataclasses import dataclass, field
from http.cookiejar import Cookie
from pathlib import Path
from urllib.parse import urlsplit

from fieldkit.core.urls import normalize_url


@dataclass
class SessionProfile:
    name: str
    origins: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    cookie_jar: list[dict] = field(default_factory=list)


def jar_cookie(record):
    return Cookie(
        0,
        record["name"],
        record["value"],
        None,
        False,
        record["domain"],
        record["domain"].startswith("."),
        record["domain"].startswith("."),
        record.get("path", "/"),
        True,
        record.get("secure", False),
        record.get("expires"),
        record.get("expires") is None,
        None,
        None,
        {},
        False,
    )


def load_profiles(filename: str) -> dict[str, SessionProfile]:
    profiles = {"anonymous": SessionProfile("anonymous")}
    if not filename:
        return profiles
    document = json.loads(Path(filename).expanduser().read_text(encoding="utf-8"))
    records = document.get("profiles") if isinstance(document, dict) else None
    if not isinstance(records, dict):
        raise ValueError("Profiles file must contain a 'profiles' object")
    for name, record in records.items():
        if not isinstance(record, dict) or not isinstance(name, str) or not name:
            raise ValueError("Each session profile must be a named object")
        if name == "anonymous":
            raise ValueError("The anonymous profile is reserved and cannot contain credentials")
        origins = record.get("origins", [])
        if not isinstance(origins, list) or not all(isinstance(item, str) for item in origins):
            raise ValueError(f"Profile {name}: origins must be a list of origin URLs")
        normalized = []
        for url in origins:
            parsed = urlsplit(normalize_url(url))
            if parsed.path not in {"", "/"} or parsed.query:
                raise ValueError(f"Profile {name}: origins cannot contain paths or queries")
            normalized.append(normalize_url(url))
        mappings = []
        for key in ("headers", "cookies"):
            value = record.get(key, {})
            if not isinstance(value, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in value.items()
            ):
                raise ValueError(f"Profile {name}: {key} must map strings to strings")
            if any("\n" in k + v or "\r" in k + v for k, v in value.items()):
                raise ValueError(f"Profile {name}: invalid newline in {key}")
            if key == "headers" and any(k.lower() == "host" for k in value):
                raise ValueError("Profile Host overrides are unsupported; use target hostnames")
            mappings.append(value)
        jar = record.get("cookie_jar", [])
        if not isinstance(jar, list) or len(jar) > 1000:
            raise ValueError("Profile cookie_jar must be a bounded list")
        for cookie in jar:
            if (
                not isinstance(cookie, dict)
                or not all(isinstance(cookie.get(k), str) and cookie[k] for k in ("name", "domain"))
                or not isinstance(cookie.get("value"), str)
            ):
                raise ValueError("Cookie jar entries require name, value and domain")
            if any("\n" in cookie[k] or "\r" in cookie[k] for k in ("name", "value", "domain")):
                raise ValueError("Cookie jar strings cannot contain newlines")
            domain = cookie["domain"].lstrip(".").lower()
            hosts = [urlsplit(o).hostname for o in normalized]
            if not any(
                h == domain or h.endswith("." + domain) or h + ".local" == domain for h in hosts
            ):
                raise ValueError("Cookie jar domain must match a profile origin")
            if not isinstance(cookie.get("path", "/"), str) or not cookie.get(
                "path", "/"
            ).startswith("/"):
                raise ValueError("Cookie path must start with /")
            if not isinstance(cookie.get("secure", False), bool) or (
                cookie.get("expires") is not None and not isinstance(cookie["expires"], int)
            ):
                raise ValueError("Cookie secure/expires types are invalid")
        if (any(mappings) or jar) and not normalized:
            raise ValueError(f"Profile {name}: credentials require explicit origins")
        profiles[name] = SessionProfile(name, normalized, *mappings, jar)
    return profiles
