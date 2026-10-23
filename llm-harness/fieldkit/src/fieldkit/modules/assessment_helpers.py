"""Small, credential-free summaries shared by HTTP assessment modules."""

import hashlib
import re
from http.cookies import CookieError, SimpleCookie
from urllib.parse import urlsplit


def response_summary(response):
    """Summarize a response without copying potentially sensitive body text."""
    return {
        "url": response.url,
        "status": response.status,
        "content_type": response.content_type,
        "bytes": len(response.body),
        "sha256": hashlib.sha256(response.body).hexdigest(),
        "error": response.error,
        "evidence": response.evidence_id,
        "looks_like_login": looks_like_login(response),
    }


def looks_like_login(response):
    """Conservatively exclude common login/error templates from access leads."""
    path = urlsplit(response.url).path.lower()
    if re.search(r"(?:^|/)(?:login|signin|sign-in|log-in|sign_in)(?:/|\.|$)", path):
        return True
    body = response.body[:131072].decode("utf-8", errors="replace").lower()
    return bool(
        re.search(r"<input\b[^>]*\btype\s*=\s*['\"]?password\b", body)
        or re.search(r"<(?:title|h1)\b[^>]*>\s*(?:access denied|unauthorized|forbidden)", body)
    )


def response_similarity(left, right):
    """Bounded token-shingle comparison; keep status/login checks separate."""
    if not left.body or not right.body:
        return 0.0
    if left.body == right.body:
        return 1.0

    def shingles(body):
        words = re.findall(r"\w+|[^\w\s]", body[:131072].decode("utf-8", errors="replace"))
        if len(words) < 4:
            return {tuple(words)}
        return {tuple(words[i : i + 4]) for i in range(len(words) - 3)}

    a, b = shingles(left.body), shingles(right.body)
    return round(len(a & b) / max(len(a | b), 1), 4)


def successful_content(response):
    return bool(
        not response.error
        and response.status is not None
        and 200 <= response.status < 300
        and response.body
        and not looks_like_login(response)
    )


def comparable_content(left, right):
    return (
        successful_content(left)
        and successful_content(right)
        and left.status == right.status
        and left.content_type.split(";", 1)[0].lower()
        == right.content_type.split(";", 1)[0].lower()
        and urlsplit(left.url).path == urlsplit(right.url).path
    )


def cookie_observations(response):
    """Return cookie attributes, never cookie values or raw Set-Cookie lines."""
    observations = []
    headers = [
        (hop.get("url", response.url), value)
        for hop in response.history
        for value in hop.get("set_cookies", [])
    ]
    headers.extend((response.url, value) for value in response.set_cookies)
    for source_url, raw in headers:
        parsed = SimpleCookie()
        try:
            parsed.load(raw)
        except CookieError:
            continue
        for name, morsel in parsed.items():
            observations.append(
                {
                    "name": name,
                    "source_url": source_url,
                    "secure": bool(morsel["secure"]),
                    "httponly": bool(morsel["httponly"]),
                    "samesite": morsel["samesite"].lower(),
                    "domain": morsel["domain"],
                    "path": morsel["path"],
                    "persistent": bool(morsel["expires"] or morsel["max-age"]),
                    "deleted": bool(
                        re.fullmatch(r"-?\d+", morsel["max-age"] or "")
                        and int(morsel["max-age"]) <= 0
                    ),
                }
            )
    return observations


def review_cookies(ctx, response):
    cookies = cookie_observations(response)
    for cookie in cookies:
        if cookie["deleted"]:
            continue
        missing = []
        if urlsplit(response.url).scheme == "https" and not cookie["secure"]:
            missing.append("Secure")
        if not cookie["httponly"]:
            missing.append("HttpOnly")
        if not cookie["samesite"]:
            missing.append("SameSite")
        if missing:
            ctx.finding(
                "cookie_attributes",
                "Review cookie protection attributes",
                cookie["source_url"],
                evidence=[response.evidence_id],
                cookie_name=cookie["name"],
                missing=missing,
                note=(
                    "Confirm the cookie's purpose; JavaScript-readable cookies can be intentional."
                ),
            )
        if cookie["samesite"] == "none" and not cookie["secure"]:
            ctx.finding(
                "cookie_samesite_none",
                "SameSite=None cookie lacks Secure",
                cookie["source_url"],
                severity="low",
                evidence=[response.evidence_id],
                cookie_name=cookie["name"],
                note="Modern browsers reject this cookie configuration.",
            )
    return cookies
