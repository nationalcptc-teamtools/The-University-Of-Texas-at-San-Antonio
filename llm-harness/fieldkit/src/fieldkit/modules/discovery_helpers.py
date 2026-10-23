"""Small, bounded parsers shared by discovery modules; never execute content."""

import re
from collections import defaultdict
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit
from xml.etree import ElementTree


class PageParser(HTMLParser):
    """Extract navigation and field names without retaining submitted/default values."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base: str | None = None
        self.links: list[tuple[str, str]] = []
        self.forms: list[dict] = []
        self._form: dict | None = None
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs = dict(attrs)
        if tag == "base" and self.base is None:
            self.base = attrs.get("href")
        if tag in {"a", "area", "link"} and attrs.get("href"):
            self.links.append((attrs["href"], tag))
        if tag in {"script", "iframe"} and attrs.get("src"):
            self.links.append((attrs["src"], tag))
        if tag == "form":
            self._form = {
                "action": attrs.get("action") or "",
                "method": (attrs.get("method") or "GET").upper(),
                "parameters": [],
            }
            self.forms.append(self._form)
        if tag in {"input", "select", "textarea", "button"} and self._form is not None:
            name = attrs.get("name")
            if name and not any(key == "disabled" for key in attrs):
                parameter = {"name": name, "in": "form", "type": attrs.get("type") or tag}
                if parameter not in self._form["parameters"]:
                    self._form["parameters"].append(parameter)
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title = (self.title + data)[:300]


def parse_page(body: bytes) -> PageParser:
    parser = PageParser()
    parser.feed(body.decode("utf-8", errors="replace"))
    return parser


def page_base(page: PageParser, document_url: str) -> str:
    """Honor an external base without reinterpreting its relative links as local."""
    try:
        return urljoin(document_url, page.base) if page.base else document_url
    except ValueError:
        return document_url


def get_seed_urls(ctx) -> list[str]:
    """Do not silently turn inventory entries for mutating methods into GET probes."""
    methods = defaultdict(set)
    for endpoint in getattr(ctx, "imported_endpoints", []):
        methods[endpoint["url"]].add(endpoint.get("method", "GET").upper())
    return [url for url in ctx.seed_urls() if not methods[url] or "GET" in methods[url]]


def robots_references(body: bytes) -> list[tuple[str, str]]:
    refs = []
    for line in body.decode("utf-8", errors="replace").splitlines():
        key, colon, value = line.partition(":")
        value = value.split("#", 1)[0].strip()
        if colon and value and key.strip().lower() in {"allow", "disallow", "sitemap"}:
            kind = "sitemap" if key.strip().lower() == "sitemap" else "robots"
            # Robots glob expressions are patterns, not fetchable endpoints.
            if kind == "sitemap" or ("*" not in value and "$" not in value):
                refs.append((value, kind))
    return refs


def sitemap_references(body: bytes) -> list[tuple[str, str]]:
    # Explicitly reject declarations instead of allowing entity expansion.
    if re.search(rb"<!\s*(?:DOCTYPE|ENTITY)\b", body, re.IGNORECASE):
        raise ValueError("Sitemap contains a DTD or entity declaration")
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError as exc:
        raise ValueError(f"Invalid sitemap XML: {exc}") from exc
    kind = "sitemap" if root.tag.rsplit("}", 1)[-1] == "sitemapindex" else "sitemap-url"
    if root.tag.rsplit("}", 1)[-1] not in {"sitemapindex", "urlset"}:
        raise ValueError("XML root is not sitemapindex or urlset")
    return [
        (node.text.strip(), kind)
        for node in root.iter()
        if node.tag.rsplit("}", 1)[-1] == "loc" and node.text and node.text.strip()
    ]


def is_html(content_type: str, body: bytes) -> bool:
    return "html" in content_type.lower() or body.lstrip().lower().startswith(
        (b"<!doctype html", b"<html")
    )


def is_javascript(url: str, content_type: str) -> bool:
    return "javascript" in content_type.lower() or urlsplit(url).path.lower().endswith(
        (".js", ".mjs", ".cjs")
    )


def positive_limits(settings: dict, *names: str) -> None:
    for name in names:
        if not isinstance(settings[name], int) or settings[name] <= 0:
            raise ValueError(f"{name} must be a positive integer")
