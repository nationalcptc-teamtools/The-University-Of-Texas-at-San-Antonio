# TLS inspection and visual inventory

Both modules accept multiple origins or `--targets-file targets.txt`, run through
`fieldkit run MODULE`, and appear in the interactive console. Their reports use the
shared per-run output directory under `--output` (default `artifacts`).

## TLS review

```bash
fieldkit run web/tls-review https://app.example.test https://192.0.2.10:8443
fieldkit run web/tls-review https://app.example.test \
  --protocol TLSv1.2 --protocol TLSv1.3 --expiry-days 45
```

`web/tls-review` opens TLS connections to each HTTPS target's hostname and port, using
the hostname for SNI. HTTP origins are recorded as `skipped_non_https`. Use explicit
HTTPS origins when you want to inspect a particular TLS listener independently of HTTP
availability.

Each requested protocol is tried with its minimum and maximum version fixed. The default
list is TLS 1.0, 1.1, 1.2, and 1.3. Negotiated results record the actual protocol and cipher.
A failed attempt is labeled `not_negotiated`, because the local OpenSSL build, connectivity,
or server policy can all prevent negotiation. It does not conclusively prove the server
has disabled that version. This module checks protocol availability and the negotiated
cipher; it does not enumerate every supported cipher suite.

The leaf certificate is inspected for:

- DNS and IP subject alternative names (SANs) and target-hostname coverage.
- Validity dates, expiration, future validity, and days remaining.
- Subject, issuer, serial number, key type, and SHA-256 fingerprint.
- Trust using the local default trust store, unless `--insecure` is supplied.

Protocol probes retrieve certificates without requiring trust so a self-signed or expired
certificate can still be inspected. Trust is checked separately. `--insecure` skips that
separate verification and labels it `skipped`; it does not label the certificate trusted.
SAN matching does not substitute a certificate common name when SAN coverage is missing.

The leaf certificate is saved as a private PEM file under `certificates/`, referenced in
`report.json`. Findings cover negotiated legacy protocols, trust failures, hostname
mismatches, validity failures, and certificates within `--expiry-days` of expiration.
TLS handshakes themselves do not submit HTTP requests. Run budgets and per-origin pacing
still apply. Findings are observations; certificate revocation checks, a full chain report,
and comprehensive cipher enumeration are outside this module's current scope.

## Page snapshots

```bash
python -m pip install -e '.[browser]'
python -m playwright install chromium
fieldkit run web/snapshot https://app.example.test \
  --path /login --width 1440 --height 900 --max-pages 20
```

`web/snapshot` records titles, response status, content type, decoded response size,
redirect history, and request/response evidence. It captures each seed URL from supplied
paths and imported inventories, or the target homepages when no seeds are supplied. The
maximum number of captures is controlled by `--max-pages` across the run.

Screenshots use the optional Playwright/Chromium installation. A browser navigates to
each page, executes its scripts, and produces a PNG of the configured viewport. Width
must be 320–3840 pixels and height 200–2160 pixels. The screenshot captures the viewport,
not the entire scrolling page. Static and rendered titles are both retained.

Browser HTTP(S) requests pass through Fieldkit's shared HTTP transport. Only GET and HEAD
requests to supplied origins are fulfilled. Requests to other origins and other HTTP
methods are blocked and listed in the page result; WebSockets are closed and service
workers are blocked. Shared session profiles, cookies, scope, limits, and evidence capture
apply to the fulfilled requests. The browser's own credential headers are not forwarded.
A page with cross-origin dependencies or an API requiring POST may therefore render only
partially; the blocked-request list helps explain why.

The run directory includes private PNGs under `screenshots/` and a standalone `gallery.html`
with titles, URLs, statuses, and images. Open the gallery locally to compare pages. Gallery
text is escaped. Screenshots show the rendered page as captured, including any sensitive
content visible to the selected profile; text redaction in exported evidence does not
remove pixels from PNGs.

For a metadata inventory without a browser dependency, use:

```bash
fieldkit run web/snapshot https://app.example.test --no-screenshot
```

This still writes response evidence and a gallery with `No screenshot` placeholders.
When screenshots are enabled but Playwright or Chromium is unavailable, installation
instructions are returned; rerun with `--no-screenshot` for metadata-only collection.
Individual browser rendering failures are preserved in page results and the error list.

## Local verification

`tests/test_platform_modules.py` generates a temporary self-signed certificate and starts
a loopback TLS server restricted to TLS 1.2. Tests verify protocol negotiation, rejection
of TLS 1.3 by that listener, trust failure, SAN matching, and saved certificate identity.

A real Chromium test captures a local HTML page, checks PNG dimensions and the gallery,
verifies that a local script used the shared evidence-producing transport, and confirms
that an external-origin script and a scripted POST reached neither server. That test is
skipped only when the optional Playwright package or Chromium executable is absent.
Metadata-only, viewport-validation, redirect, and gallery-escaping tests run without a
browser installation.
