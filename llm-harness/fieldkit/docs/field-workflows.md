# Stored content, callbacks, network vantages, and MSSQL exports

These modules share Fieldkit's private run directories, schema-version-2 reports,
CLI/console options, and MCP job interface. The four module names are
`web/stored-xss`, `integrations/callback-collector`, `network/vantage`, and
`database/mssql-export`. Use `fieldkit run <module> --help` or MCP
`fieldkit.module_info(module)` inside `fieldkit_execute_python` for the complete typed options.

## Stored-content workflow

Install the optional local browser runtime:

```bash
python -m pip install -e '.[browser]'
python -m playwright install chromium
```

Copy [the example workflow](../examples/capabilities/stored-xss-workflow.json) and
adapt its response expectations, ticket extraction, and browser URL to the actual
application. A sitemap discovers forms; it does not establish the form response
format. Exported request-vault templates can supply the explicit request bodies.

```bash
fieldkit run web/stored-xss http://app.example.test \
  --workflow-file my-ticket-workflow.json --dry-run

fieldkit run web/stored-xss http://app.example.test \
  --workflow-file my-ticket-workflow.json --confirm-submission \
  --port 8088 --public-url http://callback.example.test:8088 \
  --review-wait 60 --budget 180
```

The second command assumes an existing forward from the advertised callback URL
to the loopback listener. `PUBLIC_URL` creates no forwarding or tunnel. Without an
advertised URL, the generated loopback URL works only for callers that can reach
that loopback address. A non-loopback `BIND_HOST` needs an explicit `PUBLIC_URL`.

The workflow has a bounded `steps` array, optional scalar `variables`, and a
`browser` object with `url` and optional `profile`. Each step uses the same request
formats as request replay, explicit `expect.statuses`, optional `expect.contains`,
and optional `extract` specifications. GET/HEAD setup steps can collect CSRF inputs;
exactly one POST step carries `{{payload}}`. Shared HTTP clients retain cookies.
URL variables may change paths and queries, and cannot alter an authority. The
browser URL must identify the stored item without carrying the proof payload.

ID extractors support:

- `json`: JSON pointer, for example `{"source":"json","pointer":"/ticket_id"}`.
- `html`: the existing tag/match/attribute extractor.
- `header`: a named response header, for example `{"source":"header","name":"X-Ticket-ID"}`.
- `location`: query selection, for example `{"source":"location","name":"id"}`,
  or path component selection with `"part":"path","index":-1`.

Redirects are inspected without automatic following, so a 302/303 Location can
provide the ticket ID. Extraction is private by default. Set `public:true` only for
an identifier which should appear in the redacted report. All workflow variables
are preserved in an owner-only private file.

The default canary sends only a random proof string using a credential-free POST
to its registered callback URL. An optional bounded `PAYLOAD_TEMPLATE_FILE` must
include `{{callback_url}}` and `{{proof}}`; it can also use `{{marker}}`. Operator
templates determine their own context and behavior.

Chromium is checked before submission. Browser resources use Fieldkit's scoped
GET/HEAD transport; service workers, WebSockets, downloads, outside origins, and
other state-changing browser requests are blocked. Local proof requires an exact
callback POST body from a scoped document frame. It is intercepted and never sent
to the external listener. A stored-XSS finding requires both that execution event
and the marker in a subsequently retrieved document. HTML-escaped content alone
does not establish execution. Screenshots stay under `private-raw/`.

Chromium also uses an owned rejecting loopback proxy, with direct WebRTC UDP,
QUIC, and unmanaged DNS disabled. Authorized HTTP requests still use Fieldkit's
shared transport. Native browser tests verify that STUN UDP and TURN TCP cannot
bypass this transport while the routed canary continues to execute.

The integrated listener waits for external receipts within `REVIEW_WAIT` and the
overall `BUDGET`. Reports distinguish instrumented local execution, external HTTP
callbacks, failed workflow expectations, and unobserved execution. An external
callback does not establish a staff user's identity or privilege. To use an existing
collector, supply its full registered `CALLBACK_URL` and owner-only `RECEIPTS_FILE`;
the same marker/method/proof-hash/time checks apply. Set `--no-browser` when only
external callback observation is needed. A long wait is a background MCP job, so
poll status and read its live report instead of blocking the client turn.

## General callback collector

```bash
fieldkit run integrations/callback-collector \
  --port 8088 --public-url http://callback.example.test:8088 \
  --callbacks 2 --method GET --max-receipts 10 --budget 120
```

The collector publishes unpredictable `/callbacks/<marker>` URLs and an owner-only
receipt file in its live report. Existing forwarding must preserve an optional
public URL path prefix. It opens a passive listener and makes no outbound requests.
It stops at its receipt/time limits and closes connections on interruption.

Receipts retain allowlisted metadata: marker, canonical URL, method, time, peer
address, byte counts, and body SHA256. Request headers, cookie values, query values,
and raw bodies are not retained. An optional expected `BODY_SHA256` strengthens
correlation for a known proof body. Exact registered path, permitted method, timestamp,
and optional hash determine a match.

For offline correlation, provide `RECEIPTS_FILE`, `CALLBACK_URL`, `CALLBACK_ID`, and
optionally `SINCE_EPOCH`. Inputs must be bounded owner-only JSON/JSONL regular files.
Imported observations retain their reported provenance; they do not establish caller
identity. HTTP callbacks are supported; this module is not a DNS callback service.

## Network vantage and pivot diagnostics

```bash
# Routes, resolver state, interfaces, TUN owners, and known agent socket observations.
fieldkit run network/vantage --target 10.64.3.10 --device ligolo

# Add explicitly selected TCP handshakes, with no traffic to other ports.
fieldkit run network/vantage --target 10.64.3.10 --port 1433 --probe

# Compare another host's saved observations with this host's local measurements.
fieldkit run network/vantage --target 10.64.3.10 \
  --import-vantage other-host-report.json
```

Linux diagnostics collect bounded `ip -j` link/address/route output, route selection
for resolved targets, resolver configuration, network namespace identity, and
allowlisted sysfs/proc metadata. Process command lines and environments are omitted.
Missing tools or denied metadata produce explicit coverage gaps. `DRY_RUN` suppresses
DNS and TCP probes. Numeric-address route inspection sends no target traffic.

A TUN's existence, administrative state, descriptor owner, agent process presence,
established sockets, and selected-target TCP reachability are separate observations.
None alone verifies that an agent is authenticated to a particular proxy or that a
specific TUN carries an active tunnel. The report names the observations and limits
instead of promoting them to an unverified active state. Existing TUN ownership is
useful when diagnosing `Device or resource busy`.

Imported single vantages, lists, full reports, or `{"vantages":[...]}` documents
enable per-host comparisons. They remain reported observations with source-file
provenance. Fieldkit does not log into other hosts, repair DNS/routes, start a
tunnel, delete a device, or stop an owner process.

## Windows-authenticated MSSQL inventory and export

```bash
python -m pip install -e '.[mssql]'

# Inventory explicit databases; no table rows are exported by default.
fieldkit run database/mssql-export --host sql.example.test \
  --database CompetitionApp --credential-file private-mssql.json --budget 180

# Export only the tables named in the private selection document.
chmod 600 my-mssql-tables.json
fieldkit run database/mssql-export --host sql.example.test \
  --database CompetitionApp --credential-file private-mssql.json \
  --tables-file my-mssql-tables.json --no-inventory-only \
  --max-rows 1000 --max-total-bytes 16777216 --budget 180
```

An owner-only credential JSON file contains `domain`, `username`, and `password`,
or `hashes` in `LMHASH:NTHASH` format. `CREDENTIAL_ENV` can instead name an environment
variable holding that JSON. Secrets are passed to an isolated worker through a
temporary owner-only file and removed afterward; they are not placed in argv or
public reports. Authentication uses Impacket's Windows NTLM path. Kerberos tickets
and SQL authentication are not supported by this adapter.

Copy [the table-selection example](../examples/capabilities/mssql-tables.json) and
adapt its explicit database/schema/table objects. Database scope is never inferred
from inventory. The adapter uses metadata SELECTs, `COUNT_BIG`, and bounded row
SELECTs with quoted identifiers. It exposes no arbitrary SQL or write operation.

The owner-only `private-raw/mssql-export.zip` contains a manifest and JSONL table
members with actual row counts, exported counts, column/type metadata, and limit or
partial-error records. Public reports contain metadata and archive checksums, without
row values. Row, column, cell-conversion, total-byte, and process deadlines are bounded.
NULL and binary values are represented explicitly; decimal/date values preserve
their text representation. Long cells or unsupported types are labeled in the
manifest rather than silently treated as a complete export. Capped row selections
have no promised ordering. Interrupted or failed selected tables preserve available
partial results. This is a scoped data export, not a transactionally consistent
database backup.

## Primary references

- [Playwright routing](https://playwright.dev/python/docs/network) and
  [browser contexts](https://playwright.dev/python/docs/api/class-browsercontext).
- [Linux TUN/TAP documentation](https://docs.kernel.org/networking/tuntap.html).
- [Impacket TDS implementation](https://github.com/fortra/impacket/blob/impacket_0_12_0/impacket/tds.py).
- [SQL Server COUNT_BIG](https://learn.microsoft.com/en-us/sql/t-sql/functions/count-big-transact-sql).
