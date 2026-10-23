# Linux, replay, tools, and authenticated workflows

All modules use `fieldkit run MODULE --help` and the same options in the interactive
console. Commands below use sanitized examples; their `.example.test` hosts are
placeholders. Local import commands make no assessment requests. Replace hosts and
credentials only when selecting an authorized live operation.

## Installation and execution boundaries

The normal Python installation includes the XML/YAML parsers and SQLite support.
Optional executables are supplied by the operator:

| Capability | Requirement |
| --- | --- |
| Linux inventory | Linux; `uname`, `id`, `sudo`, `crontab`, `systemctl`, `ps`, `ss`, `findmnt`, `exportfs`, `getcap`, and `head` provide individual collection categories. Unavailable or restricted commands are reported. |
| Exposure archive/Office inspection | Python's ZIP/TAR/GZIP and XML libraries; no document macros are executed. |
| Exposure PDF inspection | Poppler `pdftotext` on `PATH`, enabled with `--pdf`. |
| Nuclei import | A captured JSONL file; no Nuclei installation. |
| Nuclei execution | Operator-installed Nuclei v3, selected with `--binary`. |
| Browser login | `pip install -e '.[browser]'` and `python -m playwright install chromium`. |

The reference `cptc-private-toolkit/` directory is an external reference and is ignored
by Fieldkit source control. Point `--template-dir` at selected external assets. Fieldkit
does not invoke Edamame's default scan or install third-party tools on its own.

HTTP modules share origin scope, profiles, redaction, pacing, concurrency, response-byte
limits, retries, and total budget. Their `--dry-run` validates inputs and writes a plan
with zero network requests; it does not test target connectivity or assert permissions.
Subprocesses use structured argv, process-group cancellation, deadlines, combined
stdout/stderr limits, and partial-result preservation. Nuclei's traffic uses its own
configured rate/concurrency/timeout. Browser login uses Playwright's transport rather
than the HTTP scheduler. These transports are explicitly described in their reports.

## Linux inventory and exposure audit

```bash
fieldkit run linux/inventory --host-id assessment-host --root /etc/cron.d \
  --root /etc/systemd/system --max-files 2000 --budget 60
fieldkit run linux/exposure-audit --root /path/to/authorized/configuration-copy \
  --exclude '*.sqlite*' --max-files 500 --max-bytes 1048576 \
  --max-total-bytes 8388608 --archives --office --pdf --budget 30
```

Inventory collects OS/kernel and local identity, passwd/group evidence, noninteractive
`sudo -n -l`, SUID/SGID metadata, capabilities, cron/systemd content, writable paths and
service executables, process names, listeners, mounts/NFS, and container/socket access
metadata. It does not connect to container daemons, create containers, run escalation
proofs, or change system configuration. Process command arguments are omitted.

Default inventory roots cover `/usr/bin`, `/usr/sbin`, cron directories, and systemd
unit directories. Supplying any `--root` replaces that list. The module still runs its
fixed read-only host collectors. Roots delimit filesystem coverage, not the entire
host. Namespace/NSS views, command availability, and current permissions affect results.

Exposure audit requires explicit roots. It inspects credential-shaped assignments,
URI credentials, private-key markers, `.env`/configuration/history/backup names, and
optional extracted text. ZIP/TAR/GZIP members and OOXML/ODF XML are inspected in memory;
member paths are never materialized on disk. `--max-extract-bytes` defaults to 1 MiB
per container, `--max-members` to 100, `--max-total-bytes` to 32 MiB, and `--max-files`
to 10,000. `--max-bytes` bounds individual file reads; `--max-output` bounds worker
output. Per-command `--timeout` and the total `--budget` also apply.

Symlinks are skipped by default. `--follow-symlinks` permits root-contained targets;
special files are skipped. `--exclude` accepts repeated path/name globs. Permission,
directory-entry, file, byte, extraction, and deadline limits are coverage evidence.
Candidates remain review leads: Fieldkit never tries discovered credentials.
`--retain-raw` preserves candidate bytes under `private-raw/` with owner-only permissions.

Host findings use `host` and `resource` instead of artificial web URLs. Each result
links to command or filesystem evidence, and `coverage` records incomplete categories.

## Nmap import

```bash
fieldkit run network/nmap-import --input examples/capabilities/nmap.xml \
  --vhosts-file examples/capabilities/vhosts.json
```

Imports retain addresses, hostnames, state, protocol/port, services/versions, script
results, original scanner metadata, and source SHA-256. The default HTTP candidate
ports are 80, 443, 8080, and 8443; repeated `--http-port` flags replace this list. Only
open TCP candidates whose service is HTTP or unknown become endpoints. TLS service
metadata or 443/8443 suggests HTTPS; inferred schemes are explicitly labeled.

The virtual-host file maps addresses to hostname lists. Both address and selected
hostname endpoints retain provenance and `authorized: false`. A missing successful
`runstats/finished` record yields an incomplete scan report. XML input is byte/node/depth
bounded and refuses entity/resource loading. No network scan or DNS resolution occurs.
Imported inventory entries require explicit origins in a later network command.

## Nuclei import and selected execution

```bash
fieldkit run web/nuclei --input examples/capabilities/nuclei.jsonl \
  --template examples/capabilities/surface-template.yaml --import-complete

# Plan selected execution without launching Nuclei or contacting the host.
fieldkit run web/nuclei https://app.example.test --execute \
  --template-dir examples/capabilities --template surface-template.yaml --dry-run
```

`--input` and `--execute` are mutually exclusive. Import preserves valid JSONL records
when other lines are malformed. `--import-complete` is an operator attestation; without
it the imported run's completion is unknown. Import can annotate selected template
hashes/behavior without executing templates. Unknown templates are marked unreviewed.

Execution requires explicit HTTP(S) origins or `--scheme`, explicit templates (at most
100), `--rate >= 1`, and an installed binary. The adapter supports a conservative static
HTTP subset: `BaseURL`/`RootURL` paths, supported methods, fixed headers/body, and reviewed
matcher/extractor types. It rejects raw requests, fuzzing, code/headless/flow, OAST,
dynamic bodies/headers, credential/Host/framing headers, redirect-enabled templates,
and unsupported DSL helpers. Use result import for templates outside this subset.

Scoped profiles with simple headers/cookies are supported. Detailed `cookie_jar`
profiles and `--insecure` are unsupported for Nuclei execution. Credentials are written
to temporary owner-only config files, not argv. Template bytes are hashed, verified,
and copied into a private execution snapshot. The runner disables public template
download/update behavior, external callbacks, redirects, and extra HTTP probing.

Findings retain tool version when known, template ID/hash, target, matcher, source,
reported severity, and a behavior classification. A GET fingerprint labeled with a
critical CVE remains a `surface_match` observation, not proof of exploitation. Probe
matches also require review. `--max-output`, `--max-results`, deadline/cancellation, and
nonzero tool exits produce partial-run evidence.

## Request replay format and edits

```bash
fieldkit run web/request-replay https://app.example.test \
  --requests-file examples/capabilities/requests.json --request-id order-read --dry-run

# Raw request selection uses ID 1.
fieldkit run web/request-replay https://app.example.test \
  --requests-file examples/capabilities/request.http --raw \
  --raw-url https://app.example.test --request-id 1 --dry-run
```

JSON accepts one request, a list, or `{"requests": [...]}`. Omitted IDs become one-based
string indexes. Request IDs must be unique and execution always requires explicit
`--request-id` selection, including generated OpenAPI/SOAP templates and vault exports.

```json
{
  "id": "order-read",
  "method": "GET",
  "url": "https://app.example.test/api/orders/known-order",
  "profile": "employee",
  "query": {"view": "summary"},
  "headers": {"Accept": "application/json"},
  "cookies": {}
}
```

Headers/cookies map strings to strings; query/form values are scalars. Choose one body
field: `form`, `json`, `xml`, text `body`, Base64-encoded binary `body_base64`, or legacy
`data`. Methods include GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE, and TRACE. Target
origins must be explicitly supplied; relative request paths resolve within that scope.
Raw HTTP/1.x requires an explicit scheme/origin for relative targets and matching Host.
Folded/duplicate headers, inconsistent framing, Host/proxy overrides, and malformed
XML/JSON are rejected. HAR multipart file reconstruction is unsupported.

An edits file is a list of `{"location": "json:/item/id", "value": "known-id"}` objects.
Locations are `query:name`, `header:name`, `cookie:name`, `form:name`, `json:/pointer`,
`xml:ElementTree-path`, or `body:replace`. Selected fields must exist; XML paths must
select exactly one element and use expanded namespaces where needed. `body:replace`
explicitly replaces the entire body. An optional control file provides requests with
matching IDs. Baseline, edited, and control results include evidence IDs and response
similarity. Similarity is comparison data, not a vulnerability conclusion.

All selected requests and edits are scope-checked before execution. `--max-requests`
defaults to 30 and counts baselines/controls. Replaying a POST can change application
state; neither imports nor discovery automatically submit these operations.

## SSRF, XXE, and SQLi checks

These modules inherit request selection, body formats, profiles, and HTTP controls.
Select 1–10 existing fields with repeated `--location`. Each probe set includes baseline
and control evidence and counts toward `--max-requests`.

```bash
fieldkit run web/ssrf-check https://app.example.test \
  --requests-file examples/capabilities/requests.json --request-id callback-submit \
  --location json:/callback --callback-url https://listener.example.test/receipt \
  --receipts-file listener-receipts.local.json --dry-run
fieldkit run web/xxe-check https://app.example.test \
  --requests-file examples/capabilities/requests.json --request-id xml-submit \
  --location 'xml:item' --callback-url https://listener.example.test/entity --dry-run
fieldkit run web/sqli-check https://app.example.test \
  --requests-file examples/capabilities/requests.json --request-id order-read \
  --location query:view --true-marker 'known-order' --dry-run
```

SSRF generates a unique callback ID per selected request/location and writes
`callbacks.json`. Fieldkit does not host a listener. A receipts file contains a list
or `{"receipts": [...]}`; each usable record needs exact `callback_id`, exact `url`,
timezone-aware `received_at`, nonempty `source`, and GET/POST/HEAD `method`. The receipt
must occur after sending and no later than the current time. `--callback-wait` permits
up to 30 seconds of bounded polling. Sending a callback URL alone is inconclusive;
only a matching receipt supports confirmation. Listener receipts are operator-provided
evidence and must come from the actual listener.

XXE requires an XML element selection. Internal entity reflection is an observation.
An external entity is confirmed only by a correlated callback receipt or a unique
`--entity-marker` served exclusively by the operator-controlled endpoint and returned
by the probe. Baseline/control appearances of that marker do not confirm XXE. No local
file-read entity or external resource crawl is generated.

SQLi collects error differences and two boolean control pairs with a resource-specific
`--true-marker`. Optional paired timing requires explicit `--timing-db mysql` or
`postgres`, `--timing-delay` of 0.5–2 seconds, `--rate 0`, and `--retries 0` to reduce
pacing/retry artifacts. Error/boolean/timing differences remain observed leads. There
is no database extraction, credential harvesting, or destructive SQL payload stage.

Reports distinguish `observed`, `confirmed`, `inconclusive`, and `unsupported`.
HTTP 403/500 is response evidence; transport errors and truncated coverage are handled
as failures/inconclusive results rather than evidence of injection.

## SOAP inventory

```bash
fieldkit run web/soap-inventory --wsdl-file examples/capabilities/service.wsdl
```

The namespace-aware parser supports WSDL 1.1, SOAP 1.1/1.2 actions/bindings, actual
service addresses, messages, and bounded XSD parameter shapes. It writes
`request-templates.json` with POST headers/XML and placeholder values. It never executes
an operation. Edit values, explicitly select template IDs, and supply target scope to
replay them. Generated endpoints remain unauthorized inventory entries.

Repeat `--wsdl-file` to supply local imports explicitly. `--fetch-imports` allows HTTP
WSDL/XSD imports only within supplied target origins; local referenced files are not
automatically opened. Defaults are 10 documents and 500 operations. WSDL 2.0, encoded
schemas, complex extensions, unresolved/cyclic shapes, and SOAP headers may need manual
completion; warnings preserve these limitations. XML entities/resource loading is blocked.

## Authorization matrix

```bash
fieldkit run web/auth-matrix https://app.example.test \
  --profiles-file profiles.local.json --matrix-file examples/capabilities/auth-matrix.json \
  --dry-run
```

The matrix declares `identities` mapping identity to named profile; `objects` with an
explicit owner; optional `functions`; and explicit rules with identity, resource,
method override, expected `allow`/`deny`, and optional `deny_statuses`. Resource checks
must assert a nonempty body marker or `json_pointer`/`equals`, with expected statuses.
Resources may use an inline `request` or `request_id` from an explicit `--database`.
Captured authentication headers/cookies are removed when switching identities;
the selected origin-bound profile supplies credentials. Templates with body/query
session credential fields must be sanitized before comparison. This prevents an
owner's captured session from being reused under an anonymous or non-owner label.
When both marker and JSON checks are supplied, both must pass.

Profile names do not determine permissions. Missing sessions, login templates,
transport errors, and unrecognized resource responses are inconclusive. HTTP 200 alone
does not establish access. An unexpected resource match against an explicit deny rule
is stronger when an independent known-allowed identity satisfies the same check.
No IDs are enumerated. The matrix runs only declared resources and rules.

An optional resource `state_check` supplies a GET request, optional profile, and
`json_pointer` into its response. It runs before/after each selected rule and preserves
value fingerprints and evidence. A change is an observation, not proof that the tested
request caused it; concurrent application changes can affect it. `--max-requests`
accounts for these additional calls.

## Dynamic session workflow and browser login

```bash
fieldkit run web/session-workflow https://app.example.test \
  --workflow-file examples/capabilities/session-workflow.json --dry-run
```

A workflow has optional scalar `variables` and explicit ordered `steps`. Each step
contains a request, `expect.statuses`, optional `expect.contains`, and named `extract`
specifications. HTML extraction matches one tag's attributes and reads a selected
attribute; JSON extraction selects a scalar using a JSON pointer. `{{name}}` variables
substitute into later request values, with URL encoding and XML escaping where needed.
Missing/ambiguous/oversize tokens and failed expectations stop later steps.

The workflow clones the selected profile into an isolated session, preserves cookie
continuity, and treats supplied body strings/extracted values as secrets for redaction.
It supports one target origin and defaults to 20 steps. `--save-profile --session-name NAME`
writes `private-session-profile.json`, including origin-bound headers and cookie domain,
path, secure, and expiry metadata. This export contains credentials.

```bash
fieldkit run web/browser-login https://app.example.test \
  --login-url https://app.example.test/login --success-selector '#account-menu' \
  --save-profile --session-name employee
```

Browser login is a separate explicit module. It opens a visible Chromium window by
default (`--headless` is optional), waits for an operator-selected URL glob/visible DOM
condition, and transfers cookies to a private HTTP profile. It blocks outside-origin
requests, service workers, and WebSockets. Credential-bearing profiles must permit
the login origin. The browser wait defaults to 90 seconds and must fit the run budget.
Its transport does not inherit HTTP pacing or retries.
LocalStorage bearer-token transfer, cross-origin SSO, and automated MFA are unsupported;
the operator can complete a compatible same-origin interactive login. A selected DOM
condition does not itself prove authorization. Snapshot's existing restricted request
behavior is unchanged.

## Evidence and examples

New modules write schema-v2 `report.json`, endpoint `inventory.json`, and evidence
sidecars. Tool/import provenance includes source identity and hashes when available.
Partial runs retain usable evidence and mark errors/completion; host coverage is explicit.
Stable IDs incorporate host/resource, template/matcher, rule/identity/object, or selected
probe dimensions when present, while existing web finding identities remain compatible.

[Sanitized inputs](../examples/capabilities/) include raw/JSON requests, edits, callback
receipt shape, authorization/session/workflow inputs, Nmap XML, WSDL, Nuclei output and
one static surface template, plus a synthetic report/evidence pair. The example report
is a format illustration, not a claim that a scan ran. See the [evidence workbench](evidence-workbench.md)
for raw capture retention, correlations, validation annotations, and private SQLite storage.
