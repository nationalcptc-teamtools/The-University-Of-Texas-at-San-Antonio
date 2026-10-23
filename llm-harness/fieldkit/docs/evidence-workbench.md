# Private evidence vault and correlation workbenches

Fieldkit's SQLite vault joins assets, identities, requests, routes, artifacts,
observations, hypotheses, workflows, and findings through evidence links. Passive
modules inspect supplied local material. Captured hosts and generated routes never
authorize network actions. Every module also writes a normal schema-v2 run report.

## Create a vault from captures

```bash
fieldkit ingest har examples/workbench/traffic.har --database artifacts/demo.sqlite \
  --tag shipment --user example-employee --role employee
fieldkit ingest burp examples/workbench/burp.xml --database artifacts/demo.sqlite
fieldkit ingest raw examples/capabilities/request.http --database artifacts/demo.sqlite \
  --raw-url https://app.example.test
fieldkit ingest openapi examples/workbench/openapi.json --database artifacts/demo.sqlite \
  --host vendor.example.test
fieldkit ingest actuator examples/workbench/actuator.json --database artifacts/demo.sqlite \
  --host vendor.example.test
fieldkit ingest js examples/workbench/routes.js --database artifacts/demo.sqlite \
  --host vendor.example.test
fieldkit ingest oidc examples/workbench/oidc.json --database artifacts/demo.sqlite \
  --host vendor.example.test
```

These aliases call `evidence/ingest`. Supported formats are HAR, Burp saved-items XML,
raw HTTP, Fieldkit report, JavaScript, OpenAPI JSON, Actuator JSON, OIDC JSON, and binary
artifact. JSON document imports are explicit; OpenAPI YAML remains supported by the
existing `web/api-inventory` module. Auto format selection recognizes `.har`, `.xml`,
`.http`, `.js`, and HAR/report-shaped `.json`; choose `--format` for other document kinds.
`--input` is repeatable on the direct module; the alias accepts multiple files.

Requests retain method, URL, query/body encoding, cookies and CSRF/other headers,
response metadata/body, original timestamp where supplied, source file/hash/index,
feature tags, and operator-supplied user/role context. Role labels are context only.
HAR and Burp responses become linked artifacts. Relative raw requests require
`--raw-url`. Duplicate/folded/framing headers and malformed captures are rejected;
HAR multipart reconstruction requires original body text/bytes; params-only captures
are rejected. Repeated URL-encoded form fields retain their order. Capture limits default to 1 MiB
per input and 1,000 records, adjustable with `--max-bytes`/`--max-records`. Inspect import
errors and completion; persisted records from a partial import remain local.

Fieldkit report import preserves observations/findings and remaps evidence references.
It does not silently open the report's other local files or recreate credentials
removed by redaction. Keep original run directories for external artifacts.
Modules using the shared HTTP transport with `--database PATH` additionally capture
raw exchanges for later replay/correlation. This option is opt-in; browser/tool
traffic uses its separate evidence paths and can be imported as captures/reports.
The original file collector retains its existing interface. Vault workbenches default
to `artifacts/fieldkit.sqlite`.

## Private storage and output contract

```text
artifacts/demo.sqlite          # schema-v1 records/links, 0600
artifacts/demo.sqlite.private/ # raw blobs, directory 0700/files 0600
artifacts/UNIQUE_RUN/
  report.json                 # schema-v2 redacted results/findings/errors/evidence
  inventory.json              # imported endpoints remain unauthorized
  evidence/                   # redacted run evidence
  private-request-templates.json # only when explicitly exporting requests
  report.md                   # evidence/report draft
```

The vault is an operator-local store, not an encryption boundary. Private request and
response JSON and blobs preserve credentials intentionally. Owner-only POSIX permissions
do not make raw stores suitable for publication. The database, its `.private/` directory,
request/profile exports, and Linux `private-raw/` data are ignored by source control.
Public record reads and run reports use redaction; arbitrary secret detection remains
heuristic. Private evidence references are explicitly marked in reports.

Records have a stable ID (`kind` plus a content/identity hash), kind, public/private JSON,
source metadata, and timestamp. Links name relationships and retain redacted details.
Result entries include `vault_evidence` with the originating vault record ID and normal
run evidence references. Preserve the vault/blobs and run directories together; a
Markdown draft does not copy raw material.

## Find and replay captured requests

```bash
fieldkit web vault --database artifacts/demo.sqlite --host vendor.example.test \
  --tag shipment --user example-employee --role employee
# Replace REQUEST_ID with an ID from the listing; export performs no requests.
fieldkit web vault --database artifacts/demo.sqlite --request-id REQUEST_ID
fieldkit run web/request-replay https://vendor.example.test \
  --database artifacts/demo.sqlite --request-id REQUEST_ID --dry-run
```

`web/request-vault` filters host, feature tag, user, and role. Selected exports write
`private-request-templates.json` with preserved raw context and an explicit credentials
marker in the report. Replay can read the database directly or that file; it requires
explicit IDs and target origins. Use the full vault request ID or a unique imported
source index. A bare `184` works only if it identifies exactly one source record.
Named profiles and explicit edits/controls follow [request replay](capabilities.md#request-replay-format-and-edits).
Importing/exporting never replays requests.

## Route and typed ID mapping

```bash
fieldkit web routes --database artifacts/demo.sqlite --host vendor.example.test
fieldkit web ids --database artifacts/demo.sqlite --host vendor.example.test \
  --route '/shipment-jobs/{id}/export'
```

`web/routes` merges observed traffic with JavaScript, OpenAPI, and Actuator candidates,
preserving method/path/asset/source and links to originating captures/documents.
JavaScript extraction is heuristic; OpenAPI/mappings are declarations while traffic
provides observed requests. The mapper makes no network requests.

`web/ids` finds bounded scalar IDs in captured JSON responses, infers resource types
from field names, and matches exact values in later requests on the same asset. The
example HAR contains a fulfillment `orderId` and separate shipment-job UUID, followed
by an export using the latter. Results retain response pointer, source request ID,
semantic type, consuming field, inferred route resource type, ambiguity, and type
mismatches. Route filters do not enumerate IDs or prove ownership/authorization.
Generic `id` fields can remain ambiguous. Ordering uses supplied capture timestamps
or indices within one capture, rather than import dates; unavailable chronology is
marked unknown. A response is never linked as the source of its own request's ID.
Captured ordering/completeness constrain correlation; reuse is not proof of causation
or permission.

Supply `--host` for imported JS/documents; a unique known hostname maps to its captured
asset. Multiple origins for one hostname can leave the context ambiguous.

## Hosts, IPs, TLS SNI, redirects, and canonical URLs

```bash
fieldkit web resolve --database artifacts/demo.sqlite --host vendor.example.test \
  --mappings-file examples/workbench/host-mappings.json
```

`web/host-resolver` keeps captured DNS name, IP, observed/expected Host, observed/expected
TLS SNI, redirect, and canonical URL separate. IPs come from captures/operator mappings;
unknown properties stay unknown. It does not run DNS resolution or treat an expected
hostname as observed SNI. Available IPs produce structured argv and a shell-quoted
`curl --resolve HOST:PORT:ADDRESS URL` command without executing it. That command keeps
the URL hostname for Host/SNI while connecting to a selected IP; it does not change
Fieldkit HTTP DNS resolution.

Optional `--probe` requires explicit origins, fetches within scope without following
redirects, records Location/canonical URL, flags outside-scope destinations, and explains
that 308 preserves method/body. A redirect is not scope authorization. Passive use
requires a database or explicit target metadata.

## Actuator, secrets, dependencies, and authentication flows

```bash
fieldkit web actuator --database artifacts/demo.sqlite
fieldkit run evidence/correlate --database artifacts/demo.sqlite
fieldkit web auth-flows --database artifacts/demo.sqlite
fieldkit findings hypotheses --database artifacts/demo.sqlite
```

Actuator analysis reads captured/imported discovery, env, configprops, info, and mappings
JSON. It identifies exposure shape, routes/controller details, dependency/configuration
clues, and secret candidates displayed as fingerprints/redacted metadata. It does not
fetch endpoints, use leaked credentials, or infer arbitrary-user access from a client secret.

Secret/dependency correlation scans request/response/document/artifact content. Repeated
fingerprints and package/version candidates link to their sources and assets. JAR
filenames and Maven-like text are clues; runtime/classpath presence is unverified.
A package version alone is not a vulnerability.

Auth-flow mapping reads authorize/callback/token traffic, OIDC discovery, client IDs,
scopes, redirects, PKCE parameters, and selected JWT claims. Payloads are decoded without
signature/issuer/audience validation and marked unverified. `auth-flow.mmd` links observed
clients and unverified subject/audience labels. No discovery endpoints are fetched and
tokens are not authenticated. Opaque/encrypted tokens or missing captures limit results.
Use the explicit [auth matrix](capabilities.md#authorization-matrix) for known IDs and rules.
The separate [JWT checker](agent-assessment-tools.md#jwt-review-and-controlled-checks)
adds private-key verification and explicitly selected protected-resource tests.

## Artifact triage and serialization review

```bash
fieldkit inspect artifact examples/workbench/serialized-export.txt \
  --database artifacts/demo.sqlite --host vendor.example.test
fieldkit inspect serialization --database artifacts/demo.sqlite
```

Triage stores the unchanged original and a transformation graph. Bounded Base64,
GZIP/zlib, ZIP, and TAR transformations create child blobs with hashes/counts, parent/
operation provenance, depth, and signature observations. Recognized signatures include
Java `AC ED 00 05`, possible pickle/PHP serialization, JSON, and compression/archive
formats. Signature detection is tentative. No objects are deserialized, no pickle or
archive contents execute, and no gadgets are generated.

Defaults are depth 4 (maximum 10), 10 MiB aggregate transformed bytes, 1 MiB per read/
transformation, 100 members, and 1,000 records. Limits/errors remain coverage evidence.
Archive members are inspected in memory, never written at member-selected filesystem
paths. Encrypted/unsupported containers require separate operator analysis.

Serialization review links observed format, asset-matched dependency clues, and artifact-
associated baseline verification. It creates hypotheses with supporting evidence,
counterevidence, and a next test. `modified_test_allowed` means a legitimate baseline
has been recorded for that artifact; the workbench itself performs no modified object
test. There is no automatic gadget or remote-command-execution stage.

## Verify a legitimate baseline

```bash
fieldkit workflow baseline https://vendor.example.test --database artifacts/demo.sqlite \
  --workflow-file examples/capabilities/verified-workflow.json --dry-run
fieldkit workflow baseline https://vendor.example.test --database artifacts/demo.sqlite \
  --request REQUEST_ID --expect-file examples/capabilities/expect-resource.json --dry-run
```

`web/workflow-verify` accepts ordered inline/vault requests with resource expectations:
nonempty marker, JSON pointer/equality, or exact body SHA-256, plus expected statuses.
Optional token extraction/substitution follows the HTTP workflow format. A successful
export/replay baseline records `baseline_verified` and `outcome: validated`; failed
transport, resource checks, or extraction block changes. Status 200 alone is insufficient.

Optional `modification` specifies exactly one `location`/`value` for the final request.
It executes only after the entire baseline passes and `--confirm-modification` is set.
Without that flag the baseline can be recorded and the supplied change stays unexecuted.
`--artifact-id` links baseline evidence to a captured artifact for the serialization
gate. Response comparisons do not automatically prove exploit impact. Origin scope
still applies; intentionally selected replay operations can have ordinary application
side effects.

## Hypotheses and evidence-linked report drafts

```bash
fieldkit findings hypotheses --database artifacts/demo.sqlite
fieldkit findings draft --database artifacts/demo.sqlite
# Replace annotation evidence IDs with existing vault IDs before importing.
fieldkit findings draft --database artifacts/demo.sqlite --findings-file annotations.local.json
```

The queue preserves candidate-secret and serialization leads with evidence for/against
and a next test. It is a bounded local review queue, not an autonomous scanner or
exhaustive attack planner.

Annotations are a bounded JSON list. Each finding requires `validation_status` of
`observed`, `validated`, or `hypothesized` and nonempty existing vault evidence IDs.
Optional title, severity, URL or host/resource, impact, and remediation notes are retained.

```json
[
  {
    "title": "Captured configuration contains a credential-shaped value",
    "kind": "configuration_exposure",
    "validation_status": "observed",
    "severity": "info",
    "url": "https://vendor.example.test/actuator/configprops",
    "evidence": ["REPLACE_WITH_EXISTING_VAULT_ID"],
    "impact": "Disclosed configuration requires review; validity is untested.",
    "remediation": "Restrict diagnostic exposure and review affected secrets."
  }
]
```

`observed` describes captured behavior, `validated` records supplied checks, and
`hypothesized` is an unproven lead. An annotation or successful legitimate baseline
does not prove command execution. Injection modules separately use `confirmed` only
under their documented evidence conditions. Existing review/export schema compatibility
and manual-review history are preserved.

`evidence/report` writes `report.json`/`report.md`, retaining evidence/context and
hypotheses. Markdown prioritizes findings; inspect JSON for the full queue/graph.
Missing evidence is reported rather than invented. Drafts need operator review before sharing.

## Scope and current integration limits

The console and direct CLI share the same modules. Shortcuts cover ingest, routes/IDs/
hosts/vault/Actuator/auth flows, artifact/serialization inspection, workflow baselines,
and findings/hypotheses. List flags repeat; console settings use uppercase option names.

Burp integration accepts saved-items XML/HAR and includes a Java Montoya
[Send to Fieldkit extension](../extensions/burp/README.md) for selected live messages.
The bridge stores captures and returns vault request IDs; it does not intercept,
modify, or send traffic to assessment targets. Fieldkit retains its Python HTTP transport and does not wrap the
external ProjectDiscovery httpx CLI. Nuclei execution supports the reviewed subset in
[capabilities](capabilities.md#nuclei-import-and-selected-execution). Passive correlations
are heuristic and bounded, with provenance and no automatic exploitation. Sanitized
[workbench inputs](../examples/workbench/) support offline demos and local fixtures.
