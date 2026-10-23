# Parameter discovery, JWT checks, Burp captures, and ffuf

These four modules use the same CLI, console, reports, and MCP Python API as the
rest of Fieldkit. Captured traffic supplies request context; explicit target origins
and module confirmation flags authorize active work. Examples use a fictional fixture
at `https://app.example.test`. Replace its origin and private inputs with your selected
assessment request before an active run.

| Module | Python execution | Operation |
| --- | --- | --- |
| `web/parameter-discovery` | `fieldkit.run("web/parameter-discovery", options)` | Native unknown-field discovery on selected requests. |
| `web/jwt-check` | `fieldkit.run("web/jwt-check", options)` | Offline token review or explicitly selected HTTP validation tests. |
| `integrations/burp-bridge` | `fieldkit.run("integrations/burp-bridge", options)` | Selected capture handoff into a private local vault. |
| `web/ffuf` | `fieldkit.run("web/ffuf", options)` | Offline JSON/JSONL import or a bounded active single-field campaign. |

Use `fieldkit run MODULE --help` or `fieldkit.module_info(module)` inside `fieldkit_execute_python` for current defaults.
Python options use uppercase keys, lists, and booleans. MCP exposes two stable tools:
`fieldkit_execute_python` and `fieldkit_search_reference`, regardless of module count.
See [MCP setup](mcp.md) for client configuration, jobs, and evidence reads.

## Private fixture inputs

From the checkout, create disposable examples under the ignored `artifacts/` directory.
The fixture session value below is a placeholder, not a working credential:

```bash
umask 077
mkdir -p artifacts/assessment-inputs
cat > artifacts/assessment-inputs/profiles.local.json <<'JSON'
{
  "profiles": {
    "demo": {
      "origins": ["https://app.example.test"],
      "headers": {"Authorization": "Bearer FIXTURE_SESSION_ONLY"}
    }
  }
}
JSON
cat > artifacts/assessment-inputs/requests.local.json <<'JSON'
{
  "requests": [{
    "id": "update",
    "url": "/settings?q=original",
    "method": "POST",
    "profile": "demo",
    "json": {"itemId": "demo-item", "options": {"existing": "keep"}}
  }]
}
JSON
```

Preserve the captured method, query, body format, CSRF fields, cookies, and relevant
headers when replacing this fixture. Profile credentials remain in local files and
are restricted to their declared origins. An existing private vault can supply the
request directly: replace `--requests-file FILE` with `--database VAULT` and use an
explicit vault `--request-id`. Importing or listing a request performs no replay.

Run reports and HTTP evidence are redacted; the optional vault intentionally retains
raw credentials and bodies with owner-only permissions. Keep its database and
`.sqlite.private/` directory together. See [private storage](evidence-workbench.md#private-storage-and-output-contract).

## Native parameter discovery

`web/parameter-discovery` adds one candidate field at a time without overwriting an
existing field. It uses three successful, non-login baselines, two random unknown-name
controls, and a distinct-value repeat for each candidate differential. Unstable
baselines, arbitrary-field echoes, and authentication failures produce inconclusive
results; echoed unknown names in schema errors are normalized before comparison.

Plan the fixture's nested JSON discovery without HTTP:

```bash
fieldkit run web/parameter-discovery https://app.example.test \
  --requests-file artifacts/assessment-inputs/requests.local.json --request-id update \
  --profiles-file artifacts/assessment-inputs/profiles.local.json \
  --json-parent /options --name hiddenMode --name ignored \
  --acceptance-pointer /options/hiddenMode \
  --max-requests 12 --max-probes 6 --budget 60 --dry-run
```

Run the selected active probes after reviewing the inputs:

```bash
fieldkit run web/parameter-discovery https://app.example.test \
  --requests-file artifacts/assessment-inputs/requests.local.json --request-id update \
  --profiles-file artifacts/assessment-inputs/profiles.local.json \
  --json-parent /options --name hiddenMode --name ignored \
  --acceptance-pointer /options/hiddenMode \
  --max-requests 12 --max-probes 6 --budget 60 --confirm-probes
```

| Location | Selection |
| --- | --- |
| Form | `--location form`; captured `form` or a dictionary `data` body. |
| JSON | `--location json --json-parent /options`; RFC 6901 pointer to exactly one existing object. Empty parent selects the root object. |
| XML/SOAP | `--location xml --xml-parent '{urn:soap}Body/{urn:app}Update'`; ElementTree expanded namespace path selecting one parent. `.` selects the root. New child elements inherit the parent's namespace. |
| Query | `--location query`; explicitly chosen, preserving existing query fields and the body. |

`auto` detects captured form, JSON, or XML bodies. Body discovery accepts POST, PUT,
and PATCH. Opaque bodies and ambiguous/non-object parents are unsupported. JSON array
indices and escaped pointer keys are supported. XML candidates must be unqualified
element names. Candidate names can also come from `--names-file FILE`, one per line,
with blank lines and full-line `#` comments ignored.

`no_signal` means a candidate was indistinguishable from unknown-name controls.
`signal` means a candidate-specific differential repeated reliably.
`confirmed_acceptance` additionally requires the configured response JSON pointer to
return both distinct marker values, absent from baseline/control responses. These
observations produce informational findings; recognition or readback does not prove
exploitability, authorization impact, or a vulnerability.

Defaults are 100 candidate names, 100 added-field requests, 30 total requests, a
300-second budget, and minimum similarity 0.98. Hard ceilings are 1,000 names, 10,000
probes, 10,000 total requests, and 3,600 seconds. Probe counts include unknown controls;
total counts include baselines. Cap or budget exhaustion preserves an incomplete
report. Retries must be zero. Use explicit schemes or fixed `--scheme https|http` to
avoid preliminary scheme-detection traffic. Scope and profile origins are checked
before any selected operation, including during dry-run.

## JWT review and controlled checks

`web/jwt-check` reads a compact JWT from `--token-file` or an explicitly selected
saved/vault request. `--token-location` selects `header:Authorization` by default;
`header:NAME`, `cookie:NAME`, `form:NAME`, and `json:/pointer` are also supported.
Token, key, saved-request, profile, expectation, and claim files must be bounded,
regular owner-only files, without symlinks. On POSIX, use `chmod 600` and keep them
owned by the user running Fieldkit.

This creates a local demonstration token and key without printing them:

```bash
python - <<'PY'
import base64, hashlib, hmac, json, os, time
from pathlib import Path
root = Path("artifacts/assessment-inputs")
root.mkdir(parents=True, exist_ok=True, mode=0o700)
def encode(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
key = b"fieldkit-fixture-only-key-do-not-use-in-production"
claims = {"sub": "demo-user", "role": "employee", "iss": "fixture-issuer",
          "aud": "fixture-client", "exp": int(time.time()) + 3600}
unsigned = encode({"alg": "HS256", "typ": "JWT"}) + "." + encode(claims)
signature = base64.urlsafe_b64encode(hmac.digest(key, unsigned.encode(), hashlib.sha256)).rstrip(b"=").decode()
files = {
    "fixture.key": key,
    "fixture.jwt": (unsigned + "." + signature).encode(),
    "jwt-requests.local.json": json.dumps({"requests": [{"id": "protected",
        "url": "https://app.example.test/me", "method": "GET",
        "headers": {"Authorization": "Bearer " + unsigned + "." + signature}}]}).encode(),
    "jwt-expect.local.json": json.dumps({"issuer": "fixture-issuer", "audience": "fixture-client",
        "baseline": {"status": 200, "identity": [{"pointer": "/user/id", "equals": "demo-user"}],
                     "resource": [{"pointer": "/resource", "equals": "demo-invoice"}]}}).encode()
}
for name, content in files.items():
    path = root / name
    path.write_bytes(content)
    os.chmod(path, 0o600)
PY
fieldkit run web/jwt-check \
  --token-file artifacts/assessment-inputs/fixture.jwt \
  --key-file artifacts/assessment-inputs/fixture.key --key-algorithm HS256 \
  --expect-file artifacts/assessment-inputs/jwt-expect.local.json
```

Offline review makes no HTTP requests. It reports fingerprint/structure, expiration,
not-before, issuer/audience comparison, and explicit-key signature verification.
Without a supplied key, the signature is `not_verified`; decoded claims do not
authenticate an identity. Supported explicit key algorithms are HS256/384/512,
RS256/384/512, PS256/384/512, ES256/384/512, and EdDSA. HMAC keys are nonempty raw
bytes, at most 4 KiB; asymmetric keys are compatible PEM public/private keys. Known
weak operator keys can be checked, including short HMAC secrets and legacy RSA keys;
`operator_key_strength` reports below-recommended strength separately. Key-type and
EC-curve compatibility still apply. Key URLs and embedded key hints do not trigger
remote fetching or trust selection, and the module does not guess or brute-force keys.

For a fixture that actually serves the asserted protected response, plan then run
signature and unsigned-token checks:

```bash
fieldkit run web/jwt-check https://app.example.test \
  --requests-file artifacts/assessment-inputs/jwt-requests.local.json --request-id protected \
  --expect-file artifacts/assessment-inputs/jwt-expect.local.json \
  --active --test signature --test none --max-requests 7 --budget 60 --dry-run
fieldkit run web/jwt-check https://app.example.test \
  --requests-file artifacts/assessment-inputs/jwt-requests.local.json --request-id protected \
  --expect-file artifacts/assessment-inputs/jwt-expect.local.json \
  --active --confirm-active --test signature --test none --max-requests 7 --budget 60
```

`EXPECT_FILE` holds private expected issuer/audience values and protected response
assertions. `baseline` requires at least one `identity` or `resource` assertion; each
is either `{"pointer":"/user/id","equals":"demo-user"}` or
`{"contains":"a distinctive protected value"}`. JSON equality is type-sensitive.
HTTP 200 alone cannot establish acceptance. Two initial baselines must match, missing
and malformed-token controls must fail every protected assertion set, and the final
baseline must still match. Credentials are isolated between requests so a baseline
Set-Cookie cannot authenticate a tokenless control.

Select tests individually with repeated `--test`. `signature` corrupts the signature;
`none` sends an unsigned token. `expired`, `issuer`, `audience`, and `claims` require
a verified baseline and a matching operator-supplied signing key; issuer/audience
tests also require matching private expectations. The expiry probe is 24 hours in
the past so ordinary clock-skew tolerance does not look like an expiry bypass.
Claim replacement uses
`--claims-file FILE`, for example `{"role":"admin"}`, and requires a distinct
`probes.claims` protected-response assertion set in `EXPECT_FILE`. The default
`claims_policy` is `observe`: accepting an operator-signed replacement produces an
`accepted_signed_claims` observation without a vulnerability finding. Set the private
expectation file's top-level `"claims_policy": "deny"` only when your known policy
requires those modified claims to be denied. Confirmation then requires the distinct
protected assertions, negative controls, and a preserved final baseline. A valid
signature alone does not establish an authorization policy bypass.

Each selected request reserves `5 + number of tests` HTTP requests: two initial
baselines, two controls, one per test, and a final baseline. `MAX_REQUESTS` defaults
to 12 and cannot exceed 1,000; tokens default to 16 KiB and cannot exceed 64 KiB.
Retries are zero and redirects are disabled. Confirmed findings require the complete
protected-access checks; rejected and inconclusive observations remain separate.

## Burp selected captures to vault IDs and MCP

Build and load the optional [Java extension](../extensions/burp/README.md), then start
a receiver in one terminal:

```bash
fieldkit run integrations/burp-bridge \
  --origin https://app.example.test --database artifacts/assessment.sqlite \
  --budget 600 --max-captures 100 --max-entries 10
```

The command prints a new private properties-file path. In Burp's **Fieldkit** tab,
select that file and optionally enter captured user, role, and feature context.
Select request/response pairs in Proxy history or Repeater, then choose **Send to
Fieldkit**. The extension returns `record_ids`; receiver reports also expose their
`request_id` values. Capture origins constrain accepted evidence without authorizing
replay. The receiver binds `127.0.0.1`, authenticates each send, follows no redirects,
and expires its configuration when its listening period ends or the job is cancelled.

List selected capture metadata and plan a replay in another terminal:

```bash
fieldkit web vault --database artifacts/assessment.sqlite --host app.example.test
fieldkit run web/request-replay https://app.example.test \
  --database artifacts/assessment.sqlite --request-id REQUEST_ID_FROM_CAPTURE --dry-run
```

An MCP client can start the receiver with `fieldkit_execute_python`:

```python
result = fieldkit.run("integrations/burp-bridge", {
    "ORIGINS": ["https://app.example.test"],
    "DATABASE": "artifacts/assessment.sqlite",
    "BUDGET": 600,
    "MAX_CAPTURES": 100,
})
```

Use `fieldkit.read_report(job_id, section="results")` in a later script to find the
ready configuration path and received request IDs while the receiver runs. The human
selects the configuration in Burp. `fieldkit.vault_records("artifacts/assessment.sqlite",
kind="request")` exposes public redacted capture metadata. Pass a chosen ID to replay,
parameter discovery, JWT checks, or ffuf with explicit target origins and confirmation
controls. These facade reads do not expose the receiver token or private raw request
bodies; arbitrary Python retains the server user's local permissions.

Defaults are a dynamically allocated port, 100 total exchanges, 10 per send, 512 KiB
per decoded request/response body, a 1 MiB capture payload, and a 120-second listening
budget. Limits can be tightened; see the extension guide for hard ceilings and
troubleshooting. `--dry-run` opens neither a listener nor a vault.

## ffuf import and bounded active campaigns

`web/ffuf` imports native JSON (`results`) or JSONL without requiring ffuf or making
HTTP requests. For a complete disposable example:

```bash
cat > artifacts/assessment-inputs/ffuf.json <<'JSON'
{"results":[{"url":"https://app.example.test/settings?q=example","status":200,"length":64,"position":1}]}
JSON
fieldkit run web/ffuf --input artifacts/assessment-inputs/ffuf.json --import-complete
```

`--import-complete` is the operator's assertion that the source campaign finished.
Without it, or when bytes/results are truncated or records malformed, the report
remains partial and preserves valid observations. Import provenance includes the
source hash. Tool status/size metadata alone does not establish a vulnerability.

Active runs need an operator-installed ffuf 2.1 executable (default `ffuf` from `PATH`;
`--binary /absolute/path/to/ffuf` also works),
exactly one saved/vault request ID, one existing replacement location, and a UTF-8
wordlist. Query/form values are encoded, and JSON string values escaped, to keep
each word confined to its selected field. The fixture request contains the existing
`q` query field:

```bash
printf 'example\nsecond\n' > artifacts/assessment-inputs/words.txt
fieldkit run web/ffuf https://app.example.test \
  --execute --requests-file artifacts/assessment-inputs/requests.local.json \
  --request-id update --profiles-file artifacts/assessment-inputs/profiles.local.json \
  --wordlist artifacts/assessment-inputs/words.txt --location query:q \
  --max-words 2 --max-requests 3 --max-results 2 --rate 1 --budget 60 --dry-run
```

Replace `--dry-run` with `--confirm-fuzz` to execute the selected campaign. Locations are
`query:NAME`, `header:NAME`, `form:NAME`, `json:/pointer`, or `body:replace`.
`--control-file FILE` optionally supplies one matching request ID. A baseline plus
any control and all selected words must fit `MAX_REQUESTS`. Arbitrary extra ffuf
arguments, recursive campaigns, and host/path replacement are not exposed.

ffuf talks only to an authenticated local fixed-endpoint relay; Fieldkit's shared HTTP transport
contacts the target with preserved method, query, body, session context, TLS checks,
byte limits, rate, concurrency, and deadlines. Redirects and retries are disabled.
The native tool receives response statuses and sizes rather than response bodies;
target evidence remains in Fieldkit's redacted HTTP records. Use `--insecure` only
when intentionally disabling target certificate verification. Private temporary
request/wordlist files use 0600 permissions under a 0700 directory and are removed
after execution. Proxy environment settings are cleared and ffuf configuration/cache
directories isolated for the campaign.

Defaults are 100 words, 100 observations, 102 total requests, and 8 MiB combined
tool output/import bytes. Hard ceilings are 10,000 words/results, 10,002 requests,
and 64 MiB output. Truncation, transport failures, tool errors, byte caps, and deadline
expiry preserve partial evidence; inspect completion and errors before continuing.
