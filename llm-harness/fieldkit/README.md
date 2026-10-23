# Fieldkit

A modular Python toolkit for CPTC team assessments, with direct commands and a
Metasploit-style interactive terminal console, plus an optional MCP server for AI agents.
Fieldkit inventories web applications and
Linux hosts, replays selected requests, and correlates captured traffic and artifacts in
a private local evidence vault. It preserves evidence for manual review.
Python 3.11 or newer is required.

Fieldkit is a standalone project inside `llm-harness/fieldkit`. Install it into its
own virtual environment and run the commands below from that directory. It is not
registered with the guarded harness broker; its CLI and MCP server use Fieldkit's
own controls and run with the operator's file and network permissions.

## Download and install

Install Git and Python with `venv` support, then run:

```bash
git clone https://github.com/Moriz82/cptc-private-toolkit.git
cd cptc-private-toolkit/llm-harness/fieldkit
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
fieldkit --help
fieldkit modules
```

For browser screenshots or explicit browser login, install the optional browser extra and Chromium:

```bash
python -m pip install -e '.[browser]'
python -m playwright install chromium
```

If Chromium reports missing system libraries, follow Playwright's platform-specific
installation output. Metadata-only snapshots work with `--no-screenshot` without the
browser extra. Modules that do not render pages run without Chromium. Nuclei execution requires an
operator-installed Nuclei v3 binary; JSONL import does not. PDF extraction optionally
uses `pdftotext` from Poppler. Missing Linux commands produce coverage errors rather
than triggering installation. See [capability setup](docs/capabilities.md).

The optional `web/ffuf` adapter uses an operator-installed ffuf 2.1 binary for active
runs; imports work without it. The [Burp capture extension](extensions/burp/README.md)
builds with a Java 17+ JDK and the Montoya API JAR. Native parameter discovery and JWT
review run in the Python environment. See the [agent assessment tools guide](docs/agent-assessment-tools.md).

Stored-content browser verification uses the browser extra. Windows-authenticated
MSSQL inventory and local table exports additionally need the `mssql` extra:

```bash
python -m pip install -e '.[mssql]'
```

See the [workflow, callback, vantage, and database guide](docs/field-workflows.md) for setup
and examples. The MSSQL adapter supports NTLM Windows authentication with a private
credential file or environment variable; Kerberos authentication is not supported.

In a new terminal, return to the checkout and run `source .venv/bin/activate` again.
Alternatively, run `.venv/bin/fieldkit` directly. Use `deactivate` when finished.

To update an existing checkout:

```bash
git pull --ff-only
source .venv/bin/activate
python -m pip install -e .
```

## Use Fieldkit from Copilot or another MCP agent

Install the optional MCP extra into the same environment:

```bash
python -m pip install -e '.[mcp]'
fieldkit mcp --help
```

The local stdio server exposes two code-mode tools: Python execution and searchable
API references. Agents compose every registered module, persistent jobs, redacted
report/evidence reads, and public vault records through a shared `fieldkit` Python API.
Use the [Copilot/VS Code configuration examples](examples/mcp/README.md) to connect
your agent. The client starts the server; `fieldkit mcp --workspace /absolute/project`
is also available directly. Network tools still require explicit target origins and
the same session profiles and module controls as the CLI.

See [MCP setup and tool usage](docs/mcp.md) for a complete ingest-to-report example,
job limits, and the boundary between agent-readable results and private raw evidence.

## Run commands or use the console

```bash
# Collect files from multiple hostnames/IPs.
fieldkit collect app.example.test 192.0.2.10 http://192.0.2.11:8080

# Load origins from a file.
fieldkit collect --targets-file targets.txt --output artifacts

# Run any module by name.
fieldkit run web/header-review https://app.example.test --path /account
fieldkit run web/site-map --help

# Start the interactive console.
fieldkit console
```

Replace example targets with your competition targets. The console exposes the same
modules and options as the direct CLI:

```text
fieldkit > modules
fieldkit > use web/site-map
fieldkit (web/site-map) > set TARGETS https://app.example.test http://192.0.2.10
fieldkit (web/site-map) > set MAX_PAGES 100
fieldkit (web/site-map) > set RATE 5
fieldkit (web/site-map) > show options
fieldkit (web/site-map) > run
fieldkit (web/site-map) > back
fieldkit > exit
```

Use `help`, `search`, `info`, `unset OPTION`, and tab completion. `set` replaces the
option value; list options accept space-separated values in the console and repeated
flags in direct commands. Quote values containing spaces. Ctrl-C saves a partial
network-run report and returns to the console. History is kept in memory only.

## Modules

| Module | Purpose |
| --- | --- |
| `web/artifacts` | Collect robots, security, secrets, sitemaps, JavaScript, and backup files. Also available as `fieldkit collect`. |
| `web/js-review` | Review downloaded scripts and source maps for endpoints, routes, hostnames, and possible secrets. |
| `web/site-map` | Bounded crawling of links, forms, robots paths, and sitemap documents. |
| `web/content-discovery` | Probe wordlists and extension variants with wildcard/soft-404 filtering. |
| `web/auth-compare` | Compare endpoint responses across supplied session profiles. |
| `web/session-check` | Review cookies and optionally execute explicit login/logout sequences. |
| `web/header-review` | Contextual checks of security headers, cookie attributes, caching, and disclosures. |
| `web/cors-check` | Inspect origin handling, credentials, and OPTIONS preflight policies. |
| `web/api-inventory` | Parse OpenAPI/Swagger JSON or YAML into endpoints and request templates. |
| `web/parameter-map` | Inventory query/form/API/JS parameter names, with optional GET marker reflection. |
| `web/parameter-discovery` | Discover unknown fields in selected captured requests with working baselines, unknown-name controls, and repeated confirmation. |
| `web/jwt-check` | Review private JWTs offline or run explicit protected-resource validation tests with missing/invalid-token controls. |
| `web/ffuf` | Import ffuf output or fuzz one selected saved request through a bounded, scoped HTTP relay. |
| `web/tls-review` | Inspect certificate trust, hostname coverage, dates, and negotiated TLS versions. |
| `web/snapshot` | Capture titles, response metadata, screenshots, and a local HTML gallery. |
| `web/report-export` | Generate a Markdown draft and evidence index from one or more reports. |
| `results/compare` | Show added, removed, and changed observations across two runs. |
| `results/merge` | Deduplicate team reports while retaining conflicting evidence and review decisions. |
| `results/review` | Assign a finding and record its review status in a new report. |
| `linux/inventory` | Collect read-only host, permission, service, process, listener, mount, and container evidence. |
| `linux/exposure-audit` | Inspect explicit filesystem roots for redacted credential/file exposure candidates. |
| `network/nmap-import` | Import bounded Nmap XML and selected HTTP services without scanning. |
| `web/nuclei` | Import JSONL or execute explicitly selected, reviewed static HTTP templates. |
| `web/request-replay` | Replay selected JSON/raw/vault requests with field edits and controls. |
| `web/ssrf-check` | Correlate selected callback probes with actual listener receipts. |
| `web/xxe-check` | Compare selected XML entity probes with external callback/content evidence. |
| `web/sqli-check` | Collect error/boolean and optional bounded timing comparisons. |
| `web/soap-inventory` | Parse WSDL 1.1/SOAP bindings and generate unexecuted request templates. |
| `web/auth-matrix` | Compare explicit identities, known resources, and expected authorization rules. |
| `web/session-workflow` | Extract HTML/JSON tokens and preserve session continuity through explicit steps. |
| `web/browser-login` | Perform optional interactive same-origin login and export a private HTTP profile. |
| `evidence/ingest` | Import HAR, Burp XML, raw HTTP, reports, documents, and artifacts into SQLite. |
| `web/request-vault` | Filter captured requests by host/user/role/tag and export selected private templates. |
| `web/routes` | Merge traffic, JavaScript, OpenAPI, and Actuator routes with provenance. |
| `web/ids` | Link typed response identifiers to observed subsequent request fields. |
| `web/host-resolver` | Distinguish captured host/IP/SNI/redirect properties and generate `curl --resolve`. |
| `web/actuator-analyze` | Review captured configuration, mapping, dependency, and secret exposures. |
| `artifacts/triage` | Inspect bounded Base64/compression/archive transformations and format signatures. |
| `web/workflow-verify` | Verify a legitimate baseline before one explicitly authorized field modification. |
| `web/auth-flow-map` | Map captured OIDC, redirect, PKCE, and unverified token claims. |
| `evidence/correlate` | Correlate redacted secret fingerprints and dependency candidates. |
| `artifacts/serialization` | Link likely serialization formats and dependencies to baseline-gated review leads. |
| `evidence/hypotheses` | Preserve supporting evidence, counterevidence, and the next test for a lead. |
| `evidence/report` | Draft evidence-linked findings with validation status, impact, and remediation notes. |
| `integrations/burp-bridge` | Receive explicitly selected Burp exchanges into the private vault through an authenticated loopback listener. |
| `web/stored-xss` | Chain explicit submission, ticket ID extraction, instrumented browser proof, and delayed callback observation. |
| `integrations/callback-collector` | Collect bounded passive HTTP callbacks and correlate exact markers, methods, body hashes, and timestamps. |
| `network/vantage` | Compare local routes, DNS, TUN ownership, agent socket observations, and optional selected TCP reachability with reported host vantages. |
| `database/mssql-export` | Inventory explicit MSSQL databases using Windows NTLM and archive selected tables locally with actual/exported row counts. |

Detailed usage:

- [Discovery, content enumeration, APIs, and parameters](docs/discovery.md)
- [Authentication, sessions, headers, CORS, and profile examples](docs/assessment.md)
- [JavaScript review, report export, comparisons, and team review](docs/offline.md)
- [TLS inspection and browser snapshots](docs/platform.md)
- [Linux, tool imports, replay, injection, SOAP, and authenticated workflows](docs/capabilities.md)
- [Private request vault, correlation, artifact workbenches, and reporting](docs/evidence-workbench.md)
- [MCP tools for Copilot and other AI agents](docs/mcp.md)
- [Parameter discovery, JWT checks, selected Burp captures, and ffuf](docs/agent-assessment-tools.md)
- [Remaining validation, recommended additions, and tooling](docs/next-steps.md)
- [Architecture and module authoring](docs/architecture.md)

## Chain modules through an inventory

Every network run prints its unique output directory. Substitute that directory for
`RUN` in subsequent commands:

```bash
fieldkit run web/site-map https://app.example.test --output artifacts
fieldkit run web/header-review https://app.example.test \
  --inventory artifacts/RUN/inventory.json
fieldkit collect https://app.example.test --output artifacts
fieldkit run web/js-review --input artifacts/RUN/report.json
fieldkit run web/report-export --input artifacts/RUN/report.json --output exports
```

`--inventory` accepts an inventory or assessment report and is repeatable. Explicit
target origins still define network scope: imported URLs do not authorize new hosts.
Offline JS review, exports, comparisons, merges, and review updates do not require
network targets. Module-specific documentation covers method-aware inventory handling.

## Targets and session profiles

Targets can be hostnames, IP addresses, or HTTP(S) origins with ports. Targets must
not include paths, credentials, queries, or fragments; use `--path` for endpoints.
IPv6 supports `::1`, `[::1]:8080`, and `http://[::1]:8080`. CIDR expansion is not implemented.

```text
# targets.txt — blank lines and full-line comments are allowed
app.example.test
192.0.2.10
http://192.0.2.11:8080
```

Target lists also accept whitespace/comma-separated values. Positional targets,
`--target`, and `--targets-file` are combined and deduplicated.

Named profiles supply reusable cookies and headers without entering credentials in
command history. See [examples/profiles.example.json](examples/profiles.example.json).
Each credential-bearing profile requires explicit allowed origins. Profiles have
isolated cookie jars, and redirects remain on the current request's origin.

```bash
fieldkit run web/auth-compare https://app.example.test \
  --profiles-file profiles.json --reference-profile admin --path /account
```

`anonymous` is built in. Keep your populated profile/sequence files local; the repository
ignores `profiles.json`, `sequence.json`, and `*.local.json`. Logout sequences can revoke
the supplied server-side session. No module guesses account passwords or performs login
steps unless those requests are explicitly supplied in a sequence file.

## Common request controls

| Option | Default | Behavior |
| --- | --- | --- |
| `--scheme` | `auto` | Bare origins try HTTPS, then HTTP on a network/TLS failure. Explicit schemes take precedence. |
| `--concurrency` | `8` | Maximum simultaneous HTTP requests across profiles and targets. Individual modules may run sequentially. |
| `--rate` | `5` | Maximum request starts per second per origin; `0` disables pacing. |
| `--timeout` | `10` | Seconds per HTTP attempt, including redirects and pacing waits. |
| `--retries` | `1` | Extra GET/HEAD/OPTIONS attempts on network errors or HTTP 429/502/503/504; mutation requests are not retried. |
| `--budget` | `300` | Total run time in seconds; expiry writes an incomplete report. |
| `--max-bytes` | `5242880` | Maximum decoded bytes per HTTP response. |
| `--insecure` | off | Disable HTTPS certificate verification for lab certificates. |
| `--database` | unset | Also retain raw HTTP request/response context in an explicit private SQLite vault. |
| `--dry-run` | off | Validate inputs and save a plan without requests or external-tool execution. |

HTTP redirects are limited to five hops and the same scheme/hostname/port. Supplied
origins are the scope boundary for discovered URLs. Environment proxy settings are
ignored. TLS negotiation has its own socket timeout and uses the shared pacing and run
budget. Snapshot browser requests are routed through the shared transport; explicit
browser login uses Playwright's own transport with same-origin routing and a bounded
login wait. Nuclei uses its own rate/concurrency/timeout controls. These two transports
do not inherit the shared HTTP request scheduler. The original collector has its own
options and does not expose the new database/dry-run flags. Modules also have explicit
crawl, candidate, page, operation, or file limits.

Parameter discovery, JWT checks, and active ffuf use zero retries and do not follow
redirects. Parameter discovery needs an explicit target scheme or a fixed `--scheme`;
JWT and ffuf request scope requires explicit HTTP(S) origins. ffuf's local relay sends
target requests through the shared HTTP scheduler and TLS verification. The Burp
bridge receives selected captures without sending requests to their origins.

## Work with captured evidence

These commands inspect sanitized local examples without contacting their example hosts:

```bash
fieldkit ingest har examples/workbench/traffic.har --database artifacts/demo.sqlite \
  --user example-employee --role employee --tag shipment
fieldkit ingest actuator examples/workbench/actuator.json \
  --database artifacts/demo.sqlite --host vendor.example.test
fieldkit web routes --database artifacts/demo.sqlite --host vendor.example.test
fieldkit web ids --database artifacts/demo.sqlite --route '/shipment-jobs/{id}/export'
fieldkit inspect artifact examples/workbench/serialized-export.txt \
  --database artifacts/demo.sqlite --host vendor.example.test
fieldkit findings draft --database artifacts/demo.sqlite
```

Importing evidence grants no network scope. Replay requires explicit target origins
and request IDs. `workflow baseline --request ID` additionally requires a resource
expectation file; see [the workflow gate](docs/evidence-workbench.md#verify-a-legitimate-baseline).

## Original file collector

`web/artifacts` checks `/robots.txt`, `/.well-known/security.txt`, `/security.txt`,
`/secrets.txt`, `/sitemap.xml`, `/sitemap_index.xml`, literal `/JS`, `/JS/`, `/js/`,
`/.js`, and `/.bak`, common script/backup filenames, homepage script references, and
`.bak` suffix variants. An extension is not a wildcard: use content discovery and
custom paths for broader coverage.

```bash
fieldkit collect http://localhost:8080 --path /assets/custom.js --paths-file paths.txt
fieldkit collect http://localhost:8080 --only-custom --path /robots.txt \
  --no-discover-js --no-backups
```

Path files contain one root-relative path per line with optional full-line `#` comments.
`--no-soft-404` disables missing-page body comparison. Heuristics can miss dynamic login
or fallback pages; HTML downloads receive a review note. Collected files are saved
without executing them or modifying their content.

## Output and evidence

```text
artifacts/UNIQUE_RUN/
  report.json               # versioned findings, results, errors, and settings
  inventory.json            # endpoints for subsequent modules
  evidence/evidence-*.json  # request/response metadata and bounded body previews
  ...                       # module-specific files, screenshots, certificates, templates
```

Network reports use schema version 2; the collector also retains its per-target
`targets[].results` structure. Export/merge tools accept legacy schema version 1.
Downloaded artifacts have sanitized, hash-suffixed filenames. Files and run directories
use owner-only permissions on POSIX. Saved artifacts include byte counts and SHA-256.

Evidence redacts configured credentials, learned cookies, recognized secret patterns,
and secrets discovered later in the run. Previews are limited to 32 KiB. Redaction is
heuristic for arbitrary content. Raw downloaded files and screenshots remain original
assessment evidence and can contain sensitive information; exports reference original
artifacts instead of copying them. Preserve run directories when sharing reports with
teammates. Inventories preserve exact local URLs for chaining, including query values.
The optional SQLite vault, its `.private/` blobs, `private-request-templates.json`,
`private-session-profile.json`, and retained Linux `private-raw/` files deliberately
preserve original data and may contain credentials. They use owner-only POSIX permissions
and are not encrypted. Redacted reports are separate from these private sources.

Findings distinguish observations and review leads. Similar responses do not prove broken
access control; reflection does not prove XSS; a credential-shaped string does not prove
that a credential is valid. Record manual confirmation using `results/review`.

Network exit statuses: `0` = completed without transport/module errors, `1` = errors or
budget exhaustion, `2` = invalid input/filesystem failure, `130` = interrupted. HTTP
statuses such as 403 are ordinary observations for assessment modules; the original
collector retains its candidate HTTP-error behavior. Inspect `completed` before treating
a report as a complete scan. Local collection and vault workbenches return `1` when
coverage/import errors occur after a report has been created; invalid options return `2`.
Older offline results commands retain their existing exit behavior.

## Development

```bash
python -m pip install -e '.[dev,browser,mcp]'
python -m playwright install chromium
python -m pytest
python -m ruff check src tests
python -m ruff format --check src tests
```

Tests use local HTTP/TLS servers, mocked transports, temporary files, captured outputs,
and fake executables, never external assessment targets. Browser and real-tool integration
tests skip when their optional runtimes are unavailable. There are 49 explicitly
registered modules. The downloaded reference toolkit stays separate from Fieldkit source;
external template directories are configurable and never scanned automatically.
Lint the Fieldkit source/tests explicitly when a working checkout also contains operator
lab scripts. A whole-checkout Ruff run additionally checks those unrelated local files.

The full test suite includes Linux-specific inventory, network, process, and filesystem
checks. Run it on Linux; a full run on macOS can fail those checks. Java bridge tests
require a working Java 17+ JDK in addition to the Python development dependencies.
