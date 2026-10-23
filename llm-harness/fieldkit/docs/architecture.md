# Architecture and module authoring

Fieldkit has one module registry and three interfaces: `argparse` commands, a
`prompt_toolkit` console, and an optional stdio MCP server. Option metadata supplies
CLI flags, console settings, Python API option schemas, help text, types, and defaults.
The interfaces run the same module code.

```text
src/fieldkit/
  cli.py, console.py         command routing and interactive terminal UI
  mcp_server.py              two-tool code-mode protocol, resources, and workflow prompt
  code_worker.py             fresh Python namespace and synchronous broker facade
  agent_worker.py            private-config worker executing the same module contract
  registry.py               explicit built-in registration
  core/
    module.py               Module / Option contracts
    assessment.py           NetworkModule / AssessmentContext runtime
    http.py                 HTTP transport and shared request controls
    targets.py, urls.py      target parsing and origin boundaries
    profiles.py             origin-bound session profiles
    redaction.py            evidence/export credential redaction
    storage.py              private run directories and artifact files
    results.py              stable IDs, normalization, merge, diff, review
    local.py                LocalModule / LocalContext host and passive run lifecycle
    process.py              bounded argv-only external process runner
    agent.py                registry-derived options, persistent jobs, public reads
    code_api.py             Python facade signatures and searchable API/module references
    codemode.py             bounded Python subprocesses and shared API broker
    xml.py                  bounded XML validation without entity/resource loading
    replay.py, workflows.py request formats, field edits, extraction/substitution
    vault.py, ingest.py      explicitly opened private SQLite graph and local imports
    correlation.py          passive route/ID/configuration/format/token helpers
    burp.py, jwt.py          selected loopback captures and bounded token verification
  modules/                  web, Linux, network-import, evidence, and results modules
```

## Add a network module

```python
from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule
from fieldkit.core.module import Option


class Example(NetworkModule):
    name = "web/example"
    description = "Example endpoint observation."
    options = COMMON_OPTIONS + (Option("EXPECTED", int, 200, "Expected status code", "--expected"),)

    def validate(self, settings):
        if not 100 <= settings["EXPECTED"] <= 599:
            raise ValueError("EXPECTED must be an HTTP status code")

    async def assess(self, ctx):
        for url in ctx.seed_urls():
            response = await ctx.fetch(url)
            ctx.add_endpoint(url, status=response.status)
            ctx.report["results"].append({"url": url, "status": response.status})
            if response.status and response.status != ctx.settings["EXPECTED"]:
                ctx.finding(
                    "unexpected_status",
                    "Review response status",
                    url,
                    confidence="observed",
                    evidence=[response.evidence_id],
                    status=response.status,
                )
```

Import and instantiate the module in `registry.modules()`. It becomes available to
`fieldkit run web/example` and `use web/example` automatically. List flags replace
list defaults when supplied; boolean flags support `--no-<flag>`. Module imports
must not perform network requests or filesystem writes.

`NetworkModule.run()` validates common settings, loads profiles/inventories, creates
a run directory, opens an assessment context, selects target schemes, and calls
`assess()`. It persists reports on normal completion, interruption, or time-budget
expiry. Use `ValueError` for invalid options and `OSError` for filesystem failures;
the interfaces render them without a traceback. Add behavior tests for new modules.

For local-only tools, subclass `Module` and implement `run(settings, console)`, or use
`LocalModule` for schema-v2 reports, host/resource identities, evidence, deadlines,
coverage, cancellation, and partial-result persistence.
Modules that mix local analysis and optional scoped HTTP can subclass `NetworkModule`
and set `requires_targets = False`, as `JSReview` does. Linux tools can follow the
same contracts without making HTTP requests. `LocalContext.command()` delegates to
the bounded process runner. Filesystem collectors use child processes so blocking
reads remain within a deadline; roots and imported paths are explicit.

## Assessment context

- `ctx.targets`: selected target origins, with scheme and port.
- `ctx.seed_urls()`: custom paths and imported endpoint URLs, falling back to origins.
- `ctx.imported_endpoints`: scoped records including methods and parameter metadata.
- `ctx.resolve(reference, base)` / `ctx.in_scope(url)`: validate discovered URLs.
- `await ctx.fetch(url, method="GET", profile=None, headers=None, data=None,
  follow_redirects=True)`: shared transport with evidence capture. Methods with side
  effects must be deliberately selected by a module; discovery does not submit forms.
- `ctx.session(name)`: isolated HTTP client/cookie jar for a named profile.
- `await ctx.clone_profile(source, name)`: copy profile settings and current cookies.
- `ctx.add_endpoint(url, method="GET", **metadata)`: upsert a scoped inventory record.
- `ctx.finding(kind, title, url, severity="info", confidence="review", evidence=[],
  **details)`: add a stable, deduplicated observation.
- `ctx.report`: `results`, `findings`, `endpoints`, `errors`, and evidence references.
- `ctx.store.root`: private run directory. Use `write_private()` for sidecars.
- `ctx.secrets`: known secret values; additions are redacted from final reports and
  evidence, including evidence captured earlier in the run. Never emit these values.

A transport error is a `FetchResult` with `error` set and is recorded automatically.
HTTP error statuses remain available for module-specific interpretation. The fetcher
has a decoded-size cap, request timeout, same-origin redirect cap, rate limiter, and
bounded retries for GET/HEAD/OPTIONS only. All profile clients share a semaphore and
per-origin pacing state. The context applies a separate total run budget.

Fetch results expose raw headers/bodies only in memory for analysis. Evidence stores
redacted request headers, original method/body, status, redirect history, hashes, and
a bounded text preview. It is re-redacted at finish after any newly discovered secrets.
Modules that deliberately save raw files must document that those files can contain
sensitive assessment data. Screenshots are original visual evidence.

## Reports and compatibility

Schema version 2 includes `module`, `started_at`, `finished_at`, `completed`, `settings`,
`target_origins`, `results`, `findings`, `endpoints`, `errors`, and `evidence`.
`inventory.json` contains endpoint metadata for chaining. The collector preserves
legacy `targets[].results` and download metadata alongside common top-level collections.

Stable identities describe an observation's location; content changes are compared
separately. Result normalization imports schema v1. Exported reports retain original
artifact roots, and merged reports namespace evidence IDs to avoid collisions.
Review history and conflicting teammate observations are preserved rather than resolved
automatically. See [offline tooling](offline.md) for those APIs and path semantics.

The registry explicitly registers 45 modules; merely placing code on disk does not load
a plugin. There is no external plugin loader. The console is a command-oriented TUI.
CLI aliases select existing modules, preserving the same option metadata and execution
contracts. MCP additionally manages bounded worker jobs for asynchronous agent calls.

## External processes and private evidence graph

`run_process()` takes argv, never a shell string. It bounds combined stdout/stderr,
streams complete records to callbacks, tracks reason/exit code/elapsed/bytes, and kills
the POSIX process group on timeout, output limit, cancellation, or callback failure.
Partial evidence survives cancellation through a caller-owned `ProcessResult`. HTTP
controls do not govern subprocess traffic; adapters must configure their tool's controls.
The ffuf adapter additionally confines tool traffic to a temporary loopback relay:
the relay reconstructs the selected target request and sends it through Fieldkit's
shared HTTP transport, keeping response bytes, TLS, session profiles, request counts,
and scope under that transport's controls.

`Vault` opens SQLite only on explicit construction; imports have no filesystem/network
side effects. Schema-v1 records store public/private JSON, source/timestamps, and typed
links. Raw blobs are content-addressed under `DATABASE.private/`. Vault schema versions
are independent of assessment report schema versions. Public reads redact data, while
private requests/responses retain replay context. Both database and blobs use owner-only
POSIX permissions and are not encrypted. Never treat the public representation as a
lossless replay source.

Passive workbenches use `LocalModule`. They preserve provenance for routes, typed ID
reuse, configuration/secret/dependency candidates, auth-flow observations, and artifact
transformations. No inspection helper executes/deserializes supplied artifacts. HTTP
workflow verification records resource-specific baseline success before a single
explicitly confirmed field change; serialization hypotheses link to that gate.

`NetworkModule` additionally accepts opt-in raw exchange capture via `DATABASE` and
an input-validation `DRY_RUN` plan with zero requests/tool execution. Dry-run is not a
connectivity or application-permission test. Nuclei and browser login have separate
transport contracts; snapshot retains its restricted browser routing. See
[capabilities](capabilities.md) and [evidence workbenches](evidence-workbench.md).

## MCP code-mode adapter

The optional MCP SDK is imported only when starting the server. It advertises two
stable tools: `fieldkit_execute_python` and `fieldkit_search_reference`. New modules
extend the registry-backed Python API and reference catalog without increasing the
MCP tool list. Exact module reference searches retrieve typed options on demand.

Each execution gets a fresh Python subprocess in the workspace with a synchronous
`fieldkit` facade. A private stdio JSON broker routes supported API calls back to the
same `FieldkitAgent` that owns persistent jobs. Scripts can compose calls, loops,
imports, and filtering, then return a JSON `result` and captured print output. Only
selected output reaches the client; intermediate API results remain in the script.
Python variables are local to one call; jobs and saved reports persist across calls.

The broker validates method signatures, derives module option validation from the
registry, and filters public data before sending it into the script. Assessment
runs still use argv-only workers and private settings files, preserving module
scope, pacing, profiles, confirmations, and report behavior. `OUTPUT` remains
server-controlled. Script failures and deadlines retain started job IDs and do not
roll back side effects or stop background assessments.

Python execution has a 1–120 second deadline, process-group cleanup, 32 KiB source,
16 KiB captured output, a 64 KiB response ceiling, and a 1,000-call broker budget.
Concurrent Python calls and assessment jobs are separately bounded by `--max-jobs`.
Closing the transport stops both kinds of worker. Assessment job metadata survives
restart; interrupted saved jobs are restored as abandoned.

This process boundary is not a security sandbox. Python retains the server user's
filesystem and network permissions and can bypass the facade through direct imports
and I/O. Facade report/evidence reads provide bounded redacted data, and facade vault
reads are read-only and workspace-limited. External sandboxing is required to restrict
arbitrary Python. Resources and the workflow prompt remain available over local
stdio. See [the MCP interface](mcp.md) for examples, migration, and public-data limits.
The optional server extra supports SDK `>=2.3,<3`; CLI/console startup does not
import the SDK.
