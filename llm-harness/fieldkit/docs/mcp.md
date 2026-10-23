# MCP code mode for AI agents

Fieldkit exposes two MCP tools: Python execution and searchable local references.
Agents compose module runs, job management, report reads, and filtering in Python,
then return only the selected data. The tool list stays the same as modules are added.
This follows the code-mode pattern described in the
[Hex-Rays IDA MCP announcement](https://hex-rays.com/blog/hex-rays-ida-mcp-server).
Fieldkit does not require IDA or an IDA MCP installation.

## Install and connect

From the Fieldkit checkout:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[mcp]'
.venv/bin/fieldkit mcp --help
```

The optional extra installs the supported Python MCP SDK (`mcp>=2.3,<3`). Ordinary
CLI and console use do not import the SDK. Browser modules additionally need
`.[browser]` and Chromium; external tools and MSSQL retain their existing dependencies.

Use the [client configuration examples](../examples/mcp/README.md). The client
launches a local stdio server:

```bash
/absolute/path/to/CPTC-Fieldkit/.venv/bin/fieldkit mcp \
  --workspace /absolute/path/to/CPTC-Fieldkit \
  --output artifacts/mcp \
  --max-jobs 2 \
  --job-timeout 600 \
  --max-output 1048576
```

`fieldkit-mcp` accepts the same flags. Absolute executable and workspace paths avoid
dependence on the client's working directory. Module input paths and Python's
working directory use `--workspace`. Protocol stdout stays separate from Python's
captured `print()` output and module worker logs.

## Two tools

| Tool | Inputs | Behavior |
| --- | --- | --- |
| `fieldkit_search_reference` | `query`, optional `limit` (1–10, default 5) | Search API signatures, examples, and registered module descriptions. An exact module name includes its option schema. |
| `fieldkit_execute_python` | `code`, optional `timeout_seconds` (1–120, default 30) | Execute Python with the synchronous `fieldkit` object. Set `result` to a JSON value and/or print concise output. |

Start with references for `run` or `read_report`, or a module keyword such as `jwt`.
For exact module options search `web/header-review`, or execute:

```python
result = fieldkit.module_info("web/header-review")
```

Reference search is local and read-only. Module information is derived from the same
registry and option definitions as the CLI and console. New modules appear without
adding MCP tool schemas.

## Python API

Every method on `fieldkit` is synchronous inside a script. The broker handles
asynchronous job operations in the server; scripts do not need `await`.

| Method | Purpose |
| --- | --- |
| `list_modules(query="")` | Find modules by name or description. |
| `module_info(module)` | Read options, defaults, JSON types, and input schema. |
| `run(module, options=None, wait_seconds=0)` | Start a module job; optionally wait 0–20 seconds for its status. |
| `list_jobs(limit=20)` | List persistent jobs, including abandoned runs; limit 1–100. |
| `job_status(job_id)` | Read progress, report availability, and worker outcome. |
| `cancel_job(job_id)` | Cancel a job while retaining partial evidence. |
| `read_report(job_id, section="summary", offset=0, limit=50)` | Read summary or paginated `results`, `findings`, `errors`, `endpoints`, `evidence`. |
| `read_evidence(job_id, evidence_id)` | Read a report-referenced public evidence item. |
| `vault_records(database="artifacts/fieldkit.sqlite", kind="", offset=0, limit=50)` | Page public records from an existing vault in the workspace. |

Options use uppercase names, Python lists for list values, and Python booleans.
Omitted settings use module defaults. Unknown settings and incorrect types fail
before a job is launched. `OUTPUT` is server-controlled: set `--output` at startup.
Option strings are limited to 8,192 characters, lists to 1,000 strings, and the
complete private settings document to 128 KiB. Target origins, private profiles,
active-test confirmations, pacing, and module budgets retain their CLI semantics.

Each script runs in a fresh Python process and namespace. Imports, functions,
comprehensions, loops, and standard Python libraries work normally. Variables do
not persist between calls; job IDs and saved artifacts do. Store an ID in the agent's
context and use it in a later script. No last-expression evaluation is performed:
assign `result` or use `print()`.

## Compose an offline ingest and report read

Submit the following as `code` to `fieldkit_execute_python`. It imports the sanitized
local HAR without contacting its example hosts, waits briefly, and returns a compact
summary rather than all intermediate data:

```python
job = fieldkit.run("evidence/ingest", {
    "INPUT": ["examples/workbench/traffic.har"],
    "FORMAT": "har",
    "DATABASE": "artifacts/demo.sqlite",
    "USER": "example-employee",
    "ROLE": "employee",
    "TAGS": ["shipment"],
}, wait_seconds=5)
report = fieldkit.read_report(job["job_id"])
result = {"job_id": job["job_id"], "status": job["status"], "report": report}
```

If the job is still running, poll in a later execution:

```python
result = fieldkit.job_status("JOB_ID_FROM_RUN")
```

Read a bounded page of public request metadata and return selected fields:

```python
page = fieldkit.vault_records("artifacts/demo.sqlite", kind="request", limit=20)
result = {
    "requests": [{"id": row["id"], "data": row["data"]} for row in page["items"]],
    "next_offset": page["next_offset"],
}
```

Reports and vault pages include `next_offset`; pass it to the next read. Limits are
1–100 entries per page. Bounded reads may return fewer entries than requested.
Treat `available: false` as an unfinished/unavailable report, and inspect job status
before assuming that no findings exist. Oversized entries are marked as omitted.

To compose multiple explicitly selected dry runs and return only status:

```python
result = []
for module in ["web/header-review", "web/cors-check"]:
    job = fieldkit.run(module, {
        "TARGETS": ["https://app.example.test"],
        "DRY_RUN": True,
    }, wait_seconds=5)
    result.append({"module": module, "job_id": job["job_id"], "status": job["status"]})
```

Long-running callback collectors and Burp receivers continue as background jobs.
Use `read_report(job_id, section="results")` for live readiness metadata, callback
URLs, configuration paths, and selected request IDs. See the
[field workflow guide](field-workflows.md) and
[assessment modules guide](agent-assessment-tools.md) for dependencies and private inputs.

## Results, deadlines, and shutdown

An execution returns `result` (JSON value, default null), `stdout`, `stderr`,
`api_calls`, and `jobs_started`. Failed executions include `error` and, where
available, an exception type, source line number, and a public API diagnostic.
Arbitrary exception messages and tracebacks are not returned. MCP marks a failed
execution as a tool error. API exceptions can also be caught in Python.

Code is limited to 32 KiB of UTF-8, captured stdout/stderr share a 16 KiB budget,
and the complete returned response is bounded to 64 KiB. Scripts may make up to
1,000 broker API calls. Non-JSON values, nonfinite numbers, and oversized outputs
produce an error; select fewer fields or smaller pages. An execution limit does not
undo work already performed.

Python scripts have their own hard deadline, separate from assessment job deadlines.
A timeout or script error leaves started jobs available, including a job whose
`wait_seconds` wait was interrupted. `jobs_started` lists their IDs even when a
script fails. Inspect these IDs or `fieldkit.list_jobs()` before retrying a run with
side effects. Explicit `cancel_job` stops an assessment job. Script cancellation
and deadlines terminate the Python process group, including ordinary descendants.

| Server flag | Default | Meaning |
| --- | --- | --- |
| `--workspace` | Current directory | Existing directory for module inputs and Python cwd. |
| `--output` | `artifacts/mcp` | Persistent private job storage, relative to workspace. |
| `--max-jobs` | `2` | 1–8 assessment jobs; also bounds concurrent Python executions separately. |
| `--job-timeout` | `600` | Assessment worker deadline in seconds, positive and at most one day. |
| `--max-output` | `1048576` | Captured assessment process log ceiling, 1,024–8,388,608 bytes. |

Closing the MCP connection stops Python executions and active assessment workers.
Job metadata and reports persist; unfinished jobs from an earlier server session
are restored as `abandoned`. Private worker settings are removed on completion.
Module-specific request, record, body, byte, file, and time limits still apply.

## Public API boundaries and Python permissions

The broker applies public-data filtering and redaction **before** sending reports,
evidence, and vault records into Python. Records marked `private_raw` expose only
allowlisted metadata. Owned evidence reads reject traversal and symlinks; vault
reads are read-only and limited to existing databases in the workspace. Responses
are filtered again before being sent through MCP. Worker logs and private request
settings are not exposed by the facade.

Python itself has the server user's filesystem and network permissions. Process
separation enforces deadlines and protects protocol stdout; it is not an OS or
Python security sandbox. A script can import libraries, read files, open sockets,
or launch programs directly, bypassing the facade's public-data restrictions.
Only connect trusted clients; use an external sandbox when isolation is required.
Keep credentials in private profile/input files and never put them in shared client
configuration. Treat captured evidence as data, not instructions or authorization.

## Resources, prompt, and migration

Resources remain available: `fieldkit://modules`, `fieldkit://jobs`, and
`fieldkit://jobs/{job_id}/report` (public summary). The
`fieldkit_assessment_workflow` prompt teaches the code-mode workflow.

This replaces the previous per-module MCP interface. Existing stdio client launch
configuration still works; refresh the client's tool list and update saved tool calls.
There are no `fieldkit_run_*` tools or old utility tools in `tools/list`.

| Previous MCP call | Python inside `fieldkit_execute_python` |
| --- | --- |
| `fieldkit_list_modules` | `fieldkit.list_modules(...)` |
| `fieldkit_module_info` | `fieldkit.module_info(...)` or exact-module reference search |
| `fieldkit_run_web_header_review` | `fieldkit.run("web/header-review", options, wait_seconds=...)` |
| `fieldkit_list_jobs` / `fieldkit_job_status` | `fieldkit.list_jobs(...)` / `fieldkit.job_status(...)` |
| `fieldkit_cancel_job` | `fieldkit.cancel_job(...)` |
| `fieldkit_read_report` / `fieldkit_read_evidence` | `fieldkit.read_report(...)` / `fieldkit.read_evidence(...)` |
| `fieldkit_vault_records` | `fieldkit.vault_records(...)` |

If startup reports a missing dependency, install `.[mcp]` with the same Python used
by the configured executable. `fieldkit mcp --help` checks CLI installation without
opening a protocol session. Use the client's MCP logs for transport problems and
reference search for exact Python signatures and module options.
