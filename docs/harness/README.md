# Guarded CPTC AI harness

This private alpha exposes a finite set of deterministic and bounded assessment
capabilities to an approved AI service. The policy broker is the only execution
path. Discovery, parsing, CVE matching, coverage, reporting, and audit
verification do not require a model call.

The `cptc` command is a trusted operator control plane. It initializes private
workspaces, displays the generated rules preamble, creates approved workflows,
applies exact inputs and approvals, stops work, reviews results, and creates
local encrypted exports. The model receives only the MCP or strict-envelope
capabilities assigned to its workflow.

## Security boundary

Classification and authorization come from the signed local policy, trusted
collectors, and operator decisions. The model cannot set scope, risk class,
approvals, disclosure class, budgets, or evidence identity. It cannot read raw
evidence or secrets, select local paths, use a shell, register tools, fetch an
arbitrary URL, upload data, or publish results.

Client-derived information remains client-confidential after redaction or
summarization. Personal and unapproved AI services receive no client-derived
data. Provider-side browsing, plugins, retention, and tool behavior must be
accepted before client facts are sent. Unknown provider behavior permits only
public or synthetic data.

Manual-only and unknown-impact actions have no broker execution path. This
includes Zerologon, spraying, credential dumping, denial of service, uncontrolled
fuzzing, domain or trust changes, service restarts, destructive database work,
infrastructure changes, and novel network-capable exploit scripts.

## Runtime flow

```text
approved policy and targets
        |
operator freezes workflow and allowances
        |
AI emits one validated action, ask_human, or finish envelope
        |
policy broker revalidates scope, disclosure, clock, budget, and module identity
        |
contained worker performs one admitted operation
        |
typed observation + encrypted raw evidence + durable UTC audit
        |
deterministic checks, findings, coverage, and reviewed export
```

Each workspace permits one target action in flight by default. The initial AI
limits are six model calls, twelve requested actions, one call in flight, and one
format-repair attempt. The model cannot increase or reset them. HTTP defaults to
one request per second and 24 requests per app job. Authentication attempts are
reserved before dispatch and remain consumed after ambiguity.

## Available alpha capabilities

- Offline typed imports for Nmap XML, network inventory, web captures, Linux,
  Windows/AD, manual result cards, and reporting records.
- One bounded HTTP metadata request for admitted `web.headers` and `web.session`
  targets.
- One-port Nmap observation through the pinned parent connection broker.
- Offline Nuclei and ZAP analysis of one operator-selected capture with reviewed
  local rules and no target network.
- Deterministic component identity, advisory matching, CVE/CWE/ATT&CK candidate
  relationships, collection limitations, findings, and check-level coverage.
- Native API, declarative captured-request, test-only isolated browser, and stdio
  MCP transports with strict typed response envelopes.

Active Nuclei/ZAP, broad Nmap/NSE, authenticated remote collection, controlled
account comparisons, database metadata collection, and automated exploitation
are not admitted in this alpha. A banner or version match is a candidate, not a
confirmed vulnerability. Missing access cannot become a clean result.

## Audit and data handling

One audit writer records RFC3339 UTC time with microseconds, monotonic time,
persisted sequence, event identity, clock status, policy and module versions,
validated parameters, reservations, dispatch, output chunks, completion,
cancellation, model usage, disclosure approvals, and export review.

Permitted stdout and stderr are preserved as encrypted raw streams within the
collection allowance. Readable logs escape terminal control characters and omit
secret values. Audit failure, insufficient storage, integrity drift, permission
drift, bad clock state, output overflow, or uncertain side effects stops new
work. Interrupted target actions become uncertain and are never automatically
retried.

Exports are local artifacts built from an exact operator-reviewed file set and
recipient-encrypted with the pinned `age` executable. The model has no export or
decryption capability. Local integrity chains are tamper-evident under a trusted
operator, not tamper-proof against a host administrator.

## Setup and validation

See [LOCAL-INSTALL.md](LOCAL-INSTALL.md). The basic operator checks are:

```sh
python3 scripts/bootstrap-harness.py --install-age
python3 -m cptc_harness doctor
python3 -m cptc_harness modules
python3 scripts/review-release-pins.py
python3 scripts/test-harness.py
```

The full test runner uses synthetic data and requires every collected test to
complete without skip, xfail, interruption, or malformed receipt. It writes a
verbose local audit, stdout/stderr streams, JUnit results, and an integrity
manifest.

Read [READINESS.md](READINESS.md) and [ACCEPTANCE.md](ACCEPTANCE.md) before
claiming profile support. The separate expected-issue benchmark is test-only and
must remain unavailable to runtime, model prompts, and target collectors.
