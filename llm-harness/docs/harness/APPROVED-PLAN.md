# Approved guarded CPTC harness plan

> **Scope update (0.1.0a5):** Human-tooling deliverables in this historical plan were removed from this repository. The guarded AI harness and trusted operator control plane remain.


Approved by the user on 2026-09-07 in task 01a07dba-16f9-75f0-8281-94410627390b.
This source-only specification records the accepted implementation request.

## Outcome

Extend this private Python 3.11+ toolkit with a CLI/TUI, deterministic core,
policy broker, provider/chat/browser adapters, MCP interface, small skills,
verbose audit, per-device durable budgets and offline team merging. Preserve
the existing web CLI, database history, reporting format and 34 baseline tests.
No absolute zero-risk or live-compatibility claim without supporting evidence.

## Authority and data boundaries

- Scope/SOW/ROE, window, target eligibility, assignment, exclusions (including
  OT/management/other teams), data policy and approvals are operator-owned.
- Only registered bounded observation/proof modules are executable by AI.
  Manual-only/unknown actions cannot become executable via approval, alias,
  wrapper, draft registration, retry or nested workflow. Zerologon, spraying,
  DoS/crash testing, uncontrolled fuzzing, infrastructure/service changes and
  uncertain production effects are manual-only. No autonomous escalation.
- No generic model shell, network, filesystem, upload, export or policy editor.
  AI only sees typed facts and exact human-selected, approved excerpts.
- Public/synthetic data may reach a preparation provider. All client-derived
  data stays local unless the client AI's exact origin, permitted categories,
  retention conditions and upstream tool containment are explicitly recorded.
  Unknown upstream browsing/plugins/uploads/tools means synthetic-only mode.
- Raw logs/evidence have no general AI read path. Credentials/cookies/tokens/
  keys stay in a broker; never argv, readable logs, prompts or export archives.
  Classification is trusted code/operator metadata, never model-supplied.
  Redaction does not declassify data. Existing ai-brief.json is confidential.
- Enforce process/filesystem/network restrictions outside the prompt. Isolate
  target workers, AI transport, audit and secrets. Mediate destinations, DNS,
  redirects, browser workers/WebSockets and subprocesses. Block unmediated tools.
  Disable telemetry, public callbacks, cloud uploads and online scanner updates.
  Permitted callback proofs require approved sinks and synthetic markers.
- Draft scripts are inert. Human review and hashing can admit only offline
  processing or existing reviewed broker operations. Novel network exploits
  require a separately tested tool release; no runtime manual-only override.

## Budgets and resilience

- One target operation and one model request in flight per workspace.
- Default HTTP 1 request/second; 24/app/job; existing 128 KiB response cap.
- Authentication disabled without an explicit method and approved allowance;
  existing two-attempt maximum or stricter policy applies, including controls.
- Six model calls, twelve model-requested actions/workflow; one format repair.
  2 KiB/excerpt, 8 KiB aggregate/decision. All cumulative/retry/pagination limits
  are reserved before dispatch and persist across restarts/chat/workspace resets.
- Modules declare timeout, request/probe, output/resource budgets and effects.
  Throttling, lockouts, instability, health thresholds, unknown outcomes or
  clock/audit failures stop relevant work. No automatic retry of uncertain work.
- Operator stop cancels queue and contained processes. AI cannot widen scope,
  reset counters, reclassify modules, alter assignments or resume stopped targets.
- Independent workspaces use exclusive target/auth-realm assignments, a durable
  device ledger and explicit handovers. Offline merging detects conflicts and
  preserves spent allowances; it is not real-time distributed coordination.

## Provider and interface requirements

- Shared versioned policy/provider/module/action/result/approval/audit contracts.
- create_session/send/cancel/close for OpenAI-compatible API, declarative local
  chat request captures and isolated Playwright browser sessions. Support JSON,
  SSE and NDJSON. Never execute captured curl; credentials stay local.
- Dedicated browser login/renewal is human-operated. Unknown formats fail closed.
- Without native tools, strict action/ask-human/finish envelopes; no partial
  stream or prose execution. No fallback to another provider with client data.
- CLI/TUI and stdio MCP use the same broker; third-party capabilities are pinned
  and allowlisted. MCP descriptions/content cannot authorize operations.
- Deterministic scans/import/parsing/dedup/coverage/report assembly use zero AI
  calls. Send state deltas/relevant schemas, never full verbose logs to models.
- Generate compact system preamble from the active policy and versioned complete
  CPTC rule reference: authorization, SOW/ROE, exclusions, time, outside help,
  public resources/repository staging, confidentiality, reporting/escalation and
  manual-only constraints. Unsupported claims remain unknown.

## Mandatory verbose audit

- Local audit.jsonl and transcript.log, per-action stdout/stderr/raw artifacts,
  integrity manifest. No central online collector. Offline merge at review time.
- Log identities, tool version/hash, validated arguments/command/cwd/permitted
  environment metadata, approvals/denials/reasons, budgets, process/network
  activity, outputs, exits, timings, stop/uncertain outcomes, model metadata and
  policy-safe messages, disclosures, assignments, manual imports and exports.
- No auth payloads/private chain-of-thought. Secret references replace secrets.
  Unexpected sensitive output is human-only restricted raw capture; readable
  logs escape terminal control characters and redact secrets. Preserve stream
  identity/raw bytes within declared limits; never silently discard output.
- One writer/time service/workspace: RFC3339 UTC microseconds Z, monotonic time,
  persistent sequence, unique IDs, source device, sync state/offset. Existing
  clock sync must be known and <=2 sec offset for active work. Do not change
  clocks or contact arbitrary NTP servers. Offline parsing/export still works.
- Persist intents/reservations before dispatch; fsync checkpoints; reserve output
  space; fail closed on integrity/permission/storage failure. Interrupted work
  is uncertain. Rotation uses immutable closed segments and chained manifests;
  tamper-evident under trusted-host assumptions, not root-proof.
- Raw client output requires verified approved encrypted volume or streaming
  file encryption before persistence. AI never accesses decryption keys.
- Human-only close/export creates reviewed local bundle; optional age recipient
  encryption, manifest and decrypt/integrity verification. No uploads, deletion,
  implicit approved destination or claims about remote retention deletion.

## Tool tracks

- Network: bounded Nmap execution/import, service inventory, TLS/protocol facts.
- Web: existing baseline/default-login checks, session and controlled-account
  authorization comparisons, reviewed Nuclei rules, constrained ZAP workflows.
- Linux: structured identity/permissions/services/tasks/sudo/SUID/capabilities.
- Windows/AD: identity/domain inventory, service/task ACLs, SMB/LDAP observations,
  controlled-account checks. No destructive or uncertain automated tests.
- Exploitation: bounded admitted proofs, manual-only cards and result intake.
- Reporting: evidence-backed findings, owner/coverage/dedup/retest/offline merge.
  Unsupported cases stay visible; scanner candidates do not prove exploitation.

## Implementation and test gates

1. Freeze contracts; implement policy/audit/budgets and compatible migration.
2. Prove OS isolation and manual-only enforcement before target execution.
3. Providers, CLI/TUI, MCP, skills and preamble.
4. All-track fixtures/tools/reporting and independent adversarial review.
5. Validate eligible profiles on Dell CPTC11 plus Juice Shop, after current
   access/isolation/identity/usage/recovery preflight. Preserve Dell journals
   and active Juice Shop. Disruptive tests remain manual even in the lab.
6. Package and close/export proof. No live compatibility claim for missing lab
   acceptance. No Git push/publish without separate explicit authorization.

Test scope: old records/regressions; malicious tool/policy/prompt inputs; manual
aliases/wrappers/scripts; exfil through query/header/body/log/errors/browser/WS/
callbacks/chunking; upstream tools unknown; DNS/redirect/IPv6/path/fd/process
escapes; scanner defaults; cumulative budgets and handover conflicts; stop and
health events; UTC/skew/clock jumps/output/order/crash/disk/permissions/tamper;
encrypted export interruption/wrong-key/source preservation; vulnerable versus
hardened/false-positive/unsupported fixtures; weak/slow model invalid formats;
token comparison against transcript-heavy baseline with full human audit.

## Build agents

Named Luna planner xhigh before delegated work; Terra workers high own policy,
isolation, budgets, audit, providers; named Luna implementer high owns bounded
adapters/skills/tests/UI; named Luna reviewer high is independent. Main owns
contracts/migration/dependencies/integration/acceptance. Maximum two writers with
disjoint ownership; preserve others' edits. Compact briefs, explicit tests and
stops, no live data/credentials in agent prompts. Record actual/requested model
and results. Missing models pause, never substitute. Project-only preference;
do not change global settings or the competition provider.
