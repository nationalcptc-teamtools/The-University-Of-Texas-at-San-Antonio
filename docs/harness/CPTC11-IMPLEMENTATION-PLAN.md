# CPTC11-validated competition testing toolkit

Approved by the operator on 2026-09-07. This extends APPROVED-PLAN.md and
NATIVE-TOOLS-PLAN.md; their stricter data, isolation, audit and publication
requirements remain binding. Baseline: private alpha 0.1.0a3, commit 70097d1.

## Goal and acceptance

Deliver network/TLS, web/API, Linux, Windows/AD and database assessment,
usable without AI or with the engagement's explicitly approved AI. Preserve
existing interfaces, report formats, records and regressions, including the
original 34 web tests. Software-test counts are not vulnerability coverage.

Every independently verified CPTC11 weakness must be accounted for. Every
automated-eligible weakness requires a matching result with the predicate's
required evidence. Manual-only weaknesses require cards, prerequisites,
evidence intake and retest tracking. Unsupported, inaccessible, incomplete
and missed checks stay visible. Original scenario weaknesses and subsequently
published applicable vulnerabilities are separate benchmark populations.
No claim of detecting every unknown vulnerability is permitted.

The RIT archive at http://cptc.rit.edu/cptc11/ supplies VM images and telemetry;
no explicit answer key was established. Build expected findings independently
from reviewed configuration/image evidence and bounded validation. Historical
attack telemetry is not evidence of successful exploitation. Quarantine
sensitive inputs; do not bulk import command histories or clipboard records.

## Architecture and interfaces

Approved assets/accounts -> frozen assessment plan -> bounded broker actions
-> typed observations -> deterministic detection -> evidence review ->
findings, check-level coverage and reports. AI is optional throughout.

Versioned interfaces cover component identity (full package/release/build and
provenance), check definitions (applicability, evidence, effects, limits and
references), immutable assessment waves, check results (completeness and
consumption), findings (CVE/CWE/related attack, prerequisites and review), and
external test-only benchmark entries. Retain existing single-target actions.
Migrations are additive and preserve old records, classifications and counters.

Freeze target/check/account-role assignments with policy and release hashes.
Reserve wave allowances atomically before dispatch. Give waves/actions stable
identifiers. No duplicate dispatch on retries. After interrupted dispatch,
mark uncertain and stop; do not rerun automatically. Coverage is target x
check x role, not one row per module. Absence of output is not negative proof.

## Enforcement gates

Repair durable stop across CLI, human CLI, TUI and MCP, including busy/dead
audit writers. Persist independent control intent and reconcile into the
central writer; audit failures latch stop rather than being swallowed.
Enforce target/realm/workflow/device resource budgets and recursive typed
disclosure validation at results and provider boundaries before expanding
target collection.

Separate target, provider, secret, evidence and audit processes. Pass only
reviewed inputs, necessary mounts and broker-created connection descriptors.
No AI shell, arbitrary filesystem/socket access, custom scripts, runtime tool
registration, uploads, callbacks, clipboard, email or infrastructure control.
Scope is validated before DNS and every connection; numeric endpoints are
pinned. Account for actual traffic, bytes and deadlines. Block redirects,
alternate proxies, direct sockets, telemetry, updates and unapproved browser
or WebSocket traffic. A tool that cannot be mediated remains unsupported.

Do not admit broad scanner/NSE categories. Each profile has pinned code and
dependency hashes, effects, request/runtime/output/resource bounds, synthetic
positive and negative tests, independent review and live acceptance evidence.

Credentials use opaque references bound to endpoint, realm, principal, method
and workflow. Grants are one-use, reserved before dispatch; uncertain attempts
remain consumed. Session handles never outlive workflow authorization and are
revoked on stop, expiry, rotation or uncertainty. MFA/unexpected challenges
require humans. No certificate bypass, background reauthentication, method
fallback or generic SSH/PowerShell interface. Use reviewed queries or exact
hashed collector commands. Secrets never enter argv, readable logs, ordinary
evidence or model payloads.

Keep one target operation in flight, HTTP 1 request/sec and 24 requests/app/job,
auth <=2 attempts unless stricter, and existing per-profile collection limits.
Unknown clock synchronization or offset >2 seconds blocks new target work.
The AI cannot reset counters, widen scope, approve itself or resume stops.
Device ledgers survive workspace recreation; offline handovers retain consumed
allowances and reject conflicts without claiming disconnected global locking.

## Data, audit and AI

Client-derived summaries remain confidential. Unapproved/personal AI receives
zero client data. Unknown provider tools/retention behavior allows only
public/synthetic data; no fallback provider. Exact human excerpt approvals
bind artifact/excerpt/destination hashes and byte allowance. Nested fields,
errors, URLs and repeated small transfers pass the same disclosure checks.

Encrypt raw capture before disk persistence; no AI decryption/read capability.
Quarantine unexpected secret-bearing artifacts and exclude from export;
reviewed redacted derivatives may be produced. Keep engagement data outside
Git, build-agent prompts and the general shared context vault.

Audit JSONL, readable transcript, encrypted stdout/stderr and integrity
manifests record complete permitted bytes, stream identity, policy/module/
action/approval/destination IDs, permitted command/environment metadata,
resource reservations, timings, completion, stop and uncertainty. Escape
terminal controls. One writer assigns UTC microsecond Z timestamps, persisted
sequence, monotonic duration and clock status. Independent control intents
preserve original receipt time when later reconciled. Reserve disk before
dispatch. Audit failure, full disk, permission drift, tamper or collection-cap
exhaustion stops action/work; no silent output drops. Local exports require
content, archive, recipient decryption and integrity checks; originals remain.

Preserve create_session/send/cancel/close for native API, declarative captured
requests and isolated browser transports. Never execute captured curl. Client
browser data stays blocked until login/display/network boundaries are proven.
Invalid/partial prose, duplicate actions and stale approvals cannot execute.
Use compact versioned skills/MCP; deterministic routines make zero model calls.
Keep 6 model calls, 12 model-requested actions, 1 in-flight call and 1 format
repair per approved workflow. Generate preamble from approved SOW/ROE/policy
and versioned local CPTC rules, covering exclusions/windows/confidentiality,
outside assistance, permitted resources, staging, reporting and escalation.
Discoveries and credentials never expand authorization; unknown effects and
manual-only actions cannot be launched through approvals or wrappers.

## Detection and human use

Network: bounded service/TLS/protocol evidence. Linux: exact package/distro
provenance, patch applicability, permission context, service/tasks, sudo,
SUID and capabilities. Windows/AD: build/patch supersedence, service/task ACL,
SMB/LDAP posture, domain/account policy, delegation/GPO/AD CS relationships.
Web/API: route/role coverage, sessions, controlled-account comparisons and
individually reviewed application tests. Database: approved metadata, grants,
transport and authentication posture. OT/fragile: manual evidence only.

Normal SUID presence, sticky temporary directories, root-context writable
checks and missing access must not create findings or clean conclusions.
Preserve offline Nuclei/ZAP; new rules require the full admission gate. State-
changing, injection/upload and business-logic tests need individually reviewed
known-effect profiles; unknown impact stays manual. Zerologon, spraying,
credential dumping, coercion, DoS/crash, destructive actions, domain changes
and infrastructure operations have no automated execution capability.

Prepare offline official CVE/vendor/distro/package advisory snapshots with
source, acquisition time, revision, schema, hashes and upstream signatures
where available. Refresh only in preparation without client queries. Exact
ecosystem version semantics and package/patch evidence take precedence over
banner inference. Withdrawn/conflicting/ambiguous records produce limitations.
Candidate, observed condition, human-confirmed, not-observed, unknown,
incomplete and unsupported are distinct. Version alone cannot confirm a CVE;
CWE/ATT&CK mappings are relationships, not proof of successful exploitation.
Attack relationships require evidenced prerequisites; never execute chains.

Provide guarded operator CLI/TUI and standalone human collectors/runbooks/
manual cards. Standalone procedures explain which controls humans enforce.
Prepare, doctor, plan, estimate traffic, run, stop, findings, coverage, manual
import, retest, audit verification and local encrypted export work without AI.

## Ordered packages and ownership

1. Main + named Luna planner: contracts, migrations, independent benchmark.
2. Terra worker: stop, accounting, auth, isolation, disclosure and audit.
3. Named Luna implementer: advisory matching, detection and coverage.
4. Luna collectors; Terra transport: network/Linux, Windows/AD, web/API/DB.
5. Luna: human tooling, skills/MCP, reports and packaging.
6. Independent Luna reviewer; main: integration, Dell acceptance and release.

Planner briefs precede delegated implementation. Main owns shared interfaces
and migrations. At most two writers, disjoint ownership; preserve others'
edits. Use project-only Luna/Terra exception, no global changes/substitutions.
Record requested/actual model evidence, files, tests and outcomes. Agents use
source/synthetic data only; reviewers do not approve their own changes.

## Verification and release

Each check needs vulnerable/hardened/false-positive/ambiguous/partial/access-
denied/unsupported fixtures. Test backports, Windows supersedence, wrong
products, rejected/conflicting advisories and missing prerequisites. Test
prompt injection, nested/encoded secrets, cumulative disclosure, browser
channels and final provider payloads. Test DNS/IPv6/redirect/proxy/direct socket
escapes, descriptors, auth expiry/revocation/realm binding and lockouts.
Inject crashes across reservation/dispatch/capture/completion/handover. Test
stop, clocks, full disk, permissions, tamper, log injection, truncation, export
interruption/wrong keys/unchanged originals, slow/unavailable/invalid models.
Require >=80% token reduction against frozen transcript baseline and zero
model calls in deterministic workflows.

Benchmark answers remain outside package/runtime and AI inputs. Compare
externally; changing answers cannot change runtime behavior. Use blinded
identities, hardened controls and withheld variants. Eligibility is reviewed
independently; misses cannot be hidden by moving them into manual coverage.

Dell preflight revalidates access, guest/server identity, assignment, current
usage, clock, storage, isolation and recovery safeguards. Run from approved
operator environment, never the Proxmox control host. Preserve journals,
guests, relays and active Juice Shop. No incidental reboot/reset/guest-agent/
route/infrastructure repair. Validate existing profiles, external eligible
targets, approved credentialed reads, findings/benchmark, manual/retest, then
operator/approved-AI workflows. OT remains manual; Juice Shop is supplemental.

Readiness reports separate tests, automatic detection, manual coverage, false
positives and unresolved gaps. Each supported profile needs live evidence;
unavailable access blocks the claim. Package privately with pinned offline
dependencies/advisories, runbooks, skills/MCP and verified local export. Keep
commits local; pushes and competition staging require their authorization.
