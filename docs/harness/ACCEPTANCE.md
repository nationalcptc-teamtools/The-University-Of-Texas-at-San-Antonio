# Acceptance status — private alpha 0.1.0a2

The approved plan is implemented in part. The enforcement foundation and the
listed fixture-tested interfaces are available for private evaluation. The full
competition release gate is **not met**, and no active profile is live-accepted.
Do not describe this artifact as safe for arbitrary client testing or as having
zero exfiltration/disruption risk.

## Verified locally

The test suite uses synthetic data, private temporary storage and loopback
servers. It includes real bubblewrap workers, real age encryption/decryption,
real Chromium with user cgroup limits, the stdio MCP protocol and the isolated
signing/secret/audit processes. Dependency and executable versions are recorded
in `RELEASE-ENVIRONMENT.json` and `cptc_harness/resources/release-integrity.json`.
Only Linux x86_64 / Python 3.14.7 was exercised; the language target remains
Python 3.11+ and other supported-version runs are still required.

| Area | Evidence in tests | Limits of that evidence |
|---|---|---|
| Legacy behavior | Original 34 web tests; migration row/history/backup repeatability | Migration requires operator-verified encrypted storage |
| Broker | Unknown fields/handlers/aliases, manual-only denial, target/clock/window/profile/SOW/ROE gates | Static admitted modules only; no arbitrary tool safety claim |
| Scope and HTTP | CIDR/hostname exclusion, DNS answer validation, URL path/header restrictions, real numeric loopback connection and rate persistence | No live profile acceptance; no scanner-wide DNS/redirect mediation claim |
| Ledger | Cumulative reservations, replay, exclusive realm/target, copied workspace, persistent stop, combined handover limits, source seal and multi-hop consumption | Disconnected devices need exclusive assignments; no global live coordinator |
| AI transport | Native JSON, complete SSE, template allowlist, disclosure categories, signed capability nonce/expiry, secret reference binding/reflection denial, slow cancellation | Actual competition provider and retention/tool guarantees unverified; no client API live acceptance |
| Browser | Real isolated Chromium and proxy, route/method/body caps, hash drift, manual-login refusal | Synthetic/public only; full malicious-browser/WS flood corpus incomplete |
| MCP | Actual initialize/list-tools/list-resources, two tools only, twelve-action budget, denied unknown action | Synthetic-only; stdio recipient identity cannot authorize client disclosure |
| Audit | Complete bounded bytes, stream identity, UTC/sequence/hash chain, secret-key redaction, overflow, allocation failure, tampering, permission drift, every rotation checkpoint and persistent failure markers | Simulated disk failures/crashes; not hardware power-cut validation or administrator resistance |
| Isolation | No home reads, pins, closed descriptors, no ambient environment, process denial, resource/output caps; actual attempted native passive egress denied | Host administrator remains outside the boundary; profiles are narrowly admitted |
| Exports / timelines | Exact reviewed file set, age encrypt/decrypt, wrong-key rejection, source preservation, modified-input rejection, signed merge, source audit-chain verification | Encrypted local export only; interruption corpus not exhaustive; no uploads |
| Imports / reporting | Vulnerable/hardened/malformed/unsupported fixtures across tracks, typed values, scope checks, deduplication, candidate states, reviewed evidence linkage, forged/missing result stops | Not every requested scanner/proof has a supported profile; Windows collector not executed |
| Efficiency | Fixed 24-observation/6-turn benchmark, 40,752 baseline vs 4,644 compact input tokens, 43,398 stdout bytes retained | 88.6% fewer fixture input tokens; zero real model calls; not a provider billing claim |

The independent Luna reviewer reported concrete enforcement and integrity
findings throughout implementation. Main integrated fixes and targeted regression
tests. `BUILD-AGENTS.json` records requested roles/models and outcomes. The
collaboration API does not expose provider-reported actual model identity, so
that field remains null rather than inferring it from the request.

## Native and human continuation

The standalone human CLI and local collection kit are implemented. Native
Nmap now has real one-connect IPv4 open/refused fixtures through AF_UNIX,
preflight/pin/scope refusal, duplicate request denial, bounded output, stop and
cleanup uncertainty tests. A full Runtime test verifies encrypted auditing,
exactly one spent probe and persistent budget denial of a second request.

Nuclei and ZAP run offline in a networkless worker. Vulnerable, hardened,
incomplete, malformed and unknown-rule fixtures are tested. Nuclei must emit
its processing receipt; an empty stream fails. ZAP requires one exact site and
eight reviewed rule IDs. A real synthetic scanner tries to connect to a host
listener and is denied. Java's runtime/configuration closure is pinned and a
mutation test fails admission. Raw stdout/stderr retain stream identity and
are encrypted by the real audit writer. Neither passive module sends a target
request or makes a model call.

The native/human independent review identified a silent Nuclei skip, permissive
report shapes, missing egress evidence, incomplete Java pins, delayed admission
stop handling and a cleanup-stop edge. These were fixed with explicit regressions.
Final review found no remaining blocker in the exercised changes; live acceptance
and broader profiles are not implied. Exact counts are in RELEASE-STATUS.json.

## Explicitly outstanding work

1. Complete live acceptance for the one-port Nmap and HTTP observation profiles.
   IPv6 native Nmap and broader discovery/probe modes remain unadmitted.
2. Any future active Nuclei/ZAP profile needs separate reviewed effects, budgets
   and containment. Their original active registry IDs remain unsupported.
3. Admit remote Linux and Windows/AD collectors, authenticated session handling,
   controlled-account comparisons and more complete TLS/protocol observations.
   Run the PowerShell collection aid on an appropriate isolated Windows fixture.
4. Review any future automated proof profile separately, with exact prerequisites,
   effects, traffic/output/time limits and fixture evidence. None is admitted now.
   Manual-only operations, including Zerologon, remain manual even in the lab.
5. Prove an isolated teammate-operated browser display/login flow and recipient-
   bound MCP transport before permitting client data through either interface.
6. Complete provider end-to-end acceptance with the actual approved service,
   current retention/tools conditions and a trusted signed capability gateway.
   Do not turn a local profile flag into a claim about upstream behavior.
7. Expand the adversarial matrix for browser WebSockets/floods, all network
   transports, every future native scanner default, export interruption and
   crash/power-loss behaviors. Existing tests do not prove these unimplemented
   profiles or every hypothetical channel safe.
8. Complete Dell CPTC11 and Juice Shop live acceptance for every claimed active
   profile. Current work reached read-only access/recovery preflight for Dell;
   target identity, exclusive current use, isolation, approved target profiles and
   action evidence remain outstanding. A subsequent operator preflight located
   the correct Juice Shop guest, verified its Docker identity and health, and
   received HTTP 200 for two bounded checks from this workstation. Its private
   route is available; the prior address belonged to a different deployment.
   This is access/health evidence, not active-profile acceptance. Raw records
   remain in restricted encrypted local storage. Existing services and lifecycle
   journals were preserved.

Before each live check, record the authorized target tuple, verified guest
identity, usage/exclusive assignment, current recovery safeguards, protected
evidence storage, clock state, permitted operating window and exact reviewed
module profile. Run only admitted observations. Preserve the evidence and
compare the actual result with the fixture expectation; do not substitute a
successful connection for acceptance. No automated disruptive tests are allowed.

## Release and publication gate

The private wheel/source archive are evaluation artifacts. A competition release
requires the outstanding implementation, passing full local tests, independent
review with resolved blockers, and live evidence for each claimed supported
profile. Disabled capabilities stay visible in coverage. Do not upgrade status
merely because a package builds or a test run passes.

No public or private remote push is authorized by this build request. Commits stay
local. Any later competition publication also needs the approved CPTC staging
process and current event rules. Client inventories, raw outputs, credentials,
engagement logs and provider sessions must not enter this repository or its
build-agent context.
