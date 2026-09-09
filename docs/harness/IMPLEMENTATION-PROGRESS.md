# CPTC11 implementation progress

Plan: CPTC11-IMPLEMENTATION-PLAN.md. Baseline: 70097d1 / private 0.1.0a3.
Started 2026-09-07; continuation 2026-09-08. This remains a development alpha; full CPTC11 implementation and live acceptance
are incomplete. READINESS.md is the current release gate summary.

## Implemented and independently reviewed

- Additive assessment contracts, frozen reference hashes, exact wave/item/action
  result binding and integrity-linked human review metadata. Legacy v1 operation
  contracts and historical meaning remain unchanged.
- External benchmark comparator with independent expected answers, original
  scenario/later advisory populations, negative controls, exact manual-result
  identity, scope/deployment provenance and captured evidence links. Empty or
  incomplete catalogs cannot pass. No reviewed CPTC11 answer catalog exists yet.
- Durable stop sentinel/queue shared by operator CLI, TUI and MCP. Stop survives a
  busy/unavailable writer and reconciles centrally after recovery. Allowlisted
  reason codes are persisted. Audit failures latch a stop.
- Recursive final-provider schema checks and explicit denial of untyped client
  facts even under fixture aliases. Exact approved excerpts remain text only.
- Finite offline detector with component-specific results, exact product aliases,
  source-action/evidence hash matching, explicit incomplete/unknown states and
  corrected Samba/CWE relationship. No automatic exploit confirmation.
- Offline normalized advisory catalog and Debian/RPM/SemVer/Windows comparators.
  Independent review found ordering/identity issues; main corrections have
  focused tests and independent re-review. This cache is not yet integrated
  with collection or admitted as comprehensive CVE coverage.
- Reports preserve legacy observations and add detections, evidence index and
  check-level coverage. Unsupported platform capabilities remain visible.
- Human `checks`, `findings` and `gaps` commands and competition runbook. New web
  metadata captures bind header assertions to the exact encrypted metadata.
- Compact production harness skill updated; no client-data MCP admission added.

- Atomic engagement/device/workspace/workflow/target/realm reservations across
  all six counters. Existing stricter ceilings persist across restart; model
  charges retain workspace identity. Historical charges are backfilled before
  new admission, and unknown legacy authentication attribution blocks new auth.
- Frozen operator observation waves, ordered single-use claims, runtime/broker
  integration, plan/hash/role binding, complete receipt checks and conservative
  recovery. Partial reservations roll back atomically. Real encrypted-audit
  loopback tests exercise paced requests and no duplicate traffic after restart.
- Linux collector provenance now reaches the typed detector, includes the
  finite critical paths and rejects symlink mode as evidence of permissions.

## Verification so far

- Historical pre-split 34-test web operator suite: passed before removal; it is preserved in Git history and the separate local human-tool archive, not in alpha 0.1.0a5.
- Final full synthetic suite: 757 passed with complete capture, no collection
  problems, and no unexpected reports. It includes active and queued
  reservation recovery, scanner-contract, relay, mapping, and transport
  accounting regressions.
- Python 3.11 deterministic suite: 757 passed. The full synthetic suite now
  passes in both the system Python and pinned Python 3.11 environment.
- Corrected RPM comparator matched installed librpm for 196 synthetic pairs.
- Fixed token baseline: 40,752 versus 4,644 input tokens (88.6% reduction), zero
  model calls, 43,398 stdout bytes retained and local audit verified.
- Packaging boundary suite: 13 passed. Explicit input lists reject unreviewed
  evidence and nested test/answer files before distribution. The package gate
  built identical artifacts twice and loaded the code-anchored scanner catalog
  from an extracted wheel layout. Human tooling remains excluded.
- Source secret scan: 257 source files, no findings at that checkpoint; final
  source/package scan and reproducibility receipts accompany the private build.
- Independent reviews found and corrected stop-log, disclosure, advisory identity,
  evidence, scope ceiling and wave crash-consistency defects. Review applies to
  the implemented surface, not the entire approved plan or live acceptance.

## Remaining implementation gates

The development continuation added first-class transport reservations and
durable attempt receipts, conservative crash recovery, immutable scanner plan
semantics, deterministic multi-service candidate mapping, atomic handover
transport ceilings, and loopback-only HTTP, SMB2 negotiate, and NBSTAT
validators. The exact Nmap request fixtures use one sealed compound receipt,
record cumulative TCP and UDP resources, and cannot resume after a terminal
result. Structured MS17-010 and unmapped-CVE cards remain manual-only. The
catalog admits no live scanner profile. Existing bounded HTTP
receipts reconstruct application-layer request and body sizes; they do not
measure complete headers, TLS, or wire bytes.

Complete the parent-owned connected relay and actual wire accounting;
credential grants and actual isolated authenticated collection; complete paged
collector receipts and richer all-platform inventories; advisory feed
normalization/runtime integration; remaining finite web/database/AD checks;
manual cards/retest completeness; quarantine/export and failure corpus review;
profile-level live acceptance and independent CPTC11 benchmark. Private alpha
packaging and installation evidence are recorded separately under dist/. Preserve unsupported status until each gate passes.

## Live preflight and dependency

Read-only Dell management access worked. Guest count/control-host usage and
operator-guest configuration were checked through the existing pinned helper;
full outputs stayed encrypted in private lab audit storage. No target scans,
guest changes, journal changes or profile admission occurred in this continuation.
Kali operator guest has no trusted local SSH host-key record and its guest agent
is disabled. A trusted console fingerprint was requested from the user. Do not
accept TOFU, enable guest agents, change routes or run target collection from
Proxmox management as a workaround.

## Build data-handling incident

One Luna worker mistakenly started shared-history `sync` and was terminated
without a result; subsequent `verify` did not run. No importer process remained.
Metadata checks found a local leftover staging directory/lock, no completed
manifest for this device, and no index/project publication mtime during the
worker's reported window. These checks do not prove that no data was ever
published. Do not inspect raw staged histories in model context, automatically
publish them or delete source records. Main and all agents are now explicitly
restricted to sanitized handoff notes, with no history sync/import for this task.

## Ownership and next safe action

Main owns contracts, migrations, integration, and admission. For this
continuation the user explicitly authorized Daybreak for scanner architecture
and independent security review; Astra owns the separate Harbinger and Merlin
interface redesign. Source and synthetic data only. No live profile is admitted
by a builder claim. Continue with the outstanding connected relay,
credential-bound collectors, packet-accounting evidence, and lab validation
before enabling any exact scanner runner.
