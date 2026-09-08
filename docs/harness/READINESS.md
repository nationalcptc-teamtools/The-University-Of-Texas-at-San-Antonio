# Private 0.1.0a4 readiness

This build delivers additional enforcement, deterministic detection, evidence
checks and operator workflows. **The full approved CPTC11 plan is incomplete.**
It is not a competition release or a claim to detect every CPTC11 weakness.

## Usable development capabilities

- Human `cptc-tools` and harness `cptc` CLIs, independent Linux/PowerShell kit,
  manual cards, compatible imports, evidence-backed reports, findings and gaps.
- Eleven finite deterministic predicates; component/target/source hashes stay
  attached to conclusions. Missing access, conflicting evidence and incomplete
  collection remain visible. Configuration weaknesses need not have a CVE.
- Offline advisory matching library with tested Debian, RPM, SemVer and limited
  Windows build/supersedence semantics. It is not yet connected to collected
  package inventory or a complete normalized advisory feed.
- Durable stops independent of the audit writer; recursive final-provider
  disclosure checks; additive ledger migration and persistent scope ceilings.
- Operator-only frozen waves of four existing bounded observation profiles.
  Atomic allowances, deterministic order, hash binding, paced HTTP requests,
  single-use claims and conservative recovery prevent automatic replay after
  possible dispatch. They add no arbitrary command or authentication capability.
- External benchmark comparator with distinct original/later populations and
  evidence requirements. Expected answers remain outside the runtime package.

See [the practical workflow](../../human/runbooks/competition-assessment.md) and
[the independent human kit](../../human/README.md). Private distribution files
and reproducibility receipts are under `dist/`.

## Acceptance accounting

Exact final test/review/build results are recorded in `RELEASE-STATUS.json` and
`dist/BUILD-RECEIPT-a4.json`; the historical alpha3 evidence is preserved under
`history/`. Passing synthetic tests does not convert a profile to live accepted.

| Measure | Status |
|---|---|
| Implemented deterministic predicates | 11 |
| Additional unsupported capabilities shown | 14 |
| Manual-only capability families shown | 5 |
| Reviewed independent CPTC11 benchmark entries | Not established |
| Automated-eligible entries detected live | Not measured |
| Manual coverage against benchmark | Not measured |
| Live false-positive / missed-issue totals | Not measured |
| Alpha4 profiles with completed live acceptance | 0 |
| Fixed transcript token comparison | 88.6% fewer input tokens; zero model calls |

The fixed token experiment retains 43,398 stdout bytes and verifies its local
audit. It compares input tokens only, not provider billing or reasoning usage.

## Remaining release blockers

1. Trusted operator-guest SSH identity and approved access; then independent
   CPTC11 asset/deployment provenance and a reviewed expected-weakness catalog.
   Read-only Dell management preflight succeeded, but management access does
   not authorize using that host as the scanner. No guest/journal/route changes
   were made to bypass the operator-access gap.
2. Credential grants, authenticated transport, complete actual protocol/byte
   accounting and richer paged inventory collectors. Authentication remains
   disabled. Current reservations enforce declared profile bounds, not a
   claimed complete wire-traffic meter.
3. Native Windows/AD execution, patch/AD CS/GPO/delegation predicates, reviewed
   web/API role/state-changing profiles, TLS posture and database role/grant
   collection; advisory feed normalization and runtime correlation.
4. Full manual/retest benchmark coverage, withheld variants and per-profile
   positive/negative live evidence. OT/disruptive/unknown-impact checks remain
   manual-only, including in the lab.
5. Full Python 3.11 isolated-runtime acceptance. Pure deterministic tests pass,
   but this installed 3.11 interpreter lacks `os.memfd_create`; it cannot use a
   less-isolated fallback. Other platforms remain unadmitted.
6. Client provider arrangement, browser login/display/egress acceptance and
   recipient-bound client-data MCP. Existing stdio MCP remains synthetic-only.
7. New handover format preserving scope ceilings, waves and attempt records.
   Legacy v2 handover blocks ledgers whose new controls it cannot preserve.
8. Remaining malicious-worker, quarantine/export interruption and full-disk
   corpus. Local integrity is tamper-evident under trusted-operator assumptions.

## Data handling follow-up

A worker mistakenly started the general shared-history importer earlier in the
build. It was terminated without completion; metadata inspection did not prove
whether any partial publication occurred. The incident is recorded in
`IMPLEMENTATION-PROGRESS.md`. No history importer was rerun. Raw staged histories
must stay out of model context; cleanup or publication requires a separate
review. Only a sanitized implementation handoff is appropriate for shared notes.

No push, upload, competition publication, automatic deletion, infrastructure
change, new provider authorization or global configuration change is included.
