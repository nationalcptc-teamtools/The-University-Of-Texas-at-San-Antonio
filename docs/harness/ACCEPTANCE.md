# Acceptance status: private alpha 0.1.0a5

The enforcement foundation and listed synthetic-tested interfaces are available
for private evaluation. The complete competition release gate is not met. No
active profile is accepted for arbitrary client targets, and the toolkit does
not claim that it finds every vulnerability.

## Evidence required for a supported profile

A supported profile requires all of the following:

1. reviewed module manifest, traffic and resource limits, effects, and cleanup;
2. vulnerable, hardened, ambiguous, partial, and unsupported synthetic fixtures;
3. adversarial boundary tests for scope, disclosure, process, audit, and stop;
4. independent review of the implementation and evidence predicate;
5. relevant bounded live evidence from an explicitly eligible lab target.

Scanner output alone does not confirm a finding. Findings retain their evidence,
collection completeness, prerequisites, limitations, review state, and CVE/CWE
or ATT&CK relationship. Manual-only coverage is accounted for separately.

## Locally exercised controls

The synthetic suite covers policy and schema rejection, manual-only aliases,
persistent target and authentication budgets, crash and uncertain outcomes,
recursive disclosure rules, DNS and redirect boundaries, worker isolation,
complete output capture, UTC ordering, audit rotation, log injection, encrypted
exports, wrong keys, handovers, slow and malformed models, MCP limits, and zero
model-call deterministic workflows.

Native integration tests exercise the reviewed one-port Nmap shim, offline
Nuclei/ZAP workers, real age encryption, bubblewrap isolation, and browser/MCP
test surfaces when their pinned dependencies are present. The test runner rejects
skips, xfails, collection gaps, duplicate test receipts, and interrupted runs.

## Remaining release blockers

- complete and independently reviewed CPTC11 expected-issue catalog;
- correct automatic result for every automated-eligible benchmark entry;
- complete manual card and evidence state for every manual-only entry;
- authenticated Linux, Windows/AD, web, and database collection profiles;
- live profile evidence on the intended Kali/operator and lab topology;
- actual approved competition AI provider, retention, and server-side tool
  behavior;
- independent final security review and a clean reproducible release build.

The standalone human toolkit and legacy team scripts are not part of this
release. The `cptc` CLI remains solely as the trusted control plane for the AI
harness.
