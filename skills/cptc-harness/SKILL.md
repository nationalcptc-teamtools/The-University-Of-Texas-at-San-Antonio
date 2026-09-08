---
name: cptc-harness
description: Use the guarded CPTC harness for typed offline imports and approved bounded observations.
---

# Guarded CPTC harness

Use the static registry and the current operator policy.  Select one exact
module ID from the preamble allowlist.  Supply an empty argument object unless
the module schema explicitly permits a field.  The registry rejects unknown
fields, unregistered IDs, manual-only procedures, ineligible targets, and
stale policy revisions.

Use offline import modules for reviewed Nmap XML, network, web, Linux,
Windows/AD, exploitation result, and reporting records.  Imports use trusted
operator-selected bytes.  They return typed observations, source hashes,
parse issues, and duplicate counts.  Raw client data stays human-only
restricted evidence.
An operation marked complete can still have incomplete collection. Preserve
collector limitation codes and failed attempts; do not treat missing observations
as a clean finding or complete coverage.
Detection and advisory matching are deterministic. Never ask the model to
rediscover CVEs from a full transcript. Use the recorded target, check, account
role, component, evidence and collection state. A version match is a candidate;
CWE and ATT&CK relationships do not mean exploitation succeeded. Preserve
conflicts, unknown patch provenance and missing prerequisites. Expected CPTC11
answers belong only to the external benchmark and must never enter runtime.

Use the web header and session modules only with the bounded transport.  They
make one metadata request under the registered request budget.  They do not
follow redirects, submit credentials, or expose response bodies or header
values to the model.
`web.response_capture` and offline capture selection require an explicit operator.
Do not request them as model actions or request their evidence or keys.
Ordinary metadata output is not a complete passive-scanner response capture.

Native Nmap observes exactly one registered TCP port through a pinned parent-only
connect broker. Offline Nuclei/ZAP observation modules require a human-selected
response artifact; the model cannot supply raw captures. Active Nuclei/ZAP,
remote host execution, authentication, client browser login and client-data
stdio MCP are not admitted in this release.
Zerologon, password spraying, DoS/crash testing, and domain changes are
manual-only.  Ask a human to perform those checks and import the reviewed
result card.  Never create an alias, wrapper, shell command, arbitrary scanner
template, or model-supplied approval/source/policy/classification field.

Use `ask_human` when a manual-only or uncertain action is needed.  Use
`finish` only with an admitted status.  Skill output must be one complete JSON
object with an `action`, `ask_human`, or `finish` value.  Do not send prose,
partial JSON, unknown fields, or streamed execution fragments.

The operator's immutable workflow permits at most six model calls, twelve
model-requested actions, one call in flight and one format repair. The model
cannot increase limits, reset counters, widen scope or resume stopped targets.
Use compact typed state; full output remains in local human-only audit storage.
Never request raw evidence, credentials, local paths, arbitrary URLs, uploads,
exports, clipboard access, policy edits or a different provider. Client-derived
facts remain confidential even after names and addresses are removed.

The trusted `cptc` control plane belongs only to the operator. It does not grant
CLI, filesystem, shell, approval, evidence-selection, or export access to the AI.
Frozen observation waves are operator-only. The model cannot freeze, run, restart,
repair, or edit a wave; interrupted actions require operator review.
