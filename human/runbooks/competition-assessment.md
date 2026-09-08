# Competition assessment workflow

This is a private development build. Run `cptc-tools checks` to see the finite
detector catalog and unsupported capabilities. Its results do not establish
complete CPTC11 coverage. A profile needs fixtures, independent review and
relevant live evidence before it can be called supported for competition.

Use an approved operator machine with protected engagement storage outside Git.
The AI is optional for every command below. Values in angle brackets are
operator-supplied identifiers or private paths; never paste secrets into argv.

```text
cptc-tools preflight
cptc-tools modules
cptc-tools checks
cptc-tools init <workspace> --policy <approved-policy.json> --recipient <age-recipient> --age <pinned-age>
cptc-tools --workspace <workspace> import network.nmap_import --input <private-nmap.xml>
cptc-tools --workspace <workspace> import linux.output_import --input <private-linux.json>
cptc-tools --workspace <workspace> import windows_ad.output_import --input <private-windows.json>
cptc-tools --workspace <workspace> findings
cptc-tools --workspace <workspace> gaps
cptc-tools --workspace <workspace> coverage
cptc-tools --workspace <workspace> audit-verify
cptc-tools --workspace <workspace> report
```

The policy must name exact assets, assignments, scope/exclusions, operating
window, SOW/ROE and admitted modules before any target work. Collection uses
single-target actions. Observation waves order and reserve those same actions;
they add no credentials, new network methods or scanner categories.

```text
cptc-tools --workspace <workspace> assessment-plan --id <wave-id> --target <approved-target-id> --module web.headers --output <private-plan.json>
cptc-tools --workspace <workspace> assessment-freeze --plan <private-plan.json> --sha256 <reviewed-plan-hash>
cptc-tools --workspace <workspace> assessment-status --id <wave-id> --sha256 <reviewed-plan-hash>
cptc-tools --workspace <workspace> assessment-run --id <wave-id> --sha256 <reviewed-plan-hash>
```

Planning reports the exact hash, item count and declared traffic/output bounds
without DNS or target requests. Freeze spends every item's allowance atomically.
Only the four existing observation profiles (`network.nmap_inventory`,
`web.headers`, `web.session`, `web.response_capture`) are eligible for these
operator-only waves. Each item still passes broker clock, scope, audit and
encryption gates at dispatch. Completed items cannot rerun; an interrupted
claimed item becomes uncertain and stops the wave after restart. New code or
changed policy invalidates its plan hash. Credentialed collection remains
unavailable. Current ceilings describe declared profile allowances; detailed
wire-byte accounting remains an acceptance gap.

Explicit `budget_limits` may cap `request_limit`, `output_bytes`, `process_limit`,
`model_calls`, `actions` and `auth_posts` per engagement, device, workspace,
workflow, target origin or realm. Target keys are `scheme://host:port`; workflow
keys are workflow/wave IDs. Fixed identity and target/realm keys must exist in
the policy. Previously recorded stricter ceilings persist even if a new policy
omits or widens them. Budgets are not refunded after failure or uncertainty.
Legacy v2 handover rejects a ledger containing new ceilings or wave state until
a reviewed format can preserve them; it cannot silently drop those controls.

```text
cptc-tools --workspace <workspace> run network.nmap_inventory --target <approved-target-id>
cptc-tools --workspace <workspace> run web.headers --target <approved-target-id>
cptc-tools --workspace <workspace> stop --reason suspected_lockout
```

Stop reasons are `operator_request`, `suspected_lockout`, `health_degradation`
and `audit_failure`. Stop writes durable intent before contacting the central
audit writer. Keep the workspace stopped until a human reconciles the outcome;
there is no AI resume or budget-reset operation. Stops, failed collection and
uncertain actions remain in the audit and reports.

Read `detections` in the JSON report alongside `evidence_index` and
`check_coverage`. Different ports, paths and services retain component IDs.
`candidate` needs more evidence; `observed_condition` means a reviewed predicate
was satisfied; neither is a human-confirmed exploit. A missing or partial
collection cannot establish `not_observed`. Legacy observations retain their
original meaning and are not silently promoted to new findings.

The standalone collectors in `human/collectors` and their formats remain usable
without the harness. Follow [collector procedures](collectors-and-imports.md)
and [standalone responsibilities](without-harness.md). Outside the broker,
the human enforces scope, traffic, storage encryption, logging and stopping;
those scripts do not supply broker isolation. Native PowerShell validation is
still required before relying on Windows collector completeness.

Use [manual evidence intake](manual-evidence.md) for disruptive or uncertain
tests. Zerologon, spraying, credential dumping, coercion, DoS, infrastructure
changes and fragile/OT testing have no automated admission. Cards describe the
review and evidence workflow; they do not authorize executing the test.

The separate `human/benchmark.py` comparator runs only outside assessment
runtime. It requires owner-only, hash-selected catalog/report files outside
Git, a reviewed complete expected-issue catalog, matching scope and deployment
provenance, and action-linked evidence. Keep the answers inaccessible to
collectors, AI, detector processes and their logs. Current reports deliberately
leave deployment provenance unset until independent evidence is recorded.

Reports and raw evidence remain local and confidential. For a reviewed local
export use the existing `cptc export-review` and `cptc export` workflow described
in [the harness guide](../../docs/harness/README.md); an export never uploads or
authorizes a destination. Do not copy client-derived records into development
agent prompts, Git or the shared context vault.
