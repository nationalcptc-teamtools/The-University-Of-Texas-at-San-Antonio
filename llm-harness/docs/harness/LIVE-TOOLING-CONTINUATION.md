# AI harness continuation

This repository now contains only the guarded AI harness and its trusted
operator control plane. Standalone collectors, broad team scripts, NXC helpers,
phishing assets, report templates, and the earlier web operator application are
outside this repository.

The AI may request only a module in the immutable registry. The operator uses
`cptc` to create the workspace and workflow, inspect the generated preamble,
apply exact approvals, stop execution, and review deterministic results. The
model never receives a shell, a filesystem path, raw evidence, secrets, or an
export capability.

Typical control-plane sequence:

```sh
cptc doctor
cptc modules
cptc init /approved/engagement --policy /approved/policy.json \
  --recipient age1RECIPIENT --age /approved/bin/age
cptc --workspace /approved/engagement preamble
cptc --workspace /approved/engagement workflow-create WORKFLOW_ID \
  --provider /approved/provider.json --module MODULE_ID --target TARGET_ID
cptc --workspace /approved/engagement ai-step WORKFLOW_ID \
  --provider /approved/provider.json
cptc --workspace /approved/engagement coverage
cptc --workspace /approved/engagement audit-verify
```

Offline Nmap, Linux, Windows/AD, web, exploitation-result, and reporting inputs
must be selected by the operator and passed to exact import modules. The model
cannot select local evidence. Network modules remain individually admitted and
budgeted; unsupported scanners and unknown effects remain blocked.

Use `cptc --workspace WORKSPACE stop --reason operator_request` for immediate
durable stop intent. A stopped or uncertain workflow cannot be resumed by the
AI. Preserve its record for review.

The two Dell validation VMs are preparation targets only. Their availability
does not expand an engagement policy or admit a module.
