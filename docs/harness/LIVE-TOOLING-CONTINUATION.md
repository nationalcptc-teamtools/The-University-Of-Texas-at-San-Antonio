# Lab-driven tooling continuation

This implements the approved continuation using source code and synthetic build
fixtures. Live inventories, target addresses, credentials, raw responses and
audit records remain outside Git and build-agent prompts.

The bounded live workflow exposed two gaps. Versioned host imports discarded
collector limitations even when some observations parsed successfully. HTTP
metadata collection intentionally withheld header values, which made its output
unsuitable as a complete response for offline passive scanners. The passive
validator rejected that input; the record must remain a failed attempt.

## Frozen changes

1. Preserve only bounded, known collector limitation codes. Report operation
   outcomes and incomplete collection separately from finding confirmation.
   Make host collector caps explicit instead of silently clipping inventories.
2. Add an operator-only, one-request HTTP response capture with the same scope,
   clock, traffic, timeout, isolation, stop and encrypted-audit gates. Keep
   ordinary model-facing metadata withholding unchanged. Unsupported response
   framing remains unsupported; do not reconstruct missing header values.
3. Let a human select one completed capture by action and evidence identifiers
   for local offline Nuclei or ZAP. Verify the audit and plaintext checksum;
   decrypt only in a networkless process and retain plaintext only in memory.
   There is no model/MCP replay or key-reading capability.
4. Return a nonzero human CLI exit status for unsuccessful actions and invalid
   audits. Preserve the structured result and original failed records.
5. Publish coverage and reports through durable generation journals, restore or
   quarantine interrupted output, and export only completion-audited file hashes.
6. Test synthetic refusal/failure cases, obtain independent review, then repeat
   only the newly admitted observation against the already assigned lab target.
   Keep cumulative request usage across releases and policy revisions.

## Human workflow

Use `cptc-tools run web.response_capture --target TARGET_ID --workspace WORKSPACE`.
After reviewing the result's action and response evidence identifiers, use:

```sh
cptc-tools replay-capture web.nuclei_observation --workspace WORKSPACE \
  --action-id ACTION_ID --evidence-id EVIDENCE_ID --identity AGE_IDENTITY_FILE
cptc-tools replay-capture web.zap_observation --workspace WORKSPACE \
  --action-id ACTION_ID --evidence-id EVIDENCE_ID --identity AGE_IDENTITY_FILE
```

Replay performs no target request and uses no model. It accepts only a completed
operator capture and the two reviewed offline scanner profiles. The explicit
identity path is a local operator input; the identity contents are never logged.
Existing `web.headers` and `web.session` evidence cannot substitute for a complete
capture. A failed or truncated capture cannot be replayed by this command.

## Validation boundaries

Network reachability does not authorize credential use without a trusted guest
identity. Guest-level collection waits for a verified SSH host key or another
approved authenticated access path. Do not enable guest agents, alter routes,
replace existing relays, restart services, or change lifecycle journals to force
validation. Disruptive operations remain manual-only in the lab as well.

Detailed acceptance evidence and remaining gaps are recorded in ACCEPTANCE.md
and RELEASE-STATUS.json after validation. The full competition release remains
subject to the original approved gates; a new local package does not waive them.
