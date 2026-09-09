# Manual-only CPTC procedure cards

These cards are intake prompts.  They are not executable commands.

## Zerologon

Confirm target, written authorization, maintenance window, and a reversible
proof method.  A human operator performs the approved check.  Record attempted,
blocked, observed, or confirmed outcome and attach reviewed evidence.

## Password spraying

Confirm the account set, lockout threshold, rate, and operator approval.  A
human operator performs any permitted test.  Stop on lockout, throttle, or
uncertain impact.  Import the reviewed result card.

## DoS or crash testing

Do not run this through the harness.  Obtain separate written authorization
and a human-run safety plan.  Record health checks, stop conditions, and the
reviewed result.

## Domain changes

Do not change domain, identity, policy, or service state through the harness.
Use the operator's approved manual procedure and import only the reviewed
result and evidence reference.

## MS17-010 relationship review

Confirm the exact target and authentication realm, written authorization, the
maintenance window, the recovery owner, and a current health baseline. A human
selects and reviews the exact test method. Record the OS build, patch
provenance, SMB identity, protocol posture, UTC timestamps, result state, and
reviewed evidence references. Keep a tool candidate separate from a confirmed
finding. After remediation, repeat the reviewed evidence collection and compare
the same build, patch, service, protocol, and scope fields.

Allowed result states are attempted, blocked, observed, confirmed, and
incomplete. This card cannot launch the Metasploit
`auxiliary/scanner/smb/smb_ms17_010` module or another test.

## Unmapped CVE relationship review

Confirm the exact target and service. Verify product identity, version
provenance, patch source, advisory source, and advisory revision. A human
reviews applicability, contradictory evidence, and possible test effects.
Record UTC timestamps, access limits, evidence references, and collection
completeness. Refresh the advisory record before a retest. Repeat only admitted
evidence collection.

Allowed result states are attempted, blocked, observed, confirmed, incomplete,
and unsupported. This card has no execution path.
