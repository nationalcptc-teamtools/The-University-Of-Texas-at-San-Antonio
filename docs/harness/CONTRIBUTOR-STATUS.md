# Contributor checkpoint

Branch: `feat/guarded-cptc-harness`. Destination: private repository only.

This checkpoint extends the guarded harness with a fail-closed full-suite test
runner, Linux memfd compatibility for Python 3.11, export failure boundaries,
and a finite nine-rule platform posture library with synthetic positive,
negative, ambiguous, incomplete, denied and untrusted cases.

The standalone human kit also includes
`scripts/fix-nxc-bloodhound-config.sh`. It selects BloodHound CE or legacy for
the active NetExec environment, creates a unique local backup, rejects symlinked
configuration paths, writes atomically, and verifies the resulting flags. It
does not run NetExec or BloodHound collection.

Run the complete synthetic suite with a new output directory:

```text
.tools/compat311/bin/python scripts/test-harness.py
```

The runner fixes the test roots to `tests` and `web`, disables third-party
pytest plugin auto-loading, records UTC microsecond audit and transcript files,
captures stdout/stderr, rejects skipped, xfailed, missing or duplicate cases,
prunes protected engagement storage before opening source inputs, and verifies
that the reviewed source snapshot did not change during execution. The current
checkpoint passes 656 tests and 17 subtests under Python 3.11 and the operator
Python 3.14 environment, including all 34 legacy web tests. Both audited runs
had complete capture and matching source hashes. A green software result does
not set `full_cptc11_accepted`.

## Current integration boundary

`cptc_harness/platform_checks.py` contains deterministic predicates and strict
fact schemas. These predicates are not yet registered as broker modules or
included in production coverage totals. Do not report them as live-supported
checks until operator-only typed import, source/action/evidence binding,
reporting integration and relevant live validation are complete.

Authentication and credentialed collection remain disabled. The independent
CPTC11 expected-issue catalog, authenticated Linux and Windows collection,
native Windows execution, and complete Dell acceptance remain open work.
Manual-only actions remain unavailable to the model and broker.

Do not add client evidence, credentials, raw logs, expected benchmark answers,
provider sessions or engagement databases to this repository. Use synthetic
fixtures for development. Keep unsupported and missing-access states visible.
