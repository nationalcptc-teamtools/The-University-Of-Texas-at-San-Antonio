# Contributor status: AI-only split

Alpha 0.1.0a5 removes the standalone human product surface and legacy team tool
archive from this private repository. The release now contains the guarded AI
harness, operator control plane, compact skill, documentation, and synthetic
tests only.

The external source inventory has no copied upstream source. Runtime and build
dependencies remain exactly pinned and recorded with their license sources.
Unknown licensing continues to block imports.

Before sharing a change, run `scripts/test-harness.py`, build the two allowlisted
artifacts with `scripts/package-harness.py`, inspect `git diff`, and run the
secret scan. Keep commits private and do not push without explicit permission.
