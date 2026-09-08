# UTSA CPTC Team Knowledge Base (2025)
Tools and scripts, know-hows for the 2025-2026 season UTSA Cyber CPTC team. 

## Guarded harness (private alpha)

The [operator guide](docs/harness/README.md) covers strict data boundaries,
manual-only high-risk tests, encrypted evidence, verbose UTC auditing, compact
AI transports, typed all-track imports and deterministic reports. See the
[acceptance status](docs/harness/ACCEPTANCE.md) for disabled capabilities and
outstanding live-validation gates. This preparation build is not approved
competition staging.

The operator-facing NetExec configuration helper is available directly as
[`nxc-fix.sh`](nxc-fix.sh). It switches the active NetExec environment between
BloodHound CE and legacy configuration, creates a local backup, and does not
run collection. Third-party source admission and redistribution rules are in
the [license policy](docs/harness/THIRD-PARTY-LICENSES.md).

## Web coverage workflow

Start with [web/README.md](web/README.md) for the Python CLI, per-application
checklists, bounded HTTP scans, default-login verification, and Obsidian
evidence exports. Python 3.11+ is sufficient; the old installer is optional.

The [buildout design](web/BUILDOUT-PROPOSAL.md) records the review of the
CPTC11 material and the longer-term integration plan.
