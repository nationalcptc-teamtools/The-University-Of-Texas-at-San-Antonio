# Guarded CPTC LLM harness

This folder contains the deterministic policy broker, restricted AI
interfaces, bounded collectors, evidence pipeline, audit system, and synthetic
test suite for CPTC assessment work.

The `cptc` command remains because it is
the trusted operator control plane used to initialize workspaces, approve and
stop AI workflows, inspect coverage, verify audits, and create reviewed local
exports. It must never be exposed to the model as a shell capability.

Start with [the harness guide](docs/harness/README.md), [local installation](docs/harness/LOCAL-INSTALL.md), and [current readiness](docs/harness/READINESS.md). Run the commands below from this `llm-harness/` directory.

```sh
python3 scripts/bootstrap-harness.py --install-age
python3 -m cptc_harness doctor
python3 -m cptc_harness modules
python3 scripts/test-harness.py
```

The separate private team applications are [Harbinger](https://github.com/Moriz82/Harbinger) for technical evidence and [Merlin](https://github.com/Moriz82/Merlin) for scribe drafting and reviewed Ghostwriter delivery. They do not execute assessment tools or connect to this AI harness. Use [team-env-setup](../setup_scripts/team-env-setup/README.md) to prepare their reviewed Kali host packages.

All client-derived data remains confidential. Raw evidence is encrypted before
persistence and is unavailable to the AI transport. Unknown-impact and
manual-only procedures have no execution path through the broker. This is a
private development alpha; supported profiles still require the live acceptance
recorded in the readiness documents.

External source may enter this repository only through the reviewed license
gate in [THIRD-PARTY-LICENSES.md](docs/harness/THIRD-PARTY-LICENSES.md). Do not
push this repository to the public team-tools project.
