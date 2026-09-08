# CPTC human toolkit

For independent native tools and local collectors, start with
[Using the tools without the harness](runbooks/without-harness.md). Those
collectors and cards need no model or harness installation.

For check coverage, findings and frozen observation waves, use the
[competition assessment workflow](runbooks/competition-assessment.md).
This development build has a finite detector catalog and explicit unsupported
checks. It has not passed complete CPTC11 benchmark acceptance.

`cptc-tools` is an operator-directed terminal entry point for the guarded
harness. It lists the reviewed static registry, checks local prerequisites,
creates and operates an owner-only workspace, imports reviewed offline files,
and produces coverage, reports, and audit verification. It has no provider,
model, MCP, shell-runner, remoting, credential-retrieval, or service-mutation command.

Use the installed `cptc-tools --help` command from any directory, or
`./human/cptc-tools --help` from the repository root. `modules` and
`preflight` are read-only and do not open a runtime or import optional AI
adapters. `import` accepts only an offline registered module and reads an
owner-only file. A bounded `run` still requires the active policy, eligible
assignment, release profile, audit, isolation, and rate gates.

`run web.response_capture` records one complete approved response as encrypted
human evidence. `replay-capture` accepts its exact action/evidence identifiers
and a local age identity reference to feed the reviewed offline Nuclei or ZAP
profile. Plaintext stays in memory; the key is mounted only in a networkless
decryptor. See [the capture workflow](../docs/harness/LIVE-TOOLING-CONTINUATION.md).
These commands are operator-only and never expose capture/key access to a model.

Failed, blocked, stopped and uncertain operations return exit code 2. Imports
with valid observations and collector limitations may complete successfully,
but reports and coverage label their collection incomplete. Host collectors
emit fixed limitation codes for clipped inventories and unavailable metadata.

Raw client evidence remains local and human-only. Do not put credentials,
cookies, tokens, or raw client data in command arguments, shell history,
runbooks, or synthetic examples.
