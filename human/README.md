# CPTC human toolkit

For independent native tools and local collectors, start with
[Using the tools without the harness](runbooks/without-harness.md). Those
collectors and cards need no model or harness installation.

`cptc-tools` is an operator-directed terminal entry point for the guarded
harness. It lists the reviewed static registry, checks local prerequisites,
creates and operates an owner-only workspace, imports reviewed offline files,
and produces coverage, reports, and audit verification. It has no provider,
model, MCP, shell-runner, remoting, credential, or service-mutation command.

Use the installed `cptc-tools --help` command from any directory, or
`./human/cptc-tools --help` from the repository root. `modules` and
`preflight` are read-only and do not open a runtime or import optional AI
adapters. `import` accepts only an offline registered module and reads an
owner-only file. A bounded `run` still requires the active policy, eligible
assignment, release profile, audit, isolation, and rate gates.

Raw client evidence remains local and human-only. Do not put credentials,
cookies, tokens, or raw client data in command arguments, shell history,
runbooks, or synthetic examples.
