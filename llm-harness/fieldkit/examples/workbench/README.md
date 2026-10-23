# Sanitized workbench inputs

These files contain synthetic application traffic and configuration. The IP
`192.0.2.44`, `.example.test` hosts, user/context, credentials, and invalid token are
documentation placeholders. No file is a live capture or a usable credential.

`traffic.har` records an order number and separate shipment-job UUID, a later export
using that UUID, an authorize request with PKCE parameters, an example token response,
and a request carrying that token. Its signature is a documentation placeholder;
decoded claims remain unverified. `burp.xml` contains
one saved request/response with Base64-preserved HTTP bytes. `openapi.json`, `routes.js`,
and `actuator.json` supply overlapping route declarations and dependency/secret clues.
`oidc.json` supplies discovery metadata; `host-mappings.json` supplies an explicit IP.

`serialized-export.txt` is Base64 for the five-byte Java serialization stream header
followed by the null marker (`AC ED 00 05 70`). It contains no executable object graph.
Artifact triage detects the decoded signature without deserialization.

Run the offline example sequence in [the evidence workbench guide](../../docs/evidence-workbench.md).
The resulting SQLite vault is private raw storage, even when these particular inputs
are synthetic. Imports, route/ID mapping, artifact inspection, and report drafts never
contact the example hosts. Replay/baseline examples use `--dry-run`.
