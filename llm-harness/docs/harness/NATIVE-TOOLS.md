# Native tools used by the AI harness

Native programs are operator-installed dependencies behind specific broker
profiles. Presence on PATH never grants admission. Each admitted profile pins
the executable and required files, applies process and network containment,
declares traffic and output budgets, and records complete permitted output.

- Nmap is limited to the reviewed one-port connect profile through the parent
  connection broker. Arbitrary flags, NSE scripts, discovery sweeps, and direct
  sockets are unavailable.
- Nuclei and ZAP run only offline against one operator-selected response capture
  with reviewed local rules. Active scanner profiles are unavailable.
- `age` encrypts restricted raw evidence and reviewed exports. The model cannot
  access identities or request an export.
- Chromium is limited to synthetic browser adapter tests. Client-data browser
  use remains blocked until its provider and network boundaries are accepted.

Versions, sources, licenses, and redistribution limits are recorded in
[THIRD-PARTY-INVENTORY.json](THIRD-PARTY-INVENTORY.json). Runtime hashes and
configuration closure are recorded in the release integrity resources. A hash
or version change invalidates the affected profile until review and retesting.

The repository contains no NXC configuration helper, standalone host collector,
general scanner wrapper, or human tool bundle.
