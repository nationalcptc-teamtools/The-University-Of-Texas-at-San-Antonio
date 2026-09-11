# Synthetic read-only wave support

This folder contains test-only channels, clocks, encryption stand-ins, and
fault hooks.

The channels never open a network socket. The wave factory creates a complete
synthetic frozen approval for ledger and broker tests. The encryptor does not provide
client-data protection. Use it only with synthetic bytes in package tests.

Run the tests from the repository root:

```text
PYTHONDONTWRITEBYTECODE=1 python -m pytest -p no:cacheprovider -q tests/readonly_wave_v1
```

Do not copy these helpers into a production service or use them for live
assessment traffic.
