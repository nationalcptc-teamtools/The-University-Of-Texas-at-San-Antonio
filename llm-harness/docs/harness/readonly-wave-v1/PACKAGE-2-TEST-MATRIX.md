# Package 2 test matrix

Run the synthetic package tests from the repository root:

```text
PYTHONDONTWRITEBYTECODE=1 python -m pytest -p no:cacheprovider -q tests/readonly_wave_v1
```

The tests cover the following controls:

| Area | Control |
| --- | --- |
| Ledger | WAL, full sync, mandatory pins, persisted identity and limits, legacy migration, frozen wave binding, duplicate actions, in-flight limit, stop gate, recovery, incomplete markers |
| Audit | UTC time, sequence, hash chain, strict state, durable failure marker, evidence inventory, delete/modify/extra detection, flock serialization, typed age records, sealed descriptors, encrypted capture, output limits |
| Broker | Catalog and wave binding, exact provider use, provider-open uncertainty, durable finalization, provenance receipts, typed parser result, no retry |
| Service | Peer checks, owner and group policy, canonical bytes, method-specific schemas, SOCK_SEQPACKET round trip, packet size, duplicate fields, identifier-only requests, stop |
| Integrity | Manifest hashes, trusted owner and parent policy, exact closure, trust anchor, symlink and path rejection |

Tests use synthetic response bytes. They do not contact CPTC11, Proxmox, Kali,
Ghostwriter, or an AI provider.
