# Bounded profile runtime

This package executes a reviewed network observation. It does not expose a
general socket, URL, request, command, scanner, or script interface.

## Runtime sequence

1. Verify the externally anchored `portcast-live-v1` manifest with nofollow file descriptors.
2. Verify the exact Python 3.14 interpreter, sealed Paramiko dependency tree, native libraries, and package initializers.
3. Replace Python import paths with the verified release and runtime roots. Reject any project or SSH module outside those roots.
4. Load the manifest-pinned profile from `bounded-profiles-v1.json` and require `live_admitted`.
5. Reserve the exact action and cumulative budgets in SQLite.
6. Start the isolated broker and bind it to that committed running attempt.
7. Pass the broker two fixed, sealed service credential descriptors. Credential text never enters argv, environment variables, readable logs, or the wire worker.
8. Consume one short-lived nonce before the broker opens its fixed target channel.
9. Durably acknowledge every successful connect, send, and receive event before the next wire operation.
10. Receive the bounded raw response only as a sealed anonymous file descriptor and encrypt it through the isolated Audit service.
11. Finalize the Ledger attempt within its deadline before recording a complete wire receipt.
12. Parse only the typed fields that the profile permits and record transport cleanup before Harbinger export.

An interrupted broker, missing acknowledgement, expired nonce, deadline
crossing, or receipt persistence failure becomes `uncertain`. The Ledger stop
latch prevents another action. The frozen action identifier cannot be retried.

## PortCast profile

The first live profile is `web.http_jellyfin_public_identity`. It sends one
HTTP GET to the fixed PortCast service. It does not authenticate, redirect,
retry, send a body, use a proxy, or accept a runtime destination.

The parser retains the product and version identity. The result state is
`candidate`. A version match does not confirm a vulnerability or a CVE.

## Harbinger export

`build_portcast_harbinger_envelope` accepts a verified Runtime, the frozen
plan, explicit review identifiers and times, and an operator signing
reference. Export fails unless all of these records agree:

- Audit integrity and the operation intent.
- One complete wire receipt.
- One complete Ledger attempt and reservation.
- One complete result receipt and typed result.
- One successful lab transport cleanup receipt.

The signed envelope contains typed facts, counters, hashes, the audited release
manifest hash, and the encrypted evidence identifier. It does not contain the
encrypted artifact path, response bytes, ciphertext, credentials, cookies, or
CVE claims. Harbinger keeps the original signed envelope restricted and imports
one candidate observation.

## Test

Run the profile and export tests without lab traffic:

```sh
python -m pytest -q tests/profile_runtime tests/test_portcast_live.py
```

The test channels and responses are synthetic. Live execution uses the frozen
coordinator in `testing/cptc11_lab` after its separate release and lab gates
pass.
