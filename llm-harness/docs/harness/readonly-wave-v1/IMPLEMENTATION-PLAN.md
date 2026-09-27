# CPTC11 read-only wave v1 implementation plan

## Purpose

Build a sibling release for four exact CPTC11 observations. Do not modify or
import the frozen PortCast runtime. This package collects bounded facts. It
does not confirm findings, execute exploits, authenticate, follow redirects,
or accept caller-supplied network fields.

The first live admission order is ShorePass Traefik, CrewComms Redis, GPS
Keycloak, and Penny Meilisearch. Stop the wave after any uncertain result.

## Release boundary

Create `cptc11_readonly_wave_v1/` with these owned modules:

| Module | Responsibility |
|---|---|
| `contracts.py` | Closed action, result, counter, and limitation types |
| `catalog.py` | Hash-anchored lookup for exactly four profiles |
| `wire.py` | Exact HTTP/1.1 and RESP request and response framing |
| `broker.py` | Reservation-bound, one-shot dispatch |
| `ledger.py` | Dedicated durable SQLite intent and budget ledger |
| `audit.py` | Encrypted raw capture and chained receipts |
| `service.py` | Local `SOCK_SEQPACKET` authority |
| `integrity.py` | Sibling release, worker, runtime, and ELF verification |
| `harbinger.py` | Signed metadata-only observation v2 export |
| `parsers/` | One pure parser for each profile |

Add deployment files under `deployment/cptc11-readonly-wave-v1/`, synthetic
lab support under `testing/cptc11_readonly_wave_v1/`, tests under
`tests/readonly_wave_v1/`, and operator documentation in this directory.

Do not import `cptc_harness.profile_runtime` at runtime. Preserve every file
and hash in the PortCast release. Assert this in the release tests.

## Closed profile catalog

The caller supplies only a frozen `wave_id`, plan ID, action ID, and profile
ID. The catalog supplies every endpoint, byte, timeout, parser, and limit.
The ledger accepts an action only when its action order, operation hash, target,
and budget match the stored `FrozenWaveApproval`.

| Profile | Fixed operation | Maximum use |
|---|---|---|
| `shorepass.traefik_public_version.v1` | HTTP GET `10.0.1.99:8080/api/version` | 1 connect, 1 request, 512 B TX, 4 KiB RX/capture, 8 s |
| `crewcomms.redis_ping.v1` | Send exactly `*1\r\n$4\r\nPING\r\n` to `10.0.1.14:6379` | 1 connect, 1 request, 14 B TX, 128 B RX/capture, 5 s |
| `gps.keycloak_oidc_metadata.v1` | HTTP GET `10.0.1.13:8180/realms/gps/.well-known/openid-configuration` | 1 connect, 1 request, 512 B TX, 16 KiB RX/capture, 8 s |
| `penny.meilisearch_health.v1` | HTTP GET `10.0.1.11:7700/health` | 1 connect, 1 request, 384 B TX, 2 KiB RX/capture, 8 s |

All four profiles have zero UDP, TLS, authentication, redirects, retries,
request bodies, DNS, proxies, callbacks, and runtime options. Exact successful
request bytes are frozen with the catalog and covered by tests.

Package 1 freezes these exact byte sequences. HTTP header names, values, order,
line endings, and the final empty line are part of the contract.

| Profile | Request bytes | Length | SHA-256 |
|---|---|---:|---|
| ShorePass | `GET /api/version HTTP/1.1\r\nHost: 10.0.1.99:8080\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n` | 123 | `3f55e7ee7ebb6fe0b6f8123468c89abc1a8e93c924456e2bd0a354a301b64e2f` |
| CrewComms | `*1\r\n$4\r\nPING\r\n` | 14 | `a43cb6a3b9d261112714d00e36b33106d1479eb1b3d8131a07684d4d477c5989` |
| GPS | `GET /realms/gps/.well-known/openid-configuration HTTP/1.1\r\nHost: 10.0.1.13:8180\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n` | 155 | `73d878866168bca13988d737cf0eef2b65806ec3d8be44a6b45c2fb17d4ddce5` |
| Penny | `GET /health HTTP/1.1\r\nHost: 10.0.1.11:7700\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n` | 118 | `fa8c6e1974fc90afc4110f570ba2e90b8e81b417b9ecbb389d3b905a8f79391e` |

Use these target IDs:

- `cptc11-prod-shorepass`
- `cptc11-prod-crewcomms`
- `cptc11-prod-gps`
- `cptc11-prod-penny`

## Parsing and disclosure

Raw bytes move from a read-only memfd with write, grow, shrink, and seal seals
directly to encrypted audit storage. Ordinary files are rejected. Readable
audit events and Harbinger envelopes contain typed facts and hashes only.

- The Traefik parser accepts bounded UTF-8 JSON with no duplicate keys. It
  reads the exact top-level `Version` field, accepts one optional leading `v`,
  validates Semantic Versioning syntax, and emits the normalized version and a
  fixed product-marker boolean. It discards every other field and all body
  bytes.
- The Redis parser accepts one RESP simple string or error. It emits only
  `pong`, `authentication_required`, `unexpected`, or `incomplete`. It rejects
  additional frames, arrays, bulk values, and oversized replies.
- The Keycloak parser retains HTTP status, realm-path match, issuer scheme,
  presence booleans, and values from frozen grant-type and signing-algorithm
  enums. The grant enum is `authorization_code`, `implicit`, `refresh_token`,
  `password`, `client_credentials`,
  `urn:ietf:params:oauth:grant-type:device_code`, and
  `urn:openid:params:grant-type:ciba`. The signing enum is `RS256`, `RS384`,
  `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`, and `EdDSA`.
  Unknown values become booleans. Missing arrays remain distinguishable through
  their presence booleans. It discards URLs, hosts, identifiers, and body
  bytes.
- The Meilisearch parser retains HTTP status and one health state:
  `available`, `unavailable`, `other`, or `malformed`. It reads only the exact
  top-level `status` field. Another valid string becomes `other`; a missing or
  non-string field becomes `malformed`. It discards diagnostics and body bytes.

No parser emits a CVE, credential, header value, error text, artifact path,
ciphertext, benchmark value, or confirmed finding.

## Isolation and relay

Install a separate root-owned service at
`/usr/lib/cptc-harness/cptc11-readonly-wave-v1`. Use a separate state root,
socket, trust anchor, manifest, audit recipient, and persistent ledger.

The service uses:

- `RootDirectory` for the exact verified release;
- `IPAddressDeny=any` and `IPAddressAllow=100.85.84.30/32`;
- empty capability and ambient-capability sets;
- `NoNewPrivileges`, private devices, and kernel protection controls;
- private PID, IPC, UTS, mount, and user namespaces for target workers;
- an empty environment and an exact descriptor allowlist.

Only the pinned Dell SSH endpoint is reachable from the service. Target
connections originate from the approved Kali guest through OpenSSH local
forwarding.

PortCast and this wave are mutually exclusive. The Kali relay helper provides
`plan`, `apply`, `verify`, and `restore`. It replaces only the known PortCast
fragment after verifying its hash. The wave fragment permits exactly:

```text
10.0.1.11:7700
10.0.1.13:8180
10.0.1.14:6379
10.0.1.99:8080
```

It denies remote listeners, agent forwarding, X11, TTY, tunnels, gateway
ports, user startup commands, and shell execution. Run `sshd -t` and contextual
`sshd -T` checks before reload. Restore must reproduce the PortCast fragment
SHA-256
`0bbce970017f0aba4c44de79acd8426f95c9b3b6a105a116f24a3902d6462a3d`
and OpenSSH runtime pin
`9bcaeaa02a0c9f52b1b32c4259a35043b9dd0caec55f6fec150ec6f5a722df16`.
Any difference latches stop.

## Durable execution

Persist and fsync intent plus target, workflow, device, and workspace
reservations before dispatch. Use deterministic action IDs. Share the Dell
remote lock name with PortCast so both releases cannot operate together.

The audit writer uses an exclusive `flock` and reloads its state under that
lock before each mutation. A typed age record is required in production.
Synthetic encrypted records are available only to tests with `test_only=True`.

Each receipt binds release, policy, plan, action, profile, target, catalog,
operation, parser, worker, runtime, and encrypted-evidence hashes. It records
UTC timestamps with microseconds, monotonic duration, actual resource counts,
one outcome, one limitation, and cleanup state.

A provider open is contact-attempted before the provider call. Any open error
therefore becomes `uncertain`, persists a stop, and never retries. A request
that might have reached a target becomes `uncertain` after an interruption.
If central persistence fails, write a durable action-specific incomplete
marker. Never retry it automatically.

## Harbinger contract

Add a version 2 signed-observation schema in both private repositories. Keep
version 1 unchanged. Pin the contract, release, catalog, runtime, worker,
operation, profile, module, and parser hashes. Use a UUIDv5 replay identity.

Harbinger verifies every pin and counter, imports metadata-only observations,
sets `vulnerability_assessment` to `not_performed`, creates no confirmed
finding, and rejects raw paths, ciphertext, CVEs, extra fields, stale cards,
wrong targets, incomplete receipts, and exact replays.

## Test order

1. Reject mutations to destination, method, path, headers, body, proxy,
   redirect, retry, executable, environment, filesystem, and runtime options.
2. Verify exact HTTP bytes, partial sends, timeouts, compression, chunking,
   redirects, truncation, stop, and malformed responses.
3. Verify the exact 14-byte Redis request, `NOAUTH`, extra frames, unsupported
   types, timeout, truncation, and the 128-byte cap.
4. Use positive, negative, malformed, partial, ambiguous, and wrong-product
   fixtures for each parser.
5. Inject crashes at intent, reservation, dispatch, first byte, capture,
   parse, completion, and signing boundaries.
6. Exercise audit failure, full disk, permission drift, clock jumps, duplicate
   actions, and restart recovery.
7. Prove capability, descriptor, environment, filesystem, and direct-socket
   containment with the real launcher and privileged systemd acceptance.
8. Prove the Kali relay permits only the four catalog destinations and restores
   the exact PortCast policy.
9. Verify Harbinger v2 signature, pins, schema, replay, redaction,
   deduplication, and no-finding behavior.
10. Build twice and compare artifacts. Verify exact native closure, license
    source compliance, benchmark exclusion, and unchanged PortCast hashes.

## Live admission

Require green synthetic and packaging tests, privileged systemd proof, relay
apply-and-restore proof, independent review, fresh operating windows, and a
read-only Dell/Kali preflight. Execute one action at a time in this order:

1. ShorePass Traefik version.
2. CrewComms Redis `PING`.
3. GPS Keycloak metadata.
4. Penny Meilisearch health.

Revalidate Dell, Kali, clock, storage, assignment, relay mode, stop state, and
reservation immediately before each action. Wait at least one second between
HTTP actions. Stop on instability or uncertainty.

Redirect posture, TLS certificates, harmless root-page identities, Swagger
presence, MySQL greeting, and HEAD-only presence checks are later candidates.
Authorization comparisons, file and URL diagnostics, navigation data,
uploads, local-file embedding, Redis commands beyond `PING`, authentication,
NSE scripts without individual review, Metasploit, exploitation, state
changes, credential actions, fuzzing, crash tests, denial of service, dumping,
and target cleanup remain manual-only until separately reviewed and admitted.
