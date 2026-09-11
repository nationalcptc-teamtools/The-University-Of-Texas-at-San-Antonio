# CPTC11 bounded profile wave implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` or `superpowers:executing-plans`.
> Complete the gates in order. Do not dispatch a live request until every
> earlier gate for that profile passes.

**Goal:** Account for every independently reviewed CPTC11 benchmark weakness
with a safe deterministic detector or a complete manual-only test card, and
validate each automated profile against the Dell lab without allowing an AI to
run an arbitrary request, scanner, exploit, or command.

**Architecture:** Harbinger accepts signed typed observations and does not own
target sockets. The guarded harness expands a frozen assessment wave into
single-target actions. A parent-owned worker sends one exact request, accounts
for actual wire bytes, encrypts raw output before persistence, and passes a
bounded response to a target-specific pure parser. The benchmark catalog stays
outside the runtime and is compared only after collection.

**Tech stack:** Python 3.11, immutable JSON profile catalogs, SQLite budget and
action ledgers, age-encrypted evidence, pinned native tools, pytest, mypy, and
Harbinger's signed harness-observation contract.

**Spec:** `docs/harness/CPTC11-IMPLEMENTATION-PLAN.md` and
`docs/harness/APPROVED-PLAN.md`.

## Global constraints

- Work only in the private `Moriz82/cptc-private-toolkit` and private
  `Moriz82/Harbinger` repositories. Commit on `main` only.
- Use the exact seven production targets already registered for CPTC11. Do not
  address the gateway, support guests, management plane, other teams, or an
  address learned from a response.
- Use one target operation at a time. Persist intent and all reservations
  before dispatch. A request that might have reached a target is `uncertain`
  after interruption and is never retried automatically.
- Keep HTTP at one request per second and at most 24 requests per application
  job. A smaller profile limit always wins. Authentication attempts are zero
  for this wave.
- Validate Dell and Kali identity, VM identity, VM state, assignment, clock
  synchronization, storage, installed tool hashes, and stop state immediately
  before each live action.
- Connect from the approved Kali guest through the pinned isolated relay. Do
  not run a target request from the Proxmox management host.
- Do not change guests, routes, DNS, time, certificates, services, accounts,
  files, databases, containers, or infrastructure. Do not follow redirects.
- Do not automate password guessing, spraying, credential use, uploads,
  arbitrary file reads, SSRF, traversal, state changes, fuzzing, command
  execution, Metasploit exploitation, NSE scripts with unknown effects, denial
  of service, dumping, coercion, or cleanup on a target.
- OT and fragile control actions stay manual-only. A successful lab request
  does not admit an OT profile.
- Raw responses and stream bytes are encrypted before disk persistence. The AI
  and Harbinger receive typed facts only. Do not write benchmark answers,
  credentials, raw client evidence, or decrypted artifacts to Git.
- Every profile has exact destination, method or payload, headers, TLS rules,
  response cap, timeout, request count, possible effects, parser allowlist,
  discarded fields, fixtures, and limitations. Runtime arguments are empty.
- A service banner or version creates a candidate. It does not confirm a CVE.
  Custom application weaknesses use CWE relationships when supported. ATT&CK
  relationships require observed prerequisites.
- Every manual-only entry names prerequisites, operator steps, evidence,
  stop conditions, cleanup expectations, and retest criteria. The harness has
  no execution path for a manual card.
- New third-party code is forbidden unless its revision, license, notice, and
  redistribution obligations are recorded first. Invoked tools are pinned and
  inventoried even when their code is not copied.
- The candidate benchmark is test-only, incomplete until independent review,
  and inaccessible to collectors, parsers, AI prompts, packaged wheels, and
  Harbinger runtime logs.

## System shape

```text
Frozen assessment wave
  -> broker policy, stop, assignment, clock, and budget checks
  -> durable intent plus target/workflow/device reservations
  -> pinned relay and one fixed worker operation
  -> encrypted stdout, stderr, and raw response
  -> exact typed receipt with actual connections, requests, and bytes
  -> pure target-specific parser with an allowlisted output schema
  -> signed observation envelope
  -> Harbinger metadata-only trust preview and confirmed merge
  -> external benchmark comparison
```

The worker contract is a closed tagged union. It contains `Http11RequestV1`,
`TlsHelloV1`, `RedisPingV1`, or `MysqlGreetingV1`. There is no generic URL,
socket, command, script, request body, header map, proxy option, redirect
option, retry option, or shell field. The profile loader supplies all fields
from a hash-anchored checked-in catalog. The caller supplies only the frozen
profile identifier and action identifier.

Each typed result contains:

- profile, module, target, wave, action, policy, catalog, parser, worker, and
  runtime-pin identifiers;
- started, first-byte, completed, and captured UTC timestamps;
- TCP connect count, TLS handshake count, application request count, transmitted
  bytes, received bytes, captured bytes, timeout state, exit state, and stop
  state;
- response status or protocol disposition, collection completeness, evidence
  digest, encrypted artifact reference, typed facts, and limitations;
- no response body, cookie value, authorization data, URL query value, internal
  identifier, coordinate, message content, database row, or secret.

## Fixed profile definitions

### ShorePass (`10.0.1.99`)

| Profile | Exact operation | Budget | Typed facts | Discarded data |
|---|---|---:|---|---|
| `shorepass.traefik_public_version.v1` | TCP/HTTP GET `http://10.0.1.99:8080/api/version`; `Host: 10.0.1.99:8080`; `Accept: application/json`; `Connection: close` | 1 connect, 1 request, 512 B tx, 4 KiB rx, 8 s | HTTP status, strict Traefik product marker, semantic version when exact | all other JSON fields, headers except bounded content metadata, body |
| `shorepass.http_redirect_posture.v1` | TCP/HTTP HEAD `http://10.0.1.99/`; `Host: probe-a.rooms.allports.tours`; no redirect | 1 connect, 1 request, 384 B tx, 2 KiB rx, 8 s | status, whether one absolute HTTPS location uses the same approved host and no user-info/query/fragment | full location after validation, server text, body |
| `shorepass.tls_certificate.v1` | TLS 1.2+ handshake to `10.0.1.99:443` with SNI `probe-a.rooms.allports.tours`; no HTTP request | 1 connect, 1 handshake, 1 KiB tx, 16 KiB rx, 8 s | negotiated TLS version/cipher, certificate SHA-256, SAN match result, validity times | certificate subject text beyond registered DNS suffix, extensions not used by posture detector |
| `shorepass.host_context_pair.v1` | Two separate HTTPS GET actions to `/api/id`; first host `probe-a.rooms.allports.tours`, second host `probe-b.rooms.allports.tours`; certificate pin from the preceding frozen wave; no redirect | 2 actions, each 1 connect/handshake/request, 512 B tx, 4 KiB rx, 8 s; aggregate HTTP count 2 | status and a keyed digest of the normalized returned room identifier; pair result records equal/different only | returned identifier, response body, unrelated fields |
| `shorepass.diagnostics_presence.v1` | HTTPS GET `/api/diagnostics/` with host `probe-a.rooms.allports.tours`; certificate pin; no query/body/redirect | 1 connect, 1 handshake, 1 request, 512 B tx, 4 KiB rx, 8 s | status and exact harmless diagnostics-service marker from the root index | endpoint details, host data, files, URLs, response body |
| `shorepass.passwd_marker_head.v1` | HTTPS HEAD `/passwd` with host `probe-a.rooms.allports.tours`; certificate pin; no body | 1 connect, 1 handshake, 1 request, 512 B tx, 2 KiB rx, 8 s | status, content length presence, content type | file bytes, last-modified value, entity tag |
| `shorepass.mysql_greeting.v1` | TCP connect to `10.0.1.99:3306`; read exactly one server greeting; send no client packet | 1 connect, 0 requests, 0 B application tx, 1 KiB rx, 5 s | protocol version, product family, normalized semantic version when exact, capability-bit names | connection ID, salt/auth plugin data, raw greeting |

`host_context_pair` proves that the application derives context from an
untrusted host label. It does not alone prove unauthorized access to another
real room. The known IDOR, client-side authorization, diagnostics file and URL
features, state-changing routes, Docker socket, and host-root mount conditions
remain static-observation or manual-only entries. The live profiles never call
those operations.

### APT-GPS (`10.0.1.13`)

| Profile | Exact operation | Budget | Typed facts | Discarded data |
|---|---|---:|---|---|
| `gps.keycloak_oidc_metadata.v1` | HTTP GET `http://10.0.1.13:8180/realms/gps/.well-known/openid-configuration`; no redirect | 1 connect, 1 request, 512 B tx, 16 KiB rx, 8 s | status, realm match, issuer scheme, advertised grant and signing algorithm names from a closed enum | full endpoint URLs, hostnames, identifiers, body |
| `gps.swagger_web_presence.v1` | HTTP GET `http://10.0.1.13:8081/`; no redirect | 1 connect, 1 request, 384 B tx, 8 KiB rx, 8 s | status, exact Swagger UI marker | HTML, script configuration, URLs |
| `gps.swagger_searoute_presence.v1` | HTTP GET `http://10.0.1.13:8091/`; no redirect | same as web Swagger | status, exact Swagger UI marker | HTML, script configuration, URLs |
| `gps.navigation_read_presence.v1` | HTTP GET `http://10.0.1.13:8080/api/navigation.php`; no query, cookie, authorization, or redirect | 1 connect, 1 request, 384 B tx, 4 KiB rx, 8 s | status, JSON/non-JSON content class, normalized schema-field presence from a closed set | coordinates, vessel data, logs, messages, values, body |
| `gps.mysql_greeting.v1` | TCP connect to `10.0.1.13:3306`; read one greeting; send no client packet | 1 connect, 0 requests, 0 B application tx, 1 KiB rx, 5 s | same MySQL facts as ShorePass | same MySQL discarded fields |
| `gps.searoute_http_identity.v1` | HTTP GET `http://10.0.1.13:8090/`; no query/body/redirect | 1 connect, 1 request, 384 B tx, 4 KiB rx, 8 s | status and exact application identity marker when present | route or voyage data, HTML/body |

The weather endpoint, CSV download/export, route save, navigation update, and
any endpoint that accepts a remote URL, path, position, or state remain
manual-only. The runtime does not contain their request shapes. JWT claim
validation, wildcard CORS, forwarded-IP trust, TLS verification settings,
database credential presence, and writable source mounts are detected from
reviewed offline configuration facts.

### APT-CREWCOMMS (`10.0.1.14`)

| Profile | Exact operation | Budget | Typed facts | Discarded data |
|---|---|---:|---|---|
| `crewcomms.http_root_identity.v1` | HTTP GET `http://10.0.1.14/`; no redirect | 1 connect, 1 request, 384 B tx, 8 KiB rx, 8 s | status, exact application title/marker, content class | page text, links, forms, body |
| `crewcomms.http_login_posture.v1` | HTTP GET `http://10.0.1.14/login/`; no redirect, cookie, query, or body | 1 connect, 1 request, 384 B tx, 8 KiB rx, 8 s | status, login-form marker, names of session-cookie security attributes only | cookie names/values, CSRF values, form text, body |
| `crewcomms.tls_certificate.v1` | TLS handshake to `10.0.1.14:443` with no HTTP request and a catalog-pinned SNI only after offline certificate identity is established | 1 connect, 1 handshake, 1 KiB tx, 16 KiB rx, 8 s | same certificate posture fields as ShorePass | same certificate discarded fields |
| `crewcomms.redis_ping.v1` | TCP connect to `10.0.1.14:6379`; send exactly `*1\r\n$4\r\nPING\r\n`; read one RESP value; close | 1 connect, 1 request, 14 B tx, 128 B rx, 5 s | `pong`, `authentication_required`, `unexpected`, or `incomplete` | error text and all other bytes |

Redis `PING` can establish unauthenticated command availability. It cannot
establish the server version, key contents, persistence, bind policy, or impact.
The Redis 5.0.3 component identity comes from the reviewed image record and
creates CVE candidates only. Mass assignment, MD5 password hashing, predictable
reset tokens, open redirect, GET-based state changes, insecure cookie config,
and seeded authentication records are offline source detections. The harness
never logs in, resets an account, follows `next`, deletes data, reads Redis
keys, runs `INFO` or `CONFIG`, or tests a credential.

### Penny (`10.0.1.11`)

| Profile | Exact operation | Budget | Typed facts | Discarded data |
|---|---|---:|---|---|
| `penny.http_redirect_posture.v1` | HTTP HEAD `http://10.0.1.11/`; `Host: penny.allports.tours`; no redirect | 1 connect, 1 request, 384 B tx, 2 KiB rx, 8 s | status and validated same-host HTTPS redirect posture | location after validation, body, server text |
| `penny.tls_certificate.v1` | TLS handshake to `10.0.1.11:443` with SNI `penny.allports.tours`; no HTTP request | 1 connect, 1 handshake, 1 KiB tx, 16 KiB rx, 8 s | certificate posture fields | unused certificate fields |
| `penny.librechat_health.v1` | HTTPS GET `/api/health` on 443 with pinned certificate and SNI `penny.allports.tours`; no redirect | 1 connect, 1 handshake, 1 request, 512 B tx, 4 KiB rx, 8 s | status and closed health-state enum only | details, identifiers, build/config data, body |
| `penny.tabular_health.v1` | TLS GET `https://10.0.1.11:8045/health` with SNI `penny.allports.tours`; pinned certificate; no authorization | 1 connect, 1 handshake, 1 request, 512 B tx, 4 KiB rx, 8 s | status and closed health-state enum only | database details, schema names, diagnostics, body |
| `penny.meilisearch_health.v1` | HTTP GET `http://10.0.1.11:7700/health`; no redirect or authorization | 1 connect, 1 request, 384 B tx, 2 KiB rx, 8 s | status and closed health-state enum only | version, database content, body |
| `penny.mongo_express_presence.v1` | HTTP HEAD `http://10.0.1.11:8081/`; no redirect or authorization header | 1 connect, 1 request, 384 B tx, 2 KiB rx, 8 s | status, authentication challenge present/absent, exact product marker only when available in headers | realm text, cookies, page/body, database names |

The live profiles do not upload a file, choose an entity identifier, name a
server-local path, query a document, refresh a schema, read database records,
invoke an MCP server, or submit a chat prompt. RAG path handling, local embed,
entity authorization, conditional JWT fail-open, JWT debug logging, wildcard
CORS, tabular static-key/logging/query shape, HTTP cleartext proxying, and
enabled high-capability MCP configuration are offline detections or manual-only
cards. Secret-bearing configuration stays quarantined.

### APT-DC-01, APT-ENVCTRL, and PortCast

- Keep the existing DC SMB-signing action as a lab-only observation until its
  complete runtime dependency closure and parent metering pass admission. The
  one completed observation remains `not_observed`; it is not repeated.
- Keep Windows Defender collection blocked until an approved principal,
  credential grant, WinRM HTTPS certificate pin, exact commands, and attempt
  allowance exist. No credentialed DC action is part of this wave.
- Keep APT-ENVCTRL live automation disabled. Import reviewed offline source and
  configuration observations. Provide manual cards for every control action.
- Admit the PortCast Jellyfin public-identity GET only after the opaque advisory
  catalog, exact canonical URL, actual wire-byte receipt, parent reservations,
  package integrity, and independent review gates pass.

## Offline detector set

Offline detectors consume normalized observations, not target names or expected
answers. Each detector has vulnerable, hardened, ambiguous, partial, and wrong-
product fixtures.

| Family | Required predicates |
|---|---|
| File permissions | exact path class, service execution context, owner, group, mode, mount direction, and mutability; a writable file is not exploitable without a privileged consumer |
| Compose exposure | service, image identity, published address/port, network mode, volume source/target/mode, socket or host-root mount, environment-key presence only, and completeness |
| Source authorization | request-controlled field or identifier reaches a security decision or object lookup without an evidenced server-side ownership/role check |
| Source path handling | untrusted path component reaches join/open/write or remote fetch; dynamic proof stays manual-only |
| Authentication storage | exact hashing function and salt/work-factor evidence; never retain hash values or seed credentials |
| Token/session | entropy/binding/expiry/signature/claim/cookie predicates with explicit missing and conditional states |
| HTTP routing | state-changing method exposure, redirect target construction, cleartext service, CORS pair, proxy trust, and diagnostic/public route exposure |
| Component identity | product, full version/release, architecture, OS/package provenance, image digest, and evidence source; generic banner matches stay candidates |
| Windows/AD | SMB/LDAP posture, patch/build/supersedence, service/task ACL and Defender facts only when collection is complete and trusted |

No detector may inspect the external benchmark catalog. Tests replace target
names and addresses and include withheld variants. Changing the answer catalog
must not change a detector result.

## Manual-only cards

Create one card per dynamic condition that the safe profile set cannot prove.
At minimum, cards cover ShorePass cross-room IDOR and diagnostics file/URL
features; GPS traversal, arbitrary write, weather fan-out, and state updates;
CrewComms mass assignment, reset workflow, open redirect, and destructive GET
routes; Penny upload traversal, local-file embed, entity authorization, MCP
capabilities, and database access; Windows privileged checks; EnvCtrl control
inputs; and every exploit, crash, denial, spray, dump, or infrastructure action.

Each card contains:

1. exact benchmark/check identifier and affected component;
2. authorization and access prerequisites;
3. known side effects and why automation is blocked;
4. operator-controlled procedure at a descriptive level, without an executable
   harness payload for a blocked action;
5. expected positive, negative, incomplete, and stop evidence;
6. evidence fields that may be imported and fields that stay restricted;
7. cleanup owner and confirmation, if the human action changes state;
8. retest predicate and reviewer sign-off.

## Ordered implementation tasks

### Task 1: Close current trust gates

**Files:**

- Modify only the current PortCast advisory/catalog boundary and focused tests.
- Review the current Harbinger signed observation changes without overlapping
  edits.
- Finalize the external benchmark review outside Git.

- [ ] Make a validated advisory catalog unforgeable to ordinary callers, or
  revalidate every record and the pinned catalog digest at the detection
  boundary.
- [ ] Run focused PortCast tests, full Python 3.11 tests, mypy, and package
  integrity tests.
- [ ] Obtain independent read-only PortCast re-review.
- [ ] Obtain independent read-only Harbinger trust/reconnect re-review.
- [ ] Apply benchmark reviewer corrections without moving the expected catalog
  into the repository.

**Gate:** No unresolved High or Medium issue. No live request.

### Task 2: Add closed worker contracts and parent wire accounting

**Files:**

- Create `cptc_harness/profile_runtime/contracts.py`.
- Create `cptc_harness/profile_runtime/catalog.py`.
- Create `cptc_harness/profile_runtime/receipts.py`.
- Create `cptc_harness/profile_runtime/worker.py`.
- Create `cptc_harness/profile_runtime/README.md`.
- Modify `cptc_harness/broker.py`, `cptc_harness/ledger.py`,
  `cptc_harness/network.py`, `cptc_harness/audit_service.py`, and packaging
  manifests only after current shared-file edits are reconciled.
- Create focused tests under `tests/profile_runtime/`.

**Interfaces:**

- `load_profile(profile_id: str) -> SealedProfile`
- `reserve_profile_action(action: FrozenProfileAction) -> ReservationReceipt`
- `dispatch_profile(action: ReservedProfileAction) -> ProfileWireReceipt`
- `parse_profile(receipt: ProfileWireReceipt) -> TypedProfileObservation`
- `sign_observation(observation: TypedProfileObservation) -> SignedEnvelope`

- [ ] Write failures for caller-supplied host, port, method, header, payload,
  SNI, proxy, redirect, retry, executable, environment, and file path fields.
- [ ] Write failures for incomplete target/workflow/device reservation and for
  any dispatch before a durable intent fsync.
- [ ] Implement the four-operation closed union and sealed catalog lookup.
- [ ] Count actual connect, handshake, request, tx-byte, rx-byte, and capture
  events in the parent. Reject missing or contradictory child counters.
- [ ] Treat timeout, broken relay, process death, audit failure, cap exhaustion,
  and absent completion checkpoint as uncertain. Latch stop.
- [ ] Encrypt each output chunk before persistence and verify no plaintext
  artifact is created.
- [ ] Test stop before dispatch, during connect, during receive, with a busy
  writer, and with a failed writer.
- [ ] Test direct sockets, DNS, IPv6, redirect, proxy variables, inherited file
  descriptors, subprocess, and alternate executable escapes.

**Gate:** Synthetic adversarial suite passes. Zero target traffic.

#### Kali channel containment plan

The parent-owned channel is admitted only after OpenSSH enforces its egress
destination on the Kali operator VM. Add one reviewed `sshd_config.d` fragment
for sessions from the ephemeral Dell namespace address `10.0.254.253`. The
fragment permits local forwarding only to `10.0.1.30:8096`, denies remote
listeners, X11 forwarding, tunnels, and gateway ports, and ends with
`Match all`. It does not change a CPTC11 target or the Dell host.

Deliver the change as a three-step operator helper:

1. `plan` prints the exact proposed fragment, destination, source match,
   backup path, validation command, and reload command. It makes no change.
2. `apply` requires the exact Kali host identity, creates one private backup,
   writes through a private temporary file, runs `/usr/sbin/sshd -t`, replaces
   only the dedicated fragment, and reloads SSH only after validation. If the
   effective policy differs, restore the backup and keep the profile blocked.
3. `verify` runs `sshd -T` with the exact user, peer address, local address,
   and port context. It accepts only `PermitOpen 10.0.1.30:8096`, local-only
   TCP forwarding, no listen destination, no X11, no tunnel, and no gateway
   ports. It emits a fixed marker without configuration contents.

The live preflight executes only that fixed verification command. The nested
Paramiko object exposes a parameterless `open_portcast_channel()` method. It
does not expose a generic channel opener to the broker or model. If effective
server enforcement cannot be demonstrated, `scan-portcast` remains blocked.
Test plan, repeat apply, verify, invalid configuration rollback, connection
survival, alternate destination refusal, and restore from the Kali snapshot.

### Task 3: Implement MySQL and TLS common modules

**Files:**

- Create `cptc_harness/profiles/common_mysql/` with `catalog.json`, `parser.py`,
  `README.md`, and fixtures.
- Create `cptc_harness/profiles/common_tls/` with `catalog.json`, `parser.py`,
  `README.md`, and fixtures.
- Create `tests/profiles/test_common_mysql.py` and
  `tests/profiles/test_common_tls.py`.

- [ ] Parse only the first bounded MySQL server greeting. Validate packet
  length, sequence zero, protocol 10, NUL termination, version grammar, and
  capability lengths. Omit salt, connection ID, and plugin bytes.
- [ ] Parse a supplied TLS receipt. Accept only catalog-pinned SNI, TLS 1.2 or
  later, certificate SHA-256, SAN match, validity, and closed cipher names.
- [ ] Add malformed, oversized, truncated, wrong-protocol, credential-bearing,
  and parser-confusion fixtures.
- [ ] Document that MySQL sends no client handshake and TLS performs no HTTP.

**Gate:** Pure parser and contract tests pass. Zero target traffic.

### Task 4: Implement ShorePass profiles

**Files:**

- Create `cptc_harness/profiles/shorepass/` with `catalog.json`, `parsers.py`,
  `detectors.py`, `README.md`, and synthetic fixtures.
- Create `tests/profiles/test_shorepass_profiles.py`.

- [ ] Encode the seven exact ShorePass operations in this plan.
- [ ] Implement strict JSON, header, certificate, pair, and marker parsers.
- [ ] Add positive, hardened, redirect, body-reflection, oversized, malformed,
  partial, timeout, and wrong-host fixtures.
- [ ] Prove `/api/id` results retain only a keyed equality relationship.
- [ ] Add offline detectors and manual cards for the remaining reviewed source
  and configuration conditions.

**Gate:** Independent profile review passes. Zero target traffic.

### Task 5: Implement GPS profiles

**Files:**

- Create `cptc_harness/profiles/gps/` with `catalog.json`, `parsers.py`,
  `detectors.py`, `README.md`, and synthetic fixtures.
- Create `tests/profiles/test_gps_profiles.py`.

- [ ] Encode the six exact GPS operations in this plan.
- [ ] Allow only the `gps` realm and discard full OIDC endpoints.
- [ ] Treat Swagger as presence only. Do not crawl routes from the live UI.
- [ ] Retain only navigation schema presence. Reject a parser output containing
  any coordinate or field value.
- [ ] Add offline detectors and manual cards for every reviewed condition.

**Gate:** Independent profile review passes. Zero target traffic.

### Task 6: Implement CrewComms profiles

**Files:**

- Create `cptc_harness/profiles/crewcomms/` with `catalog.json`, `parsers.py`,
  `detectors.py`, `README.md`, and synthetic fixtures.
- Create `tests/profiles/test_crewcomms_profiles.py`.

- [ ] Encode the four exact CrewComms operations in this plan.
- [ ] Require one exact RESP reply for Redis and reject additional frames.
- [ ] Retain cookie attribute names only. Reject cookie names and values from
  the typed output.
- [ ] Add source detectors without retaining account records or hash values.
- [ ] Add manual cards for stateful proofs.

**Gate:** Independent profile review passes. Zero target traffic.

### Task 7: Implement Penny profiles

**Files:**

- Create `cptc_harness/profiles/penny/` with `catalog.json`, `parsers.py`,
  `detectors.py`, `README.md`, and synthetic fixtures.
- Create `tests/profiles/test_penny_profiles.py`.

- [ ] Encode the six exact Penny operations in this plan.
- [ ] Map health bodies to a closed enum and discard every detail value.
- [ ] Treat an authentication challenge as a Boolean and discard its realm.
- [ ] Prove no catalog entry can name an upload, document, entity, local path,
  query, record, schema, MCP, or refresh operation.
- [ ] Add offline detectors and manual cards for every reviewed condition.

**Gate:** Independent profile review passes. Zero target traffic.

### Task 8: Build benchmark-independent coverage

**Files:**

- Create `testing/cptc11_benchmark/coverage.py`.
- Create `testing/cptc11_benchmark/comparison.py`.
- Create `tests/test_cptc11_benchmark_coverage.py`.
- Keep expected catalog files in the restricted external state root.

- [ ] Validate the corrected expected catalog, asset image provenance, advisory
  date, evidence references, automatic/manual eligibility, and reviewer state.
- [ ] Reject an expected entry from runtime/package/model inputs.
- [ ] Build target x check x account-role results with complete, incomplete,
  unsupported, manual-only, candidate, observed, not-observed, and confirmed
  states.
- [ ] Compare after collection in a process that cannot alter detector output.
- [ ] Test renamed targets, randomized addresses, withheld fixtures, changed
  answers, duplicate entries, and reclassification attempts.
- [ ] Produce separate automatic true-positive, automatic miss, false-positive,
  manual-covered, unsupported, and unresolved totals.

**Gate:** Every reviewed benchmark entry has exactly one visible disposition.

### Task 9: Connect signed observations to Harbinger

**Files:**

- Modify only the Harbinger signed harness importer and its dedicated README
  after its trust-boundary re-review passes.
- Add synthetic contract fixtures to both private repositories and verify the
  same contract hash.

- [ ] Require execution provenance, all resource counters, parser/catalog/
  runtime hashes, evidence digest, and valid signature.
- [ ] Show metadata only before trust approval. Do not expose or transfer the
  raw signed envelope as ordinary evidence.
- [ ] Map candidate, observed, not-observed, incomplete, blocked, and manual
  states without turning a scanner candidate into a confirmed finding.
- [ ] Preserve source action and evidence references in Harbinger revisions.
- [ ] Verify readiness before SSE reconnect enables mutations.

**Gate:** Harbinger backend, frontend, contract, reconnect, and security tests
pass. No live import yet.

### Task 10: Package and independent review

**Files:**

- Modify `docs/harness/PACKAGE-CONTENTS.json`,
  `docs/harness/THIRD-PARTY-INVENTORY.json`, `pyproject.toml`, and
  `scripts/package-harness.py` once, after all feature files stabilize.
- Update `docs/harness/READINESS.md` and `docs/harness/RELEASE-STATUS.json`.

- [ ] Recompute every source/resource/parser/catalog hash.
- [ ] Verify excluded benchmark, raw evidence, credentials, development state,
  caches, and decrypted files are absent from Git and release archives.
- [ ] Run Gitleaks and exact forbidden-literal checks.
- [ ] Run full pinned Python 3.11 tests, mypy, frontend tests, typecheck, build,
  packaging tests, and archive extraction review.
- [ ] Obtain independent correctness and security review.

**Gate:** No unresolved High or Medium issue and no unexpected package file.

### Task 11: Live Dell acceptance, one action at a time

- [ ] Revalidate Dell/Kali pins, VM identities and states, assignment, clock,
  storage, ZFS pools, active journals, stop state, relay isolation, and existing
  services before each action.
- [ ] Freeze one target/profile action. Review exact traffic estimate and
  encrypted output reservation.
- [ ] Persist intent and reservations. Dispatch once. Record actual counters.
- [ ] Stop on throttle, instability, unexpected challenge, redirect, size cap,
  timeout, certificate mismatch, target identity mismatch, audit failure, or
  incomplete capture.
- [ ] Parse, sign, and import the typed result only after receipt validation.
- [ ] Compare externally to the benchmark. Do not alter a detector to recognize
  an answer by target name or expected result.
- [ ] Repeat only for the next independently admitted profile.

Run order:

1. PortCast public identity.
2. ShorePass HTTP redirect and Traefik version.
3. CrewComms root and Redis ping.
4. GPS Swagger, Keycloak metadata, navigation presence, SeaRoute identity, and
   MySQL greeting.
5. Penny redirect, service health/presence, and TLS.
6. ShorePass TLS-dependent profiles and MySQL greeting.

**Gate:** Each claimed profile has fixture evidence, independent review, one
bounded live receipt, correct typed import, and no unexplained traffic.

### Task 12: Final acceptance report

- [ ] Reconcile every independently reviewed expected weakness.
- [ ] Separate original scenario weaknesses from later advisory candidates.
- [ ] Report automatic detections, manual-only coverage, false positives,
  incomplete checks, unavailable access, unsupported conditions, and misses.
- [ ] Do not use the phrase `finds every vulnerability` unless the frozen
  benchmark has no miss and every entry is accounted for.
- [ ] State that benchmark completeness does not cover unknown vulnerabilities.
- [ ] Keep raw evidence local and encrypted. Commit source, synthetic fixtures,
  documentation, and safe manifests only. Push only to the private remote after
  repository privacy and publication checks pass.

## Acceptance commands

Use the repository's pinned Python 3.11 environment. Run focused tests after
each task and the full suite only after shared manifests stabilize.

```text
python -m pytest -q tests/profile_runtime tests/profiles
python -m pytest -q tests/test_cptc11_benchmark_coverage.py
python -m pytest -q
python -m mypy cptc_harness/profile_runtime cptc_harness/profiles testing/cptc11_benchmark
python scripts/package-harness.py --verify-only
```

Harbinger acceptance:

```text
python -m pytest -q
npm test -- --run
npm run typecheck
npm run build
```

The live runner is not exposed as a generic command in this plan. The operator
uses the guarded assessment-wave interface. That interface displays the exact
profile, target, traffic estimate, reservations, and stop state before dispatch.
