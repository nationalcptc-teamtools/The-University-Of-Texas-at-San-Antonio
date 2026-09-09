# Bounded scanner and verification architecture

Approved for private development on 2026-09-09. This plan applies only to the
guarded CPTC harness. It does not add scanner execution to Harbinger or Merlin.

## Purpose

The harness will convert trusted observations into a finite list of scanner or
verification candidates. An operator can review and freeze one exact action.
The policy broker then enforces the target, module, protocol, traffic, time,
evidence, and approval limits.

The product name for controlled proof actions is **Bounded Verification
Actions**, or **BVA**. A BVA can verify one known condition on one approved
target. It cannot select a payload, create a session, make a persistent change,
or confirm a finding without human review.

Authorization for a CPTC event or an assessment does not admit all installed
scanner content. The immutable profile catalog is the execution allowlist.
Unknown behavior remains unavailable until a later reviewed release.

## Operator flow

```text
trusted typed observation
        |
deterministic candidate mapping
        |
operator reviews exact target, effects, and limits
        |
canonical plan and policy hashes are frozen
        |
ledger reserves all allowances before dispatch
        |
broker starts one contained worker and one network relay
        |
typed result plus encrypted raw evidence and traffic receipt
        |
human reviews candidate, observed condition, or limitation
```

The model can request a catalog lookup or suggest a candidate. It cannot run a
scanner, create an approval, change a plan, add a module, set a target, or read
raw evidence. Initial scanner execution is available only through the operator
CLI. MCP can show plans, status, and stop state after those interfaces receive
separate tests. MCP does not expose Metasploit, NSE, or BVA execution.

## Control surfaces

Use the harness as the only execution authority.

- The operator CLI prepares, freezes, runs, stops, and reviews an action.
- The policy broker validates every request again before target traffic.
- The ledger stores the reservation, attempt intent, actual traffic events,
  terminal receipt, and uncertainty state.
- The audit service stores UTC events and encrypted permitted output.
- Harbinger can later import a reviewed signed derivative. It does not control
  the scanner.
- Merlin receives only a human-reviewed finding lead from Harbinger.

Do not add a scanner console, Metasploit RPC service, or direct Harbinger runner.
These options duplicate the authorization and stop boundaries.

## Trust boundaries

Treat model text, target output, scanner output, CVE text, and imported labels as
untrusted data. Only these items grant authority:

1. The current operator-owned SOW, ROE, scope, target profile, and time window.
2. An exact profile in the checked-in catalog with a verified catalog hash.
3. A broker-generated target and network grant.
4. A durable reservation that covers the complete declared maximum.
5. An action-specific approval when the profile is a proof.

Nmap, NSE Lua, Ruby, and Metasploit code run as untrusted third-party workers.
The worker has no route to the assessment network. A parent-owned relay is its
only target path. The worker receives no credentials, general filesystem,
provider connection, callback listener, proxy, package update path, or arbitrary
arguments.

## Versioned profile contract

`ScannerProfile` is a strict, immutable contract. Unknown and missing fields are
errors. The profile contains:

- Exact profile ID, engine family, upstream module ID, check ID, tier, and
  admission state.
- Package or release identity, source path, source hash, dependency or tree
  hashes, license identity, and distribution decision.
- One fixed runner and its fixed options. Target values come only from the
  broker. The request cannot contain command strings, paths, scripts, or scanner
  flags.
- Exact protocol, port, target scheme, prerequisites, and compound network
  grant.
- Declared protocol effects and an explicit no-authentication, no-retry, and
  no-fallback policy.
- Separate ceilings for TCP connect attempts, UDP datagrams, protocol requests,
  transmitted bytes, received bytes, wall time, CPU time, process count, output,
  and authentication attempts.
- Typed parser output, completeness rules, candidate mappings, evidence class,
  and required approval type.

Admission states are `design_only`, `synthetic_only`, `live_admitted`,
`blocked`, and `manual_only`. Installed software does not change the state.

## Initial finite catalog

| Profile | Initial state | Exact behavior and maximum |
|---|---|---|
| `network.nse_smb2_security_mode` | `synthetic_only` | One IPv4 host. TCP/445 plus UDP/137. Two TCP attempts, one UDP datagram, two protocol requests, 4 KiB sent, 16 KiB received, 15 seconds wall time, 10 seconds CPU, one process, 16 KiB output, no authentication. |
| `network.nse_smb2_time` | `synthetic_only` | Same compound grant and limits. |
| `network.msf_http_version` | `design_only` | HTTP on TCP/80. One connect and one fixed `GET /`, 4 KiB sent, 16 KiB received, 10 seconds wall and CPU time, one process, 16 KiB output, no authentication or redirect. |

The two NSE profiles need two TCP attempts because Nmap first confirms port 445
and the NSE library then opens the SMB connection. The pinned Nmap library also
attempts one NetBIOS name query on UDP/137. It then sends one SMB2 negotiate
message. The relay must reject SMB session setup, tree connect, transactions,
authentication, and file operations.

The Metasploit profile remains design-only until the exact framework source,
Ruby dependency closure, module, runner, and license set are pinned. The local
module hash alone is not enough.

Categories, wildcards, `-sC`, runtime NSE paths, `--datadir`, `--script-args`,
Metasploit console text, resource scripts, RPC, module strings, datastore
options, payloads, handlers, sessions, callbacks, and `ForceExploit` are not
contract fields and cannot be requested.

## Deterministic mapping

Candidate mapping uses only typed observations from trusted parsers.

- An SMB service on the exact admitted port can suggest the two SMB NSE
  observations when both TCP/445 and UDP/137 are within the approved grant.
- An HTTP service on port 80 can suggest the existing bounded HTTP observation.
  The Metasploit profile appears only when an operator explicitly selects its
  design candidate.
- An MS17-010 or CVE-2017-0144 candidate creates a manual review card. It does
  not create an execution plan.

A CVE string, port number, scanner label, or model statement cannot select a
proof by itself. The same sorted observations and catalog revision must produce
the same canonical plan bytes.

## Connected relay

The existing Nmap connect bridge reports only open or closed state. Keep it for
the one-port inventory profile. Add a separate connected relay for NSE and later
Metasploit profiles.

The worker runs under Bubblewrap in a network namespace without a veth or
external route. It inherits one local control channel. The native shim submits a
fixed endpoint request. The parent validates the request against the frozen
profile and broker grant.

For a data connection, the parent:

1. Stores the attempt intent and reservation before any external socket call.
2. Creates and connects the exact approved external socket.
3. Creates a local socket pair.
4. Sends only the worker side through `SCM_RIGHTS`.
5. Relays data between the local and external sockets.
6. Counts each connection, datagram, protocol message, and byte in the parent.
7. Applies the protocol validator before forwarding client data.
8. Stops relaying at the first limit, forbidden message, deadline, stop, or
   ambiguous failure.

The relay preserves UDP message boundaries. The SMB validator accepts one
NetBIOS node-status query and one SMB2 negotiate request. It buffers fragmented
writes before it validates a complete message. It does not log packet contents
to the readable transcript.

The worker mount set contains only its reviewed executable, required read-only
libraries and data, empty temporary directories, and the fixed configuration.
Clear the environment. Deny extra processes, namespace changes, raw sockets,
unexpected descriptors, and later program execution. No direct worker socket
can reach an external interface.

If target traffic may have occurred and the worker, relay, audit, capture, or
cleanup path fails, mark the action uncertain. Consume the complete reservation,
close every relay, kill the worker process group, latch stop, and require human
review. Never retry or resume the action automatically.

## Metasploit runner

Do not expose `msfconsole`, MCP, RPC, a console command, or a resource file. Use
one fixed Ruby runner after its complete runtime closure is pinned. The runner
loads only the selected module from read-only paths and receives a sealed config
with the profile ID and broker-approved target.

The first candidate is `auxiliary/scanner/http/http_version`. The relay accepts
one HTTP/1.1 `GET /` request to the exact host and port. It rejects credentials,
request bodies, redirects, proxy use, callback configuration, and a second
request.

Future exploit verification uses a separate BVA runner. It can call only a
reviewed module's `check` path. It cannot call `run`, `exploit`,
`exploit_simple`, or create a payload, handler, or session. The initial BVA proof
catalog is empty.

`auxiliary/scanner/ssh/ssh_version` is blocked because the current module can
retry with deprecated algorithms. `auxiliary/scanner/smb/smb_version` is blocked
because it can try several dialects, use port 139, and authenticate.
`auxiliary/scanner/smb/smb_ms17_010` remains manual-only because the module logs
on, connects to `IPC$`, sends a transaction, enables extra implant checks by
default, and declares unknown effects in its metadata.

## Approval and result states

An observation wave binds the plan hash, policy revision, release hash, target,
profile, and maximum resources. Every Metasploit action is operator-only.

A future BVA approval also binds the request, action, candidate, module and
manifest hashes, exact target, generated arguments, expected effects, evidence
requirements, operator, and expiry. An approval cannot admit a manual-only or
unknown-impact module.

Results remain distinct:

- `candidate`: a deterministic relationship needs more evidence.
- `observed`: the admitted check completed and its predicate matched.
- `not_observed`: the check completed with sufficient negative evidence.
- `incomplete`, `unsupported`, or `uncertain`: no defensible conclusion.
- `confirmed`: a human accepted the evidence and impact.

Scanner output never creates a confirmed finding.

## Test order and release gates

Implement in this order:

1. Strict design-only contracts, catalog hashes, deterministic mapping, and
   static fixtures.
2. Durable connection, datagram, request, byte, deadline, and crash accounting.
3. Loopback stream and datagram relays with fake workers and packet-count
   reconciliation.
4. Native shim tests for descriptor transfer, malformed requests, direct-socket
   isolation, process denial, stop, deadline, and output failure.
5. Exact NSE commands and parsers with synthetic vulnerable, hardened, partial,
   malformed, unsupported, and malicious-output fixtures.
6. Pinned Metasploit runtime and fixed HTTP runner tests.
7. Operator plan, freeze, run, status, stop, evidence review, and signed export.
8. Independent review, Kali VM tests, then one profile and one approved lab
   endpoint at a time from the operator guest.

Tests must reject hash drift, categories, wildcards, paths, arbitrary options,
credentials, retries, fallbacks, callbacks, payloads, sessions, console and RPC
use, stale approvals, wrong targets or ports, DNS changes, redirects, proxy
attempts, extra connections, forbidden SMB commands, resource overruns, worker
crashes, stop races, audit failure, full disk, and replayed plans.

Do not promote a profile to `live_admitted` until its fixtures, containment,
packet counts, encrypted evidence, audit chain, target health, and stop behavior
pass independent review and an approved live test. Promotion is a reviewed source
change. Runtime input cannot change it.
