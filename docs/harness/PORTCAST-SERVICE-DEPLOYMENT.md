# PortCast canonical service deployment

Live admission requires an independent review and a root-owned installation.
The application does not create this state. The deployment helper does not
start the service or send a target request.

Use [`deployment/manage-portcast-service.py`](../../deployment/manage-portcast-service.py)
for the deployment operations. Run it with the manifest SHA-256 that the
independent reviewer approved. Do not calculate or approve that value inside a
service startup command.

## Required state

Prepare these items before `apply`:

- The reviewed source tree is complete and has no symlinks in the release file
  set.
- The sealed RootDirectory runtime, static launcher, CPython standard library,
  native extensions, bubblewrap, age, and their native libraries match the
  release manifest.
- `/var/lib/cptc-harness/portcast-live-v1` is an initialized `root:root`
  directory with mode `0700`. Keep the deployment lock, journal, release
  history, trust records, and encrypted credentials root-owned. The schema-v7
  admission uses `/var/lib/cptc-harness/portcast-live-v7` as a root-owned parent
  and creates its `runtime/` child, owned by `_cptc-portcast:cptc-harness`
  with mode `0700`, plus a root-owned `admission/` directory with mode `0700`
  and a read-only admission projection directory.
- Keep the v3, v4, and v5 state trees unchanged. The service mounts their
  required inputs read-only. The consumed v5 private marker must remain in
  place. Its projection and runtime must remain empty.
- Schema v6 expired before deployment. The v6 state path must be absent. The
  manager refuses v7 if it finds any v6 state. It records that verified absence
  as one immutable root-owned v6-unused receipt under the v7 state tree.
- The old v1 ledger at
  `/var/lib/cptc-harness/portcast-live-v1/runtime/ledger/cptc11-dell-validation`
  is read-only. The old audit directory and v2 result are also read-only. The
  fresh v7 ledger is
  `/var/lib/cptc-harness/portcast-live-v1/runtime/v7/ledger/cptc11-dell-validation-portcast-v7`
  inside the service root. The service has no broad v1 runtime mount.
- The start gate creates one root-owned `0600` marker in
  `/var/lib/cptc-harness/portcast-live-v7/admission` with `O_CREAT|O_EXCL`.
  It binds the anchored release, v7 plan, and v7 action. The nonroot service
  can read the root-owned projection but cannot change its `0755` parent or
  `0444` marker. A second start, a missing or
  tampered marker, or a plan/action/release mismatch blocks startup.
- The release contains the reviewed public `age` recipient. It does not contain
  the private identity. The service verifies the recipient and the sealed
  `age` executable before it accepts a local request.
- `/etc/cptc-harness/credentials/cptc11-dell.cred` and
  `/etc/cptc-harness/credentials/cptc11-kali.cred` are nonempty, regular,
  root-owned systemd encrypted-credential blobs. Remove all group and other
  permissions.
- Install `deployment/portcast-live-v1.sysusers` through the reviewed system
  sysusers workflow before `apply`. It creates the locked, dynamically
  allocated `_cptc-portcast` account with `cptc-harness` as its sole group.
  Do not select numeric UID or GID values. The deployment helper resolves and
  validates this identity before it changes a release path. Only the
  frozen-plan operator can use the service socket.

Create the encrypted blobs through the approved local systemd credential
workflow. Do not put plaintext credentials in a command argument, environment
variable, file in this repository, or deployment log. The helper checks file
metadata only. It never reads or prints credential contents.

## Host clock attestation

Before a production service start, create the short-lived host clock record as
root:

```sh
sudo /usr/bin/python3.14 -I -S deployment/manage-portcast-service.py attest-clock
```

The command accepts no path or user arguments. It calls the fixed host
`timedatectl` commands with a 30-second deadline, verifies synchronization and
an offset of at most two seconds, and writes
`/run/cptc-harness-clock/portcast-live-v1.json` atomically. The file
is root-owned with mode `0440`, bound into the private service root as one
read-only file, and expires after 30 seconds of the current boot's monotonic
clock. A boot identity change, malformed record, clock jump, or expiry blocks
active work. The service does not access host D-Bus and does not mount a broad
`/etc` tree. Run this command again for a later operating window.

The audit writer and broker receive one shared `ClockService` from the opened
runtime. They use the same validated attestation and cannot refresh it or
change the host clock.

## Plan

Set the reviewed digest in a task-specific shell variable. Then inspect the
complete proposed installation without root access:

```sh
PORTCAST_MANIFEST_SHA256='<reviewed-manifest-sha256>'
/usr/bin/python3.14 -I -S deployment/manage-portcast-service.py plan \
  --expected-manifest-sha256 "$PORTCAST_MANIFEST_SHA256"
```

The command verifies the source file hashes, sealed Python runtime, exact
interpreter, exact ELF membership, ELF hashes, and the complete `DT_NEEDED`
closure. Its JSON output identifies all fixed
paths and states that it will not start the service or create target traffic.

## Apply

Run `apply` from the reviewed source tree:

```sh
sudo /usr/bin/python3.14 -I -S deployment/manage-portcast-service.py apply \
  --expected-manifest-sha256 "$PORTCAST_MANIFEST_SHA256"
```

Stop the unit before `apply`. The helper refuses an active unit and takes an
exclusive deployment lock before it changes files. The static launcher holds
a shared nonblocking lock for the complete service lifetime. A start attempted
during deployment fails closed. The lock is root-owned, group-readable by
`cptc-harness`, and not group-writable. This lets the non-root service take a
shared lock without letting it change deployment control data.

The helper copies only manifest-listed files. It installs the release at
`/usr/lib/cptc-harness/portcast-live-v1`, as a private systemd
`RootDirectory`, the reviewed unit at
`/etc/systemd/system/portcast-live-v1.service`, and the supplied reviewed hash
at `/etc/cptc-harness/trust/portcast-live-v1.sha256`. Installed release files
are read-only and root-owned. The static launcher, sealed Python interpreter,
`bwrap`, `age`, and dynamic loader are the exact executable allowlist and use
mode `0555`. Every other regular release file, including shared libraries and
data, uses mode `0444`; every release directory uses mode `0555`. Verification
rejects any mode drift. The helper never generates the anchor from the installed
tree.

Each durable replace is recorded in a local deployment journal and followed by
a parent-directory sync. A failed replacement is compensated. If compensation
fails, the journal remains and later changes are blocked for manual recovery.

An upgrade retains one `.previous` release, unit, sysusers policy, and anchor.
Before another apply, verify and archive that complete generation with the
digest accepted by its reviewer:

```sh
sudo /usr/bin/python3.14 -I -S deployment/manage-portcast-service.py \
  retire-previous \
  --expected-previous-manifest-sha256 '<reviewed-previous-manifest-sha256>'
```

`retire-previous` refuses an active service, partial artifacts, a digest
mismatch, unsafe metadata, an existing destination, or an unresolved journal.
It verifies the complete previous release plus its unit, identity policy, and
trust anchor. It moves only those four fixed `.previous` paths to local names
bound to the full manifest digest. It records a root-only UTC receipt under
`deployment-history`. A repeated command with the same digest verifies the
archived files and receipt before it reports that the generation was already
retired.

An early development manifest can omit the sysusers policy pin. The operation
refuses that generation unless the reviewer supplies the exact observed policy
digest separately:

```sh
sudo /usr/bin/python3.14 -I -S deployment/manage-portcast-service.py \
  retire-previous \
  --expected-previous-manifest-sha256 '<reviewed-previous-manifest-sha256>' \
  --expected-legacy-sysusers-sha256 '<reviewed-legacy-sysusers-sha256>'
```

This exception applies only when the reviewed previous manifest has no
sysusers entry. The helper rejects the extra argument when the manifest already
pins that file. The receipt records `operator-reviewed-legacy` as the pin
source and preserves the observed digest with the other artifact hashes.

The operation records each replacement in the deployment journal. If a move or
receipt write fails, it restores completed moves. A compensation failure keeps
the journal and blocks later changes for manual recovery. The operation does
not start or stop the service, send target traffic, change credentials, or
remove the state directory.

## Verify

Verify the installed release before systemd loads it:

```sh
sudo /usr/bin/python3.14 -I -S deployment/manage-portcast-service.py verify
sudo /usr/bin/systemctl daemon-reload
sudo /usr/bin/systemctl start portcast-live-v1.service
sudo -u moriz /usr/bin/python3.14 -I -S \
  deployment/manage-portcast-service.py inspect
```

`verify` checks the external anchor, every installed release and runtime file,
the native closure, the installed unit hash, the exact static launcher, the
credential metadata, and state-directory metadata. It also runs the static
launcher with `--verify-startup-only` in a private bubblewrap user, network,
PID, IPC, and UTS namespace with an empty environment. The isolated startup
shape mounts the installed application, external trust anchor, and deployment
lock read-only and supplies the `/proc`, `/dev`, `/sys`, and `/run` API
filesystems used by the production `RootDirectory`. The network namespace has
no target route. The startup test imports only the anchored release and sealed
runtime. It does not load credentials, open the service socket, start a broker,
or connect to Dell, Kali, or a target.

The service manager runs a privileged, bounded `--admit-start` pre-start gate
before the nonroot service process. The gate verifies the anchored release,
v7 plan, exact consumed v5 state, and immutable v6-unused receipt. It
atomically creates the external
one-start marker and exits before it
can load credentials, open the socket, or create the broker. A second start,
missing or tampered marker projection, or a plan/action/release mismatch blocks
the unit. The gate uses only fixed local paths and has no network access.

The canonical service runs as `_cptc-portcast:cptc-harness`, retains an empty
capability set and `NoNewPrivileges=yes`, and receives only its `runtime/`
subtree as writable. It verifies its nonroot effective UID/GID, exact group
set, service-owned runtime metadata, and root-owned, root-group, mode-`0440`
systemd credential files before it opens a socket. The socket inherits the service user and
`cptc-harness` group; the service does not rewrite its ownership.

On the first start, the service creates the evidence runtime in a private
staging directory. It validates the policy, public recipient, executable path
and hash, directory layout, ownership, and modes. It then renames the complete
directory into place and syncs the parent directory before it opens the local
socket. Publication uses the Linux no-replace rename operation. A competing
file, directory, or link blocks startup and is preserved. The service then
opens the SQLite ledger and audit writer, performs recovery, checks SQLite and
audit integrity, and retains that one runtime for the service lifetime. It
does all of this before it loads target credentials or binds the socket.
The v7 application runtime is the fixed logical path
`/var/lib/cptc-harness/portcast-live-v1/runtime/v7/runtime`. Its host storage
is `/var/lib/cptc-harness/portcast-live-v7/runtime`. The failed v3 through v5
inputs and the v6-unused receipt are mounted read-only. The contained audit worker receives only the v7
`audit/` child. The current ledger is the fixed
`runtime/v7/ledger/cptc11-dell-validation-portcast-v7` directory. Historical
audit, result, ledger, v3, v4, and v5 paths are read-only
inputs.

The coordinator loads and hash-checks the v1 through v5 plans. It verifies the
v2 audit chain and result, the empty v3 and v4 output state, and the exact v4
continuation row. It requires the predecessor mounts and historical ledger to
be read-only. These checks run before credential loading, socket binding, or
broker creation. It uses the v7 runtime for new audit, ledger, and result
records. It also validates the root-produced canonical v5 predecessor receipt
before runtime creation and before broker creation. A changed, missing, or
writable historical input blocks startup. The v2 through v5 actions are never
retried.

A restart is blocked by the external one-start marker, even if the writable v7
runtime, audit directory, or ledger is deleted or replaced. The service does
not repair or replace a partial final runtime or a corrupt ledger or audit
chain. Incomplete staging
directories are never treated as authority and remain available for review
after an abrupt stop. The request handler cannot provision or reopen storage;
both `inspect` and `execute` use the already-open startup authority.

The public recipient is sealed in the frozen plan and service source. A change
to either value requires a new plan hash, release seal, review, and deployment.
The service does not read the operator's private `age` identity.

The canonical service gives each accepted peer a fixed idle receive deadline.
It contains a peer disconnect or broken response pipe and continues to serve
the next authorized request. The service launches the network broker through
the sealed bubblewrap binary. That child receives private user, PID, IPC, and
UTS namespaces, no effective capabilities, the fixed read-only release and
ledger mounts, an empty environment, and only standard descriptors. The
service sends credential descriptors only after the child reports the exact
zero-capability sandbox state. The broker shares the service network namespace
so the unit's `IPAddressDeny=any` and single Dell `/32` allowance remain the
network authority; the worker cannot select another route or destination.

The separate `inspect` command runs as the fixed authorized operator. The root
deployment identity is refused. It sends only the fixed local `inspect`
request and cannot send `execute`. The response contains state metadata only.
A failed or unavailable inspection fails verification and does not retry.
After startup preparation succeeds, `inspect` validates existing state without
creating or reopening a policy, ledger, audit writer, or evidence runtime.

Before the first action, `inspect` returns `null`. After an action has durable
admission history, it returns a blocked replay status and this fixed execution
object:

```json
{
  "reservation_state": "complete",
  "attempt_count": 1,
  "attempt_state": "complete",
  "transport_counters": {
    "tcp_connects": 1,
    "udp_datagrams": 0,
    "protocol_requests": 1,
    "tx_bytes": 103,
    "rx_bytes": 282
  },
  "wire_counters_verified": true,
  "result_receipt_present": true
}
```

The receive-byte value depends on the bounded response. It must be from 1 to
8192. A clean first execution also requires `status=complete`,
`reservation_state=complete`, one complete attempt, one connection, one
request, 103 transmitted bytes, a verified wire-counter match, a result
receipt, `receipt_outcome=complete`, and `cleanup_status=passed`. A later
inspection reports `status=blocked` because replay is denied. It keeps the
same completed execution metadata. Null counters mean the service has no
verified attempt counters. They do not mean zero traffic.

The response does not contain response bodies, headers, evidence paths,
evidence hashes, credentials, stdout, or audit contents.

Review the JSON fields `manifest_sha256`, `installed_unit_sha256`,
`startup_smoke`, `clock_admission_checked`, `inspect`, `target_traffic`, and
`state_preserved`. `release-only-no-target` verifies the installed release and
isolated startup path. It deliberately reports `clock_admission_checked: false`.
Create a fresh clock attestation immediately before the separate acceptance or
production start gate. Keep the
output with the deployment review record.

## Roll back

Stop the service before rollback:

```sh
sudo /usr/bin/systemctl stop portcast-live-v1.service
sudo /usr/bin/python3.14 -I -S deployment/manage-portcast-service.py rollback
sudo /usr/bin/systemctl daemon-reload
sudo /usr/bin/python3.14 -I -S deployment/manage-portcast-service.py verify
```

Rollback refuses to run while the service is active. It restores the complete
`.previous` release, unit, sysusers policy, and anchor as one reviewed set. It
moves the newer set to `.rolled-back` paths for investigation. It preserves
`/var/lib/cptc-harness/portcast-live-v1` and both encrypted credential blobs.
Do not delete those records as part of rollback.

## Release boundary

Before `apply`, independently review the final manifest, interpreter pin,
native runtime closure, service unit, frozen plan, source hashes, dependency
licenses, and deployment-helper hash. Any change to a listed file requires a
new manifest and review.

Private packaging also runs a source-compliance gate. Every redistributed
copyleft component must name a present, hashed corresponding-source archive or
a reviewed immutable offer with a hashed local notice. Until those records are
complete, packaging fails before it creates an artifact. Do not treat copied
license text as corresponding source.

Do not copy a mutable development checkout into the installed path. Do not
enable automatic restart. Do not use `execute` as a deployment smoke test.
Keep the live action blocked until the independent reviewer accepts the final
source and the operator authorizes the current operating window.

The helper has a durable replacement journal and refuses a new deployment when
an unresolved journal exists. It does not diagnose or repair an arbitrary
partially modified installation. A release operator must review such state and
restore one complete generation before another apply. This deterministic
reconciliation check remains a release blocker until its system-level recovery
exercise is accepted.

Before live admission, run the fixed privileged synthetic acceptance. The
controller file is not executable. Invoke it only through the manifest-pinned
interpreter. First inspect the no-write plan:

```sh
/usr/bin/python3.14 -I -S deployment/portcast-systemd-acceptance.py plan \
  --expected-manifest-sha256 "$PORTCAST_MANIFEST_SHA256"
```

After independent review, start one synthetic run:

```sh
sudo /usr/bin/python3.14 -I -S \
  deployment/portcast-systemd-acceptance.py run \
  --expected-manifest-sha256 "$PORTCAST_MANIFEST_SHA256"
```

Record the returned `run_id`. Verify the durable receipt, or reconcile any
ambiguous result without starting the unit again:

```sh
sudo /usr/bin/python3.14 -I -S \
  deployment/portcast-systemd-acceptance.py verify --run-id '<run-id>'
sudo /usr/bin/python3.14 -I -S \
  deployment/portcast-systemd-acceptance.py reconcile --run-id '<run-id>'
```

When review is complete, stop the temporary instance and remove its ephemeral
unit. Cleanup preserves the receipt, journal, and encrypted synthetic artifact:

```sh
sudo /usr/bin/python3.14 -I -S \
  deployment/portcast-systemd-acceptance.py cleanup --run-id '<run-id>'
```

If cleanup itself reports an uncertain result, do not call `cleanup` again.
Inspect and use the journal-bound recovery command. It accepts only a terminal
inactive or failed unit whose exact runtime-unit hash matches the original
`unit-installed` event. It never starts or stops a unit:

```sh
sudo /usr/bin/python3.14 -I -S \
  deployment/portcast-systemd-acceptance.py recover-cleanup --run-id '<run-id>'
```

The controller refuses an active or unknown production-unit state. It accepts
no command, path, unit property, environment, credential, or target argument.
An ambiguous start, including a nonzero result, timeout, process error, or
unexpected controller exception, is durably marked uncertain and is never
retried automatically. An ambiguous cleanup follows the same no-retry rule.
The temporary unit uses the installed `RootDirectory`, the same dynamically
resolved `_cptc-portcast:cptc-harness` identity, an empty
capability set, `PrivateNetwork=yes`,
`RestrictAddressFamilies=AF_UNIX AF_NETLINK`, and
`IPAddressDeny=any`. Its root-owned run journal is separate from the only
writable `worker/` subtree, including `worker/audit/`. It starts the fixed audit worker, encrypts one constant
synthetic record, and records effective capabilities, network namespace,
complete interface set, descriptor set, encrypted artifact integrity, the
resolved service account/group/UID/GID, and the exact systemd property readback.
Receipt schema v2 requires that service identity and zero effective capabilities.
Acceptance treats `IPAddressDeny=any` and
systemd's canonical IPv4/IPv6 orderings as the exact deny-all set
`{0.0.0.0/0, ::/0}` and rejects missing or extra ranges.

The property contract is strict. `RestrictAddressFamilies` and
`RestrictNamespaces` are the only unordered systemd property sets. Member
ordering is ignored for those two fields, but missing members, extra members,
and duplicate members fail validation. All other properties remain exact
scalar comparisons. The receipt keeps the original systemd strings; the
unordered comparison does not rewrite or normalise recorded evidence.

The controller records only fixed, bounded stage and diagnostic-code pairs for
uncertain stages. Post-start failures use separate
`property-readback`, `worker-receipt`, and `receipt-finalization` stages. It
never writes systemctl output, exception text, commands, paths, property
values, or secrets to the acceptance journal. An uncertain stage always
records `automatic_retry=false` and requires reconciliation or recovery
through the documented no-retry path.

The parent unit explicitly uses `ProtectHostname=no`,
`ProtectKernelTunables=no`, `ProtectKernelLogs=no`, `ProcSubset=all`, and
`RestrictSUIDSGID=no`. Local systemd tests showed that each stricter setting
blocks Bubblewrap before it can create the nested audit sandbox. Bubblewrap
still creates separate user, network, PID, IPC, mount, and UTS namespaces. It
drops all capabilities, clears the environment, and exposes fixed mounts only.
The parent remains a nonroot process with `NoNewPrivileges=yes`, an empty
capability set, a read-only application root, private devices, and systemd IP
denial. `AF_NETLINK` is available only so Bubblewrap can initialize the private
loopback interface. The acceptance receipt requires an isolated network
namespace, zero effective capabilities, no target addresses, and zero target
bytes.

The production unit also permits `AF_INET` for its one fixed IPv4 broker route.
Its systemd policy denies every address first and then permits only the reviewed
`100.85.84.30/32` destination. The synthetic acceptance unit never permits
`AF_INET` or `AF_INET6`.

Repository tests validate the controller and receipt contract without root
access. They do not prove that the host systemd and kernel enforce these
properties. A prior schema-v1 synthetic unit start failed before target
traffic and was reconciled as uncertain. A schema-v2 run then failed before
audit initialization because the parent hardening blocked Bubblewrap. That
run was also reconciled as uncertain and was not retried. Those historical
journals predate the fixed diagnostic-code contract and contain their generic
uncertain phase plus the no-retry marker and UTC timeline fields. New runs use
the fixed stage and diagnostic-code pairs described above. Neither result is acceptance evidence.
A reviewed schema-v2 privileged run and valid receipt are still required before
live admission.
