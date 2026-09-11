# CPTC11 lab transport

This module creates one bounded lab observation for the guarded harness. It is
not a general scanner. Harbinger can import reviewed results after its parser
accepts the result format.

The transport connects to Dell at `100.85.84.30:22`. It verifies the pinned
Dell SSH key. It creates one guarded network namespace and opens Kali SSH with
this Dell-side command:

```text
ip netns exec hbg-cptc11-vdi socat STDIO TCP:10.0.254.201:22
```

The nested SSH handshake verifies Kali's separate pinned key. Neither hop
opens a TCP listener. The module has no arbitrary command, shell, target, or
scanner option interface.

## Run the checks

Run the integrity inventory without target traffic:

```sh
cd /home/moriz/Documents/CPTC/The-University-Of-Texas-at-San-Antonio
python -m testing.cptc11_lab.transport preflight \
  --run-root ~/.local/state/harbinger/cptc11
```

Run the one admitted lab observation:

```sh
cd /home/moriz/Documents/CPTC/The-University-Of-Texas-at-San-Antonio
python -m testing.cptc11_lab.transport scan-dc \
  --run-root ~/.local/state/harbinger/cptc11
```

Run the frozen PortCast identity action:

```sh
cd /home/moriz/Documents/CPTC/The-University-Of-Texas-at-San-Antonio
python3 -m testing.cptc11_lab.transport scan-portcast \
  --run-root ~/.local/state/harbinger/cptc11
```

This command has no target, method, path, header, proxy, authentication, or
retry option. It checks the frozen release and operating window before it
opens the Dell lab transport. It then checks the exact Kali OpenSSH runtime,
the relay policy, and a denied Kali-local forwarding control. These checks
issue one short-lived channel capability for `10.0.1.30:8096`.

The frozen action sends exactly one request:

```text
GET /System/Info/Public HTTP/1.1
Accept: application/json
Connection: close
Host: 10.0.1.30:8096
```

The coordinator permits one TCP connection, one request, no authentication,
no redirect, and no retry. It records actual transmitted and received bytes.
It encrypts the complete permitted response before it records a complete wire
receipt. It also records whether Kali, the relay guardian, and Dell closed
cleanly. A repeated invocation is blocked before the lab session opens.

The fixed action state is in
`~/.local/state/cptc-harness/cptc11-portcast-wave-v1`. The CLI prints metadata
only. Raw HTTP bytes remain in the encrypted Audit evidence store. The typed
result identifies Jellyfin Server 10.10.7 as a component candidate. It does
not confirm a vulnerability or a CVE.

The exact target command is:

```text
/usr/bin/nmap --unprivileged -sT -Pn -n -p 445 --script /usr/share/nmap/scripts/smb2-security-mode.nse --max-retries 0 --max-parallelism 1 --host-timeout 15s --script-timeout 8s -oX - 10.0.1.6
```

The Nmap result is an SMB signing observation. It cannot confirm a
vulnerability or assign a CVE. The historical DC result remains
`unmetered_lab_acceptance`; do not repeat it to manufacture stronger evidence.

## Runtime identity

The inventory uses only fixed `dpkg-query` and `sha256sum` calls. It verifies
the exact Kali Nmap package and the 19 reviewed Nmap, NSE, and NSE library
files. It does not execute Nmap, `ldd`, or any scanner script during preflight.
Unknown fields, missing files, extra files, duplicate paths, malformed hashes,
and revision drift fail closed.

Each scan needs a successful inventory from the same open session. The
inventory grant is used once. A second scan needs a new run and a new
preflight.

## Credentials and evidence

The canonical root service accepts only two systemd encrypted-credential
inputs: `cptc11-dell` and `cptc11-kali`. systemd exposes them at the fixed
`/run/credentials/portcast-live-v1.service/` path. The service rejects a
missing, symlinked, empty, wrong-owner, or group/world-accessible credential
before it creates a network connection. It copies each value into a sealed
anonymous descriptor. The broker owns the resulting `LabSession`; the fixed
wire operation receives only that broker-owned channel.

The operator CLI remains a separate, human-run lab utility. Its default
configuration contains only these encrypted credential locators:

- `~/.config/credstore.encrypted/cptc11-regional-dell-prox.cred`
- `~/.config/credstore.encrypted/cptc11-regional-kali.cred`

That utility can call `systemd-creds decrypt --user`. The canonical root
service cannot use the operator-home locators and never invokes that command.
Secrets do not enter command arguments, result files, or readable audit
records in either path.

Each invocation creates a UTC-named mode-`0700` directory. Before target
dispatch, the runner writes an exact action-intent record and reserves space
for stdout, stderr, and the typed result. Reservation failure prevents target
traffic.

Target output and typed results are encrypted with `age` before they replace
their reserved files. The local identity is mode `0600`. The readable
`transcript.jsonl` contains metadata only. It records UTC time with
microseconds, a monotonic timestamp, sequence, event ID, action state, byte
counts, and failure reasons. Each stream has a 16 KiB collection limit.
Incomplete capture fails closed.

## Scope and lifecycle

The code records the seven production addresses in the engagement allowlist.
This transport accepts only `10.0.1.6` and the exact SMB profile. Other listed
addresses stay blocked until a separate target and check review is complete.

Before mutation, a read-only preflight verifies the Dell hostname, required
tools, bridge, and reserved-name state. A guardian then locks the namespace
name. Existing names cause failure and are not deleted.

The guardian handles `EXIT`, `HUP`, `INT`, and `TERM`. Cleanup removes only the
network link and namespace created by that guardian. All failure paths close
Kali, the guardian, and Dell in that order.

## Test offline

The unit tests use synthetic outputs and fake transports. They do not connect
to Dell, Kali, or a target.

```sh
cd /home/moriz/Documents/CPTC/The-University-Of-Texas-at-San-Antonio
python -m pytest -q tests/test_cptc11_lab_transport.py
python -m pytest -q tests/test_portcast_live.py tests/profile_runtime
```
