# Private team environment setup

Use this tool on a reviewed Kali Linux host. Run the examples below from
`setup_scripts/team-env-setup/`. Do not run it on this development host. It
prepares native Kali packages for a selected profile. It does not
start scanners, fetch application code, contact GitHub, pull images, start
services, change firewall rules, or change group membership.

The profiles use shared package bundles. `tester` installs the evidence,
network, web, Linux, and Windows or AD bundles. `scribe` installs the evidence
bundle. `harbinger_host` and `merlin_host` install the evidence and Compose
host bundles. `both` installs the shared host packages once. The Compose bundle
requires `docker.io`, `docker-cli`, and `docker-compose`.

The tester profile requires these native Kali package groups:

- Network: nmap, nbtscan, onesixtyone, whois, and sslscan.
- Web: gobuster, nikto, sqlmap, wpscan, whatweb, wafw00f, and ffuf. ZAP is
  optional and is recorded as unavailable when native Kali metadata has no
  candidate.
- Linux: peass, john, and hashcat.
- Windows or AD: smbclient, python3-impacket, netexec, certipy-ad, enum4linux,
  and smbmap.
- Evidence: jq, unzip, age, python3, python3-venv, and git.

Prepare a lock as root. This command performs one `apt-get update` after it
checks that configured APT sources select one approved native Kali suite. It
supports `kali-rolling` and `kali-last-snapshot`. The snapshot option lets a
dedicated competition image keep its installed Kali source configuration.

The source gate accepts the Kali redirector, the Kali download service, and the
RIT Kali mirror used by the two approved test images. It also accepts the Kali
Deb822 `mirror+file` form when the local mirror file contains one approved
origin. It rejects mixed suites, third-party sources, source packages, unsafe
files, trust overrides, and unsupported components.

APT verifies the signed repository metadata. The tool also verifies the cached
Kali InRelease signature with the Kali archive keyring and a fixed local `sqv`
or `gpgv` binary. Rolling metadata must be no more than 14 days old. A static
`kali-last-snapshot` release has no rolling-age limit, but its signature, date,
suite, source, and any `Valid-Until` value still must pass. The lock records
exact package versions, origin, suite, component, architecture, and source
metadata hash. It does not install packages.

The APT commands use a temporary private configuration. They do not inherit an
`APT_CONFIG`, proxy variables, alternate package roots, trust directories, or
APT and dpkg hooks. The configuration trusts only the Kali archive keyring and
uses the source files that passed the gate. The verified InRelease file must
also match the selected suite and approved source origin. A download failure or
an unrecognized warning stops lock preparation so stale indexes cannot pass as
a new refresh. The only accepted warning is APT's exact deprecation notice for
the fixed Kali keyring option on a legacy one-line source.

```sh
sudo ./team-env-setup.sh prepare-lock --profile tester --lock /private/tester.lock.json
./team-env-setup.sh review-lock --lock /private/tester.lock.json \
  --review /private/tester.review.json --reviewer release-owner
./team-env-setup.sh plan --lock /private/tester.lock.json \
  --review /private/tester.review.json
```

`plan` is read-only. It does not create state or update APT metadata. Review
every required package before you create the review file. The review records a
reviewer and UTC time, and binds the exact lock hash. A changed lock requires a
new review. Required unavailable packages stop lock preparation. Optional
unavailable packages remain visible in the plan.

Apply only after review. The apply preflight checks Kali Linux, root access,
architecture, sources, current signed metadata, the review binding, and the
availability of every required locked version. It then runs one pinned native
Kali installation command. It does not upgrade, remove, clone, use pip or Go,
download software, or start a scanner.

```sh
sudo ./team-env-setup.sh apply --apply --lock /private/tester.lock.json \
  --review /private/tester.review.json
sudo ./team-env-setup.sh verify --lock /private/tester.lock.json \
  --review /private/tester.review.json
```

The tool rejects symlinked, group-readable, world-readable, or unsafe lock,
review, and state inputs. Apply and verify write mode-0600 JSON receipts plus
private UTC `events.jsonl` and readable `events.log` files. These logs record
only command status and package metadata. They do not record APT output.

Verify an application input before an operator starts Harbinger or Merlin. The
input must already exist locally. The tool accepts a local private source tree
or an operator-provided archive hash. It does not clone, download, or query a
client inventory.

```sh
./team-env-setup.sh verify-release --app harbinger \
  --source /private/Harbinger --expected-sha256 <operator-hash>
```

After NetExec creates the intended user's private configuration, use the common
entry point to select its BloodHound collector:

```sh
sudo ./team-env-setup.sh nxc-fix --auto --user kali
```

This command delegates to the adjacent `nxc-fix.sh` module. It updates only
an existing local NetExec configuration. It does not run NetExec, sudo, or a
network command. Automatic mode selects the BloodHound CE collector when both
collector packages are installed. It writes a unique mode-0600 backup only when
it changes the configuration.
