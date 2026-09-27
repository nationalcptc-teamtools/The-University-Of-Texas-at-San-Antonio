# CPTC private team toolkit

This private repository keeps team scripts, templates, and setup notes by task. The guarded LLM harness is contained in [`llm-harness/`](llm-harness/README.md). It has its own package, tests, and deployment files.

## Find a tool

| Category | Contents |
| --- | --- |
| [`Azure/`](Azure/) and [`aws/`](aws/) | Cloud-specific tooling and notes |
| [`cloud/`](cloud/) | Shared cloud notes; installers are consolidated under `setup_scripts/` |
| [`setup_scripts/`](setup_scripts/) | [Setup master](setup_scripts/setup_master.sh), historical scripts, workstation configuration, and the [Kali team setup tool](setup_scripts/team-env-setup/README.md) |
| [`comms/`](comms/) and [`injects/`](injects/) | Communication and inject templates |
| [`linux/`](linux/) and [`windows/`](windows/) | Host and AD scripts and tools |
| [`network/`](network/) | Network scan notes, firewall script, and the separate [Samba test share](network/samba/) |
| [`phishing/`](phishing/) | Phishing templates and guides |
| [`reporting/`](reporting/) | Report and presentation templates |
| [`web/`](web/README.md) | Web notes, SQL injection and SOAP scripts; the installer is under `setup_scripts/` |
| [`wordlists/`](wordlists/) | Historical team wordlist |

## Contributor scripts

The reorganization retains each contributor's script contents and Git history. These are commit author names or GitHub accounts, not a claim that a script has been tested against a current target.

| Contributor in history | Files in this layout |
| --- | --- |
| `NetrunnerAlez` | [`web/api_sqli.py`](web/api_sqli.py), [`web/soap/sarce.py`](web/soap/sarce.py), [`web/soap/wdsl-parser.sh`](web/soap/wdsl-parser.sh) |
| Derya Yavuz | `setup_scripts/legacy/` installer and terminal configuration originals, `network/iptables.sh`, and `linux/` scripts |
| EricEsquivel | `setup_scripts/legacy/Bloodhound-setup.sh` and `windows/tools/ADRecon.ps1` |
| DylanDavis1 | `setup_scripts/legacy/Windows-Setup.sh` (included in the master with one shared APT update) |

The SOAP scripts have an existing command-name mismatch and one fixed URL. Read the [web notes](web/README.md) before using them. The historical `aws/lambdaprivesc.py` also fails a Python syntax check because its `attach_user_policy` call lacks a comma between arguments. These contributor files were preserved for a separate functional review. No network target was contacted to validate them during the folder move.

## Paths changed by this move

| Former path | New path |
| --- | --- |
| `scripts/api_sqli.py` | `web/api_sqli.py` |
| `scripts/sarce.py` | `web/soap/sarce.py` |
| `scripts/bash/wdsl-parser.sh` | `web/soap/wdsl-parser.sh` |
| `team-env-setup.sh` | `setup_scripts/team-env-setup/team-env-setup.sh` |
| `tools/team-env-setup/` | `setup_scripts/team-env-setup/` |
| `nxc-fix.sh` | `setup_scripts/team-env-setup/nxc-fix.sh` |
| Harness commands such as `python3 scripts/test-harness.py` | Run from `llm-harness/`: `cd llm-harness && python3 scripts/test-harness.py` |

The installed harness command remains `cptc`. The archived team files were restored from this repository's commit `9341dda63c`; the separate former human and Python web applications remain available in Git history.

## Setup master

The executable [setup master](setup_scripts/setup_master.sh) runs the Kali setup in order: reviewed team packages, base Linux, terminal configuration, Linux tools, Windows/AD tools, Web, Cloud, GCP, AWS, and BloodHound CE with RustHound CE. The category installer and terminal configuration commands are written directly in the master and run in its Bash process. The former standalone scripts are preserved unchanged in [`setup_scripts/legacy/`](setup_scripts/legacy/) only for attribution and comparison; the master does not execute those files. The reviewed team environment lock backend remains a separate Python package tool, which the master calls directly for apply and verify. Each package install stays in its own section; the master runs one shared APT metadata update. Run it as the intended regular Kali user with sudo access, passing an existing reviewed team setup lock and its matching review file:

```bash
bash setup_scripts/setup_master.sh /private/tester.lock.json /private/tester.review.json
```

Alternatively set `CPTC_SETUP_LOCK` and `CPTC_SETUP_REVIEW` and run it without arguments. The reviewed lock is applied and verified before the additional installers run. **That lock covers only the team environment package bundle.** The later legacy sections retain separate, unpinned APT, Git, Go, pipx, and download commands; review their sources and current versions before running the master. Each section stops the master if a command fails. The master includes selected path and compatibility fixes; it comments out the old BloodHound.py collector, hardcoded Python 3.11 library copies, global Certipy pip install, and rename of the distribution Certipy executable. Its BloodHound CE section uses Kali Docker packages, downloads the [official Compose example](https://github.com/SpecterOps/BloodHound/tree/main/examples/docker-compose), and pulls its container images without starting BloodHound; RustHound CE is built using its [documented `make install`](https://github.com/g0h4n/RustHound-CE/blob/main/HELP.md). Several historical sections still download and execute external installers. The standalone [team environment tool](setup_scripts/team-env-setup/README.md) remains available for its separate lock and review workflow.

| Previous installer | Archived original |
| --- | --- | --- |
| `Configs/setup.sh` | `setup_scripts/legacy/setup.sh` |
| `Configs/terminal_config.zsh` | `setup_scripts/legacy/terminal_config.zsh` |
| `linux/linux-tooling.sh` | `setup_scripts/legacy/linux-tooling.sh` |
| `windows/Windows-Setup.sh`, `windows/windows-tooling.sh`, `windows/Bloodhound-setup.sh` | `setup_scripts/legacy/` |
| `web/web-tooling.sh` | `setup_scripts/legacy/web-tooling.sh` |
| `cloud/cloud-tooling.sh`, `cloud/gcp-tooling.sh`, `aws/aws-tooling.sh` | `setup_scripts/legacy/` |

## Kali Samba test share

Run these on two Kali Linux hosts in the VDI network. The first script installs Samba when needed and adds a guest-accessible, writable `cptc-test` share. It creates `/srv/cptc-samba-test/test.txt` and `/srv/cptc-samba-test/test/test.txt`, each initially containing `Hello World`. Guest clients can read, write, and traverse the share. The script checks the proposed Samba configuration before applying it, backs up the previous config, and refuses to replace an unrelated share directory. The host must allow TCP 445 from the client.

```bash
sudo bash network/samba/create_samba_share.sh
```

On the other Kali host, pass the first host's IPv4 address. The client script installs `cifs-utils` when needed, mounts the share read/write at `~/cptc-samba-test`, and confirms that it can create and remove a guest file.

```bash
bash network/samba/join_samba_share.sh 192.0.2.10
cat ~/cptc-samba-test/test.txt ~/cptc-samba-test/test/test.txt
sudo umount ~/cptc-samba-test
```

The guest share requires no password. Any host that can reach TCP 445 can modify files in this test share. The server script adds `map to guest = Bad User` to Samba's global settings when it is absent; it refuses to override a different existing value or an `include` based configuration. Its printed backup path can be used to restore the prior Samba configuration. Re-running the script keeps guest-created files and edits to the two test files.
