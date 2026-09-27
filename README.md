# CPTC private team toolkit

This private repository keeps team scripts, templates, and setup notes by task. The guarded LLM harness is contained in [`llm-harness/`](llm-harness/README.md). It has its own package, tests, and deployment files.

## Find a tool

| Category | Contents |
| --- | --- |
| [`Azure/`](Azure/) and [`aws/`](aws/) | Cloud-specific tooling and notes |
| [`cloud/`](cloud/) | Shared cloud and GCP setup scripts |
| [`Configs/`](Configs/) | Workstation configuration and the [Kali team setup tool](Configs/team-env-setup/README.md) |
| [`comms/`](comms/) and [`injects/`](injects/) | Communication and inject templates |
| [`linux/`](linux/) and [`windows/`](windows/) | Host and AD scripts and tools |
| [`network/`](network/) | Network scan notes and firewall script |
| [`phishing/`](phishing/) | Phishing templates and guides |
| [`reporting/`](reporting/) | Report and presentation templates |
| [`web/`](web/README.md) | Web tooling, SQL injection and SOAP scripts |
| [`wordlists/`](wordlists/) | Historical team wordlist |

## Contributor scripts

The reorganization retains each contributor's script contents and Git history. These are commit author names or GitHub accounts, not a claim that a script has been tested against a current target.

| Contributor in history | Files in this layout |
| --- | --- |
| `NetrunnerAlez` | [`web/api_sqli.py`](web/api_sqli.py), [`web/soap/sarce.py`](web/soap/sarce.py), [`web/soap/wdsl-parser.sh`](web/soap/wdsl-parser.sh) |
| Derya Yavuz | `aws/` scripts, `cloud/gcp-tooling.sh`, `network/iptables.sh`, `linux/` scripts, and `Configs/terminal_config.zsh` |
| EricEsquivel | `windows/Bloodhound-setup.sh` and `windows/tools/ADRecon.ps1` |
| DylanDavis1 | `windows/Windows-Setup.sh` |

The SOAP scripts have an existing command-name mismatch and one fixed URL. Read the [web notes](web/README.md) before using them. The historical `aws/lambdaprivesc.py` also fails a Python syntax check because its `attach_user_policy` call lacks a comma between arguments. These contributor files were preserved for a separate functional review. No network target was contacted to validate them during the folder move.

## Paths changed by this move

| Former path | New path |
| --- | --- |
| `scripts/api_sqli.py` | `web/api_sqli.py` |
| `scripts/sarce.py` | `web/soap/sarce.py` |
| `scripts/bash/wdsl-parser.sh` | `web/soap/wdsl-parser.sh` |
| `team-env-setup.sh` | `Configs/team-env-setup/team-env-setup.sh` |
| `tools/team-env-setup/` | `Configs/team-env-setup/` |
| `nxc-fix.sh` | `Configs/team-env-setup/nxc-fix.sh` |
| Harness commands such as `python3 scripts/test-harness.py` | Run from `llm-harness/`: `cd llm-harness && python3 scripts/test-harness.py` |

The installed harness command remains `cptc`. The archived team files were restored from this repository's commit `9341dda63c`; the separate former human and Python web applications remain available in Git history.
