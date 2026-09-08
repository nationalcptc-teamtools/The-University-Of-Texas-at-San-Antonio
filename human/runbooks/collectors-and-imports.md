# Local collectors and offline imports

`collectors/collect-linux.py` and `collectors/collect-windows.ps1` are human-run
local metadata collectors. They do not contact targets, invoke a shell, use
sudo, use remoting, prompt for credentials, enumerate secrets, or mutate
services/domains. Windows output is unvalidated until it runs on an actual
Windows host; unsupported fields are reported as unsupported.

Run a collector only as an operator, redirecting output to a protected local
file, then use the matching `import` command. Linux and Windows envelopes must
keep `network_access`, `sudo_used`, and `service_changes` false. The parser
returns typed identity, permission, service/task, policy, and controlled-account
facts; raw bytes remain human-only evidence.
