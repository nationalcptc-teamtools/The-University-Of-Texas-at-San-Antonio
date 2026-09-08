# Using the tools without the harness

The collectors and native applications work without an AI provider, MCP,
SQLite workspace, or the Python harness package. Keep these files with the
team's approved native tools. The `cptc-tools` commands are an optional way to
add enforced scope, persistent budgets, encrypted audit capture and reports.

## Local Linux and Windows observations

Run the appropriate collector **on the assigned guest**, from a human terminal.
These scripts do not connect to a remote machine, authenticate, change services,
or run exploitation. Set the opaque target ID to the identifier in your scope.
Use the collector's `--help` / PowerShell parameter help for its exact interface.

```sh
python3 human/collectors/collect-linux.py --help
```

The standalone PowerShell file is `human/collectors/collect-windows.ps1`.
Its platform execution remains unverified; review it on the approved Windows
guest before relying on its output. Collection gaps are not clean findings.

Write client output only to the team's approved encrypted volume or directly
through its approved encryption tool. Record the command, tool hash/version,
operator, target, UTC start/end times, exit status and evidence checksum in the
engagement record. Keep stdout and stderr as separate evidence streams. The
standalone collectors do not supply the harness's durable audit service.

## Native Nmap

After the human scope, assignment, availability and budget checks, this exact
example observes one TCP port. Replace the documentation address and port with
the exact approved endpoint; record and charge the attempt before running it.

```sh
nmap -sT --unprivileged -Pn -n -p 443 --max-retries 0 \
  --max-parallelism 1 --host-timeout 8s -oX - 192.0.2.10
```

This direct command does not get the harness's network isolation, stop latch,
scope enforcement or output encryption. Route its streams into approved local
encrypted evidence before testing. Do not add discovery, NSE scripts, version
probes, OS detection, UDP, retries or extra ports to this profile. An open TCP
port is an observation, not a confirmed vulnerability.

## Native passive web review

Nuclei supports passive analysis of stored HTTP responses. ZAP supports HAR
import and passive rules. Use copies of the reviewed templates and configuration
shipped in `cptc_harness/resources/`; the guarded native profiles are available
through `cptc-tools import web.nuclei_observation` and
`cptc-tools import web.zap_observation`. The human envelope example is
`human/examples/web-passive-observation.json`.

For direct GUI/manual use, import only the human-reviewed capture, disable
telemetry and updates, and isolate the application from target and Internet
networks before opening client material. Do not select request replay, spider,
active scan, uploads or callback services. The bundled ZAP 2.17.0 import add-on
uses its original HAR-import behavior; newer `sendRequests`/`maxMessages`
configuration options are not supported by that add-on and must not be assumed.

## Manual checks and reporting

Use `human/cards/` to record prerequisites, authorization, expected effects,
operator decisions, evidence and retest results. Zerologon, crash/DoS testing,
spraying and domain changes have no AI launch path. Keep candidate scanner
matches separate from human-verified findings.

The examples and cards can be used directly with the team's existing reporting
workflow. Importing them into `cptc-tools` is optional. Source evidence and logs
remain client-confidential after summarization.
