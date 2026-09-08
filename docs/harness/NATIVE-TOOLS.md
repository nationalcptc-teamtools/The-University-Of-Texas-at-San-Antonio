# Native and independent human tools

`cptc-tools` is the model-free operator interface. It can initialize a private
workspace, run an exact module, import an owner-selected artifact, report,
verify audit integrity and stop work. Its read-only preflight hashes discovered
files; it does not execute arbitrary PATH wrappers to obtain their versions.

The [human kit](../../human/README.md) contains standalone local collectors,
manual cards, native-tool procedures and synthetic examples. Those artifacts
can be used with the team's existing reporting workflow without installing the
harness. Direct native commands do not inherit the broker's enforcement or
audit guarantees; the operator supplies scope, traffic and evidence controls.

## Nmap 7.991: one TCP observation

`network.nmap_inventory` performs one TCP connection to one exact approved
IPv4 address and port. IPv6 is explicitly unadmitted before any probe. It reserves the cumulative budget first. The pinned
Nmap process has an isolated network namespace and a fixed command: connect
scan, no discovery, no DNS, no retries, one port, one parallel operation and an
eight-second Nmap host timeout. No NSE, version detection, UDP or OS scan is
admitted. No caller-supplied scanner flags exist.

A reviewed shared library sends an address/port request over AF_UNIX. The parent
checks the grant, opens and closes the real target socket, then returns its
result. Nmap never receives a target-connected descriptor. The XML must agree
with the parent observation. Repeated/mismatched requests, uncertain effects,
stops after a probe, malformed XML and output failures preserve evidence and
stop the target workflow. All process starts/exits and raw stream chunks are
audited. Open/refused fixtures use the actual native binary.

This design does not use Nmap's general proxy flag: it does not cover connect
port scanning. See the [official Nmap proxy limitations](https://nmap.org/book/man-bypass-firewalls-ids.html).

## Nuclei 3.11.1 and ZAP 2.17.0: offline response observations

Use an owner-only input file with exactly these fields:

```json
{"version":1,"target":"http://192.0.2.10/","response_base64":"BASE64_COMPLETE_HTTP_RESPONSE"}
```

The response must contain a status line, headers, an empty line and complete
decoded body, at most 32 KiB total. Chunked/compressed, inconsistent-length,
multi-response and malformed captures are rejected. URLs must pass the current
scope; URL credentials, query strings and fragments are rejected. The example
is a format illustration, not testing authorization.

```sh
cptc-tools import web.nuclei_observation --workspace /approved/engagement \
  --input /approved/encrypted-storage/reviewed-response.json
cptc-tools import web.zap_observation --workspace /approved/engagement \
  --input /approved/encrypted-storage/reviewed-response.json
cptc-tools report --workspace /approved/engagement
cptc-tools audit-verify --workspace /approved/engagement
```

Nuclei uses the reviewed three header-presence rules and a mandatory processing
receipt. An empty result stream is a failure, not a clean result. The `.txt`
capture suffix is required by this pinned passive implementation. Complete raw
scanner JSON is encrypted: Nuclei can include response contents in its `path`
field even when its raw-output omission flag is used. Facts expose only static
rule IDs, severity and match counts. These checks observe header presence; they
do not establish that a present policy is correct.

ZAP receives one synthetic HAR request with the original HTTP/HTTPS scheme and
the selected response. All passive rules are disabled before the eight reviewed
rule IDs are enabled. The pinned import add-on supports stored HAR import, not
the newer replay configuration options. There is no replay, spider, active
scan or browser job. The worker loads only the required passive add-ons and
uses `-silent -notel`. Its mandatory call-home add-on has no external network
route. Missing site data and unknown rule IDs fail validation. Scanner matches
remain candidates requiring human confirmation.

Both workers have no target/provider network route, no client request/session
store, a cleared environment, sealed input descriptors, restricted mounts,
a 32 KiB ZAP report cap and a combined 128 KiB action capture allowance, a 30-second action deadline and a verified user cgroup with
768 MiB memory and 128 tasks. Temporary files use a bounded memory filesystem.
The parent verifies resource enforcement before releasing the scanner's startup
gate. Only encrypted raw stream artifacts leave the worker. Host memory/swap
and the operator's metadata storage must satisfy engagement encryption policy.

Reference behavior: [Nuclei passive scanning](https://docs.projectdiscovery.io/opensource/nuclei/running),
[ZAP passive configuration](https://www.zaproxy.org/docs/desktop/addons/passive-scanner/job-pscanconf/),
[ZAP import automation](https://www.zaproxy.org/docs/desktop/addons/import-export/automation/).

## Preparation and admission

`bootstrap-native-tools.py --install-zap` verifies the official archive SHA256
before extracting regular files. It does not update runtime pins or admit a
profile. Nmap/Nuclei come from the reviewed host packages. Rebuild the shim with
the supplied compiler script, inspect changes, and review deployment hashes
before use on a different machine. Runtime never installs or updates tools.

The binary catalog, worker/resource hashes and Java closure are checked at
dispatch. The complete test suite and independent review provide synthetic
evidence. Live guest/profile acceptance remains a separate gate. Remote host
execution, active authentication comparisons and disruptive procedures have no
new automated capability in this release.
