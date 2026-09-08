# Guarded CPTC harness — private alpha 0.1.0a3

This terminal-first harness implements a local policy broker, persistent budgets,
encrypted evidence capture, UTC audit files, typed imports, bounded HTTP metadata
observations, compact AI workflows and deterministic reports. The existing
`web/cptc_web.py` workflow and its report format remain available to human operators.
They are not granted to the AI as shell capabilities.

The operator entry point is `cptc-tools`. It adds no model calls to imports,
observations, coverage or reporting. The independent [human kit](../../human/README.md)
also supplies local Linux/Windows collectors, native-tool procedures and manual
evidence cards for teams using their own workflow.

**This is a private development alpha, not an accepted competition release.**
No active profile has completed the required live acceptance. Read
[ACCEPTANCE.md](ACCEPTANCE.md) before claiming support. Unknown or unmediated
operations are blocked. Ordinary requests can still affect defective services;
there is no zero-risk or tamper-proof claim.

## Entry points and preparation

Run from the private source worktree or install the private wheel. Python 3.11+
is the language target; the tested host uses Linux x86_64 and Python 3.14.7.
See [LOCAL-INSTALL.md](LOCAL-INSTALL.md) for the operator installation and
standalone human kit.
The isolation profiles require working unprivileged bubblewrap namespaces.
Synthetic browser tests also require the pinned Chromium, Playwright and a user
systemd instance with cgroup resource enforcement. Other operating systems have
not been admitted.

```sh
python3 scripts/bootstrap-harness.py --install-age
python3 scripts/bootstrap-native-tools.py --install-zap
sh cptc_harness/native/build-nmap-shim.sh .tools/native/nmap-connect.so
python3 -m cptc_harness.human preflight
python3 -m cptc_harness doctor
python3 scripts/review-release-pins.py
python3 -m pytest -q tests web
python3 -m unittest discover -s web -p 'test_*.py'
python3 -m build --no-isolation
```

Bootstrap is an explicit **preparation-only** download of the official age 1.3.2
Linux AMD64 archive. Its SHA256 is pinned; Sigsum verification is not implemented.
It installs only into ignored `.tools/`, without changing PATH or global settings.
Runtime code never downloads tools, templates, browser extensions or updates.
Install the exact dependencies from the reviewed lock file in an isolated Python
environment before assessment. Package resolution and updates are preparation
steps and must not receive client data.

The release contains exact worker and host executable hashes. Package or host
updates intentionally invalidate affected workers. `review-release-pins.py`
checks these pins offline; `--propose FILE` writes a separate review candidate.
It never changes the admitted manifest. Re-admission requires reviewing the
changed binaries/source and repeating relevant tests, not merely accepting new
hashes. The included manifest describes the tested host, not every Linux host.

## Create restricted engagement storage

Copy `examples/policy.synthetic.json` to a private file outside Git for a
preparation workspace. It deliberately contains no eligible targets or active
window. It is not authorization for client testing. Use a unique stable
engagement/device/workspace identity and keep the device ledger outside the
disposable workspace.

```sh
umask 077
python3 -m cptc_harness init /approved/local/engagement \
  --policy /approved/local/policy.json \
  --recipient age1OPERATOR_PUBLIC_RECIPIENT \
  --age /approved/local/age
python3 -m cptc_harness --workspace /approved/local/engagement preamble
python3 -m cptc_harness --workspace /approved/local/engagement run network.nmap_import \
  --input /approved/local/reviewed-synthetic.xml
python3 -m cptc_harness --workspace /approved/local/engagement coverage
python3 -m cptc_harness --workspace /approved/local/engagement report
python3 -m cptc_harness --workspace /approved/local/engagement audit-verify
```

Paths and recipient above are placeholders. The CLI is for the local human
operator. Do not expose the CLI, Python interpreter, filesystem or shell to the
model. Owner-only directories/files and a path outside Git are mandatory.
Use approved encrypted storage for the entire workspace and external ledger:
typed policy, result and audit metadata remain confidential plaintext within
that storage. Raw evidence is age-encrypted before persistence even when the
whole volume is encrypted. Decryption identities must be held separately and
are never available to the AI transport.

`--workspace` precedes the subcommand. `modules` prints the versioned immutable
manifests and strict argument/result schemas. `tui` is a local operator menu.
The core interfaces are frozen dataclasses in `cptc_harness/contracts.py`;
model envelopes are validated separately and cannot populate trusted identity,
classification, approval or policy fields.

## Capability admission

| Capability | This alpha |
|---|---|
| Nmap XML and structured network imports | Local deterministic parsing; fixtures tested |
| Web capture imports | Header/session facts from operator-selected captures |
| Linux and Windows/AD imports | Typed identity, permissions, service/task, privilege and protocol observations |
| Human result / finding / coverage / retest imports | Typed, source-hashed, human-reviewed records |
| `web.headers`, `web.session` | One eligible-target HTTP metadata request; synthetic integration tested; live acceptance pending |
| `web.response_capture` | Operator-only one-response GET, encrypted capture and human-selected offline replay; bounded lab smoke passed |
| `network.nmap_inventory` | Pinned native Nmap, exactly one TCP connect through the parent broker; native synthetic fixtures tested |
| `web.nuclei_observation`, `web.zap_observation` | Offline native analysis of one human-selected response; networkless workers, reviewed rules and encrypted streams |
| Active `web.nuclei`, `web.zap` | Unsupported; no active scanner profile admitted |
| Remote Linux/Windows execution | Unsupported; operator collection scripts supplied separately |
| Authenticated login and controlled-account active comparisons | Unsupported; no target credential adapter admitted |
| TLS and protocol inventory beyond current HTTP metadata/import fields | Incomplete; no additional live profile admitted |
| Automated exploitation proofs | None admitted in this alpha |
| Zerologon, spraying, DoS/crash, domain changes and unknown impact | Manual-only; no approval, alias or script override |

`scripts/collect-linux.py` and `scripts/collect-windows.ps1` are **human-operated
collection aids**, not AI execution capabilities. Review them for the specific
host before use. Linux collection was exercised locally; the PowerShell script
has not been executed on Windows. Unsupported fields remain visible in parser
issues and coverage. A connection or scanner match never establishes safety or
confirms a finding. Reports preserve conflicting states, source hashes, owners
and evidence links. `confirmed_by_human` means a reviewed human claim linked to
an integrity-checked local artifact; it is not independent exploit validation.

Manual-only cards are included in `cptc_harness/resources/MANUAL-ONLY-CARDS.md`.

## Native observation tools

See [NATIVE-TOOLS.md](NATIVE-TOOLS.md) for exact tool boundaries, capture input,
reviewed versions, human use and preparation. The tool catalog pins binaries,
ZAP's files and Java runtime/configuration closure; it never treats an available
binary as an automatic admission. Source/native changes require review and tests.
The model can request a human decision and record operator-selected results.
It cannot launch the test, generate an executable network script, change a
service/domain, run a custom scanner template or register new runtime tools.

## Enforced data boundaries

| Category | Handling |
|---|---|
| Public references / synthetic fixtures | Permitted for preparation and development agents |
| Client inventories, findings, configurations and summaries | Client-confidential; local restricted storage; selected typed facts only to the explicitly admitted client AI |
| Raw output, bodies, screenshots and evidence | Human-only restricted capture; no model file-read capability |
| Passwords, cookies, tokens, keys and authentication stores | Separate secret broker; opaque references; no argv, readable transcript or export access |

Derived facts retain source confidentiality after redaction. `ai-brief.json`
from the legacy workflow is explicitly client-confidential. Client data and raw
logs must stay out of Git, development-agent prompts, shared AI memory, cloud
storage and the general Obsidian context vault.

Unapproved or unknown AI services receive **zero client-derived information**.
An approved client profile needs an exact HTTPS origin/path, numeric address
allowlist, categories, authorization, retention terms and trusted reviewer.
Immediately before client transmission, a nonce-bound signed capability
attestation must match model, origin, configuration hash, retention hash and a
short expiry, and attest that tools, plugins, browsing and uploads are disabled.
This is a claim from the approved gateway's trusted signing key; local filtering
cannot prove the provider's internal behavior. Without that verified arrangement,
only public/synthetic workflows run. The expected supplied CPTC AI remains an
unverified assumption. There is no automatic provider fallback.

The disclosure gate bounds fields, full envelopes and cumulative small transfers.
Excerpts require an operator-selected artifact hash, exact excerpt hash,
destination/profile hash, reviewer and byte allowance. The model cannot approve
or change those fields. Arbitrary target text, HTTP headers/bodies, errors,
attachments and raw evidence are not automatically forwarded.

AI-written code remains inert. No arbitrary shell, URL fetch, upload, clipboard,
email, repository publication or infrastructure-management endpoint exists in
the model interface. Prompt instructions supplement these capability limits.

## Process and network separation

The local operator/runtime is trusted. The audit writer runs in a dedicated
networkless bubblewrap process with only the audit directory writable. Other
components use bounded framed RPC; no raw-evidence read RPC is exposed.
The writer owns UTC timestamps, sequence numbers, evidence encryption and hash
checkpoints. It cannot read provider credentials or signing/decryption keys.

Target HTTP and provider HTTP run in separate networkless workers. The trusted
broker validates destinations and passes one already-connected socket, a sealed
request descriptor and read-only runtime files. They have no home directory,
raw engagement mount, ambient environment or arbitrary connection capability.
The separate secret worker holds short-lived credentials in memory and grants
opaque, origin/profile-bound descriptor references. The signing worker receives
only an operator-selected signing key descriptor and reviewed handover bytes.
Generic admitted local workers also have seccomp process-creation restrictions.

Browser workers have a dedicated ephemeral profile, pinned resources and cgroup
limits. Their proxy permits only reviewed exact-origin routes and bounded bodies;
popups, service workers and WebSockets are blocked. This alpha allows only
synthetic/public browser content. Teammate-operated client login and client-data
browser transport are blocked until an isolated display/login boundary is proven.
Existing browser profiles, cookies and conversations are never imported.

For targets, the broker checks registered target identity, eligible profile,
assignment, CIDR and hostname allowlists, address exclusions and every DNS answer.
It pins the actual numeric connection, rejects URL credentials, queries,
unexpected headers/bodies, traversal and redirects, and stops on lockout,
throttling, 5xx, truncation or connection uncertainty. There are no public
callbacks, scanner telemetry or unapproved health checks. Native scanner traffic
is not assumed safe merely because an invocation is wrapped in Python.

These restrictions constrain capabilities granted by this harness. They do not
isolate a hostile administrator or an unrelated agent already given this user's
shell, home directory or network. Do not connect such a general agent to client
storage and claim that this broker contains it.

## Limits, stop and offline workspaces

Defaults are six model calls, twelve model-requested actions and one format
repair per operator-created workflow; one model call and one target operation
in flight; HTTP at most one request per second and 24 per canonical application;
authentication disabled (any future adapter must honor the maximum two attempts).
Model-visible excerpts are at most 2 KiB, disclosure context at most 8 KiB.
Each module additionally caps runtime, requests, processes and output; current
collection caps are 128 KiB per action and 32 KiB per target response.

Reservations are consumed before dispatch, even after a failure. SQLite WAL/FULL
device ledgers reside under `~/.local/state/cptc-harness/<engagement>/`, outside
workspace recreation. Workspace/audit identities and canonical paths are bound.
Target and shared authentication-realm assignments are exclusive. The AI cannot
reset counters, modify scope, reclassify risk or resume a stop.

```sh
python3 -m cptc_harness --workspace /approved/local/engagement stop \
  --reason "operator stop for review"
```

Stop uses the persistent ledger without waiting for the active audit-writer
lock. Running contained processes observe the latch and are terminated. Socket
setup has a bounded timeout; cancellation is not claimed to undo requests
already sent. There is no automatic retry after uncertain effects or improvised
rollback. Clock synchronization is checked read-only before active work; unknown
state, an offset over two seconds or detected clock jumps blocks it. No host
clock changes or automatic external NTP requests occur.

Human-only `handover-export` requires a prior stop, no running actions, exact
recipient device/key and an operator signing-key reference. It seals the source
against further execution. The recipient uses `handover-import` with the exact
reviewed bundle digest and trusted source key. Signatures, policy versions,
assignments, replay history, all origin-device counters and combined limits are
validated transactionally. Multi-hop consumption persists. A failed outcome
audit stops the destination while preserving imported accounting.

Disconnected machines cannot enforce real-time global limits. Assign them
exclusive targets and authentication realms before disconnecting. No automatic
reassignment or reset workflow is shipped.

## AI transports and compact operation

The adapter contract is `create_session`, `send`, `cancel`, `close`. Native
OpenAI-compatible JSON, complete SSE/NDJSON streams and declarative captured
request templates are supported. Captured curl commands are never executed.
Templates have a tiny allowed field set and one complete messages/prompt slot;
copied conversations, cookies and session material are rejected.

Create an operator-bound workflow with `workflow-create ID --provider FILE
--module MODULE [--target TARGET] [--synthetic]`, then use `ai-step ID --provider
FILE`. `--credential-prompt` uses a hidden local terminal prompt and a temporary
secret-broker reference. Do not put credentials into command arguments or files.
Only complete validated action/ask-human/finish envelopes are accepted. Prose,
partial streams, native unexpected tool calls and invalid fields execute nothing.
One repair may be attempted; uncertainty stops the workflow. Provider-reported
model and usage are recorded separately from the requested model. A model's
finish claim is not a verified completion.

`mcp --workflow ID --provider FILE` exposes only `cptc_capabilities` and
`cptc_action`, with no filesystem resources. **Stdio MCP is synthetic-only**:
the caller's eventual recipient cannot be authenticated by a local provider
profile. Do not infer client-data authorization from MCP availability.

`skills/cptc-harness/SKILL.md` is the compact runtime skill. The preamble verifies
the complete pinned local CPTC rules reference and includes the current SOW/ROE,
window, exclusions, confidentiality, outside-assistance, staging, reporting,
escalation and capability constraints. Local inventories, parsing, deduplication,
coverage and report generation use zero model calls. The synthetic benchmark
measured 88.6% fewer input tokens than an accumulated transcript baseline while
retaining all fixture output locally; see [TOKEN-BENCHMARK.json](TOKEN-BENCHMARK.json)
for the exact comparison and limits.

## Audit, evidence and engagement close

`audit/audit.jsonl` and `audit/transcript.log` contain structured and readable
chronological events. Each includes central microsecond UTC time ending in Z,
monotonic capture time, persisted sequence, unique event ID, engagement/device/
operator/workspace/session/action identity and clock status/offset when available.
Output timestamps mean local receipt time, not remote execution time.

Actions record module source/version, validated parameters, command and permitted
environment/descriptor metadata, intent, reservations, dispatch, process start,
output chunks, destination/method/status/timing, completion/exit/cancellation,
evidence hashes and remaining accounting. Model exchanges retain complete
permitted bytes in encrypted local capture with short readable metadata. Private
chain-of-thought and authentication payloads are not requested or logged.
Terminal control characters are escaped. Unexpected sensitive output stays in
encrypted capture, not the readable transcript or model context.

Output space is reserved before work; full permitted bytes preserve stream
identity. Overflow terminates the action and records incomplete capture. Audit
failure, disk exhaustion, permission drift, orphaned evidence, tampering or an
interrupted reservation blocks new work across restarts. Closed segments are
hashed and chained. A journal recovers rotation at each durable boundary;
inconsistent append/checkpoint state is blocked for human investigation. Do not
delete markers or edit journals to make a failing check pass.

Use `audit-seal` to close a segment. For a local encrypted export, create an exact
file review with `export-review FILE... --output REVIEW`, inspect its contents and
hash, then `export --review REVIEW --approved-hash HASH --recipient RECIPIENT
--identity DECRYPTION_KEY_REFERENCE --output BUNDLE.age --age AGE_BINARY`.
The operator must possess an appropriate local verification identity; there is
no model access to it. Encryption, archive contents and decrypted hashes are
verified before success. Export writes a local artifact and authorizes no upload
or destination. Source records remain unchanged. Plaintext bundle export is not
implemented in this alpha; encrypted export is the supported close path.

`merge-timeline AUDIT_DIRECTORY... --output FILE` verifies complete source audit
directories and preserves original UTC times, sequences, device IDs and clock
uncertainty. Sorting is a presentation timeline, not proof of exact cross-machine
ordering. Isolated JSONL files without their integrity chain are rejected.

Keep records until the operator applies approved retention/disposal rules. There
is no automatic deletion, live central collector or promise of provider deletion.
Integrity chains are tamper-evident under trusted-operator assumptions, not
tamper-proof against administrators.

## Legacy compatibility, source rules and publication

`migrate-legacy PATH --encrypted-volume-verified` adds the harness version setting
and a consistent backup without deleting legacy rows or changing the old schema
version. The flag is an explicit operator storage attestation, not an automatic
encryption detector. Migration is refused without it because old databases and
their backups retain the compatible plaintext format. Existing reports and the
34 original regression tests are preserved. Old client-derived briefs must be
treated as confidential even if generated before the new label existed.

The local `CPTC-RULES-2025-10.txt` is the complete extracted reference. Its SHA256
is `49223ed970c33e74d863d092bd415c02cdc747bedf21fc573a57e6b3b3598ea3`;
the user-supplied PDF SHA256 is
`1a87bc5c81241ab3f6aecfaa97845f53235db8ef8ce1dffe7388a04b11a5cfbb`.
Rules, event-specific SOW/ROE and supplied AI conditions must be revalidated for
the actual competition. Availability of a service, discovered asset, credential
or model suggestion never expands authorization.

The architecture follows [OWASP prompt-injection guidance](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html),
[OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
and established [age tooling](https://github.com/FiloSottile/age).
Development remains private and local. A push requires separate authorization;
competition publication additionally requires the approved CPTC staging process.
Luna/Terra builder roles are recorded in [BUILD-WORKFLOW.md](BUILD-WORKFLOW.md)
and [BUILD-AGENTS.json](BUILD-AGENTS.json). They do not choose the engagement's AI
provider or grant outside assistance.
