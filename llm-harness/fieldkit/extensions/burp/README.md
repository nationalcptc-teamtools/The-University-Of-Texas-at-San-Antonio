# Send selected Burp captures to Fieldkit

This optional Java extension adds a **Fieldkit** tab and **Send to Fieldkit** context
menu. It sends only the messages you select to Fieldkit's authenticated loopback
receiver. The receiver saves private raw exchanges and redacted request metadata in
the local vault; captured origin allowlists do not authorize target requests.

## Build and load

Use a Java 17+ JDK with `javac` and `jar`, Python 3.11+, and the Montoya API JAR.
The build targets Java 17 and Montoya API **2026.7**, whose coordinates are documented
in [PortSwigger's API repository](https://github.com/PortSwigger/burp-extensions-montoya-api).
From the Fieldkit checkout:

```bash
mkdir -p /tmp/fieldkit-montoya
curl -fsSL \
  https://repo.maven.apache.org/maven2/net/portswigger/burp/extensions/montoya-api/2026.7/montoya-api-2026.7.jar \
  -o /tmp/fieldkit-montoya/montoya-api-2026.7.jar
python3 extensions/burp/build.py \
  --api-jar /tmp/fieldkit-montoya/montoya-api-2026.7.jar
```

The build prints `extensions/burp/dist/fieldkit-burp.jar` as an absolute path. It
uses the explicit local API JAR for compilation; the API is provided by Burp at
runtime. Add a Java extension in Burp's **Extensions** view and select this output
JAR. The extension name is **Send to Fieldkit**, and its suite tab is **Fieldkit**.
Use a Burp release compatible with that API. See [PortSwigger's extension tutorial](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/first-extension)
for Burp's extension-loading workflow.

## Start the receiver and send captures

In an activated Fieldkit environment:

```bash
fieldkit run integrations/burp-bridge \
  --origin https://app.example.test --database artifacts/assessment.sqlite \
  --budget 600 --max-captures 100 --max-entries 10
```

1. Replace the fictional origin with the exact HTTP(S) origin of your selected
   captures. Repeat `--origin` for additional capture origins.
2. Keep the receiver running and select its printed private properties file in
   Burp's **Fieldkit** tab. Use **Select receiver configuration** to browse for it.
3. Optionally enter **Captured user**, **Captured role**, and **Feature**. These
   labels are capture context; they do not prove identity or authorization.
4. Select messages in Proxy history or Repeater, right-click, and choose **Send to
   Fieldkit**. A request without a response can also be captured.
5. Read the `record_ids` returned in the tab. The receiver's report contains matching
   `request_id` values, plus capture IDs, timestamps, methods, statuses, and context.

The Java client sends a bounded batch on a background worker with a four-send queue.
It sends to `127.0.0.1` only, does not use environment proxies, follows no redirects,
and reads at most 16 KiB of the receiver response. The receiver validates every
exchange's origin before storing the batch. Raw bodies and credentials stay in the
private database/blob store. Public vault records and run reports are redacted.

The generated properties file contains a temporary receiver credential. On POSIX,
it must be owner-only; Fieldkit writes it with mode 0600. Select the fresh file from
the current run. The receiver removes its owned configuration on normal shutdown or
cancellation. `--config-file PATH` can choose a new output path; an existing file or
symlink is rejected. The receiver stops after its listening budget or capture limit.
Ctrl-C closes the listener and preserves received capture reports.

## Bounds

| Option | Default | Accepted range |
| --- | --- | --- |
| `--port` | `0` (allocate a port) | 0–65535 |
| `--max-captures` | `100` | 1–10000 exchanges |
| `--max-entries` | `10` | 1–50 exchanges per send |
| `--max-body-bytes` | `524288` | 1–8388608 decoded bytes per request/response body |
| `--max-bytes` | `1048576` | Positive capture payload size, at most 16777216 bytes |
| `--budget` | `120` | Positive listening period in seconds |
| `--timeout` | `10` | Positive per-receiver-request deadline in seconds |

The JSON/Base64 envelope counts toward `--max-bytes`; a batch may exceed that cap
even when each body meets its own limit. Malformed or unsupported captures, outside
origins, invalid credentials, and exceeded bounds are rejected. `--dry-run` writes
a plan without opening a listener or vault.

## Use captured IDs from CLI or MCP

```bash
fieldkit web vault --database artifacts/assessment.sqlite --host app.example.test
fieldkit run web/parameter-discovery https://app.example.test \
  --database artifacts/assessment.sqlite --request-id REQUEST_ID_FROM_CAPTURE \
  --name hiddenMode --dry-run
```

The module's default location detects form/JSON/XML captures; choose `--location
query` explicitly for query discovery. For active discovery, add `--confirm-probes`
after selecting the request and inspecting its plan. Other replay/JWT/ffuf operations
likewise require their own explicit target origins and controls.

MCP exposes `fieldkit_run_integrations_burp_bridge`, live ready/capture results through
`fieldkit_read_report`, and redacted request records through `fieldkit_vault_records`.
The human still selects the private configuration file in Burp. The full
[agent assessment guide](../../docs/agent-assessment-tools.md#burp-selected-captures-to-vault-ids-and-mcp)
shows that workflow. No MCP read tool returns the receiver credential or raw capture
bodies.

If a send fails, confirm that the receiver is still running, the current configuration
is selected, its permissions are private, all selected origins are allowed, and the
batch meets byte/count limits. The extension displays fixed diagnostics rather than
exception text that could contain credentials.
