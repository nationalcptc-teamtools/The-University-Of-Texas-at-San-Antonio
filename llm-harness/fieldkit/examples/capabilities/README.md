# Sanitized capability inputs

All hosts, users, secrets, listener records, and reports here are synthetic. Example
HTTP commands in the documentation use `--dry-run` unless intentionally illustrating
an operator login. Importing these files makes no assessment requests.

| Files | Use |
| --- | --- |
| `requests.json`, `request.http`, `edits.json` | Selected JSON/raw replay and existing-field edits. |
| `callback-receipts.json` | Listener receipt shape only; placeholder IDs/timestamp cannot confirm a real probe. |
| `auth-matrix.json` | Known objects/functions with explicit owner/allow/deny/resource checks. |
| `session-workflow.json` | HTML CSRF extraction, explicit form login, JSON token extraction, later header substitution. |
| `verified-workflow.json`, `expect-resource.json` | Resource-specific baseline expectations; no modification is supplied. |
| `nmap.xml`, `vhosts.json` | Offline selected HTTP-service import with documentation-reserved IPs. |
| `nuclei.jsonl`, `surface-template.yaml` | Offline result import and a static marker fingerprint. |
| `service.wsdl` | WSDL 1.1/SOAP 1.1 inventory with one read-status operation. |
| `report.example.json`, `evidence.example.json` | Synthetic schema-v2 web report and redacted evidence. |
| `host-report.example.json`, `host-evidence.example.json` | Synthetic host/resource finding and evidence. |
| `exposure-fixture.env` | Harmless credential-shaped candidate for an explicit local file audit. |

To inspect the toy exposure file without scanning host directories:

```bash
fieldkit run linux/exposure-audit --root examples/capabilities/exposure-fixture.env \
  --host-id documentation-fixture --max-files 1 --budget 5
```

Report examples illustrate the contract; they do not claim an assessment actually ran.
See [capability documentation](../../docs/capabilities.md) for formats and limitations.
