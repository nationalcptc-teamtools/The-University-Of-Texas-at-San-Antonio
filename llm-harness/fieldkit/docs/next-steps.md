# Fieldkit next steps

Updated: October 22, 2026. Baseline: commit `b951c5d`.

The stored-XSS workflow, general HTTP callback collector, network vantage
diagnostics, and MSSQL read-only export are implemented and exposed through MCP.
The baseline passed 527 tests, with one optional Nuclei test skipped. Remaining
work is real-environment validation and the additions below.

## Validate the existing features first

- [ ] Validate the target application's actual ticket/staff-review workflow.
  Configure the submission, ticket ID extraction, session profile, and browser URL.
  Confirm callback reachability from the relevant host. Preserve the distinction
  between local browser execution, an external callback, and verified staff identity.
- [ ] Validate MSSQL inventory and a selected-table export against a real SQL Server
  using Windows NTLM authentication. Independently compare table and exported row
  counts, check type handling, and inspect truncation and partial-export records.
  Current SQL tests use simulated responses and an installed-driver smoke check.
- [ ] Validate network diagnostics against the actual pivot setup. Compare reports
  from the relevant hosts, check DNS and selected-target TCP reachability, and
  compare observed TUN ownership with the proxy's actual session state.

See the [field workflow guide](field-workflows.md) for current options and examples.

## Prioritized additions

### 1. Readiness command: `fieldkit doctor`

- [ ] Check Python, optional dependency versions, Chromium, and external binaries.
- [ ] Check private vault/profile permissions and configured session-profile scope.
- [ ] Report callback listener/advertised URL configuration, DNS, and route state.
- [ ] Provide explicitly selected reachability checks without starting scans or
  modifying network configuration.
- [ ] Expose the same structured readiness results through CLI and MCP.

Completion: an operator can identify missing dependencies or configuration before
starting an assessment, with clear errors and redacted results.

### 2. Read-only Ligolo API integration

- [ ] Query an explicitly configured, authenticated Ligolo control plane.
- [ ] Associate connected agents, sessions, TUN devices, and routes.
- [ ] Correlate that state with `network/vantage` and selected TCP checks.
- [ ] Preserve provenance and distinguish connected, attached, and reachable states.

Completion: Fieldkit can report the agent/session-to-TUN association directly,
while retaining the limits of each reachability observation. The adapter should
make no route, interface, or tunnel changes.

Reference: [Ligolo API and WebUI](https://docs.ligolo.ng/webui/).

### 3. DNS/HTTPS callback provider integration

- [ ] Add an Interactsh provider adapter for DNS and HTTPS interactions.
- [ ] Support an explicitly selected self-hosted service and private configuration.
- [ ] Persist correlation state for delayed callbacks and resumable polling/import.
- [ ] Normalize receipts into Fieldkit's redacted evidence format with marker,
  protocol, timestamps, and provenance.
- [ ] Retain the rule that a callback alone does not establish reviewer identity
  or privilege.

Completion: callback-based workflows can use DNS/HTTPS and survive beyond the
current bounded HTTP listener's lifetime. Public forwarding currently must already
exist; setting `PUBLIC_URL` does not create it.

Reference: [Interactsh](https://github.com/projectdiscovery/interactsh).

### 4. Broader MSSQL authentication

- [ ] Add Kerberos/ccache support when required by the AD lab workflow.
- [ ] Add explicit SQL authentication as a separate mode.
- [ ] Add real-server integration fixtures for the supported authentication modes.
- [ ] Preserve read-only SQL, private credentials, explicit database/table scope,
  export limits, and actual versus exported row counts.

Completion: authentication modes are explicit and independently tested. The current
adapter supports NTLM password/hash authentication. Its bounded archive is a scoped
data export, not a transactionally consistent database backup.

## Tooling and setup

| Tool | Next action |
| --- | --- |
| Playwright/Chromium, MCP SDK, Impacket, ffuf, Nmap | Available in the local environment at the date above. Keep versions and readiness checks reproducible on competition machines. |
| Nuclei | Missing from the checked environment. Install if using Fieldkit's existing Nuclei execution adapter; its absence caused the optional test skip. Select and review templates explicitly. |
| Burp Suite | Use with the Fieldkit bridge to capture legitimate request baselines. Confirm the desktop application and extension are available on the competition machine. |
| Interactsh | Recommended for the DNS/HTTPS callback adapter above. |
| sqlcmd | Optional independent check of database access and export counts; not required by the current Impacket adapter. |

Optional Python extras remain separate: `browser` installs Playwright, `mcp`
installs the MCP SDK, and `mssql` installs Impacket. Chromium installation is an
additional browser setup step. See [installation instructions](../README.md).

Tool references: [Nuclei](https://github.com/projectdiscovery/nuclei),
[Burp Proxy](https://portswigger.net/burp/documentation/desktop/tools/proxy), and
[sqlcmd](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-download-install).
