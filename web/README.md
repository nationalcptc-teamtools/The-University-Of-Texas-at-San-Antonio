# Web coverage workflow

This CLI turns a list of web apps into assigned checks and evidence. Use it
to prevent basic tests, especially default credentials, from being missed.
It runs locally with Python 3.11+ and no extra packages. It does not need
the APT installer, an AI API key, or a running Obsidian instance.

## What works now

- Nmap XML import and explicit application URLs, including alternate ports
  and application base paths.
- Twenty required checks per application, owner assignment, pending and
  blocked work, evidence references, and append-only check history.
- Serial HTTP scans: root response/product hints, selected header presence,
  robots/sitemap response metadata, and a Git HEAD exposure candidate check
  with a nonexistent-path control.
- A Grafana initial-login verifier with an unauthenticated identity baseline,
  an invalid login control, and protected identity verification.
- Markdown coverage pages, finding draft sections, structured evidence,
  and a small scope-aware AI brief.

The broader team DOCX already included default credentials. This workflow
adds the missing per-app record of whether the check happened and what it
proved. The [buildout design](BUILDOUT-PROPOSAL.md) explains the source review.

## Start an engagement

Run these commands from the repository root. Keep engagement data outside
the Git repository and outside the shared general-purpose AI context vault.

```sh
python3 web/cptc_web.py --help
```

Create a scope JSON using [scope.example.json](scope.example.json). Its
default is loopback only. Replace the networks with the engagement's actual
authorized networks, add the exact hostnames needed, and list every excluded
network, including OT. A hostname must be explicitly named, and every DNS
answer must also fall within allowed networks. Exclusions win.

Example using documentation addresses; this is an illustration, not a target:

```json
{
  "allowed_cidrs": ["192.0.2.0/24"],
  "excluded_cidrs": ["192.0.2.240/28"],
  "allowed_hosts": ["portal.example.test"],
  "allow_http_login": false
}
```

```sh
python3 web/cptc_web.py init ~/cptc-engagements/practice --scope /path/to/scope.json
python3 web/cptc_web.py import-nmap ~/cptc-engagements/practice /path/to/scan.xml --owner web-team
python3 web/cptc_web.py add ~/cptc-engagements/practice https://portal.example.test/ --owner web-team
python3 web/cptc_web.py status ~/cptc-engagements/practice
```

Importing does not send requests. Review inferred HTTP/HTTPS schemes and
base paths before scanning. Nmap service discovery cannot inventory all
named virtual hosts or applications under separate paths. Add those explicitly.
The scope is copied into the engagement database at initialization; editing
the source JSON later does not change a running engagement's scope.

## Run the first pass

```sh
python3 web/cptc_web.py scan ~/cptc-engagements/practice --all
python3 web/cptc_web.py next ~/cptc-engagements/practice
python3 web/cptc_web.py assign ~/cptc-engagements/practice 1 web-tester
```

Use an app ID instead of `--all` to scan a single app. Requests are serial,
with at least 250 ms between requests in each command, a 24-request budget
per app/command, a 128 KiB response-body cap, and socket/read deadlines.
These bounds do not impose a total deadline on the OS DNS resolver.
No redirects are followed. Review a redirect and explicitly register its
destination if scope permits it. HTTPS certificate verification stays on;
configure local trust for lab certificates when needed.

The built-in HTTP client ignores environment proxy settings and connects
to the validated numeric DNS address. Targets can use any port that you
explicitly register, but their address must pass the stored scope. This
release does not implement path exclusions or a network-scanner runner.

An exit code of `0` means the requested operation completed. It does not
mean the app is secure or every checklist item is complete. A blocked scan,
input error, or unsupported verification returns `2` and preserves results
already recorded. `status` and `export` do not turn incomplete checks into
passes. Throttling or lockout responses stop the current app check.

## Default credentials: mandatory check, narrow automation

```sh
python3 web/cptc_web.py default-creds ~/cptc-engagements/practice 1
```

This command supports Grafana's documented initial credentials only. It
matches both page and health-API signals, requires anonymous identity access
to be rejected, verifies that a deliberately invalid login is rejected, and
then verifies the expected identity using the returned session. Cookies and
request credentials stay in memory. HTTP 200 or a cookie alone cannot confirm
the finding. No password changes or administrative write operations occur.

There are at most two login POSTs per origin in an engagement, reserved in
the database before each request. Interrupted attempts count. A rerun cannot
reset that budget, and different base paths on one origin share it. Separate
engagement directories are not a shared lockout budget; coordinate testers
before using multiple workspaces against the same service.

HTTP login is disabled unless `allow_http_login` was explicitly enabled in
the engagement scope, which may be appropriate for a local fixture or a
permitted HTTP-only lab. The example scope leaves it disabled.

The profile requests the fixed `/login`, `/api/health`, and `/api/user` paths
under the registered app base. The identity response follows Grafana's
[current-user API](https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/api-legacy/user/#actual-user).
The adapter is tested against synthetic Grafana-like fixtures, not a live
Grafana deployment. Treat live compatibility as unverified until tested on
your lab's version. Alternate SSO, custom login routes, CSRF mechanisms,
bootstrap behavior, and other products can require manual testing. They
remain pending or blocked. A verified initial login proves accepted
credentials and identity; it does not establish all administrator capabilities
or whether a password-change prompt can be bypassed.

Vendor defaults must match the product and deployment. Jenkins documents a
generated bootstrap password; modern Tomcat does not ship a manager-role
user. Do not treat guessed pairs as universal defaults. See the
[Grafana sign-in guide](https://grafana.com/docs/grafana/latest/setup-grafana/sign-in-to-grafana/),
[Jenkins setup](https://www.jenkins.io/doc/book/installing/linux/), and
[Tomcat default user configuration](https://github.com/apache/tomcat/blob/main/conf/tomcat-users.xml).

## Record manual checks

Put a reviewed proof file under the engagement's `evidence/` directory.
Evidence content is not automatically ingested into an AI brief. The tracker
records its relative path, size, and SHA-256. Export refuses a changed or
missing artifact. Use a new file for a retest instead of overwriting proof.

```sh
python3 web/cptc_web.py record ~/cptc-engagements/practice 1 authorization \
  --state complete --result confirmed \
  --note 'Controlled account accessed a resource owned by the second test account; see reviewed evidence' \
  --evidence ~/cptc-engagements/practice/evidence/authorization-proof.md

python3 web/cptc_web.py record ~/cptc-engagements/practice 2 default_credentials \
  --state blocked --note 'Custom login flow; assigned for manual verification'
```

Do not put passwords, session values, or sensitive customer data in command
arguments, owner names, URLs, or notes. Automated evidence stores bounded
metadata and hashes, not raw response bodies or session headers. Basic note
redaction is best effort; review exports before sharing them.

States are `pending`, `complete`, `blocked`, and `na`. Completed checks need
evidence and one of `observed`, `no_issue_observed`, `candidate`, or `confirmed`.
Other states use `not_tested`; a blocker or not-applicable decision needs a
reason. `no_issue_observed` applies only to the recorded test conditions.
An automated rerun appends history and preserves a prior candidate, confirmed
finding, or not-applicable decision. A human can record a new disposition
after review; the old event and evidence remain.

## Manual checks that must remain visible

| Check | Work and evidence needed |
| --- | --- |
| Inventory/login surface | Review each web port, named host, app path, login page, and setup/admin interface; attach a reviewed inventory or screenshot |
| Anonymous access | Compare access to a sensitive route with and without a valid session; document why it should be protected |
| Default credentials | Identify product/deployment, consult its source, use the approved attempt budget, and prove identity/access rather than status codes |
| Transport | Observe the actual login submission and session-bearing requests; an HTTP home page alone is insufficient |
| App map | Record routes, forms, APIs, inputs, accounts, roles, and crawler/browser coverage limits |
| Authorization | Use controlled accounts with different ownership/roles; compare the same resource/action and retain both responses |
| Session | Observe cookie attributes, login rotation, logout invalidation, and expiry with controlled sessions |
| Account flows | Test permitted registration/reset cases with controlled accounts and preserve expected versus observed behavior |
| Files | Review exposed files and upload/download functions with a minimal proof; preserve scope and relevant access controls |
| Input handling | Select checks based on the actual inputs and reproduce candidates before reporting a vulnerability |
| API/browser policy | Check actual authorization and CORS/browser behavior; metadata or a missing header alone does not prove impact |
| Components | Confirm product/version/configuration and vulnerability prerequisites; retain authoritative references |
| Business logic | Define the expected workflow and demonstrate the permitted test case that violates its rules |
| Finding review/retest | Verify affected systems, technical and business impact, mitigations, references, and remediation results |

The HTTP first pass completes only its narrow observation checks. It leaves
login-surface review, account tests, authorization, business logic, and other
manual work open. Use the detailed team DOCX and
[OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)
for test-specific guidance. This is not complete WSTG coverage.

## Export and use with an agent

```sh
python3 web/cptc_web.py export ~/cptc-engagements/practice
```

Open `export/coverage.md` and `export/app-<id>.md` in the engagement's Obsidian
workspace. `evidence.json` contains recorded evidence and check history.
`ai-brief.json` contains scope, app IDs, ownership, and prioritized incomplete
checks. Export replaces generated pages; enter durable decisions with `record`.
Finding draft sections follow the existing report template and leave severity,
business impact, compliance, and mitigations for supported review.

An agent can read `ai-brief.json`, inspect selected evidence locally, run
authorized checks through this CLI, and record results. The contract is in
[AGENTS.md](AGENTS.md). This is a tool-driven local workflow; this release does
not start a hosted AI agent or send engagement data to a provider. Nuclei/ZAP
imports, a browser dashboard, and additional login adapters are future work.

Use one operator process per engagement. The CLI refuses concurrent commands
against the same local workspace. Do not synchronize or concurrently open
the SQLite database through Obsidian LiveSync, SMB, or a cloud file share.
Share reviewed generated Markdown instead. Cross-workspace merge is not yet
implemented.

## Verify locally

```sh
python3 -m unittest discover -s web -p 'test_*.py' -v
```

Tests start synthetic loopback HTTP servers and cover scope enforcement,
DNS pinning, redirects, evidence state, false authentication success,
persistent login budgets, redacted exports, and the complete CLI workflow.
