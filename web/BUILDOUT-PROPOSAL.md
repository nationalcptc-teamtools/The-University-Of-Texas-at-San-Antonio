# CPTC web coverage and automation

Status: initial design and roadmap, 2026-09-07. The first CLI release is
implemented; [README.md](README.md) describes its actual supported behavior
and limitations. This document also includes proposed later integrations.

## What the existing material shows

The first release should make basic web checks difficult to miss. Its main
measure of success is evidence-backed coverage of each application, followed
by the number of distinct, verified findings that reach the scribe.

Sources inspected locally:

| Source | Existing value | Gap to address |
| --- | --- | --- |
| `web/web-tooling.sh` | Installs web tools | No scan orchestration, checklist state, output contract, or evidence handoff |
| `nmap_scans.md` | Network discovery, web screenshots, mention of default credentials | Manual transcription; inconsistent output formats; no per-app completion tracking |
| `reporting/obsidian_final_2.zip`, archived Web HTTP checklist | Fingerprinting, content discovery, virtual hosts, TLS, CVE lookup | No default-login, session, or authenticated authorization checks in this short checklist |
| `../OneDrive_1_5-28-2026/checklists/web_checklist.docx` | Already includes default credentials, IDOR, session testing, and many other web tests | Topics do not have per-application owners, required evidence, completion criteria, or a priority queue |
| `reporting/machine_enum_template.md` | Per-machine enumeration and finding notes | Web apps, alternate ports, roles, and individual check status need their own records |
| `reporting/FINDING_TEMPLATE.docx` | Technical description, business impact, affected systems, compliance, evidence, mitigations, references | Scanner observations need validation and a reliable handoff into this structure |

The absence of default-credential findings cannot be attributed simply to a
missing topic: the broader DOCX explicitly lists that test. The proposed
workflow addresses the missing connection between the checklist, the apps
actually discovered, evidence, and reporting.

There are also two small setup issues to fix during implementation:
`web/web-tooling.sh` uses `ZAP_DIR` without defining it in that script, and
the EyeWitness example has `---threads`. The existing installer assumes
APT; running this new workflow on Arch should not execute that installer.

## Recommended first release

Build a Python CLI in this repository, with one local engagement database
and generated Markdown pages that Obsidian can read. Existing tools remain
available for deeper testing. The tracker must work without an AI service.

One operator process owns an engagement database. Individual testers can
run separate engagement workspaces and hand over exports. Concurrent writes
through a shared/synchronized database are not a supported first-release
workflow. A future shared dashboard needs its own server and coordination
design.

Alternative: use the same core with a local browser interface. This gives
testers a more convenient board but adds UI, API, and browser-session work.
A checklist-only release is quicker, but does not enforce execution or
automatically collect evidence. CLI plus Obsidian is the recommended start.

Extend this existing repository. Do not move or duplicate the previous
competition material into a new project. Store real engagement data outside
tracked source files, and do not place it in the general AI context vault.

## Operator flow

1. Create an engagement with explicit allowed targets and exclusions,
   including OT exclusions already required by the team's scan notes.
2. Import Nmap XML or an explicit list of application URLs. Discovery data
   is inventory, not permission to contact newly discovered targets.
3. Review application candidates and assign an owner. Track scheme, host,
   port, and base path; two apps on one IP must not collapse into one check.
4. Run the basic HTTP checks. Save bounded observations and create manual
   work for checks that cannot be completed automatically.
5. Review a product match, then run the matching default-login verifier
   within the engagement's attempt budget. Unsupported products remain
   assigned manual checks.
6. Test relevant account roles and application functions. Record each
   result, the conditions tested, and evidence references.
7. Review candidate findings, produce a scribe handoff, and retest after
   remediation. The coverage board lists anything still untested or blocked.

Nmap XML is the intended input contract, rather than parsing pasted terminal
tables. When the team's Nmap examples are updated, preserve exclusions in
every relevant scan command and save machine-readable output.

## Required coverage

Create the following checks for every application. Priority describes the
order to work; applicability depends on the actual app. A command finishing
successfully is not proof that a check found no issue.

| Priority | Check | Minimum record before closure |
| --- | --- | --- |
| First | Application inventory | Exact origin/base path, service evidence, owner, and separately tracked alternate ports/vhosts |
| First | Product and login identification | Observed product signals, login mechanism, confidence, and any conflicting fingerprint |
| First | Anonymous access to sensitive functions | Resource, unauthenticated result, and why access should require an account |
| First | Default credentials | Product-specific source, permitted attempt count, outcome, and verified identity/access or a blocker |
| First | Exposed setup/admin interfaces | URL, access requirement, observed function, and minimal proof of exposure |
| First | Public files and metadata | Small bounded path set; response content signature and comparison with a nonexistent path |
| First | Cleartext login/session transport | Actual credential/session route and observed protocol; separate login from a generic HTTP landing page |
| Next | Application map | Pages, forms, API endpoints, and role coverage; flag incomplete crawling or JS-only flows |
| Next | Object and function authorization | Controlled accounts/roles, resource ownership, expected access, and actual result |
| Next | Session lifecycle | Cookie properties, login/logout observations, and access after logout when applicable |
| Next | Registration/reset behavior | Workflow-specific evidence using permitted test accounts and a defined attempt budget |
| Next | Files, uploads, and downloads | Actual exposed function, input/output evidence, and bounded validation |
| Next | Input handling | Candidate SQLi, XSS, traversal, SSRF, or similar leads with reproducible validation appropriate to the app |
| Next | Browser and API configuration | CORS, relevant headers, documentation exposure, and demonstrated effect where required |
| Later | Components and TLS depth | Verified product/version/configuration, current source, and applicability rather than a banner-only CVE claim |
| Later | Business workflows | Expected rules, permitted account actions, tested abuse case, and demonstrated business effect |
| Handoff | Finding quality | Evidence, affected assets, technical impact, business impact, mitigations, and references |
| Handoff | Retest | Date, method, observed result, and unresolved limitations |

This is an operational starting set, not a claim of complete WSTG coverage.
Detailed checks should link to the team's existing DOCX material and stable
WSTG sections instead of copying long generic attack lists into the UI.

## Automated checks and integrations

The initial built-in scan performs bounded HTTP requests against explicit
application entries. It gathers product/login hints, redirect observations,
selected response metadata, common public-file candidates, and configuration
observations. Use response signatures and nonexistent-path controls to avoid
calling a catch-all HTTP 200 page an exposed file.

Do not automatically equate missing headers with a high-severity finding,
robots entries with vulnerabilities, an accessible login page with access,
or a version banner with an exploitable CVE. Each is a lead until the
appropriate validation is recorded.

Add Nmap import first. Nuclei and ZAP result imports can follow as separate
adapters. Each import preserves tool/version/template or rule identity,
asset attribution, and source-file provenance. Imported alerts enter the
candidate queue; they do not close all checks for an application.

A future Nuclei runner should use a reviewed, fixed template selection and
explicit request limits. A future ZAP runner should use an application
context, verified authentication, and job tests. Neither integration is
required for the initial tracker to work.

## Default-login verification

Give this check its own queue, visible from the engagement overview. Show
which apps have login pages, which product was identified, whether a
verifier exists, and the remaining manual work.

Each supported profile needs a product/deployment match, an authoritative
default source, exact supported authentication behavior, a protected-resource
or identity verification step, a bounded request/attempt count, and known
failure conditions. Do not reuse the repository's general password list as
a default-login profile.

Authentication proof requires a valid contrast with unauthenticated access
and, when the attempt budget permits, a suitable negative control. A status
200, redirect, issued cookie, or absence of an error string is insufficient.
An already-public resource must not prove a credential worked. Unexpected
responses, MFA, unsupported CSRF flows, throttling, or lockout signals leave
the result inconclusive or blocked. Stop after proof; do not change the
password, configure the application, or exercise privileged write features.

For the first supported product, Grafana documents an initial default login
and a password-change prompt. The adapter must distinguish that initial
setup state from demonstrated access to protected functions. Keep its
supported deployment/version behavior explicit and test it locally before
calling the adapter ready.

Do not label guessed pairs as universal vendor defaults. Jenkins documents
a generated bootstrap password. Modern Tomcat ships without a manager-role
user. Those products can still require checks for anonymous access or
operator-supplied lab credentials, but those are different assertions.

## State, evidence, and AI

Separate execution status from the security result. Execution can be
pending, running, complete, blocked, or not applicable. Results can be
not tested, no issue observed under recorded conditions, candidate, or
confirmed. Blocked and not-applicable entries require a reason; confirmed
findings and completed checks require evidence. The board shows these
counts separately instead of hiding them in a single success percentage.

Keep append-only check attempts with operator identity and UTC timestamps.
Never replace prior finding evidence with a later negative scan. Link
findings to one or more affected apps and check attempts; provide a separate
reviewer disposition rather than allowing a scanner alert to become a final
report automatically.

Evidence records include stable IDs, timestamps, tool/check version, request
method and redacted location, response status, interpretation, limits, and
artifact hashes. Keep raw evidence restricted to the engagement workspace
when needed. Mask authorization values, cookies, tokens, credentials, and
sensitive response content in exported context; redaction is not a guarantee
that arbitrary raw responses are safe to share.

AI gets a small structured brief: application metadata, explicit scope,
completed checks, unresolved leads, missing evidence, and allowed next
actions. It can prioritize, deduplicate, explain gaps, and draft the existing
finding sections. Retrieved pages and scanner output are untrusted evidence,
not instructions to execute. No direct shell commands are derived from page
text. Product matching alone does not authorize credential attempts.

Finding drafts use the team's current template fields. Severity, compliance
claims, and business impact require support and review. Leave unproven
claims unresolved instead of inventing them for a polished report.

## Acceptance tests before operational use

- Import fixtures covering alternate web ports, TLS services, multiple apps,
  IPv4/IPv6, malformed XML, and duplicate records without losing coverage.
- Refuse out-of-scope targets and redirects before contacting them. Exercise
  hostname resolution, excluded addresses, redirect loops, and budget limits.
- Test vulnerable and hardened local apps with identical branding. Detect
  the intended default-login case while rejecting invalid credentials,
  public identity pages, catch-all 200 pages, and fake success responses.
- Verify throttling, timeouts, unsupported login mechanisms, and interrupted
  runs stay visible as incomplete work.
- Ensure credentials and session values do not enter console output,
  generated Markdown/AI briefs, source control, or shared context.
- Prevent completed/confirmed state without required evidence. Preserve
  prior attempts, owner assignments, reviewer decisions, and retest history.
- Run the full local loop: initialize, import, scan, validate, record,
  export, reopen, and show the same unresolved checks and finding links.

Use synthetic loopback fixtures first. No historical competition address is
a live test target for this development task.

## Decisions for the build

The initial release uses CLI with Obsidian exports. It uses SQLite with one
local operator process, strict address/hostname scope, no followed redirects,
250 ms request spacing, a 24-request basic-scan budget, and a persistent
two-POST login budget per origin. Grafana is the first authentication adapter;
synthetic fixtures validate its protocol behavior. Live product compatibility,
additional adapters, external scanner imports, and a browser UI remain later
work. See the README for the authoritative current feature boundary.

## Primary references checked on 2026-09-07

- [OWASP WSTG 4.2: default credentials](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials)
- [OWASP WSTG 4.2: authorization testing](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/)
- [Nmap XML output](https://nmap.org/book/output-formats-xml-output.html)
- [Nuclei running and output controls](https://docs.projectdiscovery.io/opensource/nuclei/running)
- [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
- [Grafana first sign-in](https://grafana.com/docs/grafana/latest/setup-grafana/sign-in-to-grafana/)
- [Jenkins installation and bootstrap password](https://www.jenkins.io/doc/book/installing/linux/)
- [Tomcat default user configuration](https://github.com/apache/tomcat/blob/main/conf/tomcat-users.xml)
