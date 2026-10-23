# JavaScript review, reports, and team workflow

These modules work with local evidence collected by Fieldkit. Automatic findings are
leads for manual review. They do not establish exploitability or application impact.
All commands also work through the interactive console with `use`, `set`, and `run`.

## Review JavaScript

Read an artifact collection report, individual script, source map, or directory:

```bash
fieldkit run web/js-review --input artifacts/RUN/report.json
fieldkit run web/js-review --input ./downloaded-js --output reviews
fieldkit run web/js-review --input app.js --input vendor.js
fieldkit run web/js-review --input app.js --check endpoints --check routes
```

The default checks are `endpoints`, `routes`, `hostnames`, `secrets`, and `maps`.
The output includes source names, line and column numbers, redacted surrounding
context, and a confidence of `review`. Endpoint and route checks use static string
matching; computed URLs and obfuscated code may not be identified. Possible-secret
checks cover common credential assignment names, GitHub token patterns, AWS access-key
IDs, and JWT-shaped literals. An AWS access-key ID or JWT-shaped string is a lead,
not proof of a valid credential. Detected values are redacted in the findings.

Local input does not require targets. To add discovered URLs to a scoped endpoint
inventory or retrieve remote source maps, supply explicit target origins:

```bash
fieldkit run web/js-review https://app.example.test \
  --input artifacts/RUN/report.json --fetch-maps
fieldkit run web/js-review https://app.example.test \
  --inventory artifacts/RUN/inventory.json --fetch-maps
fieldkit run web/js-review https://app.example.test --path /assets/app.js
```

With no local `--input`, remote inputs are the JavaScript/source-map URLs selected by
`--path` or `--inventory`. A homepage alone does not perform JavaScript discovery;
use the collector or site mapper to create that inventory. An inventory does not
authorize scope: supply target origins for remote requests. `--fetch-maps` defaults
to false and requires explicit origins. All fetched references and redirects remain
subject to the shared request limits and scope rules.

Source maps may be adjacent local files, JSON data URLs, or optional remote references.
The reviewer analyzes embedded `sourcesContent`, including sectioned maps; it never
executes JavaScript or treats source-map `sources` names as filesystem paths. Missing
embedded content cannot be reconstructed from mappings. File references cannot escape
the explicitly supplied directory, the explicit input file's parent, or a report's run
directory. Symlinks pointing outside that root are rejected. Exported and reviewed
reports preserve each artifact's original run root. To review such a report, explicitly
authorize those original locations:

```bash
fieldkit run web/js-review --input exports/RUN/report.json \
  --artifact-root artifacts/ORIGINAL_RUN
```

`--artifact-root` is repeatable for merged reports. References to other locations are
rejected even if a report claims they contain its artifacts. The default `--max-files`
is 500; `--max-bytes` bounds each input and each map's embedded content. Limit and parse
errors appear in the run report.

## Export reports

```bash
fieldkit run web/report-export --input artifacts/RUN/report.json --output exports
fieldkit run web/report-export \
  --input teammate-a/report.json --input teammate-b/report.json --output exports
```

A unique output directory contains `report.json` and `report.md`. The Markdown draft
includes affected URLs, observations, severity, confidence, reproduction guidance,
manual impact/remediation placeholders, and an evidence index. It supports the original
collector schema (v1) and assessment reports (v2). Multiple inputs are merged first.

Exports redact common credential fields, credential-shaped assignments, and detected
token formats. Redaction is heuristic: review the draft before sharing it, particularly
when manually adding arbitrary secrets to notes or context. Original collected artifacts
stay in their original run directories. Preserve those directories alongside the reports;
an evidence index does not copy original artifact files into the export. `artifact_root`
metadata preserves the original absolute location when a report moves within the same
machine. When transferring evidence to another machine, transfer the complete original
run folders and update their `artifact_root` metadata to the new location, then pass those
roots explicitly to JavaScript review.

## Compare runs

```bash
fieldkit run results/compare \
  --before artifacts/BASELINE/report.json \
  --after artifacts/LATER/report.json --output comparisons
```

The output has `added`, `removed`, and `changed` arrays separately for findings,
request/results records, and endpoints. Each changed record preserves its `before`
and `after` values. Stable identities use semantic location fields such as URL,
method, profile, finding kind/title, source/line, parameter, and cookie name.
Timestamps, evidence IDs, local artifact paths, and team review decisions do not count
as a changed observation. A changed HTTP status or body hash does.

JavaScript line changes may appear as removed/added locations. Compare outputs have a
different structure from assessment reports; inspect their Markdown/JSON directly
rather than passing them back into assessment report importers.

## Merge and assign team findings

```bash
fieldkit run results/merge \
  --input teammate-a/report.json --input teammate-b/report.json --output team
fieldkit run results/review \
  --input team/RUN/report.json --finding-id finding-REPLACE_WITH_ID \
  --assignee Alice --status in-progress --note 'Checking application behavior' \
  --output team
```

Review statuses are `unreviewed`, `in-progress`, `confirmed`, `dismissed`, and `resolved`.
Use the ID shown in the report. Each update writes a new report and preserves previous
review metadata in `review_history`; source reports are not edited. Export the updated
report to include the assignment and review status in the draft.

Merging deduplicates findings, results, and endpoints. Evidence IDs are namespaced by
input report and retain the originating report location. Conflicting observations are
preserved in `observation_conflicts`, and incompatible review assignments/decisions
remain visible in `review_conflicts`. The first observation/review stays primary; the
merge does not silently resolve a teammate's decision.

## Developer API

`fieldkit.core.results` exports:

- `stable_id(record, kind="finding")`: stable semantic-location identifier.
- `normalize_report(report)`: copy a v1/v2 report into the common schema.
- `load_report(path)`: parse and normalize a saved report.
- `compare_reports(before, after)`: compare record collections with both sides of changes.
- `merge_reports(reports)`: deduplicate while preserving review/evidence provenance.
- `update_review(report, finding_id, status=..., assignee=..., note=...)`: return a copy
  with one finding's review metadata updated.

These functions do not mutate their inputs. Network modules should use the common
assessment context for scoped requests, endpoint inventory, finding creation, and
redacted evidence. `JSReview` sets `requires_targets = False` to permit local-only runs.
