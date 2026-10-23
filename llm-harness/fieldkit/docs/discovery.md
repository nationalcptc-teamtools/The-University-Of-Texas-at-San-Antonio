# Discovery and input mapping

These modules run through both interfaces:

```bash
fieldkit run web/site-map https://app.example.test --max-pages 100 --max-depth 3
fieldkit console
```

In the console, select `use web/site-map`, set `TARGETS`, inspect `show options`, and `run`.
All examples use placeholder targets. Replace them with the origins in your assessment.
Multiple positional targets and `--targets-file targets.txt` are supported.

Each run writes its own directory under `--output` (default: `artifacts`). The common
runtime produces `report.json`, `inventory.json`, and redacted request/response evidence.
Pass an inventory or report to another module with `--inventory path/to/inventory.json`;
repeat the flag to combine sources. Supply explicit targets on every network run: imported
URLs do not extend scope. A session selected by `--profiles-file` and `--profile` is used
for the run; profiles must allow the requested origin. `--rate`, `--concurrency`, `--timeout`,
`--retries`, `--budget`, and `--max-bytes` bound network requests.

## Site mapping

```bash
fieldkit run web/site-map https://app.example.test \
  --path /portal --max-pages 150 --max-depth 4 --output artifacts
```

`web/site-map` starts at each homepage, `/robots.txt`, `/sitemap.xml`, custom paths, and
imported endpoints. It parses robots `Allow`, `Disallow`, and `Sitemap` entries; sitemap
indexes and namespaced sitemap documents; HTML links, scripts, iframes, forms, and field
names. Robots patterns containing `*` or `$` are recorded neither as concrete paths nor
requested. The module does not treat robots rules as crawl permissions.

Every discovered URL must resolve to a supplied origin. HTTP(S) scheme, hostname, and
port all participate in scope. An HTML `<base>` is honored. Forms are cataloged with their
method and field names, without retaining default input values or submitting the form.
HTTP 401/403 responses are labeled authentication/permission boundaries for manual review.

`MAX_PAGES` limits requests across the entire run, including robots and sitemaps.
`MAX_DEPTH` starts at zero for seeds. Pending work and discovered inventory are also
bounded; the summary indicates truncation. Crawling skips paths containing `logout`,
`signout`, `delete`, or `remove` by default. `SKIP_PATHS` in the console replaces that list;
repeated CLI `--skip-path` flags supply its replacement list. These are heuristic exclusions, not a guarantee
that every application's GET requests are free of side effects. No browser rendering or
JavaScript execution is performed. XML DTD/entity declarations are rejected.

## Content discovery

```bash
fieldkit run web/content-discovery https://app.example.test \
  --wordlist words.txt --extension php --extension bak --max-candidates 1000
```

A small built-in wordlist covers common administrative, API, configuration, backup, and
status paths. Supplying `--word` or `--wordlist` replaces the defaults. Wordlist files use
one path/word per line, support `#` comment lines, and are limited to 10 MiB. Relative words
are rooted at `/`; absolute external URLs and `//host` paths are invalid. Every file
candidate is requested as written and with each supplied extension appended. Directory
candidates ending in `/` do not receive suffixes. For example, `--word config
--extension php --extension bak` probes `/config`, `/config.php`, and `/config.bak`.

With `SOFT_404` enabled, two random missing paths calibrate each directory/extension shape
before candidate requests. Successful fallback bodies can be filtered even when they
reflect the requested path. Bodies of up to 8 KiB can be compared approximately using
`--similarity` (default `0.98`); larger bodies require an exact normalized match. Distinct
redirect destinations are preserved. Redirects are not followed in this module. Disable
calibration with `--no-soft-404` if a site's behavior makes it unsuitable.

Results include status, content type, size, SHA-256, verdict, evidence reference, and a
simple rank. Nonmissing responses that differ from calibration enter the inventory.
Wildcard detection is heuristic: dynamic fallback content, generic access-denied pages,
and catch-all redirects can require manual review. Filtered responses remain in the
report rather than being silently discarded. `MAX_CANDIDATES` covers the entire run;
calibration adds at most two requests per candidate shape and is subject to the run budget.

## API inventory

```bash
fieldkit run web/api-inventory https://app.example.test
fieldkit run web/api-inventory https://app.example.test \
  --path /docs/openapi.yaml --only-custom --max-operations 1000
```

`web/api-inventory` discovers common specification paths and reads OpenAPI 3.x or Swagger
2.0 JSON/YAML documents. It inventories methods, parameter names/locations/types, simple
request-body properties, declared security schemes, and whether authentication is optional.
It honors Swagger `basePath` and OpenAPI document/path/operation server declarations,
including variables with defaults. Out-of-scope server URLs are omitted.

Local JSON Pointer references are resolved with cycle/depth checks. External references
are never fetched, and skipped references are noted in each document result. Complex
composed schemas (`allOf`/`oneOf`/`anyOf`), deeply nested body fields, callbacks, and links
are not expanded. Invalid documents become unrecognized-document results. A specification
is a declaration, not proof of actual access control.

A private `request-templates.json` sidecar contains methods, URLs, query/header placeholders,
body placeholders, and required authentication scheme names. No generated operation is
executed, including GET operations; only the specification URLs are requested. Fill in
path parameters, request bodies, and credentials before manually using a template.
`MAX_DOCUMENTS` and `MAX_OPERATIONS` bound the run.

## Parameter mapping

```bash
fieldkit run web/parameter-map https://app.example.test \
  --inventory artifacts/PRIOR_RUN/inventory.json --path /assets/app.js
fieldkit run web/parameter-map https://app.example.test \
  --path '/search?q=example' --reflect --max-parameters 25
```

`web/parameter-map` combines query names, links, HTML form fields, imported API parameters,
JavaScript URL query strings, and syntactic JavaScript parameter-access hints. JS hints are
marked `unknown` because calls such as `.get("name")` do not establish a receiving endpoint.
The module inspects each homepage and its input URLs; it does not recursively crawl pages
or automatically download every referenced script. Chain a site-map/artifact inventory to
supply those inputs. URLs known only as non-GET operations are inventoried without fetching
them. `MAX_URLS` bounds fetched input URLs.

Marker requests are disabled by default. `--reflect` sends a random harmless alphanumeric
marker in one GET query parameter at a time, compares against a baseline, and records
response body offsets and header names. `--marker` accepts a custom marker of 8–64
alphanumeric/underscore/hyphen characters. Baseline occurrences prevent a positive finding.
POST forms, body/header parameters, unknown JS hints, password/file fields, sensitive
parameter names, action-like paths, and unresolved API path templates are not probed.

`MAX_PARAMETERS` limits reflection probes; each probe uses a baseline plus a marker request.
A reflection finding is a lead for manual investigation and does not establish XSS or
another vulnerability. Field values and surrounding response snippets are omitted from
parameter records; the shared evidence capture handles redaction and bounded previews.
