# Authentication, sessions, headers, and CORS

These four modules use the shared Fieldkit runtime. Each accepts multiple target origins,
`--targets-file`, repeated `--path`, and `--inventory` reports from discovery modules. Requests
stay within explicit target origins. A target with a nonstandard port must include it, for
example `https://lab.test:8443`.

Each run creates `report.json`, `inventory.json`, and an `evidence/` directory. Findings are
review leads, with evidence references and contextual notes. Request credentials and learned
cookie values are redacted from evidence. Keep profile and login-sequence files private; they
contain your input credentials and are not copied into the report.

## Session profiles

Create a JSON file such as `profiles.json`:

```json
{
  "profiles": {
    "user": {
      "origins": ["https://lab.test"],
      "cookies": {"session": "REPLACE_WITH_USER_SESSION"}
    },
    "admin": {
      "origins": ["https://lab.test"],
      "headers": {"Authorization": "Bearer REPLACE_WITH_ADMIN_TOKEN"}
    }
  }
}
```

The built-in `anonymous` profile is reserved and contains no supplied credentials. Credentials
are bound to the listed origins, including scheme and port. Each profile uses a separate cookie
jar. Prefer the `cookies` mapping to a fixed `Cookie` header so server cookie updates can take
effect. Most modules choose a profile with `--profile user`.

## `web/auth-compare`

```bash
fieldkit run web/auth-compare https://lab.test \
  --profiles-file profiles.json \
  --compare-profile anonymous --compare-profile user --compare-profile admin \
  --reference-profile admin --path /account --path /api/users
```

The default is to compare all profiles against the last profile in the file. Specify the
reference explicitly when its intended role matters. Names such as `user` and `admin` do not
assign permissions within Fieldkit.

For every endpoint, the report includes each profile's HTTP status, final URL, response size,
body hash, content type, login-page heuristic, and evidence reference. Other profiles are compared
with the reference using bounded token-shingle similarity. `--similarity 0.95` is the default
threshold. An access lead requires similar, nonempty successful content, the same final path and
content type, and no recognized login template. Profiles bound to other origins are recorded as
unavailable instead of being sent to the endpoint.

A shared public page or application template can match across identities. A `200` response alone
does not establish access. Inspect returned records and the application's expected permissions.

## `web/session-check`

Without a sequence file, this module only visits supplied endpoints and reviews cookie flags:

```bash
fieldkit run web/session-check https://lab.test --path /login
```

For login rotation and logout invalidation, provide an explicit sequence JSON file:

```json
{
  "protected_url": "/account",
  "authenticated_contains": "Your private account dashboard",
  "login": {
    "url": "/login",
    "method": "POST",
    "data": {
      "username": "REPLACE_WITH_TEST_USER",
      "password": "REPLACE_WITH_TEST_PASSWORD"
    }
  },
  "logout": {
    "url": "/logout",
    "method": "POST"
  }
}
```

```bash
fieldkit run web/session-check https://lab.test \
  --sequence-file sequence.json --cookie-name session
```

`data` objects are submitted as form fields. For a JSON API, use a serialized JSON string for
`data` and `"headers": {"Content-Type": "application/json"}`. Requests default to `POST` if the
method is omitted. Both steps accept explicit headers. Sequence URLs must share one origin
within the configured targets. Relative sequence URLs require exactly one target.

Fieldkit uses a working copy of the selected profile, checks the protected resource anonymously,
executes login, and verifies that the protected response differs from the anonymous baseline.
The optional `authenticated_contains` marker improves this check; it must be present in the
authenticated response and absent from the anonymous response. Choose a stable string visible
only after authentication. Public pages and failed login baselines produce an inconclusive result.

Cookie values are compared in memory; the report lists only changed, unchanged, added, and
removed names. `--cookie-name` identifies the actual session cookies for rotation findings.
Unchanged cookies are flagged only when a login transition was observed. With no names supplied,
the report inventories changes without assuming which cookie identifies the session.

Before logout, Fieldkit clones the authenticated credentials and cookie jar. After executing
logout on the working session, it replays the protected request using that earlier snapshot.
Matching authenticated-looking content becomes an invalidation review lead. Failed logout
requests do not become invalidation findings. To check logout using an existing profile, omit
the login step and supply `--profiles-file profiles.json --profile user`.

The sequence runner supports explicit HTTP requests. It does not automate browser login,
multi-factor authentication, or extraction of changing CSRF tokens. Supply current required
headers/form fields, or use an existing session profile. A configured logout may revoke the
server-side session you supplied even though Fieldkit keeps local profile files unchanged.

## `web/header-review`

```bash
fieldkit run web/header-review https://lab.test 192.0.2.10 \
  --path / --path /api/status
fieldkit run web/header-review https://lab.test --path /account \
  --profiles-file profiles.json --profile user
```

Checks include HTTPS HSTS presence or disabling, MIME-sniffing policy, HTML content security
and anti-framing policies, referrer policy, cookie flags, server disclosures, and cache controls
for authenticated HTML/JSON responses. HTML-specific checks do not flag ordinary JSON responses
for lacking document policies. An enforced CSP `frame-ancestors` directive satisfies the framing
check; a report-only policy does not. Missing headers and technology disclosures are observations,
not evidence that an application is exploitable. Cookies intentionally read by JavaScript may
legitimately omit `HttpOnly`.

## `web/cors-check`

```bash
fieldkit run web/cors-check https://lab.test --path /api/account \
  --profiles-file profiles.json --profile user
fieldkit run web/cors-check https://lab.test --path /api/account \
  --origin https://fieldkit.invalid --preflight-method POST \
  --preflight-header content-type
```

Default probes send `https://fieldkit.invalid`, `null`, and a target-name suffix under
`fieldkit.invalid` as Origin header values. Fieldkit connects only to the scoped target; it does
not contact those Origin hosts. Each probe makes a `GET` using the selected profile and an
unauthenticated `OPTIONS` preflight. Redirects are recorded without following them for these
policy probes. `--preflight-method` advertises a method in OPTIONS; it does not send that method.

The report separately evaluates preflight policy for requests with and without browser
credentials, including allowed methods and headers. It records origin reflection, `null` origin
handling, credential policy, and `Vary: Origin`. Wildcard origin plus credential allowance is
reported as an invalid credentialed-sharing configuration, not as demonstrated data exposure.
Wildcard allowed headers do not authorize an `Authorization` request header by themselves.

Confirm sensitive response content and browser cookie/preflight behavior before treating a
credentialed-origin lead as a vulnerability. These probes inspect HTTP policy; they do not run a
browser exploit.

The preflight and credential rules follow the
[WHATWG Fetch Standard](https://fetch.spec.whatwg.org/#cors-preflight-fetch).

## Console equivalents

```text
use web/auth-compare
set TARGETS https://lab.test
set PROFILES_FILE profiles.json
set COMPARE_PROFILES anonymous user admin
set REFERENCE_PROFILE admin
set PATHS /account /api/users
run
```

Use `show options` to see each module's options. Shared `RATE`, `RETRIES`, `TIMEOUT`, `BUDGET`,
and `MAX_BYTES` settings apply to all requests made by these modules.
