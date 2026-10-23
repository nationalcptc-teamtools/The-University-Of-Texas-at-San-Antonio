"""Explicit authenticated HTTP workflows and separate optional browser login."""

import asyncio
import importlib.util
import json
import uuid
from http.cookiejar import Cookie
from urllib.parse import urlsplit

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule, write_private
from fieldkit.core.http import origin
from fieldkit.core.module import Option
from fieldkit.core.replay import bounded_json, execute_request, resolve_request, validate_request
from fieldkit.core.workflows import extract_value, profile_document, substitute
from fieldkit.modules.assessment_helpers import response_summary

SESSION_OUTPUT_OPTIONS = (
    Option(
        "SAVE_PROFILE",
        bool,
        False,
        "Write a private reusable session profile (contains credentials)",
        "--save-profile",
    ),
    Option("SESSION_NAME", str, "authenticated", "Exported session profile name", "--session-name"),
)


def save_session(ctx, name):
    if ctx.settings["SAVE_PROFILE"]:
        relative = "private-session-profile.json"
        write_private(
            ctx.store.root / relative,
            json.dumps(profile_document(ctx, name, ctx.settings["SESSION_NAME"]), indent=2),
        )
        ctx.report["private_session"] = {
            "file": relative,
            "contains_credentials": True,
            "permissions": "0600",
            "profile_name": ctx.settings["SESSION_NAME"],
        }


class SessionWorkflow(NetworkModule):
    name = "web/session-workflow"
    description = "Execute explicit HTML/JSON token workflows with cookie/session continuity."
    options = (
        COMMON_OPTIONS
        + SESSION_OUTPUT_OPTIONS
        + (
            Option(
                "WORKFLOW_FILE",
                str,
                "",
                "Explicit workflow JSON with steps/variables",
                "--workflow-file",
            ),
            Option("MAX_STEPS", int, 20, "Maximum workflow HTTP requests", "--max-steps"),
        )
    )

    def validate(self, settings):
        if not settings["WORKFLOW_FILE"] or settings["MAX_STEPS"] <= 0:
            raise ValueError("Supply --workflow-file and positive --max-steps")
        if settings["SESSION_NAME"] == "anonymous" or not settings["SESSION_NAME"]:
            raise ValueError("SESSION_NAME must be nonempty and cannot be anonymous")
        workflow = bounded_json(settings["WORKFLOW_FILE"], settings["MAX_BYTES"])
        if (
            not isinstance(workflow, dict)
            or not isinstance(workflow.get("steps"), list)
            or not 1 <= len(workflow["steps"]) <= settings["MAX_STEPS"]
        ):
            raise ValueError("Workflow requires a bounded nonempty steps list")
        variables = workflow.get("variables", {})
        if not isinstance(variables, dict) or not all(
            isinstance(k, str) and isinstance(v, (str, int, float, bool))
            for k, v in variables.items()
        ):
            raise ValueError("Workflow variables must map names to scalar values")
        seen = set()
        for number, step in enumerate(workflow["steps"], 1):
            if not isinstance(step, dict):
                raise ValueError("Workflow steps must be objects")
            step["id"] = str(step.get("id", number))
            if step["id"] in seen:
                raise ValueError("Workflow step IDs must be unique")
            seen.add(step["id"])
            validate_request(step.get("request"))
            expectation = step.get("expect")
            if (
                not isinstance(expectation, dict)
                or not isinstance(expectation.get("statuses"), list)
                or not expectation["statuses"]
                or any(
                    not isinstance(s, int) or not 100 <= s <= 599 for s in expectation["statuses"]
                )
            ):
                raise ValueError("Each workflow step requires explicit expect.statuses")
            if "contains" in expectation and not isinstance(expectation["contains"], str):
                raise ValueError("Workflow expect.contains must be a string")
            extraction = step.get("extract", {})
            if not isinstance(extraction, dict) or any(
                not isinstance(k, str)
                or not isinstance(v, dict)
                or v.get("source") not in {"html", "json"}
                for k, v in extraction.items()
            ):
                raise ValueError("Workflow extract must map names to html/json specifications")
        self._workflow = workflow

    async def assess(self, ctx):
        if len(ctx.targets) != 1:
            raise ValueError("Session workflow requires exactly one target origin")
        variables = dict(self._workflow.get("variables", {}))
        ctx.secrets.extend(str(v) for v in variables.values())
        working = "workflow-" + uuid.uuid4().hex
        await ctx.clone_profile(ctx.settings["PROFILE"], working)
        # Static URL scope is validated for every step before any state-changing request.
        for step in self._workflow["steps"]:
            url = step["request"]["url"]
            if "{{" in url:
                # Variable substitution may change paths/queries but never authorities.
                parsed = urlsplit(url)
                if "{{" in parsed.netloc or "{{" in parsed.scheme:
                    raise ValueError("Workflow URL authorities cannot contain variables")
            resolve_request(ctx, {**step["request"], "url": url, "profile": working})
        for step in self._workflow["steps"]:
            record = {
                "kind": "session_workflow",
                "request_id": step["id"],
                "outcome": "inconclusive",
            }
            ctx.report["results"].append(record)
            try:
                request = substitute(step["request"], variables)
                request.update(profile=working, id=step["id"])

                # Login bodies can use application-specific field names; all supplied body
                # strings are secret for this explicitly authenticated workflow.
                def register(item):
                    if isinstance(item, dict):
                        for v in item.values():
                            register(v)
                    elif isinstance(item, list):
                        for v in item:
                            register(v)
                    elif isinstance(item, str):
                        ctx.secrets.append(item)

                for key in ("form", "json", "xml", "body", "data"):
                    if key in request:
                        register(request[key])
                response, _ = await execute_request(ctx, request, label="workflow-step")
                record.update(url=request["url"], response=response_summary(response))
                expected = step["expect"]
                if (
                    response.error
                    or response.status not in expected["statuses"]
                    or (
                        "contains" in expected
                        and expected["contains"].encode() not in response.body
                    )
                ):
                    raise ValueError("Workflow step did not meet explicit response expectation")
                values = {}
                for name, spec in step.get("extract", {}).items():
                    values[name] = extract_value(response, spec)
                    ctx.secrets.append(values[name])
                variables.update(values)
                from fieldkit.core.redaction import SENSITIVE

                ctx.profiles[working].headers.update(
                    {
                        k: v
                        for k, v in request.get("headers", {}).items()
                        if SENSITIVE.search(k) and k.lower() != "cookie"
                    }
                )
                record.update(outcome="observed", extracted_variables=list(values))
            except ValueError as exc:
                record.update(outcome="inconclusive", detail=str(exc))
                ctx.report["errors"].append(
                    {"error": "workflow_failed", "request_id": step["id"], "detail": str(exc)}
                )
                return
        save_session(ctx, working)


class BrowserLogin(NetworkModule):
    name = "web/browser-login"
    description = "Explicit optional Playwright login and private HTTP session transfer."
    options = (
        COMMON_OPTIONS
        + SESSION_OUTPUT_OPTIONS
        + (
            Option("LOGIN_URL", str, "", "Scoped login URL", "--login-url"),
            Option(
                "SUCCESS_SELECTOR",
                str,
                "",
                "Explicit authenticated DOM selector",
                "--success-selector",
            ),
            Option("SUCCESS_URL", str, "", "Explicit authenticated URL glob", "--success-url"),
            Option(
                "BROWSER_TIMEOUT",
                float,
                90.0,
                "Bounded interactive login wait",
                "--browser-timeout",
            ),
            Option(
                "HEADLESS", bool, False, "Launch browser without a visible window", "--headless"
            ),
        )
    )

    def validate(self, settings):
        if not settings["LOGIN_URL"] or not (
            settings["SUCCESS_SELECTOR"] or settings["SUCCESS_URL"]
        ):
            raise ValueError("Browser login requires LOGIN_URL and explicit success selector/URL")
        if not 0 < settings["BROWSER_TIMEOUT"] <= settings["BUDGET"]:
            raise ValueError("BROWSER_TIMEOUT must be positive and fit BUDGET")
        if not settings["SESSION_NAME"] or settings["SESSION_NAME"] == "anonymous":
            raise ValueError("SESSION_NAME cannot be empty or anonymous")

    async def assess(self, ctx):
        if len(ctx.targets) != 1:
            raise ValueError(
                "Browser login supports one explicit origin; cross-origin SSO is unsupported"
            )
        url = ctx.resolve(ctx.settings["LOGIN_URL"], ctx.targets[0])
        if not url:
            raise ValueError("Browser LOGIN_URL leaves explicit scope")
        profile = ctx.profiles[ctx.settings["PROFILE"]]
        if (profile.headers or profile.cookies or profile.cookie_jar or profile.origins) and origin(
            url
        ) not in {origin(o) for o in profile.origins}:
            ctx.report["errors"].append(
                {"error": "profile_scope", "detail": "Profile does not allow browser login origin"}
            )
            return
        if importlib.util.find_spec("playwright") is None:
            ctx.report["errors"].append(
                {
                    "error": "missing_dependency",
                    "detail": "Install Fieldkit[browser] and run playwright install chromium",
                }
            )
            return
        from playwright.async_api import Error, async_playwright
        from playwright.async_api import TimeoutError as BrowserTimeout

        working = "browser-" + uuid.uuid4().hex
        await ctx.clone_profile(ctx.settings["PROFILE"], working)
        try:
            async with async_playwright() as api:
                browser = await api.chromium.launch(headless=ctx.settings["HEADLESS"])
                try:
                    profile = ctx.profiles[working]
                    context = await browser.new_context(
                        ignore_https_errors=ctx.settings["INSECURE"],
                        extra_http_headers=profile.headers,
                        service_workers="block",
                    )
                    seed = [
                        {"name": k, "value": v, "url": ctx.targets[0]}
                        for k, v in profile.cookies.items()
                    ]
                    seed.extend(
                        {
                            "name": c["name"],
                            "value": c["value"],
                            "domain": c["domain"],
                            "path": c.get("path", "/"),
                            "secure": c.get("secure", False),
                            "expires": c.get("expires") or -1,
                        }
                        for c in profile.cookie_jar
                    )
                    if seed:
                        await context.add_cookies(seed)

                    async def route(request):
                        if ctx.in_scope(request.request.url):
                            await request.continue_()
                        else:
                            ctx.report.setdefault("browser_blocked_origins", []).append(
                                urlsplit(request.request.url).netloc
                            )
                            await request.abort()

                    await context.route("**/*", route)

                    async def websocket(socket):
                        ctx.report["browser_websockets_blocked"] = True
                        await socket.close()

                    await context.route_web_socket("**/*", websocket)
                    page = await context.new_page()
                    ctx.console.print(
                        "Complete login in the browser; waiting for the success condition.",
                        markup=False,
                    )
                    async with asyncio.timeout(ctx.settings["BROWSER_TIMEOUT"]):
                        await page.goto(url, timeout=int(ctx.settings["TIMEOUT"] * 1000))
                        if ctx.settings["SUCCESS_URL"]:
                            await page.wait_for_url(
                                ctx.settings["SUCCESS_URL"],
                                timeout=int(ctx.settings["BROWSER_TIMEOUT"] * 1000),
                            )
                        if ctx.settings["SUCCESS_SELECTOR"]:
                            await page.locator(ctx.settings["SUCCESS_SELECTOR"]).wait_for(
                                state="visible", timeout=int(ctx.settings["BROWSER_TIMEOUT"] * 1000)
                            )
                        cookies = await context.cookies(ctx.targets)
                        for c in cookies:
                            ctx.secrets.append(c["value"])
                            cookie = Cookie(
                                0,
                                c["name"],
                                c["value"],
                                None,
                                False,
                                c["domain"],
                                c["domain"].startswith("."),
                                c["domain"].startswith("."),
                                c["path"],
                                True,
                                c["secure"],
                                int(c["expires"]) if c["expires"] > 0 else None,
                                c["expires"] <= 0,
                                None,
                                None,
                                {},
                                False,
                            )
                            ctx.session(working).cookies.jar.set_cookie(cookie)
                        ctx.seeded_profiles.add(
                            (
                                working,
                                origin(url),
                            )
                        )
                        ctx.report["results"].append(
                            {
                                "kind": "browser_login",
                                "url": url,
                                "outcome": "observed",
                                "transferred_cookie_names": [c["name"] for c in cookies],
                                "note": "Success condition is operator defined; localStorage "
                                "bearer tokens, MFA automation and cross-origin SSO "
                                "are unsupported",
                            }
                        )
                        save_session(ctx, working)
                finally:
                    await browser.close()
        except (Error, BrowserTimeout, TimeoutError) as exc:
            ctx.report["errors"].append({"error": "browser_login_failed", "detail": str(exc)[:500]})
