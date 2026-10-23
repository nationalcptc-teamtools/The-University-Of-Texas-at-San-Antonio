"""Legitimate export/replay baseline gate and one explicit controlled field change."""

import hashlib

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule
from fieldkit.core.module import Option
from fieldkit.core.replay import (
    bounded_json,
    edit_request,
    execute_request,
    resolve_request,
    validate_request,
)
from fieldkit.core.vault import Vault
from fieldkit.core.workflows import extract_value, substitute
from fieldkit.modules.assessment_helpers import (
    looks_like_login,
    response_similarity,
    response_summary,
)
from fieldkit.modules.auth_matrix import response_check


class WorkflowVerifier(NetworkModule):
    name = "web/workflow-verify"
    description = "Verify an explicit legitimate sequence before one confirmed field modification."
    options = COMMON_OPTIONS + (
        Option(
            "WORKFLOW_FILE",
            str,
            "",
            "Sequence with requests, resource expectations and one change",
            "--workflow-file",
        ),
        Option(
            "REQUEST_IDS",
            list,
            [],
            "Vault requests for baseline; requires --expect-file",
            "--request-id",
        ),
        Option("EXPECT_FILE", str, "", "Resource-specific baseline check JSON", "--expect-file"),
        Option(
            "CONFIRM_MODIFICATION",
            bool,
            False,
            "Explicitly authorize the single supplied modification",
            "--confirm-modification",
        ),
        Option(
            "ARTIFACT_ID",
            str,
            "",
            "Known artifact whose unmodified replay is being verified",
            "--artifact-id",
        ),
        Option(
            "MAX_STEPS", int, 10, "Maximum baseline steps including final replay", "--max-steps"
        ),
    )

    def validate(self, settings):
        if not settings["DATABASE"] or settings["MAX_STEPS"] <= 0:
            raise ValueError("Workflow verification requires DATABASE and positive MAX_STEPS")
        if settings["WORKFLOW_FILE"]:
            workflow = bounded_json(settings["WORKFLOW_FILE"], settings["MAX_BYTES"])
        else:
            if not settings["REQUEST_IDS"] or not settings["EXPECT_FILE"]:
                raise ValueError("Supply WORKFLOW_FILE or selected request IDs and EXPECT_FILE")
            check = bounded_json(settings["EXPECT_FILE"])
            workflow = {
                "steps": [{"request": name, "expect": check} for name in settings["REQUEST_IDS"]]
            }
        if (
            not isinstance(workflow, dict)
            or not isinstance(workflow.get("steps"), list)
            or not 1 <= len(workflow["steps"]) <= settings["MAX_STEPS"]
        ):
            raise ValueError("Workflow requires a bounded nonempty steps list")
        with Vault(settings["DATABASE"], create=False) as vault:
            for step in workflow["steps"]:
                if not isinstance(step, dict) or "request" not in step:
                    raise ValueError("Each workflow step requires a request")
                step["request"] = (
                    vault.request(str(step["request"]))
                    if not isinstance(step["request"], dict)
                    else validate_request(step["request"])
                )
                check = step.get("expect")
                if not isinstance(check, dict) or not (
                    check.get("contains") or "json_pointer" in check or "sha256" in check
                ):
                    raise ValueError(
                        "Baseline expectations require a resource marker, "
                        "JSON value or body SHA-256"
                    )
                if "contains" in check and (
                    not isinstance(check["contains"], str) or not check["contains"]
                ):
                    raise ValueError("Resource marker must be a nonempty string")
                if "json_pointer" in check and (
                    not isinstance(check["json_pointer"], str)
                    or not check["json_pointer"].startswith("/")
                    or "equals" not in check
                ):
                    raise ValueError("JSON resource check requires /pointer and equals")
                if "sha256" in check and (
                    not isinstance(check["sha256"], str)
                    or len(check["sha256"]) != 64
                    or any(c not in "0123456789abcdef" for c in check["sha256"])
                ):
                    raise ValueError("Body SHA-256 must be 64 lowercase hexadecimal characters")
                if not isinstance(check.get("statuses", [200]), list) or not all(
                    isinstance(s, int) and 100 <= s <= 599 for s in check.get("statuses", [200])
                ):
                    raise ValueError("Expected statuses must be HTTP status integers")
                extract = step.get("extract", {})
                if not isinstance(extract, dict) or not all(
                    isinstance(k, str)
                    and isinstance(v, dict)
                    and v.get("source") in {"json", "html"}
                    for k, v in extract.items()
                ):
                    raise ValueError("Extract requires named HTML/JSON specifications")
            if settings["ARTIFACT_ID"] and vault.get(settings["ARTIFACT_ID"])["kind"] != "artifact":
                raise ValueError("ARTIFACT_ID must identify a captured artifact")
        change = workflow.get("modification")
        if change and (
            not isinstance(change, dict)
            or not isinstance(change.get("location"), str)
            or "value" not in change
        ):
            raise ValueError("Modification must specify exactly one location/value")
        if change and set(change) - {"location", "value"}:
            raise ValueError("Only one selected request field modification is supported")
        self._workflow = workflow

    async def assess(self, ctx):
        workflow = self._workflow
        variables = {}
        for step in workflow["steps"]:
            resolve_request(ctx, step["request"])
        evidence, last, response = [], None, None
        result = {
            "kind": "workflow_verification",
            "baseline_verified": False,
            "artifact": ctx.settings["ARTIFACT_ID"] or None,
            "outcome": "inconclusive",
            "steps": [],
        }
        ctx.report["results"].append(result)
        for step in workflow["steps"]:
            request = substitute(step["request"], variables)
            response, _ = await execute_request(ctx, request, label="unmodified-baseline")
            check = step["expect"]
            valid = (
                not response.error
                and not looks_like_login(response)
                and response.status in check.get("statuses", [200])
                and hashlib.sha256(response.body).hexdigest() == check["sha256"]
                and (
                    not ("contains" in check or "json_pointer" in check)
                    or response_check(response, check) is True
                )
                if "sha256" in check
                else response_check(response, check) is True
            )
            evidence.append(response.evidence_id)
            result["steps"].append({**response_summary(response), "expectation_met": valid})
            if not valid:
                result["detail"] = "Legitimate unmodified baseline failed; modification blocked"
                break
            for name, specification in step.get("extract", {}).items():
                try:
                    variables[name] = extract_value(response, specification)
                except ValueError as exc:
                    result["detail"] = "Token extraction failed; modification blocked"
                    ctx.report["errors"].append({"error": "extraction_failed", "detail": str(exc)})
                    break
                ctx.secrets.append(variables[name])
            if result.get("detail"):
                break
            last = request
        else:
            result.update(
                baseline_verified=True,
                outcome="validated",
                detail="Explicit baseline resource expectations met; no exploit impact inferred",
            )
        change = workflow.get("modification")
        result["modification_requested"] = bool(change)
        result["modification_executed"] = False
        if result["baseline_verified"] and change:
            if not ctx.settings["CONFIRM_MODIFICATION"]:
                result["detail"] = (
                    "Baseline validated; single modification requires --confirm-modification"
                )
            else:
                modified_request = edit_request(last, change["location"], change["value"])
                modified, _ = await execute_request(
                    ctx, modified_request, label="single-controlled-modification"
                )
                result.update(
                    modification_executed=True,
                    comparison=response_summary(modified),
                    similarity=response_similarity(response, modified),
                    modification_outcome="inconclusive" if modified.error else "observed",
                )
                evidence.append(modified.evidence_id)
        result["evidence"] = evidence
        with Vault(ctx.settings["DATABASE"]) as vault:
            identifier = vault.put(
                "workflow", result, source={"run": str(ctx.store.root), "evidence": evidence}
            )
            if ctx.settings["ARTIFACT_ID"]:
                vault.link(ctx.settings["ARTIFACT_ID"], identifier, "baseline_verification")
