"""Passive, selected Burp captures into the local request vault."""

from fieldkit.core.burp import BurpReceiver, capture_origins
from fieldkit.core.local import LOCAL_OPTIONS, LocalModule
from fieldkit.core.module import Option


class BurpBridge(LocalModule):
    name = "integrations/burp-bridge"
    description = (
        "Receive selected Burp request/response pairs into the private vault over loopback."
    )
    options = LOCAL_OPTIONS + (
        Option("DATABASE", str, "artifacts/fieldkit.sqlite", "Private capture vault", "--database"),
        Option("ORIGINS", list, [], "Allowed capture origins; grants no probing scope", "--origin"),
        Option("PORT", int, 0, "Loopback port; 0 selects an unused port", "--port"),
        Option(
            "CONFIG_FILE",
            str,
            "",
            "New private Burp properties file; default run directory",
            "--config-file",
        ),
        Option("MAX_CAPTURES", int, 100, "Maximum exchanges before stopping", "--max-captures"),
        Option("MAX_ENTRIES", int, 10, "Maximum exchanges per send", "--max-entries"),
        Option(
            "MAX_BODY_BYTES",
            int,
            524288,
            "Maximum decoded bytes per request/response",
            "--max-body-bytes",
        ),
        Option(
            "DRY_RUN", bool, False, "Save capture plan without opening listener/vault", "--dry-run"
        ),
    )

    def validate(self, settings):
        self._origins = capture_origins(settings["ORIGINS"])
        if not settings["DATABASE"]:
            raise ValueError("DATABASE is required")
        if not 0 <= settings["PORT"] <= 65535:
            raise ValueError("PORT must be 0-65535")
        if not 1 <= settings["MAX_ENTRIES"] <= 50 or not 1 <= settings["MAX_CAPTURES"] <= 10000:
            raise ValueError("MAX_ENTRIES must be 1-50 and MAX_CAPTURES 1-10000")
        if not 0 < settings["MAX_BODY_BYTES"] <= 8388608 or settings["MAX_BYTES"] > 16777216:
            raise ValueError(
                "Body limit must be 1-8388608 and capture limit at most 16777216 bytes"
            )

    async def assess(self, ctx):
        if ctx.settings["DRY_RUN"]:
            ctx.report["plan"] = {
                "capture_origins": sorted(self._origins),
                "network_requests": 0,
                "listener_opened": False,
                "scope_authorizes_requests": False,
            }
            return
        await BurpReceiver(ctx, self._origins).run()
