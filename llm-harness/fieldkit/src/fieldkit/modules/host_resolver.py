"""Keep hostname/IP/SNI/Host/redirect/canonical properties distinct."""

import asyncio
import shlex
from urllib.parse import urljoin, urlsplit

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule
from fieldkit.core.module import Option
from fieldkit.core.replay import bounded_json
from fieldkit.core.vault import Vault
from fieldkit.modules.assessment_helpers import response_summary


class HostResolver(NetworkModule):
    name = "web/host-resolver"
    description = (
        "Explain captured host/redirect mappings and generate unexecuted curl --resolve argv."
    )
    requires_targets = False
    options = COMMON_OPTIONS + (
        Option("HOST", str, "", "Passive hostname filter", "--host"),
        Option(
            "MAPPINGS_FILE",
            str,
            "",
            "Operator supplied host-to-address JSON mapping",
            "--mappings-file",
        ),
        Option("PROBE", bool, False, "Explicitly fetch supplied scoped target origins", "--probe"),
        Option("MAX_RECORDS", int, 1000, "Captured asset ceiling", "--max-records"),
    )

    def validate(self, settings):
        if settings["MAX_RECORDS"] <= 0 or not (
            settings["DATABASE"] or settings["TARGETS"] or settings["TARGETS_FILE"]
        ):
            raise ValueError("Supply DATABASE or target origins and positive MAX_RECORDS")
        if settings["PROBE"] and not (settings["TARGETS"] or settings["TARGETS_FILE"]):
            raise ValueError(
                "Probe requires explicit target scope; captured assets do not authorize it"
            )
        self._mappings = (
            bounded_json(settings["MAPPINGS_FILE"]) if settings["MAPPINGS_FILE"] else {}
        )
        if not isinstance(self._mappings, dict):
            raise ValueError("Host mappings must be a hostname-to-address object")
        import ipaddress

        for key, value in self._mappings.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValueError("Mapping host/address values must be strings")
            ipaddress.ip_address(value)

    async def _execute(self, ctx):
        async with ctx:
            async with asyncio.timeout(ctx.settings["BUDGET"]):
                if ctx.settings["PROBE"]:
                    await ctx.prepare()
                await self.assess(ctx)

    async def assess(self, ctx):
        assets = []
        if ctx.settings["DATABASE"]:
            with Vault(ctx.settings["DATABASE"], create=False) as vault:
                assets = vault.records("asset", limit=ctx.settings["MAX_RECORDS"])
        assets.extend(
            {
                "id": "explicit-target",
                "data": {"origin": group[0], "dns_name": urlsplit(group[0]).hostname},
            }
            for group in ctx.candidates
        )
        for asset in assets:
            data = asset["data"]
            host = data["dns_name"]
            if ctx.settings["HOST"] and ctx.settings["HOST"] != host:
                continue
            url = data["origin"]
            parsed = urlsplit(url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            address = self._mappings.get(host) or data.get("ip")
            record = {
                "kind": "host_resolution",
                "url": url,
                "asset": asset["id"],
                "dns_name": host,
                "ip": address,
                "ip_source": "operator_mapping"
                if host in self._mappings
                else "captured"
                if address
                else "unknown",
                "tls_sni": data.get("tls_sni"),
                "expected_tls_sni": host if parsed.scheme == "https" else None,
                "observed_host_header": data.get("observed_host_header"),
                "expected_host_header": parsed.netloc,
                "canonical_url": None,
                "observed_redirect": None,
            }
            if ctx.settings["PROBE"] and ctx.in_scope(url):
                response = await ctx.fetch(url, follow_redirects=False)
                record["response"] = response_summary(response)
                location = response.headers.get("location")
                if location:
                    record["observed_redirect"] = location
                    record["canonical_url"] = urljoin(response.url, location)
                    record["redirect_outside_scope"] = not ctx.in_scope(record["canonical_url"])
                    record["explanation"] = (
                        "308 preserves the method/body at the redirect address"
                        if response.status == 308
                        else "Redirect observed; scope governs any follow-up"
                    )
            if address:
                # Validate captured and operator supplied addresses before generating a command.
                import ipaddress

                ipaddress.ip_address(address)
                resolve_address = f"[{address}]" if ":" in address else address
                argv = ["curl", "--resolve", f"{host}:{port}:{resolve_address}", url]
                record.update(curl_argv=argv, curl_command=shlex.join(argv), executed=False)
            ctx.report["results"].append(record)
