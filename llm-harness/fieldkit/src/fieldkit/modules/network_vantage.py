"""Read-only local routing/tunnel diagnostics and explicit TCP vantage comparison."""

import asyncio
import errno
import hashlib
import json
import shutil
import socket
import sys
import time
from pathlib import Path

from fieldkit.core.local import LOCAL_OPTIONS, LocalModule
from fieldkit.core.module import Option
from fieldkit.core.storage import utc_now
from fieldkit.core.vantage import (
    DEVICE,
    address,
    parse_interfaces,
    parse_routes,
    safe_read,
    target_name,
)

SOURCES = [
    "https://www.kernel.org/doc/html/latest/networking/operstates.html",
    "https://www.kernel.org/doc/html/latest/networking/tuntap.html",
    "https://man7.org/linux/man-pages/man8/ip-route.8.html",
    "https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/net/tun.c",
]
OUTCOMES = {
    "reachable",
    "refused",
    "timeout",
    "no_route",
    "permission_denied",
    "error",
    "not_probed",
    "unavailable",
}
VANTAGE_OPTIONS = (
    Option("TARGETS", list, [], "Explicit IP addresses or DNS hostnames (repeat)", "--target"),
    Option("PORTS", list, [], "Explicit TCP ports to check (repeat)", "--port"),
    Option(
        "PROBE", bool, False, "Connect once to the explicitly selected TCP endpoints", "--probe"
    ),
    Option(
        "DRY_RUN", bool, False, "Inspect local metadata; suppress DNS and TCP probes", "--dry-run"
    ),
    Option(
        "IMPORT", list, [], "Structured vantage JSON from another host (repeat)", "--import-vantage"
    ),
    Option(
        "DEVICE", str, "", "Existing interface name to focus busy-device diagnostics", "--device"
    ),
    Option(
        "MAX_HOSTS",
        int,
        8,
        "Maximum selected targets plus imported host observations",
        "--max-hosts",
    ),
    Option("MAX_PORTS", int, 16, "Maximum explicitly selected ports", "--max-ports"),
    Option("MAX_PROBES", int, 32, "Maximum actual TCP connection attempts", "--max-probes"),
    Option("MAX_ADDRESSES", int, 2, "Maximum resolver addresses per target", "--max-addresses"),
    Option("MAX_INTERFACES", int, 128, "Maximum interfaces retained", "--max-interfaces"),
    Option("MAX_ROUTES", int, 256, "Maximum routes retained", "--max-routes"),
    Option(
        "MAX_PROCESSES", int, 1024, "Maximum process metadata entries inspected", "--max-processes"
    ),
    Option("MAX_FDS", int, 4096, "Maximum process descriptors inspected", "--max-fds"),
)


def parse_dns(data, maximum):
    addresses = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        parts = line.split()
        parsed = address(parts[0]) if parts else None
        if parsed and parsed not in addresses:
            addresses.append(parsed)
    return addresses[:maximum], len(addresses) > maximum


def text(value, label, maximum=128):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(c) < 32 for c in value)
    ):
        raise ValueError(f"Invalid imported {label}")
    return value


def imported_vantage(document, settings):
    """Keep a bounded schema; imported claims never become local measurements."""
    if not isinstance(document, dict):
        raise ValueError("Imported vantage must be an object")
    result = {
        "host": text(document.get("host"), "host"),
        "provenance": "reported",
        "observed_at": text(document.get("observed_at", "unspecified"), "observed_at"),
        "interfaces": [],
        "tunnels": [],
        "targets": [],
    }
    for name, maximum in (
        ("interfaces", settings["MAX_INTERFACES"]),
        ("tunnels", settings["MAX_INTERFACES"]),
        ("targets", settings["MAX_HOSTS"]),
    ):
        values = document.get(name, [])
        if not isinstance(values, list) or len(values) > maximum:
            raise ValueError(f"Imported {name} exceeds its count limit")
    for item in document.get("interfaces", []):
        if not isinstance(item, dict) or not DEVICE.fullmatch(str(item.get("name", ""))):
            raise ValueError("Invalid imported interface")
        entry = {"name": item["name"], "provenance": "reported"}
        for key in ("exists", "admin_up", "lower_up", "tun", "persistent", "multiqueue"):
            if key in item:
                if not isinstance(item[key], bool):
                    raise ValueError("Imported interface flags must be boolean")
                entry[key] = item[key]
        for key in ("operstate", "link_kind", "tunnel_kind"):
            if isinstance(item.get(key), str):
                entry[key] = text(item[key], key, 32)
        result["interfaces"].append(entry)
    for item in document.get("tunnels", []):
        if not isinstance(item, dict) or not DEVICE.fullmatch(str(item.get("interface", ""))):
            raise ValueError("Invalid imported tunnel observation")
        state = item.get("state", "unknown")
        if state not in {
            "active",
            "connected",
            "disconnected",
            "unknown",
            "attached",
            "reported_active",
            "unverified",
        }:
            raise ValueError("Unsupported imported tunnel state")
        result["tunnels"].append(
            {
                "interface": item["interface"],
                "reported_state": state,
                "state": "reported",
                "active_tunnel_verified": False,
                "provenance": "reported",
            }
        )
    probe_count = 0
    for item in document.get("targets", []):
        if not isinstance(item, dict):
            raise ValueError("Invalid imported target")
        name = target_name(item.get("target"))
        entry = {"target": name, "tcp": [], "routes": [], "provenance": "reported"}
        dns = item.get("dns", {})
        if not isinstance(dns, dict) or not isinstance(dns.get("addresses", []), list):
            raise ValueError("Invalid imported DNS observation")
        if len(dns.get("addresses", [])) > settings["MAX_ADDRESSES"]:
            raise ValueError("Imported DNS addresses exceed MAX_ADDRESSES")
        dns_addresses = [address(value) for value in dns.get("addresses", [])]
        if any(value is None for value in dns_addresses):
            raise ValueError("Invalid imported DNS address")
        entry["dns"] = {"addresses": dns_addresses, "provenance": "reported"}
        checks = item.get("tcp", [])
        routes = item.get("routes", [])
        if (
            not isinstance(checks, list)
            or not isinstance(routes, list)
            or len(routes) > settings["MAX_ADDRESSES"]
        ):
            raise ValueError("Invalid imported target checks/routes")
        for check in checks:
            if not isinstance(check, dict) or not address(check.get("address")):
                raise ValueError("Imported TCP checks require an IP address")
            port = check.get("port")
            if (
                type(port) is not int
                or not 1 <= port <= 65535
                or check.get("outcome") not in OUTCOMES
            ):
                raise ValueError("Invalid imported TCP result")
            if address(name) and address(name) != address(check["address"]):
                raise ValueError("Imported TCP address disagrees with literal target")
            probe_count += 1
            if probe_count > settings["MAX_PROBES"]:
                raise ValueError("Imported TCP checks exceed MAX_PROBES")
            entry["tcp"].append(
                {
                    "address": address(check["address"]),
                    "port": port,
                    "outcome": check["outcome"],
                    "provenance": "reported",
                }
            )
        for route in routes:
            if not isinstance(route, dict) or not address(route.get("address")):
                raise ValueError("Invalid imported route lookup")
            records = route.get("records", [])
            if not isinstance(records, list) or any(not isinstance(r, dict) for r in records):
                raise ValueError("Invalid imported route records")
            # Canonical imported route fields differ from native ip JSON.
            native = (
                [
                    {
                        "dst": r.get("destination", "default"),
                        "dev": r.get("device"),
                        "type": r.get("type", "unicast"),
                        **({"gateway": r["gateway"]} if "gateway" in r else {}),
                    }
                    for r in records
                    if isinstance(r, dict)
                ]
                if isinstance(records, list)
                else None
            )
            normalized, truncated = parse_routes(native, settings["MAX_ROUTES"])
            if truncated:
                raise ValueError("Imported routes exceed MAX_ROUTES")
            entry["routes"].append(
                {
                    "address": address(route["address"]),
                    "records": normalized,
                    "provenance": "reported",
                }
            )
        result["targets"].append(entry)
    return result


async def tcp_check(ip, port, timeout):
    """One TCP handshake, no banner read, credentials, payload, or retry."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    stream = socket.socket(family, socket.SOCK_STREAM)
    stream.setblocking(False)
    started = time.monotonic()
    outcome, code = "reachable", None
    try:
        async with asyncio.timeout(timeout):
            await asyncio.get_running_loop().sock_connect(stream, (ip, port))
    except TimeoutError:
        outcome = "timeout"
    except OSError as exc:
        code = exc.errno
        outcome = {
            errno.ECONNREFUSED: "refused",
            errno.ENETUNREACH: "no_route",
            errno.EHOSTUNREACH: "no_route",
            errno.EACCES: "permission_denied",
            errno.EPERM: "permission_denied",
            errno.ETIMEDOUT: "timeout",
        }.get(code, "error")
    finally:
        stream.close()
    return {
        "address": ip,
        "port": port,
        "outcome": outcome,
        "errno": code,
        "elapsed": time.monotonic() - started,
        "provenance": "locally_measured",
        "note": "TCP handshake only; refusal does not prove the host unreachable.",
    }


class NetworkVantage(LocalModule):
    name = "network/vantage"
    description = "Read-only host, DNS, route and tunnel diagnostics with explicit TCP probes."
    accepts_targets = True
    options = LOCAL_OPTIONS + VANTAGE_OPTIONS

    def validate(self, settings):
        if sys.platform != "linux":
            raise ValueError("network/vantage currently requires Linux")
        for key, ceiling in (
            ("MAX_HOSTS", 32),
            ("MAX_PORTS", 64),
            ("MAX_PROBES", 128),
            ("MAX_ADDRESSES", 8),
            ("MAX_INTERFACES", 1024),
            ("MAX_ROUTES", 4096),
            ("MAX_PROCESSES", 10000),
            ("MAX_FDS", 65536),
        ):
            if type(settings[key]) is not int or not 1 <= settings[key] <= ceiling:
                raise ValueError(f"{key} must be between 1 and {ceiling}")
        if type(settings["MAX_BYTES"]) is not int or not 1 <= settings["MAX_BYTES"] <= 8388608:
            raise ValueError("MAX_BYTES must be an integer between 1 and 8388608")
        self.targets = list(dict.fromkeys(target_name(t) for t in settings["TARGETS"]))
        if len(self.targets) > settings["MAX_HOSTS"]:
            raise ValueError("Selected targets exceed MAX_HOSTS")
        self.ports = []
        for value in settings["PORTS"]:
            if not str(value).isdigit() or not 1 <= int(value) <= 65535:
                raise ValueError("PORTS must contain explicit integers between 1 and 65535")
            if int(value) not in self.ports:
                self.ports.append(int(value))
        if len(self.ports) > settings["MAX_PORTS"]:
            raise ValueError("Selected ports exceed MAX_PORTS")
        if settings["DEVICE"] and not DEVICE.fullmatch(settings["DEVICE"]):
            raise ValueError("DEVICE must be one existing Linux interface name")
        if settings["PROBE"] and not (self.targets and self.ports):
            raise ValueError("PROBE requires explicit TARGETS and PORTS")
        needed = sum(1 if address(t) else settings["MAX_ADDRESSES"] for t in self.targets) * len(
            self.ports
        )
        if settings["PROBE"] and needed > settings["MAX_PROBES"]:
            raise ValueError(
                "Selected TCP checks exceed MAX_PROBES; reduce targets/addresses/ports"
            )
        self.imports = []
        if len(settings["IMPORT"]) > settings["MAX_HOSTS"]:
            raise ValueError("Import files exceed MAX_HOSTS")
        for filename in settings["IMPORT"]:
            source = Path(filename).expanduser().resolve()
            content = safe_read(source, settings["MAX_BYTES"])
            try:
                document = json.loads(content)
            except (ValueError, RecursionError) as exc:
                raise ValueError("Invalid imported vantage JSON") from exc
            candidates = (
                document.get("vantages", [document.get("vantage", document)])
                if isinstance(document, dict)
                else document
            )
            if not isinstance(candidates, list):
                raise ValueError("Import requires a vantage object, report, list or {vantages: []}")
            for item in candidates:
                observation = imported_vantage(item, settings)
                observation["source_file"] = source.name
                observation["source_sha256"] = hashlib.sha256(content.encode()).hexdigest()
                self.imports.append(observation)
                if len(self.imports) + len(self.targets) > settings["MAX_HOSTS"]:
                    raise ValueError("Selected targets plus reported hosts exceed MAX_HOSTS")

    async def assess(self, ctx):
        async with asyncio.timeout(ctx.settings["BUDGET"]):
            vantage = {
                "schema_version": 1,
                "host": ctx.host,
                "observed_at": utc_now(),
                "provenance": "locally_measured",
                "identity": {},
                "resolver": {},
                "interfaces": [],
                "routes": [],
                "processes": [],
                "tun_owners": [],
                "tunnels": [],
                "targets": [],
            }
            ctx.report["vantage"] = vantage
            ctx.report["reported_vantages"] = self.imports
            ctx.report["diagnostics"] = []
            ctx.report["sources"] = SOURCES
            ctx.report["limits"] = [
                "Measurements apply only to this process's network namespace and current user.",
                "Process/TUN/TCP metadata does not prove tunnel forwarding.",
                "No route/device/session changes or remote-host commands are performed.",
                "TCP results concern one address/port/time and do not identify the service.",
                "Route lookups use default selectors; marked/port-dependent policy can differ.",
            ]
            argv = [
                sys.executable,
                "-m",
                "fieldkit.core.vantage",
                "--budget",
                str(min(ctx.settings["TIMEOUT"], ctx.deadline - time.monotonic())),
            ]
            for name in ("MAX_INTERFACES", "MAX_PROCESSES", "MAX_FDS", "MAX_BYTES"):
                argv += ["--" + name.lower().replace("_", "-"), str(ctx.settings[name])]
            collected, evidence = await ctx.command("network_metadata", argv)
            if collected.reason == "finished":
                try:
                    metadata = json.loads(collected.stdout)
                    for key in ("identity", "resolver", "interfaces", "processes", "tun_owners"):
                        vantage[key] = metadata.get(
                            key, {} if key in {"identity", "resolver"} else []
                        )
                    ctx.report["coverage"].append(
                        {"category": "metadata_visibility", **metadata.get("coverage", {})}
                    )
                    if metadata.get("coverage", {}).get("truncated"):
                        ctx.error(
                            "metadata_limit",
                            "local metadata",
                            "Process/interface/fd ceiling reached",
                        )
                except (ValueError, TypeError, AttributeError, RecursionError):
                    ctx.error("malformed_metadata", "metadata collector")
            ip = shutil.which("ip")
            if ip:
                addresses = []
                for category, args, parser in (
                    ("links", ["-j", "-d", "link", "show"], parse_interfaces),
                    ("addresses", ["-j", "address", "show"], parse_interfaces),
                ):
                    result, command_evidence = await ctx.command("network_" + category, [ip, *args])
                    if result.reason != "finished":
                        continue
                    try:
                        records, truncated = parser(
                            json.loads(result.stdout), ctx.settings["MAX_INTERFACES"]
                        )
                        if truncated:
                            ctx.error("record_limit", category, "Collector count ceiling reached")
                        if category == "addresses":
                            addresses = records
                        else:
                            indexed = {item["name"]: item for item in vantage["interfaces"]}
                            for item in records:
                                indexed.setdefault(item["name"], {}).update(item)
                            if len(indexed) > ctx.settings["MAX_INTERFACES"]:
                                ctx.error(
                                    "record_limit",
                                    category,
                                    "Interface snapshot union exceeds ceiling",
                                )
                            vantage["interfaces"] = list(indexed.values())[
                                : ctx.settings["MAX_INTERFACES"]
                            ]
                    except (ValueError, TypeError, RecursionError):
                        ctx.error("malformed_ip_json", category)
                by_name = {item["name"]: item for item in addresses}
                for item in vantage["interfaces"]:
                    item["addresses"] = by_name.get(item["name"], {}).get("addresses", [])
                for family, selector in (("ipv4", "-4"), ("ipv6", "-6")):
                    result, _ = await ctx.command(
                        "network_routes_" + family,
                        [ip, "-j", selector, "route", "show", "table", "all"],
                    )
                    coverage = {
                        "category": "route_family_visibility",
                        "family": family,
                        "status": result.reason,
                        "retained": 0,
                        "truncated": False,
                    }
                    ctx.report["coverage"].append(coverage)
                    if result.reason != "finished":
                        continue
                    try:
                        remaining = ctx.settings["MAX_ROUTES"] - len(vantage["routes"])
                        records, truncated = parse_routes(json.loads(result.stdout), remaining)
                        vantage["routes"].extend({**record, "family": family} for record in records)
                        coverage.update(retained=len(records), truncated=truncated)
                        if truncated:
                            ctx.error(
                                "record_limit", family, "Combined route count ceiling reached"
                            )
                    except (ValueError, TypeError, RecursionError):
                        coverage["status"] = "malformed"
                        ctx.error("malformed_ip_json", family)
            else:
                ctx.error(
                    "missing_dependency",
                    "ip",
                    "Install iproute2 for routes; sysfs evidence is retained",
                )
            for target in self.targets:
                ctx.check_deadline()
                entry = {"target": target, "dns": {}, "routes": [], "tcp": []}
                vantage["targets"].append(entry)
                resolved = [address(target)] if address(target) else []
                if resolved:
                    entry["dns"] = {"outcome": "literal_address", "addresses": resolved}
                elif ctx.settings["DRY_RUN"]:
                    entry["dns"] = {"outcome": "not_resolved_dry_run", "addresses": []}
                else:
                    result, dns_evidence = await ctx.command(
                        "target_dns", ["getent", "ahosts", target]
                    )
                    resolved, truncated = parse_dns(
                        bytes(result.stdout), ctx.settings["MAX_ADDRESSES"]
                    )
                    entry["dns"] = {
                        "outcome": "resolved" if resolved else "unresolved",
                        "addresses": resolved,
                        "evidence": [dns_evidence],
                        "addresses_truncated": truncated,
                        "resolver": "system NSS/getent",
                    }
                    if truncated:
                        ctx.error("address_limit", target, "Resolver addresses truncated")
                    if not resolved:
                        ctx.report["diagnostics"].append(
                            {
                                "kind": "dns_unresolved",
                                "target": target,
                                "detail": (
                                    "Check this host's NSS/DNS configuration and resolver path. "
                                    "Another host may resolve the hostname differently."
                                ),
                                "evidence": [dns_evidence],
                            }
                        )
                for ip_address in resolved:
                    if ip:
                        family = "-6" if ":" in ip_address else "-4"
                        result, route_evidence = await ctx.command(
                            "target_route", [ip, "-j", family, "route", "get", ip_address]
                        )
                        records = []
                        if result.reason == "finished":
                            try:
                                records, _ = parse_routes(json.loads(result.stdout), 8)
                            except (ValueError, TypeError, RecursionError):
                                ctx.error("malformed_ip_json", ip_address)
                        entry["routes"].append(
                            {
                                "address": ip_address,
                                "records": records,
                                "outcome": "route_selected" if records else "unavailable",
                                "evidence": [route_evidence],
                            }
                        )
                        if not records:
                            ctx.report["diagnostics"].append(
                                {
                                    "kind": "route_unavailable",
                                    "target": target,
                                    "address": ip_address,
                                    "detail": (
                                        "Review the address, routing policy and namespace. "
                                        "A route lookup sends no packets."
                                    ),
                                    "evidence": [route_evidence],
                                }
                            )
                    for port in self.ports:
                        if not ctx.settings["PROBE"] or ctx.settings["DRY_RUN"]:
                            entry["tcp"].append(
                                {
                                    "address": ip_address,
                                    "port": port,
                                    "outcome": "not_probed",
                                    "provenance": "local_plan",
                                }
                            )
                            continue
                        ctx.check_deadline()
                        observation = await tcp_check(
                            ip_address,
                            port,
                            min(ctx.settings["TIMEOUT"], ctx.deadline - time.monotonic()),
                        )
                        observation["evidence"] = [
                            ctx.evidence(observation, source="explicit TCP handshake")
                        ]
                        entry["tcp"].append(observation)
            self.diagnose(ctx, vantage)
            for imported in self.imports:
                imported["evidence"] = [
                    ctx.evidence(imported, source="reported vantage " + imported["source_file"])
                ]
            comparison = []
            for observation in [vantage, *self.imports]:
                for target in observation["targets"]:
                    for check in target["tcp"]:
                        comparison.append(
                            {
                                "host": observation["host"],
                                "target": target["target"],
                                "observed_at": observation["observed_at"],
                                "address": check["address"],
                                "port": check["port"],
                                "outcome": check["outcome"],
                                "provenance": "reported"
                                if observation is not vantage
                                else check["provenance"],
                                "evidence": check.get("evidence", observation.get("evidence", [])),
                            }
                        )
            ctx.report["vantage_comparison"] = comparison
            report_evidence = ctx.evidence(vantage, source="local network vantage")
            ctx.report["results"].append(
                {
                    "kind": "network_vantage",
                    "host": ctx.host,
                    "resource": "local network namespace",
                    "targets": len(vantage["targets"]),
                    "tcp_probes": sum(
                        c["outcome"] != "not_probed" for t in vantage["targets"] for c in t["tcp"]
                    ),
                    "evidence": [report_evidence],
                }
            )
            if ctx.settings["DRY_RUN"]:
                ctx.report["plan"] = {
                    "targets": self.targets,
                    "ports": self.ports,
                    "tcp_probes": 0,
                    "dns_lookups": 0,
                }
            ctx.console.print(
                f"Host: {ctx.host}; "
                f"namespace: {vantage['identity'].get('network_namespace', 'unknown')}; "
                f"interfaces: {len(vantage['interfaces'])}; "
                f"tunnel devices: {len(vantage['tunnels'])}",
                markup=False,
            )
            for item in vantage["targets"]:
                devices = sorted(
                    {
                        r["device"]
                        for lookup in item["routes"]
                        for r in lookup["records"]
                        if r.get("device")
                    }
                )
                outcomes = sorted({check["outcome"] for check in item["tcp"]})
                ctx.console.print(
                    f"{item['target']}: DNS {item['dns'].get('outcome', 'unknown')}; "
                    f"route via {', '.join(devices) or 'unavailable'}; "
                    f"TCP {', '.join(outcomes) or 'not probed'}",
                    markup=False,
                )

    def diagnose(self, ctx, vantage):
        owners = vantage["tun_owners"]
        for interface in vantage["interfaces"]:
            tunnel = interface.get("tun") or interface.get("tunnel_kind")
            if not tunnel:
                continue
            attached = [
                owner
                for owner in owners
                if owner["interface"] == interface["name"]
                and owner.get("namespace_matches") is True
            ]
            item = {
                "interface": interface["name"],
                "exists": True,
                "admin_up": interface.get("admin_up", False),
                "operstate": interface.get("operstate", "unknown"),
                "attachment_observed": bool(attached),
                "owners": attached,
                "established_owner_transport_observed": any(
                    p.get("established_tcp_sockets")
                    for p in vantage["processes"]
                    if any(p["pid"] == o["pid"] for o in attached)
                ),
                "state": "attached" if attached else "unverified",
                "active_tunnel_verified": False,
                "provenance": "locally_measured",
            }
            vantage["tunnels"].append(item)
            if ctx.settings["DEVICE"] and interface["name"] != ctx.settings["DEVICE"]:
                continue
            ctx.report["diagnostics"].append(
                {
                    "kind": "existing_tunnel_device",
                    "device": interface["name"],
                    "attachment_observed": bool(attached),
                    "detail": (
                        "The interface name exists. Review its session and descriptor owners "
                        "before allocating it. Exclusive/single-queue TUN allocation can "
                        "return device busy; UP and attachment do not prove forwarding."
                    ),
                }
            )
        if ctx.settings["DEVICE"] and not any(
            i["name"] == ctx.settings["DEVICE"] for i in vantage["interfaces"]
        ):
            ctx.report["diagnostics"].append(
                {
                    "kind": "device_not_observed",
                    "device": ctx.settings["DEVICE"],
                    "detail": (
                        "Device not observed in this namespace. Collection limits or a "
                        "different host/namespace may explain it."
                    ),
                }
            )
        interfaces = {i["name"]: i for i in vantage["interfaces"]}
        for target in vantage["targets"]:
            for lookup in target["routes"]:
                for route in lookup["records"]:
                    dev = interfaces.get(route.get("device"), {})
                    if dev.get("admin_up") is False:
                        ctx.report["diagnostics"].append(
                            {
                                "kind": "route_device_down",
                                "target": target["target"],
                                "device": route["device"],
                                "detail": (
                                    "Selected route uses an administratively down interface. "
                                    "Review the interface and route with its network owner."
                                ),
                            }
                        )
            reachable = any(check["outcome"] == "reachable" for check in target["tcp"])
            reported = [
                item["host"]
                for item in self.imports
                for t in item["targets"]
                if t["target"] == target["target"]
                and any(c["outcome"] == "reachable" for c in t["tcp"])
            ]
            if reported and not reachable:
                ctx.report["diagnostics"].append(
                    {
                        "kind": "different_reported_vantage",
                        "target": target["target"],
                        "reported_hosts": list(dict.fromkeys(reported)),
                        "detail": (
                            "Imported observations report TCP success from these hosts. "
                            "Test there if authorized; Fieldkit has not accessed or verified them."
                        ),
                    }
                )
            local_addresses = set(target["dns"].get("addresses", []))
            for imported in self.imports:
                for remote in imported["targets"]:
                    remote_addresses = set(remote["dns"].get("addresses", []))
                    if (
                        remote["target"] == target["target"]
                        and remote_addresses
                        and local_addresses
                        and remote_addresses != local_addresses
                    ):
                        ctx.report["diagnostics"].append(
                            {
                                "kind": "different_reported_dns",
                                "target": target["target"],
                                "reported_host": imported["host"],
                                "detail": (
                                    "Imported host reports a different address set. Compare "
                                    "split DNS, resolver configuration and observation time."
                                ),
                            }
                        )
            for check in target["tcp"]:
                if check["outcome"] in {"timeout", "no_route", "permission_denied", "refused"}:
                    detail = {
                        "timeout": (
                            "Timeout is inconclusive. Check the route, tunnel/session, "
                            "filtering and service availability from this host."
                        ),
                        "no_route": (
                            "Connect reported no usable path. Compare the route lookup, "
                            "interface state and this host's namespace."
                        ),
                        "permission_denied": (
                            "Local connect was denied. Review the user's network policy "
                            "and namespace restrictions."
                        ),
                        "refused": (
                            "TCP endpoint refused the handshake. The path may work while "
                            "the service is closed or rejects connections."
                        ),
                    }[check["outcome"]]
                    ctx.report["diagnostics"].append(
                        {
                            "kind": "tcp_" + check["outcome"],
                            "target": target["target"],
                            "address": check["address"],
                            "port": check["port"],
                            "detail": detail,
                            "evidence": check.get("evidence", []),
                        }
                    )
