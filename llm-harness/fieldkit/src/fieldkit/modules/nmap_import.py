"""Offline Nmap XML import; discovery is evidence, never scope authorization."""

import hashlib
import ipaddress
import json
from pathlib import Path

from fieldkit.core.local import LOCAL_OPTIONS, LocalModule
from fieldkit.core.local_worker import regular_read
from fieldkit.core.module import Option
from fieldkit.core.results import stable_id
from fieldkit.core.urls import normalize_url
from fieldkit.core.xml import parse_xml


def read_bounded(filename, limit):
    # Explicit import paths may be symlinks, but must resolve to regular files.
    # A FIFO or device must not block an otherwise offline import on open/read.
    data = regular_read(Path(filename).expanduser(), limit, follow=True)
    if len(data) > limit:
        raise ValueError("Input exceeds configured byte limit")
    return data


def script_record(node):
    def value(child):
        return {
            "tag": child.tag,
            "key": child.get("key"),
            "text": child.text or "",
            "children": [value(item) for item in child],
        }

    return {
        "id": node.get("id"),
        "output": node.get("output", ""),
        "data": [value(child) for child in node],
    }


class NmapImport(LocalModule):
    name = "network/nmap-import"
    description = "Import existing bounded Nmap XML and selected HTTP service inventory."
    options = LOCAL_OPTIONS + (
        Option("INPUT", str, "", "Existing Nmap XML file", "--input"),
        Option(
            "HTTP_PORTS",
            list,
            ["80", "443", "8080", "8443"],
            "HTTP candidate ports (repeat)",
            "--http-port",
        ),
        Option("VHOSTS_FILE", str, "", "JSON address -> virtual-host names", "--vhosts-file"),
        Option("MAX_NODES", int, 50000, "XML node ceiling", "--max-nodes"),
    )

    def validate(self, settings):
        if not settings["INPUT"] or settings["MAX_NODES"] <= 0:
            raise ValueError("Supply --input XML and positive --max-nodes")
        if any(not p.isdigit() or not 1 <= int(p) <= 65535 for p in settings["HTTP_PORTS"]):
            raise ValueError("HTTP_PORTS must contain valid port numbers")

    async def assess(self, ctx):
        data = read_bounded(ctx.settings["INPUT"], ctx.settings["MAX_BYTES"])
        root, _ = parse_xml(
            data, max_bytes=ctx.settings["MAX_BYTES"], max_nodes=ctx.settings["MAX_NODES"]
        )
        if root.tag != "nmaprun":
            raise ValueError("Not an Nmap XML document")
        vhosts = {}
        if ctx.settings["VHOSTS_FILE"]:
            try:
                vhosts = json.loads(read_bounded(ctx.settings["VHOSTS_FILE"], 1048576))
            except (ValueError, RecursionError) as exc:
                raise ValueError("Malformed virtual-host JSON") from exc
            if not isinstance(vhosts, dict) or any(
                not isinstance(k, str)
                or not isinstance(v, list)
                or not all(isinstance(h, str) for h in v)
                for k, v in vhosts.items()
            ):
                raise ValueError("Virtual hosts must map address strings to lists of hostnames")
            for hosts in vhosts.values():
                for host in hosts:
                    url = normalize_url(f"http://{host}/")
                    from urllib.parse import urlsplit

                    parsed = urlsplit(url)
                    if parsed.path != "/" or parsed.query or parsed.port:
                        raise ValueError("Virtual hosts must be bare names, without paths or ports")
        provenance = {
            "file": str(Path(ctx.settings["INPUT"]).expanduser().resolve()),
            "sha256": hashlib.sha256(data).hexdigest(),
            "scanner": root.attrib,
        }
        evidence = ctx.evidence(provenance, source=ctx.settings["INPUT"])
        finished = root.find("runstats/finished")
        complete = finished is not None and finished.get("exit") == "success"
        ctx.report["scan"] = {
            "provenance": provenance,
            "finished": finished.attrib if finished is not None else None,
            "complete": complete,
            "authorized_scope": False,
        }
        if not complete:
            ctx.error(
                "incomplete_scan", ctx.settings["INPUT"], "Missing successful runstats/finished"
            )
        for node in root.findall("host"):
            ctx.check_deadline()
            addresses = [dict(a.attrib) for a in node.findall("address")]
            names = [dict(n.attrib) for n in node.findall("hostnames/hostname")]
            address = "unknown"
            for entry in addresses:
                if entry.get("addrtype") not in {"ipv4", "ipv6"}:
                    continue
                try:
                    parsed_address = ipaddress.ip_address(entry.get("addr", ""))
                    if entry["addrtype"] != f"ipv{parsed_address.version}":
                        raise ValueError("Address family does not match addrtype")
                except ValueError:
                    ctx.error("invalid_nmap_address", entry.get("addr", "missing"))
                    continue
                if address == "unknown":
                    address = entry["addr"]
            host_record = {
                "kind": "nmap_host",
                "host": address,
                "addresses": addresses,
                "hostnames": names,
                "status": dict(node.find("status").attrib)
                if node.find("status") is not None
                else {},
                "scripts": [script_record(s) for s in node.findall("hostscript/script")],
                "extraports": [dict(p.attrib) for p in node.findall("ports/extraports")],
                "ports": [],
                "evidence": [evidence],
            }
            for port in node.findall("ports/port"):
                state = port.find("state")
                service = port.find("service")
                item = {
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "state": dict(state.attrib) if state is not None else {},
                    "service": dict(service.attrib) if service is not None else {},
                    "scripts": [script_record(s) for s in port.findall("script")],
                }
                host_record["ports"].append(item)
                if (
                    address == "unknown"
                    or item["protocol"] != "tcp"
                    or item["state"].get("state") != "open"
                    or item["port"] not in ctx.settings["HTTP_PORTS"]
                ):
                    continue
                service_name = item["service"].get("name", "")
                # An explicitly selected candidate port can be included when Nmap lacked -sV.
                if service_name and "http" not in service_name:
                    continue
                tls = item["service"].get("tunnel") == "ssl" or service_name == "https"
                scheme = "https" if tls or item["port"] in {"443", "8443"} else "http"
                note = (
                    "Nmap reported TLS/HTTPS"
                    if tls
                    else "Scheme inferred from selected port/service; verify before assessment"
                )
                host_values = [address, *vhosts.get(address, [])]
                for hostname in dict.fromkeys(host_values):
                    authority = f"[{hostname}]" if ":" in hostname else hostname
                    url = normalize_url(f"{scheme}://{authority}:{item['port']}/")
                    endpoint = {
                        "url": url,
                        "method": "GET",
                        "source": provenance["file"],
                        "source_address": address,
                        "service": item["service"],
                        "scheme_inference": note,
                        "authorized": False,
                        "virtual_host": hostname != address,
                        "evidence": [evidence],
                    }
                    endpoint["id"] = stable_id(endpoint, "endpoint")
                    if not any(e["id"] == endpoint["id"] for e in ctx.report["endpoints"]):
                        ctx.report["endpoints"].append(endpoint)
            host_evidence = ctx.evidence(host_record, source=address)
            host_record["evidence"].append(host_evidence)
            ctx.report["results"].append(host_record)
