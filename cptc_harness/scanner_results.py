"""Strict typed parsing for the admitted Nmap SMB signing observation."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Any, Literal, Mapping
import xml.etree.ElementTree as ET

from .contracts import PolicyError
from .scanner_catalog_v2 import LiveScannerProfile, PROFILE_ID_V2, get_profile_v2


_MAX_XML_BYTES = 16 * 1024
_RECEIPT_FIELDS = {
    "status", "reason", "tcp_connects", "udp_datagrams", "protocol_requests",
    "tx_bytes", "rx_bytes",
}
_ALLOWED_TAGS = {
    "nmaprun", "scaninfo", "verbose", "debugging", "host", "status", "address",
    "hostnames", "hostname", "ports", "port", "state", "service", "hostscript", "script",
    "table", "elem", "times", "runstats", "finished", "hosts",
}
_DIALECTS = frozenset({"2.0.2", "2.1", "3.0", "3.0.2", "3.1.1"})
_SIGNING_MESSAGES = {
    "Message signing enabled and required": (True, True),
    "Message signing enabled but not required": (True, False),
    "Message signing is disabled and not required!": (False, False),
}


@dataclass(frozen=True, slots=True)
class Smb2SecurityModeResult:
    """One immutable SMB dialect and signing-mode observation."""

    profile_id: str
    target_ipv4: str
    dialect: str
    signing_enabled: bool
    signing_required: bool
    disposition: Literal["observed_candidate", "not_observed"]
    confirmed_vulnerability: bool = False


@dataclass(frozen=True, slots=True)
class Smb2XmlFacts:
    """Protocol facts only; this type makes no collection or vulnerability claim."""

    target_ipv4: str
    dialect: str
    signing_enabled: bool
    signing_required: bool


_XML_DECLARATION = b'<?xml version="1.0" encoding="UTF-8"?>\n'
_NMAP_STYLESHEET = (
    b'<?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>\n'
)
_NMAP_DOCTYPE = b"<!DOCTYPE nmaprun>\n"


def _strip_exact_nmap_preamble(raw: bytes) -> bytes:
    """Remove inert Nmap boilerplate while rejecting all other declarations."""

    body = raw
    if body.startswith(_XML_DECLARATION):
        body = body[len(_XML_DECLARATION):]
    if body.startswith(_NMAP_DOCTYPE):
        body = body[len(_NMAP_DOCTYPE):]
    if body.startswith(_NMAP_STYLESHEET):
        body = body[len(_NMAP_STYLESHEET):]
    comments = tuple(re.finditer(br"<!--.*?-->", body, flags=re.DOTALL))
    if comments:
        if len(comments) != 1 or re.fullmatch(
            br"<!-- Nmap [\x20-\x7e]{1,480} -->", comments[0].group(0)
        ) is None:
            raise PolicyError("SMB result XML contains a forbidden comment")
        start, end = comments[0].span()
        body = body[:start] + body[end:]
    lowered = body.lower()
    if any(marker in lowered for marker in (b"<!doctype", b"<!entity", b"<!--", b"<?")):
        raise PolicyError("SMB result XML contains a forbidden declaration")
    return body


def _canonical_ipv4(value: str) -> str:
    if type(value) is not str:
        raise PolicyError("SMB result target must be canonical IPv4")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise PolicyError("SMB result target must be canonical IPv4") from None
    if address.version != 4 or str(address) != value:
        raise PolicyError("SMB result target must be canonical IPv4")
    return value


def _verify_receipt(profile: LiveScannerProfile, receipt: Mapping[str, Any]) -> None:
    if not isinstance(receipt, Mapping) or set(receipt) != _RECEIPT_FIELDS:
        raise PolicyError("SMB relay receipt shape is invalid")
    if receipt["status"] != "complete" or receipt["reason"] != "complete":
        raise PolicyError("SMB relay receipt is not complete")
    numeric = tuple(receipt[name] for name in (
        "tcp_connects", "udp_datagrams", "protocol_requests", "tx_bytes", "rx_bytes",
    ))
    if any(type(value) is not int or value < 0 for value in numeric):
        raise PolicyError("SMB relay receipt counters are invalid")
    connects, datagrams, requests, sent, received = numeric
    if (connects, datagrams, requests) != (
        profile.tcp_connects, profile.udp_datagrams, profile.protocol_requests,
    ):
        raise PolicyError("SMB relay receipt request accounting differs")
    if not 0 < sent <= profile.tx_bytes or not 0 < received <= profile.rx_bytes:
        raise PolicyError("SMB relay receipt byte accounting exceeds the profile")


def _parse_xml(raw: bytes, target_ipv4: str) -> tuple[str, str]:
    raw = _strip_exact_nmap_preamble(raw)
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, ValueError):
        raise PolicyError("SMB result XML is malformed") from None
    if root.tag != "nmaprun":
        raise PolicyError("SMB result XML root is invalid")
    elements = tuple(root.iter())
    if any(not isinstance(item.tag, str) or item.tag not in _ALLOWED_TAGS for item in elements):
        raise PolicyError("SMB result XML contains an unsupported element")
    hosts = tuple(root.iter("host"))
    addresses = tuple(root.iter("address"))
    ports = tuple(root.iter("port"))
    scripts = tuple(root.iter("script"))
    if len(hosts) != 1 or len(addresses) != 1:
        raise PolicyError("SMB result XML must contain one target host")
    if len(ports) != 1:
        raise PolicyError("SMB result XML must contain one target port")
    if len(scripts) != 1:
        raise PolicyError("SMB result XML must contain one admitted script")
    host, address, port, script = hosts[0], addresses[0], ports[0], scripts[0]
    if address.attrib != {"addr": target_ipv4, "addrtype": "ipv4"}:
        raise PolicyError("SMB result XML target differs from the requested IPv4")
    statuses = tuple(child for child in host if child.tag == "status")
    if len(statuses) != 1 or statuses[0].attrib.get("state") != "up":
        raise PolicyError("SMB result XML host state is incomplete")
    if port.attrib != {"protocol": "tcp", "portid": "445"}:
        raise PolicyError("SMB result XML port differs from the admitted port")
    states = tuple(child for child in port if child.tag == "state")
    services = tuple(child for child in port if child.tag == "service")
    if len(states) != 1 or states[0].attrib.get("state") != "open":
        raise PolicyError("SMB result XML port state is incomplete")
    if len(services) != 1 or services[0].attrib.get("name") not in {"microsoft-ds", "smb"}:
        raise PolicyError("SMB result XML service differs from SMB")
    host_scripts = tuple(child for child in host if child.tag == "hostscript")
    if (len(host_scripts) != 1 or tuple(host_scripts[0]) != (script,)
            or any(child.tag == "script" for child in port)):
        raise PolicyError("SMB result XML script is outside the admitted host-script location")
    if set(script.attrib) != {"id", "output"} or script.attrib["id"] != "smb2-security-mode":
        raise PolicyError("SMB result XML script differs from the admitted script")
    tables = tuple(child for child in script if child.tag == "table")
    if len(tables) != 1 or set(tables[0].attrib) != {"key"}:
        raise PolicyError("SMB result XML must contain one structured dialect")
    dialect = tables[0].attrib["key"]
    if dialect not in _DIALECTS:
        raise PolicyError("SMB result XML dialect is unsupported")
    values = tuple(child for child in tables[0] if child.tag == "elem")
    if len(values) != 1 or values[0].attrib or values[0].text not in _SIGNING_MESSAGES:
        raise PolicyError("SMB result XML signing mode is unsupported")
    message = values[0].text
    for element in elements:
        if element is not values[0] and element.text and element.text.strip():
            raise PolicyError("SMB result XML contains unstructured free text")
        if element.tail and element.tail.strip():
            raise PolicyError("SMB result XML contains unstructured free text")
    output_lines = tuple(line.strip() for line in script.attrib["output"].splitlines() if line.strip())
    if output_lines != (f"{dialect}:", message):
        raise PolicyError("SMB result XML structured and rendered output contradict")
    return dialect, message


def parse_smb2_xml_facts(xml: bytes, *, target_ipv4: str) -> Smb2XmlFacts:
    """Validate one bounded Nmap XML document and return protocol facts only."""

    target = _canonical_ipv4(target_ipv4)
    if type(xml) is not bytes or not 0 < len(xml) <= _MAX_XML_BYTES:
        raise PolicyError("SMB result output exceeds the admitted limit")
    dialect, message = _parse_xml(xml, target)
    signing_enabled, signing_required = _SIGNING_MESSAGES[message]
    if signing_required and not signing_enabled:
        raise PolicyError("SMB signing flags contradict")
    return Smb2XmlFacts(target, dialect, signing_enabled, signing_required)


def parse_smb2_security_mode_result(
    xml: bytes,
    *,
    profile: LiveScannerProfile,
    target_ipv4: str,
    exit_code: int,
    stderr: bytes,
    relay_receipt: Mapping[str, Any],
) -> Smb2SecurityModeResult:
    """Validate one complete bounded run and return only typed SMB signing facts."""

    admitted = get_profile_v2(PROFILE_ID_V2)
    if not isinstance(profile, LiveScannerProfile) or profile != admitted:
        raise PolicyError("SMB result profile does not match the live admission")
    target = _canonical_ipv4(target_ipv4)
    if type(xml) is not bytes or not 0 < len(xml) <= min(_MAX_XML_BYTES, profile.output_bytes):
        raise PolicyError("SMB result output exceeds the admitted limit")
    if type(exit_code) is not int or exit_code != 0:
        raise PolicyError("SMB scanner exit status is not successful")
    if type(stderr) is not bytes or stderr:
        raise PolicyError("SMB scanner stderr must be empty")
    _verify_receipt(profile, relay_receipt)
    facts = parse_smb2_xml_facts(xml, target_ipv4=target)
    disposition: Literal["observed_candidate", "not_observed"] = (
        "not_observed" if facts.signing_required else "observed_candidate"
    )
    return Smb2SecurityModeResult(
        profile.profile_id, target, facts.dialect, facts.signing_enabled,
        facts.signing_required, disposition,
    )


__all__ = [
    "Smb2SecurityModeResult",
    "Smb2XmlFacts",
    "parse_smb2_security_mode_result",
    "parse_smb2_xml_facts",
]
