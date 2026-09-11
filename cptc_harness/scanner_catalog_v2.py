"""Immutable catalog for the single live-admitted SMB signing profile."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .contracts import PolicyError, canonical_json
from .scanner_contracts import SourcePin, TrafficBudget


PROFILE_ID_V2 = "network.nse_smb2_security_mode"
EXPECTED_CATALOG_SHA256_V2 = "83be9c7e1b3ff2bdd2c164b555f2ccb7614566489ee2cba77dcc574fef7a1fca"
_CATALOG_PATH = Path(__file__).parent / "resources" / "scanner-profiles-v2.json"
_BUDGET_FIELDS = (
    "tcp_connects", "udp_datagrams", "protocol_requests", "tx_bytes", "rx_bytes",
    "timeout_s", "cpu_s", "output_bytes", "process_limit", "auth_attempts",
)
_EXPECTED_BUDGET = (2, 1, 2, 4096, 16384, 15.0, 10.0, 16384, 1, 0)
_EXPECTED_RUNTIME_PINS = (
    ("command_template_sha256", "cca77e21e818b4ca1b57f9dfa69a7bfa9de2cd8ee0d0e962311376e0093791a1"),
    ("dependency_closure_sha256", "461563b2f17d501c1bbf0f05b86ff7494d0a2e177d43d92523d0d1b5410191fe"),
    ("nbstat_request_sha256", "ceea3d122f7ab944367b4a65f6c6699471a3aee6163c145e0e804a1b10b80a64"),
    ("nmap_package_revision", "package:nmap-7.991-1.1"),
    ("nmap_path", "/usr/bin/nmap"),
    ("nmap_sha256", "ee8f517262c083b934de98844064c01d5b0cf6bdf9ffac39032187bf303303cc"),
    ("nmap_version", "7.991"),
    ("parser_path", "cptc_harness/scanner_results.py"),
    ("parser_sha256", "fe12bc1e0fdfbfff8414312855f8b2b9b70c70a0cd371cbdbfe8605c3371fda3"),
    ("script_path", "/usr/share/nmap/scripts/smb2-security-mode.nse"),
    ("script_sha256", "184a49f77869088d10309ae5b4c37ffa7065b984436aae2aba77ba86d4d801ae"),
    ("smb2_request_sha256", "df36284962f3ca182e53bbbc6328f247e86de0e42eee51db97d553242ae9f78d"),
)
_EXPECTED_COMMAND_TEMPLATE = (
    "/usr/bin/nmap", "-n", "-Pn", "-sT", "-p", "445", "--script",
    "/usr/share/nmap/scripts/smb2-security-mode.nse", "-oX", "-", "--",
    "{target_ipv4}",
)
_REQUIRED_DEPENDENCY_PATHS = frozenset({
    "/usr/share/nmap/nselib/smb.lua",
    "/usr/share/nmap/nselib/smb2.lua",
    "/usr/share/nmap/nselib/stdnse.lua",
    "/usr/lib/libc.so.6",
    "/usr/lib/libpcap.so.1",
    "/usr/lib/liblua5.4.so.5.4",
    "/usr/lib64/ld-linux-x86-64.so.2",
})
_EXPECTED_DEPENDENCY_CLOSURE_SHA256 = "461563b2f17d501c1bbf0f05b86ff7494d0a2e177d43d92523d0d1b5410191fe"
_PROFILE_FIELDS = {
    "profile_id", "family", "upstream_id", "runner_id", "tier", "mode",
    "protocol", "port", "budget", "source", "runtime_pins", "parser_id",
    "command_template", "dependency_manifest", "dependency_closure_sha256",
    "dependency_closure_complete", "allowed_options", "effects",
}
_SOURCE_FIELDS = {"repository", "path", "revision", "sha256", "license", "redistributable"}


@dataclass(frozen=True, slots=True)
class DependencyPin:
    """One immutable path and content hash in the observed runtime closure."""

    path: str
    sha256: str


@dataclass(frozen=True, slots=True)
class LiveScannerProfile:
    """Exact immutable description of the admitted SMB observation."""

    profile_id: str
    family: str
    upstream_id: str
    runner_id: str
    tier: str
    mode: str
    protocol: str
    port: int
    budget: TrafficBudget
    source: SourcePin
    runtime_pins: tuple[tuple[str, str], ...]
    command_template: tuple[str, ...]
    dependency_manifest: tuple[DependencyPin, ...]
    dependency_closure_sha256: str
    dependency_closure_complete: bool
    parser_id: str
    allowed_options: tuple[str, ...]
    effects: tuple[str, ...]

    @property
    def tcp_connects(self) -> int:
        return self.budget.tcp_connects

    @property
    def udp_datagrams(self) -> int:
        return self.budget.udp_datagrams

    @property
    def protocol_requests(self) -> int:
        return self.budget.protocol_requests

    @property
    def tx_bytes(self) -> int:
        return self.budget.tx_bytes

    @property
    def rx_bytes(self) -> int:
        return self.budget.rx_bytes

    @property
    def output_bytes(self) -> int:
        return self.budget.output_bytes


@dataclass(frozen=True, slots=True)
class LiveScannerCatalog:
    """Hash-anchored v2 catalog envelope."""

    version: int
    catalog_sha256: str
    profiles: tuple[LiveScannerProfile, ...]
    path: Path


def _profile_from_dict(value: Any) -> LiveScannerProfile:
    if not isinstance(value, dict) or set(value) != _PROFILE_FIELDS:
        raise PolicyError("unknown or missing live scanner profile field")
    budget = value["budget"]
    source = value["source"]
    pins = value["runtime_pins"]
    if not isinstance(budget, dict) or tuple(budget) != _BUDGET_FIELDS:
        raise PolicyError("live scanner profile budget shape differs")
    budget_values = tuple(budget[name] for name in _BUDGET_FIELDS)
    if budget_values != _EXPECTED_BUDGET:
        raise PolicyError("live scanner profile budget differs")
    if not isinstance(source, dict) or set(source) != _SOURCE_FIELDS:
        raise PolicyError("live scanner profile source pin differs")
    if not isinstance(pins, dict) or tuple(sorted(pins.items())) != _EXPECTED_RUNTIME_PINS:
        raise PolicyError("live scanner profile runtime pin differs")
    command = value["command_template"]
    if not isinstance(command, list) or tuple(command) != _EXPECTED_COMMAND_TEMPLATE:
        raise PolicyError("live scanner command template differs")
    dependencies = value["dependency_manifest"]
    if (not isinstance(dependencies, list)
            or any(not isinstance(item, dict) or set(item) != {"path", "sha256"} for item in dependencies)):
        raise PolicyError("live scanner dependency manifest is invalid")
    dependency_pairs = tuple((item["path"], item["sha256"]) for item in dependencies)
    dependency_paths = tuple(item[0] for item in dependency_pairs)
    if (len(dependency_pairs) != 23 or dependency_paths != tuple(sorted(dependency_paths))
            or len(set(dependency_paths)) != len(dependency_paths)
            or not _REQUIRED_DEPENDENCY_PATHS <= set(dependency_paths)
            or any(type(path) is not str or not path.startswith("/")
                   or type(sha256) is not str or len(sha256) != 64
                   or any(character not in "0123456789abcdef" for character in sha256)
                   for path, sha256 in dependency_pairs)):
        raise PolicyError("live scanner dependency manifest differs")
    closure_hash = hashlib.sha256(canonical_json(dependencies)).hexdigest()
    if (value["dependency_closure_sha256"] != closure_hash
            or closure_hash != _EXPECTED_DEPENDENCY_CLOSURE_SHA256):
        raise PolicyError("live scanner dependency closure hash differs")
    if value["dependency_closure_complete"] is not False:
        raise PolicyError("Arch lab candidate must keep its dependency closure incomplete")
    options = value["allowed_options"]
    effects = value["effects"]
    if not isinstance(options, list) or options:
        raise PolicyError("live scanner profile does not accept runtime arguments")
    if not isinstance(effects, list) or tuple(effects) != (
        "network_observation", "no_authentication", "no_retry", "no_fallback",
    ):
        raise PolicyError("live scanner profile effects differ")
    exact = (
        value["profile_id"], value["family"], value["upstream_id"], value["runner_id"],
        value["tier"], value["mode"], value["protocol"], value["port"],
        source["repository"], source["path"], source["revision"], source["sha256"],
        source["license"], source["redistributable"], value["parser_id"],
    )
    expected = (
        PROFILE_ID_V2, "nse", "smb2-security-mode.nse",
        "live.nmap.nse-smb2-security-mode-v2", "observation", "lab_candidate",
        "smb", 445, "https://github.com/nmap/nmap", "scripts/smb2-security-mode.nse",
        "package:nmap-7.991-1.1",
        "184a49f77869088d10309ae5b4c37ffa7065b984436aae2aba77ba86d4d801ae",
        "LicenseRef-Nmap-Public-Source-License-Version-0.95", False,
        "nmap.xml.smb2-security-mode-v2",
    )
    if exact != expected:
        raise PolicyError("live scanner profile differs from the admitted profile")
    return LiveScannerProfile(
        value["profile_id"], value["family"], value["upstream_id"], value["runner_id"],
        value["tier"], value["mode"], value["protocol"], value["port"],
        TrafficBudget.from_dict(budget), SourcePin.from_dict(source), tuple(sorted(pins.items())),
        tuple(command), tuple(DependencyPin(*item) for item in dependency_pairs),
        closure_hash, False,
        value["parser_id"], (), tuple(effects),
    )


def load_catalog_v2(path: Path | None = None) -> LiveScannerCatalog:
    """Load and fully verify the checked-in one-profile v2 catalog."""

    resolved = _CATALOG_PATH if path is None else Path(path)
    try:
        value = json.loads(resolved.read_bytes())
    except (OSError, ValueError, TypeError):
        raise PolicyError("live scanner catalog is unavailable") from None
    if not isinstance(value, dict) or set(value) != {"version", "catalog_sha256", "profiles"}:
        raise PolicyError("unknown or missing live scanner catalog field")
    unsigned = {"version": value["version"], "profiles": value["profiles"]}
    actual_hash = hashlib.sha256(canonical_json(unsigned)).hexdigest()
    if value["catalog_sha256"] != actual_hash:
        raise PolicyError("live scanner catalog hash differs")
    if value["catalog_sha256"] != EXPECTED_CATALOG_SHA256_V2:
        raise PolicyError("live scanner catalog hash anchor differs")
    if value["version"] != 2 or not isinstance(value["profiles"], list) or len(value["profiles"]) != 1:
        raise PolicyError("live scanner catalog is not the reviewed finite set")
    profiles = tuple(_profile_from_dict(row) for row in value["profiles"])
    return LiveScannerCatalog(2, value["catalog_sha256"], profiles, resolved)


def get_profile_v2(profile_id: str, path: Path | None = None) -> LiveScannerProfile:
    """Return the exact admitted profile; wildcards and aliases are rejected."""

    if type(profile_id) is not str or profile_id != PROFILE_ID_V2:
        raise PolicyError("unknown live scanner profile")
    return load_catalog_v2(path).profiles[0]


def verify_profile_runtime(profile: LiveScannerProfile, pins: Mapping[str, str]) -> None:
    """Reject any profile mutation or runtime identity outside the exact pins."""

    if not isinstance(profile, LiveScannerProfile) or profile != get_profile_v2(PROFILE_ID_V2):
        raise PolicyError("live scanner profile does not match the admitted profile")
    if not isinstance(pins, Mapping):
        raise PolicyError("live scanner runtime pin mapping is invalid")
    try:
        supplied = tuple(sorted(pins.items()))
    except (AttributeError, TypeError, ValueError):
        raise PolicyError("live scanner runtime pin mapping is invalid") from None
    if supplied != profile.runtime_pins:
        raise PolicyError("live scanner runtime pin differs")
    if not profile.dependency_closure_complete:
        raise PolicyError("live scanner dependency closure is incomplete")


__all__ = [
    "EXPECTED_CATALOG_SHA256_V2",
    "DependencyPin",
    "LiveScannerCatalog",
    "LiveScannerProfile",
    "PROFILE_ID_V2",
    "get_profile_v2",
    "load_catalog_v2",
    "verify_profile_runtime",
]
