"""Deterministic service-to-profile mapping with an explicit manual boundary."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .scanner_catalog import PROFILE_IDS, plan_for, profile_for
from .scanner_contracts import (
    ScanPlan,
    ScannerContractError,
    ScannerGrant,
    ScannerObservation,
)


MANUAL_MS17_010 = "manual.msf_smb_ms17_010"
MANUAL_UNMAPPED_CVE = "manual.unmapped_cve_review"
_MS17_CVES = frozenset(f"CVE-2017-01{value:02d}" for value in range(43, 49))
_ORDER = {profile_id: number for number, profile_id in enumerate((*PROFILE_IDS, MANUAL_MS17_010, MANUAL_UNMAPPED_CVE))}


@dataclass(frozen=True, slots=True)
class ManualReviewCard:
    card_id: str
    title: str
    prerequisites: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    result_states: tuple[str, ...]
    retest_requirements: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProfileSelection:
    profile_id: str
    target_id: str

    @classmethod
    def from_dict(cls, value: object) -> "ProfileSelection":
        if not isinstance(value, dict) or set(value) != {"profile_id", "target_id"}:
            raise ScannerContractError("invalid scanner profile selection")
        profile_id = value["profile_id"]
        target_id = value["target_id"]
        if profile_id != "network.msf_http_version":
            raise ScannerContractError("only an exact design-only profile can be selected")
        try:
            checked_target = ScannerObservation.from_dict({
                "target_id": target_id,
                "address": "192.0.2.1",
                "port": 1,
                "service": "selection",
                "scheme": None,
                "cves": [],
            }).target_id
        except (AttributeError, TypeError):
            raise ScannerContractError("invalid scanner profile selection") from None
        return cls(profile_id, checked_target)


_MANUAL_CARDS = {
    MANUAL_MS17_010: ManualReviewCard(
        card_id=MANUAL_MS17_010,
        title="MS17-010 relationship review",
        prerequisites=(
            "Confirm the exact target and authentication realm are in scope.",
            "Record written authorization and an approved maintenance window.",
            "Name the recovery owner and record a current health baseline.",
            "Have a human select and review the exact test method.",
        ),
        evidence_requirements=(
            "Record the OS build, patch provenance, SMB service identity, and protocol posture.",
            "Record UTC timestamps, the approved target, the human-run outcome, and evidence references.",
            "Keep scanner candidates separate from a human-confirmed finding.",
        ),
        result_states=("attempted", "blocked", "observed", "confirmed", "incomplete"),
        retest_requirements=(
            "Repeat the reviewed evidence collection after remediation.",
            "Compare the same build, patch, service, protocol, and scope fields.",
        ),
    ),
    MANUAL_UNMAPPED_CVE: ManualReviewCard(
        card_id=MANUAL_UNMAPPED_CVE,
        title="Unmapped CVE relationship review",
        prerequisites=(
            "Confirm the exact target and service are in scope.",
            "Verify product identity, version provenance, and patch source.",
            "Have a human review applicability and possible test effects.",
        ),
        evidence_requirements=(
            "Record the advisory source, revision, applicability facts, and contradictory evidence.",
            "Record UTC timestamps, access limits, evidence references, and collection completeness.",
        ),
        result_states=("attempted", "blocked", "observed", "confirmed", "incomplete", "unsupported"),
        retest_requirements=(
            "Refresh the reviewed advisory record before the retest.",
            "Repeat only the admitted evidence collection and compare its provenance.",
        ),
    ),
}


@dataclass(frozen=True, slots=True)
class MappingDecision:
    profile_id: str
    target_id: str
    address: str
    port: int
    status: str
    reason: str
    plan: ScanPlan | None
    manual_card: ManualReviewCard | None = None


def _blocked(profile_id: str, observation: ScannerObservation, reason: str) -> MappingDecision:
    return MappingDecision(
        profile_id=profile_id,
        target_id=observation.target_id,
        address=observation.address,
        port=observation.port,
        status="blocked",
        reason=reason,
        plan=None,
    )


def _manual(profile_id: str, observation: ScannerObservation, reason: str) -> MappingDecision:
    return MappingDecision(
        profile_id=profile_id,
        target_id=observation.target_id,
        address=observation.address,
        port=observation.port,
        status="manual_only",
        reason=reason,
        plan=None,
        manual_card=_MANUAL_CARDS[profile_id],
    )


def _canonical_observation(item: ScannerObservation) -> ScannerObservation:
    try:
        checked = ScannerObservation.from_dict({
            "target_id": item.target_id,
            "address": item.address,
            "port": item.port,
            "service": item.service,
            "scheme": item.scheme,
            "cves": list(item.cves),
        })
    except (AttributeError, TypeError):
        raise ScannerContractError("scanner observation contains an invalid typed value") from None
    if checked != item:
        raise ScannerContractError("scanner observation is not canonical")
    return checked


def _canonical_grant(item: ScannerGrant) -> ScannerGrant:
    try:
        checked = ScannerGrant.from_dict({
            "profile_id": item.profile_id,
            "target_id": item.target_id,
            "endpoints": [
                {"protocol": endpoint.protocol, "address": endpoint.address, "port": endpoint.port}
                for endpoint in item.endpoints
            ],
        })
    except (AttributeError, TypeError):
        raise ScannerContractError("scanner grant contains an invalid typed value") from None
    if checked != item:
        raise ScannerContractError("scanner grant is not canonical")
    return checked


def _canonical_selection(item: ProfileSelection) -> ProfileSelection:
    try:
        checked = ProfileSelection.from_dict({
            "profile_id": item.profile_id,
            "target_id": item.target_id,
        })
    except (AttributeError, TypeError):
        raise ScannerContractError("invalid scanner profile selection") from None
    if checked != item:
        raise ScannerContractError("scanner profile selection is not canonical")
    return checked


def map_observations(observations: Iterable[ScannerObservation], grants: Iterable[ScannerGrant] = (), *,
                     selections: Iterable[ProfileSelection] = ()) -> tuple[MappingDecision, ...]:
    observations = tuple(observations)
    grants = tuple(grants)
    selections = tuple(selections)
    if not all(isinstance(item, ScannerObservation) for item in observations):
        raise ScannerContractError("mapping requires typed observations")
    if not all(isinstance(item, ScannerGrant) for item in grants):
        raise ScannerContractError("mapping requires typed grants")
    if not all(isinstance(item, ProfileSelection) for item in selections):
        raise ScannerContractError("mapping requires typed profile selections")
    observations = tuple(_canonical_observation(item) for item in observations)
    grants = tuple(_canonical_grant(item) for item in grants)
    selections = tuple(_canonical_selection(item) for item in selections)
    selection_set = {(item.profile_id, item.target_id) for item in selections}
    if len(selection_set) != len(selections):
        raise ScannerContractError("duplicate scanner profile selection")
    used_selections: set[tuple[str, str]] = set()
    addresses: dict[str, str] = {}
    identities = set()
    services: dict[tuple[str, str, int], tuple[str, str | None, tuple[str, ...]]] = {}
    for item in observations:
        old_address = addresses.setdefault(item.target_id, item.address)
        if old_address != item.address:
            raise ScannerContractError("conflicting target address")
        identity = (item.target_id, item.address, item.port, item.service, item.scheme, item.cves)
        if identity in identities:
            raise ScannerContractError("duplicate scanner observation")
        identities.add(identity)
        endpoint = (item.target_id, item.address, item.port)
        service = (item.service, item.scheme, item.cves)
        if endpoint in services and services[endpoint] != service:
            raise ScannerContractError("conflicting service observation")
        services[endpoint] = service
    grant_map: dict[tuple[str, str], ScannerGrant] = {}
    for grant in grants:
        if grant.profile_id not in PROFILE_IDS:
            raise ScannerContractError("unknown grant profile")
        key = (grant.profile_id, grant.target_id)
        if key in grant_map:
            raise ScannerContractError("duplicate compound grant")
        grant_map[key] = grant

    decisions: list[MappingDecision] = []
    for observation in observations:
        smb = observation.port == 445 and observation.service in {"microsoft-ds", "smb"}
        http = observation.port == 80 and observation.service in {"http", "www"} and observation.scheme == "http"
        if _MS17_CVES.intersection(observation.cves) and (
            observation.port in {139, 445} or observation.service in {"microsoft-ds", "smb", "netbios-ssn"}
        ):
            decisions.append(_manual(
                MANUAL_MS17_010, observation,
                "manual-only candidate for auxiliary/scanner/smb/smb_ms17_010; no execution plan",
            ))
        unknown_cves = sorted(set(observation.cves) - _MS17_CVES)
        if unknown_cves:
            decisions.append(_manual(
                MANUAL_UNMAPPED_CVE, observation,
                f"manual review required for {len(unknown_cves)} CVE relationship(s); no execution plan",
            ))
        selected_msf = (PROFILE_IDS[2], observation.target_id)
        if smb:
            candidates = PROFILE_IDS[:2]
        elif http and selected_msf in selection_set:
            candidates = (PROFILE_IDS[2],)
            used_selections.add(selected_msf)
        else:
            candidates = ()
        for profile_id in candidates:
            grant = grant_map.get((profile_id, observation.target_id))
            if grant is None:
                decisions.append(_blocked(profile_id, observation, "ROE grant is missing or incomplete"))
                continue
            try:
                plan = plan_for(profile_id, observation, grant=grant)
            except ScannerContractError as exc:
                decisions.append(_blocked(profile_id, observation, str(exc)))
            else:
                profile = profile_for(profile_id)
                decisions.append(MappingDecision(
                    profile_id=profile_id,
                    target_id=observation.target_id,
                    address=observation.address,
                    port=observation.port,
                    status=profile.mode,
                    reason=f"mapped from exact {profile.upstream_id}; no runtime dispatch",
                    plan=plan,
                ))
    if unused := selection_set - used_selections:
        raise ScannerContractError(f"scanner profile selection has no matching observation: {len(unused)}")
    decisions.sort(key=lambda item: (item.target_id, item.address, item.port,
                                     _ORDER.get(item.profile_id, len(_ORDER))))
    return tuple(decisions)
