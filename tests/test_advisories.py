"""Synthetic tests for offline advisory loading and exact matching."""
import hashlib
import json

import pytest

from cptc_harness.advisories import AdvisoryCatalog, load_catalog, match_components
from cptc_harness.advisories import _compare, _parse_version, _debian_segment_compare, _rpm_segment_compare
from cptc_harness.assessment_contracts import ComponentIdentity


RELEASE = "b" * 64
SOURCE_A = "a" * 64
SOURCE_B = "c" * 64
WHEN = "2026-09-08T05:02:09Z"


def advisory(*, advisory_id="CVE-2021-41773", product="Apache HTTP Server",
             ecosystem="debian", distribution="", comparator="debian",
             introduced="2.4.49-1", fixed="2.4.50-1", last_affected="",
             state="active", source_sha256=SOURCE_A, cve_ids=None,
             required_patch_ids=(), superseding_patch_ids=()):
    return {"advisory_id": advisory_id, "cve_ids": cve_ids or [advisory_id],
            "state": state, "publisher": "Microsoft" if ecosystem == "windows" else "synthetic-publisher",
            "source_url": ("https://msrc.microsoft.com/update-guide/vulnerability/" if ecosystem == "windows" else "https://public.example.test/advisories/") + advisory_id,
            "source_sha256": source_sha256, "acquired_at": WHEN,
            "ecosystem": ecosystem, "product": product, "distribution": distribution,
            "comparator": comparator, "introduced": introduced, "fixed": fixed,
            "last_affected": last_affected,
            "required_patch_ids": list(required_patch_ids),
            "superseding_patch_ids": list(superseding_patch_ids)}


def catalog_payload(records):
    return {"schema": "cptc.advisories.v1", "release_sha256": RELEASE,
            "records": records}


def load(records):
    payload = catalog_payload(records)
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return load_catalog(raw, expected_sha256=hashlib.sha256(raw).hexdigest(),
                        release_sha256=RELEASE)


def component(*, component_id="pkg-1", product="Apache HTTP Server", ecosystem="debian",
              distribution="ubuntu", version="2.4.49", release="1",
              provenance="package_database", os_build="", patch_ids=()):
    return ComponentIdentity(component_id, "fixture-target", ecosystem, product, version,
                             release, "", distribution, os_build, tuple(patch_ids),
                             ("operator-import",), provenance)


def test_load_catalog_validates_source_release_and_is_immutable():
    catalog = load([advisory()])
    assert isinstance(catalog, AdvisoryCatalog)
    assert catalog.records[0].source_sha256 == SOURCE_A
    assert catalog.publisher_authenticated is False
    with pytest.raises(Exception):
        catalog.records = ()
    with pytest.raises(ValueError):
        load_catalog(catalog_payload([advisory()]), expected_sha256="d" * 64,
                     release_sha256=RELEASE)
    with pytest.raises(ValueError):
        load_catalog(catalog_payload([advisory()]), expected_sha256="a" * 64,
                     release_sha256="e" * 64)


def test_loader_rejects_duplicate_keys_unknown_fields_and_bad_identifiers():
    duplicate = ('{"schema":"cptc.advisories.v1","schema":"cptc.advisories.v1",'
                 '"release_sha256":"' + RELEASE + '","records":[]}').encode()
    with pytest.raises(ValueError):
        load_catalog(duplicate, expected_sha256=hashlib.sha256(duplicate).hexdigest(),
                     release_sha256=RELEASE)
    for change in (
        {"extra": True},
        {"source_url": "http://public.example.test/advisory"},
        {"cve_ids": ["CVE-guess"]},
        {"required_patch_ids": ["KB-nope"]},
        {"introduced": "", "fixed": "", "last_affected": ""},
    ):
        value = advisory()
        value.update(change)
        with pytest.raises(ValueError):
            load([value])


def test_debian_rpm_semver_and_windows_comparators_use_documented_boundaries():
    deb = load([advisory(comparator="debian", introduced="1:1.0~rc1-1",
                         fixed="1:1.0-2")])
    assert match_components([component(version="1:1.0~rc1-1", release="1")], deb)[0].state == "affected_candidate"
    assert match_components([component(version="1.0", release="2")], deb)[0].state == "fixed"

    rpm = load([advisory(advisory_id="CVE-2017-7494", cve_ids=["CVE-2017-7494"],
                         product="Samba", ecosystem="rpm", comparator="rpm",
                         introduced="4.0~rc1-1", fixed="4.0-2")])
    assert match_components([component(product="Samba", ecosystem="rpm", distribution="fedora",
                                       version="4.0~rc1", release="1")], rpm)[0].state == "affected_candidate"
    assert match_components([component(product="Samba", ecosystem="rpm", distribution="fedora",
                                       version="4.0", release="2")], rpm)[0].state == "fixed"

    semver = load([advisory(advisory_id="CVE-2024-0001", cve_ids=["CVE-2024-0001"],
                            ecosystem="semver", comparator="semver", product="Samba",
                            introduced="1.2.3-rc.1", fixed="1.2.3")])
    assert match_components([component(product="Samba", ecosystem="semver", distribution="",
                                       version="1.2.3-rc.1", release="")], semver)[0].state == "affected_candidate"
    assert match_components([component(product="Samba", ecosystem="semver", distribution="",
                                       version="1.2.3+build.7", release="")], semver)[0].state == "fixed"

    win = load([advisory(advisory_id="CVE-2024-0002", cve_ids=["CVE-2024-0002"],
                         ecosystem="windows", comparator="windows_build", product="Windows 10",
                         introduced="10.0.19045.1", fixed="10.0.19045.5000")])
    assert match_components([component(product="Windows 10", ecosystem="windows", distribution="windows",
                                       version="", release="", os_build="10.0.19045.1000")], win)[0].state == "affected_candidate"
    assert match_components([component(product="Windows 10", ecosystem="windows", distribution="windows",
                                       version="", release="", os_build="10.0.19045.5000")], win)[0].state == "fixed"


def test_banner_patch_provenance_withdrawn_and_missing_release_stay_safe():
    catalog = load([advisory(product="Samba", advisory_id="CVE-2017-7494",
                             cve_ids=["CVE-2017-7494"], ecosystem="rpm", comparator="rpm",
                             introduced="4.0-1", fixed="4.1-1")])
    banner = match_components([component(product="Samba", ecosystem="rpm", distribution="fedora",
                                         version="4.0", release="1", provenance="banner")], catalog)[0]
    assert banner.state == "affected_candidate"
    assert {"version_only", "backport_unverified", "configuration_unverified"} <= set(banner.limitations)
    missing = match_components([component(product="Samba", ecosystem="rpm", distribution="fedora",
                                          version="4.0", release="", provenance="package_database")], catalog)[0]
    assert missing.state == "unknown"
    withdrawn = load([advisory(state="withdrawn")])
    assert match_components([component()], withdrawn)[0].state == "withdrawn"


def test_wrong_identity_conflict_and_patch_supersedence_are_visible():
    wrong_product = load([advisory(product="Samba")])
    assert match_components([component()], wrong_product)[0].state == "unsupported"
    wrong_distribution = load([advisory(distribution="debian")])
    assert match_components([component(distribution="fedora")], wrong_distribution)[0].state == "unsupported"

    conflict = load([advisory(source_sha256=SOURCE_A),
                     advisory(advisory_id="CVE-2021-41773", source_sha256=SOURCE_B,
                              introduced="2.4.49-1", fixed="2.4.49-1")])
    result = match_components([component(version="2.4.49", release="1")], conflict)
    assert result[0].state == "conflict"
    assert "conflicting_applicability" in result[0].limitations

    patched = load([advisory(product="Windows Server 2019", ecosystem="windows", comparator="windows_build",
                             introduced="10.0.17763.0", required_patch_ids=["KB123456"], superseding_patch_ids=["KB123457"], fixed="")])
    match = match_components([component(product="Windows Server 2019", ecosystem="windows", distribution="windows",
                                        os_build="10.0.17763.100", provenance="os_inventory", patch_ids=("KB123457",))], patched)[0]
    assert match.state == "fixed"


def test_reordered_components_are_deterministic_and_unknown_is_not_clean():
    catalog = load([advisory(), advisory(advisory_id="CVE-2017-7494", product="Samba",
                                          cve_ids=["CVE-2017-7494"], source_sha256=SOURCE_B)])
    components = [component(component_id="b"), component(component_id="a", product="Samba")]
    assert match_components(components, catalog) == match_components(reversed(components), catalog)
    unknown = match_components([component(provenance="unknown")], catalog)
    apache_unknown = next(item for item in unknown if item.advisory_id == "CVE-2021-41773")
    assert apache_unknown.state == "unknown"


@pytest.mark.parametrize("left,right,expected", [
    ("1", "a", -1), ("1.0~rc1", "1.0", -1), ("1.0+git", "1.0a", 1),
    ("1.00", "1.0", 0), ("1.0a1", "1.0a2", -1), ("1.0a", "1.0+", -1),
    ("", "0", 0), ("~", "", -1), ("1.0", "1.0.0", -1),
])
def test_debian_authoritative_ordering_vectors(left, right, expected):
    assert _debian_segment_compare(left, right) == expected
    assert _debian_segment_compare(right, left) == -expected


@pytest.mark.parametrize("left,right,expected", [
    ("1.0", "1_0", 0), ("1.0", "1+0", 0), ("1.0a", "1.0.a", 0),
    ("1.0~rc1", "1.0", -1), ("1.0", "1.0^git", -1), ("1.0^git", "1.0.1", -1),
    ("1.0+", "1.0", 0), ("1.01", "1.1", 0), ("1.a", "1.1", -1),
])
def test_rpm_authoritative_ordering_vectors(left, right, expected):
    assert _rpm_segment_compare(left, right) == expected
    assert _rpm_segment_compare(right, left) == -expected


@pytest.mark.parametrize("comparator", ["debian", "rpm"])
@pytest.mark.parametrize("value", ["bad:1.0", "-1:1.0", "1:", "١:1.0", "1.é"])
def test_malformed_epoch_and_non_ascii_are_unknown(comparator, value):
    assert _parse_version(value, comparator) is None


@pytest.mark.parametrize("value", ["1.2.3-01", "1.2.3-rc.00", "01.2.3", "1.2.3-", "1.2"])
def test_strict_semver_rejects_invalid_versions(value):
    assert _parse_version(value, "semver") is None


def test_same_cve_for_other_product_or_distribution_cannot_contaminate_match():
    cache = load([advisory(distribution="ubuntu"), advisory(product="Samba", fixed="1.0-1", introduced="0.1-1"),
                  advisory(distribution="debian", fixed="1.0-1", introduced="0.1-1")])
    match = match_components([component(distribution="ubuntu")], cache)[0]
    assert match.state == "affected_candidate"
    assert "conflicting_applicability" not in match.limitations


def test_windows_product_and_build_family_bind_patch_supersedence():
    record = advisory(product="Windows Server 2019", ecosystem="windows", comparator="windows_build",
                      introduced="10.0.17763.0", fixed="10.0.17763.200", superseding_patch_ids=["KB1234567"])
    cache = load([record])
    server = component(product="Windows Server 2019", ecosystem="windows", distribution="windows",
                       version="", release="", os_build="10.0.17763.100", provenance="os_inventory")
    from dataclasses import replace
    assert match_components([server], cache)[0].state == "affected_candidate"
    assert match_components([replace(server, patch_ids=("KB1234567",))], cache)[0].state == "fixed"
    assert match_components([replace(server, product="Windows 10")], cache)[0].state == "unsupported"
    assert match_components([replace(server, os_build="10.0.20348.100", patch_ids=("KB1234567",))], cache)[0].state == "unknown"
    for changes in ({"product": "Samba"}, {"publisher": "unknown"}, {"source_url": "https://example.test/"},
                    {"fixed": "10.0.20348.200"}, {"comparator": "semver"}):
        with pytest.raises(ValueError): load([{**record, **changes}])
