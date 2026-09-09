#!/usr/bin/env python3
"""Prepare reviewed native Kali packages for private team applications.

Lock preparation performs one approved signed Kali APT metadata refresh. The
program does not contact an application source, start containers, or start a
scanner. A separate human review binds a lock hash before apply.
"""
from __future__ import annotations

import argparse
import datetime as dt
from email.utils import parsedate_to_datetime
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
DEFAULT_MANIFEST = ROOT / "manifest.json"
LOCK_SCHEMA = "cptc.team-env.lock.v1"
REVIEW_SCHEMA = "cptc.team-env.review.v1"
RECEIPT_SCHEMA = "cptc.team-env.receipt.v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+.-]+$")
KALI_KEYRING = "/usr/share/keyrings/kali-archive-keyring.gpg"
SUPPORTED_KALI_SUITES = frozenset({"kali-rolling", "kali-last-snapshot"})
SUPPORTED_KALI_COMPONENTS = frozenset({"main", "contrib", "non-free", "non-free-firmware"})
APPROVED_KALI_ORIGINS = frozenset({
    "http://http.kali.org/kali", "https://http.kali.org/kali",
    "http://kali.download/kali", "https://kali.download/kali",
    "http://mirrors.rit.edu/kali", "https://mirrors.rit.edu/kali",
})
MIRROR_POLICY_ORIGIN = "mirror+file:/etc/apt/mirrors/kali.list"
APPROVED_KALI_POLICY_ORIGINS = APPROVED_KALI_ORIGINS | {MIRROR_POLICY_ORIGIN}
APT_EXECUTABLES = {"apt-get": "/usr/bin/apt-get", "apt-cache": "/usr/bin/apt-cache"}
SQV = "/usr/bin/sqv"
GPGV = "/usr/bin/gpgv"


class TeamEnvError(ValueError):
    """Expected safe-stop condition. Do not print implementation tracebacks."""


def safe_subprocess_environment() -> dict[str, str]:
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}


def apt_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
    """Run one fixed APT binary without inherited config, hooks, roots, or proxies."""
    if not command or command[0] not in APT_EXECUTABLES:
        raise TeamEnvError("APT command is not approved")
    with tempfile.TemporaryDirectory(prefix="cptc-team-apt-") as temporary:
        root = Path(temporary)
        parts = root / "apt.conf.d"
        trusted_parts = root / "trusted.gpg.d"
        parts.mkdir(mode=0o700)
        trusted_parts.mkdir(mode=0o700)
        config = root / "apt.conf"
        config.write_text(
            'Dir::Etc::main "/dev/null";\n'
            f'Dir::Etc::parts "{parts}";\n'
            'Dir::Etc::sourcelist "/etc/apt/sources.list";\n'
            'Dir::Etc::sourceparts "/etc/apt/sources.list.d";\n'
            f'Dir::Etc::trusted "{KALI_KEYRING}";\n'
            f'Dir::Etc::trustedparts "{trusted_parts}";\n'
            'APT::Get::AllowUnauthenticated "false";\n'
            'Acquire::AllowInsecureRepositories "false";\n'
            'Acquire::AllowDowngradeToInsecureRepositories "false";\n'
            'Acquire::https::Verify-Peer "true";\n'
            'Acquire::https::Verify-Host "true";\n'
            'Acquire::http::Proxy "DIRECT";\n'
            'Acquire::https::Proxy "DIRECT";\n'
            'APT::Update::Pre-Invoke "";\n'
            'APT::Update::Post-Invoke "";\n'
            'APT::Update::Post-Invoke-Success "";\n'
            'DPkg::Pre-Invoke "";\n'
            'DPkg::Pre-Install-Pkgs "";\n'
            'DPkg::Post-Invoke "";\n',
            encoding="utf-8",
        )
        config.chmod(0o600)
        environment = safe_subprocess_environment()
        environment.update({"APT_CONFIG": str(config), "DEBIAN_FRONTEND": "noninteractive"})
        return subprocess.run([APT_EXECUTABLES[command[0]], *command[1:]], env=environment, **kwargs)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TeamEnvError("Cannot read JSON input: " + str(path)) from exc
    if not isinstance(data, dict):
        raise TeamEnvError("JSON input must be an object: " + str(path))
    return data


def allowed_private_owners() -> set[int]:
    owners = {os.geteuid()}
    if os.geteuid() == 0 and os.environ.get("SUDO_UID", "").isdigit():
        owners.add(int(os.environ["SUDO_UID"]))
    return owners


def private_input(path: Path) -> dict[str, Any]:
    """Read a lock or review only when it is a private regular file."""
    try:
        info = path.lstat()
    except OSError as exc:
        raise TeamEnvError("Cannot inspect private input: " + str(path)) from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid not in allowed_private_owners() or info.st_mode & 0o077:
        raise TeamEnvError("Private input is symlinked, modified, or has unsafe permissions")
    return read_json(path)


def write_private_json(path: Path, value: dict[str, Any]) -> None:
    """Atomically write a 0600 JSON file and fsync the containing directory."""
    parent = path.parent
    if parent.exists():
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid not in allowed_private_owners() or info.st_mode & 0o077:
            raise TeamEnvError("Private output directory is symlinked, modified, or has unsafe permissions")
    else:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid not in allowed_private_owners() or info.st_mode & 0o077:
            raise TeamEnvError("Private output file is symlinked, modified, or has unsafe permissions")
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(canonical_bytes(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def checked_hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise TeamEnvError(field + " must be a lowercase SHA-256 value")
    return value


def load_manifest(path: Path) -> dict[str, Any]:
    manifest = read_json(path)
    if manifest.get("schema") != "cptc.team-env.manifest.v2":
        raise TeamEnvError("Unsupported manifest schema")
    if manifest.get("expected_architecture") != "amd64":
        raise TeamEnvError("Manifest must declare the supported amd64 architecture")
    bundles = manifest.get("bundles")
    packages = manifest.get("packages")
    profiles = manifest.get("profiles")
    apps = manifest.get("applications")
    if not isinstance(bundles, dict) or not isinstance(packages, dict) or not isinstance(profiles, dict) or not isinstance(apps, dict):
        raise TeamEnvError("Manifest bundles, packages, profiles, and applications must be objects")
    for name, item in packages.items():
        if not PACKAGE.fullmatch(str(name)) or not isinstance(item, dict) or not isinstance(item.get("required"), bool) or not isinstance(item.get("reason"), str):
            raise TeamEnvError("Manifest contains an invalid package entry")
    for name, values in bundles.items():
        if not isinstance(name, str) or not isinstance(values, list) or not values or any(value not in packages for value in values):
            raise TeamEnvError("Manifest contains an invalid package bundle")
    for name in ("tester", "scribe", "harbinger_host", "merlin_host", "both"):
        if name not in profiles:
            raise TeamEnvError("Manifest must define profile " + name)
    if not {"docker.io", "docker-cli", "docker-compose"} <= set(profile_packages(manifest, "both")):
        raise TeamEnvError("Both host profile must require Docker daemon, client, and Compose packages")
    for name in ("harbinger", "merlin"):
        app = apps.get(name)
        if not isinstance(app, dict) or app.get("type") != "compose" or app.get("profile") != name + "_host":
            raise TeamEnvError("Manifest must define " + name + " as a host Compose application")
        if app.get("release_input") != "local_private_source_or_operator_archive":
            raise TeamEnvError("Application release input must remain local")
    return manifest


def profile_packages(manifest: dict[str, Any], profile: str, seen: set[str] | None = None) -> list[str]:
    seen = set() if seen is None else seen
    if profile in seen or profile not in manifest["profiles"]:
        raise TeamEnvError("Unknown or cyclic profile: " + profile)
    seen.add(profile); data = manifest["profiles"][profile]
    if not isinstance(data, dict): raise TeamEnvError("Invalid profile: " + profile)
    result: list[str] = []
    for bundle in data.get("bundles", []):
        if bundle not in manifest["bundles"]: raise TeamEnvError("Unknown package bundle: " + str(bundle))
        result.extend(manifest["bundles"][bundle])
    for included in data.get("includes", []): result.extend(profile_packages(manifest, included, seen))
    if not result: raise TeamEnvError("Profile has no packages: " + profile)
    return list(dict.fromkeys(result))


def release_names_for_origins(suite: str, origins: tuple[str, ...]) -> set[str]:
    policy_origin_expression(origins)
    names = set()
    for origin in origins:
        parsed = urlsplit(origin)
        base = parsed.netloc + parsed.path
        encoded = re.sub(r"[^A-Za-z0-9.+-]", "_", base)
        names.add(encoded + "_dists_" + suite + "_InRelease")
    return names


def fixed_signature_verifier() -> tuple[str, str]:
    for kind, value in (("sqv", SQV), ("gpgv", GPGV)):
        path = Path(value)
        if not path.exists():
            continue
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022
                or not info.st_mode & 0o111):
            raise TeamEnvError("Fixed signature verifier is unsafe")
        return kind, str(path)
    raise TeamEnvError("A fixed sqv or gpgv signature verifier is required for lock preparation")


def verify_release_signature(release: Path, keyring: Path) -> bool:
    kind, verifier = fixed_signature_verifier()
    if kind == "sqv":
        with tempfile.TemporaryDirectory(prefix="cptc-team-sqv-") as temporary:
            output = Path(temporary) / "verified-release"
            command = [verifier, "--keyring=" + str(keyring), "--output=" + str(output),
                       "--cleartext", str(release)]
            result = subprocess.run(command, text=True, env=safe_subprocess_environment(),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    else:
        result = subprocess.run([verifier, "--keyring", str(keyring), str(release)], text=True,
                                env=safe_subprocess_environment(), stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, check=False)
    return result.returncode == 0


def release_datetime(value: str | None, field: str) -> dt.datetime:
    if not value:
        raise TeamEnvError("Verified Kali metadata has no " + field)
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise TeamEnvError("Verified Kali metadata has an invalid " + field) from exc
    if parsed.tzinfo is None:
        raise TeamEnvError("Verified Kali metadata has an invalid " + field)
    return parsed.astimezone(dt.timezone.utc)


def validate_release_freshness(fields: dict[str, str], suite: str) -> tuple[str, str | None, str]:
    now = dt.datetime.now(dt.timezone.utc)
    release_date = release_datetime(fields.get("Date"), "Date")
    if release_date > now + dt.timedelta(hours=2):
        raise TeamEnvError("Verified Kali metadata Date is in the future")
    valid_until_text = fields.get("Valid-Until")
    if valid_until_text and release_datetime(valid_until_text, "Valid-Until") < now:
        raise TeamEnvError("Verified Kali metadata is expired")
    if suite == "kali-rolling" and now - release_date > dt.timedelta(days=14):
        raise TeamEnvError("Verified Kali rolling metadata is stale")
    policy = "rolling_14_day_max_age" if suite == "kali-rolling" else "static_snapshot_signature_and_date"
    return release_date.isoformat().replace("+00:00", "Z"), valid_until_text, policy


def signed_kali_release_metadata(lists_dir: Path, suite: str,
                                 origins: tuple[str, ...]) -> dict[str, Any]:
    """Validate a cached official Kali InRelease without calling apt update."""
    if suite not in SUPPORTED_KALI_SUITES:
        raise TeamEnvError("Unsupported Kali suite: " + suite)
    keyring = Path(KALI_KEYRING)
    try:
        keyring_info = keyring.lstat()
    except OSError as exc:
        raise TeamEnvError("Kali archive keyring is required for lock preparation") from exc
    if (not stat.S_ISREG(keyring_info.st_mode) or stat.S_ISLNK(keyring_info.st_mode)
            or keyring_info.st_uid not in {0, os.geteuid()} or keyring_info.st_mode & 0o022):
        raise TeamEnvError("Kali archive keyring is unsafe")
    fixed_signature_verifier()
    expected_names = release_names_for_origins(suite, origins)
    candidates = sorted(lists_dir.glob("*_InRelease"))
    verified: list[dict[str, Any]] = []
    for release in candidates:
        if release.name not in expected_names or release.is_symlink() or not release.is_file():
            continue
        if not verify_release_signature(release, keyring):
            continue
        raw = release.read_bytes()
        marker = b"\n\n"
        start = raw.find(marker)
        end = raw.find(b"\n-----BEGIN PGP SIGNATURE-----")
        if start < 0 or end < 0:
            continue
        fields: dict[str, str] = {}
        for line in raw[start + len(marker):end].decode("utf-8", "strict").splitlines():
            if ":" in line and not line.startswith(" "):
                key, value = line.split(":", 1)
                fields[key] = value.strip()
        if fields.get("Origin") != "Kali" or fields.get("Suite") != suite:
            continue
        release_date, valid_until, freshness_policy = validate_release_freshness(fields, suite)
        verified.append({"origin": "Kali", "suite": suite, "source_metadata_sha256": sha256_bytes(raw),
                         "release_file": str(release), "release_date": release_date,
                         "valid_until": valid_until, "freshness_policy": freshness_policy})
    if verified:
        hashes = {item["source_metadata_sha256"] for item in verified}
        if len(hashes) != 1:
            raise TeamEnvError("Conflicting verified Kali " + suite + " InRelease metadata is cached")
        return verified[0]
    raise TeamEnvError("No verified official Kali " + suite + " InRelease metadata is available locally")


def safe_apt_input(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise TeamEnvError("APT source input is unsafe") from exc
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022):
        raise TeamEnvError("APT source input is unsafe")


def approved_kali_origin(uri: str) -> str:
    normalized = uri.rstrip("/")
    if normalized not in APPROVED_KALI_ORIGINS:
        raise TeamEnvError("APT source origin is not approved")
    return normalized


def source_origins(uri: str, apt_root: Path) -> tuple[str, ...]:
    if uri.rstrip("/") in APPROVED_KALI_ORIGINS:
        return (approved_kali_origin(uri),)
    expected = apt_root / "mirrors" / "kali.list"
    expected_uri = "mirror+file://" + str(expected)
    if uri != expected_uri:
        raise TeamEnvError("APT source origin is not approved")
    safe_apt_input(expected)
    mirrors = [line.strip() for line in expected.read_text(encoding="utf-8").splitlines()
               if line.strip() and not line.lstrip().startswith("#")]
    if len(mirrors) != 1:
        raise TeamEnvError("APT mirror input must contain exactly one approved Kali origin")
    return (approved_kali_origin(mirrors[0]), "mirror+file:" + str(expected))


def checked_source_values(suite: str, components: list[str]) -> None:
    if suite not in SUPPORTED_KALI_SUITES:
        raise TeamEnvError("APT source suite is not supported")
    if (not components or len(components) != len(set(components))
            or not set(components) <= SUPPORTED_KALI_COMPONENTS):
        raise TeamEnvError("APT source components are not supported")


def parse_legacy_source(line: str, apt_root: Path) -> tuple[str, tuple[str, ...]]:
    match = re.fullmatch(r"deb(?:\s+\[([^]]+)\])?\s+(\S+)\s+(\S+)\s+(.+)", line)
    if not match:
        raise TeamEnvError("APT source entry is not an approved binary Kali source")
    options, uri, suite, component_text = match.groups()
    if options:
        values = options.split()
        allowed = {"arch=amd64", "signed-by=" + KALI_KEYRING}
        if len(values) != len(set(values)) or any(value not in allowed for value in values):
            raise TeamEnvError("APT source options are not approved")
    components = component_text.split()
    checked_source_values(suite, components)
    return suite, source_origins(uri, apt_root)


def deb822_stanzas(path: Path) -> list[dict[str, str]]:
    safe_apt_input(path)
    stanzas: list[dict[str, str]] = []
    fields: dict[str, str] = {}
    current: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines() + [""]:
        if not raw.strip():
            if fields:
                stanzas.append(fields)
                fields = {}
            current = None
            continue
        if raw.lstrip().startswith("#"):
            continue
        if raw[0].isspace():
            if current is None:
                raise TeamEnvError("APT Deb822 source continuation is invalid")
            fields[current] += " " + raw.strip()
            continue
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9-]*):\s*(.*)", raw)
        if not match:
            raise TeamEnvError("APT Deb822 source field is invalid")
        current = match.group(1).lower()
        if current in fields:
            raise TeamEnvError("APT Deb822 source field is duplicated")
        fields[current] = match.group(2).strip()
    return stanzas


def parse_deb822_source(fields: dict[str, str], apt_root: Path) -> tuple[str, tuple[str, ...]] | None:
    if fields.get("enabled", "yes").lower() == "no":
        return None
    allowed = {"types", "uris", "suites", "components", "signed-by", "enabled"}
    unknown = set(fields) - allowed
    if unknown:
        raise TeamEnvError("APT Deb822 source has an unsupported field")
    required = {"types", "uris", "suites", "components", "signed-by"}
    if not required <= set(fields):
        raise TeamEnvError("APT Deb822 source is incomplete")
    if fields.get("enabled", "yes").lower() != "yes":
        raise TeamEnvError("APT Deb822 Enabled value is invalid")
    types = fields["types"].split()
    uris = fields["uris"].split()
    suites = fields["suites"].split()
    if types != ["deb"] or len(uris) != 1 or len(suites) != 1 or fields["signed-by"] != KALI_KEYRING:
        raise TeamEnvError("APT Deb822 source is not an approved binary Kali source")
    components = fields["components"].split()
    checked_source_values(suites[0], components)
    return suites[0], source_origins(uris[0], apt_root)


def validate_kali_sources(apt_root: Path = Path("/etc/apt")) -> tuple[str, tuple[str, ...]]:
    """Return the one approved suite and the exact origins APT can select."""
    if apt_root.is_symlink() or not apt_root.is_dir():
        raise TeamEnvError("APT source directory is unsafe")
    source_dir = apt_root / "sources.list.d"
    if source_dir.exists() and (source_dir.is_symlink() or not source_dir.is_dir()):
        raise TeamEnvError("APT source directory is unsafe")
    entries: list[tuple[str, tuple[str, ...]]] = []
    list_paths = [apt_root / "sources.list"]
    if source_dir.exists():
        list_paths.extend(sorted(source_dir.glob("*.list")))
    for path in list_paths:
        if not path.exists():
            continue
        safe_apt_input(path)
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                entries.append(parse_legacy_source(line, apt_root))
    if source_dir.exists():
        for path in sorted(source_dir.glob("*.sources")):
            for fields in deb822_stanzas(path):
                entry = parse_deb822_source(fields, apt_root)
                if entry is not None:
                    entries.append(entry)
    suites = {suite for suite, _origins in entries}
    if not entries or len(suites) != 1:
        raise TeamEnvError("APT sources must select one supported Kali suite")
    origins = tuple(sorted({origin for _suite, values in entries for origin in values}))
    return next(iter(suites)), origins


def refresh_signed_kali_metadata() -> tuple[str, tuple[str, ...]]:
    if os.geteuid() != 0: raise TeamEnvError("Lock preparation requires root for the one approved APT metadata refresh")
    suite, origins = validate_kali_sources()
    result = apt_run(["apt-get", "update"], text=True, capture_output=True, check=False)
    if result.returncode: raise TeamEnvError("Signed native Kali APT metadata refresh failed")
    output = (result.stdout or "") + "\n" + (result.stderr or "")
    diagnostics = [line for line in output.splitlines() if line.startswith(("W:", "E:"))]
    fixed_keyring_notice = re.compile(
        r"^W: \S+: Loading " + re.escape(KALI_KEYRING)
        + r" from deprecated option Dir::Etc::Trusted$"
    )
    if any(not fixed_keyring_notice.fullmatch(line) for line in diagnostics):
        raise TeamEnvError("Signed native Kali APT metadata refresh returned warnings")
    signed_kali_release_metadata(Path("/var/lib/apt/lists"), suite, origins)
    return suite, origins


def policy_origin_expression(origins: tuple[str, ...]) -> str:
    if not origins or any(origin not in APPROVED_KALI_POLICY_ORIGINS for origin in origins):
        raise TeamEnvError("APT policy origins were not validated")
    return "(?:" + "|".join(re.escape(origin) for origin in origins) + ")"


def parse_policy(policy: str, package: str, suite: str, origins: tuple[str, ...]) -> tuple[str, str]:
    candidate = re.search(r"^\s*Candidate:\s*(\S+)$", policy, re.MULTILINE)
    if not candidate or candidate.group(1) == "(none)":
        raise TeamEnvError("No candidate version in local APT metadata for " + package)
    version = candidate.group(1)
    current = None
    expression = re.compile(r"^\s*\d+\s+" + policy_origin_expression(origins) + r"\s+" + re.escape(suite)
                            + r"/([a-z0-9-]+)\s+\S+")
    for line in policy.splitlines():
        heading = re.match(r"^\s*(?:\*{3}\s*)?(\S+)\s+\d+\s*$", line)
        if heading:
            current = heading.group(1)
            continue
        source = expression.match(line)
        if source and current == version:
            return version, source.group(1)
    raise TeamEnvError("Candidate for " + package + " is not from native Kali " + suite + " metadata")


def exact_version_available(policy: str, version: str, suite: str, component: str,
                            origins: tuple[str, ...]) -> bool:
    current = None
    source = re.compile(r"^\s*\d+\s+" + policy_origin_expression(origins) + r"\s+" + re.escape(suite)
                        + "/" + re.escape(component) + r"\s+\S+")
    for line in policy.splitlines():
        match = re.match(r"^\s*(?:\*{3}\s*)?(\S+)\s+\d+\s*$", line)
        if match: current = match.group(1); continue
        if current == version and source.match(line): return True
    return False


def collect_live_metadata(manifest: dict[str, Any], names: Iterable[str], architecture: str,
                          suite: str, origins: tuple[str, ...]) -> dict[str, Any]:
    metadata = signed_kali_release_metadata(Path("/var/lib/apt/lists"), suite, origins)
    entries = []
    for package in names:
        result = apt_run(["apt-cache", "policy", package], text=True, capture_output=True, check=False)
        try:
            if result.returncode: raise TeamEnvError("Cannot query local APT metadata")
            version, component = parse_policy(result.stdout, package, metadata["suite"], origins)
        except TeamEnvError:
            if manifest["packages"][package]["required"]: raise TeamEnvError("Required package is unavailable from native Kali metadata: " + package)
            entries.append({"name": package, "required": False, "state": "unavailable_optional"}); continue
        entries.append({"name": package, "version": version, "origin": metadata["origin"],
                        "suite": metadata["suite"], "component": component,
                        "architecture": architecture, "source_metadata_sha256": metadata["source_metadata_sha256"],
                        "required": manifest["packages"][package]["required"], "state": "locked"})
    return {"metadata": metadata, "packages": entries}


def fixture_metadata(path: Path, packages: Iterable[str], architecture: str, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read a test-only fixture. Production preparation never accepts this path."""
    fixture = read_json(path)
    if fixture.get("schema") != "cptc.team-env.synthetic-apt.v1" or fixture.get("trusted") is not True:
        raise TeamEnvError("Synthetic APT fixture has the wrong schema")
    suite = fixture.get("suite")
    if fixture.get("architecture") != architecture or fixture.get("origin") != "Kali" or suite not in SUPPORTED_KALI_SUITES:
        raise TeamEnvError("Synthetic APT fixture does not describe supported Kali metadata")
    source_hash = checked_hash(fixture.get("source_metadata_sha256"), "source_metadata_sha256")
    source_packages = fixture.get("packages")
    if not isinstance(source_packages, dict):
        raise TeamEnvError("Synthetic APT fixture packages must be an object")
    entries = []
    for name in packages:
        item = source_packages.get(name)
        required = True if manifest is None else manifest["packages"][name]["required"]
        if not isinstance(item, dict) or not isinstance(item.get("version"), str) or not item["version"]:
            if required: raise TeamEnvError("Synthetic APT fixture has no version for " + name)
            entries.append({"name": name, "required": False, "state": "unavailable_optional"}); continue
        component = item.get("component")
        if not isinstance(component, str) or not re.fullmatch(r"[a-z0-9-]+", component):
            raise TeamEnvError("Synthetic APT fixture has an invalid component")
        entries.append({"name": name, "version": item["version"], "origin": "Kali", "suite": suite,
                        "component": component, "architecture": architecture, "source_metadata_sha256": source_hash,
                        "required": required, "state": "locked"})
    return {"metadata": {"origin": "Kali", "suite": suite, "source_metadata_sha256": source_hash,
                           "release_file": "synthetic fixture"}, "packages": entries}


def lock_payload(manifest: dict[str, Any], profile: str, metadata: dict[str, Any]) -> dict[str, Any]:
    return {"schema": LOCK_SCHEMA, "created_at_utc": utc_now(), "status": "pending_review", "profile": profile,
            "manifest_sha256": sha256_json(manifest), "architecture": manifest["expected_architecture"],
            "metadata": metadata["metadata"], "packages": metadata["packages"]}


def load_lock(path: Path) -> dict[str, Any]:
    lock = private_input(path)
    expected = {"schema", "created_at_utc", "status", "profile", "manifest_sha256", "architecture", "metadata", "packages"}
    if set(lock) != expected or lock.get("schema") != LOCK_SCHEMA or lock.get("status") != "pending_review":
        raise TeamEnvError("Lock has an unsupported schema or state")
    checked_hash(lock.get("manifest_sha256"), "manifest_sha256")
    if lock.get("architecture") != "amd64" or not isinstance(lock.get("profile"), str):
        raise TeamEnvError("Lock has an unsupported profile or architecture")
    metadata = lock.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("origin") != "Kali" or metadata.get("suite") not in SUPPORTED_KALI_SUITES:
        raise TeamEnvError("Lock is not bound to supported Kali metadata")
    checked_hash(metadata.get("source_metadata_sha256"), "source_metadata_sha256")
    entries = lock.get("packages")
    if not isinstance(entries, list) or not entries:
        raise TeamEnvError("Lock has no packages")
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("state") not in {"locked", "unavailable_optional"}:
            raise TeamEnvError("Lock package fields are invalid")
        if not PACKAGE.fullmatch(str(entry.get("name"))) or not isinstance(entry.get("required"), bool): raise TeamEnvError("Lock package name or requirement is invalid")
        if entry["state"] == "unavailable_optional":
            if entry["required"] or set(entry) != {"name", "required", "state"}: raise TeamEnvError("Required package cannot be unavailable")
            continue
        if set(entry) != {"name", "version", "origin", "suite", "component", "architecture", "source_metadata_sha256", "required", "state"} or not isinstance(entry.get("version"), str) or not entry["version"]:
            raise TeamEnvError("Lock package version fields are invalid")
        if entry.get("origin") != "Kali" or entry.get("architecture") != "amd64":
            raise TeamEnvError("Lock package is not a native Kali amd64 package")
        if entry.get("suite") != metadata["suite"]:
            raise TeamEnvError("Lock package suite does not match the metadata suite")
        if not isinstance(entry.get("component"), str) or not re.fullmatch(r"[a-z0-9-]+", entry["component"]):
            raise TeamEnvError("Lock package component is invalid")
        if entry.get("source_metadata_sha256") != metadata["source_metadata_sha256"]:
            raise TeamEnvError("Lock package metadata hash does not match the lock")
    return lock


def review_payload(lock: dict[str, Any], reviewer: str) -> dict[str, Any]:
    if not reviewer or len(reviewer) > 120 or any(c in reviewer for c in "\r\n"):
        raise TeamEnvError("Reviewer must be a short single-line identifier")
    return {"schema": REVIEW_SCHEMA, "decision": "approved", "reviewer": reviewer,
            "reviewed_at_utc": utc_now(), "lock_sha256": sha256_json(lock)}


def load_review(path: Path, lock: dict[str, Any]) -> dict[str, Any]:
    review = private_input(path)
    expected = {"schema", "decision", "reviewer", "reviewed_at_utc", "lock_sha256"}
    if set(review) != expected or review.get("schema") != REVIEW_SCHEMA or review.get("decision") != "approved":
        raise TeamEnvError("Review is not an approved lock review")
    if not isinstance(review.get("reviewer"), str) or not review["reviewer"] or review.get("lock_sha256") != sha256_json(lock):
        raise TeamEnvError("Review does not bind this exact lock")
    checked_hash(review["lock_sha256"], "lock_sha256")
    return review


def dpkg_architecture() -> str:
    result = subprocess.run(["/usr/bin/dpkg", "--print-architecture"], text=True, capture_output=True,
                            env=safe_subprocess_environment(), check=False)
    if result.returncode:
        raise TeamEnvError("Cannot determine the dpkg architecture")
    return result.stdout.strip()


def kali_host() -> bool:
    try:
        fields = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
                      if "=" in line)
    except OSError:
        return False
    return fields.get("ID", "").strip('"') == "kali"


def required_and_optional(manifest: dict[str, Any], profile: str, lock: dict[str, Any]) -> tuple[list[str], list[str]]:
    manifest_names = {name: manifest["packages"][name]["required"] for name in profile_packages(manifest, profile)}
    lock_names = [entry["name"] for entry in lock["packages"]]
    if set(lock_names) != set(manifest_names) or len(lock_names) != len(set(lock_names)):
        raise TeamEnvError("Lock packages do not match the selected manifest role")
    required = [name for name in lock_names if manifest_names[name]]
    optional = [name for name in lock_names if not manifest_names[name]]
    if any(entry["name"] in required and entry["state"] != "locked" for entry in lock["packages"]):
        raise TeamEnvError("Required package is not locked")
    return required, optional


def plan_data(manifest: dict[str, Any], lock: dict[str, Any], review: dict[str, Any]) -> dict[str, Any]:
    required, optional = required_and_optional(manifest, lock["profile"], lock)
    versions = {entry["name"]: entry.get("version") for entry in lock["packages"]}
    unavailable = [entry["name"] for entry in lock["packages"] if entry["state"] == "unavailable_optional"]
    return {"action": "reviewed native Kali package plan", "profile": lock["profile"], "architecture": lock["architecture"],
            "required": [{"package": package, "version": versions[package]} for package in required],
            "optional_visible_not_installed": [{"package": package, "version": versions[package]} for package in optional if versions[package]],
            "optional_unavailable": unavailable,
            "reviewer": review["reviewer"], "effects": ["does not create directories", "does not update APT metadata",
            "does not start or pull Harbinger or Merlin", "does not change firewall rules or group membership"]}


def apply_preflight(manifest: dict[str, Any], lock: dict[str, Any], review: dict[str, Any]) -> list[str]:
    required, _ = required_and_optional(manifest, lock["profile"], lock)
    if not kali_host():
        raise TeamEnvError("Apply is permitted only on Kali Linux")
    if os.geteuid() != 0:
        raise TeamEnvError("Apply requires root. Review and plan do not require root")
    if dpkg_architecture() != lock["architecture"]:
        raise TeamEnvError("Host dpkg architecture does not match the reviewed lock")
    if lock["manifest_sha256"] != sha256_json(manifest):
        raise TeamEnvError("Lock does not match the local manifest")
    if review["lock_sha256"] != sha256_json(lock):
        raise TeamEnvError("Review does not match the local lock")
    suite, origins = validate_kali_sources()
    if suite != lock["metadata"]["suite"]:
        raise TeamEnvError("Configured Kali suite does not match the reviewed lock")
    current = signed_kali_release_metadata(Path("/var/lib/apt/lists"), suite, origins)
    if current["source_metadata_sha256"] != lock["metadata"]["source_metadata_sha256"]:
        raise TeamEnvError("Current signed Kali metadata does not match the reviewed lock")
    for entry in lock["packages"]:
        if not entry["required"]: continue
        policy = apt_run(["apt-cache", "policy", entry["name"]], text=True, capture_output=True, check=False)
        if policy.returncode or not exact_version_available(
                policy.stdout, entry["version"], current["suite"], entry["component"], origins):
            raise TeamEnvError("Required locked version is no longer available: " + entry["name"])
    return required


def state_dir(value: str | None) -> Path:
    if value:
        return Path(value).expanduser()
    return Path.home() / ".local" / "state" / "cptc-private-toolkit" / "team-env-setup"


def secure_state_directory(directory: Path) -> Path:
    if directory.exists() or directory.is_symlink():
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid not in allowed_private_owners() or info.st_mode & 0o077:
            raise TeamEnvError("Private state input is symlinked, modified, or has unsafe permissions")
    else:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return directory


def private_event_file(path: Path) -> None:
    if not path.exists(): return
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid not in allowed_private_owners() or info.st_mode & 0o077:
        raise TeamEnvError("Private state event input is symlinked, modified, or has unsafe permissions")


def _write_all(descriptor: int, output: bytes) -> None:
    view = memoryview(output)
    while view:
        try:
            written = os.write(descriptor, view)
        except InterruptedError:
            continue
        if not isinstance(written, int) or written <= 0 or written > len(view):
            raise OSError("Private state event write stopped")
        view = view[written:]


@contextmanager
def private_audit_lock(directory: Path):
    """Serialize validation and append of the two-file audit chain."""
    lock = directory / ".events.lock"
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in allowed_private_owners()
                or info.st_mode & 0o077):
            raise TeamEnvError("Private state audit lock is unsafe")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try: fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally: os.close(descriptor)


def append_event(directory: Path, command: str, status: str, lock_hash: str, detail: dict[str, Any], *, publish=None) -> None:
    """Append one paired audit event and publish an optional receipt atomically.

    The callback runs only after both audit files are durable.  A callback
    failure compensates by truncating both files to their original offsets.
    """
    directory = secure_state_directory(directory)
    with private_audit_lock(directory):
        jsonl, readable = directory / "events.jsonl", directory / "events.log"
        private_event_file(jsonl); private_event_file(readable)
        previous = ""; readable_lines: list[str] = []
        if jsonl.exists():
            try:
                for raw in jsonl.read_text(encoding="utf-8").splitlines():
                    event = json.loads(raw)
                    if not isinstance(event, dict) or event.get("schema") != "cptc.team-env.event.v1" or event.get("previous_sha256") != previous:
                        raise ValueError
                    observed = event.pop("event_sha256", None)
                    if observed != sha256_json(event): raise ValueError
                    previous = observed
                    readable_lines.append(event["created_at_utc"] + " " + event["command"] + " " + event["status"] + " " + observed + "\n")
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                raise TeamEnvError("Private state event log was modified or is invalid") from exc
        if readable.exists() and readable.read_text(encoding="utf-8") != "".join(readable_lines):
            raise TeamEnvError("Readable private state event log was modified or is invalid")
        event = {"schema": "cptc.team-env.event.v1", "created_at_utc": utc_now(), "command": command,
                 "status": status, "lock_sha256": lock_hash, "detail": detail, "previous_sha256": previous}
        event["event_sha256"] = sha256_json(event)
        line = canonical_bytes(event) + b"\n"
        readable_line = (event["created_at_utc"] + " " + command + " " + status + " " + event["event_sha256"] + "\n").encode("utf-8")
        outputs = ((jsonl, line), (readable, readable_line))
        opened: list[tuple[Path, int, int, bool]] = []
        try:
            for path, _ in outputs:
                existed = path.exists()
                descriptor = os.open(
                    path,
                    os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                )
                try:
                    original_size = os.fstat(descriptor).st_size
                    os.fchmod(descriptor, 0o600)
                except BaseException:
                    os.close(descriptor)
                    if not existed:
                        path.unlink(missing_ok=True)
                    raise
                opened.append((path, descriptor, original_size, existed))
            try:
                for (_, output), (_, descriptor, _, _) in zip(outputs, opened, strict=True):
                    _write_all(descriptor, output)
                    os.fsync(descriptor)
                if publish is not None:
                    publish()
            except BaseException as failure:
                rollback_failure = None
                for _, descriptor, original_size, _ in opened:
                    try:
                        os.ftruncate(descriptor, original_size)
                        os.fsync(descriptor)
                    except BaseException as error:
                        rollback_failure = rollback_failure or error
                if rollback_failure is not None:
                    raise TeamEnvError(
                        "Private state event rollback failed; inspect both audit files before another mutation"
                    ) from failure
                for path, _, original_size, existed in opened:
                    if not existed and original_size == 0:
                        path.unlink(missing_ok=True)
                raise
        finally:
            for _, descriptor, _, _ in opened:
                os.close(descriptor)


def publish_receipt(directory: Path, payload: dict[str, Any], *, audit_hash: str, detail: dict[str, Any]) -> Path:
    """Publish a receipt only as part of the paired durable audit append."""
    directory = secure_state_directory(directory)
    command, status = payload["command"], payload["status"]
    name = command + "-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + os.urandom(4).hex() + ".json"
    target = directory / name
    temporary = directory / ("." + name + ".pending")
    write_private_json(temporary, payload)
    published = False
    def publish() -> None:
        nonlocal published
        try:
            os.replace(temporary, target)
            published = True
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try: os.fsync(directory_fd)
            finally: os.close(directory_fd)
        except BaseException:
            if published:
                try: target.unlink(missing_ok=True)
                except OSError: pass
            raise
    try:
        append_event(directory, command, status, audit_hash, detail, publish=publish)
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)
    return target


def receipt(directory: Path, command: str, lock: dict[str, Any], status: str, detail: dict[str, Any]) -> Path:
    payload = {"schema": RECEIPT_SCHEMA, "created_at_utc": utc_now(), "command": command, "status": status,
               "lock_sha256": sha256_json(lock), "detail": detail}
    return publish_receipt(directory, payload, audit_hash=payload["lock_sha256"], detail=detail)


def installed_version(name: str) -> str | None:
    result = subprocess.run(["/usr/bin/dpkg-query", "-W", "--showformat=${Status} ${Version}", name], text=True,
                            capture_output=True, env=safe_subprocess_environment(), check=False)
    if result.returncode:
        return None
    fields = result.stdout.strip().split()
    if len(fields) != 4 or fields[:3] != ["install", "ok", "installed"]:
        return None
    return fields[3]


def verify_packages(lock: dict[str, Any], required: Iterable[str] | None = None) -> dict[str, str]:
    failures: list[str] = []
    installed: dict[str, str] = {}
    required_names = set(required) if required is not None else {entry["name"] for entry in lock["packages"] if entry["required"]}
    for entry in lock["packages"]:
        if entry["name"] not in required_names or entry["state"] != "locked": continue
        name, expected = entry["name"], entry["version"]
        actual = installed_version(name)
        copyright_path = Path("/usr/share/doc") / name / "copyright"
        if actual != expected:
            failures.append(name + " version does not match lock")
        elif not copyright_path.is_file():
            failures.append(name + " copyright file is missing")
        else:
            installed[name] = actual
    if failures:
        raise TeamEnvError("; ".join(failures))
    return installed


def tree_hash(source: Path) -> str:
    if not source.is_dir() or source.is_symlink():
        raise TeamEnvError("Release source must be a local non-symlinked directory")
    digest = hashlib.sha256()
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if ".git" in relative.parts:
            continue
        if path.is_symlink() or not path.is_file():
            if path.is_symlink():
                raise TeamEnvError("Release source cannot contain symlinks")
            continue
        digest.update(str(relative).encode("utf-8") + b"\0")
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    return digest.hexdigest()


def file_hash(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise TeamEnvError("Release archive must be a local non-symlinked regular file")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def command_manifest(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.manifest))
    print(json.dumps(manifest, sort_keys=True, indent=2))
    return 0


def command_prepare_lock(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.manifest))
    names = profile_packages(manifest, args.profile)
    suite, origins = refresh_signed_kali_metadata()
    metadata = collect_live_metadata(manifest, names, manifest["expected_architecture"], suite, origins)
    payload = lock_payload(manifest, args.profile, metadata)
    write_private_json(Path(args.lock), payload)
    print("Pending review lock: " + str(Path(args.lock)))
    return 0


def reviewed_inputs(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    manifest = load_manifest(Path(args.manifest))
    lock = load_lock(Path(args.lock))
    review = load_review(Path(args.review), lock)
    if lock["manifest_sha256"] != sha256_json(manifest):
        raise TeamEnvError("Lock does not match the local manifest")
    return manifest, lock, review


def command_review_lock(args: argparse.Namespace) -> int:
    lock = load_lock(Path(args.lock))
    payload = review_payload(lock, args.reviewer)
    write_private_json(Path(args.review), payload)
    print("Approved review: " + str(Path(args.review)))
    return 0


def command_plan(args: argparse.Namespace) -> int:
    manifest, lock, review = reviewed_inputs(args)
    print(json.dumps(plan_data(manifest, lock, review), sort_keys=True, indent=2))
    return 0


def command_apply(args: argparse.Namespace) -> int:
    if not args.apply:
        raise TeamEnvError("Apply is inert without the explicit --apply flag")
    manifest, lock, review = reviewed_inputs(args)
    packages = apply_preflight(manifest, lock, review)
    versions = {entry["name"]: entry["version"] for entry in lock["packages"]}
    command = ["apt-get", "install", "--assume-yes", "--no-install-recommends"] + [name + "=" + versions[name] for name in packages]
    result = apt_run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    directory = state_dir(args.receipt_dir)
    path = receipt(directory, "apply", lock, "success" if result.returncode == 0 else "apt_failed",
                   {"exit_code": result.returncode, "packages": packages})
    print("Private receipt: " + str(path))
    return result.returncode


def command_verify(args: argparse.Namespace) -> int:
    manifest, lock, _review = reviewed_inputs(args)
    required, _optional = required_and_optional(manifest, lock["profile"], lock)
    installed = verify_packages(lock, required)
    path = receipt(state_dir(args.receipt_dir), "verify", lock, "success", {"installed": installed})
    print("Private receipt: " + str(path))
    return 0


def command_verify_release(args: argparse.Namespace) -> int:
    directory = state_dir(args.receipt_dir)
    expected = args.expected_sha256 if isinstance(args.expected_sha256, str) and SHA256.fullmatch(args.expected_sha256) else "0" * 64
    input_kind = "source" if bool(args.source) and not args.archive else "archive" if bool(args.archive) and not args.source else "invalid"
    application = args.app if isinstance(args.app, str) and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", args.app) else "unapproved"
    try:
        manifest = load_manifest(Path(args.manifest))
        if args.app not in manifest["applications"]:
            raise TeamEnvError("Unknown application: " + args.app)
        expected = checked_hash(args.expected_sha256, "expected_sha256")
        if bool(args.source) == bool(args.archive):
            raise TeamEnvError("Provide exactly one local --source or --archive input")
        actual = tree_hash(Path(args.source)) if args.source else file_hash(Path(args.archive))
        if actual != expected:
            raise TeamEnvError("Local release input hash does not match the operator-provided hash")
    except (TeamEnvError, OSError):
        failure = {"schema": RECEIPT_SCHEMA, "created_at_utc": utc_now(), "command": "verify-release", "status": "failed",
                   "application": application, "input_kind": input_kind, "sha256": expected}
        try:
            publish_receipt(directory, failure, audit_hash=expected,
                            detail={"application": application, "input_kind": input_kind, "outcome": "failed"})
        except Exception as audit_error:
            raise TeamEnvError("Release verification failure could not be durably audited") from audit_error
        raise
    payload = {"schema": RECEIPT_SCHEMA, "created_at_utc": utc_now(), "command": "verify-release", "status": "success",
               "application": application, "input_kind": input_kind, "sha256": actual}
    target = publish_receipt(directory, payload, audit_hash=actual,
                             detail={"application": application, "input_kind": input_kind, "outcome": "success"})
    print("Private receipt: " + str(target))
    return 0


def parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="local manifest path")
    root = argparse.ArgumentParser(description="Prepare reviewed native Kali packages for private team applications.")
    commands = root.add_subparsers(dest="command", required=True)
    show = commands.add_parser("manifest", parents=[common], help="print the fixed package manifest")
    show.set_defaults(func=command_manifest)
    prepare = commands.add_parser("prepare-lock", parents=[common], help="write a pending-review lock from local APT metadata")
    prepare.add_argument("--profile", default="both", choices=("tester", "scribe", "harbinger_host", "merlin_host", "both"))
    prepare.add_argument("--lock", required=True)
    prepare.set_defaults(func=command_prepare_lock)
    review = commands.add_parser("review-lock", help="bind a human approval to an exact pending lock")
    review.add_argument("--lock", required=True)
    review.add_argument("--review", required=True)
    review.add_argument("--reviewer", required=True)
    review.set_defaults(func=command_review_lock)
    for name, func, description in (("plan", command_plan, "show reviewed plan without writes"),
                                    ("apply", command_apply, "install the reviewed required packages"),
                                    ("verify", command_verify, "verify package versions and copyright files")):
        item = commands.add_parser(name, parents=[common], help=description)
        item.add_argument("--lock", required=True)
        item.add_argument("--review", required=True)
        item.add_argument("--receipt-dir")
        if name == "apply":
            item.add_argument("--apply", action="store_true")
        item.set_defaults(func=func)
    release = commands.add_parser("verify-release", parents=[common], help="verify a local private application release input")
    release.add_argument("--app", required=True, choices=("harbinger", "merlin"))
    release.add_argument("--source")
    release.add_argument("--archive")
    release.add_argument("--expected-sha256", required=True)
    release.add_argument("--receipt-dir")
    release.set_defaults(func=command_verify_release)
    return root


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        return args.func(args)
    except TeamEnvError as exc:
        print("team-env-setup: " + str(exc), file=sys.stderr)
        return 2
    except OSError as exc:
        print("team-env-setup: local operation failed: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
