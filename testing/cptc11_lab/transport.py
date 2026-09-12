"""Pinned, headless transport for read-only CPTC11 lab scanning.

The public surface intentionally exposes only :class:`LabSession.run_scan`.
It has no arbitrary-command method and never creates a local or remote listener.
"""

from __future__ import annotations

import base64
import argparse
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import ipaddress
import io
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Mapping, Protocol, TextIO
import uuid

from cptc_harness.contracts import PolicyError
from cptc_harness.profile_runtime.service_client import validate_portcast_result_v6
from cptc_harness.scanner_results import parse_smb2_xml_facts
from cptc_harness.portcast_identity import (
    PORTCAST_PROFILE_ID,
    PORTCAST_TARGET_IPV4,
    PORTCAST_TARGET_PORT,
    get_portcast_profile,
    validate_portcast_identity_response,
)


class TransportError(RuntimeError):
    """A pinned transport operation failed."""


class PreflightRejected(TransportError):
    """The Dell host failed a read-only preflight check."""


class TargetRejected(ValueError):
    """A scan target was outside the exact engagement allowlist."""


class TemplateRejected(ValueError):
    """A scanner template was not in the fixed read-only catalog."""


@dataclass(frozen=True, slots=True)
class SshEndpoint:
    """One exact SSH hop, including its SHA-256 host-key pin."""

    host: str
    port: int
    username: str
    host_key_sha256: str

    def __post_init__(self) -> None:
        ipaddress.ip_address(self.host)
        if not 1 <= self.port <= 65535:
            raise ValueError("SSH port is outside the valid range")
        if not self.username or any(char.isspace() for char in self.username):
            raise ValueError("SSH username must be a single nonempty token")
        if not self.host_key_sha256.startswith("SHA256:"):
            raise ValueError("SSH host key must use SHA256 fingerprint form")


@dataclass(frozen=True, slots=True, repr=False)
class EncryptedCredentialRef:
    """A safe locator for one field inside a local systemd-creds blob."""

    encrypted_path: Path
    credential_name: str
    secret_key: str | None = None

    def __post_init__(self) -> None:
        path = self.encrypted_path.expanduser()
        if not path.is_absolute() or path.suffix != ".cred":
            raise ValueError("credential reference must be an absolute .cred path")
        if not self.credential_name or self.secret_key == "":
            raise ValueError("credential reference fields cannot be empty")

    def __repr__(self) -> str:
        return (
            "EncryptedCredentialRef("
            f"encrypted_path={str(self.encrypted_path)!r}, "
            f"credential_name={self.credential_name!r}, secret_key=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class ServiceCredentialRef:
    """One fixed credential name supplied by the canonical systemd service."""

    credential_name: str

    def __post_init__(self) -> None:
        if self.credential_name not in {"cptc11-dell", "cptc11-kali"}:
            raise ValueError("service credential name is not fixed")

    def __repr__(self) -> str:
        return f"ServiceCredentialRef(credential_name={self.credential_name!r})"


@dataclass(frozen=True, slots=True)
class RemoteNames:
    """Exact names reserved for the one ephemeral VDI bridge."""

    namespace: str = "hbg-cptc11-vdi"
    host_veth: str = "hbg11-vh"
    namespace_veth: str = "hbg11-vn"
    lock_path: str = "/run/lock/hbg-cptc11-vdi.lock"
    bridge: str = "vmbr111"

    def __post_init__(self) -> None:
        shell_safe = set("abcdefghijklmnopqrstuvwxyz0123456789-")
        for value in (self.namespace, self.host_veth, self.namespace_veth):
            if not value or not set(value) <= shell_safe:
                raise ValueError("remote names must use lowercase ASCII, digits, and hyphens")
        if max(len(self.host_veth), len(self.namespace_veth)) > 15:
            raise ValueError("Linux interface names cannot exceed 15 characters")
        if self.lock_path != "/run/lock/hbg-cptc11-vdi.lock" or self.bridge != "vmbr111":
            raise ValueError("remote lock and bridge are fixed for this lab")


@dataclass(frozen=True, slots=True)
class LabConfig:
    dell: SshEndpoint
    kali: SshEndpoint
    dell_credential: EncryptedCredentialRef | ServiceCredentialRef
    kali_credential: EncryptedCredentialRef | ServiceCredentialRef
    remote: RemoteNames = RemoteNames()


_CREDENTIAL_ROOT = Path("/home/moriz/.config/credstore.encrypted")

DEFAULT_CONFIG = LabConfig(
    dell=SshEndpoint(
        host="100.85.84.30",
        port=22,
        username="root",
        host_key_sha256="SHA256:i+6XXKZaZXbtabv/5BifieLu6RVGTjkdhF8B6y5+SIM",
    ),
    kali=SshEndpoint(
        host="10.0.254.201",
        port=22,
        username="root",
        host_key_sha256="SHA256:0IHD7brwbkt3dllpQNOHw3bwwurq0bFMbyNcb+4s8Bs",
    ),
    dell_credential=EncryptedCredentialRef(
        encrypted_path=_CREDENTIAL_ROOT / "cptc11-regional-dell-prox.cred",
        credential_name="cptc11-regional-dell-prox",
    ),
    kali_credential=EncryptedCredentialRef(
        encrypted_path=_CREDENTIAL_ROOT / "cptc11-regional-kali.cred",
        credential_name="cptc11-regional-kali",
    ),
)

SERVICE_CONFIG = replace(
    DEFAULT_CONFIG,
    dell_credential=ServiceCredentialRef("cptc11-dell"),
    kali_credential=ServiceCredentialRef("cptc11-kali"),
)
_SERVICE_SESSION_AUTHORITY = object()


ALLOWED_TARGETS = frozenset(
    {
        "10.0.1.6",
        "10.0.1.10",
        "10.0.1.11",
        "10.0.1.13",
        "10.0.1.14",
        "10.0.1.30",
        "10.0.1.99",
    }
)

KALI_REQUIRED_FILE_PATHS: tuple[str, ...] = (
    "/usr/bin/nmap",
    "/usr/share/nmap/scripts/smb2-security-mode.nse",
    "/usr/share/nmap/nselib/asn1.lua",
    "/usr/share/nmap/nselib/base32.lua",
    "/usr/share/nmap/nselib/datetime.lua",
    "/usr/share/nmap/nselib/dns.lua",
    "/usr/share/nmap/nselib/ipOps.lua",
    "/usr/share/nmap/nselib/listop.lua",
    "/usr/share/nmap/nselib/netbios.lua",
    "/usr/share/nmap/nselib/nsedebug.lua",
    "/usr/share/nmap/nselib/smb.lua",
    "/usr/share/nmap/nselib/smb2.lua",
    "/usr/share/nmap/nselib/smbauth.lua",
    "/usr/share/nmap/nselib/stdnse.lua",
    "/usr/share/nmap/nselib/strict.lua",
    "/usr/share/nmap/nselib/stringaux.lua",
    "/usr/share/nmap/nselib/tableaux.lua",
    "/usr/share/nmap/nselib/unicode.lua",
    "/usr/share/nmap/nselib/unittest.lua",
)

_KALI_REQUIRED_FILES_SHELL = " ".join(shlex.quote(path) for path in KALI_REQUIRED_FILE_PATHS)

KALI_INVENTORY_ARGV: tuple[str, ...] = (
    "/bin/sh",
    "-eu",
    "-c",
    f"""export LC_ALL=C
printf '%s\\n' HARBINGER_KALI_RUNTIME_V1
printf 'nmap_package\\t%s\\n' \"$(/usr/bin/dpkg-query -W -f='${{Version}}' nmap)\"
for path in {_KALI_REQUIRED_FILES_SHELL}; do
  test -f \"$path\" -a -r \"$path\"
  digest=$(/usr/bin/sha256sum -- \"$path\" | /usr/bin/awk '{{print $1}}')
  printf 'file\\t%s\\t%s\\n' \"$path\" \"$digest\"
done
""",
)

KALI_OPENSSH_REQUIRED_FILE_PATHS: tuple[str, ...] = (
    "/bin/bash",
    "/bin/hostname",
    "/bin/sh",
    "/etc/ssh/sshd_config",
    "/usr/bin/awk",
    "/usr/bin/chmod",
    "/usr/bin/chown",
    "/usr/bin/dpkg-query",
    "/usr/bin/install",
    "/usr/bin/mkdir",
    "/usr/bin/mktemp",
    "/usr/bin/mv",
    "/usr/bin/rm",
    "/usr/bin/sha256sum",
    "/usr/bin/sync",
    "/usr/bin/systemctl",
    "/usr/sbin/sshd",
    "/usr/share/doc/bash/copyright",
    "/usr/share/doc/coreutils/copyright",
    "/usr/share/doc/dpkg/copyright",
    "/usr/share/doc/gawk/copyright",
    "/usr/share/doc/hostname/copyright",
    "/usr/share/doc/openssh-server/copyright",
    "/usr/share/doc/systemd/copyright",
)
KALI_OPENSSH_REQUIRED_PACKAGES: tuple[str, ...] = (
    "bash",
    "coreutils",
    "dpkg",
    "gawk",
    "hostname",
    "openssh-server",
    "systemd",
)
_KALI_OPENSSH_REQUIRED_FILES_SHELL = " ".join(
    shlex.quote(path) for path in KALI_OPENSSH_REQUIRED_FILE_PATHS
)
_KALI_OPENSSH_REQUIRED_PACKAGES_SHELL = " ".join(
    shlex.quote(package) for package in KALI_OPENSSH_REQUIRED_PACKAGES
)

KALI_OPENSSH_INVENTORY_ARGV: tuple[str, ...] = (
    "/bin/sh",
    "-eu",
    "-c",
    f"""export LC_ALL=C
printf '%s\n' HARBINGER_KALI_OPENSSH_RUNTIME_V2
printf 'hostname\t%s\n' "$(/bin/hostname)"
machine_digest=$(/usr/bin/sha256sum -- /etc/machine-id | /usr/bin/awk '{{print $1}}')
printf 'machine_id_sha256\t%s\n' "$machine_digest"
for package in {_KALI_OPENSSH_REQUIRED_PACKAGES_SHELL}; do
  version=$(/usr/bin/dpkg-query -W -f='${{Version}}' "$package")
  printf 'package\t%s\t%s\n' "$package" "$version"
done
for path in {_KALI_OPENSSH_REQUIRED_FILES_SHELL}; do
  test -f "$path" -a -r "$path"
  digest=$(/usr/bin/sha256sum -- "$path" | /usr/bin/awk '{{print $1}}')
  printf 'file\t%s\t%s\n' "$path" "$digest"
done
for path in /etc/ssh/sshd_config.d/*.conf; do
  test -e "$path" || continue
  test -f "$path" -a -r "$path"
  digest=$(/usr/bin/sha256sum -- "$path" | /usr/bin/awk '{{print $1}}')
  printf 'sshd_fragment\t%s\t%s\n' "$path" "$digest"
done
unit_path=$(/usr/bin/systemctl show --property=FragmentPath --value ssh.service)
case "$unit_path" in
  /usr/lib/systemd/system/*|/lib/systemd/system/*|/etc/systemd/system/*|/run/systemd/system/*) ;;
  *) exit 72 ;;
esac
case "$unit_path" in *[!A-Za-z0-9_./@:-]*) exit 72 ;; esac
test -f "$unit_path" -a -r "$unit_path"
digest=$(/usr/bin/sha256sum -- "$unit_path" | /usr/bin/awk '{{print $1}}')
printf 'service_unit\t%s\t%s\n' "$unit_path" "$digest"
dropin_paths=$(/usr/bin/systemctl show --property=DropInPaths --value ssh.service)
set -f
for path in $dropin_paths; do
  case "$path" in
    /usr/lib/systemd/system/ssh.service.d/*.conf|/lib/systemd/system/ssh.service.d/*.conf|/etc/systemd/system/ssh.service.d/*.conf|/run/systemd/system/ssh.service.d/*.conf) ;;
    *) exit 72 ;;
  esac
  test -f "$path" -a -r "$path"
  digest=$(/usr/bin/sha256sum -- "$path" | /usr/bin/awk '{{print $1}}')
  printf 'service_dropin\t%s\t%s\n' "$path" "$digest"
done
printf '%s\n' HARBINGER_KALI_OPENSSH_RUNTIME_END_V2
""",
)

KALI_PORTCAST_RELAY_POLICY_ARGV: tuple[str, ...] = (
    "/bin/sh",
    "-eu",
    "-c",
    """export LC_ALL=C
effective=$(/usr/sbin/sshd -T -C 'user=root,host=10.0.254.201,addr=10.0.254.253,laddr=10.0.254.201,lport=22')
policy_value() {
  printf '%s\n' "$effective" | /usr/bin/awk -v key="$1" '
    $1 == key { count += 1; $1 = ""; sub(/^ /, ""); value = $0 }
    END { if (count != 1) exit 1; print value }
  '
}
test "$(policy_value permitopen)" = '10.0.1.30:8096'
test "$(policy_value permitlisten)" = 'none'
test "$(policy_value allowtcpforwarding)" = 'local'
test "$(policy_value x11forwarding)" = 'no'
test "$(policy_value permittunnel)" = 'no'
test "$(policy_value gatewayports)" = 'no'
printf '%s\n' HARBINGER_PORTCAST_RELAY_POLICY_V1
""",
)

DC_SMB_SCAN_ARGV: tuple[str, ...] = (
    "/usr/bin/nmap",
    "--unprivileged",
    "-sT",
    "-Pn",
    "-n",
    "-p",
    "445",
    "--script",
    "/usr/share/nmap/scripts/smb2-security-mode.nse",
    "--max-retries",
    "0",
    "--max-parallelism",
    "1",
    "--host-timeout",
    "15s",
    "--script-timeout",
    "8s",
    "-oX",
    "-",
    "10.0.1.6",
)

# This immutable worker identity is not in either execution allowlist. The
# release cannot run it until a parent-owned wire-accounting path is admitted.
PORTCAST_HTTP_WORKER_ARGV: tuple[str, ...] = (
    "/usr/bin/python3",
    "-I",
    "-S",
    "/usr/libexec/cptc-harness/portcast-http-worker-v1.py",
)

SCAN_TEMPLATES: Mapping[str, tuple[str, ...]] = {
    "dc-smb-security": DC_SMB_SCAN_ARGV,
}

_OUTPUT_CAP = 16 * 1024
_ENCRYPTED_ARTIFACT_RESERVATION = _OUTPUT_CAP + 2048
_TARGET_PENDING_ARTIFACTS = (
    "dc-smb-security.stdout.age.pending",
    "dc-smb-security.stderr.age.pending",
    "dc-smb-security.typed.json.age.pending",
)
_PORTCAST_PENDING_ARTIFACTS = (
    "portcast-identity.stdout.age.pending",
    "portcast-identity.stderr.age.pending",
    "portcast-identity.typed.json.age.pending",
)
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_AGE_BINARY = _PROJECT_ROOT / ".tools" / "age"
_DEFAULT_AGE_KEYGEN = _PROJECT_ROOT / ".tools" / "age-keygen"
_DEFAULT_AGE_IDENTITY = Path(
    "/home/moriz/.local/share/cptc-harness/operator-keys/lab-validation.agekey"
)
class EvidenceEncryptor(Protocol):
    def encrypt(self, data: bytes) -> bytes: ...


class AgeEncryptor:
    """Encrypt target-derived bytes to the enrolled local lab recipient."""

    def __init__(self, age: Path, keygen: Path, identity: Path) -> None:
        for executable in (age, keygen):
            if executable.is_symlink() or not executable.is_file() or not os.access(executable, os.X_OK):
                raise TransportError("age encryption executable is unavailable")
        if identity.is_symlink() or not identity.is_file() or identity.stat().st_mode & 0o077:
            raise TransportError("age identity permissions are unsafe")
        result = subprocess.run(
            (str(keygen), "-y", str(identity)),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            env={},
            close_fds=True,
        )
        recipient = result.stdout.decode("ascii", "strict").strip() if result.returncode == 0 else ""
        if re.fullmatch(r"age1[0-9a-z]{50,80}", recipient) is None:
            raise TransportError("age recipient derivation failed")
        self._age = age
        self._recipient = recipient

    @classmethod
    def default(cls) -> "AgeEncryptor":
        return cls(_DEFAULT_AGE_BINARY, _DEFAULT_AGE_KEYGEN, _DEFAULT_AGE_IDENTITY)

    def encrypt(self, data: bytes) -> bytes:
        result = subprocess.run(
            (str(self._age), "-r", self._recipient),
            check=False,
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=20,
            env={},
            close_fds=True,
        )
        if result.returncode or not result.stdout.startswith(b"age-encryption.org/v1"):
            raise TransportError("age evidence encryption failed")
        return result.stdout

    @property
    def age_binary(self) -> Path:
        """Return the pinned public executable path for AuditService setup."""

        return self._age

    @property
    def recipient(self) -> str:
        """Return the public age recipient. This value is not a decryption key."""

        return self._recipient


@dataclass(frozen=True, slots=True)
class RuntimeFilePin:
    path: str
    sha256: str


@dataclass(frozen=True, slots=True)
class RuntimePackagePin:
    name: str
    version: str


@dataclass(frozen=True, slots=True)
class KaliRuntimeManifest:
    """Typed identity of the exact Kali runtime used for a lab observation."""

    schema: int
    nmap_package: str
    files: tuple[RuntimeFilePin, ...]

    @property
    def sha256(self) -> str:
        payload = {
            "schema": self.schema,
            "nmap_package": self.nmap_package,
            "files": [{"path": pin.path, "sha256": pin.sha256} for pin in self.files],
            "inventory_argv_sha256": _argv_sha256(KALI_INVENTORY_ARGV),
            "scan_argv_sha256": _argv_sha256(DC_SMB_SCAN_ARGV),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class OpenSshRuntimeManifest:
    """Typed identity of the Kali OpenSSH server used for channel policy."""

    schema: int
    hostname: str
    machine_id_sha256: str
    packages: tuple[RuntimePackagePin, ...]
    files: tuple[RuntimeFilePin, ...]
    sshd_fragments: tuple[RuntimeFilePin, ...]
    service_unit: RuntimeFilePin
    service_dropins: tuple[RuntimeFilePin, ...]

    @property
    def sha256(self) -> str:
        payload = {
            "schema": self.schema,
            "hostname": self.hostname,
            "machine_id_sha256": self.machine_id_sha256,
            "packages": [
                {"name": pin.name, "version": pin.version}
                for pin in self.packages
            ],
            "files": [
                {"path": pin.path, "sha256": pin.sha256} for pin in self.files
            ],
            "sshd_fragments": [
                {"path": pin.path, "sha256": pin.sha256}
                for pin in self.sshd_fragments
            ],
            "service_unit": {
                "path": self.service_unit.path,
                "sha256": self.service_unit.sha256,
            },
            "service_dropins": [
                {"path": pin.path, "sha256": pin.sha256}
                for pin in self.service_dropins
            ],
            "inventory_argv_sha256": _argv_sha256(KALI_OPENSSH_INVENTORY_ARGV),
            "policy_argv_sha256": _argv_sha256(KALI_PORTCAST_RELAY_POLICY_ARGV),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class LabSmbObservation:
    """Typed lab evidence that remains explicitly outside live admission."""

    schema_version: int
    profile_id: str
    related_check_id: str
    target_id: str
    target_ipv4: str
    dialect: str
    signing_enabled: bool
    signing_required: bool
    disposition: str
    collection_state: str
    confirmed_vulnerability: bool
    limitations: tuple[str, ...]
    runtime_pinset_sha256: str
    evidence_sha256: str
    evidence_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile_id": self.profile_id,
            "related_check_id": self.related_check_id,
            "target_id": self.target_id,
            "target_ipv4": self.target_ipv4,
            "dialect": self.dialect,
            "signing_enabled": self.signing_enabled,
            "signing_required": self.signing_required,
            "disposition": self.disposition,
            "collection_state": self.collection_state,
            "confirmed_vulnerability": self.confirmed_vulnerability,
            "limitations": list(self.limitations),
            "runtime_pinset_sha256": self.runtime_pinset_sha256,
            "evidence_sha256": self.evidence_sha256,
            "evidence_bytes": self.evidence_bytes,
        }


@dataclass(frozen=True, slots=True)
class LabPortcastObservation:
    """Typed PortCast identity that does not claim advisory prerequisites."""

    schema_version: int
    profile_id: str
    related_module_id: str
    target_id: str
    target_ipv4: str
    target_port: int
    product: str
    version: str
    ecosystem: str
    provenance: str
    disposition: str
    collection_state: str
    confirmed_vulnerability: bool
    limitations: tuple[str, ...]
    evidence_sha256: str
    evidence_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile_id": self.profile_id,
            "related_module_id": self.related_module_id,
            "target_id": self.target_id,
            "target_ipv4": self.target_ipv4,
            "target_port": self.target_port,
            "product": self.product,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "provenance": self.provenance,
            "disposition": self.disposition,
            "collection_state": self.collection_state,
            "confirmed_vulnerability": self.confirmed_vulnerability,
            "limitations": list(self.limitations),
            "evidence_sha256": self.evidence_sha256,
            "evidence_bytes": self.evidence_bytes,
        }


REVIEWED_KALI_PINSET: KaliRuntimeManifest | None = KaliRuntimeManifest(
    schema=1,
    nmap_package="7.98+dfsg-1kali1",
    files=tuple(
        RuntimeFilePin(path, digest)
        for path, digest in sorted(
            (
                ("/usr/bin/nmap", "ffe95fb194da6718cf46fc60c2149f07e8f39179c60a99ea671958b5bb1f7c18"),
                ("/usr/share/nmap/scripts/smb2-security-mode.nse", "525787a85b6def7f57406e4f9be59a965cc77dc8a1a508273c03a1328c8bedc8"),
                ("/usr/share/nmap/nselib/asn1.lua", "28c31e265dcb8c13ccb8defebb864cb52d6c56e1487d638dc3f24790493926dd"),
                ("/usr/share/nmap/nselib/base32.lua", "c25da1d0dc0d25b8780efbb8d0849fa9936762e4249fdbfe37e74594bbd872c0"),
                ("/usr/share/nmap/nselib/datetime.lua", "df366d1a7d46fe35d61fc800453348be9f107c013832d389c4c74dce49faeac9"),
                ("/usr/share/nmap/nselib/dns.lua", "3bf131bcdd81f2fabfd2bfade69b54e5f5849b910436f89c18e8ccf50c399717"),
                ("/usr/share/nmap/nselib/ipOps.lua", "46e930df8413c5e35c11213e2d08ff2ef1c448ee2044b2f8bdabb7ac63c7fabf"),
                ("/usr/share/nmap/nselib/listop.lua", "db44d68f87600fa22856c7dc5c9ab082bad94d2180d55f89cb614d429d3cc665"),
                ("/usr/share/nmap/nselib/netbios.lua", "6df1ed42d82d5a016816a7179cc8d99f827e7eb90c702835ad61f254abf7fc0f"),
                ("/usr/share/nmap/nselib/nsedebug.lua", "a668fedcc46c7f723ac24dd7c046193eae2e77aae7130ab17963f79cf65ad548"),
                ("/usr/share/nmap/nselib/smb.lua", "262e47edcfdcee5e23b706b459fac9bd16bef1a5c6ba6b86427de84df9cf625b"),
                ("/usr/share/nmap/nselib/smb2.lua", "24c34c861200122cf6a1cef6c98996e969af5e1cf028d7cf50619ce3a21001e3"),
                ("/usr/share/nmap/nselib/smbauth.lua", "8fbedb07ede517ddfeea00386ad03b17ee24c6969a7cfbe1734e2faa9dfe96ac"),
                ("/usr/share/nmap/nselib/stdnse.lua", "ed971dc54a91fc9084c96d3a46aca1163eee2aeb8e5cd194eb8ab3c2e601684b"),
                ("/usr/share/nmap/nselib/strict.lua", "d397b66faf4aee8e2310d4d6d4ae957040e4ca048e05ebe8355ad83f55dc97e7"),
                ("/usr/share/nmap/nselib/stringaux.lua", "f1ff333e1fc978a234d797115c4849011bdedc105c54e050698f5deca3440a19"),
                ("/usr/share/nmap/nselib/tableaux.lua", "d1fd46b655c1044eff39090cb13cfda8230d439a4e68727c7023901ca8fc2cd8"),
                ("/usr/share/nmap/nselib/unicode.lua", "6cbd9b01727482f520753b49ab7f475c2796a59e54d0dc5e31297838bf7b0af8"),
                ("/usr/share/nmap/nselib/unittest.lua", "09b7ad3f1977981def8997b221a06ca7e0b0a484970921b7a74d97c026da2776"),
            )
        )
    ),
)

# Exact target-silent inventory collected from the dedicated CPTC11 Kali
# operator VM. Any package, host identity, command, or required-file drift
# blocks the PortCast channel-policy preflight before ``sshd -T`` is invoked.
CPTC11_KALI_OPENSSH_PRE_RELAY_PINSET = OpenSshRuntimeManifest(
    schema=2,
    hostname="cptc11-export-t1-vdi-kali01",
    machine_id_sha256=(
        "243500f5ca4683df06f22561458dd7e63"
        "f7b10aa1ef5a6660cf42983285f3915"
    ),
    packages=tuple(
        RuntimePackagePin(name, version)
        for name, version in (
            ("bash", "5.3-2"),
            ("coreutils", "9.7-3"),
            ("dpkg", "1.23.5+kali1"),
            ("gawk", "1:5.3.2-1"),
            ("hostname", "3.25"),
            ("openssh-server", "1:10.2p1-5"),
            ("systemd", "259.1-1"),
        )
    ),
    files=tuple(
        RuntimeFilePin(path, digest)
        for path, digest in sorted(
            (
                (
                    "/bin/bash",
                    "e6537d192a330c2788b9a1f8ed2df3b254fbda57cb7e54b0d5a3dcf67dc8c884",
                ),
                (
                    "/bin/hostname",
                    "a9f8d0b870f2184ac9f51fc21d7951a8543349cffdc8cd6904c23d2485682220",
                ),
                (
                    "/bin/sh",
                    "a6f559e00b69a4aa4d8cb607be18d9386c5aee55c509e2c075549dcf00e00fc7",
                ),
                (
                    "/etc/ssh/sshd_config",
                    "1df28dc31327abbbdae794aa4ac46b25b2efff10658a1c46ee9e4f53e46def24",
                ),
                (
                    "/usr/bin/awk",
                    "16b48c0812cc16ac615eff1926b62ef77da4d24b32cf8a18fe6e276741c0b3b8",
                ),
                (
                    "/usr/bin/chmod",
                    "7e37f672db75ae783260e7565d26218d25cebbc5a6d61118284c9719d246a90e",
                ),
                (
                    "/usr/bin/chown",
                    "22538ede9a6532d7c5db3c67c73bbcd68adc44a1ac99e09a2d739282aebff1ca",
                ),
                (
                    "/usr/bin/dpkg-query",
                    "f7f3103accd619f3dff78122c0f0b582d68edd3a692a19d23b51a3227a8d2ba5",
                ),
                (
                    "/usr/bin/install",
                    "daa4c9bda9ae0ebc3c778b7778c2634d85674690673facea20f6984b976f4e91",
                ),
                (
                    "/usr/bin/mkdir",
                    "bd3d9b36a1cc1c63b8dca7967003f4e5b0bb8556c87cbb7c1916aa358bf3f053",
                ),
                (
                    "/usr/bin/mktemp",
                    "61f09af83b1ccbd744d424ba5ad19b2af4edb5ad67c367cc092f58422b7bbb7c",
                ),
                (
                    "/usr/bin/mv",
                    "7db4661c6397fe5fd5ba6837692aa5adb7dce1efc656369d7b08dfd6ece525a0",
                ),
                (
                    "/usr/bin/rm",
                    "c959a237e7b95d229eea44764b2246fcb61a95dc679a10ad0cc97ad84c2316c1",
                ),
                (
                    "/usr/bin/sha256sum",
                    "89f8c1d1ba3c76138f3771e1a91e2796ade6180b1c1e4258c04698ff32787c97",
                ),
                (
                    "/usr/bin/sync",
                    "cbf7bb37ba1849b687c87d4fd3195312bc1bd8aa6221e70b22f8a5c5cf57a105",
                ),
                (
                    "/usr/bin/systemctl",
                    "478fe28680dab18f4a70eb50ba03edf5da3c4cb0b329d6f09b59ec1b4b6bec40",
                ),
                (
                    "/usr/sbin/sshd",
                    "e0f0341fe7b33a0802fc023b58c0c39d7486c13b5e3cc18813bf8bc2d48265b2",
                ),
                (
                    "/usr/share/doc/bash/copyright",
                    "06319d84c3e5ed096036f6a9310a030c7e84e50dff2b8a6792285c83ec0ada73",
                ),
                (
                    "/usr/share/doc/coreutils/copyright",
                    "3a63d4b11a7ba4c1c17175072ea28e07b0f80c7bc1ca042b27431fe65a14755b",
                ),
                (
                    "/usr/share/doc/dpkg/copyright",
                    "3376ec6f7bebf6b1e55da9d5dc591c73e752b45dccb0488e8365d2cf216a1746",
                ),
                (
                    "/usr/share/doc/gawk/copyright",
                    "4d8bd683c14ce5e3f68094a56892ecd336524e9977b6cfd3eb22ef835d67f367",
                ),
                (
                    "/usr/share/doc/hostname/copyright",
                    "94189fc5a9a7b7224d96e1a0cfdfe9be0df2018b04bf21d591627ab96b30cad1",
                ),
                (
                    "/usr/share/doc/openssh-server/copyright",
                    "af946edbe423f2af7cb2297e68ed177748461b3c8ecee9884ea087bea7b06f92",
                ),
                (
                    "/usr/share/doc/systemd/copyright",
                    "0fff813dc14e7c0a6d2bfba748ed17485fedb768b7fc9702b15261e81cfd357f",
                ),
            )
        )
    ),
    sshd_fragments=(
        RuntimeFilePin(
            "/etc/ssh/sshd_config.d/20-systemd-userdb.conf",
            "d9accafa92bfec25801224015ac1ffbf52bb1649a656779ada3cd502da7feba3",
        ),
    ),
    service_unit=RuntimeFilePin(
        "/usr/lib/systemd/system/ssh.service",
        "1e3c11483cc51a6c7aa3ab92affa43a313cab65e9721a64ce7720404cf6de1c8",
    ),
    service_dropins=(),
)
CPTC11_KALI_OPENSSH_PINSET = replace(
    CPTC11_KALI_OPENSSH_PRE_RELAY_PINSET,
    sshd_fragments=tuple(
        sorted(
            CPTC11_KALI_OPENSSH_PRE_RELAY_PINSET.sshd_fragments
            + (
                RuntimeFilePin(
                    "/etc/ssh/sshd_config.d/70-harbinger-portcast.conf",
                    "0bbce970017f0aba4c44de79acd8426f95c9b3b6a105a116f24a3902d6462a3d",
                ),
            ),
            key=lambda pin: pin.path,
        )
    ),
)
REVIEWED_OPENSSH_PINSET: OpenSshRuntimeManifest | None = CPTC11_KALI_OPENSSH_PINSET


def build_lab_smb_observation(xml: bytes) -> LabSmbObservation:
    """Validate one saved DC scan while retaining its unmetered limitation."""

    if REVIEWED_KALI_PINSET is None:
        raise PreflightRejected("reviewed Kali pinset is unavailable")
    facts = parse_smb2_xml_facts(xml, target_ipv4="10.0.1.6")
    return LabSmbObservation(
        schema_version=1,
        profile_id="lab.cptc11.kali.nmap_smb2_security_mode.v1",
        related_check_id="network.nse_smb2_security_mode",
        target_id="cptc11-prod-apt-dc-01",
        target_ipv4=facts.target_ipv4,
        dialect=facts.dialect,
        signing_enabled=facts.signing_enabled,
        signing_required=facts.signing_required,
        disposition="not_observed" if facts.signing_required else "observed_candidate",
        collection_state="unmetered_lab_acceptance",
        confirmed_vulnerability=False,
        limitations=(
            "network_request_accounting_unavailable",
            "production_profile_not_admitted",
        ),
        runtime_pinset_sha256=REVIEWED_KALI_PINSET.sha256,
        evidence_sha256=hashlib.sha256(xml).hexdigest(),
        evidence_bytes=len(xml),
    )


def build_lab_portcast_observation(
    body: bytes, *, receipt: Mapping[str, Any]
) -> LabPortcastObservation:
    """Validate saved synthetic or independently collected PortCast evidence."""

    identity = validate_portcast_identity_response(body, receipt=receipt)
    profile = get_portcast_profile(PORTCAST_PROFILE_ID)
    return LabPortcastObservation(
        schema_version=1,
        profile_id=profile.profile_id,
        related_module_id=profile.module_id,
        target_id=identity.target_id,
        target_ipv4=profile.target_ipv4,
        target_port=profile.target_port,
        product=identity.product,
        version=identity.version,
        ecosystem=identity.ecosystem,
        provenance=identity.provenance,
        disposition="candidate_identity",
        collection_state="unmetered_lab_acceptance",
        confirmed_vulnerability=False,
        limitations=(
            "network_request_accounting_unavailable",
            "production_profile_not_admitted",
            "manual_prerequisite_review_required",
        ),
        evidence_sha256=hashlib.sha256(body).hexdigest(),
        evidence_bytes=len(body),
    )


def _argv_sha256(argv: tuple[str, ...]) -> str:
    encoded = json.dumps(list(argv), separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _runtime_pin(path: str, digest: str) -> RuntimeFilePin:
    if not path.startswith("/") or "//" in path or "/../" in path or path.endswith("/.."):
        raise PreflightRejected("Kali runtime path is not canonical")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise PreflightRejected("Kali runtime digest is invalid")
    return RuntimeFilePin(path, digest)


def parse_kali_runtime_manifest(raw: bytes) -> KaliRuntimeManifest:
    """Parse the bounded, fixed inventory protocol without accepting free-form fields."""

    if type(raw) is not bytes or not 0 < len(raw) <= _OUTPUT_CAP:
        raise PreflightRejected("Kali runtime inventory exceeds its capture allowance")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise PreflightRejected("Kali runtime inventory is not UTF-8") from None
    if "\r" in text or "\x00" in text or not text.endswith("\n"):
        raise PreflightRejected("Kali runtime inventory framing is invalid")
    lines = text.splitlines()
    if len(lines) < 3 or lines[0] != "HARBINGER_KALI_RUNTIME_V1":
        raise PreflightRejected("Kali runtime inventory schema is invalid")
    scalars: dict[str, str] = {}
    files: list[RuntimeFilePin] = []
    seen_paths: set[str] = set()
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) == 2 and fields[0] == "nmap_package":
            key, value = fields
            if key in scalars or not value or len(value) > 128:
                raise PreflightRejected("Kali runtime scalar is duplicate or invalid")
            scalars[key] = value
            continue
        if len(fields) == 3 and fields[0] == "file":
            _kind, path, digest = fields
            if path in seen_paths:
                raise PreflightRejected("Kali runtime path is duplicate")
            seen_paths.add(path)
            pin = _runtime_pin(path, digest)
            files.append(pin)
            continue
        raise PreflightRejected("Kali runtime inventory contains an unknown field")
    if set(scalars) != {"nmap_package"}:
        raise PreflightRejected("Kali runtime scalar is missing")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}", scalars["nmap_package"]):
        raise PreflightRejected("Kali Nmap package revision is invalid")
    file_paths = {pin.path for pin in files}
    if file_paths != set(KALI_REQUIRED_FILE_PATHS):
        raise PreflightRejected("Kali runtime required file set differs")
    return KaliRuntimeManifest(
        schema=1,
        nmap_package=scalars["nmap_package"],
        files=tuple(sorted(files, key=lambda pin: pin.path)),
    )


def parse_openssh_runtime_manifest(raw: bytes) -> OpenSshRuntimeManifest:
    """Parse only the fixed OpenSSH package and file identity protocol."""

    if type(raw) is not bytes or not 0 < len(raw) <= _OUTPUT_CAP:
        raise PreflightRejected("Kali OpenSSH inventory exceeds its capture allowance")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise PreflightRejected("Kali OpenSSH inventory is not UTF-8") from None
    if "\r" in text or "\x00" in text or not text.endswith("\n"):
        raise PreflightRejected("Kali OpenSSH inventory framing is invalid")
    lines = text.splitlines()
    if (
        len(lines) < 8
        or lines[0] != "HARBINGER_KALI_OPENSSH_RUNTIME_V2"
        or lines[-1] != "HARBINGER_KALI_OPENSSH_RUNTIME_END_V2"
    ):
        raise PreflightRejected("Kali OpenSSH inventory schema is invalid")
    scalars: dict[str, str] = {}
    packages: list[RuntimePackagePin] = []
    seen_packages: set[str] = set()
    files: list[RuntimeFilePin] = []
    seen_paths: set[str] = set()
    sshd_fragments: list[RuntimeFilePin] = []
    service_units: list[RuntimeFilePin] = []
    service_dropins: list[RuntimeFilePin] = []
    seen_dynamic_paths: set[str] = set()
    for line in lines[1:-1]:
        fields = line.split("\t")
        if len(fields) == 2 and fields[0] in {"hostname", "machine_id_sha256"}:
            key, value = fields
            if key in scalars or not value or len(value) > 128:
                raise PreflightRejected("Kali OpenSSH scalar is duplicate or invalid")
            scalars[key] = value
            continue
        if len(fields) == 3 and fields[0] == "package":
            _kind, name, version = fields
            if (
                name in seen_packages
                or name not in KALI_OPENSSH_REQUIRED_PACKAGES
                or not version
                or len(version) > 128
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}", version) is None
            ):
                raise PreflightRejected("Kali OpenSSH package pin is invalid")
            seen_packages.add(name)
            packages.append(RuntimePackagePin(name, version))
            continue
        if len(fields) == 3 and fields[0] == "file":
            _kind, path, digest = fields
            if path in seen_paths:
                raise PreflightRejected("Kali OpenSSH path is duplicate")
            seen_paths.add(path)
            files.append(_runtime_pin(path, digest))
            continue
        if len(fields) == 3 and fields[0] in {
            "sshd_fragment", "service_unit", "service_dropin"
        }:
            kind, path, digest = fields
            if path in seen_dynamic_paths or path in seen_paths:
                raise PreflightRejected("Kali OpenSSH dynamic path is duplicate")
            if kind == "sshd_fragment":
                valid_path = re.fullmatch(
                    r"/etc/ssh/sshd_config[.]d/[A-Za-z0-9_.-]+[.]conf", path
                )
                destination = sshd_fragments
            elif kind == "service_unit":
                valid_path = re.fullmatch(
                    r"/(?:usr/lib|lib|etc|run)/systemd/system/[A-Za-z0-9@_.:-]+",
                    path,
                )
                destination = service_units
            else:
                valid_path = re.fullmatch(
                    r"/(?:usr/lib|lib|etc|run)/systemd/system/ssh[.]service[.]d/"
                    r"[A-Za-z0-9@_.:-]+[.]conf",
                    path,
                )
                destination = service_dropins
            if valid_path is None:
                raise PreflightRejected("Kali OpenSSH dynamic path is outside its root")
            seen_dynamic_paths.add(path)
            destination.append(_runtime_pin(path, digest))
            continue
        raise PreflightRejected("Kali OpenSSH inventory contains an unknown field")
    if set(scalars) != {"hostname", "machine_id_sha256"}:
        raise PreflightRejected("Kali OpenSSH scalar is missing")
    if seen_packages != set(KALI_OPENSSH_REQUIRED_PACKAGES):
        raise PreflightRejected("Kali OpenSSH package set differs")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", scalars["hostname"]):
        raise PreflightRejected("Kali hostname is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", scalars["machine_id_sha256"]):
        raise PreflightRejected("Kali machine identity hash is invalid")
    if {pin.path for pin in files} != set(KALI_OPENSSH_REQUIRED_FILE_PATHS):
        raise PreflightRejected("Kali OpenSSH required file set differs")
    if len(service_units) != 1:
        raise PreflightRejected("Kali OpenSSH service unit set differs")
    return OpenSshRuntimeManifest(
        schema=2,
        hostname=scalars["hostname"],
        machine_id_sha256=scalars["machine_id_sha256"],
        packages=tuple(sorted(packages, key=lambda pin: pin.name)),
        files=tuple(sorted(files, key=lambda pin: pin.path)),
        sshd_fragments=tuple(sorted(sshd_fragments, key=lambda pin: pin.path)),
        service_unit=service_units[0],
        service_dropins=tuple(sorted(service_dropins, key=lambda pin: pin.path)),
    )


def parse_portcast_relay_policy(raw: bytes) -> bool:
    """Accept only the fixed marker from the effective OpenSSH policy check."""

    if raw != b"HARBINGER_PORTCAST_RELAY_POLICY_V1\n":
        raise PreflightRejected("Kali PortCast forwarding policy is not enforced")
    return True


@dataclass(frozen=True, slots=True)
class CommandOutput:
    stdout: bytes
    stderr: bytes = b""
    status: int = 0
    capture_complete: bool = True
    stdout_total_bytes: int = 0
    stderr_total_bytes: int = 0


class RunDirectory:
    """One private, timestamped artifact directory for a live invocation."""

    def __init__(
        self, path: Path, stream: TextIO, encryptor: EvidenceEncryptor | None
    ) -> None:
        self.path = path
        self.transcript_path = path / "transcript.jsonl"
        self._stream = stream
        self._encryptor = encryptor
        self._command_occurrences: dict[str, int] = {}
        self.transcript = JsonlTranscript(stream)

    def _sync_directory(self) -> None:
        descriptor = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def reserve_target_action(
        self, *, template: str, target: str, runtime_pinset_sha256: str
    ) -> None:
        """Persist exact intent and allocate every target-derived artifact before dispatch."""

        if self._encryptor is None:
            raise TransportError("scan requires an encrypted durable run directory")
        if template != "dc-smb-security" or target != "10.0.1.6":
            raise ValueError("target action reservation is outside the fixed lab profile")
        intent = {
            "runtime_pinset_sha256": runtime_pinset_sha256,
            "schema": "cptc11-lab-action-intent-v1",
            "target": target,
            "template": template,
        }
        encoded = (json.dumps(intent, sort_keys=True, separators=(",", ":")) + "\n").encode()
        intent_path = self.path / "dc-smb-security.intent.json"
        created: list[Path] = []
        try:
            descriptor = os.open(intent_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            created.append(intent_path)
            for name in _TARGET_PENDING_ARTIFACTS:
                path = self.path / name
                descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                created.append(path)
                try:
                    os.posix_fallocate(descriptor, 0, _ENCRYPTED_ARTIFACT_RESERVATION)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            self._sync_directory()
        except (OSError, TransportError) as error:
            for path in reversed(created):
                if path.name.endswith(".pending"):
                    try:
                        path.unlink()
                    except FileNotFoundError:
                        pass
            self._sync_directory()
            self.transcript.emit(
                "action.reserve", phase=template, target=target, status="failed",
                reason=type(error).__name__,
            )
            raise TransportError("could not reserve target evidence storage") from error
        self.transcript.emit(
            "action.reserve", phase=template, target=target, status="passed",
            bytes=_ENCRYPTED_ARTIFACT_RESERVATION * len(_TARGET_PENDING_ARTIFACTS),
        )

    def reserve_portcast_action(self) -> None:
        """Reserve distinct PortCast artifacts without dispatching the candidate."""

        if self._encryptor is None:
            raise TransportError("scan requires an encrypted durable run directory")
        intent = {
            "profile_id": PORTCAST_PROFILE_ID,
            "schema": "cptc11-lab-action-intent-v1",
            "target": "10.0.1.30:8096",
            "template": "portcast-identity",
        }
        encoded = (json.dumps(intent, sort_keys=True, separators=(",", ":")) + "\n").encode()
        intent_path = self.path / "portcast-identity.intent.json"
        created: list[Path] = []
        try:
            descriptor = os.open(intent_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            created.append(intent_path)
            for name in _PORTCAST_PENDING_ARTIFACTS:
                path = self.path / name
                descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                created.append(path)
                try:
                    os.posix_fallocate(descriptor, 0, _ENCRYPTED_ARTIFACT_RESERVATION)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            self._sync_directory()
        except OSError as error:
            for path in reversed(created):
                if path.name.endswith(".pending"):
                    try:
                        path.unlink()
                    except FileNotFoundError:
                        pass
            self._sync_directory()
            self.transcript.emit(
                "action.reserve", phase="portcast-identity", target="10.0.1.30",
                status="failed", reason=type(error).__name__,
            )
            raise TransportError("could not reserve target evidence storage") from error
        self.transcript.emit(
            "action.reserve", phase="portcast-identity", target="10.0.1.30",
            status="passed",
            bytes=_ENCRYPTED_ARTIFACT_RESERVATION * len(_PORTCAST_PENDING_ARTIFACTS),
        )

    def _store_reserved_target_artifact(self, name: str, payload: bytes) -> None:
        pending = self.path / f"{name}.pending"
        destination = self.path / name
        if not pending.is_file() or destination.exists():
            raise TransportError("target evidence storage was not reserved")
        if len(payload) > _ENCRYPTED_ARTIFACT_RESERVATION:
            raise TransportError("encrypted target evidence exceeded its reservation")
        descriptor = os.open(pending, os.O_WRONLY)
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            written = 0
            while written < len(payload):
                written += os.write(descriptor, payload[written:])
            os.ftruncate(descriptor, len(payload))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(pending, destination)
        self._sync_directory()

    @classmethod
    def create(
        cls, root: Path, *, encryptor: EvidenceEncryptor | None = None
    ) -> "RunDirectory":
        root = root.expanduser().resolve()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ-")
        path = Path(tempfile.mkdtemp(prefix=stamp, dir=root))
        path.chmod(0o700)
        transcript_path = path / "transcript.jsonl"
        fd = os.open(transcript_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        stream = os.fdopen(fd, "w", encoding="utf-8")
        return cls(path, stream, encryptor)

    def store_command(self, label: str, stdout: bytes, stderr: bytes) -> None:
        if label not in {
            "inventory",
            "openssh-inventory",
            "openssh-policy",
            "openssh-relay-apply",
            "openssh-relay-rollback",
            "dc-smb-security",
            "portcast-identity",
        }:
            raise ValueError("artifact label is not allowlisted")
        if len(stdout) > _OUTPUT_CAP or len(stderr) > _OUTPUT_CAP:
            self.transcript.emit(
                "artifact.store", phase=label, status="failed", reason="capture_allowance"
            )
            raise TransportError("command output exceeded the capture allowance")
        sensitive = label in {"dc-smb-security", "portcast-identity"}
        if sensitive and self._encryptor is None:
            self.transcript.emit(
                "artifact.store", phase=label, status="failed", reason="encryption-unavailable"
            )
            raise TransportError("target evidence encryption is unavailable")
        occurrence = self._command_occurrences.get(label, 0) + 1
        self._command_occurrences[label] = occurrence
        if sensitive and occurrence != 1:
            raise TransportError("duplicate target command capture is forbidden")
        stem = label if occurrence == 1 else f"{label}.{occurrence}"
        payloads = tuple(
            (
                suffix,
                self._encryptor.encrypt(data) if sensitive and self._encryptor is not None else data,
            )
            for suffix, data in (("stdout", stdout), ("stderr", stderr))
        )
        for suffix, payload in payloads:
            extension = f".{suffix}.age" if sensitive else f".{suffix}"
            name = f"{label}{extension}" if sensitive else f"{stem}{extension}"
            if sensitive:
                self._store_reserved_target_artifact(name, payload)
            else:
                destination = self.path / name
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
        self._sync_directory()
        self.transcript.emit(
            "artifact.store",
            phase=label,
            status="passed",
            artifact_occurrence=occurrence,
            bytes=min(len(stdout), _OUTPUT_CAP) + min(len(stderr), _OUTPUT_CAP),
        )

    def store_typed_observation(self, observation: LabSmbObservation) -> None:
        encoded = (
            json.dumps(observation.to_dict(), sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        if len(encoded) > _OUTPUT_CAP:
            raise TransportError("typed observation exceeded the capture allowance")
        if self._encryptor is None:
            raise TransportError("typed target evidence encryption is unavailable")
        payload = self._encryptor.encrypt(encoded)
        self._store_reserved_target_artifact("dc-smb-security.typed.json.age", payload)
        self.transcript.emit(
            "artifact.store", phase="dc-smb-security.typed", status="passed",
            bytes=len(encoded),
        )

    def store_portcast_typed_observation(self, observation: LabPortcastObservation) -> None:
        encoded = (
            json.dumps(observation.to_dict(), sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        if len(encoded) > _OUTPUT_CAP:
            raise TransportError("typed observation exceeded the capture allowance")
        if self._encryptor is None:
            raise TransportError("typed target evidence encryption is unavailable")
        payload = self._encryptor.encrypt(encoded)
        self._store_reserved_target_artifact("portcast-identity.typed.json.age", payload)
        self.transcript.emit(
            "artifact.store", phase="portcast-identity.typed", status="passed",
            bytes=len(encoded),
        )

    def close(self) -> None:
        if not self._stream.closed:
            self._stream.close()


def main(
    argv: list[str] | None = None,
    *,
    connector: "Connector | None" = None,
    stdout: TextIO | None = None,
    encryptor: EvidenceEncryptor | None = None,
    portcast_session_runner: Callable[..., dict[str, Any]] | None = None,
) -> int:
    """Run preflight or one exact frozen lab action through reviewed entrypoints."""

    parser = argparse.ArgumentParser(prog="cptc11-lab-transport")
    parser.add_argument(
        "command",
        choices=("preflight", "preflight-portcast", "scan-dc", "scan-portcast"),
    )
    parser.add_argument(
        "--run-root",
        type=Path,
        default=Path("~/.local/state/harbinger/cptc11").expanduser(),
    )
    args = parser.parse_args(argv)
    destination = stdout or sys.stdout
    if args.command in {"scan-dc", "scan-portcast"} and encryptor is None:
        encryptor = AgeEncryptor.default()
    run = RunDirectory.create(args.run_root, encryptor=encryptor)
    status = "failed"
    exit_code = 1
    portcast_result: dict[str, Any] | None = None
    try:
        if args.command == "scan-portcast":
            if portcast_session_runner is None:
                from .portcast_live import run_frozen_portcast_session

                portcast_session_runner = run_frozen_portcast_session
            value = portcast_session_runner()
            portcast_result = _validate_portcast_cli_result(value)
            execution = portcast_result["execution"]
            counters = execution["transport_counters"] or {}
            run.transcript.emit(
                "profile.coordinator",
                phase="portcast-identity",
                status=portcast_result["status"],
                action_id=portcast_result["action_id"],
                audit_verified=portcast_result["audit_verified"],
                cleanup_status=portcast_result["cleanup_status"],
                receipt_outcome=portcast_result["receipt_outcome"],
                automatic_retry=False,
                reservation_state=execution["reservation_state"],
                attempt_count=execution["attempt_count"],
                attempt_state=execution["attempt_state"],
                failure_stage=execution["failure_stage"],
                wire_counters_verified=execution["wire_counters_verified"],
                result_receipt_present=execution["result_receipt_present"],
                **counters,
            )
            if not (
                portcast_result["status"] == "complete"
                and portcast_result["audit_verified"] is True
                and portcast_result["cleanup_status"] == "passed"
                and portcast_result["receipt_outcome"] == "complete"
            ):
                raise TransportError("frozen PortCast action did not complete cleanly")
        else:
            session_options = (
                {"connector": connector, "transcript": run.transcript}
                if args.command == "preflight-portcast"
                else {"connector": connector, "run_directory": run}
            )
            with LabSession(**session_options) as session:
                if args.command == "preflight":
                    session.preflight_inventory()
                elif args.command == "preflight-portcast":
                    session.preflight_portcast_inventory()
                    session.verify_portcast_alternate_destination_denied()
                else:
                    session.preflight_inventory()
                    captured = session.run_scan("dc-smb-security", "10.0.1.6")
                    run.store_typed_observation(build_lab_smb_observation(captured))
        status = "passed"
        exit_code = 0
    except BaseException as error:
        run.transcript.emit(
            "cli.finish", phase=args.command, status="failed", reason=type(error).__name__
        )
    finally:
        if exit_code == 0:
            run.transcript.emit("cli.finish", phase=args.command, status="passed")
        run.close()
    output = {
        "command": args.command,
        "run_directory": str(run.path),
        "status": status,
    }
    if portcast_result is not None:
        output.update(
            {
                "action_id": portcast_result["action_id"],
                "cleanup_status": portcast_result["cleanup_status"],
                "receipt_outcome": portcast_result["receipt_outcome"],
                "execution": portcast_result["execution"],
            }
        )
    print(json.dumps(output, sort_keys=True), file=destination)
    return exit_code


def _validate_portcast_cli_result(value: Any) -> dict[str, Any]:
    """Select metadata-only coordinator fields for transcript and stdout."""

    try:
        validated = validate_portcast_result_v6(value)
    except PolicyError:
        raise TransportError("PortCast coordinator returned invalid metadata")
    if validated["profile_id"] != PORTCAST_PROFILE_ID:
        raise TransportError("PortCast coordinator returned invalid metadata")
    # Older service responses did not carry the fixed diagnostic stage. Keep
    # accepting them, but give the operator CLI one stable metadata shape.
    validated = dict(validated)
    validated["execution"] = dict(validated["execution"])
    validated["execution"].setdefault("failure_stage", None)
    return validated


class Transcript(Protocol):
    def emit(self, event: str, **metadata: Any) -> None: ...


class NullTranscript:
    def emit(self, event: str, **metadata: Any) -> None:
        return None


class JsonlTranscript:
    """Thread-safe UTC JSONL events with a metadata-only field allowlist."""

    _SAFE_FIELDS = frozenset(
        {
            "bytes",
            "artifact_occurrence",
            "duration_ms",
            "hop",
            "phase",
            "reason",
            "status",
            "target",
            "template",
            "capture_complete",
            "stderr_bytes",
            "stdout_bytes",
            "action_id",
            "audit_verified",
            "automatic_retry",
            "cleanup_status",
            "receipt_outcome",
            "reservation_state",
            "attempt_count",
            "attempt_state",
            "failure_stage",
            "wire_counters_verified",
            "result_receipt_present",
            "tcp_connects",
            "udp_datagrams",
            "protocol_requests",
            "tx_bytes",
            "rx_bytes",
        }
    )

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream
        self._lock = threading.Lock()
        self._sequence = 0

    def emit(self, event: str, **metadata: Any) -> None:
        with self._lock:
            self._sequence += 1
            record: dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
                    "+00:00", "Z"
                ),
                "monotonic_ns": time.monotonic_ns(),
                "sequence": self._sequence,
                "event_id": uuid.uuid4().hex,
                "event": event,
            }
            for key, value in metadata.items():
                if key in self._SAFE_FIELDS and isinstance(value, (str, int, float, bool, type(None))):
                    record[key] = value
            line = json.dumps(record, sort_keys=True, separators=(",", ":"))
            self._stream.write(line + "\n")
            self._stream.flush()
            try:
                os.fsync(self._stream.fileno())
            except (AttributeError, io.UnsupportedOperation, OSError):
                pass


class CredentialResolver(Protocol):
    def resolve(
        self, reference: EncryptedCredentialRef | ServiceCredentialRef
    ) -> str: ...


class SystemdCredentialResolver:
    """Decrypt a local blob to memory without placing secret data in argv."""

    def resolve(self, reference: EncryptedCredentialRef) -> str:
        if type(reference) is not EncryptedCredentialRef:
            raise TransportError("operator credential resolver rejected service reference")
        result = subprocess.run(
            (
                "/usr/bin/systemd-creds",
                "decrypt",
                "--user",
                f"--name={reference.credential_name}",
                str(reference.encrypted_path),
                "-",
            ),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if reference.secret_key is None:
            value = result.stdout.rstrip("\r\n")
        else:
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError as error:
                raise TransportError("decrypted credential blob is not JSON") from error
            value = payload.get(reference.secret_key) if isinstance(payload, dict) else None
        if not isinstance(value, str) or not value:
            raise TransportError("encrypted credential reference did not resolve")
        return value


class SealedCredentialResolver:
    """Resolve only the two inherited, sealed service credential descriptors."""

    def __init__(self, descriptors: tuple[int, int]) -> None:
        if len(descriptors) != 2:
            raise TransportError("service credential descriptor set differs")
        self._descriptors = {
            "cptc11-dell": descriptors[0],
            "cptc11-kali": descriptors[1],
        }

    def resolve(self, reference: ServiceCredentialRef) -> str:
        if type(reference) is not ServiceCredentialRef:
            raise TransportError("service credential resolver rejected operator reference")
        try:
            descriptor = self._descriptors[reference.credential_name]
            info = os.fstat(descriptor)
            if not 1 <= info.st_size <= 64 * 1024:
                raise OSError()
            value = os.pread(descriptor, info.st_size, 0)
        except (KeyError, OSError):
            raise TransportError("sealed service credential is unavailable") from None
        if len(value) != info.st_size or b"\x00" in value:
            raise TransportError("sealed service credential content differs")
        try:
            secret = value.decode("utf-8", "strict").rstrip("\r\n")
        except UnicodeDecodeError:
            raise TransportError("sealed service credential encoding differs") from None
        if not secret:
            raise TransportError("sealed service credential is empty")
        return secret


class Guardian(Protocol):
    def await_ready(self) -> None: ...
    def close(self) -> None: ...


class KaliConnection(Protocol):
    def execute(self, argv: tuple[str, ...]) -> bytes | CommandOutput: ...
    def verify_alternate_portcast_destination_denied(self) -> bool: ...
    def close(self) -> None: ...


class DellConnection(Protocol):
    def preflight(self, config: LabConfig) -> None: ...
    def start_guardian(self, script: str) -> Guardian: ...
    def open_kali(
        self,
        proxy_argv: tuple[str, ...],
        endpoint: SshEndpoint,
        credential: EncryptedCredentialRef | ServiceCredentialRef,
    ) -> KaliConnection: ...
    def close(self) -> None: ...


class Connector(Protocol):
    def connect(
        self,
        endpoint: SshEndpoint,
        credential: EncryptedCredentialRef,
        transcript: Transcript,
    ) -> DellConnection: ...


def _preflight_script(config: LabConfig) -> str:
    names = config.remote
    return f"""set -eu
test \"$(hostname)\" = dell-prox
command -v ip >/dev/null
command -v socat >/dev/null
command -v flock >/dev/null
command -v qm >/dev/null
command -v timedatectl >/dev/null
test "$(qm status 1101)" = "status: running"
vm_config=$(qm config 1101)
printf '%s\n' "$vm_config" | grep -Fx -- 'name: APT-DC-01' >/dev/null
! printf '%s\n' "$vm_config" | grep -q '^lock:'
test "$(qm status 1109)" = "status: running"
kali_config=$(qm config 1109)
printf '%s\n' "$kali_config" | grep -Fx -- 'name: kali01' >/dev/null
printf '%s\n' "$kali_config" | grep -Fx -- 'parent: cptc11_10_regional_clean' >/dev/null
printf '%s\n' "$kali_config" | grep -Fx -- 'net0: virtio=52:54:00:11:01:09,bridge=vmbr111' >/dev/null
! printf '%s\n' "$kali_config" | grep -q '^lock:'
kali_snapshots=$(qm listsnapshot 1109)
printf '%s\n' "$kali_snapshots" | awk '
  $1 != "`->" || NF < 2 {{ exit 1 }}
  $2 == "current" {{ current += 1; next }}
  $2 == "cptc11_00_imported_verified" {{ imported += 1; next }}
  $2 == "cptc11_10_regional_clean" {{ clean += 1; next }}
  {{ exit 1 }}
  END {{ if (current != 1 || imported != 1 || clean != 1) exit 1 }}
'
test "$(timedatectl show --property=NTPSynchronized --value)" = yes
available_bytes=$(df --output=avail -B1 /run | tail -n 1 | tr -d ' ')
test "$available_bytes" -ge 1048576
test -d /sys/class/net/{names.bridge}
! ip netns list | awk '{{print $1}}' | grep -Fx -- {names.namespace}
! ip link show dev {names.host_veth} >/dev/null 2>&1
! ip link show dev {names.namespace_veth} >/dev/null 2>&1
"""


def _guardian_script(config: LabConfig) -> str:
    names = config.remote
    return f"""set -Eeuo pipefail
exec 9>{names.lock_path}
flock -n 9 || {{ printf 'LOCKED\\n' >&2; exit 73; }}
owned=0
cleanup() {{
  if [ \"$owned\" -eq 1 ]; then
    ip link del {names.host_veth} >/dev/null 2>&1 || true
    ip netns del {names.namespace} >/dev/null 2>&1 || true
  fi
}}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
! ip netns list | awk '{{print $1}}' | grep -Fx -- {names.namespace}
! ip link show dev {names.host_veth} >/dev/null 2>&1
! ip link show dev {names.namespace_veth} >/dev/null 2>&1
ip netns add {names.namespace}
owned=1
ip link add {names.host_veth} type veth peer name {names.namespace_veth}
ip link set {names.host_veth} master {names.bridge}
ip link set {names.host_veth} up
ip link set {names.namespace_veth} netns {names.namespace}
ip -n {names.namespace} link set lo up
ip -n {names.namespace} link set {names.namespace_veth} up
ip -n {names.namespace} addr add 10.0.254.253/24 dev {names.namespace_veth}
printf 'READY\\n'
while IFS= read -r control; do
  [ \"$control\" = STOP ] && break
done
"""


def _proxy_argv(config: LabConfig) -> tuple[str, ...]:
    return (
        "ip",
        "netns",
        "exec",
        config.remote.namespace,
        "socat",
        "STDIO",
        f"TCP:{config.kali.host}:{config.kali.port}",
    )


class _ServicePortcastChannelProvider:
    """One fixed direct-tcpip opener held only by the service session."""

    __slots__ = ("_nested_transport", "_timeout_s")

    def __init__(self, nested_transport: Any, *, timeout_s: float) -> None:
        self._nested_transport = nested_transport
        self._timeout_s = timeout_s

    def open_portcast_channel(self):
        return self._nested_transport.open_channel(
            "direct-tcpip",
            ("10.0.1.30", 8096),
            ("127.0.0.1", 0),
            timeout=self._timeout_s,
        )


class LabSession:
    """Own the Dell, guardian, and nested Kali channels as one lifecycle."""

    def __init__(
        self,
        *,
        connector: Connector | None = None,
        config: LabConfig = DEFAULT_CONFIG,
        transcript: Transcript | None = None,
        run_directory: RunDirectory | None = None,
        _authority: object | None = None,
    ) -> None:
        operator_config = (
            config.dell != DEFAULT_CONFIG.dell
            or config.kali != DEFAULT_CONFIG.kali
            or config.dell_credential != DEFAULT_CONFIG.dell_credential
            or config.kali_credential != DEFAULT_CONFIG.kali_credential
            or config.remote != DEFAULT_CONFIG.remote
        )
        service_config = config == SERVICE_CONFIG and _authority is _SERVICE_SESSION_AUTHORITY
        if operator_config and not service_config:
            raise ValueError(
                "CPTC11 endpoints, pins, credential references, and remote names are pinned"
            )
        self.config = config
        self.run_directory = run_directory
        self.transcript = transcript or (
            run_directory.transcript if run_directory is not None else NullTranscript()
        )
        self.connector = connector or PinnedParamikoConnector()
        self._dell: DellConnection | None = None
        self._guardian: Guardian | None = None
        self._kali: KaliConnection | None = None
        self._runtime_manifest: KaliRuntimeManifest | None = None
        self._openssh_manifest: OpenSshRuntimeManifest | None = None
        self._service_session = service_config
        self._service_portcast_channel_provider: _ServicePortcastChannelProvider | None = None
        self._portcast_candidate_ready = False
        self._portcast_alternate_denied = False
        self._portcast_channel_used = False

    @classmethod
    def _for_portcast_service(cls, credential_fds: tuple[int, int]) -> "LabSession":
        resolver = SealedCredentialResolver(credential_fds)
        return cls(
            connector=PinnedParamikoConnector(resolver),
            config=SERVICE_CONFIG,
            _authority=_SERVICE_SESSION_AUTHORITY,
        )

    def open(self) -> None:
        if self._dell is not None:
            raise TransportError("lab session is already open")
        self._runtime_manifest = None
        self._openssh_manifest = None
        self._portcast_candidate_ready = False
        self._portcast_alternate_denied = False
        self._portcast_channel_used = False
        self._service_portcast_channel_provider = None
        self.transcript.emit("session.open", phase="dell", status="starting")
        try:
            self._dell = self.connector.connect(
                self.config.dell, self.config.dell_credential, self.transcript
            )
            self._dell.preflight(self.config)
            self.transcript.emit("preflight", phase="dell", status="passed")
            self._guardian = self._dell.start_guardian(_guardian_script(self.config))
            self._guardian.await_ready()
            self.transcript.emit("guardian", phase="vdi", status="ready")
            self._kali = self._dell.open_kali(
                _proxy_argv(self.config),
                self.config.kali,
                self.config.kali_credential,
            )
            if self._service_session:
                if type(self._kali) is not _ServiceParamikoKali:
                    raise TransportError("service Kali transport differs")
                self._service_portcast_channel_provider = (
                    self._kali._take_portcast_channel_provider()
                )
            self.transcript.emit("session.open", phase="kali", status="ready")
        except BaseException as error:
            self.transcript.emit(
                "session.open", phase="cleanup", status="failed", reason=type(error).__name__
            )
            self.close()
            raise

    def _execute_kali(self, argv: tuple[str, ...], artifact_label: str) -> bytes:
        assert self._kali is not None
        result = self._kali.execute(argv)
        output = result if isinstance(result, CommandOutput) else CommandOutput(
            result, stdout_total_bytes=len(result), stderr_total_bytes=0
        )
        if self.run_directory is not None:
            self.run_directory.store_command(artifact_label, output.stdout, output.stderr)
        if not output.capture_complete:
            self.transcript.emit(
                "capture.incomplete", phase=artifact_label, status="failed",
                stdout_bytes=output.stdout_total_bytes,
                stderr_bytes=output.stderr_total_bytes,
                capture_complete=False,
            )
            raise TransportError("remote command capture was incomplete")
        if output.status:
            raise TransportError(f"allowlisted remote command failed with rc={output.status}")
        return output.stdout

    def preflight_inventory(self) -> KaliRuntimeManifest:
        if self._kali is None:
            raise TransportError("lab session is not open")
        self._runtime_manifest = None
        self.transcript.emit(
            "inventory.start", phase="kali", template="inventory", status="running"
        )
        try:
            output = self._execute_kali(KALI_INVENTORY_ARGV, "inventory")
            manifest = parse_kali_runtime_manifest(output)
            if REVIEWED_KALI_PINSET is None or manifest != REVIEWED_KALI_PINSET:
                raise PreflightRejected("Kali runtime does not match the reviewed Kali runtime")
        except BaseException as error:
            self.transcript.emit(
                "inventory.finish",
                phase="kali",
                template="inventory",
                status="failed",
                reason=type(error).__name__,
            )
            raise
        self.transcript.emit(
            "inventory.finish",
            phase="kali",
            template="inventory",
            status="passed",
            bytes=min(len(output), _OUTPUT_CAP),
        )
        self._runtime_manifest = manifest
        return manifest

    def inspect_openssh_runtime(self) -> OpenSshRuntimeManifest:
        """Collect fixed Kali OpenSSH identity without invoking ``sshd``."""

        if self._kali is None:
            raise TransportError("lab session is not open")
        self._openssh_manifest = None
        output = self._execute_kali(
            KALI_OPENSSH_INVENTORY_ARGV,
            "openssh-inventory",
        )
        manifest = parse_openssh_runtime_manifest(output)
        self._openssh_manifest = manifest
        self.transcript.emit(
            "inventory.finish",
            phase="kali-openssh",
            template="openssh-inventory",
            status="passed",
            bytes=min(len(output), _OUTPUT_CAP),
        )
        return manifest

    def preflight_portcast_inventory(self):
        """Validate the immutable admitted profile without target traffic."""

        if self._kali is None:
            raise TransportError("lab session is not open")
        profile = get_portcast_profile(PORTCAST_PROFILE_ID)
        manifest = self.inspect_openssh_runtime()
        if REVIEWED_OPENSSH_PINSET is None or manifest != REVIEWED_OPENSSH_PINSET:
            raise PreflightRejected(
                "Kali OpenSSH runtime does not match the reviewed pinset"
            )
        parse_portcast_relay_policy(
            self._execute_kali(KALI_PORTCAST_RELAY_POLICY_ARGV, "openssh-policy")
        )
        self._portcast_candidate_ready = True
        self._portcast_alternate_denied = False
        self.transcript.emit(
            "inventory.finish", phase="portcast-profile",
            template="portcast-identity", status="passed",
        )
        return profile

    def verify_portcast_alternate_destination_denied(self) -> bool:
        """Prove the SSH server rejects one fixed Kali-local control channel."""

        if self._kali is None:
            raise TransportError("lab session is not open")
        if not self._portcast_candidate_ready:
            raise PreflightRejected(
                "alternate forwarding control requires a current-session preflight"
            )
        result = self._kali.verify_alternate_portcast_destination_denied()
        if result is not True:
            raise PreflightRejected("Kali SSH forwarding control was not denied")
        self._portcast_alternate_denied = True
        self.transcript.emit(
            "boundary.verify",
            phase="openssh-policy",
            target="kali-loopback:22",
            status="passed",
        )
        return True

    def _open_portcast_channel(self):
        """Open the single service-owned PortCast channel after local controls."""

        if (
            not self._service_session
            or type(self.config.dell_credential) is not ServiceCredentialRef
            or type(self.config.kali_credential) is not ServiceCredentialRef
            or self._kali is None
        ):
            raise PreflightRejected("PortCast channel requires the canonical service session")
        if self._portcast_channel_used:
            raise PreflightRejected("PortCast channel has one use")
        if not self._portcast_candidate_ready:
            raise PreflightRejected("PortCast channel requires a current-session preflight")
        if not self._portcast_alternate_denied:
            raise PreflightRejected("PortCast channel requires alternate destination control")
        provider = self._service_portcast_channel_provider
        if provider is None:
            raise PreflightRejected("PortCast service channel is unavailable")
        self._portcast_channel_used = True
        self._portcast_candidate_ready = False
        self._portcast_alternate_denied = False
        return provider.open_portcast_channel()

    def run_portcast_identity(self) -> bytes:
        """Refuse dispatch until a parent-owned exact wire receipt is admitted."""

        if self._kali is None:
            raise TransportError("lab session is not open")
        if not self._portcast_candidate_ready:
            raise PreflightRejected("PortCast candidate requires a current-session preflight")
        self._portcast_candidate_ready = False
        self.transcript.emit(
            "scan.rejected", target="10.0.1.30", template="portcast-identity",
            reason="wire-accounting",
        )
        raise PreflightRejected(
            "PortCast live dispatch requires trusted parent wire accounting"
        )

    def run_scan(self, template: str, target: str) -> bytes:
        if self._kali is None:
            raise TransportError("lab session is not open")
        if target not in ALLOWED_TARGETS:
            self.transcript.emit(
                "scan.rejected", target=target, template=template, reason="target"
            )
            raise TargetRejected(f"target is outside CPTC11 allowlist: {target}")
        argv = SCAN_TEMPLATES.get(template)
        if argv is None:
            self.transcript.emit(
                "scan.rejected", target=target, template=template, reason="template"
            )
            raise TemplateRejected(f"scanner template is not allowlisted: {template}")
        if target != "10.0.1.6" or argv != DC_SMB_SCAN_ARGV:
            self.transcript.emit(
                "scan.rejected", target=target, template=template, reason="first-scan-boundary"
            )
            raise TargetRejected("first live scan is restricted to the DC at 10.0.1.6")
        manifest = self._runtime_manifest
        if manifest is None or REVIEWED_KALI_PINSET is None or manifest != REVIEWED_KALI_PINSET:
            self.transcript.emit(
                "scan.rejected", target=target, template=template, reason="runtime-pin"
            )
            raise PreflightRejected("scan requires a reviewed current-session Kali preflight")
        self._runtime_manifest = None
        if self.run_directory is None:
            self.transcript.emit(
                "scan.rejected", target=target, template=template, reason="durable-evidence"
            )
            raise TransportError("scan requires an encrypted durable run directory")
        self.run_directory.reserve_target_action(
            template=template,
            target=target,
            runtime_pinset_sha256=manifest.sha256,
        )
        started = time.monotonic()
        self.transcript.emit("scan.start", target=target, template=template, status="running")
        try:
            output = self._execute_kali(argv, "dc-smb-security")
        except BaseException as error:
            self.transcript.emit(
                "scan.finish",
                target=target,
                template=template,
                status="failed",
                reason=type(error).__name__,
                duration_ms=round((time.monotonic() - started) * 1000),
            )
            raise
        self.transcript.emit(
            "scan.finish",
            target=target,
            template=template,
            status="passed",
            bytes=len(output),
            duration_ms=round((time.monotonic() - started) * 1000),
        )
        return output

    def close(self) -> None:
        self._runtime_manifest = None
        self._openssh_manifest = None
        self._service_portcast_channel_provider = None
        self._portcast_candidate_ready = False
        self._portcast_alternate_denied = False
        self._portcast_channel_used = False
        errors: list[BaseException] = []
        for resource_name in ("_kali", "_guardian", "_dell"):
            resource = getattr(self, resource_name)
            setattr(self, resource_name, None)
            if resource is not None:
                try:
                    resource.close()
                except BaseException as error:
                    errors.append(error)
        self.transcript.emit(
            "session.close", phase="cleanup", status="failed" if errors else "passed"
        )
        if errors:
            raise TransportError("one or more transport resources failed to close") from errors[0]

    def __enter__(self) -> "LabSession":
        self.open()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        try:
            self.close()
        except BaseException:
            if exc is None:
                raise


def _fingerprint(server_key: Any) -> str:
    digest = hashlib.sha256(server_key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _load_paramiko():
    try:
        import paramiko
    except ImportError as error:  # pragma: no cover - depends on operator host.
        raise TransportError("Paramiko is required for the live connector") from error
    return paramiko


def _read_channel(channel: Any, *, timeout: float = 30.0) -> CommandOutput:
    stdout = bytearray()
    stderr = bytearray()
    stdout_total = 0
    stderr_total = 0
    deadline = time.monotonic() + timeout
    while True:
        if channel.recv_ready():
            chunk = channel.recv(65536)
            stdout_total += len(chunk)
            remaining = _OUTPUT_CAP - len(stdout)
            if remaining > 0:
                stdout.extend(chunk[:remaining])
        if channel.recv_stderr_ready():
            chunk = channel.recv_stderr(65536)
            stderr_total += len(chunk)
            remaining = _OUTPUT_CAP - len(stderr)
            if remaining > 0:
                stderr.extend(chunk[:remaining])
        if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
            break
        if time.monotonic() >= deadline:
            channel.close()
            raise TransportError("remote command timed out")
        time.sleep(0.02)
    return CommandOutput(
        stdout=bytes(stdout), stderr=bytes(stderr), status=channel.recv_exit_status(),
        capture_complete=stdout_total <= _OUTPUT_CAP and stderr_total <= _OUTPUT_CAP,
        stdout_total_bytes=stdout_total, stderr_total_bytes=stderr_total,
    )


class PinnedParamikoConnector:
    """Production connector. Secrets move only through Paramiko auth calls."""

    def __init__(self, resolver: CredentialResolver | None = None) -> None:
        self._resolver = resolver or SystemdCredentialResolver()

    def connect(
        self,
        endpoint: SshEndpoint,
        credential: EncryptedCredentialRef | ServiceCredentialRef,
        transcript: Transcript,
    ) -> DellConnection:
        paramiko = _load_paramiko()
        secret = self._resolver.resolve(credential)
        try:
            sock = socket.create_connection((endpoint.host, endpoint.port), timeout=15)
        except BaseException:
            del secret
            raise
        transport = paramiko.Transport(sock)
        try:
            transport.banner_timeout = 20
            transport.auth_timeout = 20
            transport.start_client(timeout=20)
            if _fingerprint(transport.get_remote_server_key()) != endpoint.host_key_sha256:
                raise TransportError("Dell SSH host-key pin mismatch")
            try:
                transport.auth_password(endpoint.username, secret, fallback=False)
            finally:
                del secret
            if not transport.is_authenticated():
                raise TransportError("Dell SSH authentication failed")
            return _ParamikoDell(transport, self._resolver, transcript)
        except BaseException:
            transport.close()
            raise


class _ParamikoGuardian:
    def __init__(self, channel: Any) -> None:
        self._channel = channel
        self._closed = False

    def await_ready(self) -> None:
        deadline = time.monotonic() + 30
        data = bytearray()
        while b"\n" not in data:
            if self._channel.recv_ready():
                chunk = self._channel.recv(1024)
                if not chunk:
                    break
                data.extend(chunk)
            if self._channel.exit_status_ready():
                break
            if time.monotonic() >= deadline:
                raise TransportError("guardian readiness timed out")
            time.sleep(0.02)
        if data.splitlines()[:1] != [b"READY"]:
            raise PreflightRejected("guardian rejected lock or reserved remote names")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if not self._channel.closed:
                self._channel.sendall(b"STOP\n")
                deadline = time.monotonic() + 15
                while not self._channel.exit_status_ready() and time.monotonic() < deadline:
                    time.sleep(0.02)
        finally:
            self._channel.close()


class _ParamikoKali:
    def __init__(self, transport: Any, proxy_channel: Any) -> None:
        self._transport = transport
        self._proxy_channel = proxy_channel

    def execute(self, argv: tuple[str, ...]) -> CommandOutput:
        from .kali_portcast_relay import (
            KALI_PORTCAST_RELAY_APPLY_ARGV,
            KALI_PORTCAST_RELAY_ROLLBACK_ARGV,
        )

        if argv not in (
            KALI_INVENTORY_ARGV,
            KALI_OPENSSH_INVENTORY_ARGV,
            KALI_PORTCAST_RELAY_POLICY_ARGV,
            KALI_PORTCAST_RELAY_APPLY_ARGV,
            KALI_PORTCAST_RELAY_ROLLBACK_ARGV,
            DC_SMB_SCAN_ARGV,
        ):
            raise TemplateRejected("nested Kali command is not an exact allowlisted argv")
        channel = self._transport.open_session(timeout=20)
        try:
            channel.exec_command(shlex.join(argv))
            return _read_channel(channel)
        finally:
            channel.close()

    def verify_alternate_portcast_destination_denied(self) -> bool:
        """Request only Kali loopback SSH and require policy denial code 1."""

        paramiko = _load_paramiko()
        try:
            channel = self._transport.open_channel(
                "direct-tcpip",
                ("127.0.0.1", 22),
                ("127.0.0.1", 0),
                timeout=5,
            )
        except paramiko.ChannelException as error:
            if error.code == 1:
                return True
            raise PreflightRejected(
                "alternate forwarding failed for a reason other than policy denial"
            ) from error
        channel.close()
        raise PreflightRejected("alternate Kali forwarding destination was permitted")

    def close(self) -> None:
        try:
            self._transport.close()
        finally:
            self._proxy_channel.close()


class _ServiceParamikoKali(_ParamikoKali):
    """Nested Kali connection that transfers the fixed opener to its owner once."""

    def __init__(self, transport: Any, proxy_channel: Any) -> None:
        super().__init__(transport, proxy_channel)
        profile = get_portcast_profile(PORTCAST_PROFILE_ID)
        self._service_portcast_channel_provider: _ServicePortcastChannelProvider | None = (
            _ServicePortcastChannelProvider(
                transport,
                timeout_s=profile.budget.timeout_s,
            )
        )

    def _take_portcast_channel_provider(self) -> _ServicePortcastChannelProvider:
        provider = self._service_portcast_channel_provider
        if provider is None:
            raise TransportError("PortCast service channel provider is unavailable")
        self._service_portcast_channel_provider = None
        return provider


class _ParamikoDell:
    def __init__(
        self, transport: Any, resolver: CredentialResolver, transcript: Transcript
    ) -> None:
        self._transport = transport
        self._resolver = resolver
        self._transcript = transcript

    def _execute_script(self, script: str, *, timeout: float = 30) -> tuple[int, bytes, bytes]:
        channel = self._transport.open_session(timeout=15)
        try:
            channel.exec_command("/bin/sh -c " + shlex.quote(script))
            result = _read_channel(channel, timeout=timeout)
            if not result.capture_complete:
                raise TransportError("Dell command capture was incomplete")
            return result.status, result.stdout, result.stderr
        finally:
            channel.close()

    def preflight(self, config: LabConfig) -> None:
        status, _stdout, _stderr = self._execute_script(_preflight_script(config))
        if status:
            raise PreflightRejected(
                "Dell read-only preflight failed or a reserved remote name exists"
            )

    def start_guardian(self, script: str) -> Guardian:
        channel = self._transport.open_session(timeout=15)
        channel.exec_command("/bin/bash -c " + shlex.quote(script))
        return _ParamikoGuardian(channel)

    def open_kali(
        self,
        proxy_argv: tuple[str, ...],
        endpoint: SshEndpoint,
        credential: EncryptedCredentialRef | ServiceCredentialRef,
    ) -> KaliConnection:
        expected_proxy = _proxy_argv(self._service_or_default_config(credential))
        if proxy_argv != expected_proxy or endpoint != DEFAULT_CONFIG.kali:
            raise TransportError("nested Kali route differs from the pinned lab route")
        paramiko = _load_paramiko()
        secret = self._resolver.resolve(credential)
        proxy_channel = self._transport.open_session(timeout=15)
        proxy_channel.exec_command(shlex.join(proxy_argv))
        nested = paramiko.Transport(proxy_channel)
        try:
            nested.banner_timeout = 20
            nested.auth_timeout = 20
            nested.start_client(timeout=20)
            if _fingerprint(nested.get_remote_server_key()) != endpoint.host_key_sha256:
                raise TransportError("Kali SSH host-key pin mismatch")
            try:
                nested.auth_password(endpoint.username, secret, fallback=False)
            finally:
                del secret
            if not nested.is_authenticated():
                raise TransportError("Kali SSH authentication failed")
            connection_type = (
                _ServiceParamikoKali
                if type(credential) is ServiceCredentialRef
                else _ParamikoKali
            )
            return connection_type(nested, proxy_channel)
        except BaseException:
            nested.close()
            proxy_channel.close()
            raise

    @staticmethod
    def _service_or_default_config(
        credential: EncryptedCredentialRef | ServiceCredentialRef,
    ) -> LabConfig:
        return SERVICE_CONFIG if type(credential) is ServiceCredentialRef else DEFAULT_CONFIG

    def close(self) -> None:
        self._transport.close()


if __name__ == "__main__":
    raise SystemExit(main())
