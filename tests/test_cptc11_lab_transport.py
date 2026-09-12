from __future__ import annotations

import io
import json
import os
from dataclasses import replace
from pathlib import Path
import re
import socket
from types import SimpleNamespace

import pytest

from cptc_harness.contracts import PolicyError
from cptc_harness.memfd import (
    MFD_ALLOW_SEALING,
    MFD_CLOEXEC,
    memfd_create,
    seal_readonly,
    write_all,
)

import testing.cptc11_lab.transport as transport

from testing.cptc11_lab.transport import (
    ALLOWED_TARGETS,
    CommandOutput,
    DC_SMB_SCAN_ARGV,
    DEFAULT_CONFIG,
    JsonlTranscript,
    KALI_INVENTORY_ARGV,
    KALI_OPENSSH_INVENTORY_ARGV,
    KALI_OPENSSH_REQUIRED_PACKAGES,
    KALI_OPENSSH_REQUIRED_FILE_PATHS,
    KALI_PORTCAST_RELAY_POLICY_ARGV,
    KALI_REQUIRED_FILE_PATHS,
    KaliRuntimeManifest,
    OpenSshRuntimeManifest,
    PORTCAST_HTTP_WORKER_ARGV,
    SERVICE_CONFIG,
    LabSession,
    PreflightRejected,
    RunDirectory,
    SCAN_TEMPLATES,
    SealedCredentialResolver,
    SystemdCredentialResolver,
    TargetRejected,
    TransportError,
    build_lab_smb_observation,
    build_lab_portcast_observation,
    main,
    parse_kali_runtime_manifest,
    parse_openssh_runtime_manifest,
    parse_portcast_relay_policy,
)


SMB_XML_FIXTURE = (
    Path(__file__).parent / "fixtures" / "scanner" / "v2" / "signing-required.xml"
).read_bytes()
SMB_XML_DC_FIXTURE = SMB_XML_FIXTURE.replace(b"192.0.2.20", b"10.0.1.6")


def _inventory_fixture(
    *, nmap_sha256: str = "a" * 64,
) -> bytes:
    file_hashes = {
        path: (nmap_sha256 if path == "/usr/bin/nmap" else "b" * 64)
        for path in KALI_REQUIRED_FILE_PATHS
    }
    lines = [
        "HARBINGER_KALI_RUNTIME_V1",
        "nmap_package\t7.98+dfsg-1kali1",
    ]
    lines.extend(f"file\t{path}\t{file_hashes[path]}" for path in KALI_REQUIRED_FILE_PATHS)
    return ("\n".join(lines) + "\n").encode()


def _openssh_inventory_fixture(
    *, sshd_sha256: str = "c" * 64,
) -> bytes:
    file_hashes = {
        path: (sshd_sha256 if path == "/usr/sbin/sshd" else "d" * 64)
        for path in KALI_OPENSSH_REQUIRED_FILE_PATHS
    }
    lines = [
        "HARBINGER_KALI_OPENSSH_RUNTIME_V2",
        "hostname\tcptc11-kali",
        f"machine_id_sha256\t{'e' * 64}",
    ]
    lines.extend(
        f"package\t{package}\t1:1.0-1"
        for package in KALI_OPENSSH_REQUIRED_PACKAGES
    )
    lines.extend(
        f"file\t{path}\t{file_hashes[path]}"
        for path in KALI_OPENSSH_REQUIRED_FILE_PATHS
    )
    lines.extend(
        (
            f"sshd_fragment\t/etc/ssh/sshd_config.d/kali.conf\t{'f' * 64}",
            f"service_unit\t/usr/lib/systemd/system/ssh.service\t{'a' * 64}",
            "HARBINGER_KALI_OPENSSH_RUNTIME_END_V2",
        )
    )
    return ("\n".join(lines) + "\n").encode()


def _openssh_inventory_for(manifest: OpenSshRuntimeManifest) -> bytes:
    lines = [
        "HARBINGER_KALI_OPENSSH_RUNTIME_V2",
        f"hostname\t{manifest.hostname}",
        f"machine_id_sha256\t{manifest.machine_id_sha256}",
    ]
    lines.extend(f"package\t{pin.name}\t{pin.version}" for pin in manifest.packages)
    lines.extend(f"file\t{pin.path}\t{pin.sha256}" for pin in manifest.files)
    lines.extend(
        f"sshd_fragment\t{pin.path}\t{pin.sha256}"
        for pin in manifest.sshd_fragments
    )
    lines.append(
        f"service_unit\t{manifest.service_unit.path}\t{manifest.service_unit.sha256}"
    )
    lines.extend(
        f"service_dropin\t{pin.path}\t{pin.sha256}"
        for pin in manifest.service_dropins
    )
    lines.append("HARBINGER_KALI_OPENSSH_RUNTIME_END_V2")
    return ("\n".join(lines) + "\n").encode()


@pytest.fixture(autouse=True)
def _review_synthetic_runtime_for_unit_tests(monkeypatch):
    manifest = parse_kali_runtime_manifest(_inventory_fixture())
    monkeypatch.setattr(transport, "REVIEWED_KALI_PINSET", manifest)
    openssh = parse_openssh_runtime_manifest(_openssh_inventory_fixture())
    monkeypatch.setattr(transport, "REVIEWED_OPENSSH_PINSET", openssh)


class FakeGuardian:
    def __init__(self, *, ready: bool = True) -> None:
        self.ready = ready
        self.stop_requested = False
        self.closed = False
        self.cleaned = False

    def await_ready(self) -> None:
        if not self.ready:
            raise RuntimeError("guardian failed before ready")

    def close(self) -> None:
        self.stop_requested = True
        self.closed = True
        self.cleaned = True


class FakeEncryptor:
    def encrypt(self, data: bytes) -> bytes:
        return b"age-encryption.org/v1\n" + data[::-1]

    @property
    def age_binary(self) -> Path:
        return Path("/synthetic/age")

    @property
    def recipient(self) -> str:
        return "age1syntheticrecipient000000000000000000000000000000000000000000000"


def _fake_decrypt(data: bytes) -> bytes:
    prefix = b"age-encryption.org/v1\n"
    assert data.startswith(prefix)
    return data[len(prefix):][::-1]


class FakeKali:
    def __init__(self, *, fail_command: bool = False, output: bytes = b"scanner output") -> None:
        self.fail_command = fail_command
        self.output = output
        self.commands: list[tuple[str, ...]] = []
        self.closed = False
        self.portcast_channels = 0
        self.alternate_denial_checks = 0
        self.openssh_output = _openssh_inventory_fixture()

    def execute(self, argv: tuple[str, ...]) -> bytes:
        self.commands.append(argv)
        if argv == KALI_INVENTORY_ARGV:
            return _inventory_fixture()
        if argv == KALI_OPENSSH_INVENTORY_ARGV:
            return self.openssh_output
        if argv == KALI_PORTCAST_RELAY_POLICY_ARGV:
            return b"HARBINGER_PORTCAST_RELAY_POLICY_V1\n"
        if self.fail_command:
            raise RuntimeError("scanner failed")
        return self.output

    def close(self) -> None:
        self.closed = True

    def open_portcast_channel(self):
        self.portcast_channels += 1
        return SimpleNamespace(
            settimeout=lambda value: None,
            send=lambda value: len(value),
            recv=lambda maximum: b"",
            close=lambda: None,
        )

    def verify_alternate_portcast_destination_denied(self):
        self.alternate_denial_checks += 1
        return True


class FakeDell:
    def __init__(
        self,
        *,
        preflight_ok: bool = True,
        guardian_ready: bool = True,
        kali_fail_command: bool = False,
    ) -> None:
        self.preflight_ok = preflight_ok
        self.guardian = FakeGuardian(ready=guardian_ready)
        self.kali = FakeKali(fail_command=kali_fail_command)
        self.preflight_calls = 0
        self.guardian_scripts: list[str] = []
        self.proxy_commands: list[tuple[str, ...]] = []
        self.closed = False

    def preflight(self, config) -> None:
        self.preflight_calls += 1
        if not self.preflight_ok:
            raise PreflightRejected("reserved remote name already exists")

    def start_guardian(self, script: str) -> FakeGuardian:
        self.guardian_scripts.append(script)
        return self.guardian

    def open_kali(self, proxy_argv, endpoint, credential) -> FakeKali:
        self.proxy_commands.append(proxy_argv)
        return self.kali

    def close(self) -> None:
        self.closed = True


class FakeConnector:
    def __init__(self, dell: FakeDell) -> None:
        self.dell = dell
        self.connect_calls = []

    def connect(self, endpoint, credential, transcript):
        self.connect_calls.append((endpoint, credential))
        return self.dell


def test_default_config_pins_both_ssh_hops_and_only_references_encrypted_credentials():
    config = DEFAULT_CONFIG

    assert (config.dell.host, config.dell.port) == ("100.85.84.30", 22)
    assert config.dell.host_key_sha256 == "SHA256:i+6XXKZaZXbtabv/5BifieLu6RVGTjkdhF8B6y5+SIM"
    assert (config.kali.host, config.kali.port) == ("10.0.254.201", 22)
    assert config.kali.host_key_sha256 == "SHA256:0IHD7brwbkt3dllpQNOHw3bwwurq0bFMbyNcb+4s8Bs"
    assert config.dell_credential.encrypted_path.name == "cptc11-regional-dell-prox.cred"
    assert config.dell_credential.credential_name == "cptc11-regional-dell-prox"
    assert config.kali_credential.encrypted_path.name == "cptc11-regional-kali.cred"
    assert config.kali_credential.credential_name == "cptc11-regional-kali"
    assert config.dell_credential.encrypted_path != config.kali_credential.encrypted_path
    assert "password" not in repr(config).lower()


def test_systemd_credential_resolver_reads_plain_secret_without_logging_or_argv(monkeypatch):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(stdout="fixture-secret\n", stderr="")

    monkeypatch.setattr("testing.cptc11_lab.transport.subprocess.run", run)
    secret = SystemdCredentialResolver().resolve(DEFAULT_CONFIG.dell_credential)

    assert secret == "fixture-secret"
    assert "fixture-secret" not in " ".join(calls[0][0])
    assert "--name=cptc11-regional-dell-prox" in calls[0][0]


def test_service_session_uses_only_inherited_sealed_credential_descriptors():
    descriptors = (
        memfd_create("synthetic-service-dell", MFD_CLOEXEC | MFD_ALLOW_SEALING),
        memfd_create("synthetic-service-kali", MFD_CLOEXEC | MFD_ALLOW_SEALING),
    )
    try:
        for descriptor, secret in zip(
            descriptors, (b"dell-service-secret\n", b"kali-service-secret\n"), strict=True
        ):
            write_all(descriptor, secret)
            os.lseek(descriptor, 0, os.SEEK_SET)
            seal_readonly(descriptor)
        session = LabSession._for_portcast_service(descriptors)
        assert session.config == SERVICE_CONFIG
        assert isinstance(session.connector._resolver, SealedCredentialResolver)
        assert session.connector._resolver.resolve(SERVICE_CONFIG.dell_credential) == (
            "dell-service-secret"
        )
        assert session.connector._resolver.resolve(SERVICE_CONFIG.kali_credential) == (
            "kali-service-secret"
        )
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def test_root_service_path_has_no_operator_home_or_user_credential_decrypt():
    root = Path(__file__).parents[1]
    source = "\n".join(
        (root / relative).read_text()
        for relative in (
            "testing/cptc11_lab/portcast_service.py",
            "testing/cptc11_lab/portcast_broker_worker.py",
            "cptc_harness/profile_runtime/broker_ipc.py",
        )
    )
    assert "/home/moriz" not in source
    assert "systemd-creds" not in source
    assert "--user" not in source


def test_open_preflights_before_guardian_and_uses_stdio_socat_without_listener(monkeypatch):
    dell = FakeDell()
    connector = FakeConnector(dell)

    def no_local_listener(*args, **kwargs):
        raise AssertionError("transport attempted to create a local socket")

    monkeypatch.setattr(socket, "socket", no_local_listener)
    session = LabSession(connector=connector)
    session.open()

    assert dell.preflight_calls == 1
    assert len(dell.guardian_scripts) == 1
    assert dell.proxy_commands == [
        ("ip", "netns", "exec", "hbg-cptc11-vdi", "socat", "STDIO", "TCP:10.0.254.201:22")
    ]
    guardian_script = dell.guardian_scripts[0]
    assert "TCP-LISTEN" not in guardian_script
    assert guardian_script.count("flock -n 9") == 1
    assert "trap cleanup EXIT" in guardian_script
    assert "trap 'exit 129' HUP" in guardian_script
    assert "trap 'exit 130' INT" in guardian_script
    assert "trap 'exit 143' TERM" in guardian_script
    assert "ip link del hbg11-vh" in guardian_script
    assert "ip netns del hbg-cptc11-vdi" in guardian_script
    session.close()


def test_dell_preflight_requires_running_unlocked_dc_clock_sync_and_storage():
    script = transport._preflight_script(DEFAULT_CONFIG)

    assert "command -v qm" in script
    assert "command -v timedatectl" in script
    assert 'test "$(qm status 1101)" = "status: running"' in script
    assert "vm_config=$(qm config 1101)" in script
    assert "grep -Fx -- 'name: APT-DC-01'" in script
    assert "grep -q '^lock:'" in script
    assert 'test "$(qm status 1109)" = "status: running"' in script
    assert "kali_config=$(qm config 1109)" in script
    assert "grep -Fx -- 'name: kali01'" in script
    assert "grep -Fx -- 'parent: cptc11_10_regional_clean'" in script
    assert "net0: virtio=52:54:00:11:01:09,bridge=vmbr111" in script
    assert "kali_snapshots=$(qm listsnapshot 1109)" in script
    assert 'current != 1 || imported != 1 || clean != 1' in script
    assert "NTPSynchronized --value" in script
    assert "available_bytes" in script
    assert "1048576" in script
    assert not any(word in script for word in ("qm start", "qm stop", "qm reboot", "qm reset"))


def test_preexisting_reserved_name_is_rejected_without_guardian_or_deletion():
    dell = FakeDell(preflight_ok=False)
    session = LabSession(connector=FakeConnector(dell))

    with pytest.raises(PreflightRejected):
        session.open()

    assert dell.preflight_calls == 1
    assert dell.guardian_scripts == []
    assert dell.proxy_commands == []
    assert dell.closed


def test_guardian_failure_closes_channel_and_outer_transport():
    dell = FakeDell(guardian_ready=False)
    session = LabSession(connector=FakeConnector(dell))

    with pytest.raises(RuntimeError, match="guardian failed"):
        session.open()

    assert dell.guardian.stop_requested
    assert dell.guardian.cleaned
    assert dell.closed


def test_context_close_stops_kali_then_guardian_cleanup(tmp_path):
    dell = FakeDell()
    run = RunDirectory.create(tmp_path, encryptor=FakeEncryptor())

    with LabSession(connector=FakeConnector(dell), run_directory=run) as session:
        session.preflight_inventory()
        assert session.run_scan("dc-smb-security", "10.0.1.6") == b"scanner output"
    run.close()

    assert dell.kali.commands == [KALI_INVENTORY_ARGV, DC_SMB_SCAN_ARGV]
    assert dell.kali.closed
    assert dell.guardian.closed
    assert dell.guardian.cleaned
    assert dell.closed


def test_rejects_unlisted_target_before_any_scanner_command():
    dell = FakeDell()
    with LabSession(connector=FakeConnector(dell)) as session:
        with pytest.raises(TargetRejected):
            session.run_scan("dc-smb-security", "10.0.1.12")

    assert dell.kali.commands == []
    assert ALLOWED_TARGETS == frozenset(
        {"10.0.1.6", "10.0.1.10", "10.0.1.11", "10.0.1.13", "10.0.1.14", "10.0.1.30", "10.0.1.99"}
    )


@pytest.mark.parametrize("template_name", sorted(SCAN_TEMPLATES))
def test_scanner_templates_are_fixed_read_only_argv(template_name, tmp_path):
    dell = FakeDell()
    run = RunDirectory.create(tmp_path, encryptor=FakeEncryptor())
    with LabSession(connector=FakeConnector(dell), run_directory=run) as session:
        session.preflight_inventory()
        session.run_scan(template_name, "10.0.1.6")
    run.close()

    assert dell.kali.commands[0] == KALI_INVENTORY_ARGV
    argv = dell.kali.commands[1]
    assert argv[0] == "/usr/bin/nmap"
    assert argv == DC_SMB_SCAN_ARGV
    assert not ({"-oA", "-oN", "-oG", "--script-args-file"} & set(argv))
    assert not any(
        token in " ".join(argv).lower()
        for token in ("exploit", "brute", "dos", "broadcast", "external", "intrusive", "auth")
    )


def test_transcript_is_utc_jsonl_metadata_and_never_logs_secret_or_scan_output(tmp_path):
    stream = io.StringIO()
    transcript = JsonlTranscript(stream)
    dell = FakeDell()
    secret = "correct horse battery staple"
    run = RunDirectory.create(tmp_path, encryptor=FakeEncryptor())

    with LabSession(
        connector=FakeConnector(dell), transcript=transcript, run_directory=run
    ) as session:
        session.preflight_inventory()
        session.run_scan("dc-smb-security", "10.0.1.6")
        transcript.emit("test", unsafe_note=secret, output=b"scanner output")
    run.close()

    text = stream.getvalue()
    events = [json.loads(line) for line in text.splitlines()]
    assert events
    assert all(event["timestamp"].endswith("Z") for event in events)
    assert secret not in text
    assert "scanner output" not in text
    assert all("event" in event for event in events)
    assert [event["sequence"] for event in events] == list(range(1, len(events) + 1))
    assert len({event["event_id"] for event in events}) == len(events)
    assert all(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", event["timestamp"]) for event in events)
    assert all(type(event["monotonic_ns"]) is int for event in events)


def test_scanner_failure_still_cleans_every_channel(tmp_path):
    dell = FakeDell(kali_fail_command=True)
    run = RunDirectory.create(tmp_path, encryptor=FakeEncryptor())

    with pytest.raises(RuntimeError, match="scanner failed"):
        with LabSession(connector=FakeConnector(dell), run_directory=run) as session:
            session.preflight_inventory()
            session.run_scan("dc-smb-security", "10.0.1.6")
    run.close()

    assert dell.kali.closed
    assert dell.guardian.cleaned
    assert dell.closed


def test_preflight_inventory_uses_one_fixed_integrity_command_and_returns_typed_manifest():
    dell = FakeDell()

    with LabSession(connector=FakeConnector(dell)) as session:
        manifest = session.preflight_inventory()

    assert dell.kali.commands == [KALI_INVENTORY_ARGV]
    assert isinstance(manifest, KaliRuntimeManifest)
    assert manifest.nmap_package == "7.98+dfsg-1kali1"
    command = " ".join(KALI_INVENTORY_ARGV)
    for path in KALI_REQUIRED_FILE_PATHS:
        assert path in command
    assert "nbstat.lua" not in command
    assert "nmap --version" not in command
    assert "ldd" not in command
    assert "sha256sum" in command


def test_runtime_manifest_parser_rejects_missing_required_file_and_duplicate_path():
    missing = _inventory_fixture().replace(
        f"file\t{KALI_REQUIRED_FILE_PATHS[-1]}\t{'b' * 64}\n".encode(), b""
    )
    with pytest.raises(PreflightRejected, match="required file"):
        parse_kali_runtime_manifest(missing)

    duplicate = _inventory_fixture() + (
        f"file\t{KALI_REQUIRED_FILE_PATHS[0]}\t{'c' * 64}\n".encode()
    )
    with pytest.raises(PreflightRejected, match="duplicate"):
        parse_kali_runtime_manifest(duplicate)


def test_scan_refuses_runtime_pin_drift_before_target_command(monkeypatch):
    dell = FakeDell()
    drifted = parse_kali_runtime_manifest(_inventory_fixture(nmap_sha256="f" * 64))
    monkeypatch.setattr(transport, "REVIEWED_KALI_PINSET", drifted)

    with LabSession(connector=FakeConnector(dell)) as session:
        with pytest.raises(PreflightRejected, match="reviewed Kali runtime"):
            session.preflight_inventory()

    assert dell.kali.commands == [KALI_INVENTORY_ARGV]


def test_scan_requires_current_one_use_preflight_before_target_command(tmp_path):
    dell = FakeDell()
    run = RunDirectory.create(tmp_path, encryptor=FakeEncryptor())
    with LabSession(connector=FakeConnector(dell), run_directory=run) as session:
        with pytest.raises(PreflightRejected, match="current-session"):
            session.run_scan("dc-smb-security", "10.0.1.6")
        session.preflight_inventory()
        session.run_scan("dc-smb-security", "10.0.1.6")
        with pytest.raises(PreflightRejected, match="current-session"):
            session.run_scan("dc-smb-security", "10.0.1.6")
    run.close()

    assert dell.kali.commands == [KALI_INVENTORY_ARGV, DC_SMB_SCAN_ARGV]


def test_lab_smb_observation_labels_unmetered_capture_without_vulnerability_claim():
    observation = build_lab_smb_observation(SMB_XML_DC_FIXTURE)

    assert observation.profile_id == "lab.cptc11.kali.nmap_smb2_security_mode.v1"
    assert observation.related_check_id == "network.nse_smb2_security_mode"
    assert observation.target_ipv4 == "10.0.1.6"
    assert observation.signing_required is True
    assert observation.disposition == "not_observed"
    assert observation.collection_state == "unmetered_lab_acceptance"
    assert observation.confirmed_vulnerability is False
    assert "network_request_accounting_unavailable" in observation.limitations


def test_first_scan_allows_only_exact_dc_smb_command_even_for_other_in_scope_target(tmp_path):
    dell = FakeDell()
    run = RunDirectory.create(tmp_path, encryptor=FakeEncryptor())

    with LabSession(connector=FakeConnector(dell), run_directory=run) as session:
        with pytest.raises(TargetRejected):
            session.run_scan("dc-smb-security", "10.0.1.10")
        session.preflight_inventory()
        session.run_scan("dc-smb-security", "10.0.1.6")
    run.close()

    assert dell.kali.commands == [KALI_INVENTORY_ARGV, DC_SMB_SCAN_ARGV]
    assert DC_SMB_SCAN_ARGV == (
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


def test_portcast_candidate_uses_fixed_python_worker_contract_and_no_curl():
    assert PORTCAST_HTTP_WORKER_ARGV == (
        "/usr/bin/python3", "-I", "-S",
        "/usr/libexec/cptc-harness/portcast-http-worker-v1.py",
    )
    assert "curl" not in " ".join(PORTCAST_HTTP_WORKER_ARGV).lower()


def test_parent_transport_exposes_no_portcast_channel_surface():
    connection = transport._ParamikoKali(
        SimpleNamespace(close=lambda: None), SimpleNamespace(close=lambda: None)
    )
    assert not hasattr(connection, "open_portcast_channel")
    assert not hasattr(connection, "open_channel")
    assert not hasattr(LabSession, "acquire_portcast_channel_provider")


def test_service_portcast_wrapper_opens_only_the_frozen_direct_tcpip_channel():
    calls = []
    channel = object()

    class NestedTransport:
        def open_channel(self, *args, **kwargs):
            calls.append((args, kwargs))
            return channel

    provider = transport._ServicePortcastChannelProvider(NestedTransport(), timeout_s=7.5)

    assert provider.open_portcast_channel() is channel
    assert calls == [
        (
            ("direct-tcpip", ("10.0.1.30", 8096), ("127.0.0.1", 0)),
            {"timeout": 7.5},
        )
    ]


def test_paramiko_dell_factory_grants_fixed_portcast_provider_only_to_service_credential(
    monkeypatch,
):
    class NestedTransport:
        def __init__(self, _channel):
            self.authenticated = False

        def start_client(self, *, timeout):
            assert timeout == 20

        def get_remote_server_key(self):
            return object()

        def auth_password(self, username, secret, *, fallback):
            assert username == DEFAULT_CONFIG.kali.username
            assert secret == "synthetic-secret"
            assert fallback is False
            self.authenticated = True

        def is_authenticated(self):
            return self.authenticated

        def close(self):
            pass

    class DellTransport:
        def open_session(self, *, timeout):
            assert timeout == 15
            return SimpleNamespace(exec_command=lambda _command: None, close=lambda: None)

    resolver = SimpleNamespace(resolve=lambda _credential: "synthetic-secret")
    monkeypatch.setattr(
        transport,
        "_load_paramiko",
        lambda: SimpleNamespace(Transport=NestedTransport),
    )
    monkeypatch.setattr(
        transport,
        "_fingerprint",
        lambda _key: DEFAULT_CONFIG.kali.host_key_sha256,
    )
    dell = transport._ParamikoDell(DellTransport(), resolver, SimpleNamespace())

    service_connection = dell.open_kali(
        transport._proxy_argv(SERVICE_CONFIG),
        DEFAULT_CONFIG.kali,
        SERVICE_CONFIG.kali_credential,
    )
    operator_connection = dell.open_kali(
        transport._proxy_argv(DEFAULT_CONFIG),
        DEFAULT_CONFIG.kali,
        DEFAULT_CONFIG.kali_credential,
    )

    assert type(service_connection) is transport._ServiceParamikoKali
    assert type(operator_connection) is transport._ParamikoKali
    assert not hasattr(operator_connection, "_take_portcast_channel_provider")
    assert (
        type(service_connection._take_portcast_channel_provider())
        is transport._ServicePortcastChannelProvider
    )
    with pytest.raises(TransportError, match="unavailable"):
        service_connection._take_portcast_channel_provider()


def test_service_portcast_channel_is_gated_by_authority_preflight_control_and_one_use():
    class Provider:
        def __init__(self):
            self.opens = 0

        def open_portcast_channel(self):
            self.opens += 1
            return object()

    session = object.__new__(LabSession)
    session.config = SERVICE_CONFIG
    session._service_session = True
    session._kali = object()
    session._portcast_candidate_ready = True
    session._portcast_alternate_denied = True
    session._portcast_channel_used = False
    session._service_portcast_channel_provider = Provider()

    assert session._open_portcast_channel() is not None
    with pytest.raises(PreflightRejected, match="one use"):
        session._open_portcast_channel()
    assert session._service_portcast_channel_provider.opens == 1


def test_blocked_portcast_dispatch_does_not_open_even_the_fixed_channel(tmp_path):
    dell = FakeDell()
    run = RunDirectory.create(tmp_path, encryptor=FakeEncryptor())
    with LabSession(connector=FakeConnector(dell), run_directory=run) as session:
        session.preflight_portcast_inventory()
        with pytest.raises(PreflightRejected, match="wire accounting"):
            session.run_portcast_identity()
    run.close()
    assert dell.kali.portcast_channels == 0
    assert dell.kali.commands == [
        KALI_OPENSSH_INVENTORY_ARGV,
        KALI_PORTCAST_RELAY_POLICY_ARGV,
    ]


def test_portcast_preflight_is_offline_and_live_dispatch_is_refused_before_command(tmp_path):
    dell = FakeDell()
    run = RunDirectory.create(tmp_path, encryptor=FakeEncryptor())
    with LabSession(connector=FakeConnector(dell), run_directory=run) as session:
        profile = session.preflight_portcast_inventory()
        assert profile.profile_id == "web.http_jellyfin_public_identity"
        with pytest.raises(PreflightRejected, match="wire accounting"):
            session.run_portcast_identity()
    run.close()
    assert dell.kali.commands == [
        KALI_OPENSSH_INVENTORY_ARGV,
        KALI_PORTCAST_RELAY_POLICY_ARGV,
    ]


def test_portcast_relay_policy_preflight_is_exact_metadata_only_and_has_no_target_connection():
    command = " ".join(KALI_PORTCAST_RELAY_POLICY_ARGV)
    assert KALI_PORTCAST_RELAY_POLICY_ARGV[:3] == ("/bin/sh", "-eu", "-c")
    assert "/usr/sbin/sshd -T" in command
    assert "addr=10.0.254.253" in command
    assert "laddr=10.0.254.201" in command
    assert "permitopen" in command.lower()
    assert "10.0.1.30:8096" in command
    assert not any(value in command.lower() for value in ("curl", "wget", "nc ", "nmap", "/dev/tcp"))
    assert parse_portcast_relay_policy(b"HARBINGER_PORTCAST_RELAY_POLICY_V1\n") is True
    for invalid in (
        b"",
        b"HARBINGER_PORTCAST_RELAY_POLICY_V1",
        b"HARBINGER_PORTCAST_RELAY_POLICY_V1\nextra\n",
    ):
        with pytest.raises(PreflightRejected):
            parse_portcast_relay_policy(invalid)


def test_openssh_inventory_is_fixed_hash_only_metadata_and_parses_typed_manifest():
    command = " ".join(KALI_OPENSSH_INVENTORY_ARGV)
    assert KALI_OPENSSH_INVENTORY_ARGV[:3] == ("/bin/sh", "-eu", "-c")
    assert "dpkg-query" in command
    assert "/usr/sbin/sshd" in command
    assert "sshd -T" not in command
    assert not any(value in command.lower() for value in ("curl", "wget", "nmap", "/dev/tcp"))

    manifest = parse_openssh_runtime_manifest(_openssh_inventory_fixture())
    assert isinstance(manifest, OpenSshRuntimeManifest)
    assert manifest.hostname == "cptc11-kali"
    assert {pin.name for pin in manifest.packages} == set(KALI_OPENSSH_REQUIRED_PACKAGES)
    assert {pin.path for pin in manifest.files} == set(KALI_OPENSSH_REQUIRED_FILE_PATHS)
    assert manifest.sshd_fragments == (
        transport.RuntimeFilePin("/etc/ssh/sshd_config.d/kali.conf", "f" * 64),
    )
    assert manifest.service_unit == transport.RuntimeFilePin(
        "/usr/lib/systemd/system/ssh.service", "a" * 64
    )
    assert manifest.service_dropins == ()
    assert re.fullmatch(r"[0-9a-f]{64}", manifest.sha256)


def test_reviewed_openssh_pinset_matches_the_target_silent_kali_inventory():
    manifest = transport.CPTC11_KALI_OPENSSH_PINSET
    assert manifest.sha256 == "9bcaeaa02a0c9f52b1b32c4259a35043b9dd0caec55f6fec150ec6f5a722df16"
    assert transport.CPTC11_KALI_OPENSSH_PRE_RELAY_PINSET.sha256 == (
        "33ed86231e1918fa1418f779a3232f8c0f6651e2c1202bc78e75c8a3597e946f"
    )
    assert manifest.hostname == "cptc11-export-t1-vdi-kali01"
    assert manifest.machine_id_sha256 == "243500f5ca4683df06f22561458dd7e63f7b10aa1ef5a6660cf42983285f3915"
    assert {pin.name: pin.version for pin in manifest.packages} == {
        "bash": "5.3-2",
        "coreutils": "9.7-3",
        "dpkg": "1.23.5+kali1",
        "gawk": "1:5.3.2-1",
        "hostname": "3.25",
        "openssh-server": "1:10.2p1-5",
        "systemd": "259.1-1",
    }
    assert {pin.path for pin in manifest.files} == set(KALI_OPENSSH_REQUIRED_FILE_PATHS)
    assert {pin.path for pin in manifest.sshd_fragments} == {
        "/etc/ssh/sshd_config.d/20-systemd-userdb.conf",
        "/etc/ssh/sshd_config.d/70-harbinger-portcast.conf",
    }
    assert manifest.service_unit.path == "/usr/lib/systemd/system/ssh.service"
    assert manifest.service_dropins == ()


def test_openssh_inventory_rejects_missing_duplicate_and_unknown_fields():
    required = KALI_OPENSSH_REQUIRED_FILE_PATHS[-1]
    missing = _openssh_inventory_fixture().replace(
        f"file\t{required}\t{'d' * 64}\n".encode(), b""
    )
    duplicate = _openssh_inventory_fixture() + (
        f"file\t{KALI_OPENSSH_REQUIRED_FILE_PATHS[0]}\t{'f' * 64}\n".encode()
    )
    unknown = _openssh_inventory_fixture() + b"config\tvalue\n"
    for value in (missing, duplicate, unknown):
        with pytest.raises(PreflightRejected):
            parse_openssh_runtime_manifest(value)


def test_portcast_preflight_blocks_unreviewed_openssh_before_policy_command(monkeypatch):
    dell = FakeDell()
    monkeypatch.setattr(transport, "REVIEWED_OPENSSH_PINSET", None)

    with LabSession(connector=FakeConnector(dell)) as session:
        with pytest.raises(PreflightRejected, match="OpenSSH runtime"):
            session.preflight_portcast_inventory()

    assert dell.kali.commands == [KALI_OPENSSH_INVENTORY_ARGV]
    assert dell.kali.portcast_channels == 0


def test_portcast_preflight_allows_one_fixed_kali_local_denial_control():
    dell = FakeDell()
    with LabSession(connector=FakeConnector(dell)) as session:
        with pytest.raises(PreflightRejected, match="current-session"):
            session.verify_portcast_alternate_destination_denied()
        session.preflight_portcast_inventory()
        assert session.verify_portcast_alternate_destination_denied() is True

    assert dell.kali.alternate_denial_checks == 1
    assert dell.kali.portcast_channels == 0


def test_lab_preflight_never_returns_parent_channel_authority(monkeypatch):
    dell = FakeDell()
    reviewed = transport.CPTC11_KALI_OPENSSH_PINSET
    monkeypatch.setattr(transport, "REVIEWED_OPENSSH_PINSET", reviewed)
    dell.kali.openssh_output = _openssh_inventory_for(reviewed)
    with LabSession(connector=FakeConnector(dell)) as session:
        session.preflight_portcast_inventory()
        session.verify_portcast_alternate_destination_denied()
        assert not hasattr(session, "acquire_portcast_channel_provider")

    assert dell.kali.portcast_channels == 0


def test_lab_session_close_leaves_no_portcast_capability(monkeypatch):
    dell = FakeDell()
    reviewed = transport.CPTC11_KALI_OPENSSH_PINSET
    monkeypatch.setattr(transport, "REVIEWED_OPENSSH_PINSET", reviewed)
    dell.kali.openssh_output = _openssh_inventory_for(reviewed)
    session = LabSession(connector=FakeConnector(dell))
    session.open()
    session.preflight_portcast_inventory()
    session.verify_portcast_alternate_destination_denied()
    session.close()

    assert not hasattr(session, "acquire_portcast_channel_provider")
    assert dell.kali.portcast_channels == 0


def test_paramiko_alternate_control_requires_administratively_prohibited(monkeypatch):
    class ChannelException(Exception):
        def __init__(self, code):
            self.code = code

    class FakeTransport:
        def __init__(self, outcome):
            self.outcome = outcome

        def open_channel(self, *args, **kwargs):
            if isinstance(self.outcome, BaseException):
                raise self.outcome
            return self.outcome

    monkeypatch.setattr(
        transport,
        "_load_paramiko",
        lambda: SimpleNamespace(ChannelException=ChannelException),
    )
    proxy = SimpleNamespace(close=lambda: None)
    denied = transport._ParamikoKali(FakeTransport(ChannelException(1)), proxy)
    assert denied.verify_alternate_portcast_destination_denied() is True

    wrong_reason = transport._ParamikoKali(FakeTransport(ChannelException(2)), proxy)
    with pytest.raises(PreflightRejected, match="other than policy"):
        wrong_reason.verify_alternate_portcast_destination_denied()

    permitted_channel = SimpleNamespace(closed=False)
    permitted_channel.close = lambda: setattr(permitted_channel, "closed", True)
    permitted = transport._ParamikoKali(FakeTransport(permitted_channel), proxy)
    with pytest.raises(PreflightRejected, match="was permitted"):
        permitted.verify_alternate_portcast_destination_denied()
    assert permitted_channel.closed is True


def test_portcast_artifact_reservation_is_private_durable_and_separate(tmp_path):
    run = RunDirectory.create(tmp_path, encryptor=FakeEncryptor())
    run.reserve_portcast_action()
    intent = json.loads((run.path / "portcast-identity.intent.json").read_text())
    assert intent == {
        "profile_id": "web.http_jellyfin_public_identity",
        "schema": "cptc11-lab-action-intent-v1",
        "target": "10.0.1.30:8096",
        "template": "portcast-identity",
    }
    assert {
        "portcast-identity.stdout.age.pending",
        "portcast-identity.stderr.age.pending",
        "portcast-identity.typed.json.age.pending",
    } <= {path.name for path in run.path.iterdir()}
    assert all(path.stat().st_mode & 0o077 == 0 for path in run.path.iterdir())
    run.close()


def test_saved_portcast_response_builds_unmetered_identity_observation_only():
    body = (Path(__file__).parent / "fixtures" / "portcast" / "jellyfin-10.10.7.json").read_bytes()
    from cptc_harness.portcast_identity import portcast_http_request_bytes
    receipt = {
        "status": "complete", "target_ipv4": "10.0.1.30", "target_port": 8096,
        "method": "GET", "path": "/System/Info/Public", "status_code": 200,
        "content_type": "application/json", "content_encoding": "identity",
        "truncated": False, "tcp_connects": 1, "protocol_requests": 1,
        "tx_bytes": len(portcast_http_request_bytes()), "rx_bytes": len(body),
        "redirects": 0, "retries": 0, "proxy_used": False,
        "authenticated": False, "request_body_bytes": 0,
    }
    observation = build_lab_portcast_observation(body, receipt=receipt)
    assert observation.product == "Jellyfin Server"
    assert observation.version == "10.10.7"
    assert observation.collection_state == "unmetered_lab_acceptance"
    assert observation.confirmed_vulnerability is False
    assert observation.limitations == (
        "network_request_accounting_unavailable",
        "production_profile_not_admitted",
        "manual_prerequisite_review_required",
    )
    assert not hasattr(observation, "server_name")


def test_portcast_reserved_raw_and_typed_artifacts_are_encrypted(tmp_path):
    body = (Path(__file__).parent / "fixtures" / "portcast" / "jellyfin-10.10.7.json").read_bytes()
    from cptc_harness.portcast_identity import portcast_http_request_bytes
    receipt = {
        "status": "complete", "target_ipv4": "10.0.1.30", "target_port": 8096,
        "method": "GET", "path": "/System/Info/Public", "status_code": 200,
        "content_type": "application/json", "content_encoding": "identity",
        "truncated": False, "tcp_connects": 1, "protocol_requests": 1,
        "tx_bytes": len(portcast_http_request_bytes()), "rx_bytes": len(body),
        "redirects": 0, "retries": 0, "proxy_used": False,
        "authenticated": False, "request_body_bytes": 0,
    }
    observation = build_lab_portcast_observation(body, receipt=receipt)
    run = RunDirectory.create(tmp_path, encryptor=FakeEncryptor())
    run.reserve_portcast_action()
    run.store_command("portcast-identity", body, b"")
    run.store_portcast_typed_observation(observation)
    run.close()
    for name in (
        "portcast-identity.stdout.age", "portcast-identity.stderr.age",
        "portcast-identity.typed.json.age",
    ):
        encrypted = (run.path / name).read_bytes()
        assert encrypted.startswith(b"age-encryption.org/v1\n")
        assert body not in encrypted


def test_scan_portcast_cli_uses_frozen_session_runner_and_writes_no_target_artifacts(
    tmp_path,
):
    output = io.StringIO()
    dell = FakeDell()
    calls = []

    def runner():
        calls.append(True)
        return {
            "action_id": "cptc11-portcast-public-identity-action-v5",
            "audit_verified": True,
            "automatic_retry": False,
            "cleanup_status": "passed",
            "profile_id": "web.http_jellyfin_public_identity",
            "receipt_outcome": "complete",
            "status": "complete",
            "workspace": "cptc11-portcast-workspace",
            "execution": {
                "reservation_state": "complete",
                "attempt_count": 1,
                "attempt_state": "complete",
                "transport_counters": {
                    "tcp_connects": 1,
                    "udp_datagrams": 0,
                    "protocol_requests": 1,
                    "tx_bytes": 103,
                    "rx_bytes": 282,
                },
                "wire_counters_verified": True,
                "result_receipt_present": True,
            },
        }

    status = main(
        ["scan-portcast", "--run-root", str(tmp_path)],
        connector=FakeConnector(dell), stdout=output, encryptor=FakeEncryptor(),
        portcast_session_runner=runner,
    )
    result = json.loads(output.getvalue())
    run_path = Path(result["run_directory"])
    assert status == 0 and result["status"] == "passed"
    assert result["action_id"] == "cptc11-portcast-public-identity-action-v5"
    assert result["receipt_outcome"] == "complete"
    assert result["cleanup_status"] == "passed"
    assert result["execution"] == {
        "reservation_state": "complete",
        "attempt_count": 1,
        "attempt_state": "complete",
        "failure_stage": None,
        "transport_counters": {
            "tcp_connects": 1,
            "udp_datagrams": 0,
            "protocol_requests": 1,
            "tx_bytes": 103,
            "rx_bytes": 282,
        },
        "wire_counters_verified": True,
        "result_receipt_present": True,
    }
    events = [json.loads(line) for line in (run_path / "transcript.jsonl").read_text().splitlines()]
    coordinator = next(event for event in events if event["event"] == "profile.coordinator")
    assert {
        key: coordinator[key]
        for key in (
            "attempt_count",
            "attempt_state",
            "failure_stage",
            "protocol_requests",
            "reservation_state",
            "result_receipt_present",
            "rx_bytes",
            "tcp_connects",
            "tx_bytes",
            "udp_datagrams",
            "wire_counters_verified",
        )
    } == {
        "attempt_count": 1,
        "attempt_state": "complete",
        "failure_stage": None,
        "protocol_requests": 1,
        "reservation_state": "complete",
        "result_receipt_present": True,
        "rx_bytes": 282,
        "tcp_connects": 1,
        "tx_bytes": 103,
        "udp_datagrams": 0,
        "wire_counters_verified": True,
    }
    assert len(calls) == 1
    assert calls == [True]
    assert dell.preflight_calls == 0
    assert dell.kali.commands == []
    assert not list(run_path.glob("portcast-identity.*.age"))


def test_scan_portcast_cli_rejects_extra_raw_result_without_disclosing_it(tmp_path):
    output = io.StringIO()
    marker = "raw-client-value-must-not-appear"

    def runner():
        return {
            "action_id": "cptc11-portcast-public-identity-action-v5",
            "audit_verified": True,
            "automatic_retry": False,
            "cleanup_status": "passed",
            "profile_id": "web.http_jellyfin_public_identity",
            "receipt_outcome": "complete",
            "status": "complete",
            "workspace": "cptc11-portcast-workspace",
            "execution": {
                "reservation_state": "complete",
                "attempt_count": 1,
                "attempt_state": "complete",
                "transport_counters": {
                    "tcp_connects": 1,
                    "udp_datagrams": 0,
                    "protocol_requests": 1,
                    "tx_bytes": 103,
                    "rx_bytes": 282,
                },
                "wire_counters_verified": True,
                "result_receipt_present": True,
            },
            "body": marker,
        }

    status = main(
        ["scan-portcast", "--run-root", str(tmp_path)],
        stdout=output,
        encryptor=FakeEncryptor(),
        portcast_session_runner=runner,
    )

    result = json.loads(output.getvalue())
    transcript = (Path(result["run_directory"]) / "transcript.jsonl").read_text()
    assert status == 1
    assert result["status"] == "failed"
    assert marker not in output.getvalue()
    assert marker not in transcript


def test_scan_portcast_cli_does_not_render_missing_counters_as_zero(tmp_path):
    output = io.StringIO()

    def runner():
        return {
            "action_id": "cptc11-portcast-public-identity-action-v5",
            "audit_verified": True,
            "automatic_retry": False,
            "cleanup_status": None,
            "profile_id": "web.http_jellyfin_public_identity",
            "receipt_outcome": None,
            "status": "blocked",
            "workspace": "cptc11-portcast-workspace",
            "reason": "frozen action has incomplete durable audit history",
            "execution": {
                "reservation_state": None,
                "attempt_count": 0,
                "attempt_state": None,
                "transport_counters": None,
                "wire_counters_verified": False,
                "result_receipt_present": False,
            },
        }

    status = main(
        ["scan-portcast", "--run-root", str(tmp_path)],
        stdout=output,
        encryptor=FakeEncryptor(),
        portcast_session_runner=runner,
    )

    result = json.loads(output.getvalue())
    events = [
        json.loads(line)
        for line in (Path(result["run_directory"]) / "transcript.jsonl").read_text().splitlines()
    ]
    coordinator = next(event for event in events if event["event"] == "profile.coordinator")
    assert status == 1
    assert result["execution"]["transport_counters"] is None
    assert not {
        "tcp_connects", "udp_datagrams", "protocol_requests", "tx_bytes", "rx_bytes"
    } & set(coordinator)


def test_scan_portcast_cli_reports_only_the_fixed_failure_stage(tmp_path):
    output = io.StringIO()

    def runner():
        return {
            "action_id": "cptc11-portcast-public-identity-action-v5",
            "audit_verified": True,
            "automatic_retry": False,
            "cleanup_status": "passed",
            "profile_id": "web.http_jellyfin_public_identity",
            "receipt_outcome": "uncertain",
            "status": "uncertain",
            "workspace": "cptc11-portcast-workspace",
            "reason": "PortCast profile transport did not complete",
            "execution": {
                "reservation_state": "uncertain",
                "attempt_count": 1,
                "attempt_state": "uncertain",
                "transport_counters": {
                    "tcp_connects": 0,
                    "udp_datagrams": 0,
                    "protocol_requests": 0,
                    "tx_bytes": 0,
                    "rx_bytes": 0,
                },
                "wire_counters_verified": True,
                "result_receipt_present": True,
                "failure_stage": "target_open",
            },
        }

    status = main(
        ["scan-portcast", "--run-root", str(tmp_path)],
        stdout=output,
        encryptor=FakeEncryptor(),
        portcast_session_runner=runner,
    )

    result = json.loads(output.getvalue())
    events = [
        json.loads(line)
        for line in (Path(result["run_directory"]) / "transcript.jsonl").read_text().splitlines()
    ]
    coordinator = next(event for event in events if event["event"] == "profile.coordinator")
    assert status == 1
    assert result["execution"]["failure_stage"] == "target_open"
    assert coordinator["failure_stage"] == "target_open"
    assert coordinator["automatic_retry"] is False


def test_run_directory_is_private_and_refuses_incomplete_command_streams(tmp_path):
    run = RunDirectory.create(tmp_path)
    assert run.path.stat().st_mode & 0o777 == 0o700

    with pytest.raises(TransportError, match="capture allowance"):
        run.store_command("inventory", b"A" * 20000, b"B" * 20000)

    assert not (run.path / "inventory.stdout").exists()
    assert not (run.path / "inventory.stderr").exists()
    run.store_command("inventory", b"A" * 100, b"B" * 100)

    stdout_path = run.path / "inventory.stdout"
    stderr_path = run.path / "inventory.stderr"
    assert len(stdout_path.read_bytes()) == 100
    assert len(stderr_path.read_bytes()) == 100
    assert stdout_path.stat().st_mode & 0o777 == 0o600
    assert stderr_path.stat().st_mode & 0o777 == 0o600
    assert run.transcript_path.stat().st_mode & 0o777 == 0o600


def test_repeated_metadata_commands_keep_each_complete_capture(tmp_path):
    run = RunDirectory.create(tmp_path, encryptor=FakeEncryptor())
    run.store_command("openssh-inventory", b"before\n", b"")
    run.store_command("openssh-inventory", b"after\n", b"warning\n")

    assert (run.path / "openssh-inventory.stdout").read_bytes() == b"before\n"
    assert (run.path / "openssh-inventory.stderr").read_bytes() == b""
    assert (run.path / "openssh-inventory.2.stdout").read_bytes() == b"after\n"
    assert (run.path / "openssh-inventory.2.stderr").read_bytes() == b"warning\n"
    events = [json.loads(line) for line in run.transcript_path.read_text().splitlines()]
    assert [event["artifact_occurrence"] for event in events] == [1, 2]
    run.close()


def test_run_directory_refuses_raw_target_capture_without_encryption(tmp_path):
    run = RunDirectory.create(tmp_path)

    with pytest.raises(TransportError, match="encryption"):
        run.store_command("dc-smb-security", b"target-output", b"")

    assert not (run.path / "dc-smb-security.stdout").exists()
    assert not (run.path / "dc-smb-security.stdout.age").exists()
    run.close()


def test_scan_requires_encrypted_durable_run_directory_before_target_command():
    dell = FakeDell()

    with LabSession(connector=FakeConnector(dell)) as session:
        session.preflight_inventory()
        with pytest.raises(TransportError, match="encrypted durable run directory"):
            session.run_scan("dc-smb-security", "10.0.1.6")

    assert dell.kali.commands == [KALI_INVENTORY_ARGV]


def test_scan_reserves_intent_and_output_space_before_remote_dispatch(tmp_path):
    dell = FakeDell()
    dell.kali.output = SMB_XML_DC_FIXTURE
    run = RunDirectory.create(tmp_path, encryptor=FakeEncryptor())
    original_execute = dell.kali.execute

    def execute(argv):
        if argv == DC_SMB_SCAN_ARGV:
            intent = json.loads((run.path / "dc-smb-security.intent.json").read_text())
            assert intent == {
                "runtime_pinset_sha256": transport.REVIEWED_KALI_PINSET.sha256,
                "schema": "cptc11-lab-action-intent-v1",
                "target": "10.0.1.6",
                "template": "dc-smb-security",
            }
            for suffix in ("stdout.age.pending", "stderr.age.pending", "typed.json.age.pending"):
                assert (run.path / f"dc-smb-security.{suffix}").stat().st_size > 16 * 1024
        return original_execute(argv)

    dell.kali.execute = execute
    with LabSession(connector=FakeConnector(dell), run_directory=run) as session:
        session.preflight_inventory()
        captured = session.run_scan("dc-smb-security", "10.0.1.6")
        run.store_typed_observation(build_lab_smb_observation(captured))
    run.close()

    assert (run.path / "dc-smb-security.stdout.age").is_file()
    assert (run.path / "dc-smb-security.stderr.age").is_file()
    assert (run.path / "dc-smb-security.typed.json.age").is_file()
    assert not list(run.path.glob("*.pending"))


def test_output_reservation_failure_prevents_target_dispatch(tmp_path, monkeypatch):
    dell = FakeDell()
    run = RunDirectory.create(tmp_path, encryptor=FakeEncryptor())

    def no_space(_fd, _offset, _length):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(transport.os, "posix_fallocate", no_space)
    with LabSession(connector=FakeConnector(dell), run_directory=run) as session:
        session.preflight_inventory()
        with pytest.raises(TransportError, match="reserve target evidence storage"):
            session.run_scan("dc-smb-security", "10.0.1.6")
    run.close()

    assert dell.kali.commands == [KALI_INVENTORY_ARGV]
    assert (run.path / "dc-smb-security.intent.json").is_file()
    assert not list(run.path.glob("*.pending"))


@pytest.mark.parametrize(
    ("command", "artifact", "expected_argv"),
    (
        ("preflight", "inventory.stdout", KALI_INVENTORY_ARGV),
        ("scan-dc", "dc-smb-security.stdout", DC_SMB_SCAN_ARGV),
    ),
)
def test_cli_exposes_only_preflight_and_exact_dc_scan(
    tmp_path, command, artifact, expected_argv
):
    dell = FakeDell()
    if command == "scan-dc":
        dell.kali.output = SMB_XML_DC_FIXTURE
    stdout = io.StringIO()

    status = main(
        [command, "--run-root", str(tmp_path)],
        connector=FakeConnector(dell),
        stdout=stdout,
        encryptor=FakeEncryptor(),
    )

    assert status == 0
    expected_commands = (
        [KALI_INVENTORY_ARGV]
        if command == "preflight"
        else [KALI_INVENTORY_ARGV, expected_argv]
    )
    assert dell.kali.commands == expected_commands
    summary = json.loads(stdout.getvalue())
    run_path = Path(summary["run_directory"])
    expected_artifact = _inventory_fixture() if command == "preflight" else SMB_XML_DC_FIXTURE
    artifact_path = run_path / (artifact if command == "preflight" else artifact + ".age")
    stored = artifact_path.read_bytes()
    assert (stored if command == "preflight" else _fake_decrypt(stored)) == expected_artifact
    if command == "scan-dc":
        typed_raw = _fake_decrypt((run_path / "dc-smb-security.typed.json.age").read_bytes())
        typed = json.loads(typed_raw)
        assert typed["collection_state"] == "unmetered_lab_acceptance"
        assert typed["confirmed_vulnerability"] is False
    assert summary["status"] == "passed"


def test_cli_portcast_preflight_cannot_open_the_target(tmp_path):
    dell = FakeDell()
    stdout = io.StringIO()

    status = main(
        ["preflight-portcast", "--run-root", str(tmp_path)],
        connector=FakeConnector(dell),
        stdout=stdout,
    )

    assert status == 0
    assert dell.kali.commands == [
        KALI_OPENSSH_INVENTORY_ARGV,
        KALI_PORTCAST_RELAY_POLICY_ARGV,
    ]
    assert dell.kali.alternate_denial_checks == 1
    assert dell.kali.portcast_channels == 0
    summary = json.loads(stdout.getvalue())
    assert summary["command"] == "preflight-portcast"
    assert summary["status"] == "passed"
    run_path = Path(summary["run_directory"])
    assert sorted(path.name for path in run_path.iterdir()) == ["transcript.jsonl"]


def test_failed_remote_command_stores_capped_stdout_and_stderr_before_raising(tmp_path):
    dell = FakeDell()
    dell.kali.output = CommandOutput(
        stdout=b"partial-output",
        stderr=b"remote-error",
        status=2,
    )
    run = RunDirectory.create(tmp_path, encryptor=FakeEncryptor())

    with pytest.raises(RuntimeError, match="rc=2"):
        with LabSession(connector=FakeConnector(dell), run_directory=run) as session:
            session.preflight_inventory()
            session.run_scan("dc-smb-security", "10.0.1.6")
    run.close()

    assert _fake_decrypt((run.path / "dc-smb-security.stdout.age").read_bytes()) == b"partial-output"
    assert _fake_decrypt((run.path / "dc-smb-security.stderr.age").read_bytes()) == b"remote-error"


def test_incomplete_remote_capture_is_stored_and_fails_closed(tmp_path):
    dell = FakeDell()
    dell.kali.output = CommandOutput(
        stdout=b"partial-output",
        stderr=b"",
        status=0,
        capture_complete=False,
        stdout_total_bytes=20000,
        stderr_total_bytes=0,
    )
    run = RunDirectory.create(tmp_path, encryptor=FakeEncryptor())

    with pytest.raises(TransportError, match="incomplete"):
        with LabSession(connector=FakeConnector(dell), run_directory=run) as session:
            session.preflight_inventory()
            session.run_scan("dc-smb-security", "10.0.1.6")
    run.close()

    assert _fake_decrypt((run.path / "dc-smb-security.stdout.age").read_bytes()) == b"partial-output"


def test_live_session_rejects_endpoint_or_remote_name_drift_before_connecting():
    connector = FakeConnector(FakeDell())
    changed_endpoint = replace(DEFAULT_CONFIG.dell, host="100.64.0.1")

    with pytest.raises(ValueError, match="pinned"):
        LabSession(connector=connector, config=replace(DEFAULT_CONFIG, dell=changed_endpoint))

    assert connector.connect_calls == []


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("encrypted_path", Path("/home/moriz/.config/credstore.encrypted/other.cred")),
        ("credential_name", "other-credential"),
        ("secret_key", "password"),
    ),
)
@pytest.mark.parametrize("side", ("dell_credential", "kali_credential"))
def test_live_session_rejects_any_credential_reference_drift_before_connecting(
    field, replacement, side
):
    connector = FakeConnector(FakeDell())
    changed = replace(getattr(DEFAULT_CONFIG, side), **{field: replacement})

    with pytest.raises(ValueError, match="pinned"):
        LabSession(
            connector=connector,
            config=replace(DEFAULT_CONFIG, **{side: changed}),
        )

    assert connector.connect_calls == []
