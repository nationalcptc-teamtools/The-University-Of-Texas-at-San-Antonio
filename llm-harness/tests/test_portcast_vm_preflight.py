from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re

import pytest

from testing.cptc11_lab.transport import DEFAULT_CONFIG, PreflightRejected, TransportError
from testing.cptc11_lab.portcast_vm_preflight import (
    PORTCAST_VM_PREFLIGHT_SCRIPT,
    RAW_OUTPUT_CAP,
    main,
    parse_portcast_vm_preflight,
    run_portcast_vm_preflight,
)


FIELDS = (
    "hostname",
    "pveversion",
    "status",
    "config",
    "snapshots",
    "bridge_link",
    "bridge_ports",
    "bridge_addresses",
    "bridge_routes",
    "network_namespaces",
    "lifecycle_process_count",
)


def _field(label: str, value: bytes) -> bytes:
    return label.encode("ascii") + b"\t" + base64.b64encode(value) + b"\n"


def _payload(**changes: bytes) -> bytes:
    values = {
        "hostname": b"dell-prox\n",
        "pveversion": b"pve-manager/9.2.4/abcdef0123456789\n",
        "status": b"status: running\n",
        "config": (
            b"agent: 0\n"
            b"balloon: 0\n"
            b"name: PortCast\n"
            b"net0: virtio=52:54:00:11:01:06,bridge=vmbr110\n"
            b"onboot: 0\n"
        ),
        "snapshots": (
            b"`-> cptc11_00_imported_verified 2026-09-01 13:01:00\n"
            b" `-> cptc11_10_regional_clean 2026-09-01 14:31:00\n"
            b"  `-> current You are here!\n"
        ),
        "bridge_link": json.dumps(
            [
                {
                    "ifindex": 25,
                    "ifname": "vmbr110",
                    "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                    "operstate": "UP",
                    "linkinfo": {"info_kind": "bridge"},
                }
            ],
            separators=(",", ":"),
        ).encode(),
        "bridge_ports": json.dumps(
            [
                {
                    "ifindex": 31,
                    "ifname": "tap1106i0",
                    "master": "vmbr110",
                    "operstate": "UP",
                }
            ],
            separators=(",", ":"),
        ).encode(),
        "bridge_addresses": json.dumps(
            [
                {
                    "ifindex": 25,
                    "ifname": "vmbr110",
                    "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                    "addr_info": [
                        {
                            "family": "inet6",
                            "local": "fe80::1",
                            "prefixlen": 64,
                            "scope": "link",
                        }
                    ],
                }
            ],
            separators=(",", ":"),
        ).encode(),
        "bridge_routes": json.dumps(
            [
                {
                    "dst": "fe80::/64",
                    "dev": "vmbr110",
                    "scope": "link",
                }
            ],
            separators=(",", ":"),
        ).encode(),
        "network_namespaces": b"",
        "lifecycle_process_count": b"0\n",
    }
    values.update(changes)
    return (
        b"HARBINGER_PORTCAST_VM_PREFLIGHT_V1\n"
        + b"".join(_field(name, values[name]) for name in FIELDS)
        + b"HARBINGER_PORTCAST_VM_PREFLIGHT_END\n"
    )


class FakeEncryptor:
    def __init__(self) -> None:
        self.inputs: list[bytes] = []

    def encrypt(self, value: bytes) -> bytes:
        self.inputs.append(value)
        return b"age-encryption.org/v1\n" + base64.b64encode(value)


class FakeDell:
    def __init__(self, response: tuple[int, bytes, bytes]) -> None:
        self.response = response
        self.calls: list[tuple[str, float]] = []
        self.closed = False

    def _execute_script(self, script: str, *, timeout: float = 30):
        self.calls.append((script, timeout))
        return self.response

    def close(self) -> None:
        self.closed = True


class FakeConnector:
    def __init__(self, connection: FakeDell) -> None:
        self.connection = connection
        self.calls = []

    def connect(self, endpoint, credential, transcript):
        self.calls.append((endpoint, credential, transcript))
        return self.connection


class ExplodingConnector:
    def __init__(self, error_type=RuntimeError) -> None:
        self.error_type = error_type

    def connect(self, endpoint, credential, transcript):
        raise self.error_type("RAW_CLIENT_OUTPUT token=secret")


class ExplodingDell(FakeDell):
    def __init__(self, *, fail_at: str, error_type=RuntimeError) -> None:
        super().__init__((0, _payload(), b""))
        self.fail_at = fail_at
        self.error_type = error_type
        self.close_calls = 0

    def _execute_script(self, script: str, *, timeout: float = 30):
        if self.fail_at == "execute":
            raise self.error_type("RAW_CLIENT_OUTPUT token=secret")
        return super()._execute_script(script, timeout=timeout)

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True
        if self.fail_at == "close":
            raise self.error_type("RAW_CLIENT_OUTPUT token=secret")


class ExplodingEncryptor:
    def __init__(self, error_type=RuntimeError) -> None:
        self.error_type = error_type

    def encrypt(self, value: bytes) -> bytes:
        raise self.error_type("RAW_CLIENT_OUTPUT token=secret")


def test_parser_returns_only_sanitized_fixed_identity() -> None:
    result = parse_portcast_vm_preflight(_payload())

    assert result.to_dict() == {
        "schema_version": 1,
        "dell_hostname": "dell-prox",
        "pve_version": "pve-manager/9.2.4",
        "vmid": 1106,
        "name": "PortCast",
        "status": "running",
        "bridge": "vmbr110",
        "mac": "52:54:00:11:01:06",
        "snapshots": [
            "cptc11_00_imported_verified",
            "cptc11_10_regional_clean",
        ],
        "bridge_up": True,
        "portcast_tap_present": True,
        "host_ipv4": False,
        "routed_ipv4": False,
        "network_namespace_count": 0,
        "lifecycle_process_count": 0,
        "vm_locked": False,
    }
    rendered = json.dumps(result.to_dict(), sort_keys=True)
    assert "agent:" not in rendered
    assert "current You are here" not in rendered
    assert "abcdef0123456789" not in rendered


def test_parser_accepts_current_pveversion_shape_but_returns_no_build_or_kernel() -> None:
    result = parse_portcast_vm_preflight(
        _payload(
            pveversion=(
                b"pve-manager/9.2.4/abcdef0123456789 "
                b"(running kernel: 7.0.14-4-pve)\n"
            )
        )
    )
    assert result.pve_version == "pve-manager/9.2.4"


def test_parser_accepts_filtered_link_local_routes_when_ip_omits_device_field() -> None:
    result = parse_portcast_vm_preflight(
        _payload(
            bridge_routes=(
                b'[{"dst":"fe80::/64","scope":"link"},'
                b'{"type":"local","dst":"fe80::1","table":"local"},'
                b'{"type":"multicast","dst":"ff00::/8","table":"local"}]'
            )
        )
    )
    assert result.to_dict()["routed_ipv4"] is False


@pytest.mark.parametrize(
    "raw",
    (
        b"",
        b"HARBINGER_PORTCAST_VM_PREFLIGHT_V1\n",
        _payload() + b"trailing\n",
        _payload().replace(b"hostname\t", b"unknown\t", 1),
        _payload().replace(b"hostname\t", b"hostname\t@@", 1),
        _payload().replace(
            b"HARBINGER_PORTCAST_VM_PREFLIGHT_END\n",
            _field("hostname", b"dell-prox\n")
            + b"HARBINGER_PORTCAST_VM_PREFLIGHT_END\n",
        ),
    ),
)
def test_parser_rejects_malformed_unknown_duplicate_or_injected_output(raw: bytes) -> None:
    with pytest.raises(PreflightRejected):
        parse_portcast_vm_preflight(raw)


@pytest.mark.parametrize(
    "changes",
    (
        {"hostname": b"other-host\n"},
        {"status": b"status: stopped\n"},
        {"config": b"name: Other\nnet0: virtio=52:54:00:11:01:06,bridge=vmbr110\n"},
        {"config": b"name: PortCast\nnet0: virtio=52:54:00:11:01:06,bridge=vmbr111\n"},
        {"config": b"name: PortCast\nnet0: virtio=52:54:00:11:01:07,bridge=vmbr110\n"},
        {
            "config": (
                b"agent: 1\nname: PortCast\n"
                b"net0: virtio=52:54:00:11:01:06,bridge=vmbr110\n"
                b"onboot: 0\n"
            )
        },
        {
            "snapshots": (
                b"`-> cptc11_00_imported_verified 2026-09-01\n"
                b" `-> current You are here!\n"
            )
        },
        {
            "config": (
                b"name: PortCast\n"
                b"net0: virtio=52:54:00:11:01:06,bridge=vmbr110\n"
                b"lock: snapshot-delete\n"
            )
        },
        {"network_namespaces": b"hbg-cptc11-vdi (id: 0)\n"},
        {"lifecycle_process_count": b"1\n"},
    ),
)
def test_parser_rejects_identity_state_snapshot_lock_namespace_and_process_drift(
    changes: dict[str, bytes],
) -> None:
    with pytest.raises(PreflightRejected):
        parse_portcast_vm_preflight(_payload(**changes))


@pytest.mark.parametrize(
    "changes",
    (
        {
            "bridge_link": (
                b'[{"ifname":"vmbr111","flags":["UP"],'
                b'"linkinfo":{"info_kind":"bridge"}}]'
            )
        },
        {"bridge_ports": b'[{"ifname":"eno1","master":"vmbr110"}]'},
        {"bridge_ports": b'[{"ifname":"tap1105i0","master":"vmbr110"}]'},
        {
            "bridge_addresses": (
                b'[{"ifname":"vmbr110","addr_info":['
                b'{"family":"inet","local":"10.0.1.2","scope":"global"}]}]'
            )
        },
        {
            "bridge_routes": b'[{"dst":"default","gateway":"10.0.1.1","dev":"vmbr110"}]'
        },
        {"bridge_routes": b'[{"dst":"2001:db8::/64","dev":"vmbr110"}]'},
        {"bridge_routes": b'[{"dst":"fe80::/64","dev":"vmbr111"}]'},
    ),
)
def test_parser_rejects_bridge_or_route_drift(changes: dict[str, bytes]) -> None:
    with pytest.raises(PreflightRejected):
        parse_portcast_vm_preflight(_payload(**changes))


def test_run_uses_exact_pinned_connector_encrypts_raw_and_writes_utc_transcript(
    tmp_path: Path,
) -> None:
    dell = FakeDell((0, _payload(), b""))
    connector = FakeConnector(dell)
    encryptor = FakeEncryptor()

    value = run_portcast_vm_preflight(
        run_root=tmp_path,
        connector=connector,
        encryptor=encryptor,
    )

    assert connector.calls[0][:2] == (DEFAULT_CONFIG.dell, DEFAULT_CONFIG.dell_credential)
    assert dell.calls == [(PORTCAST_VM_PREFLIGHT_SCRIPT, 20.0)]
    assert dell.closed is True
    assert value["status"] == "passed"
    assert value["result"]["name"] == "PortCast"
    run = Path(value["run_directory"])
    artifact = run / "portcast-vm-1106-preflight.raw.age"
    assert artifact.read_bytes().startswith(b"age-encryption.org/v1\n")
    assert _payload() not in artifact.read_bytes()
    assert len(encryptor.inputs) == 1
    raw_frame = json.loads(encryptor.inputs[0])
    assert base64.b64decode(raw_frame["stdout_base64"], validate=True) == _payload()
    transcript = [json.loads(line) for line in (run / "transcript.jsonl").read_text().splitlines()]
    assert [row["event"] for row in transcript] == [
        "vm_preflight.start",
        "vm_preflight.capture",
        "vm_preflight.finish",
    ]
    assert all(re.fullmatch(r"\d{4}-\d{2}-\d{2}T.*Z", row["timestamp"]) for row in transcript)
    assert [row["sequence"] for row in transcript] == [1, 2, 3]
    assert all(os.stat(run / name).st_mode & 0o077 == 0 for name in (
        "transcript.jsonl", "portcast-vm-1106-preflight.raw.age", "result.json"
    ))
    assert json.loads((run / "result.json").read_text()) == value["result"]
    transcript_text = (run / "transcript.jsonl").read_text()
    assert "credential" not in transcript_text
    assert str(DEFAULT_CONFIG.dell_credential.encrypted_path) not in transcript_text


@pytest.mark.parametrize(
    "response",
    (
        (0, b"x" * (RAW_OUTPUT_CAP + 1), b""),
        (0, _payload(), b"unexpected warning"),
        (1, _payload(), b""),
    ),
)
def test_run_rejects_output_limit_stderr_or_nonzero_status_without_plaintext(
    tmp_path: Path, response: tuple[int, bytes, bytes]
) -> None:
    connector = FakeConnector(FakeDell(response))
    encryptor = FakeEncryptor()
    with pytest.raises((PreflightRejected, TransportError)):
        run_portcast_vm_preflight(
            run_root=tmp_path,
            connector=connector,
            encryptor=encryptor,
        )
    for path in tmp_path.rglob("*"):
        if path.is_file() and path.name != "transcript.jsonl":
            assert _payload() not in path.read_bytes()


def test_fixed_script_contains_only_reviewed_read_only_commands_and_no_target_path() -> None:
    assert PORTCAST_VM_PREFLIGHT_SCRIPT.count("/usr/sbin/qm status 1106") == 1
    assert PORTCAST_VM_PREFLIGHT_SCRIPT.count("/usr/sbin/qm config 1106") == 1
    assert PORTCAST_VM_PREFLIGHT_SCRIPT.count("/usr/sbin/qm listsnapshot 1106") == 1
    assert "/usr/sbin/ip -details -json link show dev vmbr110" in PORTCAST_VM_PREFLIGHT_SCRIPT
    assert "/usr/sbin/bridge -json link show master vmbr110" in PORTCAST_VM_PREFLIGHT_SCRIPT
    assert "/usr/sbin/ip netns list" in PORTCAST_VM_PREFLIGHT_SCRIPT
    assert "10.0.1.30" not in PORTCAST_VM_PREFLIGHT_SCRIPT
    assert "8096" not in PORTCAST_VM_PREFLIGHT_SCRIPT
    assert not re.search(
        r"/usr/sbin/qm\s+(?:start|stop|shutdown|reset|reboot|suspend|resume|"
        r"snapshot|rollback|delsnapshot|destroy|set|clone|move_disk|terminal|"
        r"monitor|guest|vncproxy)\b",
        PORTCAST_VM_PREFLIGHT_SCRIPT,
    )
    for token in (
        "curl", "wget", "nc ", "ncat", "socat", "ssh ", "qm agent", "qm terminal"
    ):
        assert token not in PORTCAST_VM_PREFLIGHT_SCRIPT


@pytest.mark.parametrize("argv", (["1106"], ["--command", "qm stop 1106"], ["scan"]))
def test_cli_rejects_every_command_or_target_token_before_connecting(argv: list[str]) -> None:
    connector = FakeConnector(FakeDell((0, _payload(), b"")))
    with pytest.raises(SystemExit, match="accepts no arguments"):
        main(argv, connector=connector, encryptor=FakeEncryptor())
    assert connector.calls == []


@pytest.mark.parametrize("failure", ("connect", "execute", "close", "encrypt"))
def test_dependency_exceptions_are_sanitized_and_never_enter_readable_output(
    tmp_path: Path, failure: str
) -> None:
    dell = ExplodingDell(fail_at=failure)
    connector = ExplodingConnector() if failure == "connect" else FakeConnector(dell)
    encryptor = ExplodingEncryptor() if failure == "encrypt" else FakeEncryptor()

    with pytest.raises(TransportError) as raised:
        run_portcast_vm_preflight(
            run_root=tmp_path,
            connector=connector,
            encryptor=encryptor,
        )

    assert "RAW_CLIENT_OUTPUT" not in str(raised.value)
    assert "token=secret" not in str(raised.value)
    for path in tmp_path.rglob("*"):
        if path.is_file():
            content = path.read_bytes()
            assert b"RAW_CLIENT_OUTPUT" not in content
            assert b"token=secret" not in content
    if failure in {"execute", "close", "encrypt"}:
        assert dell.close_calls == 1


@pytest.mark.parametrize("failure", ("connect", "execute", "close", "encrypt"))
def test_keyboard_interrupt_dependency_failures_are_sanitized_and_close_once(
    tmp_path: Path, failure: str
) -> None:
    dell = ExplodingDell(fail_at=failure, error_type=KeyboardInterrupt)
    connector = (
        ExplodingConnector(KeyboardInterrupt)
        if failure == "connect"
        else FakeConnector(dell)
    )
    encryptor = (
        ExplodingEncryptor(KeyboardInterrupt)
        if failure == "encrypt"
        else FakeEncryptor()
    )

    with pytest.raises(TransportError, match="failed safely") as raised:
        run_portcast_vm_preflight(
            run_root=tmp_path,
            connector=connector,
            encryptor=encryptor,
        )

    assert "RAW_CLIENT_OUTPUT" not in str(raised.value)
    assert "token=secret" not in str(raised.value)
    if failure in {"execute", "close", "encrypt"}:
        assert dell.close_calls == 1


def test_public_sanitizer_contains_dependency_system_exit(tmp_path: Path) -> None:
    with pytest.raises(TransportError, match="failed safely"):
        run_portcast_vm_preflight(
            run_root=tmp_path,
            connector=ExplodingConnector(SystemExit),
            encryptor=FakeEncryptor(),
        )


@pytest.mark.parametrize("error_type", (RuntimeError, KeyboardInterrupt, SystemExit))
def test_cli_returns_fixed_json_for_unexpected_dependency_failure(
    tmp_path: Path, error_type
) -> None:
    from io import StringIO

    output = StringIO()
    status = main(
        [],
        stdout=output,
        connector=ExplodingConnector(error_type),
        encryptor=FakeEncryptor(),
        run_root=tmp_path,
    )

    assert status == 2
    rendered = output.getvalue()
    assert json.loads(rendered) == {
        "reason": "PortCast VM preflight failed safely",
        "status": "failed",
    }
    assert "RAW_CLIENT_OUTPUT" not in rendered
    assert "token=secret" not in rendered
