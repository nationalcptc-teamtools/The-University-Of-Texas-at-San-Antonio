"""Read-only network snapshots, privacy, imported claims and loopback TCP checks."""

import asyncio
import io
import json
import os
import socket
import sys
from pathlib import Path

import pytest
from rich.console import Console

from fieldkit.core.local import LocalContext
from fieldkit.core.process import ProcessResult, run_process
from fieldkit.core.vantage import (
    collect_metadata,
    parse_interfaces,
    parse_resolver,
    parse_routes,
    safe_read,
)
from fieldkit.modules.network_vantage import NetworkVantage, tcp_check


def run(tmp_path, **overrides):
    module = NetworkVantage()
    settings = {
        **module.defaults(),
        "OUTPUT": str(tmp_path / "runs"),
        "TIMEOUT": 1,
        "HOST_ID": "local-fixture",
        **overrides,
    }
    console = io.StringIO()
    code = module.run(settings, Console(file=console))
    path = max((tmp_path / "runs").glob("*/report.json"), key=lambda p: p.stat().st_mtime_ns)
    return code, json.loads(path.read_text()), path.parent, console.getvalue()


@pytest.fixture
def commands(monkeypatch):
    seen = []
    metadata = {
        "identity": {"hostname": "local-real-name", "uid": 1000, "network_namespace": "net:[123]"},
        "resolver": {"nameservers": ["127.0.0.53"], "search": ["fixture.test"]},
        "interfaces": [
            {
                "name": "ligolo-db",
                "exists": True,
                "tun": True,
                "admin_up": True,
                "operstate": "unknown",
                "persistent": True,
                "multiqueue": False,
            }
        ],
        "processes": [
            {
                "pid": 41,
                "comm": "proxy",
                "active_tunnel_verified": False,
                "established_tcp_sockets": 1,
            }
        ],
        "tun_owners": [
            {
                "interface": "ligolo-db",
                "pid": 41,
                "comm": "proxy",
                "uid": 1000,
                "namespace_matches": True,
                "attachment_observed": True,
            }
        ],
        "coverage": {"truncated": False, "processes_denied": 1},
    }

    async def command(ctx, category, argv, **kwargs):
        seen.append((category, argv))
        if category == "network_metadata":
            data = json.dumps(metadata).encode()
        elif category == "network_links":
            data = json.dumps(
                [
                    {
                        "ifname": "ligolo-db",
                        "ifindex": 7,
                        "flags": ["UP"],
                        "operstate": "UNKNOWN",
                        "link_type": "none",
                        "linkinfo": {"info_kind": "tun"},
                    }
                ]
            ).encode()
        elif category == "network_addresses":
            data = json.dumps(
                [
                    {
                        "ifname": "ligolo-db",
                        "flags": ["UP"],
                        "addr_info": [{"local": "192.0.2.1", "prefixlen": 24, "scope": "global"}],
                    }
                ]
            ).encode()
        elif category == "network_routes_ipv4":
            data = b'[{"dst":"10.64.3.10","dev":"ligolo-db","scope":"link"}]'
        elif category == "network_routes_ipv6":
            data = b'[{"dst":"2001:db8:10::/64","dev":"ligolo-db","scope":"link"}]'
        elif category == "target_route":
            data = json.dumps([{"dst": argv[-1], "dev": "ligolo-db"}]).encode()
        elif category == "target_dns":
            data = b"192.0.2.10 STREAM example\n192.0.2.10 DGRAM example\n"
        else:
            pytest.fail(f"Unexpected collector {category} {argv}")
        result = ProcessResult(stdout=bytearray(data), returncode=0, reason="finished")
        evidence = ctx.evidence({"argv": argv, "stdout": data.decode()}, source=category)
        return result, evidence

    monkeypatch.setattr(LocalContext, "command", command)
    monkeypatch.setattr("fieldkit.modules.network_vantage.shutil.which", lambda name: "/usr/bin/ip")
    return seen, metadata


def test_vantage_separates_tun_up_process_attachment_route_and_reachability(
    tmp_path, commands, monkeypatch
):
    monkeypatch.setattr(
        "fieldkit.modules.network_vantage.tcp_check",
        lambda *args: pytest.fail("implicit TCP probe"),
    )
    code, report, directory, printed = run(
        tmp_path, TARGETS=["10.64.3.10"], PORTS=["445"], DEVICE="ligolo-db"
    )
    assert code == 0 and "local-fixture" in printed and "ligolo-db" in printed
    vantage = report["vantage"]
    assert vantage["identity"]["hostname"] == "local-real-name"
    assert vantage["interfaces"][0]["admin_up"] and vantage["interfaces"][0]["tun"]
    assert vantage["tunnels"][0]["attachment_observed"]
    assert not vantage["tunnels"][0]["active_tunnel_verified"]
    assert vantage["targets"][0]["tcp"][0]["outcome"] == "not_probed"
    assert vantage["targets"][0]["routes"][0]["records"][0]["device"] == "ligolo-db"
    assert any(d["kind"] == "existing_tunnel_device" for d in report["diagnostics"])
    assert not report["findings"]
    assert directory.stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in directory.rglob("*.json"))
    for _category, argv in commands[0]:
        assert not any(
            part in {"add", "del", "delete", "set", "flush", "exec", "kill"} for part in argv
        )
        assert isinstance(argv, list)


def test_route_snapshots_include_both_families_and_explicit_coverage(tmp_path, commands):
    code, report, _, _ = run(tmp_path)
    assert code == 0
    assert [(r["family"], r["destination"]) for r in report["vantage"]["routes"]] == [
        ("ipv4", "10.64.3.10/32"),
        ("ipv6", "2001:db8:10::/64"),
    ]
    snapshots = {
        item["family"]: item
        for item in report["coverage"]
        if item["category"] == "route_family_visibility"
    }
    assert set(snapshots) == {"ipv4", "ipv6"}
    assert all(
        item["status"] == "finished" and item["retained"] == 1 and not item["truncated"]
        for item in snapshots.values()
    )
    route_commands = [
        argv for category, argv in commands[0] if category.startswith("network_routes_")
    ]
    assert [argv[2] for argv in route_commands] == ["-4", "-6"]


def test_route_ceiling_applies_across_families_and_marks_later_family(tmp_path, commands):
    code, report, _, _ = run(tmp_path, MAX_ROUTES=1)
    assert code == 1 and not report["completed"]
    assert len(report["vantage"]["routes"]) == 1
    snapshots = {
        item["family"]: item
        for item in report["coverage"]
        if item["category"] == "route_family_visibility"
    }
    assert snapshots["ipv4"]["retained"] == 1 and not snapshots["ipv4"]["truncated"]
    assert snapshots["ipv6"]["retained"] == 0 and snapshots["ipv6"]["truncated"]
    assert any(
        error["error"] == "record_limit" and error["resource"] == "ipv6"
        for error in report["errors"]
    )


def test_malformed_ipv6_snapshot_keeps_ipv4_and_marks_family(tmp_path, commands, monkeypatch):
    original = LocalContext.command

    async def command(ctx, category, argv, **kwargs):
        result, evidence = await original(ctx, category, argv, **kwargs)
        if category == "network_routes_ipv6":
            result.stdout = bytearray(b"not-json")
        return result, evidence

    monkeypatch.setattr(LocalContext, "command", command)
    code, report, _, _ = run(tmp_path)
    assert code == 1
    assert [r["family"] for r in report["vantage"]["routes"]] == ["ipv4"]
    assert any(
        item["category"] == "route_family_visibility"
        and item["family"] == "ipv6"
        and item["status"] == "malformed"
        for item in report["coverage"]
    )


def test_dry_run_suppresses_dns_and_tcp_but_keeps_local_readonly_routes(
    tmp_path, commands, monkeypatch
):
    monkeypatch.setattr(
        "fieldkit.modules.network_vantage.tcp_check", lambda *args: pytest.fail("dry-run TCP probe")
    )
    code, report, _, _ = run(
        tmp_path, TARGETS=["example.test", "10.64.3.10"], PORTS=["445"], PROBE=True, DRY_RUN=True
    )
    assert code == 0 and report["plan"]["tcp_probes"] == report["plan"]["dns_lookups"] == 0
    assert not any(category == "target_dns" for category, argv in commands[0])
    assert report["vantage"]["targets"][0]["dns"]["outcome"] == "not_resolved_dry_run"
    assert all(c["outcome"] == "not_probed" for t in report["vantage"]["targets"] for c in t["tcp"])


def test_local_dns_and_reported_other_host_comparison_never_access_other_host(tmp_path, commands):
    imported = tmp_path / "pivot.json"
    imported.write_text(
        json.dumps(
            {
                "host": "reported-pivot",
                "observed_at": "2026-01-01T00:00:00Z",
                "interfaces": [{"name": "tun9", "admin_up": True}],
                "tunnels": [
                    {"interface": "tun9", "state": "active", "token": "import-private-token"}
                ],
                "password": "import-private-secret",
                "cmdline": "--secret import-private-command",
                "targets": [
                    {
                        "target": "example.test",
                        "dns": {"addresses": ["192.0.2.20"]},
                        "tcp": [{"address": "192.0.2.20", "port": 445, "outcome": "reachable"}],
                    }
                ],
            }
        )
    )
    code, report, directory, _ = run(
        tmp_path, TARGETS=["example.test"], PORTS=["445"], IMPORT=[str(imported)]
    )
    assert code == 0 and len(report["reported_vantages"]) == 1
    remote = report["reported_vantages"][0]
    assert remote["provenance"] == "reported" and remote["tunnels"][0]["reported_state"] == "active"
    assert not remote["tunnels"][0]["active_tunnel_verified"]
    comparison = report["vantage_comparison"]
    assert comparison[0]["provenance"] == "local_plan"
    assert comparison[1]["provenance"] == "reported" and comparison[1]["outcome"] == "reachable"
    assert any(d["kind"] == "different_reported_vantage" for d in report["diagnostics"])
    assert any(d["kind"] == "different_reported_dns" for d in report["diagnostics"])
    assert all("reported-pivot" not in argv for category, argv in commands[0])
    saved = "".join(p.read_text() for p in directory.rglob("*.json"))
    assert not any(
        value in saved
        for value in ("import-private-token", "import-private-secret", "import-private-command")
    )
    assert remote["source_sha256"]


def test_import_own_report_and_claims_are_still_reported(tmp_path, commands):
    _, _, directory, _ = run(tmp_path)
    code, report, _, _ = run(tmp_path, IMPORT=[str(directory / "report.json")])
    assert code == 0 and report["reported_vantages"][0]["host"] == "local-fixture"
    assert report["reported_vantages"][0]["provenance"] == "reported"


def test_missing_ip_retains_sysfs_metadata_and_marks_coverage(tmp_path, commands, monkeypatch):
    monkeypatch.setattr("fieldkit.modules.network_vantage.shutil.which", lambda name: None)
    code, report, _, _ = run(tmp_path, TARGETS=["10.64.3.10"])
    assert code == 1 and report["vantage"]["interfaces"][0]["tun"]
    assert any(error["error"] == "missing_dependency" for error in report["errors"])
    assert not any(category.startswith("network_links") for category, argv in commands[0])


@pytest.mark.parametrize(
    "overrides",
    [
        {"TARGETS": ["10.0.0.1;id"]},
        {"TARGETS": ["https://example.test"]},
        {"TARGETS": ["--help"]},
        {"TARGETS": ["10.0.0.1/24"]},
        {"TARGETS": ["fe80::1%eth0"]},
        {"PORTS": ["1-65535"]},
        {"PORTS": ["0"]},
        {"PROBE": True},
        {"PROBE": True, "TARGETS": ["10.64.3.10"], "PORTS": ["80", "443"], "MAX_PROBES": 1},
        {"MAX_HOSTS": 0},
        {"DEVICE": "tun0;id"},
    ],
)
def test_inputs_reject_expansion_or_unbounded_probes_before_commands(
    tmp_path, monkeypatch, overrides
):
    monkeypatch.setattr(
        LocalContext, "command", lambda *args: pytest.fail("invalid input launched collector")
    )
    with pytest.raises(ValueError):
        run(tmp_path, **overrides)


def test_malformed_and_oversize_imports_rejected(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text(
        '{"host":"remote","targets":[{"target":"10.64.3.10","tcp":['
        '{"address":"192.0.2.1","port":445,"outcome":"reachable"}]}]}'
    )
    with pytest.raises(ValueError, match="disagrees"):
        run(tmp_path, IMPORT=[str(path)])
    path.write_text("X" * 1025)
    with pytest.raises(ValueError, match="byte limit"):
        run(tmp_path, IMPORT=[str(path)], MAX_BYTES=1024)


def test_ip_parsers_keep_only_network_fields_and_validate_shape():
    links, truncated = parse_interfaces(
        [
            {
                "ifname": "tun0",
                "flags": ["UP"],
                "operstate": "UNKNOWN",
                "linkinfo": {"info_kind": "tun", "secret": "omit"},
                "password": "omit",
                "addr_info": [{"local": "192.0.2.1", "prefixlen": 24}],
            }
        ],
        1,
    )
    assert not truncated and links[0]["admin_up"] and links[0]["tunnel_kind"] == "tun"
    assert "omit" not in json.dumps(links)
    routes, truncated = parse_routes(
        [
            {"dst": "10.64.3.10", "dev": "tun0", "gateway": "192.0.2.1"},
            {"dst": "default", "dev": "eth0"},
        ],
        1,
    )
    assert truncated and routes[0]["destination"] == "10.64.3.10/32"
    with pytest.raises(ValueError):
        parse_interfaces([{"ifname": "../bad", "flags": []}], 2)
    with pytest.raises(ValueError):
        parse_routes([{"dst": "bad"}], 2)
    resolver = parse_resolver(
        "nameserver 127.0.0.53\nsearch fixture.test\nhosts: files dns\nsecret token\n"
    )
    assert resolver["nameservers"] == ["127.0.0.53"] and resolver["hosts_sources"] == [
        "files",
        "dns",
    ]


def fixture_metadata(tmp_path, namespace="net:[123]"):
    sysroot, procroot, etcroot = tmp_path / "sys", tmp_path / "proc", tmp_path / "etc"
    (sysroot / "tun0").mkdir(parents=True)
    for name, value in {
        "operstate": "unknown",
        "flags": "0x10001",
        "tun_flags": "0x1801",
        "carrier": "1",
        "mtu": "1500",
        "ifindex": "7",
    }.items():
        (sysroot / "tun0" / name).write_text(value)
    (procroot / "self/ns").mkdir(parents=True)
    (procroot / "self/ns/net").symlink_to("net:[123]")
    (procroot / "net").mkdir()
    (procroot / "net/tcp").write_text(
        "header\n0: 00000000:0000 00000000:0000 01 0 0 0 1000 0 3456\n"
    )
    (procroot / "net/tcp6").write_text("header\n")
    pid = procroot / "51"
    (pid / "fd").mkdir(parents=True)
    (pid / "fdinfo").mkdir()
    (pid / "ns").mkdir()
    (pid / "ns/net").symlink_to(namespace)
    (pid / "comm").write_text("proxy\n")
    (pid / "status").write_text("Name:\tproxy\nState:\tS (sleeping)\nUid:\t1000 1000 1000 1000\n")
    (pid / "cmdline").write_text("--token process-private-token")
    (pid / "environ").write_text("PASSWORD=process-private-password")
    (pid / "fd/10").symlink_to("socket:[3456]")
    (pid / "fd/11").symlink_to("/dev/net/tun")
    (pid / "fd/12").symlink_to("/very/private/file/name")
    (pid / "fdinfo/11").write_text("pos:\t0\niff:\ttun0\n")
    etcroot.mkdir()
    (etcroot / "resolv.conf").write_text("nameserver 127.0.0.53\n")
    (etcroot / "nsswitch.conf").write_text("hosts: files dns\n")
    return {"sysroot": sysroot, "procroot": procroot, "etcroot": etcroot}


def test_proc_sysfs_metadata_never_reads_commandlines_environment_or_fd_paths(
    tmp_path, monkeypatch
):
    fixture = fixture_metadata(tmp_path)
    original = safe_read
    visited = []

    def tracked(path, maximum):
        visited.append(Path(path).name)
        assert Path(path).name not in {"cmdline", "environ"}
        return original(path, maximum)

    monkeypatch.setattr("fieldkit.core.vantage.safe_read", tracked)
    metadata = collect_metadata(**fixture)
    interface = metadata["interfaces"][0]
    assert interface["tun"] and interface["persistent"] and interface["admin_up"]
    owner = metadata["tun_owners"][0]
    assert owner["interface"] == "tun0" and owner["pid"] == 51 and owner["namespace_matches"]
    process = metadata["processes"][0]
    assert process["established_tcp_sockets"] == 1 and not process["active_tunnel_verified"]
    assert process["state"] == "S"
    saved = json.dumps(metadata)
    assert not any(
        value in saved
        for value in (
            "process-private-token",
            "process-private-password",
            "/very/private/file/name",
        )
    )
    assert "cmdline" not in visited


def test_process_namespace_and_count_bounds(tmp_path):
    metadata = collect_metadata(**fixture_metadata(tmp_path, namespace="net:[999]"), max_fds=1)
    assert metadata["coverage"]["truncated"] and metadata["coverage"]["fd_entries_scanned"] == 1
    metadata = collect_metadata(**fixture_metadata(tmp_path / "another", namespace="net:[999]"))
    assert not metadata["tun_owners"][0]["namespace_matches"]
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="regular file"):
        safe_read(fifo, 100)


@pytest.mark.parametrize("extra_process", [False, True])
def test_exact_fd_limit_reports_unscanned_processes(tmp_path, extra_process):
    fixture = fixture_metadata(tmp_path)
    process = fixture["procroot"] / "51"
    (process / "fd/11").unlink()
    (process / "fd/12").unlink()
    if extra_process:
        other = fixture["procroot"] / "52"
        (other / "fd").mkdir(parents=True)
        (other / "comm").write_text("agent\n")
        (other / "fd/10").symlink_to("socket:[3456]")
    metadata = collect_metadata(**fixture, max_fds=1)
    coverage = metadata["coverage"]
    assert coverage["processes_scanned"] == coverage["fd_entries_scanned"] == 1
    assert coverage["truncated"] is extra_process


def test_explicit_loopback_tcp_handshake_and_refusal(tmp_path, commands):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    try:
        code, report, _, _ = run(tmp_path, TARGETS=["127.0.0.1"], PORTS=[str(port)], PROBE=True)
        assert code == 0 and report["vantage"]["targets"][0]["tcp"][0]["outcome"] == "reachable"
        assert report["results"][-1]["tcp_probes"] == 1
        connection, _ = listener.accept()
        assert connection.recv(1) == b""  # Module sends no application bytes.
        connection.close()
    finally:
        listener.close()
    result = asyncio.run(tcp_check("127.0.0.1", port, 1))
    assert result["outcome"] == "refused"


def test_tcp_deadline_closes_socket(monkeypatch):
    closed = []

    class Socket:
        def setblocking(self, flag):
            pass

        def close(self):
            closed.append(True)

    async def exercise():
        loop = asyncio.get_running_loop()

        async def stalled(sock, endpoint):
            await asyncio.sleep(60)

        monkeypatch.setattr(
            "fieldkit.modules.network_vantage.socket.socket", lambda *args: Socket()
        )
        monkeypatch.setattr(loop, "sock_connect", stalled)
        result = await tcp_check("127.0.0.1", 1, 0.01)
        assert result["outcome"] == "timeout"

    asyncio.run(exercise())
    assert closed == [True]


def test_real_metadata_helper_is_bounded_and_emits_allowlisted_json():
    result = asyncio.run(
        run_process(
            [
                sys.executable,
                "-m",
                "fieldkit.core.vantage",
                "--budget",
                "1",
                "--max-processes",
                "64",
                "--max-fds",
                "512",
                "--max-interfaces",
                "64",
            ],
            timeout=2,
            max_output=262144,
        )
    )
    assert result.reason == "finished", bytes(result.stderr)
    metadata = json.loads(result.stdout)
    assert metadata["identity"]["hostname"]
    assert metadata["coverage"]["processes_scanned"] <= 64
    assert metadata["coverage"]["fd_entries_scanned"] <= 512
    assert len(metadata["interfaces"]) <= 64
    assert "cmdline" not in metadata and "environ" not in metadata


def test_budget_expiry_saves_partial_vantage(tmp_path, monkeypatch):
    async def slow(*args, **kwargs):
        await asyncio.sleep(60)

    monkeypatch.setattr(LocalContext, "command", slow)
    code, report, _, _ = run(tmp_path, BUDGET=0.02)
    assert code == 1 and not report["completed"]
    assert report["vantage"]["host"] == "local-fixture"
    assert report["errors"][0]["error"] == "budget_exhausted"
