"""Allowlisted Linux network metadata and parsers; no command lines or credentials."""

import argparse
import ipaddress
import json
import os
import re
import socket
import stat
import time
from itertools import islice
from pathlib import Path

DEVICE = re.compile(r"[A-Za-z0-9_.:-]{1,15}")
AGENTS = {
    "agent",
    "proxy",
    "chisel",
    "ssh",
    "sshd",
    "sshuttle",
    "openvpn",
    "tailscaled",
    "ligolo",
    "ligolo-ng",
    "ligolo-agent",
    "ligolo-proxy",
}
TUNNEL_KINDS = {
    "tun",
    "tap",
    "wireguard",
    "gre",
    "gretap",
    "ipip",
    "sit",
    "vti",
    "vti6",
    "ip6gre",
    "ip6gretap",
    "ip6tnl",
    "vxlan",
    "geneve",
    "l2tp",
}


def target_name(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError("Targets must be explicit IP addresses or DNS hostnames")
    if "%" in value:
        raise ValueError("Scoped IPv6 targets require a separate interface-aware tool")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if re.fullmatch(r"[0-9.]+", value):
            raise ValueError("Invalid numeric IP address") from None
        labels = value.rstrip(".").split(".")
        if not all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("Targets must be explicit IP addresses or DNS hostnames") from None
        return value.lower()


def address(value):
    if isinstance(value, str) and "%" in value:
        return None
    try:
        return str(ipaddress.ip_address(value)) if isinstance(value, str) else None
    except ValueError:
        return None


def parse_interfaces(rows, maximum):
    if not isinstance(rows, list):
        raise ValueError("ip link/address JSON must be a list")
    output = []
    for row in rows[:maximum]:
        if not isinstance(row, dict) or not DEVICE.fullmatch(str(row.get("ifname", ""))):
            raise ValueError("Invalid interface record")
        flags = row.get("flags", [])
        if not isinstance(flags, list) or not all(isinstance(f, str) for f in flags):
            raise ValueError("Invalid interface flags")
        info = row.get("linkinfo", {})
        kind = info.get("info_kind", "") if isinstance(info, dict) else ""
        entry = {
            "name": row["ifname"],
            "ifindex": row.get("ifindex"),
            "admin_up": "UP" in flags,
            "lower_up": "LOWER_UP" in flags,
            "operstate": str(row.get("operstate", "unknown"))[:32].lower(),
            "link_kind": kind if kind in TUNNEL_KINDS else str(row.get("link_type", ""))[:32],
            "tunnel_kind": kind if kind in TUNNEL_KINDS else None,
            "addresses": [],
        }
        addresses = row.get("addr_info", [])
        if not isinstance(addresses, list):
            raise ValueError("Invalid interface address list")
        for item in addresses[:32]:
            if not isinstance(item, dict):
                raise ValueError("Invalid interface address")
            local = address(item.get("local"))
            prefix = item.get("prefixlen")
            if local and type(prefix) is int and 0 <= prefix <= (128 if ":" in local else 32):
                entry["addresses"].append(
                    {
                        "address": local,
                        "prefixlen": prefix,
                        "scope": str(item.get("scope", ""))[:32],
                    }
                )
        output.append(entry)
    return output, len(rows) > maximum


def parse_routes(rows, maximum):
    if not isinstance(rows, list):
        raise ValueError("ip route JSON must be a list")
    output = []
    for row in rows[:maximum]:
        if not isinstance(row, dict):
            raise ValueError("Invalid route record")
        destination = row.get("dst", "default")
        if destination != "default":
            try:
                destination = str(ipaddress.ip_network(destination, strict=False))
            except (TypeError, ValueError) as exc:
                raise ValueError("Invalid route destination") from exc
        entry = {
            "destination": destination,
            "device": row.get("dev"),
            "type": str(row.get("type", "unicast"))[:32],
        }
        if entry["device"] is not None and not DEVICE.fullmatch(str(entry["device"])):
            raise ValueError("Invalid route device")
        for source, key in (("gateway", "gateway"), ("prefsrc", "source"), ("src", "source")):
            if source in row:
                parsed = address(row[source])
                if not parsed:
                    raise ValueError("Invalid route address")
                entry[key] = parsed
        for key in ("table", "metric", "protocol", "scope"):
            if type(row.get(key)) in {str, int}:
                entry[key] = str(row[key])[:64] if isinstance(row[key], str) else row[key]
        output.append(entry)
    return output, len(rows) > maximum


def parse_resolver(text):
    result = {"nameservers": [], "search": [], "hosts_sources": []}
    for line in text.splitlines():
        parts = line.partition("#")[0].split()
        if not parts:
            continue
        if parts[0] == "nameserver" and len(parts) > 1 and address(parts[1]):
            result["nameservers"].append(address(parts[1]))
        elif parts[0] in {"search", "domain"}:
            for domain in parts[1:7]:
                try:
                    result["search"].append(target_name(domain))
                except ValueError:
                    pass
        elif parts[0] == "hosts:":
            result["hosts_sources"] = [
                p for p in parts[1:17] if re.fullmatch(r"[A-Za-z0-9_.=-]+|\[[A-Za-z0-9=!]+\]", p)
            ]
    return result


def safe_read(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("Metadata source is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("Metadata source exceeds byte limit")
        return data.decode("utf-8", errors="replace")
    finally:
        os.close(descriptor)


def collect_metadata(
    *,
    max_interfaces=128,
    max_processes=1024,
    max_fds=4096,
    max_bytes=1048576,
    budget=10,
    sysroot=Path("/sys/class/net"),
    procroot=Path("/proc"),
    etcroot=Path("/etc"),
):
    deadline = time.monotonic() + budget
    coverage = {
        "processes_scanned": 0,
        "fd_entries_scanned": 0,
        "processes_denied": 0,
        "truncated": False,
    }

    def check():
        if time.monotonic() >= deadline:
            raise TimeoutError("Metadata collection deadline")

    def read(path, maximum=4096):
        check()
        return safe_read(path, min(maximum, max_bytes))

    identity = {
        "hostname": socket.gethostname(),
        "uid": os.getuid(),
        "euid": os.geteuid(),
        "gid": os.getgid(),
        "system": os.uname().sysname,
        "release": os.uname().release,
        "machine": os.uname().machine,
    }
    try:
        namespace = os.readlink(procroot / "self/ns/net")
        identity["network_namespace"] = (
            namespace if re.fullmatch(r"net:\[[0-9]+\]", namespace) else "unknown"
        )
    except OSError:
        identity["network_namespace"] = "unavailable"
    resolver = {}
    for name in ("resolv.conf", "nsswitch.conf"):
        try:
            # /etc/resolv.conf is commonly a managed symlink to /run.
            path = (etcroot / name).resolve()
            parsed = parse_resolver(read(path, max_bytes))
            for key, value in parsed.items():
                if value:
                    resolver[key] = value
        except (OSError, ValueError):
            resolver[name + "_available"] = False
    interfaces = []
    try:
        names = list(islice(sysroot.iterdir(), max_interfaces + 1))
    except OSError:
        names = []
        coverage["sysfs_available"] = False
    for path in names[:max_interfaces]:
        check()
        if not DEVICE.fullmatch(path.name):
            continue
        entry = {"name": path.name, "exists": True, "tun": False}
        for key in ("operstate", "flags", "carrier", "ifindex", "mtu", "tun_flags"):
            try:
                value = read(path / key).strip()
                if key == "tun_flags":
                    flags = int(value, 0)
                    entry.update(
                        tun=True,
                        tun_flags=flags,
                        persistent=bool(flags & 0x0800),
                        multiqueue=bool(flags & 0x0100),
                    )
                elif key == "flags":
                    flags = int(value, 0)
                    entry.update(admin_up=bool(flags & 1), lower_up=bool(flags & 0x10000))
                elif key in {"ifindex", "mtu", "carrier"}:
                    entry[key] = int(value)
                else:
                    entry[key] = value[:32]
            except (OSError, ValueError):
                pass
        interfaces.append(entry)
    coverage["truncated"] |= len(names) > max_interfaces
    established = set()
    for family in ("tcp", "tcp6"):
        try:
            text = read(procroot / "net" / family, max_bytes)
            for line in text.splitlines()[1:]:
                columns = line.split()
                if len(columns) > 9 and columns[3] == "01" and columns[9].isdigit():
                    established.add(columns[9])
        except (OSError, ValueError):
            coverage[family + "_available"] = False
    processes, owners = [], []
    try:
        pids = list(islice((p for p in procroot.iterdir() if p.name.isdigit()), max_processes + 1))
    except OSError:
        pids = []
        coverage["proc_available"] = False
    for path in pids[:max_processes]:
        check()
        coverage["processes_scanned"] += 1
        try:
            comm = read(path / "comm", 256).strip()
            known = comm in AGENTS
            fd_paths = list(
                islice((path / "fd").iterdir(), max_fds - coverage["fd_entries_scanned"] + 1)
            )
        except (OSError, ValueError):
            coverage["processes_denied"] += 1
            continue
        sockets, tun_fds, uid, state = set(), [], None, "unknown"
        for fd in fd_paths:
            check()
            if coverage["fd_entries_scanned"] >= max_fds:
                coverage["truncated"] = True
                break
            coverage["fd_entries_scanned"] += 1
            try:
                destination = os.readlink(fd)
            except OSError:
                continue
            if re.fullmatch(r"socket:\[[0-9]+\]", destination):
                sockets.add(destination[8:-1])
            if destination == "/dev/net/tun":
                try:
                    info = read(path / "fdinfo" / fd.name)
                    matched = re.search(r"(?m)^iff:\s*([A-Za-z0-9_.:-]{1,15})\s*$", info)
                    if matched:
                        tun_fds.append({"interface": matched[1], "fd": int(fd.name)})
                except (OSError, ValueError):
                    pass
        if known or tun_fds:
            try:
                status = read(path / "status", 8192)
                matched = re.search(r"(?m)^Uid:\s*([0-9]+)", status)
                uid = int(matched[1]) if matched else None
                matched = re.search(r"(?m)^State:\s*([A-Za-z])", status)
                state = matched[1] if matched and matched[1] in "RSDTtXZIW" else "unknown"
            except (OSError, ValueError):
                pass
            try:
                namespace = os.readlink(path / "ns/net")
                namespace = namespace if re.fullmatch(r"net:\[[0-9]+\]", namespace) else "unknown"
            except OSError:
                namespace = "unknown"
            same_namespace = (
                namespace == identity["network_namespace"]
                if namespace != "unknown" and identity["network_namespace"].startswith("net:")
                else None
            )
            item = {
                "pid": int(path.name),
                "comm": comm[:64],
                "uid": uid,
                "state": state,
                "known_agent_name": known,
                "established_tcp_sockets": len(sockets & established)
                if same_namespace is True
                else None,
                "network_namespace": namespace,
                "namespace_matches": same_namespace,
                "attached_tun_interfaces": [fd["interface"] for fd in tun_fds],
                "active_tunnel_verified": False,
                "note": (
                    "Process/TUN/TCP metadata does not prove forwarding; "
                    "socket counts use this namespace."
                ),
            }
            processes.append(item)
            owners.extend(
                {
                    "interface": fd["interface"],
                    "pid": item["pid"],
                    "comm": item["comm"],
                    "uid": uid,
                    "attachment_observed": True,
                    "namespace_matches": same_namespace,
                    "network_namespace": namespace,
                }
                for fd in tun_fds
            )
        if coverage["fd_entries_scanned"] >= max_fds:
            # An exact descriptor fit may still leave later processes unvisited.
            coverage["truncated"] |= coverage["processes_scanned"] < len(pids)
            break
    coverage["truncated"] |= len(pids) > max_processes
    return {
        "identity": identity,
        "resolver": resolver,
        "interfaces": interfaces,
        "processes": processes,
        "tun_owners": owners,
        "coverage": coverage,
    }


def main():
    parser = argparse.ArgumentParser()
    for name, default, kind in (
        ("max-interfaces", 128, int),
        ("max-processes", 1024, int),
        ("max-fds", 4096, int),
        ("max-bytes", 1048576, int),
        ("budget", 10, float),
    ):
        parser.add_argument("--" + name, type=kind, default=default)
    options = vars(parser.parse_args())
    print(json.dumps(collect_metadata(**options), separators=(",", ":")))


if __name__ == "__main__":
    main()
