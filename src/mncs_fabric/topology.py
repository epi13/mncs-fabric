"""Bounded worker-observed IP link and topology evidence.

Fabric remains transport agnostic above IP.  This module records the network
interfaces, routes, and directly observed neighbors that make a worker
reachable.  USB networking is therefore represented as an IP-capable link
medium instead of a special execution path.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows has a portable reduced view.
    fcntl = None  # type: ignore[assignment]

from .canonical import attach_identity, verify_identity
from .errors import ValidationError

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


TOPOLOGY_SCHEMA = "mncs-fabric.network-topology-observation.v0.1"
TOPOLOGY_SNAPSHOT_SCHEMA = "mncs-fabric.network-topology-snapshot.v0.1"
MAX_INTERFACES = 128
MAX_ADDRESSES_PER_INTERFACE = 64
MAX_ROUTES = 256
MAX_NEIGHBORS = 256
MEDIA = {"ethernet", "usb", "wifi", "loopback", "virtual", "other"}
STATES = {"UP", "DOWN", "UNKNOWN"}


def _bounded_text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValidationError(f"{field} must be bounded non-empty text")
    return value


def _safe_read(path: Path, maximum: int = 4096) -> str | None:
    try:
        value = path.read_text(encoding="utf-8", errors="strict").strip()
    except (OSError, UnicodeError):
        return None
    return value[:maximum] if value else None


def _mac(value: object, *, optional: bool = True) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str):
        raise ValidationError("mac_address must be text or null")
    normalized = value.lower().replace("-", ":")
    parts = normalized.split(":")
    if len(parts) != 6 or any(len(part) != 2 or any(char not in "0123456789abcdef" for char in part) for part in parts):
        raise ValidationError("mac_address is malformed")
    return normalized


def _ip(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be an IP address")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValidationError(f"{field} must be an IP address") from exc


def _network(value: object) -> str:
    if not isinstance(value, str):
        raise ValidationError("destination must be an IP network")
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise ValidationError("destination must be an IP network") from exc


def _medium(name: str, sysfs: Path | None) -> str:
    lowered = name.lower()
    if lowered in {"lo", "lo0"}:
        return "loopback"
    if lowered.startswith(("wl", "wifi")) or (sysfs is not None and (sysfs / "wireless").exists()):
        return "wifi"
    if lowered.startswith(("veth", "virbr", "docker", "br-", "tun", "tap", "wg", "zt")):
        return "virtual"
    if sysfs is not None:
        try:
            device = (sysfs / "device").resolve(strict=True)
        except OSError:
            device = None
        if device is not None and "usb" in str(device).lower().split("/"):
            return "usb"
        if device is not None and "/usb" in str(device).lower():
            return "usb"
    if lowered.startswith(("eth", "en")):
        return "ethernet"
    return "other"


def _ipv4_address(name: str) -> str | None:
    if os.name != "posix" or fcntl is None:
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            request = struct.pack("256s", name.encode("utf-8")[:15])
            result = fcntl.ioctl(stream.fileno(), 0x8915, request)  # SIOCGIFADDR
            return socket.inet_ntoa(result[20:24])
    except OSError:
        return None


def _linux_ipv6_addresses() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    path = Path("/proc/net/if_inet6")
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return result
    for line in lines[: MAX_INTERFACES * MAX_ADDRESSES_PER_INTERFACE]:
        parts = line.split()
        if len(parts) != 6:
            continue
        raw, _, prefix_hex, _, _, name = parts
        try:
            address = str(ipaddress.IPv6Address(int(raw, 16)))
            prefix = int(prefix_hex, 16)
        except ValueError:
            continue
        result.setdefault(name, []).append(f"{address}/{prefix}")
    return result


def _interface_addresses(name: str, ipv6: Mapping[str, list[str]]) -> list[str]:
    values: set[str] = set(ipv6.get(name, ()))
    address = _ipv4_address(name)
    if address is not None:
        values.add(f"{address}/32")
    return sorted(values)[:MAX_ADDRESSES_PER_INTERFACE]


def _speed(sysfs: Path | None) -> int | None:
    if sysfs is None:
        return None
    raw = _safe_read(sysfs / "speed", 32)
    if raw is None:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if 0 < value <= 10_000_000 else None


def _interfaces() -> list[dict[str, Any]]:
    try:
        names = sorted(socket.if_nameindex(), key=lambda item: item[0])
    except OSError:
        names = []
    ipv6 = _linux_ipv6_addresses() if os.name == "posix" else {}
    interfaces: list[dict[str, Any]] = []
    for index, name in names[:MAX_INTERFACES]:
        sysfs = Path("/sys/class/net") / name if Path("/sys/class/net").is_dir() else None
        operstate = _safe_read(sysfs / "operstate", 32) if sysfs else None
        state = "UP" if operstate == "up" else "DOWN" if operstate == "down" else "UNKNOWN"
        mtu_raw = _safe_read(sysfs / "mtu", 32) if sysfs else None
        try:
            mtu = int(mtu_raw) if mtu_raw is not None else None
        except ValueError:
            mtu = None
        mac = _safe_read(sysfs / "address", 64) if sysfs else None
        try:
            checked_mac = _mac(mac)
        except ValidationError:
            checked_mac = None
        interfaces.append({
            "name": name,
            "if_index": int(index),
            "state": state,
            "medium": _medium(name, sysfs),
            "speed_mbps": _speed(sysfs),
            "mtu": mtu if mtu is not None and 0 < mtu <= 1_000_000 else None,
            "mac_address": checked_mac,
            "addresses": _interface_addresses(name, ipv6),
        })
    return interfaces


def _hex_ipv4(value: str) -> str:
    return socket.inet_ntoa(struct.pack("<I", int(value, 16)))


def _routes() -> list[dict[str, Any]]:
    path = Path("/proc/net/route")
    try:
        lines = path.read_text(encoding="ascii").splitlines()[1:]
    except (OSError, UnicodeError):
        return []
    result: list[dict[str, Any]] = []
    for line in lines[:MAX_ROUTES]:
        parts = line.split()
        if len(parts) < 8:
            continue
        interface, destination_hex, gateway_hex, flags_hex, _, _, metric_raw, mask_hex = parts[:8]
        try:
            flags = int(flags_hex, 16)
            if not flags & 0x1:  # route is not up
                continue
            destination = _hex_ipv4(destination_hex)
            mask = _hex_ipv4(mask_hex)
            network = str(ipaddress.IPv4Network((destination, mask), strict=False))
            gateway_value = _hex_ipv4(gateway_hex)
            gateway = None if gateway_value == "0.0.0.0" else gateway_value
            metric = int(metric_raw)
        except (ValueError, OSError):
            continue
        result.append({
            "interface": interface,
            "destination": network,
            "gateway": gateway,
            "metric": metric if 0 <= metric <= 2**31 - 1 else None,
        })
    return sorted(result, key=lambda item: (item["destination"], item["interface"], item["gateway"] or ""))


def _neighbors() -> list[dict[str, Any]]:
    path = Path("/proc/net/arp")
    try:
        lines = path.read_text(encoding="ascii").splitlines()[1:]
    except (OSError, UnicodeError):
        return []
    result: list[dict[str, Any]] = []
    for line in lines[:MAX_NEIGHBORS]:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip_raw, _, flags_raw, mac_raw, _, interface = parts[:6]
        try:
            address = str(ipaddress.ip_address(ip_raw))
            mac = _mac(mac_raw, optional=False)
            flags = int(flags_raw, 16)
        except (ValueError, ValidationError):
            continue
        if mac == "00:00:00:00:00:00":
            continue
        result.append({
            "ip_address": address,
            "mac_address": mac,
            "interface": interface,
            "state": "REACHABLE" if flags & 0x2 else "UNKNOWN",
        })
    return sorted(result, key=lambda item: (item["interface"], item["ip_address"], item["mac_address"]))


def collect_network_topology(worker_identity: str) -> dict[str, Any]:
    """Capture one bounded local network observation without active scanning."""

    worker = _bounded_text(worker_identity, "worker_identity", 128)
    value = {
        "schema_version": TOPOLOGY_SCHEMA,
        "worker_identity": worker,
        "captured_at": _utc_now(),
        "interfaces": _interfaces(),
        "routes": _routes(),
        "neighbors": _neighbors(),
        "observation_source": "worker-local-os",
        "claim_boundary": (
            "passive worker OS observation of IP-capable links; not peer identity attestation, "
            "continuous reachability, route authorization, bandwidth guarantee, or physical-medium proof"
        ),
    }
    return attach_identity(value, "topology_identity")


def validate_network_topology(value: object, *, expected_worker_identity: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != TOPOLOGY_SCHEMA:
        raise ValidationError("unsupported network topology schema")
    required = {
        "schema_version", "worker_identity", "captured_at", "interfaces", "routes",
        "neighbors", "observation_source", "claim_boundary", "topology_identity",
    }
    if set(value) != required or not verify_identity(value, "topology_identity"):
        raise ValidationError("network topology fields or identity are invalid")
    worker = _bounded_text(value["worker_identity"], "worker_identity", 128)
    if expected_worker_identity is not None and worker != expected_worker_identity:
        raise ValidationError("network topology is bound to another worker")
    _bounded_text(value["captured_at"], "captured_at", 64)
    _bounded_text(value["observation_source"], "observation_source", 128)
    _bounded_text(value["claim_boundary"], "claim_boundary", 512)

    interfaces = value["interfaces"]
    if not isinstance(interfaces, list) or len(interfaces) > MAX_INTERFACES:
        raise ValidationError("network interfaces exceed the bounded collection")
    names: set[str] = set()
    for item in interfaces:
        if not isinstance(item, dict) or set(item) != {"name", "if_index", "state", "medium", "speed_mbps", "mtu", "mac_address", "addresses"}:
            raise ValidationError("network interface fields are invalid")
        name = _bounded_text(item["name"], "interface.name", 128)
        if name in names:
            raise ValidationError("network interface names must be unique")
        names.add(name)
        if not isinstance(item["if_index"], int) or isinstance(item["if_index"], bool) or not 0 <= item["if_index"] <= 2**31 - 1:
            raise ValidationError("interface.if_index is invalid")
        if item["state"] not in STATES or item["medium"] not in MEDIA:
            raise ValidationError("network interface state or medium is invalid")
        speed = item["speed_mbps"]
        if speed is not None and (not isinstance(speed, int) or isinstance(speed, bool) or not 0 < speed <= 10_000_000):
            raise ValidationError("interface.speed_mbps is invalid")
        mtu = item["mtu"]
        if mtu is not None and (not isinstance(mtu, int) or isinstance(mtu, bool) or not 0 < mtu <= 1_000_000):
            raise ValidationError("interface.mtu is invalid")
        _mac(item["mac_address"])
        addresses = item["addresses"]
        if not isinstance(addresses, list) or len(addresses) > MAX_ADDRESSES_PER_INTERFACE:
            raise ValidationError("interface.addresses exceed the bounded collection")
        for address in addresses:
            if not isinstance(address, str):
                raise ValidationError("interface address is invalid")
            try:
                ipaddress.ip_interface(address)
            except ValueError as exc:
                raise ValidationError("interface address is invalid") from exc

    routes = value["routes"]
    if not isinstance(routes, list) or len(routes) > MAX_ROUTES:
        raise ValidationError("network routes exceed the bounded collection")
    for route in routes:
        if not isinstance(route, dict) or set(route) != {"interface", "destination", "gateway", "metric"}:
            raise ValidationError("network route fields are invalid")
        _bounded_text(route["interface"], "route.interface", 128)
        _network(route["destination"])
        if route["gateway"] is not None:
            _ip(route["gateway"], "route.gateway")
        metric = route["metric"]
        if metric is not None and (not isinstance(metric, int) or isinstance(metric, bool) or not 0 <= metric <= 2**31 - 1):
            raise ValidationError("route.metric is invalid")

    neighbors = value["neighbors"]
    if not isinstance(neighbors, list) or len(neighbors) > MAX_NEIGHBORS:
        raise ValidationError("network neighbors exceed the bounded collection")
    for neighbor in neighbors:
        if not isinstance(neighbor, dict) or set(neighbor) != {"ip_address", "mac_address", "interface", "state"}:
            raise ValidationError("network neighbor fields are invalid")
        _ip(neighbor["ip_address"], "neighbor.ip_address")
        _mac(neighbor["mac_address"], optional=False)
        _bounded_text(neighbor["interface"], "neighbor.interface", 128)
        if neighbor["state"] not in {"REACHABLE", "UNKNOWN"}:
            raise ValidationError("network neighbor state is invalid")
    return dict(value)


def build_topology_snapshot(observations: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Project direct worker-to-worker edges from passive address/neighbor evidence."""

    checked = [validate_network_topology(dict(item)) for item in observations]
    by_mac: dict[str, tuple[str, dict[str, Any]]] = {}
    by_ip: dict[str, tuple[str, dict[str, Any]]] = {}
    for observation in checked:
        worker = observation["worker_identity"]
        for interface in observation["interfaces"]:
            if interface["mac_address"]:
                by_mac[interface["mac_address"]] = (worker, interface)
            for address in interface["addresses"]:
                by_ip[str(ipaddress.ip_interface(address).ip)] = (worker, interface)

    edges: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for observation in checked:
        source_worker = observation["worker_identity"]
        source_interfaces = {item["name"]: item for item in observation["interfaces"]}
        for neighbor in observation["neighbors"]:
            target = by_mac.get(neighbor["mac_address"]) or by_ip.get(neighbor["ip_address"])
            if target is None or target[0] == source_worker:
                continue
            target_worker, target_interface = target
            source_interface = source_interfaces.get(neighbor["interface"])
            if source_interface is None:
                continue
            left, right = sorted((source_worker, target_worker))
            if left == source_worker:
                left_if, right_if = source_interface, target_interface
            else:
                left_if, right_if = target_interface, source_interface
            key = (left, right, left_if["name"], right_if["name"])
            speeds = [item["speed_mbps"] for item in (left_if, right_if) if item["speed_mbps"] is not None]
            media = {left_if["medium"], right_if["medium"]}
            edges[key] = {
                "left_worker": left,
                "right_worker": right,
                "left_interface": left_if["name"],
                "right_interface": right_if["name"],
                "medium": next(iter(media)) if len(media) == 1 else "mixed",
                "transport": "ip",
                "speed_mbps": min(speeds) if speeds else None,
                "direct": True,
                "evidence": "passive-neighbor-match",
            }
    value = {
        "schema_version": TOPOLOGY_SNAPSHOT_SCHEMA,
        "captured_at": _utc_now(),
        "workers": [
            {"worker_identity": item["worker_identity"], "topology_identity": item["topology_identity"]}
            for item in sorted(checked, key=lambda entry: entry["worker_identity"])
        ],
        "edges": [edges[key] for key in sorted(edges)],
        "claim_boundary": "derived direct-link projection from worker observations; OS routing remains authoritative",
    }
    return attach_identity(value, "snapshot_identity")
