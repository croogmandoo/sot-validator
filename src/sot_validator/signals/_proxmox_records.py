"""Normalized Proxmox VE guest and Docker/Portainer container endpoint records."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
import json
import re
from typing import Any, Optional

from sot_validator.signals._proxmox_parsing import (
    _clean_optional_str,
    _coerce_optional_non_negative_int,
    _coerce_positive_int,
    _parse_interface_payload,
    _parse_tags,
    _require_non_empty_str,
    extract_ip_addresses,
    extract_mac_addresses,
    is_proxmox_mac,
    normalize_container_state,
    normalize_ip_address,
    normalize_proxmox_guest_status,
    normalize_proxmox_guest_type,
)


@dataclass
class ProxmoxGuestRecord:
    """Normalized Proxmox VE (:8006) QEMU VM or LXC container record."""

    vmid: int
    name: str
    guest_type: str
    node: str
    host_ip: Optional[str] = None
    status: str = "running"
    ip_addresses: list[str] = field(default_factory=list)
    mac_addresses: list[str] = field(default_factory=list)
    uptime_sec: Optional[int] = None
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.vmid = _coerce_positive_int(self.vmid, "vmid")
        self.guest_type = normalize_proxmox_guest_type(self.guest_type)
        self.name = _require_non_empty_str(self.name, "name")
        self.node = _require_non_empty_str(self.node, "node")
        self.host_ip = normalize_ip_address(self.host_ip) if self.host_ip is not None else None
        self.status = normalize_proxmox_guest_status(self.status)
        self.ip_addresses = extract_ip_addresses(self.ip_addresses)
        self.mac_addresses = extract_mac_addresses(self.mac_addresses)
        self.uptime_sec = _coerce_optional_non_negative_int(self.uptime_sec, "uptime_sec")
        self.tags = _parse_tags(self.tags)

    @property
    def is_running(self) -> bool:
        """Return True if the Proxmox guest is currently running."""
        return self.status == "running"

    @property
    def has_proxmox_mac(self) -> bool:
        """Return True if any guest MAC address matches the Proxmox OUI bc:24:11."""
        return any(is_proxmox_mac(m) for m in self.mac_addresses)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vmid": self.vmid,
            "name": self.name,
            "guest_type": self.guest_type,
            "node": self.node,
            "host_ip": self.host_ip,
            "status": self.status,
            "ip_addresses": list(self.ip_addresses),
            "mac_addresses": list(self.mac_addresses),
            "uptime_sec": self.uptime_sec,
            "tags": list(self.tags),
        }

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        default_node: Optional[str] = None,
        default_host_ip: Optional[str] = None,
    ) -> ProxmoxGuestRecord:
        raw_vmid = data.get("vmid")
        if raw_vmid is None and isinstance(data.get("id"), str) and "/" in data["id"]:
            raw_vmid = data["id"].rsplit("/", 1)[-1]
        if raw_vmid is None:
            raw_vmid = data.get("id")
        vmid = _coerce_positive_int(raw_vmid, "vmid")

        raw_type = data.get("guest_type") or data.get("type")
        if raw_type is None and isinstance(data.get("id"), str) and "/" in data["id"]:
            raw_type = data["id"].split("/", 1)[0]
        guest_type = normalize_proxmox_guest_type(raw_type or "qemu")

        name = _clean_optional_str(
            data.get("name") or data.get("hostname") or data.get("vm_name")
        ) or f"{guest_type}-{vmid}"

        node = (
            _clean_optional_str(data.get("node") or data.get("proxmox_node"))
            or _clean_optional_str(default_node)
            or "pve"
        )

        host_ip = _clean_optional_str(
            data.get("host_ip") or data.get("node_ip") or default_host_ip
        )

        raw_status = data.get("status") or data.get("state") or data.get("power_state") or "running"
        status = normalize_proxmox_guest_status(raw_status)

        ips: list[str] = []
        for key in ("ip_addresses", "ips", "ip", "ip6", "primary_ip", "inet", "inet6"):
            if key in data:
                for ip_str in extract_ip_addresses(data[key]):
                    if ip_str not in ips:
                        ips.append(ip_str)

        macs: list[str] = []
        for key in ("mac_addresses", "macs", "mac", "mac_address", "hwaddr", "macaddr"):
            if key in data:
                for mac_str in extract_mac_addresses(data[key]):
                    if mac_str not in macs:
                        macs.append(mac_str)

        for k, v in data.items():
            if isinstance(k, str) and k.lower().startswith("net"):
                for ip_str in extract_ip_addresses(v):
                    if ip_str not in ips:
                        ips.append(ip_str)
                for mac_str in extract_mac_addresses(v):
                    if mac_str not in macs:
                        macs.append(mac_str)

        for iface_key in ("interfaces", "guest_interfaces", "nics", "network"):
            if iface_key in data:
                iface_ips, iface_macs = _parse_interface_payload(data[iface_key])
                for ip_str in iface_ips:
                    if ip_str not in ips:
                        ips.append(ip_str)
                for mac_str in iface_macs:
                    if mac_str not in macs:
                        macs.append(mac_str)

        raw_uptime = data.get("uptime_sec") if data.get("uptime_sec") is not None else data.get("uptime")

        return cls(
            vmid=vmid,
            name=name,
            guest_type=guest_type,
            node=node,
            host_ip=host_ip,
            status=status,
            ip_addresses=ips,
            mac_addresses=macs,
            uptime_sec=raw_uptime,
            tags=_parse_tags(data.get("tags")),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str, **kwargs: Any) -> ProxmoxGuestRecord:
        return cls.from_dict(json.loads(raw), **kwargs)


def _parse_published_ports(value: Any) -> list[int]:
    ports: set[int] = set()
    if value is None:
        return []
    if isinstance(value, int) and not isinstance(value, bool):
        if 1 <= value <= 65535:
            ports.add(value)
        return sorted(ports)
    if isinstance(value, str):
        for token in re.split(r"[,;\s]+", value.strip()):
            if not token:
                continue
            if "->" in token:
                port_part = token.split("->", 1)[0].rsplit(":", 1)[-1].strip()
            else:
                # "[ip:]host:container[/proto]" publishes the host side; a bare "80/tcp" is exposed only.
                segs = [seg.strip() for seg in token.split("/", 1)[0].split(":")]
                if len(segs) >= 2 and segs[-2].isdigit() and segs[-1].isdigit():
                    port_part = segs[-2]
                elif len(segs) >= 2:
                    port_part = segs[-1]
                elif "/" in token:
                    continue
                else:
                    port_part = segs[0]
            if port_part.isdigit():
                p = int(port_part)
                if 1 <= p <= 65535:
                    ports.add(p)
        return sorted(ports)
    if isinstance(value, Mapping):
        # Only host-side bindings count; Docker lists exposed-only ports with just PrivatePort.
        for pub_key in ("PublicPort", "public_port", "HostPort", "host_port"):
            if value.get(pub_key) is not None:
                return _parse_published_ports(value[pub_key])
        if any(k in value for k in ("PrivatePort", "private_port")):
            return []
        # Docker inspect style {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]} or {"80/tcp": None}
        for v in value.values():
            if isinstance(v, (Mapping, list, tuple)):
                for p in _parse_published_ports(v):
                    ports.add(p)
        return sorted(ports)
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray)):
        for item in value:
            for p in _parse_published_ports(item):
                ports.add(p)
        return sorted(ports)
    return sorted(ports)


@dataclass
class ContainerEndpointRecord:
    """Normalized Docker / Portainer (:9000) container endpoint record."""

    container_id: str
    name: str
    image: str
    host_ip: Optional[str] = None
    state: str = "running"
    ip_addresses: list[str] = field(default_factory=list)
    published_ports: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.container_id = _require_non_empty_str(self.container_id, "container_id")
        cleaned_name = _require_non_empty_str(self.name, "name").lstrip("/").strip()
        if not cleaned_name:
            raise ValueError("name must be a non-empty string")
        self.name = cleaned_name
        self.image = _require_non_empty_str(self.image, "image")
        self.host_ip = normalize_ip_address(self.host_ip) if self.host_ip is not None else None
        self.state = normalize_container_state(self.state)
        self.ip_addresses = extract_ip_addresses(self.ip_addresses)
        self.published_ports = _parse_published_ports(self.published_ports)

    @property
    def is_running(self) -> bool:
        """Return True if the container is currently running."""
        return self.state == "running"

    def to_dict(self) -> dict[str, Any]:
        return {
            "container_id": self.container_id,
            "name": self.name,
            "image": self.image,
            "host_ip": self.host_ip,
            "state": self.state,
            "ip_addresses": list(self.ip_addresses),
            "published_ports": list(self.published_ports),
        }

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        default_host_ip: Optional[str] = None,
    ) -> ContainerEndpointRecord:
        container_id = _clean_optional_str(
            data.get("container_id") or data.get("Id") or data.get("id") or data.get("ID")
        )
        if not container_id:
            raise ValueError("container_id must be a non-empty string")

        raw_name = data.get("name") or data.get("Name")
        if not raw_name:
            names_list = data.get("Names") or data.get("names")
            if isinstance(names_list, Sequence) and not isinstance(names_list, (str, bytes)) and names_list:
                raw_name = names_list[0]
        name = _clean_optional_str(raw_name) or container_id[:12]
        name = name.lstrip("/").strip() or container_id[:12]

        image = _clean_optional_str(data.get("image") or data.get("Image")) or "unknown"

        host_ip = _clean_optional_str(
            data.get("host_ip") or data.get("HostIP") or data.get("endpoint_ip") or default_host_ip
        )

        raw_state = (
            data.get("state")
            if data.get("state") is not None
            else (
                data.get("State")
                if data.get("State") is not None
                else (data.get("status") or data.get("Status") or "running")
            )
        )
        state = normalize_container_state(raw_state)

        ips: list[str] = []
        for key in ("ip_addresses", "ips", "ip", "ip_address", "IPAddress"):
            if key in data:
                for ip_str in extract_ip_addresses(data[key]):
                    if ip_str not in ips:
                        ips.append(ip_str)

        net_settings = data.get("NetworkSettings") or data.get("network_settings")
        if isinstance(net_settings, Mapping):
            for ip_str in extract_ip_addresses(net_settings.get("IPAddress") or net_settings.get("ip_address")):
                if ip_str not in ips:
                    ips.append(ip_str)
            networks = net_settings.get("Networks") or net_settings.get("networks")
            if isinstance(networks, Mapping):
                for net_obj in networks.values():
                    if isinstance(net_obj, Mapping):
                        for ip_str in extract_ip_addresses(
                            net_obj.get("IPAddress")
                            or net_obj.get("ip_address")
                            or net_obj.get("GlobalIPv6Address")
                        ):
                            if ip_str not in ips:
                                ips.append(ip_str)

        raw_ports = (
            data.get("published_ports")
            if data.get("published_ports") is not None
            else (data.get("Ports") if data.get("Ports") is not None else data.get("ports"))
        )
        ports_list = _parse_published_ports(raw_ports)

        if host_ip is None and isinstance(raw_ports, Sequence) and not isinstance(raw_ports, (str, bytes)):
            for p_entry in raw_ports:
                if isinstance(p_entry, Mapping):
                    candidate_hip = normalize_ip_address(_clean_optional_str(p_entry.get("IP") or p_entry.get("ip")))
                    if candidate_hip:
                        host_ip = candidate_hip
                        break

        return cls(
            container_id=container_id,
            name=name,
            image=image,
            host_ip=host_ip,
            state=state,
            ip_addresses=ips,
            published_ports=ports_list,
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str, **kwargs: Any) -> ContainerEndpointRecord:
        return cls.from_dict(json.loads(raw), **kwargs)


def _names_match(name_a: Optional[str], name_b: Optional[str]) -> bool:
    clean_a = _clean_optional_str(name_a)
    clean_b = _clean_optional_str(name_b)
    if not clean_a or not clean_b:
        return False
    low_a = clean_a.lstrip("/").lower()
    low_b = clean_b.lstrip("/").lower()
    if low_a == low_b:
        return True
    short_a = low_a.split(".", 1)[0]
    short_b = low_b.split(".", 1)[0]
    return bool(short_a and short_a == short_b)
