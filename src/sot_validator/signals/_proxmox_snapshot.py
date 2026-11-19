"""Point-in-time Proxmox VE and Docker/Portainer cluster snapshot."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Optional

from sot_validator.signals._proxmox_parsing import (
    _clean_optional_str,
    _coerce_positive_int,
    _parse_interface_payload,
    normalize_ip_address,
    normalize_mac_address,
    normalize_proxmox_guest_type,
)
from sot_validator.signals._proxmox_records import (
    ContainerEndpointRecord,
    ProxmoxGuestRecord,
    _names_match,
)


@dataclass
class ProxmoxClusterSnapshot:
    """Point-in-time snapshot of Proxmox VE (:8006) guests and Docker/Portainer (:9000) containers."""

    guests: list[ProxmoxGuestRecord] = field(default_factory=list)
    containers: list[ContainerEndpointRecord] = field(default_factory=list)
    node_ips: dict[str, str] = field(default_factory=dict)
    unreachable_hosts: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.guests = [
            g if isinstance(g, ProxmoxGuestRecord) else ProxmoxGuestRecord.from_dict(g)
            for g in (self.guests or [])
        ]
        self.containers = [
            c if isinstance(c, ContainerEndpointRecord) else ContainerEndpointRecord.from_dict(c)
            for c in (self.containers or [])
        ]
        normalized_node_ips: dict[str, str] = {}
        for k, v in (self.node_ips or {}).items():
            key = _clean_optional_str(k)
            val = normalize_ip_address(_clean_optional_str(v))
            if key and val:
                normalized_node_ips[key.lower()] = val
        self.node_ips = normalized_node_ips

        for g in self.guests:
            if g.host_ip is None and g.node.lower() in self.node_ips:
                g.host_ip = self.node_ips[g.node.lower()]
            elif g.host_ip is not None and g.node.lower() not in self.node_ips:
                self.node_ips[g.node.lower()] = g.host_ip

        self.unreachable_hosts = {
            cleaned
            for h in (self.unreachable_hosts or set())
            if (cleaned := _clean_optional_str(h)) is not None
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "guests": [g.to_dict() for g in self.guests],
            "containers": [c.to_dict() for c in self.containers],
            "node_ips": dict(self.node_ips),
            "unreachable_hosts": sorted(self.unreachable_hosts),
        }

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any] | Sequence[Any],
        *,
        node_ips: Optional[Mapping[str, str]] = None,
        default_host_ip: Optional[str] = None,
    ) -> ProxmoxClusterSnapshot:
        resolved_node_ips: dict[str, str] = {}
        if node_ips:
            for k, v in node_ips.items():
                clean_k = _clean_optional_str(k)
                clean_v = normalize_ip_address(_clean_optional_str(v))
                if clean_k and clean_v:
                    resolved_node_ips[clean_k.lower()] = clean_v

        guests: list[ProxmoxGuestRecord] = []
        containers: list[ContainerEndpointRecord] = []
        unreachable: set[str] = set()

        if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray)):
            for item in data:
                if isinstance(item, ProxmoxGuestRecord):
                    guests.append(item)
                elif isinstance(item, ContainerEndpointRecord):
                    containers.append(item)
                elif isinstance(item, Mapping):
                    cls._ingest_entry(
                        item,
                        guests=guests,
                        containers=containers,
                        node_ips=resolved_node_ips,
                        default_host_ip=default_host_ip,
                    )
            return cls(
                guests=guests,
                containers=containers,
                node_ips=resolved_node_ips,
                unreachable_hosts=unreachable,
            )

        if not isinstance(data, Mapping):
            raise ValueError("ProxmoxClusterSnapshot payload must be a mapping or sequence")

        raw_node_ips = data.get("node_ips") or data.get("nodes_by_ip")
        if isinstance(raw_node_ips, Mapping):
            for k, v in raw_node_ips.items():
                clean_k = _clean_optional_str(k)
                clean_v = normalize_ip_address(_clean_optional_str(v))
                if clean_k and clean_v:
                    resolved_node_ips[clean_k.lower()] = clean_v

        raw_nodes = data.get("nodes")
        if isinstance(raw_nodes, Mapping):
            for k, v in raw_nodes.items():
                clean_k = _clean_optional_str(k)
                if isinstance(v, Mapping):
                    clean_v = normalize_ip_address(_clean_optional_str(v.get("ip") or v.get("host_ip")))
                else:
                    clean_v = normalize_ip_address(_clean_optional_str(v))
                if clean_k and clean_v:
                    resolved_node_ips[clean_k.lower()] = clean_v
        elif isinstance(raw_nodes, Sequence) and not isinstance(raw_nodes, (str, bytes)):
            for n_entry in raw_nodes:
                if isinstance(n_entry, Mapping):
                    n_name = _clean_optional_str(n_entry.get("node") or n_entry.get("name"))
                    n_ip = normalize_ip_address(_clean_optional_str(n_entry.get("ip") or n_entry.get("host_ip")))
                    if n_name and n_ip:
                        resolved_node_ips[n_name.lower()] = n_ip
                    if _clean_optional_str(n_entry.get("status") or "") in ("offline", "unreachable", "down"):
                        if n_name:
                            unreachable.add(n_name)
                        if n_ip:
                            unreachable.add(n_ip)

        raw_unreach = data.get("unreachable_hosts") or data.get("unreachable_nodes")
        if isinstance(raw_unreach, Iterable) and not isinstance(raw_unreach, (str, bytes, Mapping)):
            for u in raw_unreach:
                cu = _clean_optional_str(u)
                if cu:
                    unreachable.add(cu)

        top_host_ip = _clean_optional_str(data.get("host_ip") or default_host_ip)

        raw_resource_lists: list[Sequence[Any]] = []
        for key in ("data", "resources", "guests", "vms"):
            val = data.get(key)
            if isinstance(val, Sequence) and not isinstance(val, (str, bytes, bytearray)):
                raw_resource_lists.append(val)
            elif isinstance(val, Mapping) and isinstance(val.get("data"), Sequence):
                raw_resource_lists.append(val["data"])

        for res_list in raw_resource_lists:
            for item in res_list:
                if isinstance(item, Mapping):
                    r_type = _clean_optional_str(item.get("type"))
                    if r_type and r_type.lower() == "node":
                        n_name = _clean_optional_str(item.get("node") or item.get("name"))
                        n_ip = normalize_ip_address(_clean_optional_str(item.get("ip") or item.get("host_ip")))
                        if n_name and n_ip:
                            resolved_node_ips[n_name.lower()] = n_ip
                        if _clean_optional_str(item.get("status") or "") in ("offline", "unreachable", "down"):
                            if n_name:
                                unreachable.add(n_name)
                            if n_ip:
                                unreachable.add(n_ip)

        for res_list in raw_resource_lists:
            for item in res_list:
                if isinstance(item, ProxmoxGuestRecord):
                    guests.append(item)
                elif isinstance(item, ContainerEndpointRecord):
                    containers.append(item)
                elif isinstance(item, Mapping):
                    cls._ingest_entry(
                        item,
                        guests=guests,
                        containers=containers,
                        node_ips=resolved_node_ips,
                        default_host_ip=top_host_ip,
                    )

        iface_map = data.get("guest_interfaces") or data.get("interfaces") or data.get("vm_interfaces")
        if isinstance(iface_map, Mapping):
            guests_by_vmid: dict[int, list[ProxmoxGuestRecord]] = {}
            for g in guests:
                guests_by_vmid.setdefault(g.vmid, []).append(g)

            for raw_vmid_key, iface_payload in iface_map.items():
                try:
                    vmid_int = _coerce_positive_int(raw_vmid_key, "vmid")
                except ValueError:
                    continue
                iface_ips, iface_macs = _parse_interface_payload(iface_payload)
                for target_g in guests_by_vmid.get(vmid_int, []):
                    for ip_str in iface_ips:
                        if ip_str not in target_g.ip_addresses:
                            target_g.ip_addresses.append(ip_str)
                    for mac_str in iface_macs:
                        if mac_str not in target_g.mac_addresses:
                            target_g.mac_addresses.append(mac_str)

        for c_key in ("containers", "docker_containers", "portainer_containers"):
            c_val = data.get(c_key)
            if isinstance(c_val, Sequence) and not isinstance(c_val, (str, bytes, bytearray)):
                for item in c_val:
                    if isinstance(item, ContainerEndpointRecord):
                        containers.append(item)
                    elif isinstance(item, Mapping):
                        containers.append(
                            ContainerEndpointRecord.from_dict(item, default_host_ip=top_host_ip)
                        )

        endpoints = data.get("endpoints") or data.get("portainer_endpoints")
        if isinstance(endpoints, Sequence) and not isinstance(endpoints, (str, bytes, bytearray)):
            for ep in endpoints:
                if not isinstance(ep, Mapping):
                    continue
                ep_ip = _clean_optional_str(ep.get("host_ip") or ep.get("url") or ep.get("PublicURL") or top_host_ip)
                if ep_ip and "://" in ep_ip:
                    ep_ip = ep_ip.split("://", 1)[-1].split(":", 1)[0].split("/", 1)[0]
                if ep.get("Status") == 2 or str(ep.get("status", "")).lower() in ("down", "unreachable", "offline"):
                    if ep_ip:
                        unreachable.add(ep_ip)
                ep_containers = ep.get("containers") or ep.get("Containers")
                if isinstance(ep_containers, Sequence) and not isinstance(ep_containers, (str, bytes, bytearray)):
                    for c_item in ep_containers:
                        if isinstance(c_item, ContainerEndpointRecord):
                            containers.append(c_item)
                        elif isinstance(c_item, Mapping):
                            containers.append(
                                ContainerEndpointRecord.from_dict(c_item, default_host_ip=ep_ip)
                            )
                for snap in ep.get("Snapshots") or ep.get("snapshots") or []:
                    if isinstance(snap, Mapping):
                        raw_snap = snap.get("DockerSnapshotRaw") or snap.get("docker_snapshot_raw") or snap
                        snap_containers = raw_snap.get("Containers") if isinstance(raw_snap, Mapping) else None
                        if isinstance(snap_containers, Sequence) and not isinstance(snap_containers, (str, bytes, bytearray)):
                            for c_item in snap_containers:
                                if isinstance(c_item, Mapping):
                                    containers.append(
                                        ContainerEndpointRecord.from_dict(c_item, default_host_ip=ep_ip)
                                    )

        return cls(
            guests=guests,
            containers=containers,
            node_ips=resolved_node_ips,
            unreachable_hosts=unreachable,
        )

    @staticmethod
    def _ingest_entry(
        item: Mapping[str, Any],
        *,
        guests: list[ProxmoxGuestRecord],
        containers: list[ContainerEndpointRecord],
        node_ips: dict[str, str],
        default_host_ip: Optional[str],
    ) -> None:
        tpl = item.get("template")
        if tpl is True or tpl == 1 or str(tpl).strip().lower() in ("1", "true", "yes"):
            return

        r_type = _clean_optional_str(item.get("type") or item.get("guest_type"))
        if r_type and r_type.lower() in ("node", "storage", "pool", "sdn"):
            return

        if (
            r_type is None
            and "vmid" not in item
            and ("container_id" in item or "Id" in item or "Names" in item or "Image" in item)
        ):
            containers.append(
                ContainerEndpointRecord.from_dict(item, default_host_ip=default_host_ip)
            )
            return

        if r_type is not None:
            try:
                normalize_proxmox_guest_type(r_type)
            except ValueError:
                return

        if "vmid" not in item and not (isinstance(item.get("id"), str) and "/" in item["id"]):
            return

        node_name = _clean_optional_str(item.get("node"))
        resolved_hip = _clean_optional_str(item.get("host_ip") or item.get("node_ip"))
        if not resolved_hip and node_name and node_name.lower() in node_ips:
            resolved_hip = node_ips[node_name.lower()]
        if not resolved_hip:
            resolved_hip = default_host_ip

        guests.append(
            ProxmoxGuestRecord.from_dict(
                item,
                default_node=node_name,
                default_host_ip=resolved_hip,
            )
        )

    @classmethod
    def from_json(cls, raw_json: str, **kwargs: Any) -> ProxmoxClusterSnapshot:
        return cls.from_dict(json.loads(raw_json), **kwargs)

    @classmethod
    def from_json_file(cls, path: str | Path, **kwargs: Any) -> ProxmoxClusterSnapshot:
        file_path = Path(path)
        return cls.from_json(file_path.read_text(encoding="utf-8"), **kwargs)

    @classmethod
    def from_fetchers(
        cls,
        *,
        proxmox_fetcher: Optional[Callable[[], Any]] = None,
        container_fetcher: Optional[Callable[[], Any]] = None,
        node_ips: Optional[Mapping[str, str]] = None,
        default_host_ip: Optional[str] = None,
    ) -> ProxmoxClusterSnapshot:
        """Build a ProxmoxClusterSnapshot from read-only fetcher callables."""
        guests: list[ProxmoxGuestRecord] = []
        containers: list[ContainerEndpointRecord] = []
        resolved_node_ips: dict[str, str] = {}
        if node_ips:
            for k, v in node_ips.items():
                clean_k = _clean_optional_str(k)
                clean_v = normalize_ip_address(_clean_optional_str(v))
                if clean_k and clean_v:
                    resolved_node_ips[clean_k.lower()] = clean_v
        unreachable: set[str] = set()

        if proxmox_fetcher is not None:
            try:
                pve_raw = proxmox_fetcher()
                if isinstance(pve_raw, str):
                    pve_snap = cls.from_json(
                        pve_raw,
                        node_ips=resolved_node_ips,
                        default_host_ip=default_host_ip,
                    )
                elif isinstance(pve_raw, ProxmoxClusterSnapshot):
                    pve_snap = pve_raw
                else:
                    pve_snap = cls.from_dict(
                        pve_raw,
                        node_ips=resolved_node_ips,
                        default_host_ip=default_host_ip,
                    )
                guests.extend(pve_snap.guests)
                containers.extend(pve_snap.containers)
                resolved_node_ips.update(pve_snap.node_ips)
                unreachable.update(pve_snap.unreachable_hosts)
            except Exception:
                unreachable.add(default_host_ip or "proxmox")

        if container_fetcher is not None:
            try:
                ct_raw = container_fetcher()
                if isinstance(ct_raw, str):
                    ct_parsed = json.loads(ct_raw)
                else:
                    ct_parsed = ct_raw

                if isinstance(ct_parsed, ProxmoxClusterSnapshot):
                    containers.extend(ct_parsed.containers)
                    unreachable.update(ct_parsed.unreachable_hosts)
                elif isinstance(ct_parsed, Sequence) and not isinstance(ct_parsed, (str, bytes, bytearray)):
                    for item in ct_parsed:
                        if isinstance(item, ContainerEndpointRecord):
                            containers.append(item)
                        elif isinstance(item, Mapping):
                            containers.append(
                                ContainerEndpointRecord.from_dict(item, default_host_ip=default_host_ip)
                            )
                elif isinstance(ct_parsed, Mapping):
                    ct_snap = cls.from_dict(
                        ct_parsed,
                        node_ips=resolved_node_ips,
                        default_host_ip=default_host_ip,
                    )
                    containers.extend(ct_snap.containers)
                    guests.extend(ct_snap.guests)
                    unreachable.update(ct_snap.unreachable_hosts)
            except Exception:
                unreachable.add(default_host_ip or "portainer")

        return cls(
            guests=guests,
            containers=containers,
            node_ips=resolved_node_ips,
            unreachable_hosts=unreachable,
        )

    def find_guests(
        self,
        *,
        ip: Optional[str] = None,
        mac: Optional[str] = None,
        name: Optional[str] = None,
        vmid: Optional[int | str] = None,
        host_ip: Optional[str] = None,
    ) -> list[ProxmoxGuestRecord]:
        """Look up Proxmox guests matching all provided filter criteria."""
        norm_ip = normalize_ip_address(ip) if ip is not None else None
        norm_mac = normalize_mac_address(mac) if mac is not None else None
        clean_name = _clean_optional_str(name)
        norm_host_ip = normalize_ip_address(host_ip) if host_ip is not None else None
        target_vmid: Optional[int] = None
        if vmid is not None:
            try:
                target_vmid = _coerce_positive_int(vmid, "vmid")
            except ValueError:
                return []

        matches: list[ProxmoxGuestRecord] = []
        for g in self.guests:
            if target_vmid is not None and g.vmid != target_vmid:
                continue
            if norm_ip is not None and norm_ip not in g.ip_addresses:
                continue
            if norm_mac is not None and norm_mac not in g.mac_addresses:
                continue
            if clean_name is not None and not _names_match(g.name, clean_name):
                continue
            if norm_host_ip is not None and g.host_ip != norm_host_ip:
                continue
            matches.append(g)
        return matches

    def find_containers(
        self,
        *,
        ip: Optional[str] = None,
        name: Optional[str] = None,
        container_id: Optional[str] = None,
        host_ip: Optional[str] = None,
        port: Optional[int] = None,
    ) -> list[ContainerEndpointRecord]:
        """Look up Docker/Portainer containers matching all provided filter criteria."""
        norm_ip = normalize_ip_address(ip) if ip is not None else None
        clean_name = _clean_optional_str(name)
        clean_cid = _clean_optional_str(container_id)
        norm_host_ip = normalize_ip_address(host_ip) if host_ip is not None else None

        matches: list[ContainerEndpointRecord] = []
        for c in self.containers:
            if clean_cid is not None:
                cid_low = clean_cid.lower()
                c_low = c.container_id.lower()
                if not (c_low == cid_low or c_low.startswith(cid_low) or cid_low.startswith(c_low)):
                    continue
            if norm_ip is not None and norm_ip not in c.ip_addresses:
                continue
            if clean_name is not None and not _names_match(c.name, clean_name):
                continue
            if norm_host_ip is not None and c.host_ip != norm_host_ip:
                continue
            if port is not None and port not in c.published_ports:
                continue
            matches.append(c)
        return matches
