"""Merge router ARP and DHCP lease tables onto discovered hosts and Site snapshots."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
import ipaddress
import re
from typing import Any, Optional

from sot_validator.discovery._router_common import (
    _ARP_STATE_RANK,
    _canonical_ipv4,
    _coerce_datetime,
)
from sot_validator.discovery._router_records import DhcpLeaseRecord, RouterArpRecord
from sot_validator.discovery.scanner import (
    DEFAULT_GATEWAY_OCTETS,
    DiscoveredHost,
    _infer_host_role,
    _role_to_equipment_category,
)
from sot_validator.models import ArpEntry, EquipmentCategory, NetworkDevice, Site


def _timestamp_rank(value: Optional[datetime]) -> float:
    return value.timestamp() if value is not None else float("-inf")


def _arp_rank(record: RouterArpRecord) -> tuple[bool, int, float]:
    return (
        record.mac_address is not None,
        _ARP_STATE_RANK.get(record.state or "", 1),
        _timestamp_rank(record.observed_at),
    )


def _lease_rank(lease: DhcpLeaseRecord) -> tuple[bool, float]:
    # A lease without an expiry is infinite, so it outranks any finite expiry
    expires = lease.lease_expires_at
    return (
        lease.hostname is not None,
        expires.timestamp() if expires is not None else float("inf"),
    )


def _ip_slug(ip: str) -> str:
    return ip.strip().replace(".", "-")


def _is_synthetic_equipment_name(name: str, ip: str, equipment_id: str) -> bool:
    lowered = name.strip().lower()
    return (
        lowered == equipment_id.strip().lower()
        or lowered.startswith(("host-", "server-"))
        or re.fullmatch(r"[a-z_]+-" + re.escape(_ip_slug(ip)), lowered) is not None
    )


def _is_synthetic_device_hostname(hostname: str, ip: str) -> bool:
    slug = _ip_slug(ip)
    return hostname.strip().lower() in {f"{p}-{slug}" for p in ("router", "switch", "gw")}


class RouterArpDhcpCollector:
    """Merge router ARP and DHCP lease tables onto discovered hosts and Site snapshots."""

    def __init__(
        self,
        arp_records: Optional[Iterable[RouterArpRecord | Mapping[str, Any]]] = None,
        dhcp_leases: Optional[Iterable[DhcpLeaseRecord | Mapping[str, Any]]] = None,
        *,
        observed_at: Optional[datetime | str] = None,
        gateway_octets: Sequence[int] = DEFAULT_GATEWAY_OCTETS,
    ) -> None:
        self.observed_at: Optional[datetime] = _coerce_datetime(observed_at, "observed_at")
        self.gateway_octets: tuple[int, ...] = tuple(gateway_octets)
        if not self.gateway_octets:
            raise ValueError("gateway_octets must not be empty")
        self._arp: dict[str, RouterArpRecord] = {}
        self._leases: dict[str, DhcpLeaseRecord] = {}
        self.add_arp_records(arp_records or ())
        self.add_dhcp_leases(dhcp_leases or ())

    def add_arp_records(
        self, records: Iterable[RouterArpRecord | Mapping[str, Any]]
    ) -> None:
        """Merge ARP records, keeping the best record per IP."""
        for raw in records:
            record = raw if isinstance(raw, RouterArpRecord) else RouterArpRecord.from_dict(raw)
            current = self._arp.get(record.ip)
            if current is None or _arp_rank(record) > _arp_rank(current):
                self._arp[record.ip] = record

    def add_dhcp_leases(
        self, leases: Iterable[DhcpLeaseRecord | Mapping[str, Any]]
    ) -> None:
        """Merge DHCP leases, keeping the best lease per IP."""
        for raw in leases:
            lease = raw if isinstance(raw, DhcpLeaseRecord) else DhcpLeaseRecord.from_dict(raw)
            current = self._leases.get(lease.ip)
            if current is None or _lease_rank(lease) > _lease_rank(current):
                self._leases[lease.ip] = lease

    @property
    def arp_by_ip(self) -> dict[str, RouterArpRecord]:
        """Best ARP record per canonical IPv4 address."""
        return dict(self._arp)

    @property
    def leases_by_ip(self) -> dict[str, DhcpLeaseRecord]:
        """Best DHCP lease per canonical IPv4 address."""
        return dict(self._leases)

    def _merge(
        self,
        arp_records: Optional[Iterable[RouterArpRecord | Mapping[str, Any]]],
        dhcp_leases: Optional[Iterable[DhcpLeaseRecord | Mapping[str, Any]]],
    ) -> None:
        if arp_records is not None:
            self.add_arp_records(arp_records)
        if dhcp_leases is not None:
            self.add_dhcp_leases(dhcp_leases)

    def enrich_hosts(
        self,
        hosts: Sequence[DiscoveredHost | Mapping[str, Any]],
        *,
        arp_records: Optional[Iterable[RouterArpRecord | Mapping[str, Any]]] = None,
        dhcp_leases: Optional[Iterable[DhcpLeaseRecord | Mapping[str, Any]]] = None,
        overwrite: bool = False,
    ) -> list[DiscoveredHost]:
        """Backfill MAC, ARP state, hostname and inferred role onto discovered hosts."""
        self._merge(arp_records, dhcp_leases)
        enriched: list[DiscoveredHost] = []
        for raw_host in hosts:
            host = (
                raw_host
                if isinstance(raw_host, DiscoveredHost)
                else DiscoveredHost.from_dict(raw_host)
            )
            arp = self._arp.get(host.ip)
            lease = self._leases.get(host.ip)
            mac_changed = False
            hostname_changed = False

            new_mac = (arp.mac_address if arp is not None else None) or (
                lease.mac_address if lease is not None else None
            )
            if (
                new_mac is not None
                and (host.mac_address is None or overwrite)
                and new_mac != host.mac_address
            ):
                host.mac_address = new_mac
                mac_changed = True

            if host.arp_state is None or overwrite:
                if arp is not None and arp.state is not None:
                    host.arp_state = arp.state
                elif mac_changed and host.arp_state is None:
                    host.arp_state = "REACHABLE"

            new_hostname = lease.hostname if lease is not None else None
            if (
                new_hostname is not None
                and (host.hostname is None or overwrite)
                and new_hostname != host.hostname
            ):
                host.hostname = new_hostname
                hostname_changed = True

            if host.inferred_role == "host" or overwrite or mac_changed or hostname_changed:
                host.inferred_role = _infer_host_role(
                    ip=host.ip,
                    gateway_octets=self.gateway_octets,
                    mac_address=host.mac_address,
                    open_tcp_ports=host.open_tcp_ports,
                    hostname=host.hostname,
                )
            enriched.append(host)
        return enriched

    @staticmethod
    def _primary_device_id(
        site: Site, subnet_cidr: Optional[str], ip: str
    ) -> Optional[str]:
        try:
            net = ipaddress.ip_network(subnet_cidr or f"{ip}/24", strict=False)
        except ValueError:
            net = ipaddress.ip_network(f"{ip}/24", strict=False)

        def _in_net(dev: NetworkDevice) -> bool:
            try:
                return ipaddress.ip_address((dev.management_ip or "").strip()) in net
            except ValueError:
                return False

        infra = [
            d for d in site.devices if (d.role or "").strip().lower() in ("router", "switch")
        ]
        for pool in ([d for d in infra if _in_net(d)], infra):
            for role in ("router", "switch"):
                for dev in pool:
                    if (dev.role or "").strip().lower() == role:
                        return dev.device_id
        return None

    def enrich_site(
        self,
        site: Site,
        *,
        arp_records: Optional[Iterable[RouterArpRecord | Mapping[str, Any]]] = None,
        dhcp_leases: Optional[Iterable[DhcpLeaseRecord | Mapping[str, Any]]] = None,
        observed_at: Optional[datetime | str] = None,
        overwrite: bool = False,
    ) -> Site:
        """Backfill ARP, hostname, equipment and port data onto a Site in place."""
        if not isinstance(site, Site):
            raise ValueError("site must be a Site instance")
        self._merge(arp_records, dhcp_leases)
        fallback_obs = (
            _coerce_datetime(observed_at, "observed_at")
            or self.observed_at
            or datetime.now(timezone.utc)
        )
        eq_by_id = {eq.equipment_id: eq for eq in site.equipment}
        dev_by_id = {dev.device_id: dev for dev in site.devices}
        cidr_by_subnet = {s.subnet_id: s.cidr for s in site.subnets}

        for ip_rec in site.ip_addresses:
            try:
                ip_key = _canonical_ipv4(ip_rec.ip)
            except ValueError:
                continue
            arp = self._arp.get(ip_key)
            lease = self._leases.get(ip_key)
            if arp is None and lease is None:
                continue

            mac = (arp.mac_address if arp is not None else None) or (
                lease.mac_address if lease is not None else None
            )
            hostname = lease.hostname if lease is not None else None
            linked_eq = eq_by_id.get(ip_rec.assigned_object_id or "")
            linked_dev = dev_by_id.get(ip_rec.assigned_object_id or "")
            if linked_eq is not None or linked_dev is not None:
                equipment, device = linked_eq, linked_dev
            else:
                equipment = next(
                    (
                        eq
                        for eq in site.equipment
                        if ip_key in (a.strip() for a in eq.assigned_ips)
                    ),
                    None,
                )
                device = next(
                    (
                        dev
                        for dev in site.devices
                        if (dev.management_ip or "").strip() == ip_key
                    ),
                    None,
                )

            if mac is not None:
                obs_dt = (arp.observed_at if arp is not None else None) or fallback_obs
                source_id = (
                    (arp.router_id if arp is not None else None)
                    or ip_rec.arp_source_device_id
                    or self._primary_device_id(
                        site, cidr_by_subnet.get(ip_rec.subnet_id), ip_key
                    )
                )
                if ip_rec.arp_mac is None or overwrite:
                    ip_rec.arp_mac = mac
                    ip_rec.arp_last_seen = obs_dt
                    ip_rec.arp_source_device_id = source_id
                if ip_rec.arp_entry is None or overwrite:
                    ip_rec.arp_entry = ArpEntry(
                        ip=ip_rec.ip,
                        arp_mac=ip_rec.arp_mac or mac,
                        arp_last_seen=ip_rec.arp_last_seen or obs_dt,
                        arp_source_device_id=ip_rec.arp_source_device_id or source_id,
                        subnet_id=ip_rec.subnet_id,
                    )

            if hostname is not None:
                if ip_rec.assigned_object_id is None or (
                    overwrite and linked_eq is None and linked_dev is None
                ):
                    if equipment is not None:
                        ip_rec.assigned_object_id = equipment.equipment_id
                        if ip_rec.assigned_object_type is None or overwrite:
                            ip_rec.assigned_object_type = "Equipment"
                    elif device is not None:
                        ip_rec.assigned_object_id = device.device_id
                        if ip_rec.assigned_object_type is None or overwrite:
                            ip_rec.assigned_object_type = "NetworkDevice"
                    else:
                        ip_rec.assigned_object_id = hostname
                        if ip_rec.assigned_object_type is None:
                            ip_rec.assigned_object_type = "Equipment"
                if equipment is not None and (
                    overwrite
                    or _is_synthetic_equipment_name(
                        equipment.name, ip_key, equipment.equipment_id
                    )
                ):
                    equipment.name = hostname
                if device is not None and (
                    overwrite
                    or _is_synthetic_device_hostname(
                        device.hostname, device.management_ip or ip_key
                    )
                ):
                    device.hostname = hostname

            if equipment is not None and (mac is not None or hostname is not None):
                category = _role_to_equipment_category(
                    _infer_host_role(
                        ip=ip_key,
                        gateway_octets=self.gateway_octets,
                        mac_address=mac,
                        hostname=hostname,
                    )
                )
                if category is not EquipmentCategory.OTHER and (
                    equipment.category is EquipmentCategory.OTHER or overwrite
                ):
                    equipment.category = category

            if mac is not None:
                target_id = ip_rec.assigned_object_id
                for dev in site.devices:
                    for port in dev.ports:
                        matches = (
                            target_id is not None and port.connected_device_id == target_id
                        ) or (dev is device and port.name == "mgmt0")
                        if matches and (port.connected_mac is None or overwrite):
                            port.connected_mac = mac
                if (
                    device is not None
                    and device.vendor is None
                    and mac.startswith("00:04:96")
                ):
                    device.vendor = "Extreme Networks"

        return site
