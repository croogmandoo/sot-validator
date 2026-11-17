"""Per-call lookup index over a site's IP records and switch ports.

``ClassificationEngine.classify_site`` builds one ``SiteRecordIndex`` per call
and hands it to the ARP, port-state and DNS/DHCP collectors, so each target is
resolved with dict lookups instead of rescanning every IP record and port. Lookups
return records in the order the linear scans produced them: each record keeps
its position in the deduplicated input and matches are sorted by it.

An index is only valid for the exact objects it was built from; evaluators
check ``matches`` and fall back to their linear path otherwise.

``ScopeMemo`` memoizes the DHCP collector's host-IP and /24 CIDR scope checks;
the collector keeps one per scope guard object.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, Optional, Sequence

from sot_validator.models import ArpEntry, Equipment, IPAddress, NetworkDevice, Port, Site
from sot_validator.signals.arp import _normalize_mac
from sot_validator.signals.icmp import (
    ScopeViolationError,
    SubnetScopeGuard,
    _parse_allocated_slash24,
    _parse_ipv4_host,
)


def _add(index: dict, key: object, position: int) -> None:
    bucket = index.get(key)
    if bucket is None:
        index[key] = [position]
    else:
        bucket.append(position)


def _positions(index: dict, keys: Iterable[object]) -> set[int]:
    found: set[int] = set()
    for key in keys:
        bucket = index.get(key)
        if bucket:
            found.update(bucket)
    return found


def _is_foreign_port(port: Port, equipment_id: str) -> bool:
    return (
        port.connected_device_id is not None
        and port.connected_device_id.strip() != ""
        and port.connected_device_id != equipment_id
    )


class SiteRecordIndex:
    """Lookups over ``ip_addresses`` + ``site.ip_addresses`` and ``ports`` + site ports."""

    def __init__(
        self,
        site: Optional[Site],
        *,
        ip_addresses: Optional[Sequence[IPAddress]] = None,
        ports: Optional[Sequence[Port]] = None,
    ) -> None:
        self.site = site
        self.ip_addresses_arg = ip_addresses
        self.ports_arg = ports

        # IP records deduplicated by identity, explicit records first
        self.ip_records: list[IPAddress] = []
        self._ips_by_ip: dict = {}
        self._ips_by_object: dict = {}
        self._ips_by_mac: dict = {}
        seen_ips: set[int] = set()
        ip_sources: list[Sequence[IPAddress]] = []
        if ip_addresses:
            ip_sources.append(ip_addresses)
        if site is not None:
            ip_sources.append(site.ip_addresses)
        for source in ip_sources:
            for ip_rec in source:
                if id(ip_rec) in seen_ips:
                    continue
                seen_ips.add(id(ip_rec))
                position = len(self.ip_records)
                self.ip_records.append(ip_rec)
                _add(self._ips_by_ip, ip_rec.ip, position)
                _add(self._ips_by_object, ip_rec.assigned_object_id, position)
                mac = _normalize_mac(ip_rec.arp_mac) or (
                    _normalize_mac(ip_rec.arp_entry.arp_mac)
                    if isinstance(ip_rec.arp_entry, ArpEntry)
                    else None
                )
                if mac is not None:
                    _add(self._ips_by_mac, mac, position)

        # Ports deduplicated by (device_id, port_id, name), explicit ports first
        self.ports: list[Port] = []
        self._ports_by_id: dict = {}
        self._ports_by_name: dict = {}
        self._ports_by_device_name: dict = {}
        self._ports_by_device_port_id: dict = {}
        self._ports_by_device: dict = {}
        self._ports_by_connected: dict = {}
        seen_ports: set[tuple[str, str, str]] = set()
        port_sources: list[Iterable[Port]] = []
        if ports:
            port_sources.append(ports)
        if site is not None:
            port_sources.extend(device.ports for device in site.devices)
        for source in port_sources:
            for port in source:
                key = (port.device_id, port.port_id, port.name)
                if key in seen_ports:
                    continue
                seen_ports.add(key)
                position = len(self.ports)
                self.ports.append(port)
                _add(self._ports_by_id, port.port_id, position)
                _add(self._ports_by_name, port.name, position)
                _add(
                    self._ports_by_device_name,
                    f"{port.device_id}:{port.name}",
                    position,
                )
                _add(
                    self._ports_by_device_port_id,
                    f"{port.device_id}:{port.port_id}",
                    position,
                )
                _add(self._ports_by_device, port.device_id, position)
                _add(self._ports_by_connected, port.connected_device_id, position)

        # Site equipment and devices, for hostnames correlated with an IP record
        self._equipment: list[Equipment] = list(site.equipment) if site is not None else []
        self._equipment_by_id: dict = {}
        self._equipment_by_ip: dict = {}
        for position, equipment in enumerate(self._equipment):
            _add(self._equipment_by_id, equipment.equipment_id, position)
            for assigned_ip in equipment.assigned_ips:
                _add(self._equipment_by_ip, assigned_ip, position)
        self._devices: list[NetworkDevice] = list(site.devices) if site is not None else []
        self._devices_by_id: dict = {}
        self._devices_by_ip: dict = {}
        for position, device in enumerate(self._devices):
            _add(self._devices_by_id, device.device_id, position)
            _add(self._devices_by_ip, device.management_ip, position)

    def matches(
        self,
        site: Optional[Site],
        ip_addresses: Optional[Sequence[IPAddress]],
        ports: Optional[Sequence[Port]],
    ) -> bool:
        """Return True only for the identical objects the index was built from."""
        return self.matches_ips(site, ip_addresses) and ports is self.ports_arg

    def matches_ips(
        self, site: Optional[Site], ip_addresses: Optional[Sequence[IPAddress]]
    ) -> bool:
        """Like ``matches`` for callers that only look up IP records and site objects."""
        return site is self.site and ip_addresses is self.ip_addresses_arg

    def matches_ports(
        self, site: Optional[Site], ports: Optional[Sequence[Port]]
    ) -> bool:
        """Like ``matches`` for callers that only look up ports."""
        return site is self.site and ports is self.ports_arg

    def ip_records_matching(
        self,
        *,
        ips: Iterable[object],
        object_id: object,
        macs: Iterable[object] = (),
    ) -> list[IPAddress]:
        """IP records whose ``ip``, ``assigned_object_id`` or normalized MAC match."""
        found = _positions(self._ips_by_ip, ips)
        found.update(self._ips_by_object.get(object_id, ()))
        found.update(_positions(self._ips_by_mac, macs))
        return [self.ip_records[position] for position in sorted(found)]

    def ip_records_for_object(self, object_id: object) -> list[IPAddress]:
        """IP records whose ``assigned_object_id`` equals ``object_id``."""
        return [self.ip_records[position] for position in self._ips_by_object.get(object_id, ())]

    def hostnames_for_ip_record(self, ip_rec: IPAddress) -> list[str]:
        """Names of equipment, then hostnames of devices, assigned to or owning ``ip_rec``."""
        found = set(self._equipment_by_id.get(ip_rec.assigned_object_id, ()))
        found.update(self._equipment_by_ip.get(ip_rec.ip, ()))
        names = [self._equipment[position].name for position in sorted(found)]
        found = set(self._devices_by_id.get(ip_rec.assigned_object_id, ()))
        found.update(self._devices_by_ip.get(ip_rec.ip, ()))
        names.extend(self._devices[position].hostname for position in sorted(found))
        return names

    def equipment_ports(
        self,
        refs: Iterable[object],
        equipment_id: str,
        *,
        match_device_port_id: bool,
        dedicated: bool = False,
    ) -> list[Port]:
        """Ports referenced by ``refs`` or connected to ``equipment_id``.

        ``dedicated`` drops ports connected to another non-empty device id, as
        the engine's VM branch does before evaluating ARP and port state.
        """
        refs = list(refs)
        found = _positions(self._ports_by_id, refs)
        found.update(_positions(self._ports_by_name, refs))
        found.update(_positions(self._ports_by_device_name, refs))
        if match_device_port_id:
            found.update(_positions(self._ports_by_device_port_id, refs))
        found.update(self._ports_by_connected.get(equipment_id, ()))
        matched = [self.ports[position] for position in sorted(found)]
        if dedicated:
            matched = [port for port in matched if not _is_foreign_port(port, equipment_id)]
        return matched

    def device_ports(self, device_id: str) -> list[Port]:
        """Ports owned by or connected to ``device_id``."""
        found = set(self._ports_by_device.get(device_id, ()))
        found.update(self._ports_by_connected.get(device_id, ()))
        return [self.ports[position] for position in sorted(found)]


class ScopeMemo:
    """Memoized host-IP and /24 CIDR scope checks for one scope guard object."""

    def __init__(self) -> None:
        self._hosts: dict[
            str, tuple[Optional[ipaddress.IPv4Address], Optional[str], bool]
        ] = {}
        self._cidrs: dict[str, tuple[Optional[ipaddress.IPv4Network], bool]] = {}

    def host_scope(
        self, raw_ip: str, guard: Optional[SubnetScopeGuard]
    ) -> tuple[Optional[ipaddress.IPv4Address], Optional[str], bool]:
        """Return (address, normalized IP, in guard scope); address is None if invalid."""
        scope = self._hosts.get(raw_ip)
        if scope is None:
            try:
                addr = _parse_ipv4_host(raw_ip)
            except ScopeViolationError:
                scope = (None, None, False)
            else:
                parsed = str(addr)
                scope = (addr, parsed, guard is None or guard.is_ip_in_scope(parsed))
            self._hosts[raw_ip] = scope
        return scope

    def cidr_scope(
        self, cidr: str, guard: Optional[SubnetScopeGuard]
    ) -> tuple[Optional[ipaddress.IPv4Network], bool]:
        """Return (allocated /24 network or None, allowed by the guard's allocations)."""
        scope = self._cidrs.get(cidr)
        if scope is None:
            try:
                net = _parse_allocated_slash24(cidr)
            except ScopeViolationError:
                scope = (None, False)
            else:
                allowed = True
                if guard is not None and guard.allocated_subnets:
                    try:
                        guard.validate_cidr_scope(cidr)
                    except ScopeViolationError:
                        allowed = False
                scope = (net, allowed)
            self._cidrs[cidr] = scope
        return scope


__all__ = ["ScopeMemo", "SiteRecordIndex"]
