"""Two-stage /16-to-/24 subnet scanner engine and Site snapshot builder."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
import inspect
import ipaddress
from typing import Any, Optional

from sot_validator.discovery._scanner_common import (
    _infer_host_role,
    _infer_vlan_id_from_subnet,
    _normalize_mac,
    _role_to_equipment_category,
    parse_ip_neigh_output,
)
from sot_validator.discovery._scanner_models import DiscoveredHost, DiscoveryConfig
from sot_validator.discovery._scanner_probes import (
    _default_arp_table_reader,
    _default_async_ping,
    _default_async_rdns,
    _default_async_tcp_probe,
    _run_coro_sync,
)
from sot_validator.models import (
    ArpEntry,
    Equipment,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    Subnet,
    VLAN,
)
from sot_validator.signals.icmp import IcmpProbeResponse


class SubnetDiscoveryScanner:
    """Two-stage /16-to-/24 subnet discovery scanner and Site snapshot builder."""

    def __init__(
        self,
        config: Optional[DiscoveryConfig] = None,
        *,
        ping_fn: Optional[Callable[..., Any]] = None,
        tcp_probe_fn: Optional[Callable[..., Any]] = None,
        arp_table_fn: Optional[Callable[..., Any]] = None,
        rdns_fn: Optional[Callable[..., Any]] = None,
    ) -> None:
        if config is not None and not isinstance(config, DiscoveryConfig):
            raise ValueError("config must be a DiscoveryConfig instance")
        self.config: DiscoveryConfig = config or DiscoveryConfig()
        self._ping_fn = ping_fn
        self._tcp_probe_fn = tcp_probe_fn
        self._arp_table_fn = arp_table_fn
        self._rdns_fn = rdns_fn

    @staticmethod
    def _normalize_ping_result(raw: Any) -> tuple[bool, Optional[float]]:
        if raw is None:
            return False, None
        if isinstance(raw, bool):
            return raw, None
        if isinstance(raw, (int, float)):
            reachable = float(raw) >= 0.0
            return reachable, (float(raw) if reachable else None)
        if isinstance(raw, IcmpProbeResponse):
            return (
                bool(raw.reachable),
                float(raw.latency_ms) if raw.latency_ms is not None else None,
            )
        if isinstance(raw, tuple) and len(raw) >= 2:
            reachable = bool(raw[0])
            rtt = float(raw[1]) if raw[1] is not None and reachable else None
            return reachable, rtt
        if isinstance(raw, Mapping):
            reachable = bool(raw.get("reachable", False))
            raw_rtt = raw.get("rtt_ms", raw.get("latency_ms"))
            rtt = float(raw_rtt) if raw_rtt is not None and reachable else None
            return reachable, rtt
        if hasattr(raw, "reachable"):
            reachable = bool(getattr(raw, "reachable"))
            raw_rtt = getattr(raw, "rtt_ms", getattr(raw, "latency_ms", None))
            rtt = float(raw_rtt) if raw_rtt is not None and reachable else None
            return reachable, rtt
        return bool(raw), None

    @staticmethod
    def _normalize_arp_table(
        raw: Any,
    ) -> dict[str, tuple[Optional[str], Optional[str]]]:
        if raw is None:
            return {}
        if isinstance(raw, str):
            return parse_ip_neigh_output(raw)
        if isinstance(raw, Mapping):
            normalized: dict[str, tuple[Optional[str], Optional[str]]] = {}
            for raw_ip, val in raw.items():
                try:
                    ip_str = str(ipaddress.IPv4Address(str(raw_ip).strip()))
                except ValueError:
                    continue
                if val is None:
                    normalized[ip_str] = (None, None)
                elif isinstance(val, str):
                    normalized[ip_str] = (_normalize_mac(val), "REACHABLE")
                elif isinstance(val, tuple):
                    mac = _normalize_mac(val[0]) if len(val) > 0 and val[0] else None
                    state = (
                        str(val[1]).strip().upper()
                        if len(val) > 1 and val[1]
                        else None
                    )
                    normalized[ip_str] = (mac, state)
                elif isinstance(val, Mapping):
                    raw_mac = (
                        val.get("mac")
                        or val.get("mac_address")
                        or val.get("lladdr")
                    )
                    raw_state = (
                        val.get("state")
                        or val.get("arp_state")
                        or val.get("status")
                    )
                    mac = _normalize_mac(raw_mac) if raw_mac else None
                    state = str(raw_state).strip().upper() if raw_state else None
                    normalized[ip_str] = (mac, state)
            return normalized
        return {}

    async def _probe_ping(
        self, ip: str, timeout_sec: float
    ) -> tuple[bool, Optional[float]]:
        if self._ping_fn is None:
            return await _default_async_ping(ip, timeout_sec)
        try:
            res = self._ping_fn(ip, timeout_sec)
        except TypeError:
            res = self._ping_fn(ip)
        if inspect.isawaitable(res):
            res = await res
        return self._normalize_ping_result(res)

    async def _probe_tcp(self, ip: str, port: int, timeout_sec: float) -> bool:
        if self._tcp_probe_fn is None:
            return await _default_async_tcp_probe(ip, port, timeout_sec)
        try:
            res = self._tcp_probe_fn(ip, port, timeout_sec)
        except TypeError:
            res = self._tcp_probe_fn(ip, port)
        if inspect.isawaitable(res):
            res = await res
        return bool(res)

    async def _get_arp_table(
        self,
    ) -> dict[str, tuple[Optional[str], Optional[str]]]:
        if self._arp_table_fn is None:
            return await asyncio.to_thread(_default_arp_table_reader)
        res = self._arp_table_fn()
        if inspect.isawaitable(res):
            res = await res
        return self._normalize_arp_table(res)

    async def _resolve_rdns(self, ip: str) -> Optional[str]:
        if self._rdns_fn is None:
            if (
                self._ping_fn is not None
                or self._tcp_probe_fn is not None
                or self._arp_table_fn is not None
            ):
                return None
            return await _default_async_rdns(ip)
        res = self._rdns_fn(ip)
        if inspect.isawaitable(res):
            res = await res
        if isinstance(res, str) and res.strip():
            return res.strip()
        return None

    async def discover_active_subnets_async(
        self,
        *,
        arp_table: Optional[dict[str, tuple[Optional[str], Optional[str]]]] = None,
    ) -> list[str]:
        """Stage 1: Identify active /24 subnets within configured /16 or /24 CIDR."""
        net = ipaddress.IPv4Network(self.config.cidr, strict=False)
        if net.prefixlen == 24:
            return [str(net)]

        resolved_arp = (
            arp_table if arp_table is not None else await self._get_arp_table()
        )
        active_subnet_set: set[ipaddress.IPv4Network] = set()

        for ip_str, (mac, state) in resolved_arp.items():
            if not mac or (state or "").upper() in {"FAILED", "INCOMPLETE"}:
                continue
            try:
                addr = ipaddress.IPv4Address(ip_str)
            except ValueError:
                continue
            if addr in net:
                slash24 = ipaddress.IPv4Network(f"{addr}/24", strict=False)
                active_subnet_set.add(slash24)

        octets = str(net.network_address).split(".")
        prefix_two = f"{octets[0]}.{octets[1]}"
        semaphore = asyncio.Semaphore(self.config.max_concurrency)

        async def _probe_gateway(
            third_octet: int, gw_octet: int
        ) -> Optional[ipaddress.IPv4Network]:
            gw_ip = f"{prefix_two}.{third_octet}.{gw_octet}"
            async with semaphore:
                reachable, _ = await self._probe_ping(
                    gw_ip, self.config.ping_timeout_sec
                )
            if reachable:
                return ipaddress.IPv4Network(
                    f"{prefix_two}.{third_octet}.0/24", strict=False
                )
            return None

        tasks = [
            _probe_gateway(third_octet, gw_octet)
            for third_octet in range(256)
            for gw_octet in self.config.gateway_octets
        ]
        results = await asyncio.gather(*tasks)
        for subnet_net in results:
            if subnet_net is not None:
                active_subnet_set.add(subnet_net)

        sorted_subnets = sorted(active_subnet_set)[: self.config.max_active_subnets]
        return [str(s) for s in sorted_subnets]

    def discover_active_subnets(self) -> list[str]:
        """Synchronous wrapper for Stage 1 active /24 subnet discovery."""
        return _run_coro_sync(self.discover_active_subnets_async())

    async def sweep_subnet_async(
        self,
        subnet_cidr: str,
        *,
        arp_table: Optional[dict[str, tuple[Optional[str], Optional[str]]]] = None,
    ) -> list[DiscoveredHost]:
        """Stage 2: Sweep usable host IPs (.1..254) inside an active /24 subnet."""
        if not isinstance(subnet_cidr, str) or not subnet_cidr.strip():
            raise ValueError("subnet_cidr must be a non-empty /24 CIDR string")
        try:
            subnet = ipaddress.ip_network(subnet_cidr.strip(), strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid subnet CIDR {subnet_cidr!r}: {exc}") from exc
        if not isinstance(subnet, ipaddress.IPv4Network) or subnet.prefixlen != 24:
            raise ValueError(
                f"sweep_subnet requires an IPv4 /24 CIDR, got {subnet_cidr!r}"
            )

        normalized_subnet_cidr = str(subnet)
        vlan_id = _infer_vlan_id_from_subnet(normalized_subnet_cidr)
        resolved_arp = (
            arp_table if arp_table is not None else await self._get_arp_table()
        )
        semaphore = asyncio.Semaphore(self.config.max_concurrency)

        async def _evaluate_host(host_addr: ipaddress.IPv4Address) -> Optional[DiscoveredHost]:
            ip_str = str(host_addr)
            fourth_octet = int(ip_str.split(".")[3])
            mac_address, arp_state = resolved_arp.get(ip_str, (None, None))
            has_valid_arp = bool(
                mac_address
                and (arp_state or "").upper() not in {"FAILED", "INCOMPLETE"}
            )

            async with semaphore:
                icmp_reachable, rtt_ms = await self._probe_ping(
                    ip_str, self.config.ping_timeout_sec
                )

            open_ports: list[int] = []
            should_probe_tcp = (
                icmp_reachable
                or has_valid_arp
                or (fourth_octet in self.config.gateway_octets)
                or (self._tcp_probe_fn is not None)
            )
            if should_probe_tcp and self.config.tcp_ports:
                for port in self.config.tcp_ports:
                    async with semaphore:
                        is_open = await self._probe_tcp(
                            ip_str, port, self.config.tcp_timeout_sec
                        )
                    if is_open:
                        open_ports.append(port)

            if not (icmp_reachable or open_ports or has_valid_arp):
                return None

            hostname = await self._resolve_rdns(ip_str)
            inferred_role = _infer_host_role(
                ip=ip_str,
                gateway_octets=self.config.gateway_octets,
                mac_address=mac_address,
                open_tcp_ports=open_ports,
                hostname=hostname,
            )
            return DiscoveredHost(
                ip=ip_str,
                subnet_cidr=normalized_subnet_cidr,
                vlan_id=vlan_id,
                icmp_reachable=icmp_reachable,
                rtt_ms=rtt_ms,
                open_tcp_ports=open_ports,
                mac_address=mac_address,
                arp_state=arp_state,
                hostname=hostname,
                inferred_role=inferred_role,
            )

        tasks = [_evaluate_host(host_addr) for host_addr in subnet.hosts()]
        evaluated = await asyncio.gather(*tasks)
        discovered = [h for h in evaluated if h is not None]
        discovered.sort(key=lambda h: ipaddress.IPv4Address(h.ip))
        return discovered

    def sweep_subnet(self, subnet_cidr: str) -> list[DiscoveredHost]:
        """Synchronous wrapper for sweeping a single /24 subnet."""
        return _run_coro_sync(self.sweep_subnet_async(subnet_cidr))

    async def scan_async(self) -> list[DiscoveredHost]:
        """Execute two-stage discovery across configured CIDR and return all discovered hosts."""
        arp_table = await self._get_arp_table()
        active_subnets = await self.discover_active_subnets_async(arp_table=arp_table)
        all_hosts: list[DiscoveredHost] = []
        for subnet_cidr in active_subnets[: self.config.max_active_subnets]:
            subnet_hosts = await self.sweep_subnet_async(
                subnet_cidr, arp_table=arp_table
            )
            all_hosts.extend(subnet_hosts)
        all_hosts.sort(key=lambda h: ipaddress.IPv4Address(h.ip))
        return all_hosts

    def scan(self) -> list[DiscoveredHost]:
        """Synchronous wrapper for two-stage subnet and host discovery."""
        return _run_coro_sync(self.scan_async())

    def build_site_snapshot(
        self,
        hosts: Sequence[DiscoveredHost],
        active_subnets: Optional[Sequence[str]] = None,
        *,
        site_id: str = "site-discovered",
        site_name: str = "Discovered Site",
        observed_at: Optional[datetime | str] = None,
    ) -> Site:
        """Transform discovered subnets and hosts into a ready-to-validate canonical Site."""
        if not isinstance(site_id, str) or not site_id.strip():
            raise ValueError("site_id must be a non-empty string")
        if not isinstance(site_name, str) or not site_name.strip():
            raise ValueError("site_name must be a non-empty string")
        site_id = site_id.strip()
        site_name = site_name.strip()

        if observed_at is None:
            obs_dt = datetime.now(timezone.utc)
        elif isinstance(observed_at, datetime):
            obs_dt = observed_at
        elif isinstance(observed_at, str):
            obs_dt = datetime.fromisoformat(observed_at)
        else:
            raise ValueError("observed_at must be a datetime, ISO-8601 string, or None")

        normalized_hosts = [
            h if isinstance(h, DiscoveredHost) else DiscoveredHost.from_dict(h)
            for h in hosts
        ]
        normalized_hosts.sort(key=lambda h: ipaddress.IPv4Address(h.ip))

        subnet_net_set: set[ipaddress.IPv4Network] = set()
        for raw_cidr in active_subnets or ():
            net = ipaddress.ip_network(raw_cidr.strip(), strict=False)
            if isinstance(net, ipaddress.IPv4Network) and net.prefixlen == 24:
                subnet_net_set.add(net)
        for host in normalized_hosts:
            net = ipaddress.ip_network(host.subnet_cidr, strict=False)
            if isinstance(net, ipaddress.IPv4Network) and net.prefixlen == 24:
                subnet_net_set.add(net)

        sorted_subnets = sorted(subnet_net_set)
        hosts_by_subnet: dict[str, list[DiscoveredHost]] = {
            str(net): [] for net in sorted_subnets
        }
        for host in normalized_hosts:
            hosts_by_subnet.setdefault(host.subnet_cidr, []).append(host)

        vlans: list[VLAN] = []
        subnets: list[Subnet] = []
        devices: list[NetworkDevice] = []
        equipment_list: list[Equipment] = []
        ip_addresses: list[IPAddress] = []

        default_gw_octet = self.config.gateway_octets[0]

        for net in sorted_subnets:
            cidr_str = str(net)
            octets = str(net.network_address).split(".")
            third_octet = int(octets[2])
            vlan_id = str(third_octet) if third_octet > 0 else "1"
            subnet_id = f"{site_id}-sub-{third_octet}"
            subnet_hosts = hosts_by_subnet.get(cidr_str, [])

            # Resolve gateway IP for the subnet
            gateway_host = next(
                (
                    h
                    for h in subnet_hosts
                    if h.inferred_role == "router"
                    or int(h.ip.split(".")[3]) in self.config.gateway_octets
                ),
                None,
            )
            gateway_ip = (
                gateway_host.ip
                if gateway_host is not None
                else f"{octets[0]}.{octets[1]}.{octets[2]}.{default_gw_octet}"
            )

            vlans.append(
                VLAN(
                    vlan_id=vlan_id,
                    site_id=site_id,
                    name=f"VLAN {vlan_id}",
                    subnet_id=subnet_id,
                    cidr=cidr_str,
                    gateway=gateway_ip,
                )
            )
            subnets.append(
                Subnet(
                    subnet_id=subnet_id,
                    site_id=site_id,
                    cidr=cidr_str,
                    vlan_id=vlan_id,
                    gateway=gateway_ip,
                    name=f"Subnet {cidr_str}",
                )
            )

            device_hosts = [
                h for h in subnet_hosts if h.inferred_role in {"router", "switch"}
            ]
            eq_hosts = [
                h for h in subnet_hosts if h.inferred_role not in {"router", "switch"}
            ]

            subnet_devices: list[tuple[NetworkDevice, Optional[DiscoveredHost]]] = []
            for dev_host in device_hosts:
                ip_slug = dev_host.ip.replace(".", "-")
                dev_id = f"{site_id}-dev-{ip_slug}"
                dev_hostname = dev_host.hostname or f"{dev_host.inferred_role}-{ip_slug}"
                vendor = (
                    "Extreme Networks"
                    if (dev_host.mac_address or "").startswith("00:04:96")
                    else None
                )
                net_dev = NetworkDevice(
                    device_id=dev_id,
                    site_id=site_id,
                    hostname=dev_hostname,
                    management_ip=dev_host.ip,
                    vendor=vendor,
                    role=dev_host.inferred_role,
                    last_seen=obs_dt,
                    ports=[],
                )
                subnet_devices.append((net_dev, dev_host))

            if not subnet_devices and eq_hosts:
                gw_slug = gateway_ip.replace(".", "-")
                synth_dev = NetworkDevice(
                    device_id=f"{site_id}-dev-{gw_slug}",
                    site_id=site_id,
                    hostname=f"gw-{gw_slug}",
                    management_ip=gateway_ip,
                    role="router",
                    last_seen=obs_dt,
                    ports=[],
                )
                subnet_devices.append((synth_dev, None))

            primary_device: Optional[NetworkDevice] = (
                subnet_devices[0][0] if subnet_devices else None
            )
            switch_device: Optional[NetworkDevice] = next(
                (
                    d
                    for d, _ in subnet_devices
                    if d.role == "switch"
                    and primary_device is not None
                    and d.device_id != primary_device.device_id
                ),
                None,
            )

            # Link secondary network devices to primary gateway device so both have active ports
            if primary_device is not None and len(subnet_devices) > 1:
                for idx, (sec_dev, sec_host) in enumerate(subnet_devices[1:], start=1):
                    uplink_port_id = f"{primary_device.device_id}-uplink-{idx}"
                    primary_device.ports.append(
                        Port(
                            port_id=uplink_port_id,
                            device_id=primary_device.device_id,
                            name=f"uplink{idx}",
                            admin_status="up",
                            oper_status="up",
                            connected_device_id=sec_dev.device_id,
                            connected_mac=(
                                sec_host.mac_address if sec_host is not None else None
                            ),
                            vlan_id=vlan_id,
                        )
                    )
                    sec_uplink_id = f"{sec_dev.device_id}-uplink-0"
                    sec_dev.ports.append(
                        Port(
                            port_id=sec_uplink_id,
                            device_id=sec_dev.device_id,
                            name="uplink0",
                            admin_status="up",
                            oper_status="up",
                            connected_device_id=primary_device.device_id,
                            vlan_id=vlan_id,
                        )
                    )

            for port_idx, eq_host in enumerate(eq_hosts, start=1):
                ip_slug = eq_host.ip.replace(".", "-")
                eq_id = f"{site_id}-eq-{ip_slug}"
                eq_name = eq_host.hostname or f"{eq_host.inferred_role}-{ip_slug}"
                category = _role_to_equipment_category(eq_host.inferred_role)

                connected_port_ids: list[str] = []
                if primary_device is not None:
                    port_id = f"{primary_device.device_id}-p{port_idx}"
                    port_name = f"eth{port_idx}"
                    primary_device.ports.append(
                        Port(
                            port_id=port_id,
                            device_id=primary_device.device_id,
                            name=port_name,
                            admin_status="up",
                            oper_status="up",
                            connected_device_id=eq_id,
                            connected_mac=eq_host.mac_address,
                            vlan_id=vlan_id,
                        )
                    )
                    connected_port_ids.append(port_id)

                if switch_device is not None:
                    sw_port_id = f"{switch_device.device_id}-p{port_idx}"
                    sw_port_name = f"eth{port_idx}"
                    switch_device.ports.append(
                        Port(
                            port_id=sw_port_id,
                            device_id=switch_device.device_id,
                            name=sw_port_name,
                            admin_status="up",
                            oper_status="up",
                            connected_device_id=eq_id,
                            connected_mac=eq_host.mac_address,
                            vlan_id=vlan_id,
                        )
                    )
                    connected_port_ids.append(sw_port_id)

                equipment_list.append(
                    Equipment(
                        equipment_id=eq_id,
                        site_id=site_id,
                        name=eq_name,
                        category=category,
                        assigned_ips=[eq_host.ip],
                        connected_ports=connected_port_ids,
                        last_seen=obs_dt,
                    )
                )

                arp_source_id = (
                    primary_device.device_id if primary_device is not None else None
                )
                arp_entry = (
                    ArpEntry(
                        ip=eq_host.ip,
                        arp_mac=eq_host.mac_address,
                        arp_last_seen=obs_dt,
                        arp_source_device_id=arp_source_id,
                        subnet_id=subnet_id,
                    )
                    if eq_host.mac_address
                    else None
                )
                ip_addresses.append(
                    IPAddress(
                        ip=eq_host.ip,
                        subnet_id=subnet_id,
                        assigned_object_type="Equipment",
                        assigned_object_id=eq_id,
                        arp_mac=eq_host.mac_address,
                        arp_last_seen=obs_dt if eq_host.mac_address else None,
                        arp_source_device_id=(
                            arp_source_id if eq_host.mac_address else None
                        ),
                        arp_entry=arp_entry,
                    )
                )

            # Ensure every NetworkDevice has at least one active port and an IPAddress record
            for net_dev, dev_host in subnet_devices:
                if not net_dev.ports:
                    net_dev.ports.append(
                        Port(
                            port_id=f"{net_dev.device_id}-mgmt0",
                            device_id=net_dev.device_id,
                            name="mgmt0",
                            admin_status="up",
                            oper_status="up",
                            connected_mac=(
                                dev_host.mac_address if dev_host is not None else None
                            ),
                            vlan_id=vlan_id,
                        )
                    )
                devices.append(net_dev)

                if dev_host is not None:
                    arp_source_id = (
                        primary_device.device_id
                        if primary_device is not None
                        else net_dev.device_id
                    )
                    dev_arp_entry = (
                        ArpEntry(
                            ip=dev_host.ip,
                            arp_mac=dev_host.mac_address,
                            arp_last_seen=obs_dt,
                            arp_source_device_id=arp_source_id,
                            subnet_id=subnet_id,
                        )
                        if dev_host.mac_address
                        else None
                    )
                    ip_addresses.append(
                        IPAddress(
                            ip=dev_host.ip,
                            subnet_id=subnet_id,
                            assigned_object_type="NetworkDevice",
                            assigned_object_id=net_dev.device_id,
                            arp_mac=dev_host.mac_address,
                            arp_last_seen=obs_dt if dev_host.mac_address else None,
                            arp_source_device_id=(
                                arp_source_id if dev_host.mac_address else None
                            ),
                            arp_entry=dev_arp_entry,
                        )
                    )

        ip_addresses.sort(key=lambda rec: ipaddress.IPv4Address(rec.ip))

        return Site(
            site_id=site_id,
            name=site_name,
            devices=devices,
            vlans=vlans,
            subnets=subnets,
            ip_addresses=ip_addresses,
            equipment=equipment_list,
        )

    async def discover_site_async(
        self,
        site_id: str = "site-discovered",
        site_name: str = "Discovered Site",
        *,
        observed_at: Optional[datetime | str] = None,
    ) -> Site:
        """Execute two-stage discovery and return a populated canonical Site snapshot."""
        arp_table = await self._get_arp_table()
        active_subnets = await self.discover_active_subnets_async(arp_table=arp_table)
        hosts: list[DiscoveredHost] = []
        for subnet_cidr in active_subnets[: self.config.max_active_subnets]:
            subnet_hosts = await self.sweep_subnet_async(
                subnet_cidr, arp_table=arp_table
            )
            hosts.extend(subnet_hosts)
        return self.build_site_snapshot(
            hosts,
            active_subnets=active_subnets,
            site_id=site_id,
            site_name=site_name,
            observed_at=observed_at,
        )

    def discover_site(
        self,
        site_id: str = "site-discovered",
        site_name: str = "Discovered Site",
        *,
        observed_at: Optional[datetime | str] = None,
    ) -> Site:
        """Synchronous wrapper for discovering and constructing a canonical Site snapshot."""
        return _run_coro_sync(
            self.discover_site_async(
                site_id=site_id,
                site_name=site_name,
                observed_at=observed_at,
            )
        )
