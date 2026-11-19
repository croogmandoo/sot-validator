"""Switch port mode inferrer and Site port auto-mapper over FDB entries."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import ipaddress
from typing import Any, Optional

from sot_validator.models import (
    ArpEntry,
    Equipment,
    NetworkDevice,
    Site,
    Subnet,
    VLAN,
)
from sot_validator.topology._fdb_parser import FdbTableParser
from sot_validator.topology._fdb_records import (
    FdbEntry,
    PortClassificationResult,
    _HOSTNAME_TRAILING_DIGITS_PATTERN,
    _ROUTER_HOSTNAME_TOKENS,
    _ROUTER_ROLES,
    _SWITCH_HOSTNAME_TOKENS,
    _parse_mac_token,
    _site_gateway_ips,
    _unlink_port_from_equipment,
)
from sot_validator.topology.device_types import DevicePortManager
from sot_validator.topology.identifier import (
    KNOWN_OUI_VENDORS,
    _TOKEN_SPLIT_PATTERN,
    _extract_oui_prefix,
)


class SwitchFdbPortMapper:
    """Infers switch port modes (`access`, `trunk`, `uplink`, `empty`) from FDB entries and auto-binds Site ports."""

    def __init__(
        self,
        *,
        max_access_macs: int = 2,
        oui_vendors: Optional[Mapping[str, tuple[str, str]]] = None,
    ) -> None:
        if (
            isinstance(max_access_macs, bool)
            or not isinstance(max_access_macs, int)
            or max_access_macs < 1
        ):
            raise ValueError("max_access_macs must be an integer >= 1")
        self.max_access_macs = max_access_macs
        self.oui_vendors: dict[str, tuple[str, str]] = dict(KNOWN_OUI_VENDORS)
        if oui_vendors:
            for k, v in oui_vendors.items():
                self.oui_vendors[k.strip().lower()] = v

    @staticmethod
    def _classify_network_device_role(
        dev: NetworkDevice, site_gateway_ips: set[str]
    ) -> str:
        role_lower = (dev.role or "").strip().lower()
        mgmt_ip = dev.management_ip.strip() if dev.management_ip else None
        if role_lower in _ROUTER_ROLES or (
            mgmt_ip is not None and mgmt_ip in site_gateway_ips
        ):
            return "router"
        if role_lower == "switch":
            return "switch"
        hostname_lower = (dev.hostname or "").strip().lower()
        # Strip trailing digits so `site01-sw01` yields the `sw` token
        tokens = {
            _HOSTNAME_TRAILING_DIGITS_PATTERN.sub("", t)
            for t in _TOKEN_SPLIT_PATTERN.split(hostname_lower)
            if t
        }
        if not role_lower:
            if tokens & _ROUTER_HOSTNAME_TOKENS or any(
                s in hostname_lower for s in ("router", "gateway", "udm")
            ):
                return "router"
            if tokens & _SWITCH_HOSTNAME_TOKENS or any(
                s in hostname_lower for s in ("switch", "exos", "voss")
            ):
                return "switch"
            # Unroled devices without router/switch hints are treated as end-hosts
            return ""
        return role_lower

    def _infrastructure_device_ids(self, site: Site) -> set[str]:
        site_gateway_ips = _site_gateway_ips(site)
        return {
            d.device_id
            for d in site.devices
            if self._classify_network_device_role(d, site_gateway_ips)
            in ("router", "switch")
        }

    def _build_site_lookup_context(
        self,
        site: Site,
        *,
        arp_entries: Sequence[ArpEntry] = (),
        device_mac_map: Optional[Mapping[str, str]] = None,
    ) -> dict[str, Any]:
        subnet_by_id: dict[str, Subnet] = {s.subnet_id: s for s in site.subnets}
        # Invalid CIDRs in legacy inventory data are skipped rather than failing the mapping
        parsed_subnets: list[tuple[ipaddress._BaseNetwork, Subnet]] = []
        for s in site.subnets:
            try:
                parsed_subnets.append((ipaddress.ip_network(s.cidr, strict=False), s))
            except ValueError:
                continue

        parsed_vlans: list[tuple[ipaddress._BaseNetwork, VLAN]] = []
        for v in site.vlans:
            if v.cidr:
                try:
                    parsed_vlans.append((ipaddress.ip_network(v.cidr, strict=False), v))
                except ValueError:
                    continue

        site_gateway_ips = _site_gateway_ips(site)

        def infer_vlan_for_subnet_id(subnet_id: Optional[str]) -> Optional[str]:
            if not subnet_id:
                return None
            sub = subnet_by_id.get(subnet_id)
            if sub and sub.vlan_id:
                return sub.vlan_id
            for v in site.vlans:
                if v.subnet_id == subnet_id:
                    return v.vlan_id
                if sub and v.cidr and v.cidr == sub.cidr:
                    return v.vlan_id
            return None

        def infer_vlan_for_ip(ip_str: Optional[str]) -> Optional[str]:
            if not ip_str or not ip_str.strip():
                return None
            cleaned = ip_str.strip()
            for ip_rec in site.ip_addresses:
                if ip_rec.ip == cleaned:
                    v_id = infer_vlan_for_subnet_id(ip_rec.subnet_id)
                    if v_id:
                        return v_id
            try:
                ip_obj = ipaddress.ip_address(cleaned)
            except ValueError:
                return None
            for net, sub in parsed_subnets:
                if ip_obj in net:
                    return sub.vlan_id or infer_vlan_for_subnet_id(sub.subnet_id)
            for net, v in parsed_vlans:
                if ip_obj in net:
                    return v.vlan_id
            return None

        dev_by_id: dict[str, NetworkDevice] = {d.device_id: d for d in site.devices}
        dev_role_by_id: dict[str, str] = {
            d.device_id: self._classify_network_device_role(d, site_gateway_ips)
            for d in site.devices
        }
        infra_device_ids: set[str] = {
            d_id
            for d_id, role in dev_role_by_id.items()
            if role in ("router", "switch")
        }

        eq_by_id: dict[str, Equipment] = {e.equipment_id: e for e in site.equipment}

        # Map MAC -> infrastructure device_id (router or switch)
        infra_mac_to_device_id: dict[str, str] = {}
        # Map MAC -> downstream entity id (Equipment.equipment_id or non-infra NetworkDevice.device_id)
        host_mac_to_entity_id: dict[str, str] = {}
        # Map MAC -> set of IPs
        mac_to_ips: dict[str, list[str]] = {}
        # Map MAC -> inferred VLAN ID
        mac_to_vlan_id: dict[str, str] = {}
        # Map IP -> MAC
        ip_to_mac: dict[str, str] = {}

        def record_mac_ip(norm_mac: str, ip_str: str, subnet_id: Optional[str] = None) -> None:
            cleaned_ip = ip_str.strip()
            if not cleaned_ip:
                return
            mac_to_ips.setdefault(norm_mac, [])
            if cleaned_ip not in mac_to_ips[norm_mac]:
                mac_to_ips[norm_mac].append(cleaned_ip)
            ip_to_mac.setdefault(cleaned_ip, norm_mac)
            if norm_mac not in mac_to_vlan_id:
                v_id = infer_vlan_for_subnet_id(subnet_id) or infer_vlan_for_ip(
                    cleaned_ip
                )
                if v_id:
                    mac_to_vlan_id[norm_mac] = v_id

        for entry in arp_entries:
            norm_mac = _parse_mac_token(entry.arp_mac)
            if norm_mac:
                record_mac_ip(norm_mac, entry.ip, entry.subnet_id)

        for ip_rec in site.ip_addresses:
            raw_mac = ip_rec.arp_mac or (
                ip_rec.arp_entry.arp_mac if ip_rec.arp_entry is not None else None
            )
            norm_mac = _parse_mac_token(raw_mac)
            if norm_mac:
                record_mac_ip(norm_mac, ip_rec.ip, ip_rec.subnet_id)
                if ip_rec.assigned_object_id:
                    obj_id = ip_rec.assigned_object_id.strip()
                    if obj_id in infra_device_ids:
                        infra_mac_to_device_id[norm_mac] = obj_id
                    elif obj_id:
                        host_mac_to_entity_id[norm_mac] = obj_id

        # Check explicit device_mac_map (supports {device_id: mac} or {mac: device_id})
        if device_mac_map:
            for k, v in device_mac_map.items():
                norm_k = _parse_mac_token(k)
                norm_v = _parse_mac_token(v)
                if norm_v is not None and k.strip() in dev_by_id:
                    dev_id = k.strip()
                    if dev_id in infra_device_ids:
                        infra_mac_to_device_id[norm_v] = dev_id
                    else:
                        host_mac_to_entity_id[norm_v] = dev_id
                elif norm_k is not None and v.strip() in dev_by_id:
                    dev_id = v.strip()
                    if dev_id in infra_device_ids:
                        infra_mac_to_device_id[norm_k] = dev_id
                    else:
                        host_mac_to_entity_id[norm_k] = dev_id
                elif norm_v is not None and k.strip() in eq_by_id:
                    host_mac_to_entity_id[norm_v] = k.strip()
                elif norm_k is not None and v.strip() in eq_by_id:
                    host_mac_to_entity_id[norm_k] = v.strip()

        # Check NetworkDevice management_ip and router interface ports (e.g. ConsolidatedRouter)
        for dev in site.devices:
            is_infra = dev.device_id in infra_device_ids
            if dev.management_ip and dev.management_ip.strip() in ip_to_mac:
                m = ip_to_mac[dev.management_ip.strip()]
                if is_infra:
                    infra_mac_to_device_id[m] = dev.device_id
                else:
                    host_mac_to_entity_id.setdefault(m, dev.device_id)

            if dev_role_by_id.get(dev.device_id) == "router":
                for port in dev.ports:
                    if port.connected_mac and not port.connected_device_id:
                        norm_p_mac = _parse_mac_token(port.connected_mac)
                        if norm_p_mac:
                            infra_mac_to_device_id[norm_p_mac] = dev.device_id

        # Check Equipment assigned_ips -> MAC
        for eq in site.equipment:
            for ip_str in eq.assigned_ips:
                cleaned_ip = ip_str.strip()
                if cleaned_ip in ip_to_mac:
                    m = ip_to_mac[cleaned_ip]
                    host_mac_to_entity_id[m] = eq.equipment_id

        return {
            "dev_by_id": dev_by_id,
            "dev_role_by_id": dev_role_by_id,
            "infra_device_ids": infra_device_ids,
            "eq_by_id": eq_by_id,
            "infra_mac_to_device_id": infra_mac_to_device_id,
            "host_mac_to_entity_id": host_mac_to_entity_id,
            "mac_to_ips": mac_to_ips,
            "mac_to_vlan_id": mac_to_vlan_id,
        }

    def _is_infrastructure_mac(
        self,
        mac: str,
        *,
        current_device_id: str,
        ctx: Mapping[str, Any],
    ) -> tuple[bool, Optional[str], str]:
        """Return (is_infra, peer_device_id, reason_detail) for a learned MAC address."""
        infra_mac_to_device_id: Mapping[str, str] = ctx["infra_mac_to_device_id"]
        host_mac_to_entity_id: Mapping[str, str] = ctx["host_mac_to_entity_id"]
        dev_role_by_id: Mapping[str, str] = ctx["dev_role_by_id"]

        if mac in infra_mac_to_device_id:
            peer_id = infra_mac_to_device_id[mac]
            if peer_id == current_device_id:
                return False, None, ""
            role = dev_role_by_id.get(peer_id, "infrastructure")
            return True, peer_id, f"known {role} {peer_id} ({mac})"

        # If explicitly assigned to an edge Equipment or non-switch/non-router device, not an uplink
        if mac in host_mac_to_entity_id:
            return False, None, ""

        oui = _extract_oui_prefix(mac)
        if oui and oui in self.oui_vendors:
            vendor, role_hint = self.oui_vendors[oui]
            if role_hint in ("router", "switch"):
                return True, None, f"{vendor} {role_hint} OUI {oui} ({mac})"

        return False, None, ""

    def classify_site_ports(
        self,
        site: Site,
        fdb_entries: Sequence[FdbEntry],
        *,
        arp_entries: Sequence[ArpEntry] = (),
        device_mac_map: Optional[Mapping[str, str]] = None,
        voip_vlan_ids: Sequence[str] = (),
        include_empty_ports: bool = False,
    ) -> list[PortClassificationResult]:
        """Classify switch ports into `access`, `trunk`, `uplink`, or `empty` modes without mutating `site`."""
        if not isinstance(site, Site):
            raise ValueError("site must be a Site instance")

        ctx = self._build_site_lookup_context(
            site,
            arp_entries=arp_entries,
            device_mac_map=device_mac_map,
        )
        voip_vlan_set: set[str] = {
            str(v).strip() for v in voip_vlan_ids if v is not None and str(v).strip()
        }

        # Group FdbEntry records by (device_id, port_name)
        grouped: dict[tuple[str, str], list[FdbEntry]] = {}
        ordered_port_keys: list[tuple[str, str]] = []

        dev_by_id: Mapping[str, NetworkDevice] = ctx["dev_by_id"]

        for entry in fdb_entries:
            resolved_port_name = entry.port_name
            if entry.device_id in dev_by_id:
                dev = dev_by_id[entry.device_id]
                for p in dev.ports:
                    if p.port_id == entry.port_name or p.name == entry.port_name:
                        resolved_port_name = p.name
                        break
            key = (entry.device_id, resolved_port_name)
            if key not in grouped:
                grouped[key] = []
                ordered_port_keys.append(key)
            grouped[key].append(entry)

        if include_empty_ports:
            for dev in site.devices:
                if ctx["dev_role_by_id"].get(dev.device_id) not in ("switch", "router"):
                    continue
                for p in dev.ports:
                    key = (dev.device_id, p.name)
                    if key not in grouped:
                        grouped[key] = []
                        ordered_port_keys.append(key)

        results: list[PortClassificationResult] = []
        host_mac_to_entity_id: Mapping[str, str] = ctx["host_mac_to_entity_id"]
        mac_to_ips: Mapping[str, list[str]] = ctx["mac_to_ips"]
        mac_to_vlan_id: Mapping[str, str] = ctx["mac_to_vlan_id"]

        for dev_id, port_name in ordered_port_keys:
            port_entries = grouped[(dev_id, port_name)]
            unique_macs: list[str] = []
            unique_vlans: list[str] = []
            mac_vlan_map: dict[str, list[str]] = {}

            for e in port_entries:
                if e.mac_address not in unique_macs:
                    unique_macs.append(e.mac_address)
                mac_vlan_map.setdefault(e.mac_address, [])
                effective_vlan = e.vlan_id or mac_to_vlan_id.get(e.mac_address)
                if effective_vlan:
                    if effective_vlan not in unique_vlans:
                        unique_vlans.append(effective_vlan)
                    if effective_vlan not in mac_vlan_map[e.mac_address]:
                        mac_vlan_map[e.mac_address].append(effective_vlan)

            mac_count = len(unique_macs)

            # 1. Empty port
            if mac_count == 0:
                results.append(
                    PortClassificationResult(
                        device_id=dev_id,
                        port_name=port_name,
                        port_mode="empty",
                        learned_mac_count=0,
                        vlan_ids=[],
                        bound_mac=None,
                        bound_device_id=None,
                        rationale="No MAC addresses learned on port",
                    )
                )
                continue

            # 2. Check for known router/switch infrastructure MACs -> Uplink
            infra_hits: list[tuple[str, Optional[str], str]] = []
            for m in unique_macs:
                is_infra, peer_id, reason_str = self._is_infrastructure_mac(
                    m, current_device_id=dev_id, ctx=ctx
                )
                if is_infra:
                    infra_hits.append((m, peer_id, reason_str))

            if infra_hits:
                peer_ids: list[str] = []
                for _, p_id, _ in infra_hits:
                    if p_id and p_id not in peer_ids:
                        peer_ids.append(p_id)

                bound_peer_id: Optional[str] = (
                    peer_ids[0] if len(peer_ids) == 1 else None
                )
                bound_peer_mac: Optional[str] = (
                    infra_hits[0][0]
                    if mac_count == 1 and len(infra_hits) == 1
                    else None
                )
                reasons_joined = "; ".join(r for _, _, r in infra_hits)
                results.append(
                    PortClassificationResult(
                        device_id=dev_id,
                        port_name=port_name,
                        port_mode="uplink",
                        learned_mac_count=mac_count,
                        vlan_ids=unique_vlans,
                        bound_mac=bound_peer_mac,
                        bound_device_id=bound_peer_id,
                        rationale=f"Uplink port detected via {reasons_joined}",
                    )
                )
                continue

            # 3. Check for Trunk (> max_access_macs or multi-VLAN non-VoIP)
            if mac_count > self.max_access_macs:
                results.append(
                    PortClassificationResult(
                        device_id=dev_id,
                        port_name=port_name,
                        port_mode="trunk",
                        learned_mac_count=mac_count,
                        vlan_ids=unique_vlans,
                        bound_mac=None,
                        bound_device_id=None,
                        rationale=(
                            f"Trunk port: learned {mac_count} MACs "
                            f"(exceeds max_access_macs={self.max_access_macs})"
                        ),
                    )
                )
                continue

            is_voip_dual_vlan = (
                mac_count == 2
                and len(unique_vlans) == 2
                and bool(voip_vlan_set)
                and len(set(unique_vlans) & voip_vlan_set) == 1
            )
            if len(unique_vlans) > 1 and not is_voip_dual_vlan:
                results.append(
                    PortClassificationResult(
                        device_id=dev_id,
                        port_name=port_name,
                        port_mode="trunk",
                        learned_mac_count=mac_count,
                        vlan_ids=unique_vlans,
                        bound_mac=None,
                        bound_device_id=None,
                        rationale=(
                            f"Trunk port: multiple VLANs ({', '.join(unique_vlans)}) learned on port"
                        ),
                    )
                )
                continue

            # 4. Access port (1 <= mac_count <= max_access_macs)
            # Prefer MAC matching a known Equipment or non-infra NetworkDevice
            # If voip_vlan_set is provided, also prefer the MAC on the data VLAN over the voice VLAN
            data_mac_candidates = [
                m
                for m in unique_macs
                if not (
                    voip_vlan_set
                    and mac_vlan_map.get(m)
                    and set(mac_vlan_map[m]).issubset(voip_vlan_set)
                )
            ] or unique_macs
            selected_mac: str = data_mac_candidates[0]
            selected_entity_id: Optional[str] = None

            for m in data_mac_candidates:
                if m in host_mac_to_entity_id:
                    selected_mac = m
                    selected_entity_id = host_mac_to_entity_id[m]
                    break

            if selected_entity_id is None:
                for m in unique_macs:
                    if m in host_mac_to_entity_id:
                        selected_mac = m
                        selected_entity_id = host_mac_to_entity_id[m]
                        break

            if selected_entity_id is None:
                for m in data_mac_candidates:
                    if m in mac_to_ips:
                        selected_mac = m
                        break

            # Order vlan_ids so the data VLAN (if VoIP+PC dual-VLAN) comes first
            ordered_vlans = list(unique_vlans)
            if voip_vlan_set and len(ordered_vlans) > 1:
                ordered_vlans.sort(key=lambda v: (1 if v in voip_vlan_set else 0))

            if mac_count == 1:
                rationale = f"Single-MAC access port bound to {selected_mac}"
            else:
                rationale = (
                    f"Dual-MAC/VoIP+PC access port ({mac_count} MACs <= max_access_macs={self.max_access_macs}) "
                    f"bound to {selected_mac}"
                )

            results.append(
                PortClassificationResult(
                    device_id=dev_id,
                    port_name=port_name,
                    port_mode="access",
                    learned_mac_count=mac_count,
                    vlan_ids=ordered_vlans,
                    bound_mac=selected_mac,
                    bound_device_id=selected_entity_id,
                    rationale=rationale,
                )
            )

        return results

    def map_site_ports(
        self,
        site: Site,
        fdb_entries: Sequence[FdbEntry],
        *,
        arp_entries: Sequence[ArpEntry] = (),
        device_mac_map: Optional[Mapping[str, str]] = None,
        voip_vlan_ids: Sequence[str] = (),
        include_empty_ports: bool = False,
        bind_uplink_devices: bool = True,
    ) -> list[PortClassificationResult]:
        """Classify switch ports and automatically update `Site` switch `Port` and `Equipment` bindings.

        Pass `voip_vlan_ids` for VoIP+PC ports whose phone and PC sit on different VLANs;
        without it those ports are classified as `trunk`.
        """
        results = self.classify_site_ports(
            site,
            fdb_entries,
            arp_entries=arp_entries,
            device_mac_map=device_mac_map,
            voip_vlan_ids=voip_vlan_ids,
            include_empty_ports=include_empty_ports,
        )

        dev_by_id: dict[str, NetworkDevice] = {d.device_id: d for d in site.devices}
        eq_by_id: dict[str, Equipment] = {e.equipment_id: e for e in site.equipment}
        infra_device_ids = self._infrastructure_device_ids(site)

        for res in results:
            dev = dev_by_id.get(res.device_id)
            if dev is None:
                continue

            mgr = DevicePortManager(dev)
            try:
                port = mgr.get_port(res.port_name)
            except KeyError:
                port = mgr.add_port(res.port_name)

            if res.port_mode != "empty":
                # Drop stale Equipment links to this port; access bindings re-add below
                _unlink_port_from_equipment(site, dev, port)

            if res.port_mode == "access":
                port.oper_status = "up"
                port.connected_mac = res.bound_mac
                port.connected_device_id = res.bound_device_id
                if res.vlan_ids:
                    port.vlan_id = res.vlan_ids[0]
                if res.bound_device_id and res.bound_device_id in eq_by_id:
                    eq = eq_by_id[res.bound_device_id]
                    if (
                        port.port_id not in eq.connected_ports
                        and port.name not in eq.connected_ports
                    ):
                        eq.connected_ports.append(port.port_id)

            elif res.port_mode == "trunk":
                port.oper_status = "up"
                # Never bind an end-host (Equipment or non-infra device) or single MAC to a trunk port
                if (
                    port.connected_device_id
                    and port.connected_device_id not in infra_device_ids
                ):
                    port.connected_device_id = None
                port.connected_mac = None

            elif res.port_mode == "uplink":
                port.oper_status = "up"
                # Never bind an end-host (Equipment or non-infra device) to an uplink port
                if (
                    port.connected_device_id
                    and port.connected_device_id not in infra_device_ids
                ):
                    port.connected_device_id = None
                if (
                    bind_uplink_devices
                    and res.bound_device_id
                    and res.bound_device_id in dev_by_id
                ):
                    port.connected_device_id = res.bound_device_id
                    port.connected_mac = res.bound_mac
                else:
                    port.connected_mac = None

        return results

    def classify_device_ports(
        self,
        device: NetworkDevice,
        fdb_entries: Sequence[FdbEntry],
        *,
        site: Optional[Site] = None,
        arp_entries: Sequence[ArpEntry] = (),
        device_mac_map: Optional[Mapping[str, str]] = None,
        voip_vlan_ids: Sequence[str] = (),
        include_empty_ports: bool = False,
    ) -> list[PortClassificationResult]:
        """Classify switch ports for a single `NetworkDevice`."""
        if not isinstance(device, NetworkDevice):
            raise ValueError("device must be a NetworkDevice instance")
        target_site = (
            site
            if site is not None
            else Site(
                site_id=device.site_id,
                name=device.site_id,
                devices=[device],
            )
        )
        filtered_entries = [
            e for e in fdb_entries if e.device_id == device.device_id
        ]
        all_results = self.classify_site_ports(
            target_site,
            filtered_entries,
            arp_entries=arp_entries,
            device_mac_map=device_mac_map,
            voip_vlan_ids=voip_vlan_ids,
            include_empty_ports=include_empty_ports,
        )
        return [r for r in all_results if r.device_id == device.device_id]

    apply_to_site = map_site_ports
