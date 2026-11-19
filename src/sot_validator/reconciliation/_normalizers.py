"""Discovery feed normalizers and SoT matching helpers for InventoryReconciler."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
import ipaddress
import re
from typing import Any, Optional

from sot_validator.models import (
    ArpEntry,
    Equipment,
    SignalStatus,
    Site,
    Subnet,
    ValidationSignal,
)
from sot_validator.reconciliation._records import _clean_optional_str, _hostnames_match
from sot_validator.signals.hypervisor import (
    HypervisorInventoryProvider,
    HypervisorVmRecord,
    MultiVCenterInventoryProvider,
    _extract_equipment_vm_hints,
    _format_mac_canonical,
    _instances_match,
    _normalize_ip,
    _normalize_mac,
    _normalize_uuid,
)
from sot_validator.signals.icmp import IcmpProbeResponse
from sot_validator.signals.management import (
    APC_ENTERPRISE_OID_PREFIX,
    EXTREME_ENTERPRISE_OID_PREFIX,
    FixtureManagementTransport,
    SNMPV2_MIB_SYS_DESCR,
    SNMPV2_MIB_SYS_NAME,
    parse_apc_ups_oids,
    parse_extreme_switch_oids,
)


@dataclass
class _NormalizedArpObservation:
    ip: str
    mac: str
    site_id: Optional[str] = None
    subnet_id: Optional[str] = None
    arp_source_device_id: Optional[str] = None
    connected_port: Optional[str] = None
    hostname: Optional[str] = None


@dataclass
class _NormalizedSnmpObservation:
    ip: str
    sys_name: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    role: Optional[str] = None
    mac_address: Optional[str] = None
    os_version: Optional[str] = None
    serial_number: Optional[str] = None
    site_id: Optional[str] = None
    is_ups: bool = False


class _ReconcilerNormalizers:
    """Feed normalizers and SoT matching helpers inherited by InventoryReconciler."""

    @staticmethod
    def _normalize_sites(
        sites: Sequence[Site | Mapping[str, Any]]
        | Mapping[str, Site | Mapping[str, Any]]
        | Site,
    ) -> dict[str, Site]:
        if isinstance(sites, Site):
            return {sites.site_id: sites}
        if isinstance(sites, Mapping):
            if "site_id" in sites and "name" in sites:
                single = Site.from_dict(sites)
                return {single.site_id: single}
            indexed: dict[str, Site] = {}
            for _, raw_site in sites.items():
                site_obj = (
                    raw_site if isinstance(raw_site, Site) else Site.from_dict(raw_site)
                )
                indexed[site_obj.site_id] = site_obj
            return dict(sorted(indexed.items(), key=lambda kv: kv[0]))
        indexed = {}
        for item in sites:
            site_obj = item if isinstance(item, Site) else Site.from_dict(item)
            indexed[site_obj.site_id] = site_obj
        return dict(sorted(indexed.items(), key=lambda kv: kv[0]))

    @staticmethod
    def _build_subnet_index(
        sites_by_id: Mapping[str, Site],
    ) -> list[tuple[str, Subnet, ipaddress.IPv4Network]]:
        subnet_index: list[tuple[str, Subnet, ipaddress.IPv4Network]] = []
        for site_id, site in sites_by_id.items():
            for subnet in site.subnets:
                try:
                    net = ipaddress.ip_network(subnet.cidr.strip(), strict=False)
                except ValueError:
                    continue
                if isinstance(net, ipaddress.IPv4Network) and net.prefixlen == 24:
                    subnet_index.append((site_id, subnet, net))
        return subnet_index

    @staticmethod
    def _match_ip_to_allocated_subnet(
        ip_str: Optional[str],
        subnet_index: Sequence[tuple[str, Subnet, ipaddress.IPv4Network]],
        *,
        site_id_filter: Optional[str] = None,
    ) -> Optional[tuple[str, Subnet, str]]:
        cleaned = _normalize_ip(ip_str)
        if not cleaned or "/" in cleaned:
            return None
        try:
            addr = ipaddress.ip_address(cleaned)
        except ValueError:
            return None
        if not isinstance(addr, ipaddress.IPv4Address):
            return None
        if addr.is_loopback or addr.is_multicast or addr.is_unspecified:
            return None

        norm_ip = str(addr)
        filter_lower = site_id_filter.strip().lower() if site_id_filter else None
        for site_id, subnet, net in subnet_index:
            if filter_lower and site_id.lower() != filter_lower:
                continue
            if addr in net and addr != net.network_address and addr != net.broadcast_address:
                return site_id, subnet, norm_ip
        return None

    @staticmethod
    def _normalize_vm_records(
        vcenter_provider: Optional[
            HypervisorInventoryProvider
            | Sequence[HypervisorVmRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ],
        vms: Optional[Sequence[HypervisorVmRecord | Mapping[str, Any]]],
    ) -> list[HypervisorVmRecord]:
        records: list[HypervisorVmRecord] = []
        if isinstance(vcenter_provider, HypervisorInventoryProvider):
            records.extend(vcenter_provider.list_vms())
        elif isinstance(vcenter_provider, Mapping):
            provider = MultiVCenterInventoryProvider.from_dict(vcenter_provider)
            records.extend(provider.list_vms())
        elif isinstance(vcenter_provider, Sequence):
            for item in vcenter_provider:
                records.append(
                    item
                    if isinstance(item, HypervisorVmRecord)
                    else HypervisorVmRecord.from_dict(item)
                )

        if vms is not None:
            for item in vms:
                records.append(
                    item
                    if isinstance(item, HypervisorVmRecord)
                    else HypervisorVmRecord.from_dict(item)
                )
        return records

    @classmethod
    def _normalize_arp_observations(
        cls,
        arp_entries: Optional[
            Sequence[ArpEntry | Mapping[str, Any]] | Mapping[str, Any]
        ],
    ) -> list[_NormalizedArpObservation]:
        if arp_entries is None:
            return []

        raw_items: list[tuple[Optional[str], Any]] = []
        if isinstance(arp_entries, Mapping):
            if "ip" in arp_entries or "ip_address" in arp_entries:
                raw_items.append((None, arp_entries))
            else:
                for key, val in arp_entries.items():
                    if isinstance(val, str):
                        raw_items.append(
                            (None, {"ip": str(key), "arp_mac": val})
                        )
                    elif isinstance(val, ArpEntry):
                        raw_items.append((str(key), val))
                    elif isinstance(val, Mapping):
                        item_copy = dict(val)
                        if "ip" not in item_copy and "ip_address" not in item_copy:
                            item_copy["ip"] = str(key)
                            raw_items.append((None, item_copy))
                        else:
                            raw_items.append((str(key), item_copy))
                    elif isinstance(val, Sequence):
                        for entry in val:
                            raw_items.append((str(key), entry))
        else:
            for entry in arp_entries:
                raw_items.append((None, entry))

        observations: list[_NormalizedArpObservation] = []
        for site_hint, item in raw_items:
            if isinstance(item, ArpEntry):
                ip_val = _normalize_ip(item.ip)
                mac_val = _format_mac_canonical(item.arp_mac)
                if not ip_val or not mac_val:
                    continue
                resolved_site = (
                    site_hint
                    if site_hint and not site_hint[0].isdigit()
                    else None
                )
                observations.append(
                    _NormalizedArpObservation(
                        ip=ip_val,
                        mac=mac_val,
                        site_id=resolved_site,
                        subnet_id=_clean_optional_str(item.subnet_id),
                        arp_source_device_id=_clean_optional_str(
                            item.arp_source_device_id
                        ),
                    )
                )
            elif isinstance(item, Mapping):
                ip_val = _normalize_ip(
                    item.get("ip") or item.get("ip_address")
                )
                mac_val = _format_mac_canonical(
                    item.get("arp_mac")
                    or item.get("mac_address")
                    or item.get("mac")
                )
                if not ip_val or not mac_val:
                    continue
                explicit_site = _clean_optional_str(item.get("site_id")) or (
                    site_hint
                    if site_hint and not site_hint[0].isdigit()
                    else None
                )
                observations.append(
                    _NormalizedArpObservation(
                        ip=ip_val,
                        mac=mac_val,
                        site_id=explicit_site,
                        subnet_id=_clean_optional_str(item.get("subnet_id")),
                        arp_source_device_id=_clean_optional_str(
                            item.get("arp_source_device_id")
                            or item.get("device_id")
                        ),
                        connected_port=_clean_optional_str(
                            item.get("connected_port")
                            or item.get("connected_port_id")
                            or item.get("port_id")
                            or item.get("port_name")
                            or item.get("port")
                        ),
                        hostname=_clean_optional_str(item.get("hostname")),
                    )
                )
        return observations

    @classmethod
    def _normalize_snmp_observations(
        cls,
        snmp_targets: Optional[
            Mapping[str, Any]
            | Sequence[Mapping[str, Any]]
            | FixtureManagementTransport
        ],
    ) -> list[_NormalizedSnmpObservation]:
        if snmp_targets is None:
            return []

        raw_entries: list[tuple[Optional[str], Optional[str], Mapping[str, Any]]] = []
        if isinstance(snmp_targets, FixtureManagementTransport):
            for key, entry in snmp_targets._targets_by_id.items():
                raw_entries.append((snmp_targets.site_id, key, entry))
        elif isinstance(snmp_targets, Mapping):
            if "targets" in snmp_targets and isinstance(
                snmp_targets["targets"], Mapping
            ):
                fixture_site = _clean_optional_str(snmp_targets.get("site_id"))
                for key, entry in snmp_targets["targets"].items():
                    if isinstance(entry, Mapping):
                        raw_entries.append((fixture_site, str(key), entry))
            else:
                for key, entry in snmp_targets.items():
                    if isinstance(entry, Mapping):
                        raw_entries.append((None, str(key), entry))
        elif isinstance(snmp_targets, Sequence):
            for entry in snmp_targets:
                if isinstance(entry, Mapping):
                    raw_entries.append((None, None, entry))

        observations: list[_NormalizedSnmpObservation] = []
        for site_hint, key_hint, entry in raw_entries:
            if entry.get("snmp_reachable") is False or entry.get("reachable") is False:
                continue

            raw_oids = entry.get("oids")
            if isinstance(raw_oids, Mapping):
                oids: Mapping[str, Any] = raw_oids
            elif any(str(k).startswith("1.3.6.1.") for k in entry.keys()):
                oids = entry
            else:
                oids = {}

            if (
                entry.get("snmp_reachable") is None
                and entry.get("reachable") is None
                and not oids
                and not entry.get("sys_name")
                and not entry.get("hostname")
                and not entry.get("vendor")
            ):
                continue

            ip_val = _normalize_ip(
                entry.get("ip_address")
                or entry.get("ip")
                or entry.get("mgmt_ip")
                or entry.get("management_ip")
                or (key_hint if key_hint and key_hint[0].isdigit() else None)
            )
            if not ip_val:
                continue

            sys_descr = str(
                oids.get(SNMPV2_MIB_SYS_DESCR, entry.get("sys_descr", ""))
            )
            sys_descr_lower = sys_descr.lower()
            is_extreme = (
                any(
                    str(k).startswith(f"{EXTREME_ENTERPRISE_OID_PREFIX}.")
                    for k in oids
                )
                or "extreme" in sys_descr_lower
                or "extreme" in str(entry.get("vendor", "")).lower()
            )
            is_apc = (
                any(
                    str(k).startswith(f"{APC_ENTERPRISE_OID_PREFIX}.")
                    for k in oids
                )
                or "apc" in sys_descr_lower
                or "smart-ups" in sys_descr_lower
                or "apc" in str(entry.get("vendor", "")).lower()
            )

            parsed_metrics: dict[str, Any] = {}
            if is_extreme and oids:
                parsed_metrics = parse_extreme_switch_oids(oids)
            elif is_apc and oids:
                parsed_metrics = parse_apc_ups_oids(oids)

            sys_name = _clean_optional_str(
                parsed_metrics.get("sys_name")
                or oids.get(SNMPV2_MIB_SYS_NAME)
                or entry.get("sys_name")
                or entry.get("hostname")
                or entry.get("name")
            )
            vendor = _clean_optional_str(
                entry.get("vendor") or parsed_metrics.get("vendor")
            )
            model = _clean_optional_str(
                entry.get("model") or parsed_metrics.get("model")
            )
            if not model and is_extreme:
                model_match = re.search(r"\(([^)]+)\)", sys_descr)
                model = (
                    f"ExtremeSwitching {model_match.group(1)}"
                    if model_match
                    else "ExtremeSwitching"
                )
            elif not model and is_apc:
                model = "Smart-UPS"

            role = _clean_optional_str(
                entry.get("role")
                or entry.get("category")
                or ("ups" if is_apc else ("access-switch" if is_extreme else "network-device"))
            )
            mac_val = _format_mac_canonical(
                entry.get("mac_address") or entry.get("mac")
            )
            os_version = _clean_optional_str(
                entry.get("os_version") or parsed_metrics.get("os_version")
            )
            serial_number = _clean_optional_str(
                entry.get("serial_number") or parsed_metrics.get("serial_number")
            )
            site_id = _clean_optional_str(entry.get("site_id")) or site_hint

            observations.append(
                _NormalizedSnmpObservation(
                    ip=ip_val,
                    sys_name=sys_name,
                    vendor=vendor,
                    model=model,
                    role=role,
                    mac_address=mac_val,
                    os_version=os_version,
                    serial_number=serial_number,
                    site_id=site_id,
                    is_ups=is_apc,
                )
            )
        return observations

    @classmethod
    def _normalize_icmp_reachable_ips(
        cls,
        icmp_responses: Optional[Mapping[str, Any] | Sequence[Any]],
    ) -> list[str]:
        if icmp_responses is None:
            return []

        reachable_ips: list[str] = []

        def _add_ip(raw_ip: Any) -> None:
            norm = _normalize_ip(str(raw_ip) if raw_ip is not None else None)
            if norm and norm not in reachable_ips:
                reachable_ips.append(norm)

        if isinstance(icmp_responses, Mapping):
            if "targets" in icmp_responses and isinstance(
                icmp_responses["targets"], Mapping
            ):
                for entry in icmp_responses["targets"].values():
                    if isinstance(entry, Mapping) and entry.get("icmp_reachable"):
                        _add_ip(entry.get("ip_address") or entry.get("ip"))
            else:
                for key, val in icmp_responses.items():
                    if isinstance(val, bool):
                        if val:
                            _add_ip(key)
                    elif isinstance(val, IcmpProbeResponse):
                        if val.reachable:
                            _add_ip(key)
                    elif isinstance(val, ValidationSignal):
                        if val.status is SignalStatus.ACTIVE:
                            _add_ip(key)
                    elif isinstance(val, Mapping):
                        is_up = val.get(
                            "reachable", val.get("icmp_reachable", True)
                        )
                        if is_up:
                            _add_ip(val.get("ip_address") or val.get("ip") or key)
        elif isinstance(icmp_responses, Sequence) and not isinstance(
            icmp_responses, (str, bytes)
        ):
            for item in icmp_responses:
                if isinstance(item, str):
                    _add_ip(item)
                elif isinstance(item, Mapping):
                    if item.get("reachable", item.get("icmp_reachable", True)):
                        _add_ip(item.get("ip_address") or item.get("ip"))

        return reachable_ips

    @staticmethod
    def _collect_equipment_ips_and_macs(
        equipment: Equipment,
        site: Site,
    ) -> tuple[set[str], set[str]]:
        sot_ips: set[str] = set()
        sot_macs: set[str] = set()

        for raw_ip in equipment.assigned_ips:
            norm_ip = _normalize_ip(raw_ip)
            if norm_ip:
                sot_ips.add(norm_ip)

        for attr in ("mac_address", "mac_addresses"):
            attr_val = getattr(equipment, attr, None)
            if isinstance(attr_val, str):
                norm_m = _normalize_mac(attr_val)
                if norm_m:
                    sot_macs.add(norm_m)
            elif isinstance(attr_val, Iterable):
                for m in attr_val:
                    norm_m = _normalize_mac(str(m))
                    if norm_m:
                        sot_macs.add(norm_m)

        for ip_rec in site.ip_addresses:
            if (
                ip_rec.assigned_object_id == equipment.equipment_id
                or ip_rec.ip in sot_ips
            ):
                norm_ip = _normalize_ip(ip_rec.ip)
                if norm_ip:
                    sot_ips.add(norm_ip)
                for raw_mac in (
                    ip_rec.arp_mac,
                    ip_rec.arp_entry.arp_mac if ip_rec.arp_entry else None,
                ):
                    norm_m = _normalize_mac(raw_mac)
                    if norm_m:
                        sot_macs.add(norm_m)

        for dev in site.devices:
            for port in dev.ports:
                if (
                    port.connected_device_id == equipment.equipment_id
                    and port.connected_mac
                ):
                    norm_m = _normalize_mac(port.connected_mac)
                    if norm_m:
                        sot_macs.add(norm_m)

        return sot_ips, sot_macs

    @classmethod
    def _match_vm_to_equipment(
        cls,
        vm: HypervisorVmRecord,
        site: Site,
    ) -> tuple[Optional[Equipment], Optional[str]]:
        vm_uuids = {
            u
            for u in (
                _normalize_uuid(vm.bios_uuid),
                _normalize_uuid(vm.instance_uuid),
            )
            if u
        }
        vm_moref_lower = vm.vm_moref.lower()
        vm_macs = {
            norm for m in vm.mac_addresses if (norm := _normalize_mac(m)) is not None
        }
        vm_ips = {
            norm for ip in vm.ip_addresses if (norm := _normalize_ip(ip)) is not None
        }

        # Priority 1: BIOS / Instance UUID
        if vm_uuids:
            for eq in site.equipment:
                eq_uuids, _, _, _, _ = _extract_equipment_vm_hints(eq)
                if vm_uuids & set(eq_uuids):
                    return eq, "bios_uuid"

        # Priority 2: (vcenter_instance, vm_moref) or vm_moref
        fallback_moref_match: Optional[Equipment] = None
        for eq in site.equipment:
            _, inst_hint, moref_hint, _, _ = _extract_equipment_vm_hints(eq)
            if moref_hint and moref_hint.lower() == vm_moref_lower:
                if inst_hint is None or _instances_match(
                    inst_hint, vm.vcenter_instance
                ) or _instances_match(inst_hint, vm.vcenter_host):
                    return eq, "vm_moref"
                if fallback_moref_match is None:
                    fallback_moref_match = eq
        if fallback_moref_match is not None:
            return fallback_moref_match, "vm_moref"

        # Priority 3: MAC address or IP address
        ip_fallback_match: Optional[Equipment] = None
        for eq in site.equipment:
            eq_ips, eq_macs = cls._collect_equipment_ips_and_macs(eq, site)
            if vm_macs and (vm_macs & eq_macs):
                return eq, "mac"
            if vm_ips and (vm_ips & eq_ips) and ip_fallback_match is None:
                ip_fallback_match = eq
        if ip_fallback_match is not None:
            return ip_fallback_match, "ip"

        # Priority 4: Normalized hostname
        for eq in site.equipment:
            if _hostnames_match(eq.name, vm.vm_name) or (
                vm.guest_hostname is not None
                and _hostnames_match(eq.name, vm.guest_hostname)
            ):
                return eq, "hostname"

        return None, None
