"""Hypervisor VM NIC binding and VM inventory records, plus equipment VM hint extraction."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from sot_validator.models import Equipment, EquipmentCategory
from sot_validator.signals._hypervisor_common import (
    _MOREF_PATTERN,
    GuestToolsStatus,
    VmPowerState,
    _clean_optional_str,
    _format_mac_canonical,
    _infer_guest_os_family,
    _looks_like_uuid,
    _normalize_ip,
    _normalize_mac,
    _normalize_uuid,
    _parse_optional_bool,
    _require_non_empty_str,
    _split_str_items,
    normalize_guest_tools_status,
    normalize_vm_power_state,
)
from sot_validator.signals.base import normalize_utc_datetime


@dataclass
class VmNicBinding:
    """Virtual machine guest network adapter binding."""

    mac_address: Optional[str] = None
    ip_addresses: list[str] = field(default_factory=list)
    nic_label: Optional[str] = None
    vlan_id: Optional[int | str] = None
    connected: Optional[bool] = None

    def __post_init__(self) -> None:
        self.mac_address = _format_mac_canonical(self.mac_address)
        ips: list[str] = []
        for raw_ip in _split_str_items(self.ip_addresses):
            norm_ip = _normalize_ip(raw_ip)
            if norm_ip and norm_ip not in ips:
                ips.append(norm_ip)
        self.ip_addresses = ips
        self.nic_label = _clean_optional_str(self.nic_label)
        if isinstance(self.vlan_id, str):
            cleaned_vlan = self.vlan_id.strip()
            if not cleaned_vlan:
                self.vlan_id = None
            elif cleaned_vlan.isdigit():
                self.vlan_id = int(cleaned_vlan)
            else:
                self.vlan_id = cleaned_vlan
        self.connected = _parse_optional_bool(self.connected)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nic_label": self.nic_label,
            "mac_address": self.mac_address,
            "ip_addresses": list(self.ip_addresses),
            "vlan_id": self.vlan_id,
            "connected": self.connected,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VmNicBinding:
        raw_ips = data.get("ip_addresses")
        if raw_ips is None:
            raw_ips = data.get("ip_address") or data.get("ip")
        return cls(
            mac_address=data.get("mac_address") or data.get("mac"),
            ip_addresses=_split_str_items(raw_ips),
            nic_label=data.get("nic_label") or data.get("label") or data.get("name"),
            vlan_id=data.get("vlan_id") if data.get("vlan_id") is not None else data.get("vlan"),
            connected=data.get("connected"),
        )


@dataclass
class HypervisorVmRecord:
    """Normalized virtual machine inventory record owned by a vCenter instance."""

    vcenter_instance: str
    vm_moref: str
    vm_name: str
    power_state: VmPowerState
    vcenter_host: Optional[str] = None
    site_id: Optional[str] = None
    bios_uuid: Optional[str] = None
    instance_uuid: Optional[str] = None
    guest_hostname: Optional[str] = None
    guest_os_family: Optional[str] = None
    guest_os_full_name: Optional[str] = None
    guest_tools_status: Optional[GuestToolsStatus] = None
    tools_heartbeat: Optional[str] = None
    icmp_blocked_by_host_firewall: Optional[bool] = None
    nics: list[VmNicBinding] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    mac_addresses: list[str] = field(default_factory=list)
    last_updated: Optional[datetime] = None
    power_state_changed_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        self.vcenter_instance = _require_non_empty_str(
            self.vcenter_instance, "vcenter_instance"
        )
        self.vm_moref = _require_non_empty_str(self.vm_moref, "vm_moref")
        self.vm_name = _require_non_empty_str(self.vm_name, "vm_name")
        self.power_state = normalize_vm_power_state(self.power_state)
        self.vcenter_host = _clean_optional_str(self.vcenter_host)
        self.site_id = _clean_optional_str(self.site_id)
        self.bios_uuid = _normalize_uuid(self.bios_uuid)
        self.instance_uuid = _normalize_uuid(self.instance_uuid)
        self.guest_hostname = _clean_optional_str(self.guest_hostname)
        self.guest_os_full_name = _clean_optional_str(self.guest_os_full_name)
        self.guest_os_family = _infer_guest_os_family(
            self.guest_os_family, self.guest_os_full_name
        )
        self.guest_tools_status = normalize_guest_tools_status(self.guest_tools_status)
        hb = _clean_optional_str(self.tools_heartbeat)
        self.tools_heartbeat = hb.lower() if hb else None
        self.icmp_blocked_by_host_firewall = _parse_optional_bool(
            self.icmp_blocked_by_host_firewall
        )

        self.nics = [
            nic if isinstance(nic, VmNicBinding) else VmNicBinding.from_dict(nic)
            for nic in (self.nics or [])
        ]

        merged_ips: list[str] = []
        for raw_ip in _split_str_items(self.ip_addresses):
            norm_ip = _normalize_ip(raw_ip)
            if norm_ip and norm_ip not in merged_ips:
                merged_ips.append(norm_ip)
        for nic in self.nics:
            for nic_ip in nic.ip_addresses:
                if nic_ip and nic_ip not in merged_ips:
                    merged_ips.append(nic_ip)
        self.ip_addresses = merged_ips

        merged_macs: list[str] = []
        seen_norm_macs: set[str] = set()
        for raw_mac in _split_str_items(self.mac_addresses):
            norm_mac = _normalize_mac(raw_mac)
            canon_mac = _format_mac_canonical(raw_mac)
            if norm_mac and canon_mac and norm_mac not in seen_norm_macs:
                seen_norm_macs.add(norm_mac)
                merged_macs.append(canon_mac)
        for nic in self.nics:
            if nic.mac_address:
                norm_mac = _normalize_mac(nic.mac_address)
                canon_mac = _format_mac_canonical(nic.mac_address)
                if norm_mac and canon_mac and norm_mac not in seen_norm_macs:
                    seen_norm_macs.add(norm_mac)
                    merged_macs.append(canon_mac)
        self.mac_addresses = merged_macs

        if self.last_updated is not None:
            self.last_updated = normalize_utc_datetime(
                self.last_updated, field_name="last_updated"
            )
        if self.power_state_changed_at is not None:
            self.power_state_changed_at = normalize_utc_datetime(
                self.power_state_changed_at, field_name="power_state_changed_at"
            )

    @property
    def tools_status(self) -> Optional[GuestToolsStatus]:
        """Alias for guest_tools_status matching vCenter snapshot field naming."""
        return self.guest_tools_status

    @property
    def is_windows(self) -> bool:
        """Return True if the VM guest OS family is Windows."""
        return self.guest_os_family == "windows"

    @property
    def has_healthy_tools_heartbeat(self) -> bool:
        """Return True if VMware Guest Tools is running/healthy or heartbeat is green."""
        if self.guest_tools_status in (
            GuestToolsStatus.TOOLS_OK,
            GuestToolsStatus.TOOLS_OLD,
        ):
            return True
        if self.tools_heartbeat == "green":
            return True
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "vcenter_instance": self.vcenter_instance,
            "vcenter_host": self.vcenter_host,
            "site_id": self.site_id,
            "vm_moref": self.vm_moref,
            "bios_uuid": self.bios_uuid,
            "instance_uuid": self.instance_uuid,
            "vm_name": self.vm_name,
            "guest_hostname": self.guest_hostname,
            "guest_os_family": self.guest_os_family,
            "guest_os_full_name": self.guest_os_full_name,
            "power_state": self.power_state.value,
            "guest_tools_status": (
                self.guest_tools_status.value
                if self.guest_tools_status is not None
                else None
            ),
            "tools_status": (
                self.guest_tools_status.value
                if self.guest_tools_status is not None
                else None
            ),
            "tools_heartbeat": self.tools_heartbeat,
            "icmp_blocked_by_host_firewall": self.icmp_blocked_by_host_firewall,
            "nics": [nic.to_dict() for nic in self.nics],
            "ip_addresses": list(self.ip_addresses),
            "mac_addresses": list(self.mac_addresses),
            "last_updated": (
                self.last_updated.isoformat()
                if self.last_updated is not None
                else None
            ),
            "power_state_changed_at": (
                self.power_state_changed_at.isoformat()
                if self.power_state_changed_at is not None
                else None
            ),
        }

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        default_vcenter_instance: Optional[str] = None,
    ) -> HypervisorVmRecord:
        vcenter_instance = (
            _clean_optional_str(
                data.get("vcenter_instance")
                or data.get("VI SDK Server")
                or data.get("vcenter")
                or data.get("vcenter_server")
            )
            or _clean_optional_str(default_vcenter_instance)
            or _clean_optional_str(data.get("vcenter_host"))
        )
        if not vcenter_instance:
            raise ValueError("vcenter_instance must be a non-empty string")

        vcenter_host = _clean_optional_str(
            data.get("vcenter_host")
            or data.get("VI SDK Server")
            or (
                vcenter_instance
                if "." in vcenter_instance
                else None
            )
        )
        # If vcenter_instance was given as full FQDN and no separate short name, keep as provided;
        # matching handles short-name vs FQDN transparently.

        vm_moref = _clean_optional_str(
            data.get("vm_moref")
            or data.get("vcenter_moref")
            or data.get("moref")
            or data.get("VM ID")
            or data.get("vm_id")
        )
        if not vm_moref:
            raise ValueError("vm_moref must be a non-empty string")

        vm_name = _clean_optional_str(
            data.get("vm_name")
            or data.get("VM")
            or data.get("name")
            or data.get("guest_hostname")
            or data.get("DNS Name")
        )
        if not vm_name:
            raise ValueError("vm_name must be a non-empty string")

        raw_power = (
            data.get("power_state")
            if data.get("power_state") is not None
            else (
                data.get("Powerstate")
                if data.get("Powerstate") is not None
                else data.get("powerstate")
            )
        )
        power_state = normalize_vm_power_state(raw_power)

        bios_uuid = _clean_optional_str(
            data.get("bios_uuid")
            or data.get("vcenter_bios_uuid")
            or data.get("UUID")
            or data.get("VM UUID")
            or data.get("uuid")
        )
        instance_uuid = _clean_optional_str(
            data.get("instance_uuid") or data.get("SMBIOS UUID")
        )

        guest_hostname = _clean_optional_str(
            data.get("guest_hostname")
            or data.get("DNS Name")
            or data.get("hostname")
        )
        guest_os_full_name = _clean_optional_str(
            data.get("guest_os_full_name")
            or data.get("OS according to the configuration file")
            or data.get("OS according to the VMware Tools")
            or data.get("guest_os")
        )
        guest_os_family = _clean_optional_str(data.get("guest_os_family"))

        raw_tools = (
            data.get("guest_tools_status")
            if data.get("guest_tools_status") is not None
            else (
                data.get("tools_status")
                if data.get("tools_status") is not None
                else data.get("Tools")
            )
        )
        guest_tools_status = normalize_guest_tools_status(raw_tools)

        tools_heartbeat = _clean_optional_str(
            data.get("tools_heartbeat")
            or data.get("Heartbeat")
            or data.get("heartbeat")
        )

        icmp_blocked = data.get("icmp_blocked_by_host_firewall")

        raw_nics = data.get("nics") or []
        nics = [
            nic if isinstance(nic, VmNicBinding) else VmNicBinding.from_dict(nic)
            for nic in raw_nics
        ]

        top_ips = _split_str_items(
            data.get("ip_addresses")
            if data.get("ip_addresses") is not None
            else (
                data.get("primary_ip")
                if data.get("primary_ip") is not None
                else data.get("Primary IP Address")
            )
        )
        top_macs = _split_str_items(
            data.get("mac_addresses")
            if data.get("mac_addresses") is not None
            else (
                data.get("mac_address")
                if data.get("mac_address") is not None
                else data.get("Mac Address")
            )
        )

        if not nics and (top_macs or top_ips):
            nics.append(
                VmNicBinding(
                    mac_address=top_macs[0] if top_macs else None,
                    ip_addresses=top_ips,
                    nic_label="Network adapter 1",
                )
            )

        last_updated = _clean_optional_str(
            data.get("last_updated") or data.get("export_timestamp")
        ) or (
            data.get("last_updated")
            if isinstance(data.get("last_updated"), datetime)
            else None
        )
        power_state_changed_at = _clean_optional_str(
            data.get("power_state_changed_at") or data.get("poweroff_timestamp")
        ) or (
            data.get("power_state_changed_at")
            if isinstance(data.get("power_state_changed_at"), datetime)
            else None
        )

        return cls(
            vcenter_instance=vcenter_instance,
            vcenter_host=vcenter_host,
            site_id=_clean_optional_str(data.get("site_id") or data.get("Datacenter")),
            vm_moref=vm_moref,
            bios_uuid=bios_uuid,
            instance_uuid=instance_uuid,
            vm_name=vm_name,
            guest_hostname=guest_hostname,
            guest_os_family=guest_os_family,
            guest_os_full_name=guest_os_full_name,
            power_state=power_state,
            guest_tools_status=guest_tools_status,
            tools_heartbeat=tools_heartbeat,
            icmp_blocked_by_host_firewall=icmp_blocked,
            nics=nics,
            ip_addresses=top_ips,
            mac_addresses=top_macs,
            last_updated=last_updated,
            power_state_changed_at=power_state_changed_at,
        )


def _extract_equipment_vm_hints(
    equipment: Equipment,
    *,
    bios_uuid: Optional[str] = None,
    vcenter_instance: Optional[str] = None,
    vm_moref: Optional[str] = None,
    mac_addresses: Optional[Iterable[str]] = None,
) -> tuple[
    list[str],
    Optional[str],
    Optional[str],
    list[str],
    bool,
]:
    """Extract (uuid_candidates, vcenter_instance_hint, vm_moref_hint, mac_candidates, has_vm_hint)."""
    uuids: list[str] = []

    def _add_uuid(val: Optional[str]) -> None:
        norm = _normalize_uuid(val)
        if norm and norm not in uuids:
            uuids.append(norm)

    if bios_uuid:
        _add_uuid(bios_uuid)

    for attr in ("vcenter_bios_uuid", "bios_uuid", "instance_uuid", "uuid"):
        attr_val = getattr(equipment, attr, None)
        if isinstance(attr_val, str) and attr_val.strip():
            _add_uuid(attr_val)

    inst_hint = _clean_optional_str(vcenter_instance)
    if not inst_hint:
        for attr in ("vcenter_instance", "vcenter_host"):
            attr_val = getattr(equipment, attr, None)
            if isinstance(attr_val, str) and attr_val.strip():
                inst_hint = attr_val.strip()
                break

    moref_hint = _clean_optional_str(vm_moref)
    if not moref_hint:
        for attr in ("vcenter_moref", "vm_moref", "moref"):
            attr_val = getattr(equipment, attr, None)
            if isinstance(attr_val, str) and attr_val.strip():
                moref_hint = attr_val.strip()
                break

    hyp_id = _clean_optional_str(equipment.hypervisor_id)
    if hyp_id:
        if hyp_id.lower().startswith("uuid:") or _looks_like_uuid(hyp_id):
            _add_uuid(hyp_id)
        elif ":" in hyp_id or "/" in hyp_id:
            sep = ":" if ":" in hyp_id else "/"
            left, right = [part.strip() for part in hyp_id.split(sep, 1)]
            if left and not inst_hint:
                inst_hint = left
            if right:
                if _looks_like_uuid(right):
                    _add_uuid(right)
                elif not moref_hint:
                    moref_hint = right
        elif _MOREF_PATTERN.match(hyp_id):
            if not moref_hint:
                moref_hint = hyp_id
        else:
            if not inst_hint:
                inst_hint = hyp_id

    macs: list[str] = []
    if mac_addresses:
        for m in mac_addresses:
            if isinstance(m, str) and m.strip():
                macs.append(m.strip())
    for attr in ("mac_address", "mac_addresses"):
        attr_val = getattr(equipment, attr, None)
        for m in _split_str_items(attr_val):
            if m not in macs:
                macs.append(m)

    has_vm_hint = bool(
        equipment.category is EquipmentCategory.VM
        or uuids
        or inst_hint
        or moref_hint
        or hyp_id
    )
    return uuids, inst_hint, moref_hint, macs, has_vm_hint

