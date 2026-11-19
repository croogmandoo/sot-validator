"""Read-only hypervisor inventory provider interface and multi-vCenter aggregator."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Mapping, Sequence
import csv
import json
from pathlib import Path
from typing import Any, Optional

from sot_validator.models import ArpEntry, Equipment, IPAddress, Port, Site
from sot_validator.signals._hypervisor_common import (
    _ALLOWED_READONLY_MODES,
    _clean_optional_str,
    _instances_match,
    _normalize_ip,
    _normalize_mac,
    _normalize_uuid,
    _require_non_empty_str,
)
from sot_validator.signals._hypervisor_records import (
    HypervisorVmRecord,
    _extract_equipment_vm_hints,
)


class HypervisorInventoryProvider(ABC):
    """Read-only interface for querying and correlating VM inventory across vCenter instances."""

    @abstractmethod
    def list_vms(self) -> Sequence[HypervisorVmRecord]:
        """Return all known virtual machine records across reachable vCenter instances."""
        raise NotImplementedError

    @abstractmethod
    def configured_instances(self) -> set[str]:
        """Return the set of configured vCenter instance identifiers."""
        raise NotImplementedError

    @abstractmethod
    def unreachable_instances(self) -> set[str]:
        """Return the set of unreachable vCenter instance identifiers."""
        raise NotImplementedError

    def is_instance_reachable(self, vcenter_instance: str) -> bool:
        """Return True if the specified vCenter instance is reachable (not in unreachable_instances)."""
        if not vcenter_instance or not vcenter_instance.strip():
            return False
        for unreach in self.unreachable_instances():
            if _instances_match(vcenter_instance, unreach):
                return False
        configured = self.configured_instances()
        if not configured:
            return False
        for conf in configured:
            if _instances_match(vcenter_instance, conf):
                return True
        for vm in self.list_vms():
            if _instances_match(vcenter_instance, vm.vcenter_instance) or _instances_match(
                vcenter_instance, vm.vcenter_host
            ):
                return True
        return False

    def find_by_uuid(self, uuid_value: str) -> list[HypervisorVmRecord]:
        """Look up VM records matching bios_uuid or instance_uuid across all vCenter instances."""
        norm_uuid = _normalize_uuid(uuid_value)
        if not norm_uuid:
            return []
        matches: list[HypervisorVmRecord] = []
        for vm in self.list_vms():
            if vm.bios_uuid == norm_uuid or vm.instance_uuid == norm_uuid:
                matches.append(vm)
        return matches

    def find_by_moref(
        self, vm_moref: str, vcenter_instance: Optional[str] = None
    ) -> list[HypervisorVmRecord]:
        """Look up VM records matching vm_moref (scoped to vcenter_instance when provided)."""
        cleaned_moref = _clean_optional_str(vm_moref)
        if not cleaned_moref:
            return []
        target_moref = cleaned_moref.lower()
        cleaned_inst = _clean_optional_str(vcenter_instance)

        matches: list[HypervisorVmRecord] = []
        for vm in self.list_vms():
            if vm.vm_moref.lower() != target_moref:
                continue
            if cleaned_inst is not None:
                if not (
                    _instances_match(cleaned_inst, vm.vcenter_instance)
                    or _instances_match(cleaned_inst, vm.vcenter_host)
                ):
                    continue
            matches.append(vm)
        return matches

    def find_by_mac_or_ip(
        self,
        *,
        mac_addresses: Optional[Iterable[str]] = None,
        ip_addresses: Optional[Iterable[str]] = None,
        site_id: Optional[str] = None,
    ) -> list[HypervisorVmRecord]:
        """Look up VM records matching normalized NIC MAC addresses and/or IP addresses."""
        target_macs = {
            norm
            for m in (mac_addresses or ())
            if (norm := _normalize_mac(m)) is not None
        }
        target_ips = {
            norm
            for ip in (ip_addresses or ())
            if (norm := _normalize_ip(ip)) is not None
        }
        if not target_macs and not target_ips:
            return []

        cleaned_site = _clean_optional_str(site_id)

        mac_matches: list[HypervisorVmRecord] = []
        ip_matches: list[HypervisorVmRecord] = []

        for vm in self.list_vms():
            if (
                cleaned_site is not None
                and vm.site_id is not None
                and vm.site_id.lower() != cleaned_site.lower()
            ):
                continue

            vm_macs = {
                norm
                for m in vm.mac_addresses
                if (norm := _normalize_mac(m)) is not None
            }
            vm_ips = {
                norm
                for ip in vm.ip_addresses
                if (norm := _normalize_ip(ip)) is not None
            }

            if target_macs and (vm_macs & target_macs):
                mac_matches.append(vm)
            elif target_ips and (vm_ips & target_ips):
                ip_matches.append(vm)

        return mac_matches + ip_matches

    def find_by_hostname(
        self, hostname: str, *, site_id: Optional[str] = None
    ) -> list[HypervisorVmRecord]:
        """Look up VM records matching guest_hostname or vm_name (exact or short-hostname match)."""
        cleaned = _clean_optional_str(hostname)
        if not cleaned:
            return []
        target_lower = cleaned.lower()
        target_short = target_lower.split(".", 1)[0]
        cleaned_site = _clean_optional_str(site_id)

        exact_matches: list[HypervisorVmRecord] = []
        short_matches: list[HypervisorVmRecord] = []

        for vm in self.list_vms():
            site_ok = (
                cleaned_site is None
                or vm.site_id is None
                or vm.site_id.lower() == cleaned_site.lower()
            )
            if not site_ok:
                continue

            vm_name_lower = vm.vm_name.lower()
            guest_lower = vm.guest_hostname.lower() if vm.guest_hostname else None

            if target_lower == vm_name_lower or (
                guest_lower is not None and target_lower == guest_lower
            ):
                exact_matches.append(vm)
                continue

            vm_short = vm_name_lower.split(".", 1)[0]
            guest_short = guest_lower.split(".", 1)[0] if guest_lower else None

            if (
                target_lower.startswith(vm_name_lower + ".")
                or vm_name_lower.startswith(target_lower + ".")
                or (
                    guest_lower is not None
                    and (
                        target_lower.startswith(guest_lower + ".")
                        or guest_lower.startswith(target_lower + ".")
                    )
                )
                or target_short == vm_short
                or (guest_short is not None and target_short == guest_short)
            ):
                short_matches.append(vm)

        return exact_matches if exact_matches else short_matches

    def correlate_vms(
        self,
        equipment: Equipment,
        *,
        site: Optional[Site] = None,
        ip_addresses: Optional[Sequence[IPAddress]] = None,
        arp_entries: Optional[Sequence[ArpEntry]] = None,
        ports: Optional[Sequence[Port]] = None,
        bios_uuid: Optional[str] = None,
        vcenter_instance: Optional[str] = None,
        vm_moref: Optional[str] = None,
        mac_addresses: Optional[Iterable[str]] = None,
    ) -> tuple[list[HypervisorVmRecord], Optional[str]]:
        """Correlate an Equipment record across vCenter instances using the 4-tier priority order:
        1. bios_uuid
        2. (vcenter_instance, vm_moref) / vm_moref
        3. NIC mac_address / ip_addresses
        4. guest_hostname / vm_name
        """
        uuids, inst_hint, moref_hint, explicit_macs, _ = _extract_equipment_vm_hints(
            equipment,
            bios_uuid=bios_uuid,
            vcenter_instance=vcenter_instance,
            vm_moref=vm_moref,
            mac_addresses=mac_addresses,
        )

        # Priority 1: BIOS UUID / Instance UUID
        for candidate_uuid in uuids:
            uuid_matches = self.find_by_uuid(candidate_uuid)
            if uuid_matches:
                return uuid_matches, "bios_uuid"

        # Priority 2: (vcenter_instance, vm_moref) or vm_moref
        if moref_hint:
            moref_matches = self.find_by_moref(moref_hint, vcenter_instance=inst_hint)
            if not moref_matches and inst_hint is not None:
                # If VM was vMotioned across vCenters and kept or updated MoRef, check without instance filter
                # only when no instance-scoped match was found
                moref_matches = self.find_by_moref(moref_hint, vcenter_instance=None)
            if moref_matches:
                return moref_matches, "vm_moref"

        # Priority 3: MAC address + IP addresses
        resolved_ips: list[str] = []
        for ip in equipment.assigned_ips:
            norm_ip = _normalize_ip(ip)
            if norm_ip and norm_ip not in resolved_ips:
                resolved_ips.append(norm_ip)

        resolved_macs: list[str] = list(explicit_macs)

        all_ip_records: list[IPAddress] = []
        if ip_addresses:
            all_ip_records.extend(ip_addresses)
        if site is not None:
            all_ip_records.extend(site.ip_addresses)

        for ip_rec in all_ip_records:
            if (
                ip_rec.assigned_object_id == equipment.equipment_id
                or ip_rec.ip in resolved_ips
            ):
                if ip_rec.ip not in resolved_ips:
                    resolved_ips.append(ip_rec.ip)
                if ip_rec.arp_mac and ip_rec.arp_mac not in resolved_macs:
                    resolved_macs.append(ip_rec.arp_mac)
                if (
                    isinstance(ip_rec.arp_entry, ArpEntry)
                    and ip_rec.arp_entry.arp_mac
                    and ip_rec.arp_entry.arp_mac not in resolved_macs
                ):
                    resolved_macs.append(ip_rec.arp_entry.arp_mac)

        if arp_entries:
            for entry in arp_entries:
                if entry.ip in resolved_ips and entry.arp_mac not in resolved_macs:
                    resolved_macs.append(entry.arp_mac)

        all_ports: list[Port] = []
        if ports:
            all_ports.extend(ports)
        if site is not None:
            for dev in site.devices:
                all_ports.extend(dev.ports)

        connected_refs = {
            ref.strip() for ref in equipment.connected_ports if ref and ref.strip()
        }
        for port in all_ports:
            if (
                port.connected_device_id == equipment.equipment_id
                or port.port_id in connected_refs
                or port.name in connected_refs
                or f"{port.device_id}:{port.name}" in connected_refs
            ):
                # Only use port connected_mac if it's dedicated to this equipment_id
                if (
                    port.connected_device_id == equipment.equipment_id
                    and port.connected_mac
                    and port.connected_mac not in resolved_macs
                ):
                    resolved_macs.append(port.connected_mac)

        site_id = equipment.site_id or (site.site_id if site is not None else None)
        mac_ip_matches = self.find_by_mac_or_ip(
            mac_addresses=resolved_macs,
            ip_addresses=resolved_ips,
            site_id=site_id,
        )
        if mac_ip_matches:
            return mac_ip_matches, "mac_or_ip"

        # Priority 4: Normalized guest_hostname / vm_name
        hostname_matches = self.find_by_hostname(equipment.name, site_id=site_id)
        if hostname_matches:
            return hostname_matches, "hostname"

        return [], None


class MultiVCenterInventoryProvider(HypervisorInventoryProvider):
    """Read-only multi-vCenter inventory aggregator supporting JSON, CSV/RVTools, and adapter callables."""

    def __init__(
        self,
        vms: Iterable[HypervisorVmRecord | Mapping[str, Any]] = (),
        *,
        instances: Optional[Iterable[str | Mapping[str, Any]]] = None,
        unreachable_instances: Optional[Iterable[str]] = None,
        adapters: Optional[
            Mapping[str, Callable[[], Iterable[HypervisorVmRecord | Mapping[str, Any]]]]
        ] = None,
    ) -> None:
        self._vms: list[HypervisorVmRecord] = []
        self._configured_instances: set[str] = set()
        self._instance_hosts: dict[str, str] = {}
        self._unreachable_instances: set[str] = set()
        self._adapter_errors: dict[str, str] = {}

        if instances is not None:
            for inst in instances:
                if isinstance(inst, str):
                    cleaned = _clean_optional_str(inst)
                    if cleaned:
                        self._configured_instances.add(cleaned)
                elif isinstance(inst, Mapping):
                    mode = _clean_optional_str(
                        inst.get("api_mode") or inst.get("mode")
                    )
                    if mode is not None and mode.lower() not in _ALLOWED_READONLY_MODES:
                        raise ValueError(
                            f"vCenter instance api_mode must be read-only, got {mode!r}"
                        )
                    inst_id = _clean_optional_str(
                        inst.get("vcenter_instance")
                        or inst.get("instance")
                        or inst.get("name")
                        or inst.get("vcenter_host")
                    )
                    host = _clean_optional_str(inst.get("vcenter_host") or inst.get("host"))
                    if inst_id:
                        self._configured_instances.add(inst_id)
                        if host:
                            self._instance_hosts[inst_id] = host
                    if inst.get("reachable") is False or (
                        isinstance(inst.get("status"), str)
                        and inst["status"].strip().lower() in ("unreachable", "down", "error", "offline")
                    ):
                        if inst_id:
                            self._unreachable_instances.add(inst_id)
                else:
                    raise ValueError(f"Unsupported instance descriptor: {inst!r}")

        if unreachable_instances is not None:
            for unreach in unreachable_instances:
                cleaned = _clean_optional_str(unreach)
                if cleaned:
                    self._unreachable_instances.add(cleaned)
                    self._configured_instances.add(cleaned)

        for item in vms:
            rec = (
                item
                if isinstance(item, HypervisorVmRecord)
                else HypervisorVmRecord.from_dict(item)
            )
            self._vms.append(rec)
            self._configured_instances.add(rec.vcenter_instance)
            if rec.vcenter_host:
                self._instance_hosts.setdefault(rec.vcenter_instance, rec.vcenter_host)

        if adapters is not None:
            for inst_name, adapter_fn in adapters.items():
                cleaned_inst = _require_non_empty_str(inst_name, "adapter vcenter_instance")
                self._configured_instances.add(cleaned_inst)
                try:
                    adapter_items = adapter_fn()
                    for item in adapter_items:
                        rec = (
                            item
                            if isinstance(item, HypervisorVmRecord)
                            else HypervisorVmRecord.from_dict(
                                item, default_vcenter_instance=cleaned_inst
                            )
                        )
                        self._vms.append(rec)
                        self._configured_instances.add(rec.vcenter_instance)
                        if rec.vcenter_host:
                            self._instance_hosts.setdefault(
                                rec.vcenter_instance, rec.vcenter_host
                            )
                except Exception as exc:
                    self._unreachable_instances.add(cleaned_inst)
                    self._adapter_errors[cleaned_inst] = str(exc)

    def list_vms(self) -> Sequence[HypervisorVmRecord]:
        return tuple(self._vms)

    def configured_instances(self) -> set[str]:
        return set(self._configured_instances)

    def unreachable_instances(self) -> set[str]:
        return set(self._unreachable_instances)

    @property
    def adapter_errors(self) -> dict[str, str]:
        """Return any errors captured while invoking per-instance adapter callables."""
        return dict(self._adapter_errors)

    def is_instance_configured(self, vcenter_instance: str) -> bool:
        """Return True if vcenter_instance matches any configured instance or host."""
        for conf in self._configured_instances:
            if _instances_match(vcenter_instance, conf):
                return True
        for inst_id, host in self._instance_hosts.items():
            if _instances_match(vcenter_instance, host) or _instances_match(
                vcenter_instance, inst_id
            ):
                return True
        return False

    def is_instance_unreachable(self, vcenter_instance: str) -> bool:
        """Return True if vcenter_instance matches any unreachable vCenter instance."""
        for unreach in self._unreachable_instances:
            if _instances_match(vcenter_instance, unreach):
                return True
            host = self._instance_hosts.get(unreach)
            if host and _instances_match(vcenter_instance, host):
                return True
        return False

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> MultiVCenterInventoryProvider:
        """Construct MultiVCenterInventoryProvider from a parsed JSON snapshot dictionary."""
        raw_instances = data.get("instances")
        raw_vms = data.get("vms") or []
        raw_unreachable = data.get("unreachable_instances")
        export_ts = _clean_optional_str(data.get("export_timestamp"))

        vms: list[HypervisorVmRecord] = []
        for raw_vm in raw_vms:
            if isinstance(raw_vm, HypervisorVmRecord):
                vms.append(raw_vm)
            elif isinstance(raw_vm, Mapping):
                vm_dict = dict(raw_vm)
                if export_ts and vm_dict.get("last_updated") is None:
                    vm_dict["last_updated"] = export_ts
                vms.append(HypervisorVmRecord.from_dict(vm_dict))
            else:
                raise ValueError(f"Unsupported VM entry in snapshot: {raw_vm!r}")

        return cls(
            vms=vms,
            instances=raw_instances,
            unreachable_instances=raw_unreachable,
        )

    @classmethod
    def from_json(cls, raw_json: str) -> MultiVCenterInventoryProvider:
        """Construct MultiVCenterInventoryProvider from a JSON string."""
        parsed = json.loads(raw_json)
        if isinstance(parsed, list):
            return cls(vms=parsed)
        if not isinstance(parsed, Mapping):
            raise ValueError("vCenter JSON inventory must be an object or array of VMs")
        return cls.from_dict(parsed)

    @classmethod
    def from_json_file(cls, path: str | Path) -> MultiVCenterInventoryProvider:
        """Construct MultiVCenterInventoryProvider from a JSON snapshot file on disk."""
        file_path = Path(path)
        return cls.from_json(file_path.read_text(encoding="utf-8"))

    @classmethod
    def from_csv_rows(
        cls,
        rows: Iterable[Mapping[str, Any]],
        *,
        default_vcenter_instance: Optional[str] = None,
        unreachable_instances: Optional[Iterable[str]] = None,
    ) -> MultiVCenterInventoryProvider:
        """Construct MultiVCenterInventoryProvider from CSV or RVTools dictionary rows."""
        vms = [
            HypervisorVmRecord.from_dict(
                row, default_vcenter_instance=default_vcenter_instance
            )
            for row in rows
        ]
        instances: list[str] = []
        if default_vcenter_instance:
            instances.append(default_vcenter_instance)
        return cls(
            vms=vms,
            instances=instances or None,
            unreachable_instances=unreachable_instances,
        )

    @classmethod
    def from_csv_file(
        cls,
        path: str | Path,
        *,
        default_vcenter_instance: Optional[str] = None,
        unreachable_instances: Optional[Iterable[str]] = None,
    ) -> MultiVCenterInventoryProvider:
        """Construct MultiVCenterInventoryProvider from a CSV / RVTools export file."""
        file_path = Path(path)
        with file_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            return cls.from_csv_rows(
                reader,
                default_vcenter_instance=default_vcenter_instance,
                unreachable_instances=unreachable_instances,
            )
