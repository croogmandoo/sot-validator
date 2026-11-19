"""GoldenInventoryFilter: selects confirmed-active records for the golden inventory export."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import ipaddress
import re
from typing import Any, Optional

from sot_validator.migration._exporter_helpers import (
    _normalize_discrepancies,
    _normalize_sites_input,
    _normalize_validation_results,
    _strip_ip_mask,
    slugify,
)
from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    Subnet,
    VLAN,
    ValidationClassification,
    ValidationResult,
)
from sot_validator.reconciliation.reconciler import (
    DiscrepancyRecord,
    DiscrepancyType,
    ReconciliationReport,
    _extract_detail_kv,
    _infer_subnet_id,
    _short_hostname,
)


class GoldenInventoryFilter:
    """Filters Site inventory to Confirmed Active records and merges verified untracked assets."""

    def __init__(
        self,
        include_stale: bool = False,
        include_unreachable: bool = False,
        include_insufficient_data: bool = False,
        merge_untracked: bool = True,
        approved_discrepancy_ids: Optional[Iterable[str]] = None,
    ) -> None:
        self.include_stale = bool(include_stale)
        self.include_unreachable = bool(include_unreachable)
        self.include_insufficient_data = bool(include_insufficient_data)
        self.merge_untracked = bool(merge_untracked)
        self.approved_discrepancy_ids: Optional[set[str]] = (
            {str(item).strip() for item in approved_discrepancy_ids if str(item).strip()}
            if approved_discrepancy_ids is not None
            else None
        )
        self._stale_item_keys: set[tuple[str, str]] = set()

    @property
    def allowed_classifications(self) -> set[ValidationClassification]:
        allowed = {ValidationClassification.CONFIRMED_ACTIVE}
        if self.include_stale:
            allowed.add(ValidationClassification.STALE_LIKELY_UNUSED)
        if self.include_unreachable:
            allowed.add(ValidationClassification.UNREACHABLE_NEEDS_REVIEW)
        if self.include_insufficient_data:
            allowed.add(ValidationClassification.INSUFFICIENT_DATA)
        return allowed

    def is_stale(self, site_id: str, item_id: str) -> bool:
        """Return True if (site_id, item_id) was retained via include_stale=True."""
        return (
            (site_id, item_id) in self._stale_item_keys
            or ("*", item_id) in self._stale_item_keys
        )

    def _is_discrepancy_approved(
        self,
        disc: DiscrepancyRecord,
        override_approved_ids: Optional[set[str]] = None,
    ) -> bool:
        approved_set = (
            override_approved_ids
            if override_approved_ids is not None
            else self.approved_discrepancy_ids
        )
        if approved_set is None:
            return True
        candidates = {
            disc.discrepancy_id,
            disc.observed_identifier,
        }
        if disc.observed_ip:
            candidates.add(disc.observed_ip)
        if disc.observed_hostname:
            candidates.add(disc.observed_hostname)
        return bool(candidates & approved_set)

    @staticmethod
    def _match_subnet_for_ip(site: Site, ip_str: Optional[str], hint: Optional[str] = None) -> str:
        if hint and hint.strip():
            return hint.strip()
        clean_ip = _strip_ip_mask(ip_str)
        if clean_ip:
            try:
                addr = ipaddress.ip_address(clean_ip)
                for subnet in site.subnets:
                    try:
                        net = ipaddress.ip_network(subnet.cidr.strip(), strict=False)
                        if addr in net:
                            return subnet.subnet_id
                    except ValueError:
                        continue
            except ValueError:
                pass
        if site.subnets:
            return site.subnets[0].subnet_id
        return _infer_subnet_id(site.site_id, clean_ip, hint)

    def filter_site(
        self,
        site: Site | Mapping[str, Any],
        validation_results: Optional[
            Sequence[ValidationResult | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        reconciliation_report: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        *,
        approved_discrepancy_ids: Optional[Iterable[str]] = None,
    ) -> Site:
        """Return a filtered Site copy containing only validated active records and merged untracked assets."""
        site_obj = site if isinstance(site, Site) else Site.from_dict(site)
        norm_results = _normalize_validation_results(validation_results)
        norm_discs = _normalize_discrepancies(reconciliation_report)
        override_approved: Optional[set[str]] = (
            {str(x).strip() for x in approved_discrepancy_ids if str(x).strip()}
            if approved_discrepancy_ids is not None
            else None
        )

        # Index classifications for this site (or global wildcard)
        self._stale_item_keys = {
            k for k in self._stale_item_keys if k[0] != site_obj.site_id
        }
        classification_by_id: dict[str, ValidationClassification] = {}
        for res in norm_results:
            if res.site_id not in (site_obj.site_id, "unknown", "*"):
                continue
            classification_by_id[res.item_id] = res.classification
            stripped_ip = _strip_ip_mask(res.item_id)
            if stripped_ip:
                classification_by_id.setdefault(stripped_ip, res.classification)
            if res.name:
                classification_by_id.setdefault(res.name, res.classification)

        allowed = self.allowed_classifications

        retained_devices: list[NetworkDevice] = []
        retained_device_ids: set[str] = set()
        excluded_object_ids: set[str] = set()
        excluded_ips: set[str] = set()
        stale_object_ids: set[str] = set()

        for dev in site_obj.devices:
            cls = classification_by_id.get(dev.device_id) or classification_by_id.get(
                dev.hostname
            )
            if cls is not None and cls not in allowed:
                excluded_object_ids.add(dev.device_id)
                if dev.management_ip:
                    excluded_ips.add(_strip_ip_mask(dev.management_ip))
                continue
            if cls is ValidationClassification.STALE_LIKELY_UNUSED:
                self._stale_item_keys.add((site_obj.site_id, dev.device_id))
                self._stale_item_keys.add((site_obj.site_id, dev.hostname))
                stale_object_ids.add(dev.device_id)
            retained_device_ids.add(dev.device_id)
            retained_devices.append(NetworkDevice.from_dict(dev.to_dict()))

        retained_equipment: list[Equipment] = []
        retained_equipment_ids: set[str] = set()

        for eq in site_obj.equipment:
            cls = classification_by_id.get(eq.equipment_id) or classification_by_id.get(
                eq.name
            )
            if cls is not None and cls not in allowed:
                excluded_object_ids.add(eq.equipment_id)
                for raw_ip in eq.assigned_ips:
                    excluded_ips.add(_strip_ip_mask(raw_ip))
                continue
            if cls is ValidationClassification.STALE_LIKELY_UNUSED:
                self._stale_item_keys.add((site_obj.site_id, eq.equipment_id))
                self._stale_item_keys.add((site_obj.site_id, eq.name))
                stale_object_ids.add(eq.equipment_id)
            retained_equipment_ids.add(eq.equipment_id)
            retained_equipment.append(Equipment.from_dict(eq.to_dict()))

        valid_connected_ids = retained_device_ids | retained_equipment_ids
        for dev in retained_devices:
            cleaned_ports: list[Port] = []
            for port in dev.ports:
                port_copy = Port.from_dict(port.to_dict())
                if (
                    port_copy.connected_device_id
                    and port_copy.connected_device_id in excluded_object_ids
                    and port_copy.connected_device_id not in valid_connected_ids
                ):
                    port_copy.connected_device_id = None
                cleaned_ports.append(port_copy)
            dev.ports = cleaned_ports

        retained_object_ips: set[str] = set()
        for dev in retained_devices:
            if dev.management_ip:
                retained_object_ips.add(_strip_ip_mask(dev.management_ip))
        for eq in retained_equipment:
            for raw_ip in eq.assigned_ips:
                retained_object_ips.add(_strip_ip_mask(raw_ip))

        retained_ips: list[IPAddress] = []
        existing_ip_set: set[str] = set()

        for ip_rec in site_obj.ip_addresses:
            clean_ip = _strip_ip_mask(ip_rec.ip)
            cls = classification_by_id.get(ip_rec.ip) or classification_by_id.get(
                clean_ip
            )
            if cls is not None:
                if cls not in allowed:
                    continue
                if cls is ValidationClassification.STALE_LIKELY_UNUSED:
                    self._stale_item_keys.add((site_obj.site_id, ip_rec.ip))
                    self._stale_item_keys.add((site_obj.site_id, clean_ip))
            else:
                if (
                    ip_rec.assigned_object_id
                    and ip_rec.assigned_object_id in excluded_object_ids
                ):
                    continue
                if clean_ip in excluded_ips and clean_ip not in retained_object_ips:
                    continue
                if (
                    ip_rec.assigned_object_id
                    and ip_rec.assigned_object_id in stale_object_ids
                ):
                    self._stale_item_keys.add((site_obj.site_id, ip_rec.ip))
                    self._stale_item_keys.add((site_obj.site_id, clean_ip))

            retained_ips.append(IPAddress.from_dict(ip_rec.to_dict()))
            existing_ip_set.add(clean_ip)

        filtered_site = Site(
            site_id=site_obj.site_id,
            name=site_obj.name,
            address=site_obj.address,
            contact_info=site_obj.contact_info,
            rooms=list(site_obj.rooms),
            devices=retained_devices,
            vlans=[VLAN.from_dict(v.to_dict()) for v in site_obj.vlans],
            subnets=[Subnet.from_dict(s.to_dict()) for s in site_obj.subnets],
            ip_addresses=retained_ips,
            equipment=retained_equipment,
        )

        if self.merge_untracked and norm_discs:
            self._merge_site_discrepancies(
                filtered_site,
                norm_discs,
                existing_ip_set=existing_ip_set,
                override_approved_ids=override_approved,
            )

        return filtered_site

    def _merge_site_discrepancies(
        self,
        site: Site,
        discrepancies: Sequence[DiscrepancyRecord],
        *,
        existing_ip_set: set[str],
        override_approved_ids: Optional[set[str]] = None,
    ) -> None:
        existing_dev_ids = {d.device_id for d in site.devices}
        existing_dev_names = {d.hostname.lower() for d in site.devices}
        existing_eq_ids = {e.equipment_id for e in site.equipment}
        existing_eq_names = {e.name.lower() for e in site.equipment}

        for disc in discrepancies:
            if disc.site_id != site.site_id:
                continue
            if disc.discrepancy_type is DiscrepancyType.ATTRIBUTE_MISMATCH:
                continue
            if not self._is_discrepancy_approved(disc, override_approved_ids):
                continue

            kv = _extract_detail_kv(disc.details)

            if disc.discrepancy_type is DiscrepancyType.UNTRACKED_VM:
                hostname = disc.observed_hostname or disc.observed_identifier
                short_host = _short_hostname(hostname) or disc.observed_identifier
                eq_id = (
                    kv.get("item_id")
                    or f"eq-{slugify(site.site_id)}-vm-{slugify(short_host)}"
                )
                vcenter_inst = kv.get("vcenter_instance")
                vm_moref = kv.get("vm_moref") or (
                    disc.observed_identifier
                    if disc.observed_identifier.lower().startswith("vm-")
                    else None
                )
                bios_uuid = kv.get("bios_uuid")
                if vcenter_inst and vm_moref:
                    hypervisor_id = f"{vcenter_inst}:{vm_moref}"
                elif vcenter_inst:
                    hypervisor_id = vcenter_inst
                elif vm_moref:
                    hypervisor_id = f"vcenter-default:{vm_moref}"
                elif bios_uuid:
                    hypervisor_id = bios_uuid
                else:
                    hypervisor_id = disc.observed_identifier

                clean_ip = _strip_ip_mask(disc.observed_ip)
                if (
                    eq_id not in existing_eq_ids
                    and hostname.lower() not in existing_eq_names
                ):
                    vm_eq = Equipment(
                        equipment_id=eq_id,
                        site_id=site.site_id,
                        name=hostname,
                        category=EquipmentCategory.VM,
                        assigned_ips=[clean_ip] if clean_ip else [],
                        connected_ports=[],
                        hypervisor_id=hypervisor_id,
                        power_state="poweredOn",
                    )
                    site.equipment.append(vm_eq)
                    existing_eq_ids.add(eq_id)
                    existing_eq_names.add(hostname.lower())

                if clean_ip and clean_ip not in existing_ip_set:
                    subnet_id = self._match_subnet_for_ip(
                        site, clean_ip, kv.get("subnet_id")
                    )
                    site.ip_addresses.append(
                        IPAddress(
                            ip=clean_ip,
                            subnet_id=subnet_id,
                            assigned_object_type="equipment",
                            assigned_object_id=eq_id,
                            arp_mac=disc.observed_mac,
                        )
                    )
                    existing_ip_set.add(clean_ip)

            elif disc.discrepancy_type is DiscrepancyType.UNTRACKED_DEVICE:
                hostname = disc.observed_hostname or disc.observed_identifier
                short_host = _short_hostname(hostname) or disc.observed_identifier
                details_lower = f"{disc.details or ''} {hostname}".lower()

                if "vendor" in kv:
                    vendor = kv["vendor"].replace("_", " ")
                elif "extreme" in details_lower:
                    vendor = "Extreme Networks"
                elif "apc" in details_lower or "smart-ups" in details_lower or "ups" in details_lower:
                    vendor = "APC"
                else:
                    vendor = "Extreme Networks"

                if "model" in kv:
                    model = kv["model"].replace("_", " ")
                elif vendor == "Extreme Networks":
                    model_match = re.search(r"\(([^)]+)\)", disc.details or "")
                    model = (
                        f"ExtremeSwitching {model_match.group(1)}"
                        if model_match
                        else "ExtremeSwitching"
                    )
                elif vendor == "APC":
                    model = "Smart-UPS"
                else:
                    model = "Generic Device"

                if "role" in kv:
                    role = kv["role"]
                elif vendor == "APC":
                    role = "ups"
                else:
                    role = "access-switch"

                dev_id = (
                    kv.get("item_id")
                    or f"dev-{slugify(site.site_id)}-{slugify(short_host)}"
                )
                clean_ip = _strip_ip_mask(disc.observed_ip) or (
                    _strip_ip_mask(disc.observed_identifier)
                    if disc.observed_identifier and disc.observed_identifier[0].isdigit()
                    else ""
                )

                if (
                    dev_id not in existing_dev_ids
                    and hostname.lower() not in existing_dev_names
                    and hostname.lower() not in existing_eq_names
                ):
                    new_dev = NetworkDevice(
                        device_id=dev_id,
                        site_id=site.site_id,
                        hostname=hostname,
                        management_ip=clean_ip or None,
                        vendor=vendor,
                        model=model,
                        role=role,
                        ports=[],
                    )
                    site.devices.append(new_dev)
                    existing_dev_ids.add(dev_id)
                    existing_dev_names.add(hostname.lower())

                if clean_ip and clean_ip not in existing_ip_set:
                    subnet_id = self._match_subnet_for_ip(
                        site, clean_ip, kv.get("subnet_id")
                    )
                    site.ip_addresses.append(
                        IPAddress(
                            ip=clean_ip,
                            subnet_id=subnet_id,
                            assigned_object_type="network_device",
                            assigned_object_id=dev_id,
                            arp_mac=disc.observed_mac,
                        )
                    )
                    existing_ip_set.add(clean_ip)

            elif disc.discrepancy_type is DiscrepancyType.UNTRACKED_IP:
                clean_ip = _strip_ip_mask(disc.observed_ip or disc.observed_identifier)
                if clean_ip and clean_ip not in existing_ip_set:
                    subnet_id = self._match_subnet_for_ip(
                        site, clean_ip, kv.get("subnet_id")
                    )
                    site.ip_addresses.append(
                        IPAddress(
                            ip=clean_ip,
                            subnet_id=subnet_id,
                            assigned_object_type=kv.get("target_type"),
                            assigned_object_id=kv.get("target_id") or disc.observed_hostname,
                            arp_mac=disc.observed_mac,
                            arp_source_device_id=kv.get("arp_source_device_id"),
                        )
                    )
                    existing_ip_set.add(clean_ip)

    def filter_sites(
        self,
        sites: Sequence[Site | Mapping[str, Any]] | Mapping[str, Any] | Site,
        validation_results: Optional[
            Sequence[ValidationResult | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        reconciliation_report: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        *,
        approved_discrepancy_ids: Optional[Iterable[str]] = None,
    ) -> list[Site]:
        """Filter a sequence or mapping of sites and return sorted filtered Site records."""
        norm_sites = _normalize_sites_input(sites)
        filtered = [
            self.filter_site(
                s,
                validation_results=validation_results,
                reconciliation_report=reconciliation_report,
                approved_discrepancy_ids=approved_discrepancy_ids,
            )
            for s in norm_sites
        ]
        return sorted(filtered, key=lambda s: slugify(s.site_id))
