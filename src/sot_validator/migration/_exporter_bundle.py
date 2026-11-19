"""ModernSoTExporter: builds NetBox / Nautobot golden inventory bundles and writes JSON / CSV exports."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import csv
from datetime import datetime
import io
import ipaddress
import json
from pathlib import Path
from typing import Any, Optional

from sot_validator.migration._exporter_filter import GoldenInventoryFilter
from sot_validator.migration._exporter_helpers import (
    CSV_COLUMNS_BY_ENTITY,
    ENTITY_COLLECTION_KEYS,
    SUPPORTED_TARGET_PLATFORMS,
    TargetPlatform,
    _infer_equipment_manufacturer_and_model,
    _infer_vm_os_family,
    _normalize_discrepancies,
    _normalize_sites_input,
    _normalize_validation_results,
    _parse_contact_info,
    _parse_vlan_vid,
    _resolve_timestamp,
    _strip_ip_mask,
    slugify,
)
from sot_validator.models import (
    EquipmentCategory,
    Site,
    ValidationResult,
    _format_optional_datetime,
)
from sot_validator.reconciliation.reconciler import (
    DiscrepancyRecord,
    ReconciliationReport,
)


class ModernSoTExporter:
    """Exports validated golden inventory into normalized NetBox or Nautobot JSON and CSV bundles."""

    def __init__(
        self,
        sites: Optional[
            Sequence[Site | Mapping[str, Any]] | Mapping[str, Any] | Site
        ] = None,
        validation_results: Optional[
            Sequence[ValidationResult | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        reconciliation_report: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        *,
        target_platform: str = "netbox",
        inventory_filter: Optional[GoldenInventoryFilter] = None,
        include_stale: bool = False,
        merge_untracked: bool = True,
        approved_discrepancy_ids: Optional[Iterable[str]] = None,
        generated_at: Optional[datetime | str] = None,
    ) -> None:
        if not isinstance(target_platform, str):
            raise ValueError(
                f"Invalid target_platform {target_platform!r}; must be one of {sorted(SUPPORTED_TARGET_PLATFORMS)}"
            )
        norm_platform = target_platform.strip().lower()
        if norm_platform not in SUPPORTED_TARGET_PLATFORMS:
            raise ValueError(
                f"Invalid target_platform {target_platform!r}; must be one of {sorted(SUPPORTED_TARGET_PLATFORMS)}"
            )
        self.target_platform: TargetPlatform = norm_platform  # type: ignore[assignment]
        self.generated_at: datetime = _resolve_timestamp(generated_at)

        if inventory_filter is not None:
            self.inventory_filter = inventory_filter
        else:
            self.inventory_filter = GoldenInventoryFilter(
                include_stale=include_stale,
                merge_untracked=merge_untracked,
                approved_discrepancy_ids=approved_discrepancy_ids,
            )

        self._raw_sites = _normalize_sites_input(sites)
        self._validation_results = _normalize_validation_results(validation_results)
        self._discrepancies = _normalize_discrepancies(reconciliation_report)
        self._approved_discrepancy_ids = approved_discrepancy_ids

    def get_filtered_sites(self) -> list[Site]:
        """Return the filtered Site records produced by GoldenInventoryFilter."""
        return self.inventory_filter.filter_sites(
            self._raw_sites,
            validation_results=self._validation_results,
            reconciliation_report=self._discrepancies,
            approved_discrepancy_ids=self._approved_discrepancy_ids,
        )

    @staticmethod
    def _resolve_ip_with_prefix(site: Site, raw_ip: str, subnet_id: Optional[str] = None) -> str:
        text = raw_ip.strip()
        if "/" in text:
            ip_part, mask_part = text.split("/", 1)
            return f"{ip_part.strip()}/{mask_part.strip()}"

        prefix_len = 24
        if subnet_id:
            for subnet in site.subnets:
                if subnet.subnet_id == subnet_id and "/" in subnet.cidr:
                    try:
                        prefix_len = int(subnet.cidr.split("/", 1)[1].strip())
                        return f"{text}/{prefix_len}"
                    except ValueError:
                        pass

        try:
            addr = ipaddress.ip_address(text)
            for subnet in site.subnets:
                try:
                    net = ipaddress.ip_network(subnet.cidr.strip(), strict=False)
                    if addr in net:
                        prefix_len = net.prefixlen
                        break
                except ValueError:
                    continue
        except ValueError:
            pass

        return f"{text}/{prefix_len}"

    def build_bundle(
        self,
        sites: Optional[
            Sequence[Site | Mapping[str, Any]] | Mapping[str, Any] | Site
        ] = None,
        validation_results: Optional[
            Sequence[ValidationResult | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        reconciliation_report: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
    ) -> dict[str, Any]:
        """Build the normalized NetBox / Nautobot export dictionary across all 7 entity collections."""
        if (
            sites is not None
            or validation_results is not None
            or reconciliation_report is not None
        ):
            target_sites = self.inventory_filter.filter_sites(
                sites if sites is not None else self._raw_sites,
                validation_results=(
                    validation_results
                    if validation_results is not None
                    else self._validation_results
                ),
                reconciliation_report=(
                    reconciliation_report
                    if reconciliation_report is not None
                    else self._discrepancies
                ),
                approved_discrepancy_ids=self._approved_discrepancy_ids,
            )
        else:
            target_sites = self.get_filtered_sites()

        sites_out: list[dict[str, Any]] = []
        vlans_out: list[dict[str, Any]] = []
        prefixes_out: list[dict[str, Any]] = []
        devices_out: list[dict[str, Any]] = []
        interfaces_out: list[dict[str, Any]] = []
        ip_addresses_out: list[dict[str, Any]] = []
        virtual_machines_out: list[dict[str, Any]] = []

        seen_vlans: set[tuple[str, int]] = set()
        seen_ips: set[tuple[str, str]] = set()

        for site in target_sites:
            site_slug = slugify(site.site_id)
            contact_name, contact_email = _parse_contact_info(site.contact_info)

            sites_out.append(
                {
                    "name": site.name,
                    "slug": site_slug,
                    "status": "active",
                    "physical_address": site.address or "",
                    "contact_name": contact_name,
                    "contact_email": contact_email,
                    "custom_fields": {
                        "legacy_sot_id": site.site_id,
                    },
                }
            )

            # 2. VLANs (from site.vlans and synthesized from site.subnets if missing)
            for vlan in site.vlans:
                vid = _parse_vlan_vid(vlan.vlan_id, fallback=1)
                assert vid is not None
                if (site_slug, vid) in seen_vlans:
                    continue
                seen_vlans.add((site_slug, vid))
                vlan_name = vlan.name or f"VLAN-{vid}"
                legacy_vlan_id = (
                    vlan.vlan_id
                    if vlan.vlan_id.startswith(f"{site.site_id}:vlan:")
                    else f"{site.site_id}:vlan:{vlan.vlan_id}"
                )
                vlans_out.append(
                    {
                        "vid": vid,
                        "name": vlan_name,
                        "slug": slugify(f"{site.site_id}-vlan-{vid}-{vlan_name}"),
                        "site": site_slug,
                        "status": "active",
                        "custom_fields": {
                            "legacy_sot_id": legacy_vlan_id,
                        },
                    }
                )

            for subnet in site.subnets:
                if subnet.vlan_id is not None:
                    vid = _parse_vlan_vid(subnet.vlan_id, fallback=None)
                    if vid is not None and (site_slug, vid) not in seen_vlans:
                        seen_vlans.add((site_slug, vid))
                        vlan_name = subnet.name or f"VLAN-{vid}"
                        legacy_vlan_id = f"{site.site_id}:vlan:{subnet.vlan_id}"
                        vlans_out.append(
                            {
                                "vid": vid,
                                "name": vlan_name,
                                "slug": slugify(
                                    f"{site.site_id}-vlan-{vid}-{vlan_name}"
                                ),
                                "site": site_slug,
                                "status": "active",
                                "custom_fields": {
                                    "legacy_sot_id": legacy_vlan_id,
                                },
                            }
                        )

            # 3. Prefixes
            for subnet in site.subnets:
                vlan_vid = _parse_vlan_vid(subnet.vlan_id, fallback=None)
                prefixes_out.append(
                    {
                        "prefix": subnet.cidr.strip(),
                        "slug": slugify(f"{site.site_id}-{subnet.subnet_id}"),
                        "site": site_slug,
                        "vlan": vlan_vid,
                        "status": "active",
                        "description": subnet.name or "",
                        "custom_fields": {
                            "legacy_sot_id": subnet.subnet_id,
                        },
                    }
                )

            # Index object IDs and IPs -> hostname for DNS / assigned_object resolution
            hostname_by_object_id: dict[str, str] = {}
            hostname_by_ip: dict[str, str] = {}
            stale_by_object_id: dict[str, bool] = {}

            # 4a. NetworkDevices -> devices & 5. Ports -> interfaces
            for dev in site.devices:
                is_stale = self.inventory_filter.is_stale(
                    site.site_id, dev.device_id
                ) or self.inventory_filter.is_stale(site.site_id, dev.hostname)
                hostname_by_object_id[dev.device_id] = dev.hostname
                stale_by_object_id[dev.device_id] = is_stale
                if dev.management_ip:
                    hostname_by_ip[_strip_ip_mask(dev.management_ip)] = dev.hostname

                vendor = dev.vendor or "Extreme Networks"
                role_slug = slugify(dev.role or "switch")
                if dev.model:
                    device_type = dev.model
                elif vendor.upper() == "APC" or role_slug == "ups":
                    device_type = "Smart-UPS"
                else:
                    device_type = "ExtremeSwitching"

                devices_out.append(
                    {
                        "name": dev.hostname,
                        "slug": slugify(dev.hostname),
                        "manufacturer": vendor,
                        "role": role_slug,
                        "device_type": device_type,
                        "site": site_slug,
                        "status": "decommissioning" if is_stale else "active",
                        "custom_fields": {
                            "legacy_sot_id": dev.device_id,
                        },
                    }
                )

                for port in dev.ports:
                    admin_lower = (port.admin_status or "up").strip().lower()
                    enabled = admin_lower not in ("down", "disabled", "false", "0", "off")
                    poe_lower = (port.poe_status or "").strip().lower()
                    poe_mode = (
                        "pse"
                        if poe_lower
                        in ("delivering", "enabled", "up", "searching", "active", "on")
                        else "disabled"
                    )
                    description = (
                        f"Connected to {port.connected_device_id}"
                        if port.connected_device_id
                        else ""
                    )
                    untagged_vlan = _parse_vlan_vid(port.vlan_id, fallback=None)

                    interfaces_out.append(
                        {
                            "name": port.name,
                            "slug": slugify(f"{dev.hostname}-{port.name}"),
                            "device": dev.hostname,
                            "enabled": enabled,
                            "poe_mode": poe_mode,
                            "description": description,
                            "untagged_vlan": untagged_vlan,
                            "custom_fields": {
                                "legacy_sot_id": port.port_id,
                            },
                        }
                    )

            # 4b. Physical Equipment -> devices & 7. VMs -> virtual_machines
            for eq in site.equipment:
                is_stale = self.inventory_filter.is_stale(
                    site.site_id, eq.equipment_id
                ) or self.inventory_filter.is_stale(site.site_id, eq.name)
                hostname_by_object_id[eq.equipment_id] = eq.name
                stale_by_object_id[eq.equipment_id] = is_stale
                for raw_ip in eq.assigned_ips:
                    hostname_by_ip[_strip_ip_mask(raw_ip)] = eq.name

                if eq.category is EquipmentCategory.VM:
                    if eq.hypervisor_id and ":" in eq.hypervisor_id:
                        cluster = eq.hypervisor_id.split(":", 1)[0].strip() or "vcenter-default"
                    else:
                        cluster = (eq.hypervisor_id or "").strip() or "vcenter-default"

                    virtual_machines_out.append(
                        {
                            "name": eq.name,
                            "slug": slugify(eq.name),
                            "site": site_slug,
                            "cluster": cluster,
                            "status": "decommissioning" if is_stale else "active",
                            "vcpus": int(getattr(eq, "vcpus", 2) or 2),
                            "memory": int(getattr(eq, "memory", 4096) or 4096),
                            "custom_fields": {
                                "legacy_sot_id": eq.equipment_id,
                                "os_family": _infer_vm_os_family(eq.name),
                            },
                        }
                    )
                else:
                    manufacturer, device_type = _infer_equipment_manufacturer_and_model(
                        eq
                    )
                    devices_out.append(
                        {
                            "name": eq.name,
                            "slug": slugify(eq.name),
                            "manufacturer": manufacturer,
                            "role": eq.category.value,
                            "device_type": device_type,
                            "site": site_slug,
                            "status": "decommissioning" if is_stale else "active",
                            "custom_fields": {
                                "legacy_sot_id": eq.equipment_id,
                            },
                        }
                    )

            # 6. IP Addresses
            for ip_rec in site.ip_addresses:
                clean_ip = _strip_ip_mask(ip_rec.ip)
                if not clean_ip:
                    continue
                address = self._resolve_ip_with_prefix(
                    site, ip_rec.ip, ip_rec.subnet_id
                )
                if (site_slug, address) in seen_ips:
                    continue
                seen_ips.add((site_slug, address))

                resolved_host = (
                    hostname_by_object_id.get(ip_rec.assigned_object_id or "")
                    or hostname_by_ip.get(clean_ip)
                    or ""
                )
                assigned_obj = resolved_host or (ip_rec.assigned_object_id or "")

                is_ip_stale = (
                    self.inventory_filter.is_stale(site.site_id, ip_rec.ip)
                    or self.inventory_filter.is_stale(site.site_id, clean_ip)
                    or (
                        bool(ip_rec.assigned_object_id)
                        and stale_by_object_id.get(ip_rec.assigned_object_id or "", False)
                    )
                )
                if is_ip_stale:
                    ip_status = (
                        "deprecated"
                        if self.target_platform == "netbox"
                        else "decommissioning"
                    )
                else:
                    ip_status = "active"

                ip_addresses_out.append(
                    {
                        "address": address,
                        "slug": slugify(f"{site.site_id}-{address}"),
                        "site": site_slug,
                        "status": ip_status,
                        "dns_name": resolved_host,
                        "assigned_object": assigned_obj,
                        "custom_fields": {
                            "legacy_sot_id": f"{site.site_id}:ip:{clean_ip}",
                        },
                    }
                )

            # Ensure management IPs and equipment assigned IPs not in site.ip_addresses are also exported
            for dev in site.devices:
                if not dev.management_ip:
                    continue
                clean_ip = _strip_ip_mask(dev.management_ip)
                address = self._resolve_ip_with_prefix(site, dev.management_ip)
                if (site_slug, address) in seen_ips:
                    continue
                seen_ips.add((site_slug, address))
                is_ip_stale = stale_by_object_id.get(dev.device_id, False)
                ip_status = (
                    ("deprecated" if self.target_platform == "netbox" else "decommissioning")
                    if is_ip_stale
                    else "active"
                )
                ip_addresses_out.append(
                    {
                        "address": address,
                        "slug": slugify(f"{site.site_id}-{address}"),
                        "site": site_slug,
                        "status": ip_status,
                        "dns_name": dev.hostname,
                        "assigned_object": dev.hostname,
                        "custom_fields": {
                            "legacy_sot_id": f"{site.site_id}:ip:{clean_ip}",
                        },
                    }
                )

            for eq in site.equipment:
                for raw_ip in eq.assigned_ips:
                    clean_ip = _strip_ip_mask(raw_ip)
                    if not clean_ip:
                        continue
                    address = self._resolve_ip_with_prefix(site, raw_ip)
                    if (site_slug, address) in seen_ips:
                        continue
                    seen_ips.add((site_slug, address))
                    is_ip_stale = stale_by_object_id.get(eq.equipment_id, False)
                    ip_status = (
                        ("deprecated" if self.target_platform == "netbox" else "decommissioning")
                        if is_ip_stale
                        else "active"
                    )
                    ip_addresses_out.append(
                        {
                            "address": address,
                            "slug": slugify(f"{site.site_id}-{address}"),
                            "site": site_slug,
                            "status": ip_status,
                            "dns_name": eq.name,
                            "assigned_object": eq.name,
                            "custom_fields": {
                                "legacy_sot_id": f"{site.site_id}:ip:{clean_ip}",
                            },
                        }
                    )

        sites_out.sort(key=lambda r: r["slug"])
        vlans_out.sort(key=lambda r: (r["site"], r["vid"], r["slug"]))
        prefixes_out.sort(key=lambda r: (r["site"], r["prefix"], r["slug"]))
        devices_out.sort(key=lambda r: (r["site"], r["slug"]))
        interfaces_out.sort(key=lambda r: (r["device"], r["slug"]))
        ip_addresses_out.sort(key=lambda r: (r["site"], r["address"], r["slug"]))
        virtual_machines_out.sort(key=lambda r: (r["site"], r["slug"]))

        collections: dict[str, list[dict[str, Any]]] = {
            "sites": sites_out,
            "vlans": vlans_out,
            "prefixes": prefixes_out,
            "devices": devices_out,
            "interfaces": interfaces_out,
            "ip_addresses": ip_addresses_out,
            "virtual_machines": virtual_machines_out,
        }

        summary = {key: len(collections[key]) for key in ENTITY_COLLECTION_KEYS}

        return {
            "target_platform": self.target_platform,
            "generated_at": _format_optional_datetime(self.generated_at),
            "summary": summary,
            **collections,
        }

    def to_dict(self) -> dict[str, Any]:
        """Return the complete NetBox / Nautobot export bundle as a dictionary."""
        return self.build_bundle()

    def export_json(
        self,
        *,
        indent: Optional[int] = 2,
        output_path: Optional[Path | str] = None,
    ) -> str:
        """Serialize the golden inventory bundle to JSON and optionally write it to output_path."""
        payload = self.to_dict()
        content = json.dumps(payload, indent=indent)
        if output_path is not None:
            target = Path(output_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return content

    def export_csv_bundle(self, output_dir: Path | str) -> dict[str, Path]:
        """Write deterministic per-entity CSV import files to output_dir and return a path map."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        bundle = self.to_dict()
        written_files: dict[str, Path] = {}

        for entity_key in ENTITY_COLLECTION_KEYS:
            columns = CSV_COLUMNS_BY_ENTITY[entity_key]
            records: list[dict[str, Any]] = bundle.get(entity_key, [])
            csv_file = out_path / f"{entity_key}.csv"

            buf = io.StringIO()
            writer = csv.writer(buf, lineterminator="\n")
            writer.writerow(columns)

            for record in records:
                custom_fields = record.get("custom_fields") or {}
                row: list[Any] = []
                for col in columns:
                    if col in custom_fields:
                        val = custom_fields[col]
                    else:
                        val = record.get(col)
                    row.append("" if val is None else val)
                writer.writerow(row)

            csv_file.write_text(buf.getvalue(), encoding="utf-8")
            written_files[entity_key] = csv_file

        return written_files
