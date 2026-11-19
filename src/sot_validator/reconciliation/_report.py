"""ReconciliationReport: summaries, JSON, CSV and SoT onboarding output."""

from __future__ import annotations

from collections.abc import Mapping
import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
import io
import json
from pathlib import Path
from typing import Any, Optional

from sot_validator.enrichment import OuiRegistry
from sot_validator.models import _format_optional_datetime
from sot_validator.reconciliation._records import (
    ALL_DISCREPANCY_TYPES,
    DISCREPANCY_CSV_COLUMNS,
    DISCREPANCY_OUI_CSV_COLUMNS,
    ONBOARDING_CSV_COLUMNS,
    DiscrepancyRecord,
    DiscrepancyType,
    _extract_detail_kv,
    _infer_subnet_id,
    _resolve_timestamp,
    _short_hostname,
    _slugify_id,
    _sql_literal,
)
from sot_validator.reconciliation.oui_annotation import (
    discrepancy_csv_cells,
    discrepancy_dict,
)


@dataclass
class ReconciliationReport:
    """Aggregated reverse-discovery reconciliation report across sites."""

    discrepancies: list[DiscrepancyRecord] = field(default_factory=list)
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    # None when exclusion was off; set (possibly empty) when --exclude-randomized-macs ran.
    excluded_discrepancies: Optional[list[DiscrepancyRecord]] = None
    oui_registry: Optional[OuiRegistry] = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.generated_at = _resolve_timestamp(self.generated_at)
        self.discrepancies = [
            d if isinstance(d, DiscrepancyRecord) else DiscrepancyRecord.from_dict(d)
            for d in (self.discrepancies or [])
        ]

    @property
    def total_discrepancies(self) -> int:
        return len(self.discrepancies)

    @property
    def summary_by_type(self) -> dict[str, int]:
        counts: dict[str, int] = {
            dtype.value: 0 for dtype in ALL_DISCREPANCY_TYPES
        }
        for disc in self.discrepancies:
            counts[disc.discrepancy_type.value] = (
                counts.get(disc.discrepancy_type.value, 0) + 1
            )
        return counts

    @property
    def summary_by_site(self) -> dict[str, dict[str, Any]]:
        summary: dict[str, dict[str, Any]] = {}
        for site_id in sorted({d.site_id for d in self.discrepancies}):
            site_items = [d for d in self.discrepancies if d.site_id == site_id]
            by_type = {
                dtype.value: sum(
                    1 for d in site_items if d.discrepancy_type is dtype
                )
                for dtype in ALL_DISCREPANCY_TYPES
            }
            summary[site_id] = {
                "site_id": site_id,
                "total": len(site_items),
                **by_type,
                "by_type": dict(by_type),
            }
        return summary

    def to_dict(self) -> dict[str, Any]:
        data = {
            "generated_at": _format_optional_datetime(self.generated_at),
            "total_discrepancies": self.total_discrepancies,
            "summary_by_type": self.summary_by_type,
            "summary_by_site": self.summary_by_site,
            "discrepancies": [
                discrepancy_dict(d, self.oui_registry) for d in self.discrepancies
            ],
        }
        if self.excluded_discrepancies is not None:
            data["excluded_randomized_mac_count"] = len(self.excluded_discrepancies)
            data["excluded_randomized_mac_discrepancies"] = [
                discrepancy_dict(d, self.oui_registry) for d in self.excluded_discrepancies
            ]
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ReconciliationReport:
        raw_discs = data.get("discrepancies", [])
        return cls(
            discrepancies=[
                d if isinstance(d, DiscrepancyRecord) else DiscrepancyRecord.from_dict(d)
                for d in raw_discs
            ],
            generated_at=_resolve_timestamp(data.get("generated_at")),
        )

    def to_json(
        self,
        *,
        indent: Optional[int] = 2,
        output_path: Optional[Path | str] = None,
    ) -> str:
        content = json.dumps(self.to_dict(), indent=indent)
        if output_path is not None:
            target = Path(output_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return content

    @classmethod
    def from_json(cls, raw: str | Path) -> ReconciliationReport:
        if isinstance(raw, Path):
            raw_text = raw.read_text(encoding="utf-8")
        else:
            raw_text = raw
        return cls.from_dict(json.loads(raw_text))

    def to_csv(self, *, output_path: Optional[Path | str] = None) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(
            DISCREPANCY_OUI_CSV_COLUMNS if self.oui_registry is not None else DISCREPANCY_CSV_COLUMNS
        )
        for disc in self.discrepancies:
            writer.writerow(
                [
                    disc.discrepancy_id,
                    disc.discrepancy_type.value,
                    disc.site_id,
                    disc.observed_identifier,
                    disc.observed_ip or "",
                    disc.observed_mac or "",
                    disc.observed_hostname or "",
                    disc.source,
                    disc.sot_item_id or "",
                    disc.details or "",
                    disc.recommended_onboarding_action or "",
                    *discrepancy_csv_cells(disc, self.oui_registry),
                ]
            )
        content = buf.getvalue()
        if output_path is not None:
            target = Path(output_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return content

    def _build_onboarding_entries(self) -> list[dict[str, Optional[str]]]:
        entries: list[dict[str, Optional[str]]] = []
        timestamp_str = _format_optional_datetime(self.generated_at)

        for idx, disc in enumerate(self.discrepancies, start=1):
            if disc.discrepancy_type is DiscrepancyType.ATTRIBUTE_MISMATCH:
                continue

            kv = _extract_detail_kv(disc.details)
            subnet_id = _infer_subnet_id(
                disc.site_id, disc.observed_ip, kv.get("subnet_id")
            )
            notes = disc.recommended_onboarding_action or disc.details or ""

            if disc.discrepancy_type is DiscrepancyType.UNTRACKED_VM:
                hostname = disc.observed_hostname or disc.observed_identifier
                short_slug = _slugify_id(_short_hostname(hostname) or disc.observed_identifier)
                item_id = kv.get("item_id") or f"eq-{_slugify_id(disc.site_id)}-vm-{short_slug}"
                vcenter_inst = kv.get("vcenter_instance") or "vcenter-default"
                vm_moref = kv.get("vm_moref") or (
                    disc.observed_identifier
                    if disc.observed_identifier.lower().startswith("vm-")
                    else f"vm-{idx:04d}"
                )
                bios_uuid = kv.get("bios_uuid") or (
                    disc.observed_identifier
                    if "-" in disc.observed_identifier
                    and len(disc.observed_identifier) >= 32
                    else None
                )
                hypervisor_id = (
                    f"{vcenter_inst}:{vm_moref}"
                    if vcenter_inst and vm_moref
                    else (bios_uuid or disc.observed_identifier)
                )
                entries.append(
                    {
                        "record_type": DiscrepancyType.UNTRACKED_VM.value,
                        "target_table": "equipment",
                        "item_id": item_id,
                        "site_id": disc.site_id,
                        "subnet_id": subnet_id if disc.observed_ip else "",
                        "hostname": hostname,
                        "category_or_role": "VM",
                        "vendor": kv.get("vendor") or "VMware",
                        "model": kv.get("model") or "Virtual Machine",
                        "ip_address": disc.observed_ip,
                        "mac_address": disc.observed_mac,
                        "hypervisor_id": hypervisor_id,
                        "vcenter_instance": vcenter_inst,
                        "vcenter_bios_uuid": bios_uuid,
                        "vcenter_moref": vm_moref,
                        "source": disc.source,
                        "notes": notes,
                        "last_seen": timestamp_str,
                    }
                )

            elif disc.discrepancy_type is DiscrepancyType.UNTRACKED_DEVICE:
                hostname = disc.observed_hostname or disc.observed_identifier
                short_slug = _slugify_id(_short_hostname(hostname) or disc.observed_identifier)
                details_lower = (disc.details or "").lower()
                if "vendor" in kv:
                    vendor = kv["vendor"].replace("_", " ")
                elif "extreme" in details_lower:
                    vendor = "Extreme Networks"
                elif "apc" in details_lower or "smart-ups" in details_lower:
                    vendor = "APC"
                else:
                    vendor = "Unknown"

                if "model" in kv:
                    model = kv["model"].replace("_", " ")
                elif vendor == "Extreme Networks":
                    model = "ExtremeSwitching"
                elif vendor == "APC":
                    model = "Smart-UPS"
                else:
                    model = "Unknown"

                if "role" in kv:
                    role = kv["role"]
                elif vendor == "APC":
                    role = "ups"
                else:
                    role = "access-switch"

                item_id = kv.get("item_id") or f"dev-{_slugify_id(disc.site_id)}-{short_slug}"
                entries.append(
                    {
                        "record_type": DiscrepancyType.UNTRACKED_DEVICE.value,
                        "target_table": "network_devices",
                        "item_id": item_id,
                        "site_id": disc.site_id,
                        "subnet_id": subnet_id if disc.observed_ip else "",
                        "hostname": hostname,
                        "category_or_role": role,
                        "vendor": vendor,
                        "model": model,
                        "ip_address": disc.observed_ip or disc.observed_identifier,
                        "mac_address": disc.observed_mac,
                        "hypervisor_id": None,
                        "room": kv.get("room") or "MDF-101",
                        "os_version": kv.get("os_version"),
                        "serial_number": kv.get("serial_number"),
                        "source": disc.source,
                        "notes": notes,
                        "last_seen": timestamp_str,
                    }
                )

            elif disc.discrepancy_type is DiscrepancyType.UNTRACKED_IP:
                ip_val = disc.observed_ip or disc.observed_identifier
                ip_slug = _slugify_id(ip_val)
                item_id = kv.get("item_id") or f"ip-{_slugify_id(disc.site_id)}-{ip_slug}"
                target_type = kv.get("target_type") or (
                    "network_device" if disc.source == "snmp" else "equipment"
                )
                target_id = kv.get("target_id") or (
                    f"eq-{_slugify_id(disc.site_id)}-{ip_slug}"
                    if target_type == "equipment"
                    else f"dev-{_slugify_id(disc.site_id)}-{ip_slug}"
                )
                entries.append(
                    {
                        "record_type": DiscrepancyType.UNTRACKED_IP.value,
                        "target_table": "ip_arp_entries",
                        "item_id": item_id,
                        "site_id": disc.site_id,
                        "subnet_id": subnet_id,
                        "hostname": disc.observed_hostname,
                        "category_or_role": target_type,
                        "vendor": None,
                        "model": None,
                        "ip_address": ip_val,
                        "mac_address": disc.observed_mac,
                        "hypervisor_id": None,
                        "assigned_target_type": target_type,
                        "assigned_target_id": target_id,
                        "arp_source_device_id": kv.get("arp_source_device_id"),
                        "source": disc.source,
                        "notes": notes,
                        "last_seen": timestamp_str,
                    }
                )

        return entries

    def generate_onboarding_csv(
        self, *, output_path: Optional[Path | str] = None
    ) -> str:
        """Generate an operator-ready CSV import template for untracked active assets."""
        entries = self._build_onboarding_entries()
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(ONBOARDING_CSV_COLUMNS)

        for entry in entries:
            writer.writerow(
                [
                    entry.get("record_type") or "",
                    entry.get("target_table") or "",
                    entry.get("item_id") or "",
                    entry.get("site_id") or "",
                    entry.get("subnet_id") or "",
                    entry.get("hostname") or "",
                    entry.get("category_or_role") or "",
                    entry.get("vendor") or "",
                    entry.get("model") or "",
                    entry.get("ip_address") or "",
                    entry.get("mac_address") or "",
                    entry.get("hypervisor_id") or "",
                    entry.get("source") or "",
                    entry.get("notes") or "",
                ]
            )

        content = buf.getvalue()
        if output_path is not None:
            target = Path(output_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return content

    def generate_onboarding_sql(
        self, *, output_path: Optional[Path | str] = None
    ) -> str:
        """Generate deterministic SQL INSERT INTO statements for untracked active assets."""
        entries = self._build_onboarding_entries()
        statements: list[str] = []

        for entry in entries:
            table = entry.get("target_table")
            if table == "equipment":
                stmt = (
                    "INSERT INTO equipment "
                    "(equipment_id, site_id, hostname, equipment_type, vendor, model, "
                    "primary_ip, mac_address, vcenter_instance, vcenter_bios_uuid, "
                    "vcenter_moref, connected_port_id, last_seen) VALUES ("
                    f"{_sql_literal(entry.get('item_id'))}, "
                    f"{_sql_literal(entry.get('site_id'))}, "
                    f"{_sql_literal(entry.get('hostname'))}, "
                    f"{_sql_literal(entry.get('category_or_role') or 'VM')}, "
                    f"{_sql_literal(entry.get('vendor') or 'VMware')}, "
                    f"{_sql_literal(entry.get('model') or 'Virtual Machine')}, "
                    f"{_sql_literal(entry.get('ip_address'))}, "
                    f"{_sql_literal(entry.get('mac_address'))}, "
                    f"{_sql_literal(entry.get('vcenter_instance'))}, "
                    f"{_sql_literal(entry.get('vcenter_bios_uuid'))}, "
                    f"{_sql_literal(entry.get('vcenter_moref'))}, "
                    "NULL, "
                    f"{_sql_literal(entry.get('last_seen'))}"
                    ");"
                )
                statements.append(stmt)
            elif table == "network_devices":
                stmt = (
                    "INSERT INTO network_devices "
                    "(device_id, site_id, hostname, vendor, model, role, mgmt_ip, "
                    "mac_address, room, os_version, serial_number, last_seen) VALUES ("
                    f"{_sql_literal(entry.get('item_id'))}, "
                    f"{_sql_literal(entry.get('site_id'))}, "
                    f"{_sql_literal(entry.get('hostname'))}, "
                    f"{_sql_literal(entry.get('vendor') or 'Unknown')}, "
                    f"{_sql_literal(entry.get('model') or 'Unknown')}, "
                    f"{_sql_literal(entry.get('category_or_role') or 'access-switch')}, "
                    f"{_sql_literal(entry.get('ip_address') or '0.0.0.0')}, "
                    f"{_sql_literal(entry.get('mac_address') or '00:00:00:00:00:00')}, "
                    f"{_sql_literal(entry.get('room') or 'MDF-101')}, "
                    f"{_sql_literal(entry.get('os_version'))}, "
                    f"{_sql_literal(entry.get('serial_number'))}, "
                    f"{_sql_literal(entry.get('last_seen'))}"
                    ");"
                )
                statements.append(stmt)
            elif table == "ip_arp_entries":
                stmt = (
                    "INSERT INTO ip_arp_entries "
                    "(ip_id, site_id, subnet_id, ip_address, mac_address, "
                    "assigned_target_type, assigned_target_id, arp_last_seen, "
                    "arp_source_device_id) VALUES ("
                    f"{_sql_literal(entry.get('item_id'))}, "
                    f"{_sql_literal(entry.get('site_id'))}, "
                    f"{_sql_literal(entry.get('subnet_id'))}, "
                    f"{_sql_literal(entry.get('ip_address'))}, "
                    f"{_sql_literal(entry.get('mac_address'))}, "
                    f"{_sql_literal(entry.get('assigned_target_type') or 'equipment')}, "
                    f"{_sql_literal(entry.get('assigned_target_id') or 'unassigned')}, "
                    f"{_sql_literal(entry.get('last_seen'))}, "
                    f"{_sql_literal(entry.get('arp_source_device_id'))}"
                    ");"
                )
                statements.append(stmt)

        content = "\n".join(statements) + ("\n" if statements else "")
        if output_path is not None:
            target = Path(output_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return content
