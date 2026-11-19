"""Golden inventory exporter constants and module-level normalization helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import re
from typing import Any, Literal, Optional

from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    Site,
    ValidationResult,
    _parse_optional_datetime,
)
from sot_validator.reconciliation.reconciler import (
    DiscrepancyRecord,
    ReconciliationReport,
)

TargetPlatform = Literal["netbox", "nautobot"]

SUPPORTED_TARGET_PLATFORMS: frozenset[str] = frozenset({"netbox", "nautobot"})

ENTITY_COLLECTION_KEYS: tuple[str, ...] = (
    "sites",
    "vlans",
    "prefixes",
    "devices",
    "interfaces",
    "ip_addresses",
    "virtual_machines",
)

CSV_COLUMNS_BY_ENTITY: dict[str, tuple[str, ...]] = {
    "sites": (
        "name",
        "slug",
        "status",
        "physical_address",
        "contact_name",
        "contact_email",
        "legacy_sot_id",
    ),
    "vlans": (
        "vid",
        "name",
        "slug",
        "site",
        "status",
        "legacy_sot_id",
    ),
    "prefixes": (
        "prefix",
        "slug",
        "site",
        "vlan",
        "status",
        "description",
        "legacy_sot_id",
    ),
    "devices": (
        "name",
        "slug",
        "manufacturer",
        "role",
        "device_type",
        "site",
        "status",
        "legacy_sot_id",
    ),
    "interfaces": (
        "name",
        "slug",
        "device",
        "enabled",
        "poe_mode",
        "description",
        "untagged_vlan",
        "legacy_sot_id",
    ),
    "ip_addresses": (
        "address",
        "slug",
        "site",
        "status",
        "dns_name",
        "assigned_object",
        "legacy_sot_id",
    ),
    "virtual_machines": (
        "name",
        "slug",
        "site",
        "cluster",
        "status",
        "vcpus",
        "memory",
        "os_family",
        "legacy_sot_id",
    ),
}

_LINUX_NAME_INDICATORS: tuple[str, ...] = (
    "linux",
    "lin-",
    "ubuntu",
    "rhel",
    "centos",
    "debian",
)


def slugify(value: str) -> str:
    """Convert an arbitrary string into a deterministic URL-safe lowercase slug."""
    if value is None:
        return "item"
    cleaned = re.sub(r"[^a-z0-9]+", "-", str(value).strip().lower()).strip("-")
    return cleaned or "item"


def _resolve_timestamp(value: Optional[datetime | str]) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    parsed = _parse_optional_datetime(value, "generated_at")
    assert parsed is not None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _strip_ip_mask(raw_ip: Optional[str]) -> str:
    if not raw_ip:
        return ""
    return str(raw_ip).strip().split("/", 1)[0].strip()


def _parse_vlan_vid(raw_vlan_id: Optional[str | int], *, fallback: Optional[int] = 1) -> Optional[int]:
    if raw_vlan_id is None:
        return fallback
    if isinstance(raw_vlan_id, int) and not isinstance(raw_vlan_id, bool):
        return raw_vlan_id if 1 <= raw_vlan_id <= 4094 else fallback
    text = str(raw_vlan_id).strip()
    if not text:
        return fallback
    if text.isdigit():
        vid = int(text)
        return vid if 1 <= vid <= 4094 else fallback
    match = re.search(r"(\d+)$", text)
    if match:
        vid = int(match.group(1))
        if 1 <= vid <= 4094:
            return vid
    return fallback


def _parse_contact_info(contact_info: Optional[str]) -> tuple[str, str]:
    """Extract (contact_name, contact_email) from a pipe-delimited or freeform contact string."""
    if not contact_info or not contact_info.strip():
        return "", ""

    raw = contact_info.strip()
    email_match = re.search(r"[^\s|<>;,]+@[^\s|<>;,]+", raw)
    contact_email = email_match.group(0).strip() if email_match else ""

    segments = [seg.strip() for seg in raw.split("|") if seg.strip()]
    contact_name = ""
    for seg in segments:
        without_angle = re.sub(r"<[^>]*>", "", seg).strip()
        if "@" in without_angle:
            continue
        if re.fullmatch(r"[+\d\s().-]+", without_angle):
            continue
        if without_angle:
            contact_name = without_angle
            break

    return contact_name, contact_email


def _infer_equipment_manufacturer_and_model(equipment: Equipment) -> tuple[str, str]:
    name_lower = equipment.name.lower()
    category = equipment.category

    explicit_vendor = getattr(equipment, "vendor", None)
    explicit_model = getattr(equipment, "model", None)

    if category is EquipmentCategory.UPS or "apc" in name_lower or "smart-ups" in name_lower:
        manufacturer = explicit_vendor or "APC"
        model = explicit_model or "Smart-UPS"
        return manufacturer, model

    if category is EquipmentCategory.SAN or "netapp" in name_lower or "san" in name_lower:
        if "synology" in name_lower or "nas" in name_lower:
            manufacturer = explicit_vendor or "Synology"
        else:
            manufacturer = explicit_vendor or "NetApp"
        model = explicit_model or "Storage Array"
        return manufacturer, model

    if "synology" in name_lower or "nas" in name_lower:
        return explicit_vendor or "Synology", explicit_model or "Storage Array"

    if "hp" in name_lower or "proliant" in name_lower:
        return explicit_vendor or "HP", explicit_model or "PowerEdge Server"

    if "extreme" in name_lower:
        return explicit_vendor or "Extreme Networks", explicit_model or "ExtremeSwitching"

    if category is EquipmentCategory.SERVER:
        return explicit_vendor or "Dell", explicit_model or "PowerEdge Server"

    return explicit_vendor or "Generic", explicit_model or "Generic Appliance"


def _infer_vm_os_family(vm_name: str, details: Optional[str] = None) -> str:
    combined = f"{vm_name} {details or ''}".lower()
    if any(token in combined for token in _LINUX_NAME_INDICATORS):
        return "linux"
    return "windows"


def _normalize_sites_input(
    sites: Optional[Sequence[Site | Mapping[str, Any]] | Mapping[str, Any] | Site],
) -> list[Site]:
    if sites is None:
        return []
    if isinstance(sites, Site):
        return [sites]
    if isinstance(sites, Mapping):
        if "site_id" in sites and "name" in sites:
            return [Site.from_dict(sites)]
        if "sites" in sites and isinstance(sites["sites"], Sequence):
            return [
                s if isinstance(s, Site) else Site.from_dict(s)
                for s in sites["sites"]
            ]
        normalized: list[Site] = []
        for val in sites.values():
            if isinstance(val, Site):
                normalized.append(val)
            elif isinstance(val, Mapping) and "site_id" in val:
                normalized.append(Site.from_dict(val))
        return sorted(normalized, key=lambda s: s.site_id)

    return [s if isinstance(s, Site) else Site.from_dict(s) for s in sites]


def _normalize_validation_results(
    validation_results: Optional[
        Sequence[ValidationResult | Mapping[str, Any]] | Mapping[str, Any]
    ],
) -> list[ValidationResult]:
    if validation_results is None:
        return []
    if isinstance(validation_results, Mapping):
        if "results" in validation_results and isinstance(
            validation_results["results"], Sequence
        ):
            raw_list = validation_results["results"]
            return [
                r if isinstance(r, ValidationResult) else ValidationResult.from_dict(r)
                for r in raw_list
            ]
        if "item_id" in validation_results and "classification" in validation_results:
            return [ValidationResult.from_dict(validation_results)]
        results: list[ValidationResult] = []
        for key, val in validation_results.items():
            if isinstance(val, ValidationResult):
                results.append(val)
            elif isinstance(val, Mapping) and "classification" in val:
                item_dict = dict(val)
                item_dict.setdefault("item_id", str(key))
                item_dict.setdefault("item_type", "Equipment")
                item_dict.setdefault("site_id", "unknown")
                item_dict.setdefault("name", str(key))
                results.append(ValidationResult.from_dict(item_dict))
        return results

    return [
        r if isinstance(r, ValidationResult) else ValidationResult.from_dict(r)
        for r in validation_results
    ]


def _normalize_discrepancies(
    reconciliation_report: Optional[
        ReconciliationReport
        | Sequence[DiscrepancyRecord | Mapping[str, Any]]
        | Mapping[str, Any]
    ],
) -> list[DiscrepancyRecord]:
    if reconciliation_report is None:
        return []
    if isinstance(reconciliation_report, ReconciliationReport):
        return list(reconciliation_report.discrepancies)
    if isinstance(reconciliation_report, Mapping):
        if "discrepancies" in reconciliation_report and isinstance(
            reconciliation_report["discrepancies"], Sequence
        ):
            return [
                d
                if isinstance(d, DiscrepancyRecord)
                else DiscrepancyRecord.from_dict(d)
                for d in reconciliation_report["discrepancies"]
            ]
        if "discrepancy_id" in reconciliation_report:
            return [DiscrepancyRecord.from_dict(reconciliation_report)]
        return []
    return [
        d if isinstance(d, DiscrepancyRecord) else DiscrepancyRecord.from_dict(d)
        for d in reconciliation_report
    ]
