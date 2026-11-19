"""Validated Golden Inventory Exporter for NetBox and Nautobot bulk migration."""

from __future__ import annotations

from sot_validator.migration._exporter_bundle import ModernSoTExporter
from sot_validator.migration._exporter_filter import GoldenInventoryFilter
from sot_validator.migration._exporter_helpers import (
    CSV_COLUMNS_BY_ENTITY,
    ENTITY_COLLECTION_KEYS,
    SUPPORTED_TARGET_PLATFORMS,
    TargetPlatform,
    _LINUX_NAME_INDICATORS,
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


__all__ = [
    "CSV_COLUMNS_BY_ENTITY",
    "ENTITY_COLLECTION_KEYS",
    "GoldenInventoryFilter",
    "ModernSoTExporter",
    "SUPPORTED_TARGET_PLATFORMS",
    "slugify",
]
