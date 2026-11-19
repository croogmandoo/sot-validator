"""Parity constants, discrepancy/recommendation enums and record identifier helpers."""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from typing import Any, Optional

from sot_validator.migration.exporter import _parse_vlan_vid, _strip_ip_mask, slugify
from sot_validator.reconciliation.reconciler import DiscrepancyType


PARITY_ENTITY_COLLECTIONS: tuple[str, ...] = (
    "devices",
    "virtual_machines",
    "ip_addresses",
    "vlans",
    "prefixes",
    "interfaces",
)

_STALE_MODERN_STATUSES: frozenset[str] = frozenset(
    {"decommissioning", "deprecated", "quarantined", "stale", "retired", "offline"}
)

_UNTRACKED_DISCREPANCY_TYPES: frozenset[DiscrepancyType] = frozenset(
    {
        DiscrepancyType.UNTRACKED_VM,
        DiscrepancyType.UNTRACKED_DEVICE,
        DiscrepancyType.UNTRACKED_IP,
    }
)


class ParityDiscrepancyType(str, Enum):
    """Discrepancy categories surfaced during legacy-to-modern SoT dual-run comparison."""

    MISSING_IN_MODERN_SOT = "MISSING_IN_MODERN_SOT"
    STALE_LEAKED_TO_MODERN_SOT = "STALE_LEAKED_TO_MODERN_SOT"
    ATTRIBUTE_MISMATCH = "ATTRIBUTE_MISMATCH"


ALL_PARITY_DISCREPANCY_TYPES: tuple[ParityDiscrepancyType, ...] = (
    ParityDiscrepancyType.MISSING_IN_MODERN_SOT,
    ParityDiscrepancyType.STALE_LEAKED_TO_MODERN_SOT,
    ParityDiscrepancyType.ATTRIBUTE_MISMATCH,
)


class CutoverRecommendation(str, Enum):
    """Per-site migration cutover recommendation state."""

    READY_FOR_CUTOVER = "READY_FOR_CUTOVER"
    NEEDS_REMEDIATION = "NEEDS_REMEDIATION"
    BLOCKED = "BLOCKED"


ALL_CUTOVER_RECOMMENDATIONS: tuple[CutoverRecommendation, ...] = (
    CutoverRecommendation.READY_FOR_CUTOVER,
    CutoverRecommendation.NEEDS_REMEDIATION,
    CutoverRecommendation.BLOCKED,
)


def _clean_optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _clamp_percentage(value: float | int) -> float:
    return round(max(0.0, min(100.0, float(value))), 2)


def _extract_legacy_id(record: Mapping[str, Any]) -> str:
    custom_fields = record.get("custom_fields")
    if isinstance(custom_fields, Mapping):
        raw = custom_fields.get("legacy_sot_id")
        if raw is not None and str(raw).strip():
            return str(raw).strip()
    raw_top = record.get("legacy_sot_id")
    if raw_top is not None and str(raw_top).strip():
        return str(raw_top).strip()
    return ""


def _extract_explicit_ip(record: Mapping[str, Any]) -> Optional[str]:
    for key in ("primary_ip", "primary_ip4", "management_ip", "ip_address", "ip"):
        val = _clean_optional_str(record.get(key))
        if val:
            return val
    custom_fields = record.get("custom_fields")
    if isinstance(custom_fields, Mapping):
        for key in ("primary_ip", "management_ip", "ip_address"):
            val = _clean_optional_str(custom_fields.get(key))
            if val:
                return val
    return None


def _extract_record_identifier(entity_type: str, record: Mapping[str, Any]) -> str:
    legacy_id = _extract_legacy_id(record)
    if entity_type in ("devices", "virtual_machines", "sites"):
        name = _clean_optional_str(record.get("name") or record.get("hostname"))
        if name:
            return name
    elif entity_type == "ip_addresses":
        addr = _clean_optional_str(record.get("address") or record.get("ip"))
        if addr:
            return addr
    elif entity_type == "vlans":
        name = _clean_optional_str(record.get("name"))
        vid = (
            record.get("vid")
            if record.get("vid") is not None
            else record.get("vlan_id")
        )
        if name:
            return name
        if vid is not None:
            return str(vid)
    elif entity_type == "prefixes":
        prefix = _clean_optional_str(record.get("prefix") or record.get("cidr"))
        if prefix:
            return prefix
    elif entity_type == "interfaces":
        name = _clean_optional_str(record.get("name"))
        dev = _clean_optional_str(record.get("device"))
        if dev and name:
            return f"{dev}:{name}"
        if name:
            return name

    if legacy_id:
        return legacy_id
    slug_val = _clean_optional_str(record.get("slug"))
    if slug_val:
        return slug_val
    return "unknown"


def _record_candidate_tokens(
    entity_type: str, record: Mapping[str, Any]
) -> set[str]:
    tokens: set[str] = set()
    legacy_id = _extract_legacy_id(record)
    if legacy_id:
        tokens.add(legacy_id)
        tokens.add(legacy_id.lower())
        tokens.add(slugify(legacy_id))
        if ":ip:" in legacy_id:
            ip_part = legacy_id.split(":ip:", 1)[1].strip()
            if ip_part:
                tokens.add(ip_part)

    for key in ("name", "hostname", "slug", "address", "ip", "prefix", "cidr"):
        val = _clean_optional_str(record.get(key))
        if val:
            tokens.add(val)
            tokens.add(val.lower())
            tokens.add(slugify(val))
            if key in ("address", "ip"):
                clean_ip = _strip_ip_mask(val)
                if clean_ip:
                    tokens.add(clean_ip)

    if entity_type == "vlans":
        vid = _parse_vlan_vid(
            record.get("vid")
            if record.get("vid") is not None
            else record.get("vlan_id"),
            fallback=None,
        )
        if vid is not None:
            tokens.add(str(vid))

    if entity_type == "interfaces":
        dev = _clean_optional_str(record.get("device"))
        name = _clean_optional_str(record.get("name"))
        if dev and name:
            tokens.add(f"{dev}:{name}")
            tokens.add(f"{dev.lower()}:{name.lower()}")

    return tokens
