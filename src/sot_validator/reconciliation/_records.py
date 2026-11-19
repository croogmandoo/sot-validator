"""Reconciliation constants, discrepancy types, shared helpers and DiscrepancyRecord."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import ipaddress
import json
import re
from typing import Any, Optional

from sot_validator.models import _parse_optional_datetime, _require_non_empty_str
from sot_validator.reconciliation.oui_annotation import OUI_ANNOTATION_KEYS
from sot_validator.signals.hypervisor import _format_mac_canonical

VALID_DISCREPANCY_SOURCES: frozenset[str] = frozenset(
    {"vcenter", "arp", "snmp", "icmp"}
)

DISCREPANCY_CSV_COLUMNS: tuple[str, ...] = (
    "discrepancy_id",
    "discrepancy_type",
    "site_id",
    "observed_identifier",
    "observed_ip",
    "observed_mac",
    "observed_hostname",
    "source",
    "sot_item_id",
    "details",
    "recommended_onboarding_action",
)

DISCREPANCY_OUI_CSV_COLUMNS: tuple[str, ...] = DISCREPANCY_CSV_COLUMNS + OUI_ANNOTATION_KEYS

ONBOARDING_CSV_COLUMNS: tuple[str, ...] = (
    "record_type",
    "target_table",
    "item_id",
    "site_id",
    "subnet_id",
    "hostname",
    "category_or_role",
    "vendor",
    "model",
    "ip_address",
    "mac_address",
    "hypervisor_id",
    "source",
    "notes",
)


class DiscrepancyType(str, Enum):
    """Supported reverse-discovery discrepancy types."""

    UNTRACKED_VM = "UNTRACKED_VM"
    UNTRACKED_IP = "UNTRACKED_IP"
    UNTRACKED_DEVICE = "UNTRACKED_DEVICE"
    ATTRIBUTE_MISMATCH = "ATTRIBUTE_MISMATCH"


ALL_DISCREPANCY_TYPES: tuple[DiscrepancyType, ...] = (
    DiscrepancyType.UNTRACKED_VM,
    DiscrepancyType.UNTRACKED_IP,
    DiscrepancyType.UNTRACKED_DEVICE,
    DiscrepancyType.ATTRIBUTE_MISMATCH,
)


def _clean_optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned if cleaned else None
    text = str(value).strip()
    return text if text else None


def _resolve_timestamp(value: Optional[datetime | str]) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    parsed = _parse_optional_datetime(value, "generated_at")
    assert parsed is not None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_hostname(hostname: Optional[str]) -> Optional[str]:
    cleaned = _clean_optional_str(hostname)
    if cleaned is None:
        return None
    return cleaned.lower().rstrip(".")


def _short_hostname(hostname: Optional[str]) -> Optional[str]:
    norm = _normalize_hostname(hostname)
    if norm is None:
        return None
    return norm.split(".", 1)[0]


def _hostnames_match(host_a: Optional[str], host_b: Optional[str]) -> bool:
    norm_a = _normalize_hostname(host_a)
    norm_b = _normalize_hostname(host_b)
    if norm_a is None or norm_b is None:
        return False
    if norm_a == norm_b:
        return True
    if norm_a.startswith(norm_b + ".") or norm_b.startswith(norm_a + "."):
        return True
    short_a = _short_hostname(norm_a)
    short_b = _short_hostname(norm_b)
    if ("." not in norm_a or "." not in norm_b) and short_a and short_a == short_b:
        return True
    return False


def _slugify_id(raw: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "-", raw.strip().lower()).strip("-")
    return cleaned or "item"


def _sql_literal(value: Optional[str]) -> str:
    if value is None:
        return "NULL"
    escaped = str(value).replace("'", "''")
    return f"'{escaped}'"


def _extract_detail_kv(details: Optional[str]) -> dict[str, str]:
    if not details:
        return {}
    result: dict[str, str] = {}
    for match in re.finditer(r"([a-z_]+)=([^,)\s]+)", details):
        key = match.group(1).strip()
        val = match.group(2).strip().strip("'\"")
        if val and val.lower() not in ("none", "n/a", "null"):
            result[key] = val
    return result


def _infer_subnet_id(site_id: str, ip_str: Optional[str], hint: Optional[str] = None) -> str:
    if hint and hint.strip():
        return hint.strip()
    site_num_match = re.search(r"(\d+)$", site_id)
    site_token = site_num_match.group(1).zfill(3) if site_num_match else _slugify_id(site_id)
    if ip_str:
        try:
            addr = ipaddress.ip_address(ip_str.strip())
            if isinstance(addr, ipaddress.IPv4Address):
                third_octet = int(str(addr).split(".")[2])
                return f"sub-{site_token}-{third_octet:03d}"
        except ValueError:
            pass
    return f"sub-{site_token}-001"


@dataclass
class DiscrepancyRecord:
    """Single reverse-discovery discrepancy or attribute mismatch record."""

    discrepancy_id: str
    discrepancy_type: DiscrepancyType
    site_id: str
    observed_identifier: str
    observed_ip: Optional[str] = None
    observed_mac: Optional[str] = None
    observed_hostname: Optional[str] = None
    source: str = "vcenter"
    sot_item_id: Optional[str] = None
    details: Optional[str] = None
    recommended_onboarding_action: Optional[str] = None

    def __post_init__(self) -> None:
        self.discrepancy_id = _require_non_empty_str(
            self.discrepancy_id, "discrepancy_id"
        ).strip()
        if not isinstance(self.discrepancy_type, DiscrepancyType):
            try:
                self.discrepancy_type = DiscrepancyType(self.discrepancy_type)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid discrepancy_type: {self.discrepancy_type!r}"
                ) from exc
        self.site_id = _require_non_empty_str(self.site_id, "site_id").strip()
        self.observed_identifier = _require_non_empty_str(
            self.observed_identifier, "observed_identifier"
        ).strip()
        self.observed_ip = _clean_optional_str(self.observed_ip)
        self.observed_mac = _format_mac_canonical(self.observed_mac)
        self.observed_hostname = _clean_optional_str(self.observed_hostname)

        raw_source = _require_non_empty_str(self.source, "source").strip().lower()
        if raw_source not in VALID_DISCREPANCY_SOURCES:
            raise ValueError(
                f"Invalid source {self.source!r}; must be one of {sorted(VALID_DISCREPANCY_SOURCES)}"
            )
        self.source = raw_source
        self.sot_item_id = _clean_optional_str(self.sot_item_id)
        self.details = _clean_optional_str(self.details)
        self.recommended_onboarding_action = _clean_optional_str(
            self.recommended_onboarding_action
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "discrepancy_id": self.discrepancy_id,
            "discrepancy_type": self.discrepancy_type.value,
            "site_id": self.site_id,
            "observed_identifier": self.observed_identifier,
            "observed_ip": self.observed_ip,
            "observed_mac": self.observed_mac,
            "observed_hostname": self.observed_hostname,
            "source": self.source,
            "sot_item_id": self.sot_item_id,
            "details": self.details,
            "recommended_onboarding_action": self.recommended_onboarding_action,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DiscrepancyRecord:
        return cls(
            discrepancy_id=data["discrepancy_id"],
            discrepancy_type=DiscrepancyType(data["discrepancy_type"]),
            site_id=data["site_id"],
            observed_identifier=data["observed_identifier"],
            observed_ip=data.get("observed_ip"),
            observed_mac=data.get("observed_mac"),
            observed_hostname=data.get("observed_hostname"),
            source=data.get("source", "vcenter"),
            sot_item_id=data.get("sot_item_id"),
            details=data.get("details"),
            recommended_onboarding_action=data.get("recommended_onboarding_action"),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> DiscrepancyRecord:
        return cls.from_dict(json.loads(raw))
