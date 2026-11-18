"""Curation target-type constants, normalisation helpers, and the patch and audit-entry records."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import re
from typing import Any, Optional
import uuid

from sot_validator.models import (
    EquipmentCategory,
    ValidationClassification,
    _format_optional_datetime,
    _require_non_empty_str,
)
from sot_validator.signals.base import normalize_utc_datetime

_CANONICAL_TARGET_TYPES: dict[str, str] = {
    "networkdevice": "NetworkDevice",
    "network_device": "NetworkDevice",
    "device": "NetworkDevice",
    "port": "Port",
    "vlan": "VLAN",
    "subnet": "Subnet",
    "ipaddress": "IPAddress",
    "ip_address": "IPAddress",
    "ip": "IPAddress",
    "equipment": "Equipment",
}

VALID_TARGET_TYPES: tuple[str, ...] = (
    "NetworkDevice",
    "Port",
    "VLAN",
    "Subnet",
    "IPAddress",
    "Equipment",
)

GENESIS_HASH: str = "0" * 64

# Reserved target type accepted only by AuditLogEntry, for chain migration markers.
_AUDIT_LOG_TARGET_TYPE = "AuditLog"

_HASH_PATTERN = re.compile(r"[0-9a-f]{64}")

_MIGRATION_REASON = (
    "Audit entries before this marker were recorded before hash chaining and were "
    "chained retroactively during migration; their integrity before migration is "
    "not attested."
)


def _normalize_target_type(value: Any, field_name: str = "target_type") -> str:
    raw = _require_non_empty_str(value, field_name).strip()
    canonical = _CANONICAL_TARGET_TYPES.get(raw.lower())
    if canonical is None:
        raise ValueError(
            f"Invalid {field_name}: {value!r}. Expected one of {VALID_TARGET_TYPES}"
        )
    return canonical


def _normalize_optional_hash(value: Any, field_name: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str) or _HASH_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be 64 lowercase hex characters or None")
    return value


def _normalize_optional_str(value: Optional[str], field_name: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string or None")
    stripped = value.strip()
    return stripped if stripped else None


def _normalize_optional_utc_datetime(
    value: Optional[datetime | str], field_name: str
) -> Optional[datetime]:
    if value is None:
        return None
    return normalize_utc_datetime(value, field_name=field_name)


def _coerce_equipment_category(
    value: EquipmentCategory | str, field_name: str = "category"
) -> EquipmentCategory:
    if isinstance(value, EquipmentCategory):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        for candidate in (stripped, stripped.lower()):
            try:
                return EquipmentCategory(candidate)
            except ValueError:
                pass
        for member in EquipmentCategory:
            if member.name.lower() == stripped.lower():
                return member
    raise ValueError(f"Invalid {field_name}: {value!r}")


def _coerce_validation_classification(
    value: ValidationClassification | str,
    field_name: str = "pinned_classification",
) -> ValidationClassification:
    if isinstance(value, ValidationClassification):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        try:
            return ValidationClassification(stripped)
        except ValueError:
            pass
        lower = stripped.lower()
        for member in ValidationClassification:
            if member.value.lower() == lower or member.name.lower() == lower:
                return member
    raise ValueError(f"Invalid {field_name}: {value!r}")


def _require_non_negative_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value


@dataclass
class ItemEditPatch:
    """Operator modification patch for an inventory item in the curation overlay."""

    target_type: str
    target_id: str
    site_id: Optional[str] = None
    name: Optional[str] = None
    hostname: Optional[str] = None
    category: Optional[EquipmentCategory | str] = None
    role: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    vlan_id: Optional[str] = None
    subnet_id: Optional[str] = None
    room: Optional[str] = None
    notes: Optional[str] = None
    pinned_classification: Optional[ValidationClassification | str] = None
    custom_attributes: dict[str, Any] = field(default_factory=dict)
    deleted: bool = False
    updated_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        self.target_type = _normalize_target_type(self.target_type, "target_type")
        self.target_id = _require_non_empty_str(self.target_id, "target_id").strip()
        self.site_id = _normalize_optional_str(self.site_id, "site_id")
        self.name = _normalize_optional_str(self.name, "name")
        self.hostname = _normalize_optional_str(self.hostname, "hostname")
        if self.category is not None:
            self.category = _coerce_equipment_category(self.category, "category")
        self.role = _normalize_optional_str(self.role, "role")
        self.vendor = _normalize_optional_str(self.vendor, "vendor")
        self.model = _normalize_optional_str(self.model, "model")
        self.vlan_id = _normalize_optional_str(self.vlan_id, "vlan_id")
        self.subnet_id = _normalize_optional_str(self.subnet_id, "subnet_id")
        self.room = _normalize_optional_str(self.room, "room")
        self.notes = _normalize_optional_str(self.notes, "notes")
        if self.pinned_classification is not None:
            self.pinned_classification = _coerce_validation_classification(
                self.pinned_classification, "pinned_classification"
            )
        if self.custom_attributes is None:
            self.custom_attributes = {}
        elif isinstance(self.custom_attributes, Mapping):
            self.custom_attributes = dict(self.custom_attributes)
        else:
            raise ValueError("custom_attributes must be a mapping or None")
        if not isinstance(self.deleted, bool):
            raise ValueError("deleted must be a boolean")
        self.updated_at = _normalize_optional_utc_datetime(
            self.updated_at, "updated_at"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_type": self.target_type,
            "target_id": self.target_id,
            "site_id": self.site_id,
            "name": self.name,
            "hostname": self.hostname,
            "category": (
                self.category.value
                if isinstance(self.category, EquipmentCategory)
                else self.category
            ),
            "role": self.role,
            "vendor": self.vendor,
            "model": self.model,
            "vlan_id": self.vlan_id,
            "subnet_id": self.subnet_id,
            "room": self.room,
            "notes": self.notes,
            "pinned_classification": (
                self.pinned_classification.value
                if isinstance(self.pinned_classification, ValidationClassification)
                else self.pinned_classification
            ),
            "custom_attributes": dict(self.custom_attributes),
            "deleted": self.deleted,
            "updated_at": _format_optional_datetime(self.updated_at),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ItemEditPatch:
        if not isinstance(data, Mapping):
            raise ValueError("ItemEditPatch data must be a mapping")
        return cls(
            target_type=data["target_type"],
            target_id=data["target_id"],
            site_id=data.get("site_id"),
            name=data.get("name"),
            hostname=data.get("hostname"),
            category=data.get("category"),
            role=data.get("role"),
            vendor=data.get("vendor"),
            model=data.get("model"),
            vlan_id=data.get("vlan_id"),
            subnet_id=data.get("subnet_id"),
            room=data.get("room"),
            notes=data.get("notes"),
            pinned_classification=data.get("pinned_classification"),
            custom_attributes=dict(data.get("custom_attributes") or {}),
            deleted=bool(data.get("deleted", False)),
            updated_at=_normalize_optional_utc_datetime(
                data.get("updated_at"), "updated_at"
            ),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> ItemEditPatch:
        return cls.from_dict(json.loads(raw))


@dataclass(frozen=True)
class AuditLogEntry:
    """Immutable audit log record for an inventory curation mutation."""

    entry_id: str = field(default_factory=lambda: f"audit-{uuid.uuid4().hex[:12]}")
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str = "operator"
    action: str = ""
    target_type: str = ""
    target_id: str = ""
    changes: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    site_id: Optional[str] = None
    prev_hash: Optional[str] = None
    entry_hash: Optional[str] = None

    def __post_init__(self) -> None:
        resolved_entry_id = (
            f"audit-{uuid.uuid4().hex[:12]}"
            if self.entry_id is None
            else _require_non_empty_str(self.entry_id, "entry_id").strip()
        )
        object.__setattr__(self, "entry_id", resolved_entry_id)

        resolved_ts = (
            datetime.now(timezone.utc)
            if self.timestamp is None
            else normalize_utc_datetime(self.timestamp, field_name="timestamp")
        )
        object.__setattr__(self, "timestamp", resolved_ts)

        clean_actor = _require_non_empty_str(self.actor, "actor").strip()
        object.__setattr__(self, "actor", clean_actor)

        clean_action = _require_non_empty_str(self.action, "action").strip()
        object.__setattr__(self, "action", clean_action)

        raw_target_type = _require_non_empty_str(self.target_type, "target_type").strip()
        norm_target_type = (
            _AUDIT_LOG_TARGET_TYPE
            if raw_target_type.lower() == _AUDIT_LOG_TARGET_TYPE.lower()
            else _normalize_target_type(raw_target_type, "target_type")
        )
        object.__setattr__(self, "target_type", norm_target_type)

        clean_target_id = _require_non_empty_str(self.target_id, "target_id").strip()
        object.__setattr__(self, "target_id", clean_target_id)

        if self.changes is None:
            object.__setattr__(self, "changes", {})
        elif isinstance(self.changes, Mapping):
            object.__setattr__(self, "changes", dict(self.changes))
        else:
            raise ValueError("changes must be a mapping or None")

        if self.reason is None:
            object.__setattr__(self, "reason", "")
        elif isinstance(self.reason, str):
            object.__setattr__(self, "reason", self.reason)
        else:
            raise ValueError("reason must be a string")

        norm_site_id = _normalize_optional_str(self.site_id, "site_id")
        object.__setattr__(self, "site_id", norm_site_id)

        _normalize_optional_hash(self.prev_hash, "prev_hash")
        _normalize_optional_hash(self.entry_hash, "entry_hash")

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "timestamp": _format_optional_datetime(self.timestamp),
            "actor": self.actor,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "changes": dict(self.changes),
            "reason": self.reason,
            "site_id": self.site_id,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AuditLogEntry:
        if not isinstance(data, Mapping):
            raise ValueError("AuditLogEntry data must be a mapping")
        return cls(
            entry_id=data.get("entry_id") or f"audit-{uuid.uuid4().hex[:12]}",
            timestamp=normalize_utc_datetime(
                data["timestamp"], field_name="timestamp"
            )
            if "timestamp" in data and data["timestamp"] is not None
            else datetime.now(timezone.utc),
            actor=data.get("actor", "operator"),
            action=data["action"],
            target_type=data["target_type"],
            target_id=data["target_id"],
            changes=dict(data.get("changes") or {}),
            reason=data.get("reason") or "",
            site_id=data.get("site_id"),
            prev_hash=data.get("prev_hash"),
            entry_hash=data.get("entry_hash"),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> AuditLogEntry:
        return cls.from_dict(json.loads(raw))
