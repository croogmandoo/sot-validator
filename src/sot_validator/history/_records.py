"""Ledger record dataclasses, drift transition types, and coercion helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import ipaddress
import json
from typing import TYPE_CHECKING, Any, ClassVar, Optional

from sot_validator.models import (
    Site,
    ValidationClassification,
    _format_optional_datetime,
    _require_non_empty_str,
)
from sot_validator.signals.base import normalize_utc_datetime

if TYPE_CHECKING:
    from sot_validator.history.ledger import HistoryStore

ALL_CLASSIFICATION_VALUES: tuple[str, ...] = (
    ValidationClassification.CONFIRMED_ACTIVE.value,
    ValidationClassification.STALE_LIKELY_UNUSED.value,
    ValidationClassification.UNREACHABLE_NEEDS_REVIEW.value,
    ValidationClassification.INSUFFICIENT_DATA.value,
)


class DriftTransitionType(str, Enum):
    """Classification transition types tracked across consecutive validation runs."""

    NEWLY_STALE = "NEWLY_STALE"
    NEWLY_UNREACHABLE = "NEWLY_UNREACHABLE"
    RESURRECTED = "RESURRECTED"
    RECOVERED = "RECOVERED"


_DRIFT_TRANSITION_MAP: dict[
    tuple[ValidationClassification, ValidationClassification], DriftTransitionType
] = {
    (
        ValidationClassification.CONFIRMED_ACTIVE,
        ValidationClassification.STALE_LIKELY_UNUSED,
    ): DriftTransitionType.NEWLY_STALE,
    (
        ValidationClassification.CONFIRMED_ACTIVE,
        ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
    ): DriftTransitionType.NEWLY_UNREACHABLE,
    (
        ValidationClassification.STALE_LIKELY_UNUSED,
        ValidationClassification.CONFIRMED_ACTIVE,
    ): DriftTransitionType.RESURRECTED,
    (
        ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
        ValidationClassification.CONFIRMED_ACTIVE,
    ): DriftTransitionType.RECOVERED,
}


def _normalize_optional_utc_datetime(
    value: Optional[datetime | str], field_name: str
) -> Optional[datetime]:
    if value is None:
        return None
    return normalize_utc_datetime(value, field_name=field_name)


def _require_non_negative_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value


def _require_confidence(value: Any, field_name: str = "confidence") -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be a number between 0.0 and 1.0")
    score = float(value)
    if not (0.0 <= score <= 1.0):
        raise ValueError(f"{field_name} must be between 0.0 and 1.0")
    return score


def _coerce_classification(
    value: ValidationClassification | str, field_name: str = "classification"
) -> ValidationClassification:
    if isinstance(value, ValidationClassification):
        return value
    try:
        return ValidationClassification(value)
    except ValueError as exc:
        raise ValueError(f"Invalid {field_name}: {value!r}") from exc


def _coerce_transition_type(
    value: DriftTransitionType | str, field_name: str = "transition_type"
) -> DriftTransitionType:
    if isinstance(value, DriftTransitionType):
        return value
    try:
        return DriftTransitionType(value)
    except ValueError as exc:
        raise ValueError(f"Invalid {field_name}: {value!r}") from exc


@dataclass
class ValidationRunRecord:
    """Metadata summary for a recorded validation run."""

    run_id: str
    recorded_at: datetime
    site_ids: list[str] = field(default_factory=list)
    total_items: int = 0
    classification_counts: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_non_empty_str(self.run_id, "run_id")
        self.recorded_at = normalize_utc_datetime(
            self.recorded_at, field_name="recorded_at"
        )
        if isinstance(self.site_ids, (str, bytes)) or not isinstance(
            self.site_ids, Sequence
        ):
            raise ValueError("site_ids must be a sequence of site ID strings")
        normalized_sites: set[str] = set()
        for raw_site in self.site_ids:
            _require_non_empty_str(raw_site, "site_id")
            normalized_sites.add(raw_site.strip())
        self.site_ids = sorted(normalized_sites)

        self.total_items = _require_non_negative_int(
            self.total_items, "total_items"
        )
        if not isinstance(self.classification_counts, Mapping):
            raise ValueError("classification_counts must be a mapping")

        normalized_counts: dict[str, int] = {
            cls_val: 0 for cls_val in ALL_CLASSIFICATION_VALUES
        }
        for raw_key, raw_count in self.classification_counts.items():
            cls_enum = _coerce_classification(raw_key, "classification_counts key")
            count_val = _require_non_negative_int(
                raw_count, f"classification_counts[{cls_enum.value!r}]"
            )
            normalized_counts[cls_enum.value] = count_val
        self.classification_counts = normalized_counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "recorded_at": _format_optional_datetime(self.recorded_at),
            "site_ids": list(self.site_ids),
            "total_items": self.total_items,
            "classification_counts": dict(self.classification_counts),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ValidationRunRecord:
        return cls(
            run_id=data["run_id"],
            recorded_at=normalize_utc_datetime(
                data["recorded_at"], field_name="recorded_at"
            ),
            site_ids=list(data.get("site_ids", [])),
            total_items=int(data.get("total_items", 0)),
            classification_counts=dict(data.get("classification_counts", {})),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> ValidationRunRecord:
        return cls.from_dict(json.loads(raw))


@dataclass
class ItemStreakSummary:
    """Per-item multi-run historical validation state and stale streak counters."""

    site_id: str
    item_type: str
    item_id: str
    name: str
    current_classification: ValidationClassification
    current_confidence: float
    consecutive_stale_runs: int
    total_runs_seen: int
    first_seen_at: datetime
    first_stale_at: Optional[datetime] = None
    last_confirmed_active_at: Optional[datetime] = None
    stale_duration_days: float = 0.0
    previous_classification: Optional[ValidationClassification] = None
    transition_type: Optional[DriftTransitionType] = None

    def __post_init__(self) -> None:
        _require_non_empty_str(self.site_id, "site_id")
        _require_non_empty_str(self.item_type, "item_type")
        _require_non_empty_str(self.item_id, "item_id")
        _require_non_empty_str(self.name, "name")
        self.current_classification = _coerce_classification(
            self.current_classification, "current_classification"
        )
        self.current_confidence = _require_confidence(
            self.current_confidence, "current_confidence"
        )
        self.consecutive_stale_runs = _require_non_negative_int(
            self.consecutive_stale_runs, "consecutive_stale_runs"
        )
        self.total_runs_seen = _require_non_negative_int(
            self.total_runs_seen, "total_runs_seen"
        )
        self.first_seen_at = normalize_utc_datetime(
            self.first_seen_at, field_name="first_seen_at"
        )
        self.first_stale_at = _normalize_optional_utc_datetime(
            self.first_stale_at, "first_stale_at"
        )
        self.last_confirmed_active_at = _normalize_optional_utc_datetime(
            self.last_confirmed_active_at, "last_confirmed_active_at"
        )
        if isinstance(self.stale_duration_days, bool) or not isinstance(
            self.stale_duration_days, (int, float)
        ):
            raise ValueError("stale_duration_days must be a non-negative number")
        self.stale_duration_days = float(self.stale_duration_days)
        if self.stale_duration_days < 0.0:
            raise ValueError("stale_duration_days must be non-negative")

        if self.previous_classification is not None:
            self.previous_classification = _coerce_classification(
                self.previous_classification, "previous_classification"
            )
        if self.transition_type is not None:
            self.transition_type = _coerce_transition_type(
                self.transition_type, "transition_type"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "item_type": self.item_type,
            "item_id": self.item_id,
            "name": self.name,
            "current_classification": self.current_classification.value,
            "current_confidence": self.current_confidence,
            "consecutive_stale_runs": self.consecutive_stale_runs,
            "total_runs_seen": self.total_runs_seen,
            "first_seen_at": _format_optional_datetime(self.first_seen_at),
            "first_stale_at": _format_optional_datetime(self.first_stale_at),
            "last_confirmed_active_at": _format_optional_datetime(
                self.last_confirmed_active_at
            ),
            "stale_duration_days": self.stale_duration_days,
            "previous_classification": (
                self.previous_classification.value
                if self.previous_classification is not None
                else None
            ),
            "transition_type": (
                self.transition_type.value
                if self.transition_type is not None
                else None
            ),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ItemStreakSummary:
        prev_cls = data.get("previous_classification")
        trans_type = data.get("transition_type")
        return cls(
            site_id=data["site_id"],
            item_type=data["item_type"],
            item_id=data["item_id"],
            name=data["name"],
            current_classification=_coerce_classification(
                data["current_classification"], "current_classification"
            ),
            current_confidence=data.get("current_confidence", 0.0),
            consecutive_stale_runs=int(data.get("consecutive_stale_runs", 0)),
            total_runs_seen=int(data.get("total_runs_seen", 0)),
            first_seen_at=normalize_utc_datetime(
                data["first_seen_at"], field_name="first_seen_at"
            ),
            first_stale_at=_normalize_optional_utc_datetime(
                data.get("first_stale_at"), "first_stale_at"
            ),
            last_confirmed_active_at=_normalize_optional_utc_datetime(
                data.get("last_confirmed_active_at"), "last_confirmed_active_at"
            ),
            stale_duration_days=float(data.get("stale_duration_days", 0.0)),
            previous_classification=(
                _coerce_classification(prev_cls, "previous_classification")
                if prev_cls is not None
                else None
            ),
            transition_type=(
                _coerce_transition_type(trans_type, "transition_type")
                if trans_type is not None
                else None
            ),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> ItemStreakSummary:
        return cls.from_dict(json.loads(raw))


@dataclass
class DriftEvent:
    """Classification transition event observed for an item between consecutive runs."""

    NEWLY_STALE: ClassVar[DriftTransitionType] = DriftTransitionType.NEWLY_STALE
    NEWLY_UNREACHABLE: ClassVar[DriftTransitionType] = (
        DriftTransitionType.NEWLY_UNREACHABLE
    )
    RESURRECTED: ClassVar[DriftTransitionType] = DriftTransitionType.RESURRECTED
    RECOVERED: ClassVar[DriftTransitionType] = DriftTransitionType.RECOVERED

    run_id: str
    recorded_at: datetime
    site_id: str
    item_type: str
    item_id: str
    name: str
    previous_classification: ValidationClassification
    new_classification: ValidationClassification
    transition_type: DriftTransitionType
    confidence: float = 0.0

    def __post_init__(self) -> None:
        _require_non_empty_str(self.run_id, "run_id")
        self.recorded_at = normalize_utc_datetime(
            self.recorded_at, field_name="recorded_at"
        )
        _require_non_empty_str(self.site_id, "site_id")
        _require_non_empty_str(self.item_type, "item_type")
        _require_non_empty_str(self.item_id, "item_id")
        _require_non_empty_str(self.name, "name")
        self.previous_classification = _coerce_classification(
            self.previous_classification, "previous_classification"
        )
        self.new_classification = _coerce_classification(
            self.new_classification, "new_classification"
        )
        self.transition_type = _coerce_transition_type(
            self.transition_type, "transition_type"
        )
        self.confidence = _require_confidence(self.confidence, "confidence")

    @property
    def current_classification(self) -> ValidationClassification:
        """Alias for new_classification."""
        return self.new_classification

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "recorded_at": _format_optional_datetime(self.recorded_at),
            "site_id": self.site_id,
            "item_type": self.item_type,
            "item_id": self.item_id,
            "name": self.name,
            "previous_classification": self.previous_classification.value,
            "new_classification": self.new_classification.value,
            "transition_type": self.transition_type.value,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DriftEvent:
        raw_new_cls = (
            data["new_classification"]
            if "new_classification" in data
            else data["current_classification"]
        )
        return cls(
            run_id=data["run_id"],
            recorded_at=normalize_utc_datetime(
                data["recorded_at"], field_name="recorded_at"
            ),
            site_id=data["site_id"],
            item_type=data["item_type"],
            item_id=data["item_id"],
            name=data["name"],
            previous_classification=_coerce_classification(
                data["previous_classification"], "previous_classification"
            ),
            new_classification=_coerce_classification(
                raw_new_cls, "new_classification"
            ),
            transition_type=_coerce_transition_type(
                data["transition_type"], "transition_type"
            ),
            confidence=data.get("confidence", 0.0),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> DriftEvent:
        return cls.from_dict(json.loads(raw))


@dataclass
class SubnetUtilizationSummary:
    """Per-site /24 subnet IP assignment, active usage, and stale reclaimable summary."""

    subnet_id: str
    cidr: str
    total_assigned_ips: int
    confirmed_active_ips: int
    stale_reclaimable_ips: int
    active_utilization_pct: float
    site_id: Optional[str] = None

    def __post_init__(self) -> None:
        _require_non_empty_str(self.subnet_id, "subnet_id")
        _require_non_empty_str(self.cidr, "cidr")
        self.total_assigned_ips = _require_non_negative_int(
            self.total_assigned_ips, "total_assigned_ips"
        )
        self.confirmed_active_ips = _require_non_negative_int(
            self.confirmed_active_ips, "confirmed_active_ips"
        )
        self.stale_reclaimable_ips = _require_non_negative_int(
            self.stale_reclaimable_ips, "stale_reclaimable_ips"
        )
        if isinstance(self.active_utilization_pct, bool) or not isinstance(
            self.active_utilization_pct, (int, float)
        ):
            raise ValueError(
                "active_utilization_pct must be a number between 0.0 and 100.0"
            )
        self.active_utilization_pct = float(self.active_utilization_pct)
        if not (0.0 <= self.active_utilization_pct <= 100.0):
            raise ValueError(
                "active_utilization_pct must be between 0.0 and 100.0"
            )
        if self.site_id is not None:
            _require_non_empty_str(self.site_id, "site_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "subnet_id": self.subnet_id,
            "site_id": self.site_id,
            "cidr": self.cidr,
            "total_assigned_ips": self.total_assigned_ips,
            "confirmed_active_ips": self.confirmed_active_ips,
            "stale_reclaimable_ips": self.stale_reclaimable_ips,
            "active_utilization_pct": self.active_utilization_pct,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SubnetUtilizationSummary:
        return cls(
            subnet_id=data["subnet_id"],
            cidr=data["cidr"],
            total_assigned_ips=int(data["total_assigned_ips"]),
            confirmed_active_ips=int(data["confirmed_active_ips"]),
            stale_reclaimable_ips=int(data["stale_reclaimable_ips"]),
            active_utilization_pct=float(data["active_utilization_pct"]),
            site_id=data.get("site_id"),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> SubnetUtilizationSummary:
        return cls.from_dict(json.loads(raw))


class _HybridImportMethod:
    """Descriptor allowing import_json to be invoked on either HistoryStore class or instance."""

    def __init__(self, func: Any) -> None:
        self._func = func

    def __get__(self, instance: Any, owner: Any = None) -> Any:
        target = owner if instance is None else instance

        def _bound(*args: Any, **kwargs: Any) -> HistoryStore:
            return self._func(target, *args, **kwargs)

        return _bound


def _coerce_sites(
    sites: Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]
) -> list[Site]:
    if isinstance(sites, Site):
        return [sites]
    if isinstance(sites, Mapping):
        if "site_id" in sites and "name" in sites:
            return [Site.from_dict(sites)]
        return [
            v if isinstance(v, Site) else Site.from_dict(v)
            for v in sites.values()
        ]
    return [s if isinstance(s, Site) else Site.from_dict(s) for s in sites]


def _try_parse_ipv4(ip_str: Optional[str]) -> Optional[ipaddress.IPv4Address]:
    if not ip_str or not isinstance(ip_str, str) or not ip_str.strip():
        return None
    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return None
    return addr if isinstance(addr, ipaddress.IPv4Address) else None


def _try_parse_slash24_ipv4(
    cidr_str: Optional[str],
) -> Optional[ipaddress.IPv4Network]:
    if not cidr_str or not isinstance(cidr_str, str) or not cidr_str.strip():
        return None
    try:
        net = ipaddress.ip_network(cidr_str.strip(), strict=False)
    except ValueError:
        return None
    if isinstance(net, ipaddress.IPv4Network) and net.prefixlen == 24:
        return net
    return None
