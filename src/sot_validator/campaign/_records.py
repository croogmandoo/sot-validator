"""Campaign configuration, per-site wave results, run summary and circuit-breaker error."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
from typing import Any, Optional

from sot_validator.campaign.alerts import AlertEvent
from sot_validator.models import ValidationResult, _require_non_empty_str
from sot_validator.signals.base import normalize_utc_datetime

DEFAULT_CRITICAL_CATEGORIES: tuple[str, ...] = ("ups", "network_device", "san")


@dataclass
class CampaignConfig:
    """Configuration for rolling multi-site validation waves and outage circuit breakers."""

    cohort_size: int = 5
    max_unreachable_ratio_per_site: float = 0.50
    max_consecutive_aborted_sites: int = 2
    critical_categories: tuple[str, ...] = DEFAULT_CRITICAL_CATEGORIES
    high_stale_ratio_threshold: float = 0.40
    raise_on_circuit_breaker: bool = False
    include_ip_addresses: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.cohort_size, bool) or not isinstance(
            self.cohort_size, int
        ):
            raise ValueError("cohort_size must be an integer >= 1")
        if self.cohort_size < 1:
            raise ValueError("cohort_size must be >= 1")

        if isinstance(
            self.max_unreachable_ratio_per_site, bool
        ) or not isinstance(self.max_unreachable_ratio_per_site, (int, float)):
            raise ValueError(
                "max_unreachable_ratio_per_site must be a number in (0.0, 1.0]"
            )
        self.max_unreachable_ratio_per_site = float(
            self.max_unreachable_ratio_per_site
        )
        if not (0.0 < self.max_unreachable_ratio_per_site <= 1.0):
            raise ValueError(
                "max_unreachable_ratio_per_site must be in (0.0, 1.0]"
            )

        if isinstance(
            self.max_consecutive_aborted_sites, bool
        ) or not isinstance(self.max_consecutive_aborted_sites, int):
            raise ValueError(
                "max_consecutive_aborted_sites must be an integer >= 1"
            )
        if self.max_consecutive_aborted_sites < 1:
            raise ValueError("max_consecutive_aborted_sites must be >= 1")

        if isinstance(self.critical_categories, (str, bytes)) or not isinstance(
            self.critical_categories, Sequence
        ):
            raise ValueError(
                "critical_categories must be a sequence of category strings"
            )
        normalized_cats: list[str] = []
        for raw_cat in self.critical_categories:
            cat_str = _require_non_empty_str(
                raw_cat, "critical_categories item"
            ).strip().lower()
            if cat_str not in normalized_cats:
                normalized_cats.append(cat_str)
        self.critical_categories = tuple(normalized_cats)

        if isinstance(self.high_stale_ratio_threshold, bool) or not isinstance(
            self.high_stale_ratio_threshold, (int, float)
        ):
            raise ValueError(
                "high_stale_ratio_threshold must be a number in (0.0, 1.0]"
            )
        self.high_stale_ratio_threshold = float(self.high_stale_ratio_threshold)
        if not (0.0 < self.high_stale_ratio_threshold <= 1.0):
            raise ValueError(
                "high_stale_ratio_threshold must be in (0.0, 1.0]"
            )

        if not isinstance(self.raise_on_circuit_breaker, bool):
            raise ValueError("raise_on_circuit_breaker must be a boolean")
        if not isinstance(self.include_ip_addresses, bool):
            raise ValueError("include_ip_addresses must be a boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "cohort_size": self.cohort_size,
            "max_unreachable_ratio_per_site": self.max_unreachable_ratio_per_site,
            "max_consecutive_aborted_sites": self.max_consecutive_aborted_sites,
            "critical_categories": list(self.critical_categories),
            "high_stale_ratio_threshold": self.high_stale_ratio_threshold,
            "raise_on_circuit_breaker": self.raise_on_circuit_breaker,
            "include_ip_addresses": self.include_ip_addresses,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CampaignConfig:
        raw_cats = data.get("critical_categories", DEFAULT_CRITICAL_CATEGORIES)
        return cls(
            cohort_size=data.get("cohort_size", 5),
            max_unreachable_ratio_per_site=data.get(
                "max_unreachable_ratio_per_site", 0.50
            ),
            max_consecutive_aborted_sites=data.get(
                "max_consecutive_aborted_sites", 2
            ),
            critical_categories=tuple(raw_cats),
            high_stale_ratio_threshold=data.get(
                "high_stale_ratio_threshold", 0.40
            ),
            raise_on_circuit_breaker=data.get(
                "raise_on_circuit_breaker", False
            ),
            include_ip_addresses=data.get("include_ip_addresses", True),
        )


class SiteWaveStatus(str, Enum):
    """Execution outcome status for a site within a campaign wave."""

    COMMITTED = "COMMITTED"
    QUARANTINED_OUTAGE_SUSPECTED = "QUARANTINED_OUTAGE_SUSPECTED"
    SKIPPED_CIRCUIT_BREAKER = "SKIPPED_CIRCUIT_BREAKER"


@dataclass
class SiteWaveResult:
    """Per-site wave evaluation outcome, outage quarantine status, and emitted alerts."""

    site_id: str
    site_name: str
    wave_index: int
    status: SiteWaveStatus
    total_items: int
    confirmed_active_count: int
    stale_count: int
    unreachable_count: int
    insufficient_data_count: int
    unreachable_ratio: float
    stale_ratio: float
    quarantined: bool
    eligible_for_streak_tracking: bool
    results: list[ValidationResult] = field(default_factory=list)
    committed_results: list[ValidationResult] = field(default_factory=list)
    alerts: list[AlertEvent] = field(default_factory=list)
    evaluated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        _require_non_empty_str(self.site_id, "site_id")
        _require_non_empty_str(self.site_name, "site_name")
        if isinstance(self.wave_index, bool) or not isinstance(
            self.wave_index, int
        ) or self.wave_index < 0:
            raise ValueError("wave_index must be a non-negative integer")
        if not isinstance(self.status, SiteWaveStatus):
            try:
                self.status = SiteWaveStatus(self.status)
            except ValueError as exc:
                raise ValueError(f"Invalid status: {self.status!r}") from exc

        self.results = [
            r if isinstance(r, ValidationResult) else ValidationResult.from_dict(r)
            for r in self.results
        ]
        self.committed_results = [
            r if isinstance(r, ValidationResult) else ValidationResult.from_dict(r)
            for r in self.committed_results
        ]
        self.alerts = [
            a if isinstance(a, AlertEvent) else AlertEvent.from_dict(a)
            for a in self.alerts
        ]
        self.evaluated_at = normalize_utc_datetime(
            self.evaluated_at, field_name="evaluated_at"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "site_name": self.site_name,
            "wave_index": self.wave_index,
            "status": self.status.value,
            "total_items": self.total_items,
            "confirmed_active_count": self.confirmed_active_count,
            "stale_count": self.stale_count,
            "unreachable_count": self.unreachable_count,
            "insufficient_data_count": self.insufficient_data_count,
            "unreachable_ratio": self.unreachable_ratio,
            "stale_ratio": self.stale_ratio,
            "quarantined": self.quarantined,
            "eligible_for_streak_tracking": self.eligible_for_streak_tracking,
            "results": [r.to_dict() for r in self.results],
            "committed_results": [r.to_dict() for r in self.committed_results],
            "alerts": [a.to_dict() for a in self.alerts],
            "evaluated_at": self.evaluated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SiteWaveResult:
        return cls(
            site_id=data["site_id"],
            site_name=data["site_name"],
            wave_index=int(data["wave_index"]),
            status=SiteWaveStatus(data["status"]),
            total_items=int(data["total_items"]),
            confirmed_active_count=int(data["confirmed_active_count"]),
            stale_count=int(data["stale_count"]),
            unreachable_count=int(data["unreachable_count"]),
            insufficient_data_count=int(data["insufficient_data_count"]),
            unreachable_ratio=float(data["unreachable_ratio"]),
            stale_ratio=float(data["stale_ratio"]),
            quarantined=bool(data["quarantined"]),
            eligible_for_streak_tracking=bool(
                data["eligible_for_streak_tracking"]
            ),
            results=[
                r
                if isinstance(r, ValidationResult)
                else ValidationResult.from_dict(r)
                for r in data.get("results", [])
            ],
            committed_results=[
                r
                if isinstance(r, ValidationResult)
                else ValidationResult.from_dict(r)
                for r in data.get("committed_results", [])
            ],
            alerts=[
                a if isinstance(a, AlertEvent) else AlertEvent.from_dict(a)
                for a in data.get("alerts", [])
            ],
            evaluated_at=data.get("evaluated_at") or datetime.now(timezone.utc),
        )


@dataclass
class CampaignRunSummary:
    """Aggregated summary of a multi-site validation campaign run."""

    campaign_id: str
    config: CampaignConfig
    started_at: datetime
    completed_at: datetime
    total_sites_scheduled: int
    total_sites_evaluated: int
    total_waves_executed: int
    committed_site_ids: list[str] = field(default_factory=list)
    quarantined_site_ids: list[str] = field(default_factory=list)
    skipped_site_ids: list[str] = field(default_factory=list)
    circuit_breaker_tripped: bool = False
    consecutive_aborted_sites: int = 0
    site_results: list[SiteWaveResult] = field(default_factory=list)
    committed_validation_results: list[ValidationResult] = field(
        default_factory=list
    )
    alerts: list[AlertEvent] = field(default_factory=list)

    def __post_init__(self) -> None:
        _require_non_empty_str(self.campaign_id, "campaign_id")
        if not isinstance(self.config, CampaignConfig):
            self.config = CampaignConfig.from_dict(self.config)
        self.started_at = normalize_utc_datetime(
            self.started_at, field_name="started_at"
        )
        self.completed_at = normalize_utc_datetime(
            self.completed_at, field_name="completed_at"
        )
        self.committed_site_ids = list(self.committed_site_ids)
        self.quarantined_site_ids = list(self.quarantined_site_ids)
        self.skipped_site_ids = list(self.skipped_site_ids)
        self.site_results = [
            sr
            if isinstance(sr, SiteWaveResult)
            else SiteWaveResult.from_dict(sr)
            for sr in self.site_results
        ]
        self.committed_validation_results = [
            vr
            if isinstance(vr, ValidationResult)
            else ValidationResult.from_dict(vr)
            for vr in self.committed_validation_results
        ]
        self.alerts = [
            a if isinstance(a, AlertEvent) else AlertEvent.from_dict(a)
            for a in self.alerts
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "config": self.config.to_dict(),
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "total_sites_scheduled": self.total_sites_scheduled,
            "total_sites_evaluated": self.total_sites_evaluated,
            "total_waves_executed": self.total_waves_executed,
            "committed_site_ids": list(self.committed_site_ids),
            "quarantined_site_ids": list(self.quarantined_site_ids),
            "skipped_site_ids": list(self.skipped_site_ids),
            "circuit_breaker_tripped": self.circuit_breaker_tripped,
            "consecutive_aborted_sites": self.consecutive_aborted_sites,
            "site_results": [sr.to_dict() for sr in self.site_results],
            "committed_validation_results": [
                vr.to_dict() for vr in self.committed_validation_results
            ],
            "alerts": [a.to_dict() for a in self.alerts],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CampaignRunSummary:
        raw_cfg = data["config"]
        cfg = (
            raw_cfg
            if isinstance(raw_cfg, CampaignConfig)
            else CampaignConfig.from_dict(raw_cfg)
        )
        return cls(
            campaign_id=data["campaign_id"],
            config=cfg,
            started_at=data["started_at"],
            completed_at=data["completed_at"],
            total_sites_scheduled=int(data["total_sites_scheduled"]),
            total_sites_evaluated=int(data["total_sites_evaluated"]),
            total_waves_executed=int(data["total_waves_executed"]),
            committed_site_ids=list(data.get("committed_site_ids", [])),
            quarantined_site_ids=list(data.get("quarantined_site_ids", [])),
            skipped_site_ids=list(data.get("skipped_site_ids", [])),
            circuit_breaker_tripped=bool(
                data.get("circuit_breaker_tripped", False)
            ),
            consecutive_aborted_sites=int(
                data.get("consecutive_aborted_sites", 0)
            ),
            site_results=[
                sr
                if isinstance(sr, SiteWaveResult)
                else SiteWaveResult.from_dict(sr)
                for sr in data.get("site_results", [])
            ],
            committed_validation_results=[
                vr
                if isinstance(vr, ValidationResult)
                else ValidationResult.from_dict(vr)
                for vr in data.get("committed_validation_results", [])
            ],
            alerts=[
                a if isinstance(a, AlertEvent) else AlertEvent.from_dict(a)
                for a in data.get("alerts", [])
            ],
        )

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> CampaignRunSummary:
        return cls.from_dict(json.loads(raw))


class CircuitBreakerTrippedError(RuntimeError):
    """Raised when consecutive site outages exceed max_consecutive_aborted_sites."""

    def __init__(
        self,
        message: str,
        *,
        consecutive_aborted_sites: int,
        aborted_site_ids: Sequence[str],
        wave_index: int,
        summary: Optional[CampaignRunSummary] = None,
    ) -> None:
        super().__init__(message)
        self.consecutive_aborted_sites = int(consecutive_aborted_sites)
        self.aborted_site_ids = list(aborted_site_ids)
        self.wave_index = int(wave_index)
        self.summary = summary
