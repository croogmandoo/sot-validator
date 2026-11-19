"""Parity discrepancy, site readiness scorecard and MigrationParityReport models."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Optional

from sot_validator.migration._parity_records import (
    ALL_CUTOVER_RECOMMENDATIONS,
    ALL_PARITY_DISCREPANCY_TYPES,
    CutoverRecommendation,
    ParityDiscrepancyType,
    _clamp_percentage,
    _clean_optional_str,
)
from sot_validator.migration.exporter import _resolve_timestamp, slugify
from sot_validator.models import _format_optional_datetime, _require_non_empty_str


@dataclass
class ParityDiscrepancy:
    """Single dual-run parity discrepancy between Golden Inventory and Modern SoT."""

    discrepancy_id: str
    discrepancy_type: ParityDiscrepancyType
    site_id: str
    entity_type: str
    item_identifier: str
    attribute_name: Optional[str] = None
    expected_value: Optional[Any] = None
    actual_value: Optional[Any] = None
    waived: bool = False
    details: Optional[str] = None

    def __post_init__(self) -> None:
        self.discrepancy_id = _require_non_empty_str(
            self.discrepancy_id, "discrepancy_id"
        ).strip()
        if not isinstance(self.discrepancy_type, ParityDiscrepancyType):
            try:
                self.discrepancy_type = ParityDiscrepancyType(self.discrepancy_type)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid discrepancy_type: {self.discrepancy_type!r}"
                ) from exc
        self.site_id = _require_non_empty_str(self.site_id, "site_id").strip()
        self.entity_type = _require_non_empty_str(
            self.entity_type, "entity_type"
        ).strip()
        self.item_identifier = _require_non_empty_str(
            self.item_identifier, "item_identifier"
        ).strip()
        self.attribute_name = _clean_optional_str(self.attribute_name)
        self.waived = bool(self.waived)
        self.details = _clean_optional_str(self.details)

    def to_dict(self) -> dict[str, Any]:
        return {
            "discrepancy_id": self.discrepancy_id,
            "discrepancy_type": self.discrepancy_type.value,
            "site_id": self.site_id,
            "entity_type": self.entity_type,
            "item_identifier": self.item_identifier,
            "attribute_name": self.attribute_name,
            "expected_value": self.expected_value,
            "actual_value": self.actual_value,
            "waived": self.waived,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ParityDiscrepancy:
        return cls(
            discrepancy_id=data["discrepancy_id"],
            discrepancy_type=ParityDiscrepancyType(data["discrepancy_type"]),
            site_id=data["site_id"],
            entity_type=data["entity_type"],
            item_identifier=data["item_identifier"],
            attribute_name=data.get("attribute_name"),
            expected_value=data.get("expected_value"),
            actual_value=data.get("actual_value"),
            waived=bool(data.get("waived", False)),
            details=data.get("details"),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> ParityDiscrepancy:
        return cls.from_dict(json.loads(raw))


@dataclass
class SiteMigrationReadinessScorecard:
    """Per-site dual-run parity evaluation and migration readiness scorecard."""

    site_id: str
    site_name: str = ""
    readiness_score: float = 0.0
    recommendation: CutoverRecommendation = CutoverRecommendation.BLOCKED
    parity_match_percentage: float = 0.0
    confirmed_active_count: int = 0
    stale_count: int = 0
    unreachable_count: int = 0
    insufficient_data_count: int = 0
    unresolved_untracked_count: int = 0
    expected_golden_items: int = 0
    matched_modern_items: int = 0
    discrepancies: list[ParityDiscrepancy] = field(default_factory=list)
    waived_discrepancy_count: int = 0
    blocking_reasons: list[str] = field(default_factory=list)
    evaluated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        self.site_id = _require_non_empty_str(self.site_id, "site_id").strip()
        self.site_name = str(self.site_name or "").strip() or self.site_id
        self.readiness_score = _clamp_percentage(self.readiness_score)
        if not isinstance(self.recommendation, CutoverRecommendation):
            try:
                self.recommendation = CutoverRecommendation(self.recommendation)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid recommendation: {self.recommendation!r}"
                ) from exc
        self.parity_match_percentage = _clamp_percentage(self.parity_match_percentage)
        self.confirmed_active_count = max(0, int(self.confirmed_active_count))
        self.stale_count = max(0, int(self.stale_count))
        self.unreachable_count = max(0, int(self.unreachable_count))
        self.insufficient_data_count = max(0, int(self.insufficient_data_count))
        self.unresolved_untracked_count = max(0, int(self.unresolved_untracked_count))
        self.expected_golden_items = max(0, int(self.expected_golden_items))
        self.matched_modern_items = max(0, int(self.matched_modern_items))
        self.discrepancies = [
            d if isinstance(d, ParityDiscrepancy) else ParityDiscrepancy.from_dict(d)
            for d in (self.discrepancies or [])
        ]
        computed_waived = sum(1 for d in self.discrepancies if d.waived)
        self.waived_discrepancy_count = (
            computed_waived
            if self.waived_discrepancy_count == 0 and computed_waived > 0
            else max(0, int(self.waived_discrepancy_count))
        )
        self.blocking_reasons = [
            str(r).strip() for r in (self.blocking_reasons or []) if str(r).strip()
        ]
        self.evaluated_at = _resolve_timestamp(self.evaluated_at)

    @property
    def unwaived_discrepancies(self) -> list[ParityDiscrepancy]:
        return [d for d in self.discrepancies if not d.waived]

    @property
    def is_ready_for_cutover(self) -> bool:
        return self.recommendation is CutoverRecommendation.READY_FOR_CUTOVER

    @property
    def summary_by_discrepancy_type(self) -> dict[str, int]:
        counts: dict[str, int] = {
            dtype.value: 0 for dtype in ALL_PARITY_DISCREPANCY_TYPES
        }
        for disc in self.discrepancies:
            counts[disc.discrepancy_type.value] = (
                counts.get(disc.discrepancy_type.value, 0) + 1
            )
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "site_name": self.site_name,
            "readiness_score": self.readiness_score,
            "recommendation": self.recommendation.value,
            "is_ready_for_cutover": self.is_ready_for_cutover,
            "parity_match_percentage": self.parity_match_percentage,
            "confirmed_active_count": self.confirmed_active_count,
            "stale_count": self.stale_count,
            "unreachable_count": self.unreachable_count,
            "insufficient_data_count": self.insufficient_data_count,
            "unresolved_untracked_count": self.unresolved_untracked_count,
            "expected_golden_items": self.expected_golden_items,
            "matched_modern_items": self.matched_modern_items,
            "waived_discrepancy_count": self.waived_discrepancy_count,
            "unwaived_discrepancy_count": len(self.unwaived_discrepancies),
            "summary_by_discrepancy_type": self.summary_by_discrepancy_type,
            "blocking_reasons": list(self.blocking_reasons),
            "discrepancies": [d.to_dict() for d in self.discrepancies],
            "evaluated_at": _format_optional_datetime(self.evaluated_at),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SiteMigrationReadinessScorecard:
        return cls(
            site_id=data["site_id"],
            site_name=data.get("site_name", ""),
            readiness_score=float(data.get("readiness_score", 0.0)),
            recommendation=CutoverRecommendation(
                data.get("recommendation", CutoverRecommendation.BLOCKED.value)
            ),
            parity_match_percentage=float(data.get("parity_match_percentage", 0.0)),
            confirmed_active_count=int(data.get("confirmed_active_count", 0)),
            stale_count=int(data.get("stale_count", 0)),
            unreachable_count=int(data.get("unreachable_count", 0)),
            insufficient_data_count=int(data.get("insufficient_data_count", 0)),
            unresolved_untracked_count=int(data.get("unresolved_untracked_count", 0)),
            expected_golden_items=int(data.get("expected_golden_items", 0)),
            matched_modern_items=int(data.get("matched_modern_items", 0)),
            discrepancies=[
                d if isinstance(d, ParityDiscrepancy) else ParityDiscrepancy.from_dict(d)
                for d in data.get("discrepancies", [])
            ],
            waived_discrepancy_count=int(data.get("waived_discrepancy_count", 0)),
            blocking_reasons=list(data.get("blocking_reasons", [])),
            evaluated_at=_resolve_timestamp(data.get("evaluated_at")),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> SiteMigrationReadinessScorecard:
        return cls.from_dict(json.loads(raw))


@dataclass
class MigrationParityReport:
    """Multi-site migration readiness and dual-run parity report."""

    scorecards: list[SiteMigrationReadinessScorecard] = field(default_factory=list)
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __init__(
        self,
        scorecards: Optional[
            Sequence[SiteMigrationReadinessScorecard | Mapping[str, Any]]
        ] = None,
        generated_at: Optional[datetime | str] = None,
        *,
        evaluated_at: Optional[datetime | str] = None,
    ) -> None:
        resolved_ts = (
            generated_at if generated_at is not None else evaluated_at
        )
        self.generated_at = _resolve_timestamp(resolved_ts)
        self.scorecards = [
            s
            if isinstance(s, SiteMigrationReadinessScorecard)
            else SiteMigrationReadinessScorecard.from_dict(s)
            for s in (scorecards or [])
        ]

    @property
    def evaluated_at(self) -> datetime:
        return self.generated_at

    @property
    def total_sites(self) -> int:
        return len(self.scorecards)

    @property
    def ready_for_cutover_count(self) -> int:
        return sum(
            1
            for s in self.scorecards
            if s.recommendation is CutoverRecommendation.READY_FOR_CUTOVER
        )

    @property
    def needs_remediation_count(self) -> int:
        return sum(
            1
            for s in self.scorecards
            if s.recommendation is CutoverRecommendation.NEEDS_REMEDIATION
        )

    @property
    def blocked_count(self) -> int:
        return sum(
            1
            for s in self.scorecards
            if s.recommendation is CutoverRecommendation.BLOCKED
        )

    @property
    def average_readiness_score(self) -> float:
        if not self.scorecards:
            return 0.0
        return round(
            sum(s.readiness_score for s in self.scorecards) / len(self.scorecards),
            2,
        )

    @property
    def overall_readiness_score(self) -> float:
        return self.average_readiness_score

    @property
    def overall_recommendation(self) -> CutoverRecommendation:
        if not self.scorecards:
            return CutoverRecommendation.BLOCKED
        if self.blocked_count > 0:
            return CutoverRecommendation.BLOCKED
        if self.needs_remediation_count > 0:
            return CutoverRecommendation.NEEDS_REMEDIATION
        return CutoverRecommendation.READY_FOR_CUTOVER

    @property
    def overall_parity_percentage(self) -> float:
        if not self.scorecards:
            return 0.0
        return round(
            sum(s.parity_match_percentage for s in self.scorecards)
            / len(self.scorecards),
            2,
        )

    @property
    def discrepancies(self) -> list[ParityDiscrepancy]:
        return [d for s in self.scorecards for d in s.discrepancies]

    @property
    def total_discrepancies(self) -> int:
        return sum(len(s.discrepancies) for s in self.scorecards)

    @property
    def summary_by_type(self) -> dict[str, int]:
        counts: dict[str, int] = {
            dtype.value: 0 for dtype in ALL_PARITY_DISCREPANCY_TYPES
        }
        for scorecard in self.scorecards:
            for disc in scorecard.discrepancies:
                counts[disc.discrepancy_type.value] = (
                    counts.get(disc.discrepancy_type.value, 0) + 1
                )
        return counts

    @property
    def summary_by_recommendation(self) -> dict[str, int]:
        counts: dict[str, int] = {
            rec.value: 0 for rec in ALL_CUTOVER_RECOMMENDATIONS
        }
        for scorecard in self.scorecards:
            counts[scorecard.recommendation.value] = (
                counts.get(scorecard.recommendation.value, 0) + 1
            )
        return counts

    def get_scorecard(
        self, site_id: str
    ) -> Optional[SiteMigrationReadinessScorecard]:
        target_slug = slugify(site_id)
        for scorecard in self.scorecards:
            if scorecard.site_id == site_id or slugify(scorecard.site_id) == target_slug:
                return scorecard
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": _format_optional_datetime(self.generated_at),
            "total_sites": self.total_sites,
            "ready_for_cutover_count": self.ready_for_cutover_count,
            "needs_remediation_count": self.needs_remediation_count,
            "blocked_count": self.blocked_count,
            "average_readiness_score": self.average_readiness_score,
            "overall_parity_percentage": self.overall_parity_percentage,
            "total_discrepancies": self.total_discrepancies,
            "summary_by_type": self.summary_by_type,
            "summary_by_recommendation": self.summary_by_recommendation,
            "scorecards": [s.to_dict() for s in self.scorecards],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> MigrationParityReport:
        return cls(
            scorecards=[
                s
                if isinstance(s, SiteMigrationReadinessScorecard)
                else SiteMigrationReadinessScorecard.from_dict(s)
                for s in data.get("scorecards", [])
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
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return content

    @classmethod
    def from_json(cls, raw: str) -> MigrationParityReport:
        return cls.from_dict(json.loads(raw))
