"""Fleet health scoring: constants, input validators, ``FleetScoreWeights``, ``SiteScorecard`` and ``FleetScorer``."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, fields
import math
from typing import TYPE_CHECKING, Any, Optional

from sot_validator.models import ValidationClassification

if TYPE_CHECKING:
    from sot_validator.history.ledger import DriftEvent
    from sot_validator.lifecycle.certificates import CertificateFinding
    from sot_validator.lifecycle.firmware import FirmwareFinding
    from sot_validator.models import ValidationResult
    from sot_validator.quality.checks import QualityFinding

FLEET_DIMENSIONS: tuple[str, ...] = (
    "records",
    "quality",
    "certificates",
    "firmware",
    "drift",
)

TREND_IMPROVING = "improving"
TREND_STABLE = "stable"
TREND_DEGRADING = "degrading"
TREND_NEW = "new"
TREND_VALUES: tuple[str, ...] = (
    TREND_IMPROVING,
    TREND_STABLE,
    TREND_DEGRADING,
    TREND_NEW,
)
TREND_STABLE_THRESHOLD = 5.0

CERT_SEVERITIES: tuple[str, ...] = ("error", "warning", "info")
# Equals sot_validator.lifecycle.firmware.STATUS_COMPLIANT (not imported: import cycle).
_FIRMWARE_COMPLIANT = "compliant"

_RECORD_KEYS: tuple[str, ...] = tuple(c.value for c in ValidationClassification)
_STALE = ValidationClassification.STALE_LIKELY_UNUSED.value
_UNREACHABLE = ValidationClassification.UNREACHABLE_NEEDS_REVIEW.value
_INSUFFICIENT = ValidationClassification.INSUFFICIENT_DATA.value

NO_DATA = "no data"
DEFAULT_FLEET_TITLE = "Fleet Site Health Scorecard"
TOP_N = 10


def _require_count(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be a non-negative integer, got {value!r}")
    if value < 0:
        raise ValueError(f"{name} must be a non-negative integer, got {value!r}")
    return value


def _require_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number, got {value!r}")
    if math.isnan(value) or math.isinf(value):
        raise ValueError(f"{name} must be finite, got {value!r}")
    return value


def _clamp(value: float) -> float:
    return max(0.0, min(100.0, value))


@dataclass
class FleetScoreWeights:
    """Dimension weights and per-dimension penalties for the fleet health score."""

    records: float = 0.40
    quality: float = 0.20
    certificates: float = 0.15
    firmware: float = 0.15
    drift: float = 0.10
    stale_penalty: float = 1.0
    unreachable_penalty: float = 0.5
    insufficient_penalty: float = 0.25
    quality_error_penalty: float = 1.0
    quality_warning_penalty: float = 0.25
    cert_error_points: float = 25.0
    cert_warning_points: float = 10.0
    cert_info_points: float = 2.0
    drift_penalty: float = 1.0

    def __post_init__(self) -> None:
        for f in fields(self):
            value = _require_number(getattr(self, f.name), f.name)
            if value < 0:
                raise ValueError(f"{f.name} must not be negative, got {value!r}")
        if all(getattr(self, dim) == 0 for dim in FLEET_DIMENSIONS):
            raise ValueError("at least one dimension weight must be greater than 0")

    def weight(self, dimension: str) -> float:
        return getattr(self, dimension)


@dataclass
class SiteScorecard:
    """Health score, per-dimension counts and trend for one site."""

    site_id: str
    record_counts: dict[str, int] = field(
        default_factory=lambda: {key: 0 for key in _RECORD_KEYS}
    )
    quality_errors: int = 0
    quality_warnings: int = 0
    cert_findings: dict[str, int] = field(
        default_factory=lambda: {key: 0 for key in CERT_SEVERITIES}
    )
    firmware_noncompliant: int = 0
    firmware_devices: int = 0
    drift_events: int = 0
    inputs_present: list[str] = field(default_factory=list)
    dimension_scores: dict[str, float] = field(default_factory=dict)
    health_score: Optional[float] = None
    previous_score: Optional[float] = None
    trend: str = TREND_NEW

    def has(self, dimension: str) -> bool:
        return dimension in self.inputs_present

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "record_counts": dict(self.record_counts),
            "quality_errors": self.quality_errors,
            "quality_warnings": self.quality_warnings,
            "cert_findings": dict(self.cert_findings),
            "firmware_noncompliant": self.firmware_noncompliant,
            "firmware_devices": self.firmware_devices,
            "drift_events": self.drift_events,
            "inputs_present": list(self.inputs_present),
            "dimension_scores": dict(self.dimension_scores),
            "health_score": self.health_score,
            "previous_score": self.previous_score,
            "trend": self.trend,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SiteScorecard:
        trend = data.get("trend", TREND_NEW)
        if trend not in TREND_VALUES:
            raise ValueError(f"trend must be one of {TREND_VALUES}, got {trend!r}")
        health = data.get("health_score")
        if health is not None:
            _require_number(health, "health_score")
            if not 0 <= health <= 100:
                raise ValueError(f"health_score must be between 0 and 100, got {health!r}")
        record_counts = {key: 0 for key in _RECORD_KEYS}
        record_counts.update(data.get("record_counts") or {})
        cert_findings = {key: 0 for key in CERT_SEVERITIES}
        cert_findings.update(data.get("cert_findings") or {})
        return cls(
            site_id=data["site_id"],
            record_counts=record_counts,
            quality_errors=data.get("quality_errors", 0),
            quality_warnings=data.get("quality_warnings", 0),
            cert_findings=cert_findings,
            firmware_noncompliant=data.get("firmware_noncompliant", 0),
            firmware_devices=data.get("firmware_devices", 0),
            drift_events=data.get("drift_events", 0),
            inputs_present=list(data.get("inputs_present") or []),
            dimension_scores=dict(data.get("dimension_scores") or {}),
            health_score=health,
            previous_score=data.get("previous_score"),
            trend=trend,
        )


def _trend(health_score: Optional[float], previous_score: Optional[float]) -> str:
    if health_score is None or previous_score is None:
        return TREND_NEW
    delta = round(health_score - previous_score, 1)
    if abs(delta) <= TREND_STABLE_THRESHOLD:
        return TREND_STABLE
    return TREND_IMPROVING if delta > 0 else TREND_DEGRADING


class FleetScorer:
    """Score sites from plain counts (`score_site`) or typed findings (`score_fleet`)."""

    def __init__(self, weights: Optional[FleetScoreWeights] = None) -> None:
        self.weights = weights if weights is not None else FleetScoreWeights()

    def score_site(
        self,
        site_id: str,
        *,
        record_counts: Optional[Mapping[Any, int]] = None,
        quality_errors: Optional[int] = None,
        quality_warnings: Optional[int] = None,
        cert_findings: Optional[Mapping[str, int]] = None,
        firmware_devices: Optional[int] = None,
        firmware_noncompliant: Optional[int] = None,
        drift_events: Optional[int] = None,
        previous_score: Optional[float] = None,
    ) -> SiteScorecard:
        if not isinstance(site_id, str) or not site_id:
            raise ValueError(f"site_id must be a non-empty string, got {site_id!r}")
        if previous_score is not None:
            _require_number(previous_score, "previous_score")
        w = self.weights
        card = SiteScorecard(site_id=site_id, previous_score=previous_score)
        present: list[str] = []
        subs: dict[str, float] = {}

        total_records = 0
        if record_counts is not None:
            if not isinstance(record_counts, Mapping):
                raise ValueError("record_counts must be a mapping")
            for key, value in record_counts.items():
                try:
                    cls_value = ValidationClassification(key).value
                except ValueError as exc:
                    raise ValueError(f"unknown record classification: {key!r}") from exc
                card.record_counts[cls_value] += _require_count(
                    value, f"record_counts[{cls_value!r}]"
                )
            total_records = sum(card.record_counts.values())
            if total_records == 0:
                subs["records"] = 100.0
            else:
                penalty = (
                    card.record_counts[_STALE] * w.stale_penalty
                    + card.record_counts[_UNREACHABLE] * w.unreachable_penalty
                    + card.record_counts[_INSUFFICIENT] * w.insufficient_penalty
                )
                subs["records"] = 100.0 * (1 - penalty / total_records)
            present.append("records")
        denominator = total_records if total_records > 0 else 1

        if quality_errors is not None or quality_warnings is not None:
            card.quality_errors = _require_count(
                0 if quality_errors is None else quality_errors, "quality_errors"
            )
            card.quality_warnings = _require_count(
                0 if quality_warnings is None else quality_warnings, "quality_warnings"
            )
            penalty = (
                card.quality_errors * w.quality_error_penalty
                + card.quality_warnings * w.quality_warning_penalty
            )
            subs["quality"] = 100.0 * (1 - penalty / denominator)
            present.append("quality")

        if cert_findings is not None:
            if not isinstance(cert_findings, Mapping):
                raise ValueError("cert_findings must be a mapping")
            for key, value in cert_findings.items():
                if key not in CERT_SEVERITIES:
                    raise ValueError(f"unknown certificate severity: {key!r}")
                card.cert_findings[key] += _require_count(value, f"cert_findings[{key!r}]")
            subs["certificates"] = 100.0 - (
                card.cert_findings["error"] * w.cert_error_points
                + card.cert_findings["warning"] * w.cert_warning_points
                + card.cert_findings["info"] * w.cert_info_points
            )
            present.append("certificates")

        if (firmware_devices is None) != (firmware_noncompliant is None):
            raise ValueError(
                "firmware_devices and firmware_noncompliant must be given together"
            )
        if firmware_devices is not None:
            card.firmware_devices = _require_count(firmware_devices, "firmware_devices")
            card.firmware_noncompliant = _require_count(
                firmware_noncompliant, "firmware_noncompliant"
            )
            if card.firmware_noncompliant > card.firmware_devices:
                raise ValueError("firmware_noncompliant must not exceed firmware_devices")
            if card.firmware_devices == 0:
                subs["firmware"] = 100.0
            else:
                subs["firmware"] = 100.0 * (
                    1 - card.firmware_noncompliant / card.firmware_devices
                )
            present.append("firmware")

        if drift_events is not None:
            card.drift_events = _require_count(drift_events, "drift_events")
            subs["drift"] = 100.0 * (1 - card.drift_events * w.drift_penalty / denominator)
            present.append("drift")

        subs = {dim: _clamp(value) for dim, value in subs.items()}
        card.inputs_present = present
        card.dimension_scores = {dim: round(subs[dim], 1) for dim in present}
        weight_total = sum(w.weight(dim) for dim in present)
        if present and weight_total > 0:
            weighted = sum(w.weight(dim) * subs[dim] for dim in present)
            card.health_score = round(_clamp(weighted / weight_total), 1)
        card.trend = _trend(card.health_score, previous_score)
        return card

    def score_fleet(
        self,
        *,
        results: Optional[Iterable[ValidationResult]] = None,
        quality_findings: Optional[Iterable[QualityFinding]] = None,
        certificate_findings: Optional[Iterable[CertificateFinding]] = None,
        firmware_findings: Optional[Iterable[FirmwareFinding]] = None,
        drift_events: Optional[Iterable[DriftEvent]] = None,
        previous: Optional[Mapping[str, Optional[float]] | Iterable[SiteScorecard]] = None,
        site_ids: Optional[Iterable[str]] = None,
    ) -> list[SiteScorecard]:
        """Score every site seen in `site_ids` or any finding input (not `previous`)."""
        sites: set[str] = set(site_ids or ())
        records: dict[str, dict[str, int]] = {}
        quality: dict[str, list[int]] = {}
        certs: dict[str, dict[str, int]] = {}
        firmware: dict[str, list[int]] = {}
        drift: dict[str, int] = {}

        if results is not None:
            for result in results:
                counts = records.setdefault(result.site_id, {})
                key = ValidationClassification(result.classification).value
                counts[key] = counts.get(key, 0) + 1
        if quality_findings is not None:
            for finding in quality_findings:
                pair = quality.setdefault(finding.site_id, [0, 0])
                if finding.severity == "error":
                    pair[0] += 1
                elif finding.severity == "warning":
                    pair[1] += 1
        if certificate_findings is not None:
            for finding in certificate_findings:
                counts = certs.setdefault(finding.site_id, {})
                counts[finding.severity] = counts.get(finding.severity, 0) + 1
        if firmware_findings is not None:
            for finding in firmware_findings:
                pair = firmware.setdefault(finding.site_id, [0, 0])
                pair[0] += 1
                if finding.status != _FIRMWARE_COMPLIANT:
                    pair[1] += 1
        if drift_events is not None:
            for event in drift_events:
                drift[event.site_id] = drift.get(event.site_id, 0) + 1

        for mapping in (records, quality, certs, firmware, drift):
            sites.update(mapping)

        previous_scores: dict[str, Optional[float]] = {}
        if isinstance(previous, Mapping):
            previous_scores = dict(previous)
        elif previous is not None:
            for prev_card in previous:
                previous_scores[prev_card.site_id] = prev_card.health_score

        cards: list[SiteScorecard] = []
        for site_id in sorted(sites):
            quality_pair = quality.get(site_id, [0, 0]) if quality_findings is not None else None
            firmware_pair = (
                firmware.get(site_id, [0, 0]) if firmware_findings is not None else None
            )
            cards.append(
                self.score_site(
                    site_id,
                    record_counts=records.get(site_id, {}) if results is not None else None,
                    quality_errors=quality_pair[0] if quality_pair is not None else None,
                    quality_warnings=quality_pair[1] if quality_pair is not None else None,
                    cert_findings=(
                        certs.get(site_id, {}) if certificate_findings is not None else None
                    ),
                    firmware_devices=firmware_pair[0] if firmware_pair is not None else None,
                    firmware_noncompliant=(
                        firmware_pair[1] if firmware_pair is not None else None
                    ),
                    drift_events=drift.get(site_id, 0) if drift_events is not None else None,
                    previous_score=previous_scores.get(site_id),
                )
            )
        return cards
