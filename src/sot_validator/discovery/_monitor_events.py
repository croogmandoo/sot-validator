"""Scan drift event types, severities, drift events and the snapshot diff report."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib
import json
import logging
from typing import Any, Optional, Union

from sot_validator.models import _require_non_empty_str
from sot_validator.signals.base import normalize_utc_datetime

logger = logging.getLogger("sot_validator.discovery.monitor")

DriftValue = Optional[Union[str, list[int]]]


class ScanDriftEventType(str, Enum):
    """Categories of drift detected between two discovery snapshots of a site."""

    NEW_HOST_JOINED = "NEW_HOST_JOINED"
    HOST_WENT_OFFLINE = "HOST_WENT_OFFLINE"
    CRITICAL_ASSET_OFFLINE = "CRITICAL_ASSET_OFFLINE"
    MAC_ADDRESS_CHANGED = "MAC_ADDRESS_CHANGED"
    OPEN_PORTS_CHANGED = "OPEN_PORTS_CHANGED"
    NEW_SUBNET_DISCOVERED = "NEW_SUBNET_DISCOVERED"
    CLASSIFICATION_CHANGED = "CLASSIFICATION_CHANGED"


SEVERITY_LEVELS: tuple[str, ...] = ("critical", "warning", "info")

# MAC_ADDRESS_CHANGED escalates to "critical" when the asset is critical.
DEFAULT_DRIFT_SEVERITY: dict[ScanDriftEventType, str] = {
    ScanDriftEventType.NEW_HOST_JOINED: "warning",
    ScanDriftEventType.HOST_WENT_OFFLINE: "warning",
    ScanDriftEventType.CRITICAL_ASSET_OFFLINE: "critical",
    ScanDriftEventType.MAC_ADDRESS_CHANGED: "warning",
    ScanDriftEventType.OPEN_PORTS_CHANGED: "info",
    ScanDriftEventType.NEW_SUBNET_DISCOVERED: "warning",
    ScanDriftEventType.CLASSIFICATION_CHANGED: "info",
}

CRITICAL_ROLES: frozenset[str] = frozenset({"router", "switch", "hypervisor"})

_EVENT_TYPE_ORDER: dict[ScanDriftEventType, int] = {
    member: index for index, member in enumerate(ScanDriftEventType)
}
_SEVERITY_ORDER: dict[str, int] = {
    severity: index for index, severity in enumerate(SEVERITY_LEVELS)
}

LinkedKey = tuple[str, str]


def _coerce_drift_value(value: Any, field_name: str) -> DriftValue:
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        for port in value:
            if isinstance(port, bool) or not isinstance(port, int):
                raise ValueError(f"{field_name} list must contain only integers")
        return sorted(value)
    raise ValueError(f"{field_name} must be None, a string, or a list of integers")


def _seed_value(value: DriftValue) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ",".join(str(port) for port in value)
    return value


def _drift_event_id(
    site_id: str,
    event_type: ScanDriftEventType,
    target_id: str,
    ip: Optional[str],
    previous_value: DriftValue,
    current_value: DriftValue,
) -> str:
    seed = "|".join(
        (
            site_id,
            event_type.value,
            target_id,
            ip or "",
            _seed_value(previous_value),
            _seed_value(current_value),
        )
    )
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
    return f"drift-{digest}"


@dataclass
class ScanDriftEvent:
    """Single typed, severity-ranked drift observation between two site snapshots."""

    event_id: str
    event_type: ScanDriftEventType
    severity: str
    site_id: str
    target_id: str
    ip: Optional[str]
    previous_value: DriftValue
    current_value: DriftValue
    detected_at: datetime
    summary: str
    # Only set when diffed with an OUI registry and the event carries a MAC.
    mac_annotations: Optional[dict[str, dict[str, Any]]] = None

    def __post_init__(self) -> None:
        if not isinstance(self.event_type, ScanDriftEventType):
            try:
                self.event_type = ScanDriftEventType(self.event_type)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid event_type: {self.event_type!r}"
                ) from exc
        if not isinstance(self.severity, str) or self.severity not in _SEVERITY_ORDER:
            raise ValueError(
                f"Invalid severity: {self.severity!r}; expected one of {SEVERITY_LEVELS}"
            )
        _require_non_empty_str(self.event_id, "event_id")
        _require_non_empty_str(self.site_id, "site_id")
        _require_non_empty_str(self.target_id, "target_id")
        _require_non_empty_str(self.summary, "summary")
        if self.ip is not None and not isinstance(self.ip, str):
            raise ValueError("ip must be a string or None")
        self.previous_value = _coerce_drift_value(self.previous_value, "previous_value")
        self.current_value = _coerce_drift_value(self.current_value, "current_value")
        self.detected_at = normalize_utc_datetime(
            self.detected_at, field_name="detected_at"
        )

    def to_dict(self) -> dict[str, Any]:
        data = {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "severity": self.severity,
            "site_id": self.site_id,
            "target_id": self.target_id,
            "ip": self.ip,
            "previous_value": (
                list(self.previous_value)
                if isinstance(self.previous_value, list)
                else self.previous_value
            ),
            "current_value": (
                list(self.current_value)
                if isinstance(self.current_value, list)
                else self.current_value
            ),
            "detected_at": self.detected_at.isoformat(),
            "summary": self.summary,
        }
        if self.mac_annotations is not None:
            data["mac_annotations"] = {
                side: dict(annotation) for side, annotation in self.mac_annotations.items()
            }
        return data


def _empty_summary_counts() -> dict[str, Any]:
    return {
        "total": 0,
        "by_type": {member.value: 0 for member in ScanDriftEventType},
        "by_severity": {severity: 0 for severity in SEVERITY_LEVELS},
    }


def _markdown_cell(value: DriftValue) -> str:
    if value is None:
        return "-"
    if isinstance(value, list):
        text = ", ".join(str(port) for port in value)
    else:
        text = str(value)
    return text.replace("|", "\\|")


def _mac_vendor_cell(event: ScanDriftEvent) -> str:
    if not event.mac_annotations:
        return "-"
    parts = [
        f"{side}: {annotation['vendor'] or 'unknown'} ({annotation['class']})"
        for side, annotation in event.mac_annotations.items()
    ]
    return _markdown_cell("; ".join(parts))


@dataclass
class SnapshotDiffReport:
    """Drift report produced by diffing a baseline and current snapshot of one site."""

    site_id: str
    baseline_timestamp: Optional[datetime]
    current_timestamp: datetime
    events: list[ScanDriftEvent] = field(default_factory=list)
    oui_annotated: bool = False
    summary_counts: dict[str, Any] = field(init=False)

    def __post_init__(self) -> None:
        _require_non_empty_str(self.site_id, "site_id")
        if self.baseline_timestamp is not None:
            self.baseline_timestamp = normalize_utc_datetime(
                self.baseline_timestamp, field_name="baseline_timestamp"
            )
        self.current_timestamp = normalize_utc_datetime(
            self.current_timestamp, field_name="current_timestamp"
        )
        self.events = list(self.events)
        for event in self.events:
            if not isinstance(event, ScanDriftEvent):
                raise ValueError("events must contain only ScanDriftEvent instances")
        counts = _empty_summary_counts()
        for event in self.events:
            counts["total"] += 1
            counts["by_type"][event.event_type.value] += 1
            counts["by_severity"][event.severity] += 1
        self.summary_counts = counts

    @property
    def highest_severity(self) -> Optional[str]:
        if not self.events:
            return None
        return min(
            (event.severity for event in self.events),
            key=lambda severity: _SEVERITY_ORDER[severity],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "baseline_timestamp": (
                self.baseline_timestamp.isoformat()
                if self.baseline_timestamp is not None
                else None
            ),
            "current_timestamp": self.current_timestamp.isoformat(),
            "summary_counts": {
                "total": self.summary_counts["total"],
                "by_type": dict(self.summary_counts["by_type"]),
                "by_severity": dict(self.summary_counts["by_severity"]),
            },
            "highest_severity": self.highest_severity,
            "events": [event.to_dict() for event in self.events],
        }

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        baseline = (
            self.baseline_timestamp.isoformat()
            if self.baseline_timestamp is not None
            else "unknown"
        )
        lines = [
            f"# Snapshot Drift Report: {self.site_id}",
            "",
            f"- Baseline: {baseline}",
            f"- Current: {self.current_timestamp.isoformat()}",
            "",
            "## Counts",
            "",
            f"- Total: {self.summary_counts['total']}",
        ]
        for severity in SEVERITY_LEVELS:
            lines.append(f"- {severity}: {self.summary_counts['by_severity'][severity]}")
        for member in ScanDriftEventType:
            lines.append(f"- {member.value}: {self.summary_counts['by_type'][member.value]}")
        lines.extend(["", "## Events", ""])
        if not self.events:
            lines.append("No drift detected.")
        else:
            if self.oui_annotated:
                lines.append(
                    "| Severity | Type | Target | IP | Previous | Current | Summary | MAC vendor |"
                )
                lines.append("|---|---|---|---|---|---|---|---|")
            else:
                lines.append("| Severity | Type | Target | IP | Previous | Current | Summary |")
                lines.append("|---|---|---|---|---|---|---|")
            for event in self.events:
                cells = (
                    _markdown_cell(event.severity),
                    _markdown_cell(event.event_type.value),
                    _markdown_cell(event.target_id),
                    _markdown_cell(event.ip),
                    _markdown_cell(event.previous_value),
                    _markdown_cell(event.current_value),
                    _markdown_cell(event.summary),
                )
                if self.oui_annotated:
                    cells += (_mac_vendor_cell(event),)
                lines.append("| " + " | ".join(cells) + " |")
        return "\n".join(lines) + "\n"
