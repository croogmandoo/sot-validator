"""Snapshot diff engine, scan drift events, and drift alert dispatcher for discovery runs."""

from __future__ import annotations

import urllib.request

from sot_validator.discovery._monitor_dispatch import (
    DRIFT_TARGET_KINDS,
    DriftAlertDispatcher,
    DriftAlertTarget,
    DriftDispatchResult,
    DriftSender,
    HOME_ASSISTANT_EVENT_TYPE,
    _RefuseRedirectHandler,
    _URL_TARGET_KINDS,
    _default_sender,
    _drift_payload,
    _has_unsafe_chars,
    _redact,
    _redacted_destination,
)
from sot_validator.discovery._monitor_engine import (
    SnapshotDiffEngine,
    _SnapshotIndex,
    _collect_networks,
    _collect_patches,
    _collect_port_input,
    _collect_results,
    _event_sort_key,
    _format_ports,
    _ip_sort_key,
    _network_key,
    _target_for,
)
from sot_validator.discovery._monitor_events import (
    CRITICAL_ROLES,
    DEFAULT_DRIFT_SEVERITY,
    DriftValue,
    LinkedKey,
    SEVERITY_LEVELS,
    ScanDriftEvent,
    ScanDriftEventType,
    SnapshotDiffReport,
    _EVENT_TYPE_ORDER,
    _SEVERITY_ORDER,
    _coerce_drift_value,
    _drift_event_id,
    _empty_summary_counts,
    _mac_vendor_cell,
    _markdown_cell,
    _seed_value,
    logger,
)

__all__ = [
    "DriftAlertDispatcher",
    "DriftAlertTarget",
    "DriftDispatchResult",
    "ScanDriftEvent",
    "ScanDriftEventType",
    "SnapshotDiffEngine",
    "SnapshotDiffReport",
]
