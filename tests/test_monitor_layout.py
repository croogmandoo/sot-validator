"""Tests for the monitor facade: re-exported names, urllib/logger identity and module size limit."""

from __future__ import annotations

from pathlib import Path
import urllib.request

import pytest

import sot_validator.discovery as discovery
import sot_validator.discovery._monitor_dispatch as monitor_dispatch
import sot_validator.discovery._monitor_engine as monitor_engine
import sot_validator.discovery._monitor_events as monitor_events
import sot_validator.discovery.monitor as monitor

DISCOVERY_DIR = Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "discovery"

REEXPORTED_NAMES = [
    ("logger", monitor_events),
    ("DriftValue", monitor_events),
    ("ScanDriftEventType", monitor_events),
    ("SEVERITY_LEVELS", monitor_events),
    ("DEFAULT_DRIFT_SEVERITY", monitor_events),
    ("CRITICAL_ROLES", monitor_events),
    ("_EVENT_TYPE_ORDER", monitor_events),
    ("_SEVERITY_ORDER", monitor_events),
    ("LinkedKey", monitor_events),
    ("_coerce_drift_value", monitor_events),
    ("_seed_value", monitor_events),
    ("_drift_event_id", monitor_events),
    ("ScanDriftEvent", monitor_events),
    ("_empty_summary_counts", monitor_events),
    ("_markdown_cell", monitor_events),
    ("_mac_vendor_cell", monitor_events),
    ("SnapshotDiffReport", monitor_events),
    ("_SnapshotIndex", monitor_engine),
    ("_target_for", monitor_engine),
    ("_collect_patches", monitor_engine),
    ("_collect_port_input", monitor_engine),
    ("_collect_results", monitor_engine),
    ("_network_key", monitor_engine),
    ("_collect_networks", monitor_engine),
    ("_ip_sort_key", monitor_engine),
    ("_event_sort_key", monitor_engine),
    ("_format_ports", monitor_engine),
    ("SnapshotDiffEngine", monitor_engine),
    ("DRIFT_TARGET_KINDS", monitor_dispatch),
    ("_URL_TARGET_KINDS", monitor_dispatch),
    ("HOME_ASSISTANT_EVENT_TYPE", monitor_dispatch),
    ("DriftSender", monitor_dispatch),
    ("_has_unsafe_chars", monitor_dispatch),
    ("DriftAlertTarget", monitor_dispatch),
    ("DriftDispatchResult", monitor_dispatch),
    ("_RefuseRedirectHandler", monitor_dispatch),
    ("_default_sender", monitor_dispatch),
    ("_redacted_destination", monitor_dispatch),
    ("_redact", monitor_dispatch),
    ("_drift_payload", monitor_dispatch),
    ("DriftAlertDispatcher", monitor_dispatch),
]

MONITOR_ALL = [
    "DriftAlertDispatcher",
    "DriftAlertTarget",
    "DriftDispatchResult",
    "ScanDriftEvent",
    "ScanDriftEventType",
    "SnapshotDiffEngine",
    "SnapshotDiffReport",
]


@pytest.mark.parametrize(
    ("name", "module"), REEXPORTED_NAMES, ids=[name for name, _ in REEXPORTED_NAMES]
)
def test_name_importable_from_monitor(name: str, module: object) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.discovery.monitor import {name}", namespace)
    assert namespace[name] is getattr(module, name)


def test_monitor_all_unchanged() -> None:
    assert monitor.__all__ == MONITOR_ALL


@pytest.mark.parametrize("name", MONITOR_ALL)
def test_package_export_is_facade_object(name: str) -> None:
    assert getattr(discovery, name) is getattr(monitor, name)


def test_monitor_urllib_is_stdlib_module() -> None:
    assert monitor.urllib.request is urllib.request
    assert monitor_dispatch.urllib is monitor.urllib


def test_monitor_logger_name_unchanged() -> None:
    assert monitor.logger.name == "sot_validator.discovery.monitor"


def test_monitor_modules_under_800_lines() -> None:
    private = sorted(DISCOVERY_DIR.glob("_monitor_*.py"))
    assert [path.name for path in private] == [
        "_monitor_dispatch.py",
        "_monitor_engine.py",
        "_monitor_events.py",
    ]
    for path in [DISCOVERY_DIR / "monitor.py", *private]:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
