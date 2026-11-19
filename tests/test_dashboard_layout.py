"""Tests for the dashboard facade: re-exported names and module size limit."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import sot_validator.reporting as reporting
import sot_validator.reporting.dashboard as dashboard

REPORTING_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "reporting"
)

PUBLIC_NAMES = [
    "DEFAULT_DASHBOARD_FILENAME",
    "DEFAULT_DASHBOARD_TITLE",
    "HtmlDashboardGenerator",
    "generate_html_dashboard",
]

# Name -> module that defines it.
REEXPORTED_NAMES = {
    "DEFAULT_DASHBOARD_FILENAME": "_dashboard_common",
    "DEFAULT_DASHBOARD_TITLE": "_dashboard_common",
    "HtmlDashboardGenerator": "_dashboard_render",
    "generate_html_dashboard": "_dashboard_render",
    "_esc": "_dashboard_common",
    "_classification_badge_class": "_dashboard_common",
    "_inventory_record": "_dashboard_common",
    "_encode_inventory_payload": "_dashboard_common",
    "_approval_badge_class": "_dashboard_common",
    "_ups_status_badge_class": "_dashboard_common",
    "_cutover_badge_class": "_dashboard_common",
    "_coerce_manifest": "_dashboard_common",
    "_coerce_streaks": "_dashboard_common",
    "_coerce_reconciliation": "_dashboard_common",
    "_coerce_subnet_utilization": "_dashboard_common",
    "_coerce_port_reclamation_plan": "_dashboard_common",
    "_coerce_parity_report": "_dashboard_common",
    "_coerce_ups_health_report": "_dashboard_common",
    "_coerce_itsm_tickets": "_dashboard_common",
    "ALL_CLASSIFICATIONS": "generators",
    "_index_sites": "generators",
    "_resolve_report_timestamp": "generators",
    "generate_json_report": "generators",
}


@pytest.mark.parametrize("name", sorted(REEXPORTED_NAMES))
def test_name_importable_from_dashboard(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.reporting.dashboard import {name}", namespace)
    defining = importlib.import_module(
        f"sot_validator.reporting.{REEXPORTED_NAMES[name]}"
    )
    assert namespace[name] is getattr(defining, name)
    assert namespace[name] is getattr(dashboard, name)
    if callable(namespace[name]):
        assert namespace[name].__module__ == defining.__name__


def test_dashboard_all_unchanged() -> None:
    assert dashboard.__all__ == PUBLIC_NAMES


def test_package_dashboard_names_are_same_objects() -> None:
    for name in PUBLIC_NAMES:
        assert getattr(reporting, name) is getattr(dashboard, name)


def test_generator_aliases() -> None:
    generator = dashboard.HtmlDashboardGenerator
    assert generator.generate is generator.render
    assert generator.DEFAULT_FILENAME == dashboard.DEFAULT_DASHBOARD_FILENAME


def test_dashboard_modules_under_800_lines() -> None:
    private = sorted(REPORTING_DIR.glob("_dashboard_*.py"))
    assert len(private) >= 2
    for path in [REPORTING_DIR / "dashboard.py", *private]:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
