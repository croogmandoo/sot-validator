"""Tests for the fleet scorecard facade: re-exported names and module size limit."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import sot_validator.reporting as reporting
import sot_validator.reporting.fleet as fleet

REPORTING_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "reporting"
)

# Names sot_validator.reporting imports from the fleet module.
PACKAGE_NAMES = [
    "FLEET_DIMENSIONS",
    "TREND_DEGRADING",
    "TREND_IMPROVING",
    "TREND_NEW",
    "TREND_STABLE",
    "TREND_STABLE_THRESHOLD",
    "FleetScoreWeights",
    "FleetScorer",
    "SiteScorecard",
    "render_fleet_html",
    "render_fleet_markdown",
]

# Name -> module that defines it.
REEXPORTED_NAMES = {
    "FLEET_DIMENSIONS": "_fleet_scoring",
    "TREND_IMPROVING": "_fleet_scoring",
    "TREND_STABLE": "_fleet_scoring",
    "TREND_DEGRADING": "_fleet_scoring",
    "TREND_NEW": "_fleet_scoring",
    "TREND_VALUES": "_fleet_scoring",
    "TREND_STABLE_THRESHOLD": "_fleet_scoring",
    "CERT_SEVERITIES": "_fleet_scoring",
    "_FIRMWARE_COMPLIANT": "_fleet_scoring",
    "_RECORD_KEYS": "_fleet_scoring",
    "_STALE": "_fleet_scoring",
    "_UNREACHABLE": "_fleet_scoring",
    "_INSUFFICIENT": "_fleet_scoring",
    "NO_DATA": "_fleet_scoring",
    "DEFAULT_FLEET_TITLE": "_fleet_scoring",
    "TOP_N": "_fleet_scoring",
    "_require_count": "_fleet_scoring",
    "_require_number": "_fleet_scoring",
    "_clamp": "_fleet_scoring",
    "FleetScoreWeights": "_fleet_scoring",
    "SiteScorecard": "_fleet_scoring",
    "_trend": "_fleet_scoring",
    "FleetScorer": "_fleet_scoring",
    "_card_sort_key": "_fleet_render",
    "_ordered": "_fleet_render",
    "_fmt_score": "_fleet_render",
    "_fmt_timestamp": "_fleet_render",
    "_cert_text": "_fleet_render",
    "_firmware_text": "_fleet_render",
    "_count_text": "_fleet_render",
    "_table_cells": "_fleet_render",
    "TABLE_HEADERS": "_fleet_render",
    "_TOP_LISTS": "_fleet_render",
    "_top_metric": "_fleet_render",
    "_top_display": "_fleet_render",
    "_top_list": "_fleet_render",
    "_fleet_totals": "_fleet_render",
    "_dimension_detail": "_fleet_render",
    "_md_row": "_fleet_render",
    "render_fleet_markdown": "_fleet_render",
    "_esc": "_fleet_render",
    "_FLEET_STYLE": "_fleet_render",
    "_FLEET_SCRIPT": "_fleet_render",
    "_html_value": "_fleet_render",
    "render_fleet_html": "_fleet_render",
}


@pytest.mark.parametrize("name", sorted(REEXPORTED_NAMES))
def test_name_importable_from_fleet(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.reporting.fleet import {name}", namespace)
    defining = importlib.import_module(
        f"sot_validator.reporting.{REEXPORTED_NAMES[name]}"
    )
    assert namespace[name] is getattr(defining, name)
    assert namespace[name] is getattr(fleet, name)
    if callable(namespace[name]):
        assert namespace[name].__module__ == defining.__name__


def test_package_fleet_names_are_same_objects() -> None:
    for name in PACKAGE_NAMES:
        assert getattr(reporting, name) is getattr(fleet, name)


def test_fleet_has_no_all() -> None:
    assert not hasattr(fleet, "__all__")


def test_fleet_modules_under_800_lines() -> None:
    for filename in ("fleet.py", "_fleet_scoring.py", "_fleet_render.py"):
        path = REPORTING_DIR / filename
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
