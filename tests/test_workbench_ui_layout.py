"""Tests for the workbench UI facade: re-exported names and module size limit."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import sot_validator.workbench as workbench
import sot_validator.workbench.ui as ui

WORKBENCH_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "workbench"
)

PUBLIC_NAMES = ["DEFAULT_WORKBENCH_TITLE", "render_workbench_html"]

# Name -> private module that defines it.
REEXPORTED_NAMES = {
    "DEFAULT_WORKBENCH_TITLE": "_ui_common",
    "_esc": "_ui_common",
    "_safe_json_for_script": "_ui_common",
    "_badge_class": "_ui_common",
    "_STALE_CLASSIFICATION": "_ui_common",
    "_INACTIVE_POE": "_ui_common",
    "_TOPO_COLUMN_ORDER": "_ui_common",
    "_TOPO_NODE_W": "_ui_common",
    "_TOPO_NODE_H": "_ui_common",
    "_TOPO_COL_WIDTH": "_ui_common",
    "_TOPO_ROW_HEIGHT": "_ui_common",
    "_TOPO_PAD_X": "_ui_common",
    "_TOPO_PAD_Y": "_ui_common",
    "_FACEPLATE_COL_MIN": "_ui_common",
    "_FACEPLATE_STATE_LABEL": "_ui_common",
    "_FACEPLATE_LEGEND": "_ui_common",
    "_FACEPLATE_TEMPLATES": "_ui_common",
    "_template_ports_attr": "_ui_faceplate",
    "_faceplate_columns": "_ui_faceplate",
    "_poe_badge_text": "_ui_faceplate",
    "_device_node_ids": "_ui_faceplate",
    "_port_is_stale": "_ui_faceplate",
    "_port_is_uplink": "_ui_faceplate",
    "_faceplate_fill_class": "_ui_faceplate",
    "_faceplate_access_name": "_ui_faceplate",
    "_faceplate_chrome": "_ui_faceplate",
    "_render_switch_faceplate": "_ui_faceplate",
    "_topology_layout": "_ui_topology",
    "_edge_endpoints": "_ui_topology",
    "_render_topology_svg": "_ui_topology",
    "_WORKBENCH_V2_SCRIPT": "_ui_scripts",
    "_BULK_IMPORT_SCRIPT": "_ui_scripts",
    "render_workbench_html": "_ui_render",
}


@pytest.mark.parametrize("name", sorted(REEXPORTED_NAMES))
def test_name_importable_from_ui(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.workbench.ui import {name}", namespace)
    defining = importlib.import_module(
        f"sot_validator.workbench.{REEXPORTED_NAMES[name]}"
    )
    assert namespace[name] is getattr(defining, name)
    assert namespace[name] is getattr(ui, name)
    if callable(namespace[name]):
        assert namespace[name].__module__ == defining.__name__


def test_faceplate_placeholder_replaced_at_import() -> None:
    assert "__FACEPLATE_TEMPLATES__" not in ui._WORKBENCH_V2_SCRIPT
    assert '"summit x440-g2-24p"' in ui._WORKBENCH_V2_SCRIPT


def test_ui_all_unchanged() -> None:
    assert ui.__all__ == PUBLIC_NAMES


def test_package_exports_same_objects() -> None:
    assert workbench.DEFAULT_WORKBENCH_TITLE is ui.DEFAULT_WORKBENCH_TITLE
    assert workbench.render_workbench_html is ui.render_workbench_html


def test_ui_modules_under_800_lines() -> None:
    private = sorted(WORKBENCH_DIR.glob("_ui*.py"))
    assert private
    for path in [WORKBENCH_DIR / "ui.py", *private]:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
