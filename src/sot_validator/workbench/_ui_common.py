"""Workbench UI title, HTML/JSON escaping helpers and shared layout constants."""

from __future__ import annotations

import html
import json
from typing import Any

from sot_validator.models import ValidationClassification

DEFAULT_WORKBENCH_TITLE = "SoT Interactive Network & Inventory Workbench"


def _esc(value: Any) -> str:
    """Escape any value for safe inclusion in HTML text or quoted attributes."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _safe_json_for_script(payload: Any) -> str:
    """Serialize payload to JSON and escape closing script tags and HTML special sequences."""
    raw = json.dumps(payload)
    return (
        raw.replace("</", "<\\/")
        .replace("<!--", "<\\!--")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _badge_class(classification: str) -> str:
    if classification == ValidationClassification.CONFIRMED_ACTIVE.value:
        return "badge-active"
    if classification == ValidationClassification.STALE_LIKELY_UNUSED.value:
        return "badge-stale"
    if classification == ValidationClassification.UNREACHABLE_NEEDS_REVIEW.value:
        return "badge-unreachable"
    return "badge-insufficient"


_STALE_CLASSIFICATION = ValidationClassification.STALE_LIKELY_UNUSED.value
_INACTIVE_POE = frozenset({"", "off", "disabled", "none"})
_TOPO_COLUMN_ORDER: tuple[str, ...] = (
    "site",
    "router",
    "switch",
    "vlan",
    "subnet",
    "port",
    "equipment",
    "ip",
)
_TOPO_NODE_W = 200
_TOPO_NODE_H = 56
_TOPO_COL_WIDTH = 224
_TOPO_ROW_HEIGHT = 56
_TOPO_PAD_X = 24
_TOPO_PAD_Y = 36
_FACEPLATE_COL_MIN = "5rem"
_FACEPLATE_STATE_LABEL = {
    "faceplate-stale": "Stale",
    "faceplate-uplink": "Uplink",
    "faceplate-up": "Up",
    "faceplate-down": "Down",
}
_FACEPLATE_LEGEND = (
    '<p class="faceplate-legend">'
    '<span class="legend-item"><span class="legend-swatch faceplate-up" '
    'aria-hidden="true"></span> Up</span>'
    '<span class="legend-item"><span class="legend-swatch faceplate-down" '
    'aria-hidden="true"></span> Down</span>'
    '<span class="legend-item"><span class="legend-swatch faceplate-uplink" '
    'aria-hidden="true"></span> Uplink</span>'
    '<span class="legend-item"><span class="legend-swatch faceplate-stale" '
    'aria-hidden="true"></span> Stale</span>'
    '<span class="legend-item"><span class="legend-swatch faceplate-poe-badge" '
    'aria-hidden="true"></span> PoE</span>'
    "</p>"
)
# Case-insensitive vendor + model for the three Extreme faceplate templates.
_FACEPLATE_TEMPLATES: tuple[tuple[str, str, str], ...] = (
    ("extreme networks", "summit x440-g2-24p", "24"),
    ("extreme networks", "summit x460-g2-48p", "48"),
    ("extreme networks", "vsp 7400-48y", "48"),
)
