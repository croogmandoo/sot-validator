"""Self-contained interactive single-page HTML5/CSS/JS Workbench UI generator.

Facade over the private ``_ui*`` modules; every name stays importable from here.
"""

from __future__ import annotations

from sot_validator.workbench._ui_common import (
    DEFAULT_WORKBENCH_TITLE,
    _FACEPLATE_COL_MIN,
    _FACEPLATE_LEGEND,
    _FACEPLATE_STATE_LABEL,
    _FACEPLATE_TEMPLATES,
    _INACTIVE_POE,
    _STALE_CLASSIFICATION,
    _TOPO_COL_WIDTH,
    _TOPO_COLUMN_ORDER,
    _TOPO_NODE_H,
    _TOPO_NODE_W,
    _TOPO_PAD_X,
    _TOPO_PAD_Y,
    _TOPO_ROW_HEIGHT,
    _badge_class,
    _esc,
    _safe_json_for_script,
)
from sot_validator.workbench._ui_faceplate import (
    _device_node_ids,
    _faceplate_access_name,
    _faceplate_chrome,
    _faceplate_columns,
    _faceplate_fill_class,
    _poe_badge_text,
    _port_is_stale,
    _port_is_uplink,
    _render_switch_faceplate,
    _template_ports_attr,
)
from sot_validator.workbench._ui_render import render_workbench_html
from sot_validator.workbench._ui_scripts import (
    _BULK_IMPORT_SCRIPT,
    _WORKBENCH_V2_SCRIPT,
)
from sot_validator.workbench._ui_topology import (
    _edge_endpoints,
    _render_topology_svg,
    _topology_layout,
)

__all__ = [
    "DEFAULT_WORKBENCH_TITLE",
    "render_workbench_html",
]
