"""Column layout and inline SVG rendering of the workbench topology graph."""

from __future__ import annotations

from sot_validator.topology.graph import TopologyGraph
from sot_validator.workbench._ui_common import (
    _TOPO_COL_WIDTH,
    _TOPO_COLUMN_ORDER,
    _TOPO_NODE_H,
    _TOPO_NODE_W,
    _TOPO_PAD_X,
    _TOPO_PAD_Y,
    _TOPO_ROW_HEIGHT,
    _esc,
)


def _topology_layout(
    graph: TopologyGraph,
) -> tuple[dict[str, tuple[int, int]], int, int]:
    columns: dict[str, list[str]] = {node_type: [] for node_type in _TOPO_COLUMN_ORDER}
    for node in graph.nodes:
        columns.setdefault(node.node_type, []).append(node.node_id)
    positions: dict[str, tuple[int, int]] = {}
    max_rows = 1
    for col_index, node_type in enumerate(_TOPO_COLUMN_ORDER):
        column_ids = columns.get(node_type, [])
        max_rows = max(max_rows, len(column_ids))
        for row_index, node_id in enumerate(column_ids):
            positions[node_id] = (
                _TOPO_PAD_X + col_index * _TOPO_COL_WIDTH,
                _TOPO_PAD_Y + row_index * _TOPO_ROW_HEIGHT,
            )
    width = _TOPO_PAD_X * 2 + len(_TOPO_COLUMN_ORDER) * _TOPO_COL_WIDTH
    height = _TOPO_PAD_Y + max_rows * _TOPO_ROW_HEIGHT + 16
    return positions, width, height


def _edge_endpoints(
    src: tuple[int, int], dst: tuple[int, int]
) -> tuple[int, int, int, int]:
    """Stop each edge on the node box so the stroke does not cross the label."""
    sx, sy = src
    dx, dy = dst
    sy_mid = sy + _TOPO_NODE_H // 2
    dy_mid = dy + _TOPO_NODE_H // 2
    sx_mid = sx + _TOPO_NODE_W // 2
    dx_mid = dx + _TOPO_NODE_W // 2
    if sx + _TOPO_NODE_W <= dx:
        return (sx + _TOPO_NODE_W, sy_mid, dx, dy_mid)
    if dx + _TOPO_NODE_W <= sx:
        return (sx, sy_mid, dx + _TOPO_NODE_W, dy_mid)
    if sy + _TOPO_NODE_H <= dy:
        return (sx_mid, sy + _TOPO_NODE_H, dx_mid, dy)
    if dy + _TOPO_NODE_H <= sy:
        return (sx_mid, sy, dx_mid, dy + _TOPO_NODE_H)
    return (sx_mid, sy_mid, dx_mid, dy_mid)


def _render_topology_svg(graph: TopologyGraph) -> str:
    """Render one inline SVG group per node and one line per edge."""
    positions, width, height = _topology_layout(graph)
    lines: list[str] = []
    for edge in graph.edges:
        src = positions.get(edge.source_id, (0, 0))
        dst = positions.get(edge.target_id, (0, 0))
        x1, y1, x2, y2 = _edge_endpoints(src, dst)
        lines.append(
            f'<line class="topo-edge" data-relation="{_esc(edge.relation)}" '
            f'x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" />'
        )
    groups: list[str] = []
    text_y = _TOPO_NODE_H // 2
    for node in graph.nodes:
        x, y = positions.get(node.node_id, (0, 0))
        access = _esc(f"{node.node_type} {node.label}")
        groups.append(
            f'<g class="topo-node" data-node-id="{_esc(node.node_id)}" '
            f'data-node-type="{_esc(node.node_type)}" '
            f'role="button" tabindex="0" aria-label="{access}" '
            f'transform="translate({x},{y})">'
            f'<rect class="topo-node-box" width="{_TOPO_NODE_W}" '
            f'height="{_TOPO_NODE_H}" rx="6" ry="6"></rect>'
            f'<text x="12" y="{text_y}" dominant-baseline="middle">'
            f"{_esc(node.label)}</text></g>"
        )
    return (
        f'<svg id="topology-svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" '
        f'style="width:{width}px;height:{height}px">'
        f'{"".join(lines)}{"".join(groups)}</svg>'
    )
