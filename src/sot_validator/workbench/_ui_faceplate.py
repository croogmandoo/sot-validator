"""Server-rendered two-row switch faceplate for the Topology Map tab."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import math
from typing import Any, Optional

from sot_validator.topology.graph import TopologyGraph
from sot_validator.workbench._ui_common import (
    _FACEPLATE_COL_MIN,
    _FACEPLATE_LEGEND,
    _FACEPLATE_STATE_LABEL,
    _FACEPLATE_TEMPLATES,
    _INACTIVE_POE,
    _STALE_CLASSIFICATION,
    _esc,
)


def _template_ports_attr(vendor: Any, model: Any) -> Optional[str]:
    """Return 24 or 48 when vendor and model match an Extreme faceplate template."""
    vendor_l = str(vendor or "").strip().lower()
    model_l = str(model or "").strip().lower()
    for known_vendor, known_model, ports in _FACEPLATE_TEMPLATES:
        if vendor_l == known_vendor and model_l == known_model:
            return ports
    return None


def _faceplate_columns(port_count: int) -> int:
    if port_count == 24:
        return 12
    if port_count == 48:
        return 24
    if port_count <= 0:
        return 0
    return math.ceil(port_count / 2)


def _poe_badge_text(poe_status: Any) -> Optional[str]:
    if poe_status is None:
        return None
    text = str(poe_status).strip()
    if text.lower() in _INACTIVE_POE:
        return None
    return text


def _device_node_ids(graph: TopologyGraph, device_id: str) -> set[str]:
    candidates = {device_id, f"router:{device_id}", f"switch:{device_id}"}
    found = {
        node.node_id
        for node in graph.nodes
        if node.node_type in ("router", "switch") and node.node_id in candidates
    }
    return found or ({device_id} if device_id else set())


def _port_is_stale(
    device: Mapping[str, Any],
    port: Mapping[str, Any],
    results: Sequence[Mapping[str, Any]],
    equipment: Sequence[Mapping[str, Any]],
) -> bool:
    hostname = str(device.get("hostname") or "")
    device_id = str(device.get("device_id") or "")
    port_id = str(port.get("port_id") or "")
    port_name = str(port.get("name") or "")
    connected = str(port.get("connected_device_id") or "")
    name_key = f"{hostname}:{port_name}"
    refs = {
        ref
        for ref in (
            port_id,
            f"{device_id}:{port_name}",
            f"{hostname}:{port_name}",
            port_name,
        )
        if ref
    }
    touching_equipment: set[str] = set()
    for eq in equipment:
        connected_ports = eq.get("connected_ports") or []
        if any(ref in connected_ports for ref in refs):
            eq_id = eq.get("equipment_id")
            if eq_id:
                touching_equipment.add(str(eq_id))
    for res in results:
        if res.get("classification") != _STALE_CLASSIFICATION:
            continue
        item_id = str(res.get("item_id") or "")
        if item_id == port_id:
            return True
        if res.get("name") == name_key:
            return True
        if connected and item_id == connected:
            return True
        if item_id in touching_equipment:
            return True
    return False


def _port_is_uplink(
    device: Mapping[str, Any],
    port: Mapping[str, Any],
    graph: TopologyGraph,
) -> bool:
    port_name = str(port.get("name") or "")
    lowered = port_name.lower()
    if "trunk" in lowered or "uplink" in lowered:
        return True
    node_ids = _device_node_ids(graph, str(device.get("device_id") or ""))
    for edge in graph.edges:
        if edge.relation != "uplink_to" or edge.port_name != port_name:
            continue
        if edge.source_id in node_ids or edge.target_id in node_ids:
            return True
    return False


def _faceplate_fill_class(
    device: Mapping[str, Any],
    port: Mapping[str, Any],
    results: Sequence[Mapping[str, Any]],
    equipment: Sequence[Mapping[str, Any]],
    graph: TopologyGraph,
) -> str:
    if _port_is_stale(device, port, results, equipment):
        return "faceplate-stale"
    if _port_is_uplink(device, port, graph):
        return "faceplate-uplink"
    if str(port.get("oper_status") or "").strip().lower() == "up":
        return "faceplate-up"
    return "faceplate-down"


def _faceplate_access_name(port_name: Any, fill: str, poe: str) -> str:
    """Accessible name: port, link state, and PoE text when a badge is shown."""
    state = _FACEPLATE_STATE_LABEL.get(fill, "Down")
    name = f"{port_name}, {state}"
    if poe:
        name = f"{name}, PoE {poe}"
    return name


def _faceplate_chrome(hostname: str, faceplate: str) -> str:
    """Panel heading and legend sit outside the scrolling port grid."""
    return (
        '<div class="faceplate-panel">'
        '<p class="faceplate-heading">Front panel '
        f'<strong id="faceplate-hostname">{_esc(hostname)}</strong></p>'
        f"{_FACEPLATE_LEGEND}{faceplate}</div>"
    )


def _render_switch_faceplate(
    site_dict: Mapping[str, Any],
    results: Sequence[Mapping[str, Any]],
    graph: TopologyGraph,
    device_id: Optional[str] = None,
) -> str:
    """Render the two-row switch faceplate for the selected device."""
    devices = list(site_dict.get("devices") or [])
    device: Optional[Mapping[str, Any]] = None
    if device_id:
        device = next((d for d in devices if d.get("device_id") == device_id), None)
    if device is None and devices:
        device = devices[0]
    if device is None:
        return _faceplate_chrome(
            "",
            '<div id="switch-faceplate" data-device-id="" data-rows="2" '
            'data-faceplate-columns="0"><em>No ports provisioned</em></div>',
        )

    ports = list(device.get("ports") or [])
    columns = _faceplate_columns(len(ports))
    template_ports = _template_ports_attr(device.get("vendor"), device.get("model"))
    template_attr = (
        f' data-template-ports="{_esc(template_ports)}"' if template_ports else ""
    )
    style_attr = ""
    if columns > 0:
        style_attr = (
            " style=\"grid-template-columns: repeat("
            f"{columns}, minmax({_FACEPLATE_COL_MIN}, max-content));\""
        )
    equipment = list(site_dict.get("equipment") or [])
    if not ports:
        body = "<em>No ports provisioned</em>"
    else:
        cells: list[str] = []
        for port in ports:
            fill = _faceplate_fill_class(device, port, results, equipment, graph)
            poe = _poe_badge_text(port.get("poe_status"))
            badge = (
                f'<span class="faceplate-poe-badge">{_esc(poe)}</span>' if poe else ""
            )
            access = _esc(_faceplate_access_name(port.get("name"), fill, poe))
            cells.append(
                f'<button type="button" class="faceplate-port {fill}" '
                f'data-port-id="{_esc(port.get("port_id"))}" '
                f'data-port-name="{_esc(port.get("name"))}" '
                f'title="{access}" aria-label="{access}">'
                f"{_esc(port.get('name'))}{badge}</button>"
            )
        body = "".join(cells)
    faceplate = (
        f'<div id="switch-faceplate" data-device-id="{_esc(device.get("device_id"))}" '
        f'data-rows="2" data-faceplate-columns="{columns}"{template_attr}{style_attr}>'
        f"{body}</div>"
    )
    return _faceplate_chrome(str(device.get("hostname") or ""), faceplate)
