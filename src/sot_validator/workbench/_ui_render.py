"""render_workbench_html: snapshot the workbench state and assemble the page."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from sot_validator.models import EquipmentCategory, ValidationClassification
from sot_validator.topology.device_types import VALID_DEVICE_ROLES
from sot_validator.topology.graph import TopologyGraphBuilder
from sot_validator.workbench._ui_common import (
    DEFAULT_WORKBENCH_TITLE,
    _badge_class,
    _esc,
    _safe_json_for_script,
)
from sot_validator.workbench._ui_faceplate import _render_switch_faceplate
from sot_validator.workbench._ui_page_css import _PAGE_CSS
from sot_validator.workbench._ui_page_markup import _render_page_markup
from sot_validator.workbench._ui_page_script import _PAGE_SCRIPT
from sot_validator.workbench._ui_scripts import (
    _BULK_IMPORT_SCRIPT,
    _WORKBENCH_V2_SCRIPT,
)
from sot_validator.workbench._ui_topology import _render_topology_svg
from sot_validator.workbench.quality_view import (
    QUALITY_CSS,
    QUALITY_SCRIPT,
    render_quality_section,
)

if TYPE_CHECKING:
    from sot_validator.workbench.server import WorkbenchState


def render_workbench_html(
    state: WorkbenchState,
    *,
    title: str = DEFAULT_WORKBENCH_TITLE,
) -> str:
    """Render a complete, self-contained HTML5 Workbench UI pre-seeded with `state`."""
    with state._lock:
        payload = state.get_state_payload(audit_limit=100)
        graph = TopologyGraphBuilder().build(state.site, state.results)
        quality_section_html = render_quality_section(state.site)
    site_dict = payload["site"]
    results_list = payload["results"]
    templates_list = payload["templates"]
    patches_list = payload["patches"]
    vlan_summary_list = payload["vlan_subnet_summary"]
    summary = payload["summary"]
    audit_log_list = payload["audit_log"]

    cls_counts = summary.get("classification_counts", {})
    confirmed_cnt = cls_counts.get(
        ValidationClassification.CONFIRMED_ACTIVE.value, 0
    )
    stale_cnt = cls_counts.get(
        ValidationClassification.STALE_LIKELY_UNUSED.value, 0
    )
    unreachable_cnt = cls_counts.get(
        ValidationClassification.UNREACHABLE_NEEDS_REVIEW.value, 0
    )
    insufficient_cnt = cls_counts.get(
        ValidationClassification.INSUFFICIENT_DATA.value, 0
    )

    result_by_key: dict[tuple[str, str], dict[str, Any]] = {
        (r["item_type"], r["item_id"]): r for r in results_list
    }
    patch_by_key: dict[tuple[str, str], dict[str, Any]] = {
        (p["target_type"], p["target_id"]): p
        for p in patches_list
        if not p.get("deleted")
    }

    # Build initial server-rendered Inventory Table rows
    inventory_rows_html: list[str] = []
    for dev in site_dict.get("devices", []):
        dev_id = dev["device_id"]
        res = result_by_key.get(("NetworkDevice", dev_id), {})
        patch = patch_by_key.get(("NetworkDevice", dev_id), {})
        cls_val = res.get(
            "classification", ValidationClassification.INSUFFICIENT_DATA.value
        )
        room_val = patch.get("room") or ""
        vlan_val = patch.get("vlan_id") or ""
        notes_val = patch.get("notes") or ""
        ports_cnt = len(dev.get("ports", []))
        inventory_rows_html.append(
            f'<tr data-target-type="NetworkDevice" data-target-id="{_esc(dev_id)}" '
            f'data-vlan="{_esc(vlan_val)}" data-classification="{_esc(cls_val)}">'
            f"<td><code>NetworkDevice</code></td>"
            f"<td><code>{_esc(dev_id)}</code></td>"
            f"<td><strong>{_esc(dev.get('hostname'))}</strong></td>"
            f"<td>{_esc(dev.get('role') or 'switch')} ({_esc(dev.get('vendor') or '')} {_esc(dev.get('model') or '')})</td>"
            f"<td>{_esc(room_val)}</td>"
            f"<td>{_esc(vlan_val)}</td>"
            f"<td>{_esc(dev.get('management_ip') or '')} ({ports_cnt} ports)</td>"
            f"<td>{_esc(notes_val)}</td>"
            f'<td><span class="badge {_badge_class(cls_val)}">{_esc(cls_val)}</span></td>'
            f'<td><button type="button" class="btn btn-sm" '
            f"onclick=\"openEditModal('NetworkDevice', '{_esc(dev_id)}')\">Edit</button></td>"
            f"</tr>"
        )

    for eq in site_dict.get("equipment", []):
        eq_id = eq["equipment_id"]
        res = result_by_key.get(("Equipment", eq_id), {})
        patch = patch_by_key.get(("Equipment", eq_id), {})
        cls_val = res.get(
            "classification", ValidationClassification.INSUFFICIENT_DATA.value
        )
        custom_attrs = patch.get("custom_attributes") or {}
        room_val = patch.get("room") or custom_attrs.get("room") or ""
        vlan_val = patch.get("vlan_id") or custom_attrs.get("vlan_id") or ""
        notes_val = patch.get("notes") or ""
        ips_str = ", ".join(eq.get("assigned_ips", []))
        ports_str = ", ".join(eq.get("connected_ports", []))
        conn_summary = ips_str + (f" [{ports_str}]" if ports_str else "")
        inventory_rows_html.append(
            f'<tr data-target-type="Equipment" data-target-id="{_esc(eq_id)}" '
            f'data-vlan="{_esc(vlan_val)}" data-classification="{_esc(cls_val)}">'
            f"<td><code>Equipment</code></td>"
            f"<td><code>{_esc(eq_id)}</code></td>"
            f"<td><strong>{_esc(eq.get('name'))}</strong></td>"
            f"<td>{_esc(eq.get('category'))}</td>"
            f"<td>{_esc(room_val)}</td>"
            f"<td>{_esc(vlan_val)}</td>"
            f"<td>{_esc(conn_summary)}</td>"
            f"<td>{_esc(notes_val)}</td>"
            f'<td><span class="badge {_badge_class(cls_val)}">{_esc(cls_val)}</span></td>'
            f'<td><button type="button" class="btn btn-sm" '
            f"onclick=\"openEditModal('Equipment', '{_esc(eq_id)}')\">Edit</button></td>"
            f"</tr>"
        )

    for ip_rec in site_dict.get("ip_addresses", []):
        ip_val = ip_rec["ip"]
        res = result_by_key.get(("IPAddress", ip_val), {})
        patch = patch_by_key.get(("IPAddress", ip_val), {})
        cls_val = res.get(
            "classification", ValidationClassification.INSUFFICIENT_DATA.value
        )
        subnet_id = ip_rec.get("subnet_id") or ""
        notes_val = patch.get("notes") or ""
        assigned_info = ip_rec.get("assigned_object_id") or ""
        inventory_rows_html.append(
            f'<tr data-target-type="IPAddress" data-target-id="{_esc(ip_val)}" '
            f'data-subnet="{_esc(subnet_id)}" data-classification="{_esc(cls_val)}">'
            f"<td><code>IPAddress</code></td>"
            f"<td><code>{_esc(ip_val)}</code></td>"
            f"<td><strong>{_esc(patch.get('name') or ip_val)}</strong></td>"
            f"<td>IP Assignment</td>"
            f"<td>{_esc(patch.get('room') or '')}</td>"
            f"<td>{_esc(subnet_id)}</td>"
            f"<td>{_esc(assigned_info)} {_esc(ip_rec.get('arp_mac') or '')}</td>"
            f"<td>{_esc(notes_val)}</td>"
            f'<td><span class="badge {_badge_class(cls_val)}">{_esc(cls_val)}</span></td>'
            f'<td><button type="button" class="btn btn-sm" '
            f"onclick=\"openEditModal('IPAddress', '{_esc(ip_val)}')\">Edit</button></td>"
            f"</tr>"
        )

    # Template options
    template_options_html = ['<option value="">-- Custom Device (No Template) --</option>']
    for tpl in templates_list:
        tpl_id = tpl["template_id"]
        label = (
            f"{tpl['vendor']} {tpl['model']} ({tpl['role']}, "
            f"{tpl['default_port_count']} ports)"
        )
        template_options_html.append(
            f'<option value="{_esc(tpl_id)}">{_esc(label)} [{_esc(tpl_id)}]</option>'
        )

    # Device options for port manager
    device_options_html: list[str] = []
    for dev in site_dict.get("devices", []):
        device_options_html.append(
            f'<option value="{_esc(dev["device_id"])}">'
            f'{_esc(dev["hostname"])} ({_esc(dev["device_id"])})</option>'
        )

    # Device port cards
    device_cards_html: list[str] = []
    for dev in site_dict.get("devices", []):
        ports_chips: list[str] = []
        for p in dev.get("ports", []):
            oper = (p.get("oper_status") or "down").lower()
            chip_cls = "port-up" if oper == "up" else "port-down"
            poe_badge = f"⚡{_esc(p['poe_status'])}" if p.get("poe_status") else ""
            vlan_badge = f"V{_esc(p['vlan_id'])}" if p.get("vlan_id") else ""
            mac_badge = f"MAC:{_esc(p['connected_mac'])}" if p.get("connected_mac") else ""
            ports_chips.append(
                f'<div class="port-chip {chip_cls}" '
                f'title="Port {_esc(p["name"])} | Admin: {_esc(p.get("admin_status"))} | Oper: {_esc(p.get("oper_status"))} | VLAN: {_esc(p.get("vlan_id"))} | MAC: {_esc(p.get("connected_mac"))} | Connected: {_esc(p.get("connected_device_id"))}">'
                f'<span class="port-name">{_esc(p["name"])}</span>'
                f'<span class="port-meta">{vlan_badge} {poe_badge} {mac_badge}</span>'
                f"</div>"
            )
        device_cards_html.append(
            f'<div class="device-card" data-device-id="{_esc(dev["device_id"])}">'
            f'<div class="device-card-header">'
            f'<strong>{_esc(dev["hostname"])}</strong> '
            f'<code>({_esc(dev["device_id"])})</code> — '
            f'{_esc(dev.get("vendor") or "")} {_esc(dev.get("model") or "")} '
            f'[{_esc(dev.get("role") or "switch")}] '
            f'IP: <code>{_esc(dev.get("management_ip") or "N/A")}</code>'
            f"</div>"
            f'<div class="port-grid">{"".join(ports_chips) or "<em>No ports provisioned</em>"}</div>'
            f"</div>"
        )

    # VLAN & Subnet summary rows
    vlan_rows_html: list[str] = []
    for vs in vlan_summary_list:
        vlan_rows_html.append(
            f"<tr>"
            f"<td><code>{_esc(vs.get('vlan_id') or '-')}</code></td>"
            f"<td><strong>{_esc(vs.get('vlan_name') or '-')}</strong></td>"
            f"<td><code>{_esc(vs.get('subnet_id') or '-')}</code></td>"
            f"<td><code>{_esc(vs.get('cidr') or '-')}</code></td>"
            f"<td><code>{_esc(vs.get('gateway') or '-')}</code></td>"
            f"<td>{int(vs.get('ip_count', 0))}</td>"
            f"<td>{int(vs.get('device_port_count', 0))}</td>"
            f"<td>{int(vs.get('equipment_count', 0))}</td>"
            f"</tr>"
        )

    # Audit log rows
    audit_rows_html: list[str] = []
    for entry in audit_log_list:
        changes_json = json.dumps(entry.get("changes", {}))
        audit_rows_html.append(
            f"<tr>"
            f"<td><code>{_esc(entry.get('timestamp'))}</code></td>"
            f"<td>{_esc(entry.get('actor'))}</td>"
            f"<td><span class=\"badge badge-info\">{_esc(entry.get('action'))}</span></td>"
            f"<td><code>{_esc(entry.get('target_type'))}:{_esc(entry.get('target_id'))}</code></td>"
            f"<td><code>{_esc(changes_json)}</code></td>"
            f"<td>{_esc(entry.get('reason'))}</td>"
            f"</tr>"
        )

    # Filter options
    vlan_filter_opts = ['<option value="">All VLANs</option>']
    for v in site_dict.get("vlans", []):
        vlan_filter_opts.append(
            f'<option value="{_esc(v["vlan_id"])}">VLAN {_esc(v["vlan_id"])} ({_esc(v.get("name") or "")})</option>'
        )

    subnet_filter_opts = ['<option value="">All Subnets</option>']
    for s in site_dict.get("subnets", []):
        subnet_filter_opts.append(
            f'<option value="{_esc(s["subnet_id"])}">{_esc(s["cidr"])} ({_esc(s["subnet_id"])})</option>'
        )

    cls_filter_opts = ['<option value="">All Classifications</option>']
    for cls_enum in ValidationClassification:
        cls_filter_opts.append(
            f'<option value="{_esc(cls_enum.value)}">{_esc(cls_enum.value)}</option>'
        )

    role_opts = "".join(
        f'<option value="{_esc(r)}">{_esc(r)}</option>' for r in VALID_DEVICE_ROLES
    )
    cat_opts = "".join(
        f'<option value="{_esc(c.value)}">{_esc(c.value)}</option>'
        for c in EquipmentCategory
    )
    pin_opts = ['<option value="">-- Automatic (Unpinned) --</option>'] + [
        f'<option value="{_esc(c.value)}">{_esc(c.value)}</option>'
        for c in ValidationClassification
    ]

    embedded_state_json = _safe_json_for_script(payload)
    topology_payload = graph.to_dict()
    topology_payload["mermaid"] = graph.to_mermaid()
    embedded_topology_json = _safe_json_for_script(topology_payload)
    faceplate_html = _render_switch_faceplate(site_dict, results_list, graph)
    topology_svg = _render_topology_svg(graph)
    mermaid_html = _esc(topology_payload["mermaid"])
    v2_script = _WORKBENCH_V2_SCRIPT
    bulk_import_script = _BULK_IMPORT_SCRIPT
    quality_css = QUALITY_CSS
    quality_script = QUALITY_SCRIPT
    page_markup = _render_page_markup(
        title=title,
        site_dict=site_dict,
        summary=summary,
        confirmed_cnt=confirmed_cnt,
        stale_cnt=stale_cnt,
        unreachable_cnt=unreachable_cnt,
        insufficient_cnt=insufficient_cnt,
        vlan_filter_opts=vlan_filter_opts,
        subnet_filter_opts=subnet_filter_opts,
        cls_filter_opts=cls_filter_opts,
        inventory_rows_html=inventory_rows_html,
        template_options_html=template_options_html,
        role_opts=role_opts,
        device_options_html=device_options_html,
        faceplate_html=faceplate_html,
        device_cards_html=device_cards_html,
        topology_svg=topology_svg,
        mermaid_html=mermaid_html,
        vlan_rows_html=vlan_rows_html,
        audit_rows_html=audit_rows_html,
        quality_section_html=quality_section_html,
        cat_opts=cat_opts,
        pin_opts=pin_opts,
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)} — {_esc(site_dict.get("name"))}</title>
<style>
{_PAGE_CSS}{quality_css}</style>
</head>
{page_markup}<script id="initial-workbench-state" type="application/json">{embedded_state_json}</script>
<script id="initial-topology" type="application/json">{embedded_topology_json}</script>
<script>
{_PAGE_SCRIPT}{v2_script}
{bulk_import_script}
{quality_script}
</script>
</body>
</html>
"""
