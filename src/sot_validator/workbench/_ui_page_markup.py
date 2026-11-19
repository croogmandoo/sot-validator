"""Workbench page <body> markup: header, KPI grid, filter bar and tab panels."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from sot_validator.workbench._ui_common import _esc


def _render_page_markup(
    *,
    title: str,
    site_dict: Mapping[str, Any],
    summary: Mapping[str, Any],
    confirmed_cnt: int,
    stale_cnt: int,
    unreachable_cnt: int,
    insufficient_cnt: int,
    vlan_filter_opts: Sequence[str],
    subnet_filter_opts: Sequence[str],
    cls_filter_opts: Sequence[str],
    inventory_rows_html: Sequence[str],
    template_options_html: Sequence[str],
    role_opts: str,
    device_options_html: Sequence[str],
    faceplate_html: str,
    device_cards_html: Sequence[str],
    topology_svg: str,
    mermaid_html: str,
    vlan_rows_html: Sequence[str],
    audit_rows_html: Sequence[str],
    quality_section_html: str,
    cat_opts: str,
    pin_opts: Sequence[str],
) -> str:
    """Render the page body up to the embedded state and script elements."""
    return f"""<body>
<header>
  <div>
    <h1>{_esc(title)}</h1>
    <small>Site: <strong id="site-header-name">{_esc(site_dict.get("name"))}</strong> (<code>{_esc(site_dict.get("site_id"))}</code>) — Address: {_esc(site_dict.get("address") or "N/A")}</small>
  </div>
  <div>
    <button type="button" class="btn btn-sm" onclick="refreshFromApi()">Refresh State</button>
  </div>
</header>

<div class="container">
  <div id="status-banner"></div>

  <!-- 1. Overview KPI Cards & Filter Bar -->
  <section id="kpi-overview" class="kpi-grid">
    <div class="kpi-card">
      <div class="label">Network Devices</div>
      <div class="value" id="kpi-total-devices">{summary["total_devices"]}</div>
      <div class="sub">Routers, Switches &amp; Hosts</div>
    </div>
    <div class="kpi-card">
      <div class="label">Switch / Router Ports</div>
      <div class="value" id="kpi-total-ports">{summary["total_ports"]}</div>
      <div class="sub"><span id="kpi-active-ports">{summary["active_ports"]}</span> UP / <span id="kpi-poe-ports">{summary["poe_ports"]}</span> PoE</div>
    </div>
    <div class="kpi-card">
      <div class="label">VLANs &amp; /24 Subnets</div>
      <div class="value"><span id="kpi-total-vlans">{summary["total_vlans"]}</span> / <span id="kpi-total-subnets">{summary["total_subnets"]}</span></div>
      <div class="sub">Segmented Networks</div>
    </div>
    <div class="kpi-card">
      <div class="label">Equipment &amp; IPs</div>
      <div class="value"><span id="kpi-total-equipment">{summary["total_equipment"]}</span> / <span id="kpi-total-ips">{summary["total_ips"]}</span></div>
      <div class="sub">Servers, VMs, UPS, SAN, IPs</div>
    </div>
    <div class="kpi-card">
      <div class="label">Validation Breakdown</div>
      <div class="value" id="kpi-confirmed-active">{confirmed_cnt} Active</div>
      <div class="sub">
        <span id="kpi-stale">{stale_cnt}</span> Stale ·
        <span id="kpi-unreachable">{unreachable_cnt}</span> Review ·
        <span id="kpi-insufficient">{insufficient_cnt}</span> Insuff
      </div>
    </div>
  </section>

  <section id="filter-bar" class="filter-bar">
    <input type="search" id="inventory-search" placeholder="Search hostname, ID, IP, MAC, notes..." oninput="applyInventoryFilters()">
    <select id="filter-vlan" onchange="applyInventoryFilters()">
      {"".join(vlan_filter_opts)}
    </select>
    <select id="filter-subnet" onchange="applyInventoryFilters()">
      {"".join(subnet_filter_opts)}
    </select>
    <select id="filter-classification" onchange="applyInventoryFilters()">
      {"".join(cls_filter_opts)}
    </select>
  </section>

  <!-- Navigation Tabs -->
  <nav class="tabs">
    <button type="button" class="tab-btn active" data-tab="tab-inventory" onclick="switchTab('tab-inventory')">Modifiable Inventory</button>
    <button type="button" class="tab-btn" data-tab="tab-devices-ports" onclick="switchTab('tab-devices-ports')">Routers, Switches &amp; Port Manager</button>
    <button type="button" class="tab-btn" data-tab="tab-topology" onclick="switchTab('tab-topology')">Topology Map</button>
    <button type="button" class="tab-btn" data-tab="tab-vlans" onclick="switchTab('tab-vlans')">VLAN &amp; Subnet Manager</button>
    <button type="button" class="tab-btn" data-tab="tab-audit-log" onclick="switchTab('tab-audit-log')">Audit Log</button>
    <button type="button" class="tab-btn" data-tab="tab-import" onclick="switchTab('tab-import')">Bulk Import</button>
    <button type="button" class="tab-btn" data-tab="tab-quality" onclick="switchTab('tab-quality')">Data Quality</button>
  </nav>

  <!-- 2. Modifiable Inventory Table Tab -->
  <section id="tab-inventory" class="tab-panel active">
    <table id="inventory-table">
      <thead>
        <tr>
          <th>Type</th>
          <th>ID</th>
          <th>Name / Hostname</th>
          <th>Category / Role</th>
          <th>Room</th>
          <th>VLAN / Subnet</th>
          <th>IPs / Ports</th>
          <th>Operator Notes</th>
          <th>Classification</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="inventory-tbody">
        {"".join(inventory_rows_html)}
      </tbody>
    </table>
  </section>

  <!-- 3. Routers, Switches & Port Manager Tab -->
  <section id="tab-devices-ports" class="tab-panel">
    <div class="grid-2">
      <div class="card">
        <h3>Add Network Device (Template or Custom)</h3>
        <form id="create-device-form" onsubmit="submitCreateDevice(event)">
          <div class="form-row">
            <label for="dev-hostname">Hostname *</label>
            <input type="text" id="dev-hostname" name="hostname" required placeholder="e.g. sw-idf2-01">
          </div>
          <div class="form-row">
            <label for="dev-device-id">Device ID (optional, auto-generated from hostname)</label>
            <input type="text" id="dev-device-id" name="device_id" placeholder="e.g. dev-sw-idf2-01">
          </div>
          <div class="form-row">
            <label for="dev-template-id">Hardware / Virtual Template</label>
            <select id="dev-template-id" name="template_id">
              {"".join(template_options_html)}
            </select>
          </div>
          <div class="form-row">
            <label for="dev-mgmt-ip">Management IP</label>
            <input type="text" id="dev-mgmt-ip" name="management_ip" placeholder="e.g. 10.1.1.10">
          </div>
          <div class="form-row">
            <label for="dev-role">Role Override</label>
            <select id="dev-role" name="role">
              <option value="">-- Use Template Default --</option>
              {role_opts}
            </select>
          </div>
          <div class="form-row">
            <label for="dev-port-count">Port Count Override</label>
            <input type="number" id="dev-port-count" name="port_count" min="0" max="256" placeholder="Default from template">
          </div>
          <div class="form-row">
            <label for="dev-default-vlan">Default VLAN ID</label>
            <input type="text" id="dev-default-vlan" name="default_vlan_id" placeholder="e.g. 10">
          </div>
          <div class="form-row">
            <label for="dev-reason">Audit Reason</label>
            <input type="text" id="dev-reason" name="reason" placeholder="Provisioned new closet switch">
          </div>
          <button type="submit" class="btn">Create Device</button>
        </form>
      </div>

      <div class="card">
        <h3>Switch / Router Port Manager (Single or Range)</h3>
        <form id="port-manager-form" onsubmit="submitPortManager(event)">
          <div class="form-row">
            <label for="pm-device-id">Target Network Device *</label>
            <select id="pm-device-id" name="device_id" required onchange="renderSwitchFaceplate()">
              {"".join(device_options_html)}
            </select>
          </div>
          <div class="form-row">
            <label for="pm-port-name">Single Port Name (e.g. <code>1:1</code>, <code>eth1</code>)</label>
            <input type="text" id="pm-port-name" name="name" placeholder="1:1">
          </div>
          <div class="form-row">
            <label for="pm-range-spec">Or Port Range Spec (e.g. <code>1:1..1:24</code>, <code>eth1..eth8</code>)</label>
            <input type="text" id="pm-range-spec" name="range_spec" placeholder="1:1..1:24">
          </div>
          <div class="form-row">
            <label for="pm-admin-status">Admin Status</label>
            <select id="pm-admin-status" name="admin_status">
              <option value="up">up</option>
              <option value="down">down</option>
            </select>
          </div>
          <div class="form-row">
            <label for="pm-oper-status">Operational Link Status</label>
            <select id="pm-oper-status" name="oper_status">
              <option value="up">up</option>
              <option value="down">down</option>
            </select>
          </div>
          <div class="form-row">
            <label for="pm-poe-status">PoE Status</label>
            <input type="text" id="pm-poe-status" name="poe_status" placeholder="delivering / auto / off">
          </div>
          <div class="form-row">
            <label for="pm-vlan-id">Assigned VLAN ID</label>
            <input type="text" id="pm-vlan-id" name="vlan_id" placeholder="e.g. 20">
          </div>
          <div class="form-row">
            <label for="pm-connected-mac">Connected Host MAC Address</label>
            <input type="text" id="pm-connected-mac" name="connected_mac" placeholder="aa:bb:cc:dd:ee:ff">
          </div>
          <div class="form-row">
            <label for="pm-connected-device">Connected Equipment / Device ID</label>
            <input type="text" id="pm-connected-device" name="connected_device_id" placeholder="eq-srv-01">
          </div>
          <div class="form-row">
            <label for="pm-reason">Audit Reason</label>
            <input type="text" id="pm-reason" name="reason" placeholder="Patched access ports to VLAN 20">
          </div>
          <button type="submit" class="btn">Provision / Update Ports</button>
        </form>
      </div>
    </div>

    {faceplate_html}

    <div id="device-port-grids">
      {"".join(device_cards_html)}
    </div>
  </section>

  <section id="tab-topology" class="tab-panel">
    <div id="topology-scroll" class="topology-scroll">
      {topology_svg}
    </div>
    <p class="topology-caption">Mermaid source</p>
    <pre id="topology-mermaid">{mermaid_html}</pre>
  </section>

  <!-- 4. VLAN & Subnet Manager Tab -->
  <section id="tab-vlans" class="tab-panel">
    <div class="grid-2">
      <div class="card">
        <h3>Add / Update VLAN &amp; /24 Subnet</h3>
        <form id="vlan-form" onsubmit="submitVlanForm(event)">
          <div class="form-row">
            <label for="vlan-id-input">VLAN ID *</label>
            <input type="text" id="vlan-id-input" name="vlan_id" required placeholder="e.g. 30">
          </div>
          <div class="form-row">
            <label for="vlan-name-input">VLAN Name</label>
            <input type="text" id="vlan-name-input" name="name" placeholder="e.g. Voice / VoIP">
          </div>
          <div class="form-row">
            <label for="vlan-subnet-id-input">Subnet ID (optional)</label>
            <input type="text" id="vlan-subnet-id-input" name="subnet_id" placeholder="e.g. sub-vlan-30">
          </div>
          <div class="form-row">
            <label for="vlan-cidr-input">IPv4 /24 CIDR</label>
            <input type="text" id="vlan-cidr-input" name="cidr" placeholder="e.g. 10.1.30.0/24">
          </div>
          <div class="form-row">
            <label for="vlan-gateway-input">Default Gateway IP</label>
            <input type="text" id="vlan-gateway-input" name="gateway" placeholder="e.g. 10.1.30.1">
          </div>
          <div class="form-row">
            <label for="vlan-reason-input">Audit Reason</label>
            <input type="text" id="vlan-reason-input" name="reason" placeholder="Added VLAN 30 subnet">
          </div>
          <button type="submit" class="btn">Save VLAN &amp; Subnet</button>
        </form>
      </div>

      <div class="card">
        <h3>Site VLAN &amp; /24 Subnet Summary</h3>
        <table id="vlan-summary-table">
          <thead>
            <tr>
              <th>VLAN ID</th>
              <th>Name</th>
              <th>Subnet ID</th>
              <th>CIDR</th>
              <th>Gateway</th>
              <th>IPs</th>
              <th>Switch Ports</th>
              <th>Equipment</th>
            </tr>
          </thead>
          <tbody id="vlan-summary-tbody">
            {"".join(vlan_rows_html)}
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- 5. Audit Log Tab -->
  <section id="tab-audit-log" class="tab-panel">
    <table id="audit-log-table">
      <thead>
        <tr>
          <th>Timestamp (UTC)</th>
          <th>Actor</th>
          <th>Action</th>
          <th>Target</th>
          <th>Changes</th>
          <th>Reason</th>
        </tr>
      </thead>
      <tbody id="audit-log-tbody">
        {"".join(audit_rows_html)}
      </tbody>
    </table>
  </section>

  <!-- 6. Bulk CSV Import Tab -->
  <section id="tab-import" class="tab-panel">
    <div class="card import-controls">
      <h3>Bulk CSV Curation Import</h3>
      <p class="import-help">Columns: <code>record_type, record_id, field, new_value, reason</code>. Preview first; Apply writes only the previewed changes.</p>
      <div class="import-row">
        <div class="form-row">
          <label for="import-file">CSV file</label>
          <input type="file" id="import-file" accept=".csv,text/csv" onchange="invalidateImportPreview()">
        </div>
        <div class="form-row">
          <label for="import-as-of">Conflict if changed after (optional)</label>
          <input type="datetime-local" id="import-as-of" onchange="invalidateImportPreview()" oninput="invalidateImportPreview()">
        </div>
        <div class="form-row">
          <label for="import-status-filter">Show status</label>
          <select id="import-status-filter" onchange="applyImportStatusFilter()">
            <option value="">all</option>
            <option value="change">change</option>
            <option value="no_op">no_op</option>
            <option value="conflict">conflict</option>
            <option value="invalid">invalid</option>
          </select>
        </div>
      </div>
      <div class="import-actions">
        <button type="button" class="btn" id="import-preview-btn" onclick="previewImport()">Preview</button>
        <button type="button" class="btn" id="import-apply-btn" onclick="applyImport()" disabled>Apply</button>
      </div>
      <div id="import-summary" class="import-summary" aria-live="polite"></div>
      <div id="import-messages" class="import-messages" role="status"></div>
    </div>
    <div class="import-scroll">
      <table id="import-preview-table">
        <thead>
          <tr>
            <th>Row</th>
            <th>Record Type</th>
            <th>Record ID</th>
            <th>Field</th>
            <th>Old Value</th>
            <th>New Value</th>
            <th>Status</th>
            <th>Reason</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody id="import-preview-tbody"></tbody>
      </table>
    </div>
  </section>

  <!-- 7. Data Quality Tab -->
  {quality_section_html}
</div>

<!-- Inline Item Edit Modal -->
<div id="item-edit-modal" class="modal-backdrop">
  <div class="modal">
    <h3>Edit Inventory Item</h3>
    <form id="item-edit-form" onsubmit="submitItemPatch(event)">
      <input type="hidden" id="edit-target-type" name="target_type">
      <input type="hidden" id="edit-target-id" name="target_id">
      <div class="form-row">
        <label for="edit-name">Name / Hostname</label>
        <input type="text" id="edit-name" name="name">
      </div>
      <div class="form-row">
        <label for="edit-category-role">Category / Device Role</label>
        <input type="text" id="edit-category-role" name="category_or_role" list="category-role-list">
        <datalist id="category-role-list">
          {cat_opts}
          {role_opts}
        </datalist>
      </div>
      <div class="form-row">
        <label for="edit-room">Room / Closet</label>
        <input type="text" id="edit-room" name="room" placeholder="e.g. Server Room B">
      </div>
      <div class="form-row">
        <label for="edit-vlan-id">VLAN ID</label>
        <input type="text" id="edit-vlan-id" name="vlan_id" placeholder="e.g. 10">
      </div>
      <div class="form-row">
        <label for="edit-notes">Operator Notes</label>
        <textarea id="edit-notes" name="notes" rows="2"></textarea>
      </div>
      <div class="form-row">
        <label for="edit-pinned-classification">Pin Validation Classification</label>
        <select id="edit-pinned-classification" name="pinned_classification">
          {"".join(pin_opts)}
        </select>
      </div>
      <div class="form-row">
        <label for="edit-reason">Audit Reason</label>
        <input type="text" id="edit-reason" name="reason" placeholder="Verified during site walkthrough">
      </div>
      <div style="display:flex; gap:0.5rem; justify-content:space-between; margin-top:1rem;">
        <button type="button" class="btn btn-danger" onclick="submitDeleteCurrentItem()">Delete Item</button>
        <div style="display:flex; gap:0.5rem;">
          <button type="button" class="btn" style="background:var(--panel-alt);color:var(--text);" onclick="closeEditModal()">Cancel</button>
          <button type="submit" class="btn">Save Changes</button>
        </div>
      </div>
    </form>
  </div>
</div>

"""
