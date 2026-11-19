"""Inline JavaScript for the topology/faceplate tab and the Bulk Import tab."""

from __future__ import annotations

import json

from sot_validator.workbench._ui_common import _FACEPLATE_TEMPLATES

_WORKBENCH_V2_SCRIPT = """
let TOPOLOGY_GRAPH = JSON.parse(document.getElementById('initial-topology').textContent);
const FACEPLATE_TEMPLATES = __FACEPLATE_TEMPLATES__;
const TOPO_COLUMN_ORDER = ['site', 'router', 'switch', 'vlan', 'subnet', 'port', 'equipment', 'ip'];
const TOPO_NODE_W = 200;
const TOPO_NODE_H = 56;
const TOPO_COL_WIDTH = 224;
const TOPO_ROW_HEIGHT = 56;
const TOPO_PAD_X = 24;
const TOPO_PAD_Y = 36;
const FACEPLATE_STATE_LABEL = {
  'faceplate-stale': 'Stale',
  'faceplate-uplink': 'Uplink',
  'faceplate-up': 'Up',
  'faceplate-down': 'Down'
};

function templatePortsAttr(vendor, model) {
  const v = String(vendor || '').trim().toLowerCase();
  const m = String(model || '').trim().toLowerCase();
  for (let i = 0; i < FACEPLATE_TEMPLATES.length; i++) {
    const row = FACEPLATE_TEMPLATES[i];
    if (v === row[0] && m === row[1]) return row[2];
  }
  return null;
}

function faceplateColumns(portCount) {
  if (portCount === 24) return 12;
  if (portCount === 48) return 24;
  if (!portCount || portCount < 0) return 0;
  return Math.ceil(portCount / 2);
}

function poeBadgeText(poeStatus) {
  if (poeStatus === null || poeStatus === undefined) return '';
  const text = String(poeStatus).trim();
  const lower = text.toLowerCase();
  if (!text || lower === 'off' || lower === 'disabled' || lower === 'none') return '';
  return text;
}

function portIsStale(device, port, results, equipment) {
  const hostname = device.hostname || '';
  const deviceId = device.device_id || '';
  const portId = port.port_id || '';
  const portName = port.name || '';
  const connected = port.connected_device_id || '';
  const nameKey = hostname + ':' + portName;
  const refs = {};
  [portId, deviceId + ':' + portName, hostname + ':' + portName, portName].forEach(ref => {
    if (ref) refs[ref] = true;
  });
  const touching = {};
  (equipment || []).forEach(eq => {
    const connectedPorts = eq.connected_ports || [];
    for (let i = 0; i < connectedPorts.length; i++) {
      if (refs[connectedPorts[i]]) {
        touching[eq.equipment_id] = true;
        break;
      }
    }
  });
  for (let i = 0; i < (results || []).length; i++) {
    const res = results[i];
    if (res.classification !== 'Stale / Likely Unused') continue;
    const itemId = res.item_id || '';
    if (itemId === portId) return true;
    if (res.name === nameKey) return true;
    if (connected && itemId === connected) return true;
    if (touching[itemId]) return true;
  }
  return false;
}

function portIsUplink(device, port, graph) {
  const portName = String(port.name || '');
  const lowered = portName.toLowerCase();
  if (lowered.indexOf('trunk') !== -1 || lowered.indexOf('uplink') !== -1) return true;
  const deviceId = device.device_id || '';
  const ids = {};
  ids[deviceId] = true;
  ids['router:' + deviceId] = true;
  ids['switch:' + deviceId] = true;
  const edges = (graph && graph.edges) || [];
  for (let i = 0; i < edges.length; i++) {
    const edge = edges[i];
    if (edge.relation !== 'uplink_to' || edge.port_name !== portName) continue;
    if (ids[edge.source_id] || ids[edge.target_id]) return true;
  }
  return false;
}

function faceplateAccessName(portName, fill, poe) {
  const state = FACEPLATE_STATE_LABEL[fill] || 'Down';
  let name = portName + ', ' + state;
  if (poe) name += ', PoE ' + poe;
  return name;
}

function renderSwitchFaceplate() {
  const site = (WORKBENCH_STATE && WORKBENCH_STATE.site) || {};
  const devices = site.devices || [];
  const sel = document.getElementById('pm-device-id');
  const selectedId = sel ? sel.value : '';
  const device = devices.find(d => d.device_id === selectedId) || devices[0] || null;
  const face = document.getElementById('switch-faceplate');
  const heading = document.getElementById('faceplate-hostname');
  if (heading) heading.textContent = device ? (device.hostname || '') : '';
  if (!face) return;
  if (!device) {
    face.setAttribute('data-device-id', '');
    face.setAttribute('data-rows', '2');
    face.setAttribute('data-faceplate-columns', '0');
    face.removeAttribute('data-template-ports');
    face.style.gridTemplateColumns = '';
    face.innerHTML = '<em>No ports provisioned</em>';
    return;
  }
  const ports = device.ports || [];
  const columns = faceplateColumns(ports.length);
  const templatePorts = templatePortsAttr(device.vendor, device.model);
  face.setAttribute('data-device-id', device.device_id || '');
  face.setAttribute('data-rows', '2');
  face.setAttribute('data-faceplate-columns', String(columns));
  if (templatePorts) face.setAttribute('data-template-ports', templatePorts);
  else face.removeAttribute('data-template-ports');
  face.style.gridTemplateColumns = columns
    ? 'repeat(' + columns + ', minmax(5rem, max-content))'
    : '';
  if (!ports.length) {
    face.innerHTML = '<em>No ports provisioned</em>';
    return;
  }
  const results = (WORKBENCH_STATE && WORKBENCH_STATE.results) || [];
  const equipment = site.equipment || [];
  const activeName = (document.getElementById('pm-port-name').value || '');
  face.innerHTML = ports.map(port => {
    let fill = 'faceplate-down';
    if (portIsStale(device, port, results, equipment)) fill = 'faceplate-stale';
    else if (portIsUplink(device, port, TOPOLOGY_GRAPH)) fill = 'faceplate-uplink';
    else if (String(port.oper_status || '').trim().toLowerCase() === 'up') fill = 'faceplate-up';
    const poe = poeBadgeText(port.poe_status);
    const badge = poe
      ? '<span class="' + 'faceplate-poe-badge' + '">' + escapeHtml(poe) + '</span>'
      : '';
    const access = faceplateAccessName(port.name || '', fill, poe);
    const selected = activeName && port.name === activeName;
    return '<button type="button" class="' + 'faceplate-port' + ' ' + fill
      + (selected ? ' faceplate-selected' : '')
      + '" data-port-id="' + escapeHtml(port.port_id)
      + '" data-port-name="' + escapeHtml(port.name)
      + '" title="' + escapeHtml(access)
      + '" aria-label="' + escapeHtml(access) + '"'
      + (selected ? ' aria-current="true"' : '')
      + '>'
      + escapeHtml(port.name) + badge + '</button>';
  }).join('');
}

function drawTopology(graph) {
  const nodes = (graph && graph.nodes) || [];
  const edges = (graph && graph.edges) || [];
  const grouped = {};
  TOPO_COLUMN_ORDER.forEach(nodeType => { grouped[nodeType] = []; });
  nodes.forEach(node => {
    if (!grouped[node.node_type]) grouped[node.node_type] = [];
    grouped[node.node_type].push(node);
  });
  const positions = {};
  let maxRows = 1;
  TOPO_COLUMN_ORDER.forEach((nodeType, colIndex) => {
    const columnNodes = grouped[nodeType] || [];
    if (columnNodes.length > maxRows) maxRows = columnNodes.length;
    columnNodes.forEach((node, rowIndex) => {
      positions[node.node_id] = {
        x: TOPO_PAD_X + colIndex * TOPO_COL_WIDTH,
        y: TOPO_PAD_Y + rowIndex * TOPO_ROW_HEIGHT
      };
    });
  });
  const width = TOPO_PAD_X * 2 + TOPO_COLUMN_ORDER.length * TOPO_COL_WIDTH;
  const height = TOPO_PAD_Y + maxRows * TOPO_ROW_HEIGHT + 16;
  const svg = document.getElementById('topology-svg');
  svg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
  svg.setAttribute('width', String(width));
  svg.setAttribute('height', String(height));
  svg.style.width = width + 'px';
  svg.style.height = height + 'px';
  const lines = edges.map(edge => {
    const src = positions[edge.source_id] || {x: 0, y: 0};
    const dst = positions[edge.target_id] || {x: 0, y: 0};
    const ends = edgeEndpoints(src, dst);
    return '<line class="' + 'topo-edge' + '" data-relation="' + escapeHtml(edge.relation)
      + '" x1="' + ends.x1 + '" y1="' + ends.y1 + '" x2="' + ends.x2 + '" y2="' + ends.y2 + '" />';
  }).join('');
  const textY = TOPO_NODE_H / 2;
  const groups = nodes.map(node => {
    const pos = positions[node.node_id] || {x: 0, y: 0};
    const access = (node.node_type || '') + ' ' + (node.label || '');
    return '<g class="' + 'topo-node' + '" data-node-id="' + escapeHtml(node.node_id)
      + '" data-node-type="' + escapeHtml(node.node_type)
      + '" role="button" tabindex="0" aria-label="' + escapeHtml(access)
      + '" transform="translate(' + pos.x + ',' + pos.y + ')">'
      + '<rect class="topo-node-box" width="' + TOPO_NODE_W + '" height="' + TOPO_NODE_H
      + '" rx="6" ry="6"></rect><text x="12" y="' + textY
      + '" dominant-baseline="middle">' + escapeHtml(node.label) + '</text></g>';
  }).join('');
  svg.innerHTML = lines + groups;
  document.getElementById('topology-mermaid').innerHTML = escapeHtml((graph && graph.mermaid) || '');
}

function edgeEndpoints(src, dst) {
  const syMid = src.y + TOPO_NODE_H / 2;
  const dyMid = dst.y + TOPO_NODE_H / 2;
  const sxMid = src.x + TOPO_NODE_W / 2;
  const dxMid = dst.x + TOPO_NODE_W / 2;
  if (src.x + TOPO_NODE_W <= dst.x) {
    return {x1: src.x + TOPO_NODE_W, y1: syMid, x2: dst.x, y2: dyMid};
  }
  if (dst.x + TOPO_NODE_W <= src.x) {
    return {x1: src.x, y1: syMid, x2: dst.x + TOPO_NODE_W, y2: dyMid};
  }
  if (src.y + TOPO_NODE_H <= dst.y) {
    return {x1: sxMid, y1: src.y + TOPO_NODE_H, x2: dxMid, y2: dst.y};
  }
  if (dst.y + TOPO_NODE_H <= src.y) {
    return {x1: sxMid, y1: src.y, x2: dxMid, y2: dst.y + TOPO_NODE_H};
  }
  return {x1: sxMid, y1: syMid, x2: dxMid, y2: dyMid};
}

async function refreshTopologyMap() {
  try {
    const resp = await fetch('/api/topology');
    if (!resp.ok) {
      showBanner('Topology map could not be refreshed.', true);
      return;
    }
    const data = await resp.json();
    TOPOLOGY_GRAPH = data;
    drawTopology(data);
    renderSwitchFaceplate();
  } catch (err) {
    showBanner('Topology map could not be refreshed.', true);
  }
}

function fillPortManagerForm(deviceId, fields) {
  switchTab('tab-devices-ports');
  const devSel = document.getElementById('pm-device-id');
  if (deviceId) devSel.value = deviceId;
  document.getElementById('pm-port-name').value = fields.name || '';
  document.getElementById('pm-range-spec').value = '';
  document.getElementById('pm-admin-status').value = fields.admin_status || '';
  document.getElementById('pm-oper-status').value = fields.oper_status || '';
  document.getElementById('pm-poe-status').value = fields.poe_status || '';
  document.getElementById('pm-vlan-id').value = fields.vlan_id || '';
  document.getElementById('pm-connected-mac').value = fields.connected_mac || '';
  document.getElementById('pm-connected-device').value = fields.connected_device_id || '';
  renderSwitchFaceplate();
}

function onTopologyNodeClick(el) {
  document.querySelectorAll('.topo-node').forEach(nodeEl => {
    nodeEl.classList.remove('topo-selected');
  });
  el.classList.add('topo-selected');
  const nodeId = el.getAttribute('data-node-id');
  const nodeType = el.getAttribute('data-node-type');
  const nodes = (TOPOLOGY_GRAPH && TOPOLOGY_GRAPH.nodes) || [];
  let node = null;
  for (let i = 0; i < nodes.length; i++) {
    if (nodes[i].node_id === nodeId) {
      node = nodes[i];
      break;
    }
  }
  if (nodeType === 'site' || nodeType === 'subnet') {
    return;
  }
  if (!node) return;
  if (nodeType === 'router' || nodeType === 'switch') {
    openEditModal('NetworkDevice', node.node_id);
    return;
  }
  if (nodeType === 'equipment') {
    openEditModal('Equipment', node.node_id);
    return;
  }
  if (nodeType === 'ip') {
    openEditModal('IPAddress', node.node_id);
    return;
  }
  if (nodeType === 'port') {
    const meta = node.metadata || {};
    fillPortManagerForm(meta.device_id, {
      name: meta.name,
      admin_status: meta.admin_status,
      oper_status: meta.oper_status,
      poe_status: meta.poe_status,
      vlan_id: node.vlan_id || meta.vlan_id,
      connected_mac: node.mac || meta.connected_mac,
      connected_device_id: meta.connected_device_id
    });
    return;
  }
  if (nodeType === 'vlan') {
    switchTab('tab-vlans');
    const meta = node.metadata || {};
    document.getElementById('vlan-id-input').value = node.vlan_id || '';
    document.getElementById('vlan-name-input').value = node.label || '';
    document.getElementById('vlan-subnet-id-input').value = meta.subnet_id || '';
    document.getElementById('vlan-cidr-input').value = meta.cidr || '';
    document.getElementById('vlan-gateway-input').value = meta.gateway || '';
  }
}

function onFaceplatePortClick(btn) {
  const portId = btn.getAttribute('data-port-id');
  const face = btn.closest('#switch-faceplate');
  const site = (WORKBENCH_STATE && WORKBENCH_STATE.site) || {};
  const sel = document.getElementById('pm-device-id');
  const deviceId = (sel && sel.value) || (face ? face.getAttribute('data-device-id') : '');
  const device = (site.devices || []).find(d => d.device_id === deviceId);
  if (!device) return;
  const port = (device.ports || []).find(p => p.port_id === portId);
  if (!port) return;
  fillPortManagerForm(device.device_id, {
    name: port.name,
    admin_status: port.admin_status,
    oper_status: port.oper_status,
    poe_status: port.poe_status,
    vlan_id: port.vlan_id,
    connected_mac: port.connected_mac,
    connected_device_id: port.connected_device_id
  });
  const nameField = document.getElementById('pm-port-name');
  if (nameField && nameField.scrollIntoView) {
    nameField.scrollIntoView({block: 'center'});
  }
}

document.getElementById('pm-device-id').addEventListener('change', renderSwitchFaceplate);
document.getElementById('topology-svg').addEventListener('click', ev => {
  const el = ev.target.closest ? ev.target.closest('.topo-node') : null;
  if (el) onTopologyNodeClick(el);
});
document.getElementById('topology-svg').addEventListener('keydown', ev => {
  if (ev.key !== 'Enter' && ev.key !== ' ') return;
  const el = ev.target.closest ? ev.target.closest('.topo-node') : null;
  if (!el) return;
  ev.preventDefault();
  onTopologyNodeClick(el);
});
document.getElementById('switch-faceplate').addEventListener('click', ev => {
  const btn = ev.target.closest ? ev.target.closest('.faceplate-port') : null;
  if (btn) onFaceplatePortClick(btn);
});
""".replace(
    "__FACEPLATE_TEMPLATES__",
    json.dumps([list(row) for row in _FACEPLATE_TEMPLATES]),
)


# Bulk Import tab behaviour. Every CSV-derived value is rendered through escapeHtml().
_BULK_IMPORT_SCRIPT = """
let IMPORT_LAST = null;
const IMPORT_STATUS_BADGE = {
  change: 'badge-info',
  no_op: 'badge-insufficient',
  conflict: 'badge-unreachable',
  invalid: 'badge-stale'
};

function importStatusBadge(status, text) {
  return '<span class="badge ' + (IMPORT_STATUS_BADGE[status] || 'badge-insufficient') + '">' + escapeHtml(text) + '</span>';
}

function importStatusMessage(status, data, fallback) {
  if (status === 413) {
    return 'CSV file is too large for the workbench upload limit: split it into smaller files.';
  }
  if (status === 409) {
    return 'Import refused: ' + ((data && data.error) || 'the preview is out of date; preview again');
  }
  if (status === 0) {
    return fallback + ' The server closed the connection; the CSV file may be too large for the workbench upload limit.';
  }
  return authFailureMessage(status) || (data && data.error) || fallback;
}

function setImportMessages(html, neutral) {
  const el = document.getElementById('import-messages');
  el.classList.toggle('import-messages-neutral', !!neutral);
  el.innerHTML = html;
}

function invalidateImportPreview() {
  IMPORT_LAST = null;
  document.getElementById('import-apply-btn').disabled = true;
}

function clearImportPreview() {
  invalidateImportPreview();
  document.getElementById('import-preview-tbody').innerHTML = '';
  document.getElementById('import-summary').textContent = '';
}

function formatImportValue(val) {
  if (val === null || val === undefined) return '';
  return String(val);
}

function renderImportPreview(preview) {
  const tbody = document.getElementById('import-preview-tbody');
  tbody.innerHTML = (preview.rows || []).map(row => (
    '<tr data-import-status="' + escapeHtml(row.status) + '">' +
    '<td>' + escapeHtml(row.row_number) + '</td>' +
    '<td>' + escapeHtml(row.record_type) + '</td>' +
    '<td>' + escapeHtml(row.record_id) + '</td>' +
    '<td>' + escapeHtml(row.field) + '</td>' +
    '<td>' + escapeHtml(formatImportValue(row.old_value)) + '</td>' +
    '<td>' + escapeHtml(formatImportValue(row.new_value)) + '</td>' +
    '<td>' + importStatusBadge(row.status, row.status) + '</td>' +
    '<td>' + escapeHtml(row.reason) + '</td>' +
    '<td>' + escapeHtml(row.detail) + '</td>' +
    '</tr>'
  )).join('');
  const counts = preview.counts || {};
  document.getElementById('import-summary').innerHTML = ['change', 'no_op', 'conflict', 'invalid'].map(
    s => importStatusBadge(s, s + ': ' + (counts[s] || 0))
  ).join(' ');
  applyImportStatusFilter();
}

function applyImportStatusFilter() {
  const wanted = document.getElementById('import-status-filter').value;
  document.querySelectorAll('#import-preview-tbody tr').forEach(tr => {
    tr.style.display = (!wanted || tr.dataset.importStatus === wanted) ? '' : 'none';
  });
}

function importAsOfValue() {
  const raw = document.getElementById('import-as-of').value;
  if (!raw) return null;
  const parsed = new Date(raw);
  if (isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

async function postImport(route, payload) {
  let resp;
  try {
    resp = await fetch(route, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + workbenchToken() },
      body: JSON.stringify(payload)
    });
  } catch (err) {
    return { status: 0, data: {} };
  }
  let data = {};
  try {
    data = await resp.json();
  } catch (err) {
    data = {};
  }
  return { status: resp.status, ok: resp.ok, data: data };
}

async function previewImport() {
  clearImportPreview();
  setImportMessages('');
  const input = document.getElementById('import-file');
  const file = input.files && input.files[0];
  if (!file) {
    setImportMessages(escapeHtml('Choose a CSV file to preview.'), true);
    return;
  }
  const csvText = await file.text();
  const asOf = importAsOfValue();
  const result = await postImport('/api/curation/preview', { csv: csvText, as_of: asOf });
  if (result.ok && result.data.preview) {
    const preview = result.data.preview;
    renderImportPreview(preview);
    IMPORT_LAST = { csv: csvText, as_of: asOf, confirm_token: preview.confirm_token };
    document.getElementById('import-apply-btn').disabled = !preview.can_apply;
    if (!preview.can_apply) {
      const blocked = preview.counts.conflict || preview.counts.invalid;
      setImportMessages(escapeHtml(
        blocked
          ? 'Apply is disabled: fix the conflict and invalid rows, then preview again.'
          : 'Nothing to apply: every row matches the current values.'
      ), !blocked);
    }
    return;
  }
  const errors = (result.data && result.data.errors) || [];
  if (result.status === 400 && errors.length) {
    setImportMessages('CSV has errors:<ul>' + errors.map(
      e => '<li>' + escapeHtml('row ' + e.row + ': ' + e.message) + '</li>'
    ).join('') + '</ul>');
    return;
  }
  setImportMessages(escapeHtml(importStatusMessage(result.status, result.data, 'Preview failed.')));
}

async function applyImport() {
  if (!IMPORT_LAST) return;
  const pending = IMPORT_LAST;
  document.getElementById('import-apply-btn').disabled = true;
  const result = await postImport('/api/curation/apply', {
    csv: pending.csv,
    as_of: pending.as_of,
    confirm_token: pending.confirm_token
  });
  if (result.ok && result.data.state) {
    renderState(result.data.state);
    clearImportPreview();
    setImportMessages('');
    document.getElementById('import-file').value = '';
    showBanner('Applied ' + result.data.applied + ' change(s) as batch ' + result.data.batch_id, false);
    return;
  }
  invalidateImportPreview();
  const message = importStatusMessage(result.status, result.data, 'Apply failed.');
  setImportMessages(escapeHtml(message));
  showBanner(message, true);
}
"""
