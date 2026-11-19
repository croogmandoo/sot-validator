"""Core workbench page JavaScript: state, auth token, tabs, filters and edit forms."""

from __future__ import annotations

_PAGE_SCRIPT = """let WORKBENCH_STATE = JSON.parse(document.getElementById('initial-workbench-state').textContent);

const WORKBENCH_TOKEN_KEY = 'sot-validator-workbench-token';

function workbenchToken() {
  try {
    return window.sessionStorage.getItem(WORKBENCH_TOKEN_KEY) || '';
  } catch (err) {
    return '';
  }
}

function loadWorkbenchToken() {
  try {
    const hash = window.location.hash || '';
    if (hash.length > 1) {
      const fragmentToken = new URLSearchParams(hash.slice(1)).get('token');
      if (fragmentToken) {
        window.sessionStorage.setItem(WORKBENCH_TOKEN_KEY, fragmentToken);
        if (window.history && window.history.replaceState) {
          window.history.replaceState(
            null, '', window.location.pathname + window.location.search
          );
        }
        return fragmentToken;
      }
    }
  } catch (err) {
    return '';
  }
  return workbenchToken();
}

loadWorkbenchToken();

function authFailureMessage(status) {
  if (status === 401) {
    if (!workbenchToken()) {
      return 'No workbench token set: reload this page with #token=<token> to enable edits.';
    }
    return 'Workbench token rejected: check the token and reload this page with #token=<token>.';
  }
  if (status === 403) {
    return 'Write rejected as cross-origin: open the workbench at its own address and reload with #token=<token>.';
  }
  if (status === 413) {
    return 'Request too large: shorten the form and try again.';
  }
  return '';
}

function escapeHtml(val) {
  if (val === null || val === undefined) return '';
  return String(val)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function badgeClass(cls) {
  if (cls === 'Confirmed Active') return 'badge-active';
  if (cls === 'Stale / Likely Unused') return 'badge-stale';
  if (cls === 'Unreachable / Needs Manual Review') return 'badge-unreachable';
  return 'badge-insufficient';
}

function showBanner(msg, isError) {
  const el = document.getElementById('status-banner');
  el.style.display = 'block';
  el.style.background = isError ? 'rgba(239, 68, 68, 0.25)' : 'rgba(34, 197, 94, 0.25)';
  el.style.border = isError ? '1px solid #ef4444' : '1px solid #22c55e';
  el.textContent = msg;
}

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  });
  document.querySelectorAll('.tab-panel').forEach(panel => {
    panel.classList.toggle('active', panel.id === tabId);
  });
}

function renderState(state) {
  WORKBENCH_STATE = state;
  const s = state.summary || {};
  const clsCounts = s.classification_counts || {};
  document.getElementById('kpi-total-devices').textContent = s.total_devices || 0;
  document.getElementById('kpi-total-ports').textContent = s.total_ports || 0;
  document.getElementById('kpi-active-ports').textContent = s.active_ports || 0;
  document.getElementById('kpi-poe-ports').textContent = s.poe_ports || 0;
  document.getElementById('kpi-total-vlans').textContent = s.total_vlans || 0;
  document.getElementById('kpi-total-subnets').textContent = s.total_subnets || 0;
  document.getElementById('kpi-total-equipment').textContent = s.total_equipment || 0;
  document.getElementById('kpi-total-ips').textContent = s.total_ips || 0;
  document.getElementById('kpi-confirmed-active').textContent = (clsCounts['Confirmed Active'] || 0) + ' Active';
  document.getElementById('kpi-stale').textContent = clsCounts['Stale / Likely Unused'] || 0;
  document.getElementById('kpi-unreachable').textContent = clsCounts['Unreachable / Needs Manual Review'] || 0;
  document.getElementById('kpi-insufficient').textContent = clsCounts['Insufficient Data'] || 0;

  const resMap = {};
  (state.results || []).forEach(r => { resMap[r.item_type + ':' + r.item_id] = r; });
  const patchMap = {};
  (state.patches || []).forEach(p => { if (!p.deleted) patchMap[p.target_type + ':' + p.target_id] = p; });

  const site = state.site || {};
  const invRows = [];
  (site.devices || []).forEach(dev => {
    const key = 'NetworkDevice:' + dev.device_id;
    const res = resMap[key] || {};
    const patch = patchMap[key] || {};
    const cls = res.classification || 'Insufficient Data';
    const room = patch.room || '';
    const vlan = patch.vlan_id || '';
    const notes = patch.notes || '';
    const pCount = (dev.ports || []).length;
    invRows.push(`<tr data-target-type="NetworkDevice" data-target-id="${escapeHtml(dev.device_id)}" data-vlan="${escapeHtml(vlan)}" data-classification="${escapeHtml(cls)}">
      <td><code>NetworkDevice</code></td>
      <td><code>${escapeHtml(dev.device_id)}</code></td>
      <td><strong>${escapeHtml(dev.hostname)}</strong></td>
      <td>${escapeHtml(dev.role || 'switch')} (${escapeHtml(dev.vendor || '')} ${escapeHtml(dev.model || '')})</td>
      <td>${escapeHtml(room)}</td>
      <td>${escapeHtml(vlan)}</td>
      <td>${escapeHtml(dev.management_ip || '')} (${pCount} ports)</td>
      <td>${escapeHtml(notes)}</td>
      <td><span class="badge ${badgeClass(cls)}">${escapeHtml(cls)}</span></td>
      <td><button type="button" class="btn btn-sm" onclick="openEditModal('NetworkDevice', '${escapeHtml(dev.device_id)}')">Edit</button></td>
    </tr>`);
  });

  (site.equipment || []).forEach(eq => {
    const key = 'Equipment:' + eq.equipment_id;
    const res = resMap[key] || {};
    const patch = patchMap[key] || {};
    const cls = res.classification || 'Insufficient Data';
    const custom = patch.custom_attributes || {};
    const room = patch.room || custom.room || '';
    const vlan = patch.vlan_id || custom.vlan_id || '';
    const notes = patch.notes || '';
    const ips = (eq.assigned_ips || []).join(', ');
    const ports = (eq.connected_ports || []).join(', ');
    invRows.push(`<tr data-target-type="Equipment" data-target-id="${escapeHtml(eq.equipment_id)}" data-vlan="${escapeHtml(vlan)}" data-classification="${escapeHtml(cls)}">
      <td><code>Equipment</code></td>
      <td><code>${escapeHtml(eq.equipment_id)}</code></td>
      <td><strong>${escapeHtml(eq.name)}</strong></td>
      <td>${escapeHtml(eq.category)}</td>
      <td>${escapeHtml(room)}</td>
      <td>${escapeHtml(vlan)}</td>
      <td>${escapeHtml(ips)} ${ports ? '[' + escapeHtml(ports) + ']' : ''}</td>
      <td>${escapeHtml(notes)}</td>
      <td><span class="badge ${badgeClass(cls)}">${escapeHtml(cls)}</span></td>
      <td><button type="button" class="btn btn-sm" onclick="openEditModal('Equipment', '${escapeHtml(eq.equipment_id)}')">Edit</button></td>
    </tr>`);
  });

  (site.ip_addresses || []).forEach(ipRec => {
    const key = 'IPAddress:' + ipRec.ip;
    const res = resMap[key] || {};
    const patch = patchMap[key] || {};
    const cls = res.classification || 'Insufficient Data';
    const notes = patch.notes || '';
    invRows.push(`<tr data-target-type="IPAddress" data-target-id="${escapeHtml(ipRec.ip)}" data-subnet="${escapeHtml(ipRec.subnet_id || '')}" data-classification="${escapeHtml(cls)}">
      <td><code>IPAddress</code></td>
      <td><code>${escapeHtml(ipRec.ip)}</code></td>
      <td><strong>${escapeHtml(patch.name || ipRec.ip)}</strong></td>
      <td>IP Assignment</td>
      <td>${escapeHtml(patch.room || '')}</td>
      <td>${escapeHtml(ipRec.subnet_id || '')}</td>
      <td>${escapeHtml(ipRec.assigned_object_id || '')} ${escapeHtml(ipRec.arp_mac || '')}</td>
      <td>${escapeHtml(notes)}</td>
      <td><span class="badge ${badgeClass(cls)}">${escapeHtml(cls)}</span></td>
      <td><button type="button" class="btn btn-sm" onclick="openEditModal('IPAddress', '${escapeHtml(ipRec.ip)}')">Edit</button></td>
    </tr>`);
  });
  document.getElementById('inventory-tbody').innerHTML = invRows.join('');

  // Update device select and port grids
  const devSelect = document.getElementById('pm-device-id');
  devSelect.innerHTML = (site.devices || []).map(d =>
    `<option value="${escapeHtml(d.device_id)}">${escapeHtml(d.hostname)} (${escapeHtml(d.device_id)})</option>`
  ).join('');

  const devCards = (site.devices || []).map(d => {
    const chips = (d.ports || []).map(p => {
      const oper = (p.oper_status || 'down').toLowerCase();
      const cls = oper === 'up' ? 'port-up' : 'port-down';
      const meta = [
        p.vlan_id ? 'V' + p.vlan_id : '',
        p.poe_status ? '⚡' + p.poe_status : '',
        p.connected_mac ? 'MAC:' + p.connected_mac : ''
      ].filter(Boolean).join(' ');
      return `<div class="port-chip ${cls}">
        <span class="port-name">${escapeHtml(p.name)}</span>
        <span class="port-meta">${escapeHtml(meta)}</span>
      </div>`;
    }).join('');
    return `<div class="device-card" data-device-id="${escapeHtml(d.device_id)}">
      <div class="device-card-header">
        <strong>${escapeHtml(d.hostname)}</strong> <code>(${escapeHtml(d.device_id)})</code> —
        ${escapeHtml(d.vendor || '')} ${escapeHtml(d.model || '')} [${escapeHtml(d.role || 'switch')}]
        IP: <code>${escapeHtml(d.management_ip || 'N/A')}</code>
      </div>
      <div class="port-grid">${chips || '<em>No ports provisioned</em>'}</div>
    </div>`;
  }).join('');
  document.getElementById('device-port-grids').innerHTML = devCards;

  // Update VLAN summary table
  const vlanRows = (state.vlan_subnet_summary || []).map(vs => `<tr>
    <td><code>${escapeHtml(vs.vlan_id || '-')}</code></td>
    <td><strong>${escapeHtml(vs.vlan_name || '-')}</strong></td>
    <td><code>${escapeHtml(vs.subnet_id || '-')}</code></td>
    <td><code>${escapeHtml(vs.cidr || '-')}</code></td>
    <td><code>${escapeHtml(vs.gateway || '-')}</code></td>
    <td>${Number(vs.ip_count || 0)}</td>
    <td>${Number(vs.device_port_count || 0)}</td>
    <td>${Number(vs.equipment_count || 0)}</td>
  </tr>`).join('');
  document.getElementById('vlan-summary-tbody').innerHTML = vlanRows;

  // Update Audit log table
  const auditRows = (state.audit_log || []).map(a => `<tr>
    <td><code>${escapeHtml(a.timestamp)}</code></td>
    <td>${escapeHtml(a.actor)}</td>
    <td><span class="badge badge-info">${escapeHtml(a.action)}</span></td>
    <td><code>${escapeHtml(a.target_type)}:${escapeHtml(a.target_id)}</code></td>
    <td><code>${escapeHtml(JSON.stringify(a.changes || {}))}</code></td>
    <td>${escapeHtml(a.reason)}</td>
  </tr>`).join('');
  document.getElementById('audit-log-tbody').innerHTML = auditRows;

  applyInventoryFilters();
  renderSwitchFaceplate();
  refreshTopologyMap();
  refreshQualityFindings();
}

function applyInventoryFilters() {
  const q = (document.getElementById('inventory-search').value || '').toLowerCase();
  const vlan = document.getElementById('filter-vlan').value || '';
  const subnet = document.getElementById('filter-subnet').value || '';
  const cls = document.getElementById('filter-classification').value || '';

  document.querySelectorAll('#inventory-tbody tr').forEach(row => {
    const text = row.textContent.toLowerCase();
    const rowVlan = row.getAttribute('data-vlan') || '';
    const rowSubnet = row.getAttribute('data-subnet') || '';
    const rowCls = row.getAttribute('data-classification') || '';
    const matchQ = !q || text.includes(q);
    const matchVlan = !vlan || rowVlan === vlan;
    const matchSubnet = !subnet || rowSubnet === subnet;
    const matchCls = !cls || rowCls === cls;
    row.style.display = (matchQ && matchVlan && matchSubnet && matchCls) ? '' : 'none';
  });
}

async function refreshFromApi() {
  const resp = await fetch('/api/state');
  if (resp.ok) {
    const data = await resp.json();
    renderState(data);
  }
}

async function refreshAuditLog() {
  const resp = await fetch('/api/audit-log');
  if (resp.ok) {
    const data = await resp.json();
    if (data.audit_log) {
      WORKBENCH_STATE.audit_log = data.audit_log;
      renderState(WORKBENCH_STATE);
    }
  }
}

function openEditModal(targetType, targetId) {
  document.getElementById('edit-target-type').value = targetType;
  document.getElementById('edit-target-id').value = targetId;
  const site = WORKBENCH_STATE.site || {};
  const patches = WORKBENCH_STATE.patches || [];
  const patch = patches.find(p => p.target_type === targetType && p.target_id === targetId && !p.deleted) || {};

  let name = patch.name || patch.hostname || '';
  let catRole = patch.category || patch.role || '';
  if (targetType === 'NetworkDevice') {
    const dev = (site.devices || []).find(d => d.device_id === targetId) || {};
    name = name || dev.hostname || '';
    catRole = catRole || dev.role || '';
  } else if (targetType === 'Equipment') {
    const eq = (site.equipment || []).find(e => e.equipment_id === targetId) || {};
    name = name || eq.name || '';
    catRole = catRole || eq.category || '';
  } else if (targetType === 'IPAddress') {
    name = name || targetId;
  }

  document.getElementById('edit-name').value = name;
  document.getElementById('edit-category-role').value = catRole;
  document.getElementById('edit-room').value = patch.room || (patch.custom_attributes && patch.custom_attributes.room) || '';
  document.getElementById('edit-vlan-id').value = patch.vlan_id || (patch.custom_attributes && patch.custom_attributes.vlan_id) || '';
  document.getElementById('edit-notes').value = patch.notes || '';
  document.getElementById('edit-pinned-classification').value = patch.pinned_classification || '';
  document.getElementById('edit-reason').value = '';
  document.getElementById('item-edit-modal').classList.add('open');
}

function closeEditModal() {
  document.getElementById('item-edit-modal').classList.remove('open');
}

async function submitItemPatch(ev) {
  ev.preventDefault();
  const targetType = document.getElementById('edit-target-type').value;
  const targetId = document.getElementById('edit-target-id').value;
  const nameVal = document.getElementById('edit-name').value;
  const catRoleVal = document.getElementById('edit-category-role').value;
  const payload = {
    target_type: targetType,
    target_id: targetId,
    name: nameVal || null,
    hostname: targetType === 'NetworkDevice' ? (nameVal || null) : null,
    category: targetType === 'Equipment' ? (catRoleVal || null) : null,
    role: targetType === 'NetworkDevice' ? (catRoleVal || null) : null,
    room: document.getElementById('edit-room').value || null,
    vlan_id: document.getElementById('edit-vlan-id').value || null,
    notes: document.getElementById('edit-notes').value || null,
    pinned_classification: document.getElementById('edit-pinned-classification').value || null,
    reason: document.getElementById('edit-reason').value || 'Updated via Workbench UI'
  };
  const resp = await fetch('/api/items/patch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + workbenchToken() },
    body: JSON.stringify(payload)
  });
  const data = await resp.json();
  if (resp.ok && data.state) {
    closeEditModal();
    renderState(data.state);
    showBanner('Saved item patch for ' + targetType + ' ' + targetId, false);
  } else {
    showBanner(authFailureMessage(resp.status) || data.error || 'Failed to save patch', true);
  }
}

async function submitDeleteCurrentItem() {
  const targetType = document.getElementById('edit-target-type').value;
  const targetId = document.getElementById('edit-target-id').value;
  const resp = await fetch('/api/items/patch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + workbenchToken() },
    body: JSON.stringify({
      target_type: targetType,
      target_id: targetId,
      deleted: true,
      reason: document.getElementById('edit-reason').value || 'Deleted via Workbench UI'
    })
  });
  const data = await resp.json();
  if (resp.ok && data.state) {
    closeEditModal();
    renderState(data.state);
    showBanner('Deleted ' + targetType + ' ' + targetId, false);
  } else {
    showBanner(authFailureMessage(resp.status) || data.error || 'Failed to delete item', true);
  }
}

async function submitCreateDevice(ev) {
  ev.preventDefault();
  const payload = {
    hostname: document.getElementById('dev-hostname').value,
    device_id: document.getElementById('dev-device-id').value || null,
    template_id: document.getElementById('dev-template-id').value || null,
    management_ip: document.getElementById('dev-mgmt-ip').value || null,
    role: document.getElementById('dev-role').value || null,
    port_count: document.getElementById('dev-port-count').value ? Number(document.getElementById('dev-port-count').value) : null,
    default_vlan_id: document.getElementById('dev-default-vlan').value || null,
    reason: document.getElementById('dev-reason').value || 'Created device via Workbench UI'
  };
  const resp = await fetch('/api/devices', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + workbenchToken() },
    body: JSON.stringify(payload)
  });
  const data = await resp.json();
  if (resp.ok && data.state) {
    document.getElementById('create-device-form').reset();
    renderState(data.state);
    showBanner('Created device ' + data.device.hostname, false);
  } else {
    showBanner(authFailureMessage(resp.status) || data.error || 'Failed to create device', true);
  }
}

async function submitPortManager(ev) {
  ev.preventDefault();
  const payload = {
    device_id: document.getElementById('pm-device-id').value,
    name: document.getElementById('pm-port-name').value || null,
    range_spec: document.getElementById('pm-range-spec').value || null,
    admin_status: document.getElementById('pm-admin-status').value || 'up',
    oper_status: document.getElementById('pm-oper-status').value || 'down',
    poe_status: document.getElementById('pm-poe-status').value || null,
    vlan_id: document.getElementById('pm-vlan-id').value || null,
    connected_mac: document.getElementById('pm-connected-mac').value || null,
    connected_device_id: document.getElementById('pm-connected-device').value || null,
    reason: document.getElementById('pm-reason').value || 'Updated ports via Workbench UI'
  };
  const resp = await fetch('/api/devices/ports', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + workbenchToken() },
    body: JSON.stringify(payload)
  });
  const data = await resp.json();
  if (resp.ok && data.state) {
    renderState(data.state);
    showBanner('Updated ' + (data.ports ? data.ports.length : 0) + ' port(s)', false);
  } else {
    showBanner(authFailureMessage(resp.status) || data.error || 'Failed to update ports', true);
  }
}

async function submitVlanForm(ev) {
  ev.preventDefault();
  const payload = {
    vlan_id: document.getElementById('vlan-id-input').value,
    name: document.getElementById('vlan-name-input').value || null,
    subnet_id: document.getElementById('vlan-subnet-id-input').value || null,
    cidr: document.getElementById('vlan-cidr-input').value || null,
    gateway: document.getElementById('vlan-gateway-input').value || null,
    reason: document.getElementById('vlan-reason-input').value || 'Saved VLAN/Subnet via Workbench UI'
  };
  const resp = await fetch('/api/vlans', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + workbenchToken() },
    body: JSON.stringify(payload)
  });
  const data = await resp.json();
  if (resp.ok && data.state) {
    document.getElementById('vlan-form').reset();
    renderState(data.state);
    showBanner('Saved VLAN ' + data.vlan.vlan_id, false);
  } else {
    showBanner(authFailureMessage(resp.status) || data.error || 'Failed to save VLAN', true);
  }
}
"""
