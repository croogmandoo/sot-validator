"""Workbench page stylesheet, emitted inside the page <style> element."""

from __future__ import annotations

_PAGE_CSS = """:root {
  --bg: #0f172a;
  --panel: #1e293b;
  --panel-alt: #334155;
  --text: #f8fafc;
  --muted: #94a3b8;
  --accent: #38bdf8;
  --border: #475569;
  --active: #22c55e;
  --stale: #ef4444;
  --unreachable: #f59e0b;
  --insufficient: #64748b;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
}
header {
  padding: 1rem 1.5rem;
  background: var(--panel);
  border-bottom: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: center;
}
header h1 { margin: 0; font-size: 1.35rem; }
.container { max-width: 1440px; margin: 0 auto; padding: 1.25rem; }
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 0.85rem;
  margin-bottom: 1.25rem;
}
.kpi-card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.9rem 1rem;
}
.kpi-card .label { font-size: 0.8rem; color: var(--muted); text-transform: uppercase; }
.kpi-card .value { font-size: 1.55rem; font-weight: 700; margin-top: 0.25rem; }
.kpi-card .sub { font-size: 0.8rem; color: var(--muted); margin-top: 0.2rem; }
.filter-bar {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.85rem 1rem;
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  align-items: center;
  margin-bottom: 1rem;
}
.filter-bar input, .filter-bar select, form input, form select, form textarea,
.import-row input, .import-row select {
  background: var(--bg);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.45rem 0.65rem;
  font-size: 0.9rem;
}
.tabs {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-bottom: 1rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.5rem;
}
.tab-btn {
  background: var(--panel);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.5rem 1rem;
  cursor: pointer;
  font-weight: 600;
}
.tab-btn.active {
  background: var(--accent);
  color: #0f172a;
  border-color: var(--accent);
}
.tab-panel { display: none; }
.tab-panel.active { display: block; }
table {
  width: 100%;
  border-collapse: collapse;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}
th, td {
  padding: 0.6rem 0.75rem;
  text-align: left;
  border-bottom: 1px solid var(--border);
  font-size: 0.88rem;
}
th { background: var(--panel-alt); font-weight: 600; }
.badge {
  display: inline-block;
  padding: 0.2rem 0.55rem;
  border-radius: 999px;
  font-size: 0.75rem;
  font-weight: 600;
}
.badge-active { background: rgba(34, 197, 94, 0.2); color: #4ade80; }
.badge-stale { background: rgba(239, 68, 68, 0.2); color: #f87171; }
.badge-unreachable { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
.badge-insufficient { background: rgba(100, 116, 139, 0.25); color: #cbd5e1; }
.badge-info { background: rgba(56, 189, 248, 0.2); color: #38bdf8; }
.btn {
  background: var(--accent);
  color: #0f172a;
  border: none;
  border-radius: 6px;
  padding: 0.45rem 0.85rem;
  font-weight: 600;
  cursor: pointer;
}
.btn-sm { padding: 0.25rem 0.6rem; font-size: 0.8rem; }
.btn-danger { background: var(--stale); color: #fff; }
.grid-2 {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
  gap: 1rem;
  margin-bottom: 1.25rem;
}
.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem;
}
.card h3 { margin-top: 0; font-size: 1.05rem; }
.form-row {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  margin-bottom: 0.65rem;
}
.form-row label { font-size: 0.82rem; color: var(--muted); }
.device-card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.85rem 1rem;
  margin-bottom: 0.85rem;
}
.device-card-header { margin-bottom: 0.6rem; font-size: 0.92rem; }
.port-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
}
.port-chip {
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.3rem 0.5rem;
  font-size: 0.75rem;
  display: flex;
  flex-direction: column;
  min-width: 72px;
}
.port-up { background: rgba(34, 197, 94, 0.15); border-color: #22c55e; }
.port-down { background: rgba(100, 116, 139, 0.15); }
.port-name { font-weight: 700; }
.port-meta { font-size: 0.68rem; color: var(--muted); }
.modal-backdrop {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.75);
  align-items: center;
  justify-content: center;
  z-index: 50;
}
.modal-backdrop.open { display: flex; }
.modal {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.25rem;
  width: 100%;
  max-width: 520px;
}
#status-banner {
  display: none;
  padding: 0.6rem 1rem;
  border-radius: 6px;
  margin-bottom: 1rem;
  font-weight: 600;
}
.topology-scroll {
  overflow-x: auto;
  max-width: 100%;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
}
#topology-svg {
  display: block;
  max-width: none;
}
.topo-node { cursor: pointer; }
.topo-node-box {
  fill: var(--panel-alt);
  stroke: var(--border);
  stroke-width: 1;
}
.topo-node text { fill: var(--text); font-size: 12px; }
.topo-edge { stroke: var(--insufficient); stroke-width: 1.5; }
.topo-node.topo-selected .topo-node-box,
.topo-node:focus .topo-node-box {
  stroke: var(--accent);
  stroke-width: 2;
}
.topo-node.topo-selected { outline: 2px solid var(--accent); }
.topology-caption {
  margin: 0.75rem 0 0.35rem;
  font-size: 0.82rem;
  color: var(--muted);
}
#topology-mermaid {
  margin-top: 0;
  background: var(--panel);
  color: var(--muted);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.75rem;
  overflow: auto;
  white-space: pre-wrap;
}
.faceplate-panel {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.75rem;
  margin-bottom: 1rem;
  max-width: 100%;
}
.faceplate-heading {
  margin: 0 0 0.45rem;
  font-size: 0.95rem;
}
.faceplate-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin: 0 0 0.6rem;
  font-size: 0.82rem;
  color: var(--text);
}
.legend-swatch {
  display: inline-block;
  width: 0.85rem;
  height: 0.85rem;
  border-radius: 3px;
  margin-right: 0.3rem;
  vertical-align: -0.15rem;
  padding: 0;
}
#switch-faceplate {
  display: grid;
  grid-auto-flow: row;
  grid-template-rows: repeat(2, auto);
  justify-content: start;
  gap: 0.35rem;
  overflow-x: auto;
  width: 100%;
  max-width: 100%;
}
.faceplate-port {
  color: #fff;
  border: 1px solid rgba(15, 23, 42, 0.35);
  border-radius: 4px;
  min-width: 5rem;
  min-height: 2.75rem;
  font-size: 0.75rem;
  font-weight: 700;
  cursor: pointer;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.15rem;
  padding: 0.2rem 0.4rem;
  white-space: nowrap;
}
.faceplate-port.faceplate-selected {
  outline: 2px solid var(--accent);
  outline-offset: 1px;
}
.faceplate-up { background: #10b981; color: #0f172a; }
.faceplate-down { background: #64748b; }
.faceplate-uplink { background: #4f46e5; }
.faceplate-stale { background: #e11d48; }
.faceplate-poe-badge { background: #f59e0b; color: #0f172a; border-radius: 999px; padding: 0 0.35rem; font-size: 0.68rem; }
.legend-swatch.faceplate-poe-badge { padding: 0; }
.import-controls { margin-bottom: 1rem; }
.import-help { margin: 0 0 0.75rem; font-size: 0.85rem; color: var(--muted); }
.import-row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
}
.import-row input, .import-row select { max-width: 100%; }
.import-actions { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.btn:disabled { opacity: 0.45; cursor: not-allowed; }
.import-summary { margin-top: 0.75rem; font-size: 0.88rem; }
.import-messages { margin-top: 0.5rem; font-size: 0.88rem; color: #fca5a5; }
.import-messages-neutral { color: var(--muted); }
.import-messages ul { margin: 0.25rem 0 0; padding-left: 1.25rem; }
.import-scroll {
  overflow-x: auto;
  max-width: 100%;
}
#import-preview-table { min-width: 760px; }
#import-preview-table td { overflow-wrap: break-word; }
"""
