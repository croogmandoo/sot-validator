"""The ``<!DOCTYPE>`` through ``</head>`` part of the HTML dashboard page, including its ``<style>``."""

from __future__ import annotations


def _render_dashboard_head(safe_title: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{safe_title}</title>
  <style>
    :root {{
      --bg: #f8fafc;
      --surface: #ffffff;
      --border: #e2e8f0;
      --text: #0f172a;
      --muted: #475569;
      --active-bg: #dcfce7;
      --active-fg: #166534;
      --stale-bg: #fee2e2;
      --stale-fg: #991b1b;
      --unreach-bg: #fef3c7;
      --unreach-fg: #92400e;
      --insuff-bg: #e2e8f0;
      --insuff-fg: #334155;
      --accent: #2563eb;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 24px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }}
    header {{
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 2px solid var(--border);
    }}
    header h1 {{
      margin: 0 0 8px 0;
      font-size: 1.75rem;
    }}
    .header-meta {{
      color: var(--muted);
      font-size: 0.9rem;
    }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 28px;
    }}
    .kpi-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
    }}
    .kpi-label {{
      font-size: 0.8rem;
      font-weight: 600;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 6px;
    }}
    .kpi-value {{
      font-size: 1.8rem;
      font-weight: 700;
    }}
    section {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
    }}
    section h2 {{
      margin-top: 0;
      font-size: 1.25rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 10px;
    }}
    section h3 {{
      font-size: 1.05rem;
      margin: 16px 0 8px 0;
    }}
    .section-meta {{
      margin-bottom: 12px;
      font-size: 0.9rem;
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
      align-items: center;
    }}
    .filter-bar {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 16px;
      align-items: center;
    }}
    .filter-bar label {{
      font-size: 0.85rem;
      font-weight: 600;
      color: var(--muted);
      display: flex;
      flex-direction: column;
      gap: 4px;
    }}
    .filter-bar select, .filter-bar input {{
      padding: 6px 10px;
      border: 1px solid var(--border);
      border-radius: 4px;
      font-size: 0.9rem;
      min-width: 170px;
    }}
    .table-wrap {{
      overflow-x: auto;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.875rem;
    }}
    th, td {{
      text-align: left;
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    th {{
      background: #f1f5f9;
      font-weight: 600;
      white-space: nowrap;
    }}
    td.num, th.num {{
      text-align: right;
    }}
    .empty-cell {{
      text-align: center;
      color: var(--muted);
      font-style: italic;
      padding: 20px;
    }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
      white-space: nowrap;
    }}
    .badge-active {{ background: var(--active-bg); color: var(--active-fg); }}
    .badge-stale {{ background: var(--stale-bg); color: var(--stale-fg); }}
    .badge-unreachable {{ background: var(--unreach-bg); color: var(--unreach-fg); }}
    .badge-insufficient {{ background: var(--insuff-bg); color: var(--insuff-fg); }}
    .utilization-cell {{
      display: flex;
      align-items: center;
      gap: 8px;
      min-width: 150px;
    }}
    .utilization-label {{
      min-width: 56px;
      text-align: right;
      font-variant-numeric: tabular-nums;
    }}
    .progress-bar {{
      flex: 1;
      height: 8px;
      background: var(--border);
      border-radius: 4px;
      overflow: hidden;
    }}
    .progress-fill {{
      height: 100%;
      background: var(--accent);
    }}
    .signal-list {{
      margin: 6px 0 0 0;
      padding-left: 18px;
      font-size: 0.8rem;
    }}
    .mini-stats {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 16px;
    }}
    .mini-stat {{
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 12px;
      display: flex;
      gap: 10px;
      align-items: center;
      background: #f8fafc;
    }}
    .mini-stat-value {{
      font-weight: 700;
      font-size: 1.05rem;
    }}
    .muted {{ color: var(--muted); }}
  </style>
</head>
"""
