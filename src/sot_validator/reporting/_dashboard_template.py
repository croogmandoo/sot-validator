"""The ``<body>`` f-string template of the HTML dashboard page."""

from __future__ import annotations

from typing import Any

from sot_validator.reporting._dashboard_head import _render_dashboard_head


def _render_dashboard_page(
    *,
    safe_title: str,
    gen_at_str: str,
    total_items: int,
    active_count: int,
    stale_count: int,
    unreachable_count: int,
    insufficient_count: int,
    quarantine_eligible_count: int,
    untracked_discrepancies_count: int,
    reclaimable_ports_count: int,
    poe_watts_saved: float,
    ready_cutover_sites_count: int,
    ups_alerts_count: int,
    itsm_tickets_count: int,
    site_rows_html: list[str],
    subnet_rows_html: list[str],
    cls_options_html: str,
    site_options_html: str,
    type_options_html: str,
    enriched_results: list[dict[str, Any]],
    inventory_rows_html: list[str],
    inventory_data_html: str,
    manifest_meta_html: str,
    quarantine_rows_html: list[str],
    disc_by_type_html: list[str],
    disc_rows_html: list[str],
    port_plan_meta_html: str,
    port_candidates_rows_html: list[str],
    port_blocked_rows_html: list[str],
    parity_meta_html: str,
    parity_scorecard_rows_html: list[str],
    parity_discrepancy_rows_html: list[str],
    ups_meta_html: str,
    ups_rows_html: list[str],
    itsm_rows_html: list[str],
) -> str:
    head_html = _render_dashboard_head(safe_title)
    return f"""{head_html}<body>
  <header>
    <h1>{safe_title}</h1>
    <div class="header-meta">
      Generated At: <code>{gen_at_str}</code> | Mode: <code>Read-Only / Gated Operations</code>
    </div>
  </header>

  <div class="kpi-grid" id="kpi-summary">
    <div class="kpi-card">
      <div class="kpi-label">Total Evaluated</div>
      <div class="kpi-value" data-kpi="total-evaluated">{total_items}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Confirmed Active</div>
      <div class="kpi-value" data-kpi="confirmed-active">{active_count}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Stale / Likely Unused</div>
      <div class="kpi-value" data-kpi="stale-likely-unused">{stale_count}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Unreachable / Needs Manual Review</div>
      <div class="kpi-value" data-kpi="unreachable-needs-review">{unreachable_count}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Insufficient Data</div>
      <div class="kpi-value" data-kpi="insufficient-data">{insufficient_count}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Quarantine Eligible</div>
      <div class="kpi-value" data-kpi="quarantine-eligible">{quarantine_eligible_count}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Untracked Discrepancies</div>
      <div class="kpi-value" data-kpi="untracked-discrepancies">{untracked_discrepancies_count}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Reclaimable Switch Ports</div>
      <div class="kpi-value" data-kpi="reclaimable-ports">{reclaimable_ports_count} ({poe_watts_saved:.1f}W)</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Sites Ready for Cutover</div>
      <div class="kpi-value" data-kpi="migration-ready-sites" data-kpi-alias="sites-ready-for-cutover">{ready_cutover_sites_count}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">APC UPS Health Alerts</div>
      <div class="kpi-value" data-kpi="ups-critical-alerts" data-kpi-alias="ups-health-alerts">{ups_alerts_count}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">ITSM Change Tickets</div>
      <div class="kpi-value" data-kpi="itsm-tickets-count" data-kpi-alias="itsm-tickets">{itsm_tickets_count}</div>
    </div>
  </div>

  <section id="site-subnet-health">
    <h2>1. Per-Site &amp; /24 Subnet Utilization Health</h2>
    <h3>Site Classification Breakdown</h3>
    <div class="table-wrap">
      <table id="site-summary-table">
        <thead>
          <tr>
            <th>Site ID</th>
            <th>Site Name</th>
            <th class="num">Total</th>
            <th class="num">Confirmed Active</th>
            <th class="num">Stale / Likely Unused</th>
            <th class="num">Unreachable / Needs Manual Review</th>
            <th class="num">Insufficient Data</th>
          </tr>
        </thead>
        <tbody>
          {"".join(site_rows_html)}
        </tbody>
      </table>
    </div>

    <h3>/24 Subnet IP Utilization</h3>
    <div class="table-wrap">
      <table id="subnet-utilization-table">
        <thead>
          <tr>
            <th>Subnet ID</th>
            <th>Site ID</th>
            <th>CIDR</th>
            <th class="num">Total Assigned IPs</th>
            <th class="num">Confirmed Active IPs</th>
            <th class="num">Stale Reclaimable IPs</th>
            <th>Active Utilization</th>
          </tr>
        </thead>
        <tbody>
          {"".join(subnet_rows_html)}
        </tbody>
      </table>
    </div>
  </section>

  <section id="inventory-classification-section">
    <h2>2. Interactive Inventory Classification &amp; Signal Evidence Table</h2>
    <div class="filter-bar">
      <label>
        Classification
        <select id="filter-classification">
          <option value="">All Classifications</option>
          {cls_options_html}
        </select>
      </label>
      <label>
        Site ID
        <select id="filter-site">
          <option value="">All Sites</option>
          {site_options_html}
        </select>
      </label>
      <label>
        Item Type
        <select id="filter-type">
          <option value="">All Item Types</option>
          {type_options_html}
        </select>
      </label>
      <label>
        Search (ID / Name / IP / Rationale)
        <input type="search" id="filter-search" placeholder="Filter items...">
      </label>
      <div class="header-meta">
        Showing <strong id="visible-row-count">{len(enriched_results)}</strong> of {len(enriched_results)} items
      </div>
    </div>
    <div class="table-wrap">
      <table id="inventory-table">
        <thead>
          <tr>
            <th>Site ID</th>
            <th>Site Name</th>
            <th>Item Type</th>
            <th>Item ID</th>
            <th>Name</th>
            <th>Category</th>
            <th>IP Addresses</th>
            <th>Classification</th>
            <th class="num">Confidence</th>
            <th>Rationale</th>
            <th>Signals Evidence Trail</th>
          </tr>
        </thead>
        <tbody>
          {"".join(inventory_rows_html)}
        </tbody>
      </table>
    </div>
    {inventory_data_html}
  </section>

  <section id="quarantine-remediation-section">
    <h2>3. Phase 2 Quarantine &amp; Remediation Queue</h2>
    {manifest_meta_html}
    <div class="table-wrap">
      <table id="quarantine-table">
        <thead>
          <tr>
            <th>Item ID</th>
            <th>Site ID</th>
            <th>Item Type</th>
            <th>Name</th>
            <th class="num">Consecutive Stale Runs</th>
            <th class="num">Stale Duration (Days)</th>
            <th>Target Operation</th>
            <th>Graduation Status</th>
            <th>Approval Status</th>
            <th>Notes / Exemption Reason</th>
          </tr>
        </thead>
        <tbody>
          {"".join(quarantine_rows_html)}
        </tbody>
      </table>
    </div>
  </section>

  <section id="reverse-discovery-section">
    <h2>4. Phase 3 Reverse Discovery &amp; Untracked Assets</h2>
    <div class="mini-stats">
      {"".join(disc_by_type_html)}
    </div>
    <div class="table-wrap">
      <table id="discrepancies-table">
        <thead>
          <tr>
            <th>Discrepancy ID</th>
            <th>Discrepancy Type</th>
            <th>Site ID</th>
            <th>Observed Identifier</th>
            <th>Observed IP</th>
            <th>Observed MAC</th>
            <th>Observed Hostname</th>
            <th>Source</th>
            <th>SoT Item ID</th>
            <th>Details</th>
            <th>Recommended Onboarding Action</th>
          </tr>
        </thead>
        <tbody>
          {"".join(disc_rows_html)}
        </tbody>
      </table>
    </div>
  </section>

  <section id="port-reclamation-section">
    <h2>5. Phase 4 Extreme Networks Switch Port &amp; PoE Reclamation</h2>
    {port_plan_meta_html}
    <h3>Eligible Stale Access Ports (Staged ExtremeXOS / VOSS Commands)</h3>
    <div class="table-wrap">
      <table id="port-reclamation-candidates-table">
        <thead>
          <tr>
            <th>Site ID</th>
            <th>Switch Device ID</th>
            <th>Port Name</th>
            <th class="num">Inactive Runs</th>
            <th class="num">Inactive Days</th>
            <th class="num">PoE Saved</th>
            <th>ExtremeXOS Disable Commands</th>
            <th>Extreme VOSS Disable Commands</th>
            <th>1-Command Rollback</th>
          </tr>
        </thead>
        <tbody>
          {"".join(port_candidates_rows_html)}
        </tbody>
      </table>
    </div>

    <h3>LLDP Uplink Guard Protected Ports Audit</h3>
    <div class="table-wrap">
      <table id="port-reclamation-blocked-table">
        <thead>
          <tr>
            <th>Site ID</th>
            <th>Switch Device ID</th>
            <th>Port Name</th>
            <th>Port ID</th>
            <th>Guard Status</th>
            <th>Matched Safety Rules</th>
            <th>Protection Reason</th>
          </tr>
        </thead>
        <tbody>
          {"".join(port_blocked_rows_html)}
        </tbody>
      </table>
    </div>
  </section>

  <section id="migration-parity-section">
    <div id="modern-sot-parity-section">
      <h2>6. Phase 5 Modern SoT Dual-Run Parity &amp; Migration Readiness Scorecards</h2>
      {parity_meta_html}
      <h3>Per-Site Migration Readiness Scorecards</h3>
      <div class="table-wrap">
        <table id="parity-scorecards-table">
          <thead>
            <tr>
              <th>Site ID</th>
              <th>Site Name</th>
              <th class="num">Readiness Score</th>
              <th class="num">Parity Match</th>
              <th>Cutover Recommendation</th>
              <th class="num">Matched / Expected</th>
              <th class="num">Parity Discrepancies</th>
              <th class="num">Unresolved Shadow IT</th>
              <th>Blocking Reasons</th>
            </tr>
          </thead>
          <tbody>
            {"".join(parity_scorecard_rows_html)}
          </tbody>
        </table>
      </div>

      <h3>Dual-Run Parity Discrepancies</h3>
      <div class="table-wrap">
        <table id="parity-discrepancies-table">
          <thead>
            <tr>
              <th>Discrepancy ID</th>
              <th>Discrepancy Type</th>
              <th>Site ID</th>
              <th>Entity Type</th>
              <th>Item Identifier</th>
              <th>Attribute</th>
              <th>Expected</th>
              <th>Actual</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {"".join(parity_discrepancy_rows_html)}
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <section id="ups-health-section">
    <h2>7. Phase 6 APC UPS Fleet Health &amp; Environmental Telemetry</h2>
    {ups_meta_html}
    <div class="table-wrap">
      <table id="ups-health-table">
        <thead>
          <tr>
            <th>Site ID</th>
            <th>Equipment ID</th>
            <th>UPS Hostname</th>
            <th>IP Address</th>
            <th>Model</th>
            <th>Health Status</th>
            <th>Battery Status</th>
            <th>Replace Battery</th>
            <th class="num">Runtime Remaining</th>
            <th class="num">Temp</th>
            <th class="num">Output Load</th>
            <th>Output Status</th>
            <th>Active Advisories</th>
          </tr>
        </thead>
        <tbody>
          {"".join(ups_rows_html)}
        </tbody>
      </table>
    </div>
  </section>

  <section id="itsm-governance-section">
    <h2>8. Phase 6 ITSM Change-Ticket &amp; Approval Governance Queue</h2>
    <div class="table-wrap">
      <table id="itsm-tickets-table">
        <thead>
          <tr>
            <th>Ticket ID</th>
            <th>Workflow Type</th>
            <th>Title / Short Description</th>
            <th>Risk / Priority</th>
            <th>CMDB CI</th>
            <th>Sites</th>
            <th>Artifact ID</th>
            <th>Artifact SHA-256 Digest</th>
            <th>Approval Status</th>
            <th>Approved By</th>
          </tr>
        </thead>
        <tbody>
          {"".join(itsm_rows_html)}
        </tbody>
      </table>
    </div>
  </section>

  <script>
    (function () {{
      var clsSelect = document.getElementById("filter-classification");
      var siteSelect = document.getElementById("filter-site");
      var typeSelect = document.getElementById("filter-type");
      var searchInput = document.getElementById("filter-search");
      var countEl = document.getElementById("visible-row-count");
      var dataEl = document.getElementById("inventory-data");
      var statusRow = document.getElementById("inventory-status-row");
      var tbody = document.querySelector("#inventory-table tbody");
      var records = [];
      var searchBlobs = [];
      var rows = [];

      function textEl(tag, text, className) {{
        var el = document.createElement(tag);
        if (className) {{
          el.className = className;
        }}
        el.textContent = text;
        return el;
      }}

      function cell(text, wrapInCode) {{
        var td = document.createElement("td");
        if (wrapInCode) {{
          td.appendChild(textEl("code", text));
        }} else {{
          td.textContent = text;
        }}
        return td;
      }}

      function signalsCell(signals) {{
        var td = document.createElement("td");
        if (!signals.length) {{
          td.appendChild(textEl("span", "No signals", "muted"));
          return td;
        }}
        var details = document.createElement("details");
        details.appendChild(textEl("summary", signals.length + " signal(s)"));
        var list = document.createElement("ul");
        list.className = "signal-list";
        for (var i = 0; i < signals.length; i++) {{
          var sig = signals[i];
          var li = document.createElement("li");
          li.appendChild(textEl("strong", sig.type));
          li.appendChild(document.createTextNode(" [" + sig.status + "] (source: "));
          li.appendChild(textEl("code", sig.source));
          li.appendChild(document.createTextNode(", age: "));
          li.appendChild(textEl("code", sig.age));
          li.appendChild(document.createTextNode(")"));
          if (sig.details) {{
            li.appendChild(document.createTextNode(" \u2014 " + sig.details));
          }}
          list.appendChild(li);
        }}
        details.appendChild(list);
        td.appendChild(details);
        return td;
      }}

      function buildRow(rec) {{
        var tr = document.createElement("tr");
        tr.className = "inventory-row";
        tr.appendChild(cell(rec.site_id, true));
        tr.appendChild(cell(rec.site_name, false));
        tr.appendChild(cell(rec.item_type, false));
        tr.appendChild(cell(rec.item_id, true));
        tr.appendChild(cell(rec.name, false));
        tr.appendChild(cell(rec.category, false));
        tr.appendChild(cell(rec.ips, true));
        var badgeTd = document.createElement("td");
        badgeTd.appendChild(textEl("span", rec.classification, "badge " + rec.badge));
        tr.appendChild(badgeTd);
        var confTd = cell(rec.confidence, false);
        confTd.setAttribute("class", "num");
        tr.appendChild(confTd);
        tr.appendChild(cell(rec.rationale, false));
        tr.appendChild(signalsCell(rec.signals));
        return tr;
      }}

      function applyFilters() {{
        var clsVal = clsSelect ? clsSelect.value : "";
        var siteVal = siteSelect ? siteSelect.value : "";
        var typeVal = typeSelect ? typeSelect.value : "";
        var query = searchInput ? searchInput.value.trim().toLowerCase() : "";
        var visible = 0;

        for (var i = 0; i < rows.length; i++) {{
          var rec = records[i];
          var match =
            (!clsVal || rec.classification === clsVal) &&
            (!siteVal || rec.site_id === siteVal) &&
            (!typeVal || rec.item_type === typeVal) &&
            (!query || searchBlobs[i].indexOf(query) !== -1);

          rows[i].style.display = match ? "" : "none";
          if (match) {{
            visible += 1;
          }}
        }}

        if (countEl) {{
          countEl.textContent = String(visible);
        }}
      }}

      function renderRows(decoded) {{
        var fragment = document.createDocumentFragment();
        records = decoded;
        for (var i = 0; i < records.length; i++) {{
          var rec = records[i];
          searchBlobs.push(
            [
              rec.site_id,
              rec.site_name,
              rec.item_type,
              rec.item_id,
              rec.name,
              rec.category,
              rec.ips,
              rec.classification,
              rec.rationale
            ].join(" ").toLowerCase()
          );
          var row = buildRow(rec);
          rows.push(row);
          fragment.appendChild(row);
        }}
        tbody.appendChild(fragment);
        if (statusRow && statusRow.parentNode) {{
          statusRow.parentNode.removeChild(statusRow);
        }}

        if (clsSelect) clsSelect.addEventListener("change", applyFilters);
        if (siteSelect) siteSelect.addEventListener("change", applyFilters);
        if (typeSelect) typeSelect.addEventListener("change", applyFilters);
        if (searchInput) searchInput.addEventListener("input", applyFilters);
      }}

      function showLoadError() {{
        if (statusRow && statusRow.firstChild) {{
          statusRow.firstChild.textContent =
            "Could not load inventory data in this browser.";
        }}
      }}

      if (!dataEl || !tbody) {{
        return;
      }}
      if (
        typeof DecompressionStream === "undefined" ||
        typeof atob !== "function" ||
        typeof TextDecoder === "undefined"
      ) {{
        showLoadError();
        return;
      }}
      try {{
        var binary = atob(dataEl.textContent.trim());
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {{
          bytes[i] = binary.charCodeAt(i);
        }}
        var stream = new Blob([bytes]).stream().pipeThrough(
          new DecompressionStream("gzip")
        );
        new Response(stream)
          .text()
          .then(function (text) {{
            renderRows(JSON.parse(text));
          }})
          .catch(showLoadError);
      }} catch (err) {{
        showLoadError();
      }}
    }})();
  </script>
</body>
</html>
"""
