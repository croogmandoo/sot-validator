"""Read-only Data Quality tab and `/api/quality` payload for the Web Workbench."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict
import html
from typing import Any, Optional

from sot_validator.models import Site
from sot_validator.quality import (
    SINGLE_SITE_RULES,
    VALID_SEVERITIES,
    DataQualityChecker,
    QualityFinding,
)

QUALITY_EMPTY_SITE_TEXT = "No data-quality findings for this site."
QUALITY_EMPTY_FILTER_TEXT = "No findings match the selected filters."

# Severity -> existing badge colour: error red, warning amber, info blue.
QUALITY_SEVERITY_BADGES: dict[str, str] = {
    "error": "badge-stale",
    "warning": "badge-unreachable",
    "info": "badge-info",
}


def _esc(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _clean_filter(
    value: Optional[str], allowed: Sequence[str], name: str
) -> Optional[str]:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if text not in allowed:
        raise ValueError(
            f"Invalid {name} filter {text!r}: expected one of {', '.join(allowed)}"
        )
    return text


def build_quality_payload(
    site: Site,
    *,
    rule: Optional[str] = None,
    severity: Optional[str] = None,
) -> dict[str, Any]:
    """Run the single-site checker on `site` and return the filtered JSON payload."""
    wanted_rule = _clean_filter(rule, SINGLE_SITE_RULES, "rule")
    wanted_severity = _clean_filter(severity, VALID_SEVERITIES, "severity")
    findings = [
        finding
        for finding in DataQualityChecker().check_site(site)
        if (wanted_rule is None or finding.rule == wanted_rule)
        and (wanted_severity is None or finding.severity == wanted_severity)
    ]
    return {
        "site_id": site.site_id,
        "total_findings": len(findings),
        "findings": [asdict(finding) for finding in findings],
    }


def _severity_badge(severity: str) -> str:
    badge = QUALITY_SEVERITY_BADGES.get(severity, "badge-insufficient")
    return f'<span class="badge {badge}">{_esc(severity)}</span>'


def _finding_row(finding: QualityFinding) -> str:
    return (
        f'<tr data-rule="{_esc(finding.rule)}" data-severity="{_esc(finding.severity)}">'
        f"<td><code>{_esc(finding.rule)}</code></td>"
        f"<td>{_severity_badge(finding.severity)}</td>"
        f"<td>{_esc(', '.join(finding.record_ids))}</td>"
        f"<td>{_esc(finding.message)}</td>"
        "</tr>"
    )


def render_quality_section(site: Site) -> str:
    """Render the Data Quality tab section with server-side rows for `site`."""
    findings = DataQualityChecker().check_site(site)
    rule_options = "".join(
        f'<option value="{_esc(name)}">{_esc(name)}</option>' for name in SINGLE_SITE_RULES
    )
    severity_options = "".join(
        f'<option value="{_esc(name)}">{_esc(name)}</option>' for name in VALID_SEVERITIES
    )
    rows = "".join(_finding_row(finding) for finding in findings)
    empty_hidden = " hidden" if findings else ""
    return f"""<section id="tab-quality" class="tab-panel">
    <div class="card quality-controls">
      <h3>Data Quality Findings</h3>
      <div class="quality-filters">
        <div class="form-row">
          <label for="quality-rule-filter">Rule</label>
          <select id="quality-rule-filter" onchange="applyQualityFilters()">
            <option value="">All rules</option>{rule_options}
          </select>
        </div>
        <div class="form-row">
          <label for="quality-severity-filter">Severity</label>
          <select id="quality-severity-filter" onchange="applyQualityFilters()">
            <option value="">All severities</option>{severity_options}
          </select>
        </div>
      </div>
      <p id="quality-empty" class="quality-empty" role="status"{empty_hidden}>{_esc(QUALITY_EMPTY_SITE_TEXT)}</p>
    </div>
    <div class="quality-scroll">
      <table id="quality-table">
        <thead>
          <tr>
            <th>Rule</th>
            <th>Severity</th>
            <th>Records</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody id="quality-tbody">{rows}</tbody>
      </table>
    </div>
  </section>"""


QUALITY_CSS = """
.quality-filters { display: flex; flex-wrap: wrap; gap: 0.75rem; }
.quality-filters select { max-width: 100%; }
.quality-empty { margin: 0.5rem 0 0; color: var(--muted); }
.quality-scroll {
  overflow-x: auto;
  max-width: 100%;
}
#quality-table { min-width: 560px; }
#quality-table td { overflow-wrap: anywhere; }
"""


# Data Quality tab behaviour. Every finding value is rendered through escapeHtml().
QUALITY_SCRIPT = """
const QUALITY_SEVERITY_BADGE = {
  error: 'badge-stale',
  warning: 'badge-unreachable',
  info: 'badge-info'
};
const QUALITY_EMPTY_SITE_TEXT = 'No data-quality findings for this site.';
const QUALITY_EMPTY_FILTER_TEXT = 'No findings match the selected filters.';

function qualityRow(f) {
  const badge = QUALITY_SEVERITY_BADGE[f.severity] || 'badge-insufficient';
  return '<tr data-rule="' + escapeHtml(f.rule) + '" data-severity="' + escapeHtml(f.severity) + '">' +
    '<td><code>' + escapeHtml(f.rule) + '</code></td>' +
    '<td><span class="badge ' + badge + '">' + escapeHtml(f.severity) + '</span></td>' +
    '<td>' + escapeHtml((f.record_ids || []).join(', ')) + '</td>' +
    '<td>' + escapeHtml(f.message) + '</td>' +
    '</tr>';
}

function applyQualityFilters() {
  const rule = document.getElementById('quality-rule-filter').value;
  const severity = document.getElementById('quality-severity-filter').value;
  const rows = document.querySelectorAll('#quality-tbody tr');
  let visible = 0;
  rows.forEach(tr => {
    const show = (!rule || tr.dataset.rule === rule) && (!severity || tr.dataset.severity === severity);
    tr.style.display = show ? '' : 'none';
    if (show) visible += 1;
  });
  const empty = document.getElementById('quality-empty');
  if (!rows.length) {
    empty.textContent = QUALITY_EMPTY_SITE_TEXT;
    empty.hidden = false;
  } else if (!visible) {
    empty.textContent = QUALITY_EMPTY_FILTER_TEXT;
    empty.hidden = false;
  } else {
    empty.hidden = true;
  }
}

async function refreshQualityFindings() {
  try {
    const resp = await fetch('/api/quality');
    if (!resp.ok) {
      showBanner('Data quality findings could not be refreshed.', true);
      return;
    }
    const data = await resp.json();
    document.getElementById('quality-tbody').innerHTML = (data.findings || []).map(qualityRow).join('');
    applyQualityFilters();
  } catch (err) {
    showBanner('Data quality findings could not be refreshed.', true);
  }
}
"""


__all__ = [
    "QUALITY_CSS",
    "QUALITY_EMPTY_FILTER_TEXT",
    "QUALITY_EMPTY_SITE_TEXT",
    "QUALITY_SCRIPT",
    "QUALITY_SEVERITY_BADGES",
    "build_quality_payload",
    "render_quality_section",
]
