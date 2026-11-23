"""Fleet scorecard Markdown and HTML rendering over ``SiteScorecard`` lists."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
import html
from typing import Any, Optional

from sot_validator.reporting._fleet_scoring import (
    CERT_SEVERITIES,
    DEFAULT_FLEET_TITLE,
    FLEET_DIMENSIONS,
    NO_DATA,
    SiteScorecard,
    TOP_N,
    TREND_VALUES,
    _RECORD_KEYS,
    _STALE,
)
from sot_validator.reporting.generators import _escape_md_cell


# ---------------------------------------------------------------------------
# Shared report model
# ---------------------------------------------------------------------------


def _card_sort_key(card: SiteScorecard) -> tuple[Any, ...]:
    score = card.health_score
    return (
        score is None,
        score if score is not None else 0.0,
        card.site_id,
        repr(card.to_dict()),
    )


def _ordered(scorecards: Iterable[SiteScorecard]) -> list[SiteScorecard]:
    return sorted(scorecards, key=_card_sort_key)


def _fmt_score(value: Optional[float]) -> str:
    return NO_DATA if value is None else f"{float(value):.1f}"


def _fmt_timestamp(generated_at: Optional[datetime | str]) -> Optional[str]:
    if generated_at is None:
        return None
    if isinstance(generated_at, datetime):
        return generated_at.isoformat()
    return str(generated_at)


def _cert_text(card: SiteScorecard) -> str:
    if not card.has("certificates"):
        return NO_DATA
    c = card.cert_findings
    return f"{c['error']}/{c['warning']}/{c['info']}"


def _firmware_text(card: SiteScorecard) -> str:
    if not card.has("firmware"):
        return NO_DATA
    return f"{card.firmware_noncompliant}/{card.firmware_devices}"


def _count_text(card: SiteScorecard, dimension: str, value: int) -> str:
    return str(value) if card.has(dimension) else NO_DATA


def _table_cells(card: SiteScorecard) -> list[tuple[str, str]]:
    """Return (display text, sort value) for each site-table column after Site."""
    def _score_sort(value: Optional[float]) -> str:
        return "" if value is None else repr(float(value))

    cells: list[tuple[str, str]] = [
        (_fmt_score(card.health_score), _score_sort(card.health_score)),
        (_fmt_score(card.previous_score), _score_sort(card.previous_score)),
        (card.trend, card.trend),
    ]
    stale = card.record_counts[_STALE]
    cells.append((_count_text(card, "records", stale), str(stale) if card.has("records") else ""))
    cells.append(
        (
            _count_text(card, "quality", card.quality_errors),
            str(card.quality_errors) if card.has("quality") else "",
        )
    )
    c = card.cert_findings
    cells.append(
        (_cert_text(card), f"{c['error']} {c['warning']} {c['info']}" if card.has("certificates") else "")
    )
    cells.append(
        (
            _firmware_text(card),
            f"{card.firmware_noncompliant} {card.firmware_devices}" if card.has("firmware") else "",
        )
    )
    cells.append(
        (_count_text(card, "drift", card.drift_events), str(card.drift_events) if card.has("drift") else "")
    )
    return cells


TABLE_HEADERS: tuple[str, ...] = (
    "Site",
    "Health score",
    "Previous",
    "Trend",
    "Stale",
    "Quality errors",
    "Certificate findings (error/warning/info)",
    "Firmware non-compliant",
    "Drift",
)

# (title, dimension) for the top-10 risk lists, in FLEET_DIMENSIONS order.
_TOP_LISTS: tuple[tuple[str, str], ...] = (
    ("Stale records", "records"),
    ("Quality errors", "quality"),
    ("Certificate findings", "certificates"),
    ("Firmware non-compliance", "firmware"),
    ("Drift", "drift"),
)


def _top_metric(card: SiteScorecard, dimension: str) -> tuple[int, ...]:
    if dimension == "records":
        return (card.record_counts[_STALE],)
    if dimension == "quality":
        return (card.quality_errors,)
    if dimension == "certificates":
        c = card.cert_findings
        return (c["error"], c["warning"], c["info"])
    if dimension == "firmware":
        return (card.firmware_noncompliant,)
    return (card.drift_events,)


def _top_display(card: SiteScorecard, dimension: str) -> str:
    if dimension == "certificates":
        return _cert_text(card)
    if dimension == "firmware":
        return _firmware_text(card)
    return str(_top_metric(card, dimension)[0])


def _top_list(cards: list[SiteScorecard], dimension: str) -> list[SiteScorecard]:
    eligible = [
        card for card in cards if card.has(dimension) and any(_top_metric(card, dimension))
    ]
    eligible.sort(
        key=lambda card: (
            tuple(-v for v in _top_metric(card, dimension)),
            card.site_id,
            repr(card.to_dict()),
        )
    )
    return eligible[:TOP_N]


def _fleet_totals(cards: list[SiteScorecard]) -> list[tuple[str, str]]:
    """Return ordered (label, value) pairs for the fleet totals header."""
    scored = [card.health_score for card in cards if card.health_score is not None]
    mean = round(sum(scored) / len(scored), 1) if scored else None
    totals: list[tuple[str, str]] = [
        ("Sites", str(len(cards))),
        ("Sites with a score", str(len(scored))),
        ("Mean health score", _fmt_score(mean)),
    ]
    for trend in TREND_VALUES:
        totals.append(
            (f"Trend: {trend}", str(sum(1 for card in cards if card.trend == trend)))
        )

    def _present(dimension: str) -> list[SiteScorecard]:
        return [card for card in cards if card.has(dimension)]

    record_cards = _present("records")
    for key in _RECORD_KEYS:
        totals.append(
            (
                f"Records: {key}",
                str(sum(c.record_counts[key] for c in record_cards)) if record_cards else NO_DATA,
            )
        )
    quality_cards = _present("quality")
    totals.append(
        ("Quality errors", str(sum(c.quality_errors for c in quality_cards)) if quality_cards else NO_DATA)
    )
    totals.append(
        (
            "Quality warnings",
            str(sum(c.quality_warnings for c in quality_cards)) if quality_cards else NO_DATA,
        )
    )
    cert_cards = _present("certificates")
    for severity in CERT_SEVERITIES:
        totals.append(
            (
                f"Certificate findings: {severity}",
                str(sum(c.cert_findings[severity] for c in cert_cards)) if cert_cards else NO_DATA,
            )
        )
    firmware_cards = _present("firmware")
    totals.append(
        (
            "Firmware non-compliant / devices",
            (
                f"{sum(c.firmware_noncompliant for c in firmware_cards)}"
                f"/{sum(c.firmware_devices for c in firmware_cards)}"
            )
            if firmware_cards
            else NO_DATA,
        )
    )
    drift_cards = _present("drift")
    totals.append(
        ("Drift events", str(sum(c.drift_events for c in drift_cards)) if drift_cards else NO_DATA)
    )
    return totals


def _dimension_detail(card: SiteScorecard, dimension: str) -> str:
    if not card.has(dimension):
        return NO_DATA
    if dimension == "records":
        counts = ", ".join(f"{key} {card.record_counts[key]}" for key in _RECORD_KEYS)
    elif dimension == "quality":
        counts = f"errors {card.quality_errors}, warnings {card.quality_warnings}"
    elif dimension == "certificates":
        counts = ", ".join(f"{sev} {card.cert_findings[sev]}" for sev in CERT_SEVERITIES)
    elif dimension == "firmware":
        counts = f"non-compliant {card.firmware_noncompliant} of {card.firmware_devices} devices"
    else:
        counts = f"events {card.drift_events}"
    return f"{counts}; sub-score {_fmt_score(card.dimension_scores.get(dimension))}"


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def _md_row(cells: Iterable[Any]) -> str:
    return "| " + " | ".join(_escape_md_cell(cell) for cell in cells) + " |"


def render_fleet_markdown(
    scorecards: Iterable[SiteScorecard],
    generated_at: Optional[datetime | str] = None,
    title: str = DEFAULT_FLEET_TITLE,
) -> str:
    """Render the fleet scorecard as deterministic Markdown."""
    cards = _ordered(scorecards)
    lines: list[str] = [f"# {_escape_md_cell(title)}", ""]
    timestamp = _fmt_timestamp(generated_at)
    if timestamp is not None:
        lines += [f"Generated at: {_escape_md_cell(timestamp)}", ""]

    lines += ["## Fleet totals", "", _md_row(("Metric", "Value")), _md_row(("---", "---"))]
    lines += [_md_row(pair) for pair in _fleet_totals(cards)]
    lines.append("")

    lines += ["## Site table", "", _md_row(TABLE_HEADERS), _md_row(["---"] * len(TABLE_HEADERS))]
    for card in cards:
        lines.append(_md_row([card.site_id] + [text for text, _ in _table_cells(card)]))
    lines.append("")

    lines += ["## Top 10 per risk dimension", ""]
    for list_title, dimension in _TOP_LISTS:
        lines += [f"### Top 10: {list_title}", ""]
        top = _top_list(cards, dimension)
        if not top:
            lines += ["None", ""]
            continue
        lines += [_md_row(("Rank", "Site", list_title)), _md_row(("---", "---", "---"))]
        for rank, card in enumerate(top, start=1):
            lines.append(_md_row((rank, card.site_id, _top_display(card, dimension))))
        lines.append("")

    lines += ["## Per-site drill-down", ""]
    for index, card in enumerate(cards, start=1):
        lines += [f"### {index}. {_escape_md_cell(card.site_id)}", ""]
        lines.append(f"- Health score: {_fmt_score(card.health_score)}")
        lines.append(f"- Previous score: {_fmt_score(card.previous_score)}")
        lines.append(f"- Trend: {_escape_md_cell(card.trend)}")
        for dimension in FLEET_DIMENSIONS:
            lines.append(f"- {dimension}: {_escape_md_cell(_dimension_detail(card, dimension))}")
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------


def _esc(value: Any) -> str:
    """Escape any value for safe inclusion in HTML text or quoted attributes."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


_FLEET_STYLE = """
    :root {
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
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 24px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }
    header {
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 2px solid var(--border);
    }
    header h1 { margin: 0 0 8px 0; font-size: 1.75rem; }
    h2 { font-size: 1.25rem; margin: 28px 0 12px 0; }
    h3 { font-size: 1.05rem; margin: 16px 0 8px 0; }
    .header-meta { color: var(--muted); font-size: 0.9rem; }
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 28px;
    }
    .kpi-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
    }
    .kpi-label {
      font-size: 0.8rem;
      font-weight: 600;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 6px;
    }
    .kpi-value { font-size: 1.5rem; font-weight: 700; overflow-wrap: anywhere; }
    .table-wrap {
      overflow-x: auto;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 16px;
    }
    table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
    th, td {
      padding: 8px 10px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
    }
    th { background: var(--bg); color: var(--muted); font-weight: 600; }
    th button {
      font: inherit;
      color: inherit;
      background: none;
      border: 0;
      padding: 0;
      cursor: pointer;
      text-align: left;
    }
    th button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    th[aria-sort="ascending"] button::after { content: " \\25B2"; }
    th[aria-sort="descending"] button::after { content: " \\25BC"; }
    td a { color: var(--accent); overflow-wrap: anywhere; }
    .no-data { color: var(--muted); font-style: italic; }
    .trend { display: inline-block; padding: 1px 8px; border-radius: 999px; font-weight: 600; }
    .trend-improving { background: var(--active-bg); color: var(--active-fg); }
    .trend-stable { background: var(--insuff-bg); color: var(--insuff-fg); }
    .trend-degrading { background: var(--stale-bg); color: var(--stale-fg); }
    .trend-new { background: var(--unreach-bg); color: var(--unreach-fg); }
    .site-block {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px 16px;
      margin-bottom: 12px;
    }
    .site-block h3 { overflow-wrap: anywhere; }
    .site-block dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; margin: 0; }
    .site-block dt { font-weight: 600; color: var(--muted); }
    .site-block dd { margin: 0; overflow-wrap: anywhere; }
    @media (max-width: 600px) {
      body { padding: 12px; }
      header h1 { font-size: 1.4rem; }
      .kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
      .kpi-card { padding: 10px; }
      .kpi-value { font-size: 1.2rem; }
      th, td { white-space: nowrap; }
    }
"""

_FLEET_SCRIPT = """
    (function () {
      var table = document.getElementById("fleet-site-table");
      if (!table) { return; }
      var tbody = table.querySelector("tbody");
      var headers = Array.prototype.slice.call(table.querySelectorAll("thead th"));

      function parse(raw) {
        var parts = raw.split(" ");
        var nums = [];
        for (var i = 0; i < parts.length; i++) {
          var n = Number(parts[i]);
          if (parts[i] === "" || !isFinite(n)) { return null; }
          nums.push(n);
        }
        return nums;
      }

      function compareValues(a, b) {
        var na = parse(a);
        var nb = parse(b);
        if (na && nb) {
          for (var i = 0; i < Math.max(na.length, nb.length); i++) {
            var x = i < na.length ? na[i] : 0;
            var y = i < nb.length ? nb[i] : 0;
            if (x !== y) { return x < y ? -1 : 1; }
          }
          return 0;
        }
        return a < b ? -1 : (a > b ? 1 : 0);
      }

      function sortBy(col, direction) {
        var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));
        rows.sort(function (ra, rb) {
          var a = ra.children[col].getAttribute("data-sort-value") || "";
          var b = rb.children[col].getAttribute("data-sort-value") || "";
          if (a === "" && b !== "") { return 1; }
          if (b === "" && a !== "") { return -1; }
          var result = a === "" ? 0 : compareValues(a, b) * direction;
          if (result === 0) {
            result = Number(ra.getAttribute("data-index")) - Number(rb.getAttribute("data-index"));
          }
          return result;
        });
        for (var i = 0; i < rows.length; i++) { tbody.appendChild(rows[i]); }
      }

      headers.forEach(function (th, col) {
        var button = th.querySelector("button");
        if (!button) { return; }
        button.addEventListener("click", function () {
          var next = th.getAttribute("aria-sort") === "ascending" ? "descending" : "ascending";
          headers.forEach(function (other) { other.removeAttribute("aria-sort"); });
          th.setAttribute("aria-sort", next);
          sortBy(col, next === "ascending" ? 1 : -1);
        });
      });
    })();
"""


def _html_value(text: str) -> str:
    if text == NO_DATA:
        return f'<span class="no-data">{NO_DATA}</span>'
    return _esc(text)


def render_fleet_html(
    scorecards: Iterable[SiteScorecard],
    generated_at: Optional[datetime | str] = None,
    title: str = DEFAULT_FLEET_TITLE,
) -> str:
    """Render the fleet scorecard as a single self-contained HTML document."""
    cards = _ordered(scorecards)
    out: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '  <meta charset="utf-8">',
        '  <meta name="viewport" content="width=device-width, initial-scale=1.0">',
        f"  <title>{_esc(title)}</title>",
        "  <style>" + _FLEET_STYLE + "  </style>",
        "</head>",
        "<body>",
        "  <header>",
        f"    <h1>{_esc(title)}</h1>",
    ]
    timestamp = _fmt_timestamp(generated_at)
    if timestamp is not None:
        out.append(f'    <div class="header-meta">Generated at: {_esc(timestamp)}</div>')
    out.append("  </header>")

    out += ['  <section aria-labelledby="fleet-totals">', '    <h2 id="fleet-totals">Fleet totals</h2>']
    out.append('    <div class="kpi-grid">')
    for label, value in _fleet_totals(cards):
        out.append(
            f'      <div class="kpi-card"><div class="kpi-label">{_esc(label)}</div>'
            f'<div class="kpi-value">{_html_value(value)}</div></div>'
        )
    out += ["    </div>", "  </section>"]

    out += ['  <section aria-labelledby="fleet-sites">', '    <h2 id="fleet-sites">Site table</h2>']
    out.append('    <div class="table-wrap">')
    out.append('      <table id="fleet-site-table">')
    out.append("        <thead><tr>")
    for header in TABLE_HEADERS:
        sort_attr = ' aria-sort="ascending"' if header == "Health score" else ""
        out.append(
            f'          <th scope="col"{sort_attr}><button type="button">{_esc(header)}</button></th>'
        )
    out.append("        </tr></thead>")
    out.append("        <tbody>")
    for index, card in enumerate(cards, start=1):
        cells = [
            f'<td data-sort-value="{_esc(card.site_id)}">'
            f'<a href="#site-{index}">{_esc(card.site_id)}</a></td>'
        ]
        for col, (text, sort_value) in enumerate(_table_cells(card)):
            if col == 2:
                body = f'<span class="trend trend-{_esc(text)}">{_esc(text)}</span>'
            else:
                body = _html_value(text)
            cells.append(f'<td data-sort-value="{_esc(sort_value)}">{body}</td>')
        out.append(f'          <tr data-index="{index}">' + "".join(cells) + "</tr>")
    out += ["        </tbody>", "      </table>", "    </div>", "  </section>"]

    out += [
        '  <section aria-labelledby="fleet-top">',
        '    <h2 id="fleet-top">Top 10 per risk dimension</h2>',
    ]
    for list_title, dimension in _TOP_LISTS:
        out.append(f"    <h3>Top 10: {_esc(list_title)}</h3>")
        top = _top_list(cards, dimension)
        if not top:
            out.append("    <p>None</p>")
            continue
        out.append("    <ol>")
        for card in top:
            out.append(
                f"      <li>{_esc(card.site_id)}: {_esc(_top_display(card, dimension))}</li>"
            )
        out.append("    </ol>")
    out.append("  </section>")

    out += [
        '  <section aria-labelledby="fleet-drill">',
        '    <h2 id="fleet-drill">Per-site drill-down</h2>',
    ]
    for index, card in enumerate(cards, start=1):
        out.append(f'    <div class="site-block" id="site-{index}">')
        out.append(f"      <h3>{index}. {_esc(card.site_id)}</h3>")
        out.append("      <dl>")
        rows = [
            ("Health score", _fmt_score(card.health_score)),
            ("Previous score", _fmt_score(card.previous_score)),
            ("Trend", card.trend),
        ] + [(dimension, _dimension_detail(card, dimension)) for dimension in FLEET_DIMENSIONS]
        for label, value in rows:
            out.append(f"        <dt>{_esc(label)}</dt><dd>{_html_value(value)}</dd>")
        out += ["      </dl>", "    </div>"]
    out.append("  </section>")

    out += ["  <script>" + _FLEET_SCRIPT + "  </script>", "</body>", "</html>"]
    return "\n".join(out) + "\n"
