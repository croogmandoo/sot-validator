"""Fleet-wide site health scorecard, trend, and Markdown / self-contained HTML report.

Each site gets a health score from 0 to 100 built from up to five dimensions, in
``FLEET_DIMENSIONS`` order: ``records``, ``quality``, ``certificates``, ``firmware``
and ``drift``. A dimension is *present* for a site when the caller supplied its
input (even with zero findings) and *missing* otherwise.

Default weights and penalties (``FleetScoreWeights``)::

    records=0.40  quality=0.20  certificates=0.15  firmware=0.15  drift=0.10
    stale_penalty=1.0  unreachable_penalty=0.5  insufficient_penalty=0.25
    quality_error_penalty=1.0  quality_warning_penalty=0.25
    cert_error_points=25.0  cert_warning_points=10.0  cert_info_points=2.0
    drift_penalty=1.0

Let ``N`` be the sum of the four record counts when ``records`` is present. The
denominator ``D`` is ``N``, or 1 when ``records`` is missing or ``N == 0``.

Sub-scores of the present dimensions:

* records: ``100 * (1 - (stale*stale_penalty + unreachable*unreachable_penalty
  + insufficient*insufficient_penalty) / max(N, 1))``; 100 when ``N == 0``.
  ``Confirmed Active`` records carry no penalty.
* quality: ``100 * (1 - (errors*quality_error_penalty
  + warnings*quality_warning_penalty) / D)``. ``info`` findings are ignored.
* certificates: ``100 - (error*cert_error_points + warning*cert_warning_points
  + info*cert_info_points)``. These are absolute points per finding because
  certificate findings only exist for problem endpoints (no endpoint count).
* firmware: ``100 * (1 - noncompliant / devices)``; 100 when ``devices == 0``.
  Every status other than ``compliant`` (including ``unknown_platform`` and
  ``unparsed``) is non-compliant.
* drift: ``100 * (1 - drift_events*drift_penalty / D)``. Every ``DriftEvent``
  counts, whatever its ``transition_type``.

Each sub-score is clamped to [0, 100]. ``dimension_scores`` stores each clamped
sub-score rounded with ``round(x, 1)``; the health score uses the clamped,
unrounded sub-scores::

    health_score = round(clamp(sum(w_d * sub_d) / sum(w_d), 0, 100), 1)

where both sums run over the present dimensions only, so the weights of missing
dimensions drop out and the remaining weights are renormalised. A present
dimension with zero findings scores 100; a missing dimension is left out, never
counted as 0. When no dimension is present, or the present weights add up to 0,
``health_score`` is ``None`` ("no data").

Worked example: records 8 active / 2 stale (80), 1 quality error over D=10 (90),
1 certificate error (75), 1 of 4 firmware devices non-compliant (75) and 1 drift
event over D=10 (90) give ``0.4*80 + 0.2*90 + 0.15*75 + 0.15*75 + 0.1*90 = 81.5``.

Trend: the previous score is supplied by the caller (the history ledger stores no
per-site scores). With ``delta = round(health_score - previous_score, 1)``:

* ``new`` when ``previous_score`` or ``health_score`` is ``None``;
* ``stable`` when ``abs(delta) <= TREND_STABLE_THRESHOLD`` (5.0);
* ``improving`` when ``delta > 5``;
* ``degrading`` when ``delta < -5``.

Drift events come from ``HistoryStore.detect_drift`` (read-only, passed in by the
caller); nothing is read from or written to the ledger here.
"""

from __future__ import annotations

from sot_validator.reporting._fleet_render import (
    TABLE_HEADERS,
    _FLEET_SCRIPT,
    _FLEET_STYLE,
    _TOP_LISTS,
    _card_sort_key,
    _cert_text,
    _count_text,
    _dimension_detail,
    _esc,
    _firmware_text,
    _fleet_totals,
    _fmt_score,
    _fmt_timestamp,
    _html_value,
    _md_row,
    _ordered,
    _table_cells,
    _top_display,
    _top_list,
    _top_metric,
    render_fleet_html,
    render_fleet_markdown,
)
from sot_validator.reporting._fleet_scoring import (
    CERT_SEVERITIES,
    DEFAULT_FLEET_TITLE,
    FLEET_DIMENSIONS,
    FleetScoreWeights,
    FleetScorer,
    NO_DATA,
    SiteScorecard,
    TOP_N,
    TREND_DEGRADING,
    TREND_IMPROVING,
    TREND_NEW,
    TREND_STABLE,
    TREND_STABLE_THRESHOLD,
    TREND_VALUES,
    _FIRMWARE_COMPLIANT,
    _INSUFFICIENT,
    _RECORD_KEYS,
    _STALE,
    _UNREACHABLE,
    _clamp,
    _require_count,
    _require_number,
    _trend,
)
