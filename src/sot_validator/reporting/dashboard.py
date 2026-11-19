"""Interactive self-contained HTML5 operations dashboard generator (`validation_dashboard.html`).

Facade over the private ``_dashboard_*`` modules; every name stays importable from here.
"""

from __future__ import annotations

from sot_validator.reporting._dashboard_common import (
    DEFAULT_DASHBOARD_FILENAME,
    DEFAULT_DASHBOARD_TITLE,
    _approval_badge_class,
    _classification_badge_class,
    _coerce_itsm_tickets,
    _coerce_manifest,
    _coerce_parity_report,
    _coerce_port_reclamation_plan,
    _coerce_reconciliation,
    _coerce_streaks,
    _coerce_subnet_utilization,
    _coerce_ups_health_report,
    _cutover_badge_class,
    _encode_inventory_payload,
    _esc,
    _inventory_record,
    _ups_status_badge_class,
)
from sot_validator.reporting._dashboard_render import (
    HtmlDashboardGenerator,
    generate_html_dashboard,
)
from sot_validator.reporting.generators import (
    ALL_CLASSIFICATIONS,
    _index_sites,
    _resolve_report_timestamp,
    generate_json_report,
)

__all__ = [
    "DEFAULT_DASHBOARD_FILENAME",
    "DEFAULT_DASHBOARD_TITLE",
    "HtmlDashboardGenerator",
    "generate_html_dashboard",
]
