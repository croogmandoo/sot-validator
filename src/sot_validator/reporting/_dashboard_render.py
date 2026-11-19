"""HTML dashboard entry points: ``generate_html_dashboard`` and ``HtmlDashboardGenerator``."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from sot_validator.history.ledger import (
    HistoryStore,
    ItemStreakSummary,
    SubnetUtilizationSummary,
)
from sot_validator.itsm.tickets import (
    InMemoryItsmSink,
    ItsmTicketRequest,
)
from sot_validator.migration.parity import (
    ParityValidationReport,
    SiteMigrationReadinessScorecard,
)
from sot_validator.models import (
    Site,
    ValidationClassification,
    ValidationResult,
)
from sot_validator.reconciliation.reconciler import ReconciliationReport
from sot_validator.remediation.port_reclamation import (
    PortReclamationPlan,
)
from sot_validator.remediation.quarantine import (
    QuarantineEngine,
    QuarantinePolicy,
    RemediationApprovalManifest,
)
from sot_validator.remediation.sink import (
    DryRunActionPlan,
    RemediationActionType,
)
from sot_validator.reporting._dashboard_common import (
    DEFAULT_DASHBOARD_FILENAME,
    DEFAULT_DASHBOARD_TITLE,
    _coerce_itsm_tickets,
    _coerce_manifest,
    _coerce_parity_report,
    _coerce_port_reclamation_plan,
    _coerce_reconciliation,
    _coerce_streaks,
    _coerce_subnet_utilization,
    _coerce_ups_health_report,
    _esc,
)
from sot_validator.reporting._dashboard_sections import (
    _build_discovery_rows,
    _build_inventory_rows,
    _build_itsm_rows,
    _build_parity_rows,
    _build_port_rows,
    _build_quarantine_rows,
    _build_site_rows,
    _build_subnet_rows,
    _build_ups_rows,
)
from sot_validator.reporting._dashboard_template import _render_dashboard_page
from sot_validator.reporting.generators import (
    ALL_CLASSIFICATIONS,
    _index_sites,
    _resolve_report_timestamp,
    generate_json_report,
)
from sot_validator.signals.ups_health import (
    UpsFleetHealthReport,
    UpsHealthRecord,
)


def generate_html_dashboard(
    results: Sequence[ValidationResult | Mapping[str, Any]],
    *,
    sites: Optional[Sequence[Site] | Mapping[str, Site]] = None,
    action_plan: Optional[DryRunActionPlan] = None,
    approval_manifest: Optional[
        RemediationApprovalManifest | Mapping[str, Any]
    ] = None,
    manifest: Optional[RemediationApprovalManifest | Mapping[str, Any]] = None,
    streaks: Optional[
        Sequence[ItemStreakSummary | Mapping[str, Any]] | HistoryStore
    ] = None,
    reconciliation_report: Optional[
        ReconciliationReport | Mapping[str, Any]
    ] = None,
    reconciliation: Optional[ReconciliationReport | Mapping[str, Any]] = None,
    subnet_utilization: Optional[
        Sequence[SubnetUtilizationSummary | Mapping[str, Any]]
    ] = None,
    port_reclamation_plan: Optional[
        PortReclamationPlan | Mapping[str, Any]
    ] = None,
    port_plan: Optional[PortReclamationPlan | Mapping[str, Any]] = None,
    migration_parity_report: Optional[
        ParityValidationReport
        | SiteMigrationReadinessScorecard
        | Sequence[SiteMigrationReadinessScorecard | Mapping[str, Any]]
        | Mapping[str, Any]
    ] = None,
    parity_report: Optional[
        ParityValidationReport
        | SiteMigrationReadinessScorecard
        | Sequence[SiteMigrationReadinessScorecard | Mapping[str, Any]]
        | Mapping[str, Any]
    ] = None,
    migration_scorecards: Optional[
        ParityValidationReport
        | SiteMigrationReadinessScorecard
        | Sequence[SiteMigrationReadinessScorecard | Mapping[str, Any]]
        | Mapping[str, Any]
    ] = None,
    ups_health_report: Optional[
        UpsFleetHealthReport
        | UpsHealthRecord
        | Sequence[UpsHealthRecord | Mapping[str, Any]]
        | Mapping[str, Any]
    ] = None,
    ups_report: Optional[
        UpsFleetHealthReport
        | UpsHealthRecord
        | Sequence[UpsHealthRecord | Mapping[str, Any]]
        | Mapping[str, Any]
    ] = None,
    itsm_tickets: Optional[
        Sequence[ItsmTicketRequest | Mapping[str, Any]]
        | Mapping[str, Any]
        | ItsmTicketRequest
        | InMemoryItsmSink
    ] = None,
    tickets: Optional[
        Sequence[ItsmTicketRequest | Mapping[str, Any]]
        | Mapping[str, Any]
        | ItsmTicketRequest
        | InMemoryItsmSink
    ] = None,
    output_path: Optional[Path | str] = None,
    generated_at: Optional[datetime | str] = None,
    title: str = DEFAULT_DASHBOARD_TITLE,
) -> str:
    """Generate a self-contained, zero-dependency HTML5 operations dashboard."""
    report_dt = _resolve_report_timestamp(generated_at)
    sites_by_id = _index_sites(sites)

    json_report = generate_json_report(
        results,
        sites=sites_by_id if sites_by_id else None,
        action_plan=action_plan,
        output_path=None,
        generated_at=report_dt,
    )

    resolved_manifest = _coerce_manifest(
        approval_manifest if approval_manifest is not None else manifest
    )
    resolved_streaks = _coerce_streaks(streaks)
    resolved_reconciliation = _coerce_reconciliation(
        reconciliation_report
        if reconciliation_report is not None
        else reconciliation
    )
    resolved_subnets = _coerce_subnet_utilization(
        subnet_utilization, sites_by_id, results
    )
    resolved_port_plan = _coerce_port_reclamation_plan(
        port_reclamation_plan
        if port_reclamation_plan is not None
        else port_plan
    )
    raw_parity_arg = (
        migration_parity_report
        if migration_parity_report is not None
        else (
            parity_report if parity_report is not None else migration_scorecards
        )
    )
    resolved_parity = _coerce_parity_report(raw_parity_arg)
    resolved_ups = _coerce_ups_health_report(
        ups_health_report if ups_health_report is not None else ups_report
    )
    resolved_tickets = _coerce_itsm_tickets(
        itsm_tickets if itsm_tickets is not None else tickets
    )

    # Compute KPI counts
    total_items = int(json_report["total_items"])
    by_cls = json_report["summary"]["by_classification"]
    active_count = int(
        by_cls[ValidationClassification.CONFIRMED_ACTIVE.value]["count"]
    )
    stale_count = int(
        by_cls[ValidationClassification.STALE_LIKELY_UNUSED.value]["count"]
    )
    unreachable_count = int(
        by_cls[ValidationClassification.UNREACHABLE_NEEDS_REVIEW.value]["count"]
    )
    insufficient_count = int(
        by_cls[ValidationClassification.INSUFFICIENT_DATA.value]["count"]
    )

    derived_manifest_from_streaks: Optional[RemediationApprovalManifest] = None
    if resolved_manifest is None and resolved_streaks is not None:
        engine = QuarantineEngine(QuarantinePolicy())
        eval_source: Sequence[Any] = (
            results if results else resolved_streaks
        )
        derived_manifest_from_streaks = engine.evaluate(
            eval_source,
            history=resolved_streaks,
            sites=list(sites_by_id.values()) if sites_by_id else None,
            generated_at=report_dt,
            include_below_threshold=True,
        )

    if resolved_manifest is not None:
        quarantine_eligible_count = len(resolved_manifest.eligible_entries)
    elif derived_manifest_from_streaks is not None:
        quarantine_eligible_count = len(
            derived_manifest_from_streaks.eligible_entries
        )
    elif action_plan is not None:
        quarantine_eligible_count = int(
            action_plan.summary_by_action.get(
                RemediationActionType.MARK_STALE_CANDIDATE.value, 0
            )
        )
    else:
        rem_summary = json_report.get("remediation_plan", {}).get(
            "summary_by_action", {}
        )
        quarantine_eligible_count = int(
            rem_summary.get(
                RemediationActionType.MARK_STALE_CANDIDATE.value, 0
            )
        )

    untracked_discrepancies_count = (
        resolved_reconciliation.total_discrepancies
        if resolved_reconciliation is not None
        else 0
    )

    reclaimable_ports_count = (
        len(resolved_port_plan.candidates)
        if resolved_port_plan is not None
        else 0
    )
    poe_watts_saved = (
        float(resolved_port_plan.estimated_poe_watts_saved)
        if resolved_port_plan is not None
        else 0.0
    )
    ready_cutover_sites_count = (
        resolved_parity.ready_for_cutover_count
        if resolved_parity is not None
        else 0
    )
    ups_alerts_count = (
        resolved_ups.critical_count
        + resolved_ups.warning_count
        + resolved_ups.unreachable_count
        if resolved_ups is not None
        else 0
    )
    itsm_tickets_count = len(resolved_tickets)

    enriched_results: list[dict[str, Any]] = json_report["results"]
    by_site_summary: dict[str, dict[str, Any]] = json_report["summary"][
        "by_site"
    ]

    # Collect filter dropdown options
    all_site_ids = sorted(
        set(by_site_summary.keys())
        | {str(item["site_id"]) for item in enriched_results}
    )
    all_item_types = sorted(
        {str(item["item_type"]) for item in enriched_results}
    )

    site_rows_html = _build_site_rows(by_site_summary)
    subnet_rows_html = _build_subnet_rows(resolved_subnets)
    inventory_rows_html, inventory_data_html = _build_inventory_rows(
        enriched_results
    )
    manifest_meta_html, quarantine_rows_html = _build_quarantine_rows(
        resolved_manifest, derived_manifest_from_streaks, action_plan
    )
    disc_by_type_html, disc_rows_html = _build_discovery_rows(
        resolved_reconciliation
    )
    (
        port_plan_meta_html,
        port_candidates_rows_html,
        port_blocked_rows_html,
    ) = _build_port_rows(resolved_port_plan)
    (
        parity_meta_html,
        parity_scorecard_rows_html,
        parity_discrepancy_rows_html,
    ) = _build_parity_rows(resolved_parity)
    ups_meta_html, ups_rows_html = _build_ups_rows(resolved_ups)
    itsm_rows_html = _build_itsm_rows(resolved_tickets)

    cls_options_html = "".join(
        f'<option value="{_esc(c.value)}">{_esc(c.value)}</option>'
        for c in ALL_CLASSIFICATIONS
    )
    site_options_html = "".join(
        f'<option value="{_esc(sid)}">{_esc(sid)}</option>'
        for sid in all_site_ids
    )
    type_options_html = "".join(
        f'<option value="{_esc(t)}">{_esc(t)}</option>'
        for t in all_item_types
    )

    gen_at_str = _esc(json_report["generated_at"])
    safe_title = _esc(title)

    html_doc = _render_dashboard_page(
        safe_title=safe_title,
        gen_at_str=gen_at_str,
        total_items=total_items,
        active_count=active_count,
        stale_count=stale_count,
        unreachable_count=unreachable_count,
        insufficient_count=insufficient_count,
        quarantine_eligible_count=quarantine_eligible_count,
        untracked_discrepancies_count=untracked_discrepancies_count,
        reclaimable_ports_count=reclaimable_ports_count,
        poe_watts_saved=poe_watts_saved,
        ready_cutover_sites_count=ready_cutover_sites_count,
        ups_alerts_count=ups_alerts_count,
        itsm_tickets_count=itsm_tickets_count,
        site_rows_html=site_rows_html,
        subnet_rows_html=subnet_rows_html,
        cls_options_html=cls_options_html,
        site_options_html=site_options_html,
        type_options_html=type_options_html,
        enriched_results=enriched_results,
        inventory_rows_html=inventory_rows_html,
        inventory_data_html=inventory_data_html,
        manifest_meta_html=manifest_meta_html,
        quarantine_rows_html=quarantine_rows_html,
        disc_by_type_html=disc_by_type_html,
        disc_rows_html=disc_rows_html,
        port_plan_meta_html=port_plan_meta_html,
        port_candidates_rows_html=port_candidates_rows_html,
        port_blocked_rows_html=port_blocked_rows_html,
        parity_meta_html=parity_meta_html,
        parity_scorecard_rows_html=parity_scorecard_rows_html,
        parity_discrepancy_rows_html=parity_discrepancy_rows_html,
        ups_meta_html=ups_meta_html,
        ups_rows_html=ups_rows_html,
        itsm_rows_html=itsm_rows_html,
    )

    if output_path is not None:
        target = Path(output_path)
        if target.exists() and target.is_dir():
            target = target / DEFAULT_DASHBOARD_FILENAME
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(html_doc, encoding="utf-8")

    return html_doc


class HtmlDashboardGenerator:
    """Object-oriented wrapper for generating self-contained HTML5 operations dashboards."""

    DEFAULT_FILENAME = DEFAULT_DASHBOARD_FILENAME

    def render(
        self,
        results: Sequence[ValidationResult | Mapping[str, Any]],
        *,
        sites: Optional[Sequence[Site] | Mapping[str, Site]] = None,
        action_plan: Optional[DryRunActionPlan] = None,
        approval_manifest: Optional[
            RemediationApprovalManifest | Mapping[str, Any]
        ] = None,
        manifest: Optional[
            RemediationApprovalManifest | Mapping[str, Any]
        ] = None,
        streaks: Optional[
            Sequence[ItemStreakSummary | Mapping[str, Any]] | HistoryStore
        ] = None,
        reconciliation_report: Optional[
            ReconciliationReport | Mapping[str, Any]
        ] = None,
        reconciliation: Optional[
            ReconciliationReport | Mapping[str, Any]
        ] = None,
        subnet_utilization: Optional[
            Sequence[SubnetUtilizationSummary | Mapping[str, Any]]
        ] = None,
        port_reclamation_plan: Optional[
            PortReclamationPlan | Mapping[str, Any]
        ] = None,
        port_plan: Optional[PortReclamationPlan | Mapping[str, Any]] = None,
        migration_parity_report: Optional[
            ParityValidationReport
            | SiteMigrationReadinessScorecard
            | Sequence[SiteMigrationReadinessScorecard | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        parity_report: Optional[
            ParityValidationReport
            | SiteMigrationReadinessScorecard
            | Sequence[SiteMigrationReadinessScorecard | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        migration_scorecards: Optional[
            ParityValidationReport
            | SiteMigrationReadinessScorecard
            | Sequence[SiteMigrationReadinessScorecard | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        ups_health_report: Optional[
            UpsFleetHealthReport
            | UpsHealthRecord
            | Sequence[UpsHealthRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        ups_report: Optional[
            UpsFleetHealthReport
            | UpsHealthRecord
            | Sequence[UpsHealthRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        itsm_tickets: Optional[
            Sequence[ItsmTicketRequest | Mapping[str, Any]]
            | Mapping[str, Any]
            | ItsmTicketRequest
            | InMemoryItsmSink
        ] = None,
        tickets: Optional[
            Sequence[ItsmTicketRequest | Mapping[str, Any]]
            | Mapping[str, Any]
            | ItsmTicketRequest
            | InMemoryItsmSink
        ] = None,
        output_path: Optional[Path | str] = None,
        generated_at: Optional[datetime | str] = None,
        title: str = DEFAULT_DASHBOARD_TITLE,
    ) -> str:
        return generate_html_dashboard(
            results,
            sites=sites,
            action_plan=action_plan,
            approval_manifest=approval_manifest,
            manifest=manifest,
            streaks=streaks,
            reconciliation_report=reconciliation_report,
            reconciliation=reconciliation,
            subnet_utilization=subnet_utilization,
            port_reclamation_plan=port_reclamation_plan,
            port_plan=port_plan,
            migration_parity_report=migration_parity_report,
            parity_report=parity_report,
            migration_scorecards=migration_scorecards,
            ups_health_report=ups_health_report,
            ups_report=ups_report,
            itsm_tickets=itsm_tickets,
            tickets=tickets,
            output_path=output_path,
            generated_at=generated_at,
            title=title,
        )

    generate = render

    def write(
        self,
        results: Sequence[ValidationResult | Mapping[str, Any]],
        output_path: Path | str = DEFAULT_DASHBOARD_FILENAME,
        *,
        sites: Optional[Sequence[Site] | Mapping[str, Site]] = None,
        action_plan: Optional[DryRunActionPlan] = None,
        approval_manifest: Optional[
            RemediationApprovalManifest | Mapping[str, Any]
        ] = None,
        manifest: Optional[
            RemediationApprovalManifest | Mapping[str, Any]
        ] = None,
        streaks: Optional[
            Sequence[ItemStreakSummary | Mapping[str, Any]] | HistoryStore
        ] = None,
        reconciliation_report: Optional[
            ReconciliationReport | Mapping[str, Any]
        ] = None,
        reconciliation: Optional[
            ReconciliationReport | Mapping[str, Any]
        ] = None,
        subnet_utilization: Optional[
            Sequence[SubnetUtilizationSummary | Mapping[str, Any]]
        ] = None,
        port_reclamation_plan: Optional[
            PortReclamationPlan | Mapping[str, Any]
        ] = None,
        port_plan: Optional[PortReclamationPlan | Mapping[str, Any]] = None,
        migration_parity_report: Optional[
            ParityValidationReport
            | SiteMigrationReadinessScorecard
            | Sequence[SiteMigrationReadinessScorecard | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        parity_report: Optional[
            ParityValidationReport
            | SiteMigrationReadinessScorecard
            | Sequence[SiteMigrationReadinessScorecard | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        migration_scorecards: Optional[
            ParityValidationReport
            | SiteMigrationReadinessScorecard
            | Sequence[SiteMigrationReadinessScorecard | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        ups_health_report: Optional[
            UpsFleetHealthReport
            | UpsHealthRecord
            | Sequence[UpsHealthRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        ups_report: Optional[
            UpsFleetHealthReport
            | UpsHealthRecord
            | Sequence[UpsHealthRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        itsm_tickets: Optional[
            Sequence[ItsmTicketRequest | Mapping[str, Any]]
            | Mapping[str, Any]
            | ItsmTicketRequest
            | InMemoryItsmSink
        ] = None,
        tickets: Optional[
            Sequence[ItsmTicketRequest | Mapping[str, Any]]
            | Mapping[str, Any]
            | ItsmTicketRequest
            | InMemoryItsmSink
        ] = None,
        generated_at: Optional[datetime | str] = None,
        title: str = DEFAULT_DASHBOARD_TITLE,
    ) -> Path:
        target = Path(output_path)
        if target.exists() and target.is_dir():
            target = target / DEFAULT_DASHBOARD_FILENAME
        generate_html_dashboard(
            results,
            sites=sites,
            action_plan=action_plan,
            approval_manifest=approval_manifest,
            manifest=manifest,
            streaks=streaks,
            reconciliation_report=reconciliation_report,
            reconciliation=reconciliation,
            subnet_utilization=subnet_utilization,
            port_reclamation_plan=port_reclamation_plan,
            port_plan=port_plan,
            migration_parity_report=migration_parity_report,
            parity_report=parity_report,
            migration_scorecards=migration_scorecards,
            ups_health_report=ups_health_report,
            ups_report=ups_report,
            itsm_tickets=itsm_tickets,
            tickets=tickets,
            output_path=target,
            generated_at=generated_at,
            title=title,
        )
        return target
