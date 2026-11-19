"""Row and fragment builders for the numbered HTML dashboard sections 1-9."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Optional

from sot_validator.history.ledger import SubnetUtilizationSummary
from sot_validator.itsm.tickets import ItsmTicketRequest
from sot_validator.migration.parity import ParityValidationReport
from sot_validator.models import ValidationClassification
from sot_validator.reconciliation.reconciler import (
    ALL_DISCREPANCY_TYPES,
    ReconciliationReport,
)
from sot_validator.remediation.port_reclamation import (
    PortReclamationPlan,
)
from sot_validator.remediation.quarantine import (
    ApprovalStatus,
    QuarantineGraduationStatus,
    RemediationApprovalManifest,
    RemediationOperation,
)
from sot_validator.remediation.sink import DryRunActionPlan
from sot_validator.reporting._dashboard_common import (
    _approval_badge_class,
    _cutover_badge_class,
    _encode_inventory_payload,
    _esc,
    _ups_status_badge_class,
)
from sot_validator.signals.ups_health import UpsFleetHealthReport


def _build_site_rows(
    by_site_summary: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    # 1. Build Site Summary Rows
    site_rows_html: list[str] = []
    if by_site_summary:
        for sid, sdata in by_site_summary.items():
            site_rows_html.append(
                "<tr>"
                f"<td><code>{_esc(sid)}</code></td>"
                f"<td>{_esc(sdata.get('site_name', sid))}</td>"
                f"<td class=\"num\">{int(sdata.get('total', 0))}</td>"
                f"<td class=\"num\">{int(sdata.get(ValidationClassification.CONFIRMED_ACTIVE.value, 0))}</td>"
                f"<td class=\"num\">{int(sdata.get(ValidationClassification.STALE_LIKELY_UNUSED.value, 0))}</td>"
                f"<td class=\"num\">{int(sdata.get(ValidationClassification.UNREACHABLE_NEEDS_REVIEW.value, 0))}</td>"
                f"<td class=\"num\">{int(sdata.get(ValidationClassification.INSUFFICIENT_DATA.value, 0))}</td>"
                "</tr>"
            )
    else:
        site_rows_html.append(
            '<tr><td colspan="7" class="empty-cell">No site summary records available.</td></tr>'
        )
    return site_rows_html


def _build_subnet_rows(
    resolved_subnets: Sequence[SubnetUtilizationSummary],
) -> list[str]:
    # 2. Build /24 Subnet Utilization Rows
    subnet_rows_html: list[str] = []
    if resolved_subnets:
        for sub in resolved_subnets:
            pct = max(0.0, min(100.0, float(sub.active_utilization_pct)))
            subnet_rows_html.append(
                "<tr>"
                f"<td><code>{_esc(sub.subnet_id)}</code></td>"
                f"<td><code>{_esc(sub.site_id or '-')}</code></td>"
                f"<td><code>{_esc(sub.cidr)}</code></td>"
                f"<td class=\"num\">{int(sub.total_assigned_ips)}</td>"
                f"<td class=\"num\">{int(sub.confirmed_active_ips)}</td>"
                f"<td class=\"num\">{int(sub.stale_reclaimable_ips)}</td>"
                "<td>"
                '<div class="utilization-cell">'
                f'<span class="utilization-label">{pct:.2f}%</span>'
                '<div class="progress-bar">'
                f'<div class="progress-fill" style="width: {pct:.2f}%;"></div>'
                "</div>"
                "</div>"
                "</td>"
                "</tr>"
            )
    else:
        subnet_rows_html.append(
            '<tr><td colspan="7" class="empty-cell">No /24 subnet utilization data available.</td></tr>'
        )
    return subnet_rows_html


def _build_inventory_rows(
    enriched_results: Sequence[Mapping[str, Any]],
) -> tuple[list[str], str]:
    # 3. Encode Inventory Classification Rows for Client-Side Rendering
    inventory_data_html = ""
    if enriched_results:
        inventory_rows_html = [
            '<tr id="inventory-status-row"><td colspan="11" class="empty-cell">'
            "Loading inventory\u2026 (requires JavaScript)</td></tr>"
        ]
        inventory_data_html = (
            '<script id="inventory-data" type="application/octet-stream">'
            f"{_encode_inventory_payload(enriched_results)}</script>"
        )
    else:
        inventory_rows_html = [
            '<tr><td colspan="11" class="empty-cell">No inventory validation results available.</td></tr>'
        ]
    return inventory_rows_html, inventory_data_html


def _build_quarantine_rows(
    resolved_manifest: Optional[RemediationApprovalManifest],
    derived_manifest_from_streaks: Optional[RemediationApprovalManifest],
    action_plan: Optional[DryRunActionPlan],
) -> tuple[str, list[str]]:
    # 4. Build Phase 2 Quarantine & Remediation Queue Section
    active_manifest = resolved_manifest or derived_manifest_from_streaks
    manifest_meta_html = ""
    quarantine_rows_html: list[str] = []

    if resolved_manifest is not None:
        digest_valid = resolved_manifest.verify_digest()
        digest_badge = (
            '<span class="badge badge-active">SHA-256 VERIFIED</span>'
            if digest_valid
            else '<span class="badge badge-stale">DIGEST MISMATCH</span>'
        )
        manifest_meta_html = (
            '<div class="section-meta">'
            f"<span><strong>Manifest ID:</strong> <code>{_esc(resolved_manifest.manifest_id)}</code></span> "
            f"<span><strong>SHA-256 Digest:</strong> <code>{_esc(resolved_manifest.manifest_sha256)}</code></span> "
            f"{digest_badge}"
            "</div>"
        )

    if active_manifest is not None and active_manifest.entries:
        for entry in active_manifest.entries:
            op_val = (
                entry.target_operation.value
                if isinstance(entry.target_operation, RemediationOperation)
                else str(entry.target_operation)
            )
            grad_val = (
                entry.graduation_status.value
                if isinstance(entry.graduation_status, QuarantineGraduationStatus)
                else str(entry.graduation_status)
            )
            app_val = (
                entry.approval_status.value
                if isinstance(entry.approval_status, ApprovalStatus)
                else str(entry.approval_status)
            )
            app_badge = _approval_badge_class(app_val)
            quarantine_rows_html.append(
                "<tr>"
                f"<td><code>{_esc(entry.item_id)}</code></td>"
                f"<td><code>{_esc(entry.site_id)}</code></td>"
                f"<td>{_esc(entry.item_type)}</td>"
                f"<td>{_esc(entry.name)}</td>"
                f'<td class="num">{int(entry.consecutive_stale_runs)}</td>'
                f'<td class="num">{float(entry.stale_duration_days):.1f}</td>'
                f"<td><code>{_esc(op_val)}</code></td>"
                f"<td><code>{_esc(grad_val)}</code></td>"
                f'<td><span class="badge {app_badge}">{_esc(app_val)}</span></td>'
                f"<td>{_esc(entry.exemption_reason or entry.review_note or entry.rationale or '-')}</td>"
                "</tr>"
            )
    elif action_plan is not None and action_plan.actions:
        for act in action_plan.actions:
            quarantine_rows_html.append(
                "<tr>"
                f"<td><code>{_esc(act.item_id)}</code></td>"
                f"<td><code>{_esc(act.site_id)}</code></td>"
                f"<td>{_esc(act.item_type)}</td>"
                f"<td>{_esc(act.name)}</td>"
                '<td class="num">1</td>'
                '<td class="num">0.0</td>'
                f"<td><code>{_esc(act.action_type.value)}</code></td>"
                "<td><code>DRY_RUN_CANDIDATE</code></td>"
                '<td><span class="badge badge-unreachable">PENDING</span></td>'
                f"<td>{_esc(act.rationale or '-')}</td>"
                "</tr>"
            )
    else:
        quarantine_rows_html.append(
            '<tr><td colspan="10" class="empty-cell">No quarantine or remediation queue entries present.</td></tr>'
        )
    return manifest_meta_html, quarantine_rows_html


def _build_discovery_rows(
    resolved_reconciliation: Optional[ReconciliationReport],
) -> tuple[list[str], list[str]]:
    # 5. Build Phase 3 Reverse Discovery / Untracked Assets Section
    disc_by_type_html: list[str] = []
    disc_rows_html: list[str] = []
    if resolved_reconciliation is not None:
        by_type = resolved_reconciliation.summary_by_type
        for dtype in ALL_DISCREPANCY_TYPES:
            cnt = int(by_type.get(dtype.value, 0))
            disc_by_type_html.append(
                '<div class="mini-stat">'
                f'<span class="mini-stat-label"><code>{_esc(dtype.value)}</code></span>'
                f'<span class="mini-stat-value">{cnt}</span>'
                "</div>"
            )
        if resolved_reconciliation.discrepancies:
            for disc in resolved_reconciliation.discrepancies:
                disc_rows_html.append(
                    "<tr>"
                    f"<td><code>{_esc(disc.discrepancy_id)}</code></td>"
                    f"<td><code>{_esc(disc.discrepancy_type.value)}</code></td>"
                    f"<td><code>{_esc(disc.site_id)}</code></td>"
                    f"<td><code>{_esc(disc.observed_identifier)}</code></td>"
                    f"<td><code>{_esc(disc.observed_ip or '-')}</code></td>"
                    f"<td><code>{_esc(disc.observed_mac or '-')}</code></td>"
                    f"<td>{_esc(disc.observed_hostname or '-')}</td>"
                    f"<td><code>{_esc(disc.source)}</code></td>"
                    f"<td><code>{_esc(disc.sot_item_id or '-')}</code></td>"
                    f"<td>{_esc(disc.details or '-')}</td>"
                    f"<td>{_esc(disc.recommended_onboarding_action or '-')}</td>"
                    "</tr>"
                )
        else:
            disc_rows_html.append(
                '<tr><td colspan="11" class="empty-cell">No untracked assets or attribute discrepancies detected.</td></tr>'
            )
    else:
        for dtype in ALL_DISCREPANCY_TYPES:
            disc_by_type_html.append(
                '<div class="mini-stat">'
                f'<span class="mini-stat-label"><code>{_esc(dtype.value)}</code></span>'
                '<span class="mini-stat-value">0</span>'
                "</div>"
            )
        disc_rows_html.append(
            '<tr><td colspan="11" class="empty-cell">No Phase 3 reverse discovery reconciliation report provided.</td></tr>'
        )
    return disc_by_type_html, disc_rows_html


def _build_port_rows(
    resolved_port_plan: Optional[PortReclamationPlan],
) -> tuple[str, list[str], list[str]]:
    # 6. Build Phase 4 Extreme Networks Switch Port & PoE Reclamation Section
    port_plan_meta_html = ""
    port_candidates_rows_html: list[str] = []
    port_blocked_rows_html: list[str] = []
    if resolved_port_plan is not None:
        port_plan_meta_html = (
            '<div class="section-meta">'
            f"<span><strong>Plan ID:</strong> <code>{_esc(resolved_port_plan.plan_id)}</code></span> "
            f"<span><strong>CLI Dialect:</strong> <code>{_esc(resolved_port_plan.dialect.value.upper())}</code></span> "
            f"<span><strong>Eligible Ports:</strong> <code>{len(resolved_port_plan.candidates)}</code></span> "
            f"<span><strong>LLDP Guard Protected:</strong> <code>{len(resolved_port_plan.blocked_ports)}</code></span> "
            f"<span><strong>Estimated PoE Savings:</strong> <code>{resolved_port_plan.estimated_poe_watts_saved:.2f}W</code></span> "
            '<span class="badge badge-active">DRY-RUN STAGED</span>'
            "</div>"
        )
        if resolved_port_plan.candidates:
            for cand in resolved_port_plan.candidates:
                exos_cmds_str = " ; ".join(cand.exos_disable_commands)
                voss_cmds_str = " ; ".join(cand.voss_disable_commands)
                port_candidates_rows_html.append(
                    "<tr>"
                    f"<td><code>{_esc(cand.site_id or '-')}</code></td>"
                    f"<td><code>{_esc(cand.device_id)}</code></td>"
                    f"<td><code>{_esc(cand.port_name)}</code></td>"
                    f'<td class="num">{cand.inactive_runs}</td>'
                    f'<td class="num">{cand.inactive_days:.1f}</td>'
                    f'<td class="num">{cand.estimated_poe_watts_saved:.2f}W</td>'
                    f"<td><code>{_esc(exos_cmds_str)}</code></td>"
                    f"<td><code>{_esc(voss_cmds_str)}</code></td>"
                    f"<td><code>{_esc(cand.exos_rollback_command)}</code></td>"
                    "</tr>"
                )
        else:
            port_candidates_rows_html.append(
                '<tr><td colspan="9" class="empty-cell">No eligible switch ports for reclamation.</td></tr>'
            )

        if resolved_port_plan.blocked_ports:
            for bport in resolved_port_plan.blocked_ports:
                rules_str = ", ".join(bport.matched_rules) or "-"
                port_blocked_rows_html.append(
                    "<tr>"
                    f"<td><code>{_esc(bport.site_id or '-')}</code></td>"
                    f"<td><code>{_esc(bport.device_id)}</code></td>"
                    f"<td><code>{_esc(bport.port_name)}</code></td>"
                    f"<td><code>{_esc(bport.port_id)}</code></td>"
                    f'<td><span class="badge badge-stale">PROTECTED</span></td>'
                    f"<td><code>{_esc(rules_str)}</code></td>"
                    f"<td>{_esc(bport.block_reason)}</td>"
                    "</tr>"
                )
        else:
            port_blocked_rows_html.append(
                '<tr><td colspan="7" class="empty-cell">No LLDP Uplink Guard blocked ports recorded.</td></tr>'
            )
    else:
        port_candidates_rows_html.append(
            '<tr><td colspan="9" class="empty-cell">No Phase 4 Extreme port reclamation plan provided.</td></tr>'
        )
        port_blocked_rows_html.append(
            '<tr><td colspan="7" class="empty-cell">No Phase 4 LLDP Uplink Guard audit records provided.</td></tr>'
        )
    return port_plan_meta_html, port_candidates_rows_html, port_blocked_rows_html


def _build_parity_rows(
    resolved_parity: Optional[ParityValidationReport],
) -> tuple[str, list[str], list[str]]:
    # 7. Build Phase 5 Modern SoT Dual-Run Parity & Migration Readiness Scorecards Section
    parity_meta_html = ""
    parity_scorecard_rows_html: list[str] = []
    parity_discrepancy_rows_html: list[str] = []
    if resolved_parity is not None:
        overall_rec_badge = _cutover_badge_class(
            resolved_parity.overall_recommendation.value
        )
        parity_meta_html = (
            '<div class="section-meta">'
            f"<span><strong>Total Sites Evaluated:</strong> <code>{resolved_parity.total_sites}</code></span> "
            f"<span><strong>Ready for Cutover:</strong> <code>{resolved_parity.ready_for_cutover_count}</code></span> "
            f"<span><strong>Needs Remediation:</strong> <code>{resolved_parity.needs_remediation_count}</code></span> "
            f"<span><strong>Blocked:</strong> <code>{resolved_parity.blocked_count}</code></span> "
            f"<span><strong>Overall Parity:</strong> <code>{resolved_parity.overall_parity_percentage:.2f}%</code></span> "
            f"<span><strong>Average Readiness Score:</strong> <code>{resolved_parity.average_readiness_score:.2f}%</code></span> "
            f'<span class="badge {overall_rec_badge}">{_esc(resolved_parity.overall_recommendation.value)}</span>'
            "</div>"
        )
        if resolved_parity.scorecards:
            for sc in resolved_parity.scorecards:
                rec_badge = _cutover_badge_class(sc.recommendation.value)
                blockers_str = (
                    "; ".join(sc.blocking_reasons)
                    if sc.blocking_reasons
                    else "None (100% Parity Verified)"
                )
                parity_scorecard_rows_html.append(
                    "<tr>"
                    f"<td><code>{_esc(sc.site_id)}</code></td>"
                    f"<td>{_esc(sc.site_name)}</td>"
                    f'<td class="num"><strong>{sc.readiness_score:.2f}%</strong></td>'
                    f'<td class="num">{sc.parity_match_percentage:.2f}%</td>'
                    f'<td><span class="badge {rec_badge}">{_esc(sc.recommendation.value)}</span></td>'
                    f'<td class="num">{sc.matched_modern_items}/{sc.expected_golden_items}</td>'
                    f'<td class="num">{len(sc.unwaived_discrepancies)} (waived: {sc.waived_discrepancy_count})</td>'
                    f'<td class="num">{sc.unresolved_untracked_count}</td>'
                    f"<td>{_esc(blockers_str)}</td>"
                    "</tr>"
                )
                for pdisc in sc.discrepancies:
                    parity_discrepancy_rows_html.append(
                        "<tr>"
                        f"<td><code>{_esc(pdisc.discrepancy_id)}</code></td>"
                        f"<td><code>{_esc(pdisc.discrepancy_type.value)}</code></td>"
                        f"<td><code>{_esc(pdisc.site_id)}</code></td>"
                        f"<td><code>{_esc(pdisc.entity_type)}</code></td>"
                        f"<td><code>{_esc(pdisc.item_identifier)}</code></td>"
                        f"<td><code>{_esc(pdisc.attribute_name or '-')}</code></td>"
                        f"<td><code>{_esc(pdisc.expected_value if pdisc.expected_value is not None else '-')}</code></td>"
                        f"<td><code>{_esc(pdisc.actual_value if pdisc.actual_value is not None else '-')}</code></td>"
                        f"<td>{_esc(pdisc.details or '-')}</td>"
                        "</tr>"
                    )
        else:
            parity_scorecard_rows_html.append(
                '<tr><td colspan="9" class="empty-cell">No site migration readiness scorecards available.</td></tr>'
            )
        if not parity_discrepancy_rows_html:
            parity_discrepancy_rows_html.append(
                '<tr><td colspan="9" class="empty-cell">No dual-run parity discrepancies detected.</td></tr>'
            )
    else:
        parity_scorecard_rows_html.append(
            '<tr><td colspan="9" class="empty-cell">No Phase 5 Modern SoT parity report provided.</td></tr>'
        )
        parity_discrepancy_rows_html.append(
            '<tr><td colspan="9" class="empty-cell">No Phase 5 dual-run parity discrepancies provided.</td></tr>'
        )
    return parity_meta_html, parity_scorecard_rows_html, parity_discrepancy_rows_html


def _build_ups_rows(
    resolved_ups: Optional[UpsFleetHealthReport],
) -> tuple[str, list[str]]:
    # 8. Build Phase 6 APC UPS Fleet Health & Environmental Telemetry Section
    ups_meta_html = ""
    ups_rows_html: list[str] = []
    if resolved_ups is not None:
        ups_meta_html = (
            '<div class="section-meta">'
            f"<span><strong>Total UPS Units:</strong> <code>{resolved_ups.total_units}</code></span> "
            f"<span><strong>Healthy:</strong> <code>{resolved_ups.healthy_count}</code></span> "
            f"<span><strong>Warning:</strong> <code>{resolved_ups.warning_count}</code></span> "
            f"<span><strong>Critical:</strong> <code>{resolved_ups.critical_count}</code></span> "
            f"<span><strong>Unreachable:</strong> <code>{resolved_ups.unreachable_count}</code></span> "
            f"<span><strong>Battery Replacement Needed:</strong> <code>{len(resolved_ups.battery_replacement_units)}</code></span> "
            f"<span><strong>Low Runtime:</strong> <code>{len(resolved_ups.low_runtime_units)}</code></span> "
            f"<span><strong>Thermal Alerts:</strong> <code>{len(resolved_ups.thermal_alert_units)}</code></span>"
            "</div>"
        )
        if resolved_ups.records:
            for urec in resolved_ups.records:
                ubadge = _ups_status_badge_class(urec.status.value)
                adv_str = ", ".join(urec.advisories) if urec.advisories else "NONE"
                runtime_str = (
                    f"{urec.runtime_remaining_minutes:.1f} min"
                    if urec.runtime_remaining_minutes is not None
                    else "-"
                )
                temp_str = (
                    f"{urec.temperature_celsius:.1f} C"
                    if urec.temperature_celsius is not None
                    else "-"
                )
                load_str = (
                    f"{urec.output_load_pct:.1f}%"
                    if urec.output_load_pct is not None
                    else "-"
                )
                ups_rows_html.append(
                    "<tr>"
                    f"<td><code>{_esc(urec.site_id)}</code></td>"
                    f"<td><code>{_esc(urec.equipment_id)}</code></td>"
                    f"<td>{_esc(urec.name)}</td>"
                    f"<td><code>{_esc(urec.ip_address or '-')}</code></td>"
                    f"<td>{_esc(urec.model or 'APC Smart-UPS')}</td>"
                    f'<td><span class="badge {ubadge}">{_esc(urec.status.value)}</span></td>'
                    f"<td><code>{_esc(urec.battery_status or '-')}</code></td>"
                    f"<td><code>{'YES' if urec.needs_battery_replacement else 'NO'}</code></td>"
                    f'<td class="num">{_esc(runtime_str)}</td>'
                    f'<td class="num">{_esc(temp_str)}</td>'
                    f'<td class="num">{_esc(load_str)}</td>'
                    f"<td><code>{_esc(urec.output_status or '-')}</code></td>"
                    f"<td><code>{_esc(adv_str)}</code></td>"
                    "</tr>"
                )
        else:
            ups_rows_html.append(
                '<tr><td colspan="13" class="empty-cell">No APC UPS health records evaluated.</td></tr>'
            )
    else:
        ups_rows_html.append(
            '<tr><td colspan="13" class="empty-cell">No Phase 6 APC UPS fleet health telemetry report provided.</td></tr>'
        )
    return ups_meta_html, ups_rows_html


def _build_itsm_rows(
    resolved_tickets: Sequence[ItsmTicketRequest],
) -> list[str]:
    # 9. Build Phase 6 ITSM Change-Ticket & Approval Governance Queue Section
    itsm_rows_html: list[str] = []
    if resolved_tickets:
        for tkt in resolved_tickets:
            tbadge = _approval_badge_class(tkt.approval_status.value)
            sites_str = ", ".join(tkt.site_ids) if tkt.site_ids else "-"
            itsm_rows_html.append(
                "<tr>"
                f"<td><code>{_esc(tkt.ticket_id)}</code></td>"
                f"<td><code>{_esc(tkt.workflow_type.value)}</code></td>"
                f"<td>{_esc(tkt.title)}</td>"
                f"<td><code>{_esc(tkt.risk)}</code> / <code>{_esc(tkt.priority)}</code></td>"
                f"<td><code>{_esc(tkt.cmdb_ci or '-')}</code></td>"
                f"<td><code>{_esc(sites_str)}</code></td>"
                f"<td><code>{_esc(tkt.artifact_id or '-')}</code></td>"
                f"<td><code>{_esc(tkt.artifact_sha256 or '-')}</code></td>"
                f'<td><span class="badge {tbadge}">{_esc(tkt.approval_status.value)}</span></td>'
                f"<td>{_esc(tkt.approved_by or '-')}</td>"
                "</tr>"
            )
    else:
        itsm_rows_html.append(
            '<tr><td colspan="10" class="empty-cell">No Phase 6 ITSM change tickets or incident payloads queued.</td></tr>'
        )
    return itsm_rows_html
