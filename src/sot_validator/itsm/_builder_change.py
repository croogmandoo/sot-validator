"""ITSM payload builder mixin: quarantine and port reclamation change requests."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Optional

from sot_validator.itsm._enums import (
    ItsmWorkflowType,
    TicketApprovalStatus,
    TicketPriority,
    TicketRisk,
)
from sot_validator.itsm._request import (
    ItsmTicketRequest,
    _deterministic_ticket_id,
    compute_artifact_sha256,
)
from sot_validator.remediation.executor import (
    SqlRemediationScriptGenerator,
    SqlRemediationScripts,
)
from sot_validator.remediation.port_reclamation import (
    ExtremeCliDialect,
    PortReclamationPlan,
)
from sot_validator.remediation.quarantine import (
    ApprovalStatus,
    QuarantineGraduationStatus,
    RemediationApprovalManifest,
    RemediationOperation,
)


class _ChangeTicketBuilderMixin:
    """Workflow 1 (quarantine) and Workflow 2 (port reclamation) ticket builders."""

    # ------------------------------------------------------------------
    # Workflow 1: Stale SoT Quarantine / Decommission Change Request
    # ------------------------------------------------------------------

    def build_quarantine_ticket(
        self,
        manifest: RemediationApprovalManifest | Mapping[str, Any],
        *,
        ticket_id: Optional[str] = None,
        approval_status: TicketApprovalStatus | str = TicketApprovalStatus.PENDING,
        approved_by: Optional[str] = None,
        approved_at: Optional[datetime | str] = None,
        sql_scripts: Optional[SqlRemediationScripts] = None,
        site_id: Optional[str] = None,
        project_key: Optional[str] = None,
        cmdb_ci: Optional[str] = None,
    ) -> ItsmTicketRequest:
        """Build a Stale SoT Quarantine / Decommission Change Request from a RemediationApprovalManifest."""
        manifest_obj = (
            manifest
            if isinstance(manifest, RemediationApprovalManifest)
            else RemediationApprovalManifest.from_dict(manifest)
        )
        manifest_sha = compute_artifact_sha256(manifest_obj)

        all_entries = manifest_obj.entries
        if site_id is not None:
            clean_site = site_id.strip()
            scoped_entries = [e for e in all_entries if e.site_id == clean_site]
        else:
            scoped_entries = list(all_entries)

        actionable_entries = [
            e
            for e in scoped_entries
            if e.approval_status is ApprovalStatus.APPROVED
        ]
        if not actionable_entries:
            actionable_entries = [
                e
                for e in scoped_entries
                if e.graduation_status is QuarantineGraduationStatus.ELIGIBLE
                and e.approval_status is not ApprovalStatus.REJECTED
                and e.approval_status is not ApprovalStatus.EXEMPT
            ]
        if not actionable_entries:
            actionable_entries = list(scoped_entries)

        actionable_entries.sort(
            key=lambda e: (e.site_id, e.item_type, e.item_id)
        )

        site_ids = sorted({e.site_id for e in actionable_entries})
        if not site_ids and site_id:
            site_ids = [site_id.strip()]
        item_ids = [e.item_id for e in actionable_entries]

        op_counts: dict[str, int] = {}
        for entry in actionable_entries:
            op_val = entry.target_operation.value
            op_counts[op_val] = op_counts.get(op_val, 0) + 1

        primary_ci = (
            cmdb_ci.strip()
            if cmdb_ci and cmdb_ci.strip()
            else (site_ids[0] if len(site_ids) == 1 else self.default_cmdb_ci)
        )
        affected_cis = [primary_ci, *site_ids, *item_ids]

        resolved_scripts = sql_scripts
        if resolved_scripts is None and manifest_obj.approved_entries:
            try:
                resolved_scripts = SqlRemediationScriptGenerator().generate(
                    manifest_obj,
                    execution_id=f"exec-{manifest_obj.manifest_id}",
                    executed_at=manifest_obj.generated_at,
                )
            except Exception:
                resolved_scripts = None

        forward_lines: list[str] = [
            f"1. Verify change ticket approval and manifest SHA-256 digest ({manifest_sha}).",
            f"2. Execute gated SoT quarantine remediation for manifest {manifest_obj.manifest_id} ({len(actionable_entries)} record(s) across {len(site_ids) or 1} site(s)):",
        ]
        for entry in actionable_entries:
            forward_lines.append(
                f"   - [{entry.site_id}] {entry.item_type} {entry.item_id} ({entry.name}): "
                f"{entry.target_operation.value} (stale {entry.consecutive_stale_runs} runs / {entry.stale_duration_days:.1f} days, confidence={entry.confidence:.2f})"
            )
        if resolved_scripts is not None and resolved_scripts.remediate_sql.strip():
            forward_lines.append("")
            forward_lines.append("Forward SQL Script (remediate.sql):")
            forward_lines.append(resolved_scripts.remediate_sql.strip())
        else:
            forward_lines.append("")
            forward_lines.append(
                f"CLI Execution: sot-validator remediate --execute-approved-plan {manifest_obj.manifest_id}.json --confirm-write"
            )

        backout_lines: list[str] = [
            f"1. Restore pre-change SoT database records from rollback script (rollback.sql) or append-only journal (remediation_journal.jsonl) for manifest {manifest_obj.manifest_id}.",
            "2. Re-verify restored record status in SoT snapshot.",
        ]
        if resolved_scripts is not None and resolved_scripts.rollback_sql.strip():
            backout_lines.append("")
            backout_lines.append("Rollback SQL Script (rollback.sql):")
            backout_lines.append(resolved_scripts.rollback_sql.strip())
        else:
            for entry in reversed(actionable_entries):
                backout_lines.append(
                    f"   - Restore [{entry.site_id}] {entry.item_type} {entry.item_id} ({entry.name}) to pre-quarantine state."
                )

        op_summary_str = (
            ", ".join(f"{k}={v}" for k, v in sorted(op_counts.items()))
            or "none"
        )
        site_label = (
            site_ids[0]
            if len(site_ids) == 1
            else f"{len(site_ids)} sites"
        )
        title = (
            f"[SoT Quarantine] Decommission/quarantine {len(actionable_entries)} stale inventory record(s) "
            f"at {site_label} ({manifest_obj.manifest_id})"
        )
        description = (
            f"Phase 2/6 Stale SoT Inventory Quarantine & Decommission Change Request.\n"
            f"Manifest ID: {manifest_obj.manifest_id}\n"
            f"Manifest SHA-256: {manifest_sha}\n"
            f"Total Manifest Entries: {len(manifest_obj.entries)} "
            f"(Actionable: {len(actionable_entries)}, Exempt: {len(manifest_obj.exempt_entries)})\n"
            f"Sites Affected: {', '.join(site_ids) if site_ids else 'N/A'}\n"
            f"Operations Breakdown: {op_summary_str}\n"
            f"Policy Thresholds: min_consecutive_stale_runs={manifest_obj.policy.min_consecutive_stale_runs}, "
            f"min_stale_days={manifest_obj.policy.min_stale_days}, "
            f"min_confidence={manifest_obj.policy.min_confidence}"
        )

        has_decommission_or_port = any(
            e.target_operation
            in (
                RemediationOperation.DECOMMISSION_VM_RECORD,
                RemediationOperation.PROPOSE_PORT_SHUTDOWN,
            )
            for e in actionable_entries
        )
        risk = (
            TicketRisk.HIGH.value
            if len(actionable_entries) >= 10 or has_decommission_or_port
            else TicketRisk.MODERATE.value
        )
        priority = (
            TicketPriority.HIGH.value
            if risk == TicketRisk.HIGH.value
            else TicketPriority.MEDIUM.value
        )

        resolved_ticket_id = (
            ticket_id.strip()
            if ticket_id and ticket_id.strip()
            else _deterministic_ticket_id(
                "CHG",
                ItsmWorkflowType.QUARANTINE_DECOMMISSION,
                f"{manifest_obj.manifest_id}:{manifest_sha}",
            )
        )

        return ItsmTicketRequest(
            ticket_id=resolved_ticket_id,
            workflow_type=ItsmWorkflowType.QUARANTINE_DECOMMISSION,
            title=title,
            description=description,
            category="Network Source of Truth",
            risk=risk,
            priority=priority,
            implementation_plan="\n".join(forward_lines),
            backout_plan="\n".join(backout_lines),
            cmdb_ci=primary_ci,
            affected_cis=affected_cis,
            site_ids=site_ids,
            item_ids=item_ids,
            artifact_id=manifest_obj.manifest_id,
            artifact_sha256=manifest_sha,
            approval_status=approval_status,
            approved_by=approved_by,
            approved_at=approved_at,
            labels=[
                "sot-validator",
                "quarantine",
                "decommission",
                *(f"site:{s}" for s in site_ids),
            ],
            project_key=project_key or self.default_project_key,
            issue_type="Change",
            created_at=self._resolve_timestamp(manifest_obj.generated_at),
            dry_run=manifest_obj.dry_run,
            metadata={
                "manifest_id": manifest_obj.manifest_id,
                "manifest_sha256": manifest_sha,
                "total_entries": len(manifest_obj.entries),
                "actionable_count": len(actionable_entries),
                "exempt_count": len(manifest_obj.exempt_entries),
                "summary_by_status": dict(manifest_obj.summary_by_status),
                "summary_by_operation": op_counts,
            },
        )

    from_quarantine_manifest = build_quarantine_ticket
    build_quarantine_change_request = build_quarantine_ticket

    # ------------------------------------------------------------------
    # Workflow 2: Extreme Switch Port & PoE Reclamation Change Request
    # ------------------------------------------------------------------

    def build_port_reclamation_ticket(
        self,
        plan: PortReclamationPlan | Mapping[str, Any],
        *,
        ticket_id: Optional[str] = None,
        dialect: Optional[ExtremeCliDialect | str] = None,
        approval_status: TicketApprovalStatus | str = TicketApprovalStatus.PENDING,
        approved_by: Optional[str] = None,
        approved_at: Optional[datetime | str] = None,
        project_key: Optional[str] = None,
        cmdb_ci: Optional[str] = None,
    ) -> ItsmTicketRequest:
        """Build an Extreme Switch Port & PoE Reclamation Change Request from a PortReclamationPlan."""
        plan_obj = (
            plan
            if isinstance(plan, PortReclamationPlan)
            else PortReclamationPlan.from_dict(plan)
        )
        plan_sha = compute_artifact_sha256(plan_obj)
        active_dialect = (
            ExtremeCliDialect(dialect)
            if dialect is not None
            else plan_obj.dialect
        )

        candidates = list(plan_obj.candidates)
        blocked_ports = list(plan_obj.blocked_ports)

        site_ids = sorted(
            {
                s
                for s in (
                    *(c.site_id for c in candidates),
                    *(b.site_id for b in blocked_ports),
                )
                if s
            }
        )
        device_ids = sorted(
            {
                d
                for d in (
                    *(c.device_id for c in candidates),
                    *(b.device_id for b in blocked_ports),
                )
                if d
            }
        )
        port_ids = [c.port_id for c in candidates]

        primary_ci = (
            cmdb_ci.strip()
            if cmdb_ci and cmdb_ci.strip()
            else (
                device_ids[0]
                if len(device_ids) == 1
                else (site_ids[0] if len(site_ids) == 1 else self.default_cmdb_ci)
            )
        )
        affected_cis = [primary_ci, *device_ids, *site_ids, *port_ids]

        # Build LLDP Uplink Safety Guard audit summary
        guard_lines: list[str] = [
            f"LLDP Uplink Guard Audit: {len(blocked_ports)} port(s) protected/blocked from shutdown; "
            f"{len(candidates)} access port(s) eligible."
        ]
        for b_rec in blocked_ports:
            rules_str = (
                f" [rules: {', '.join(b_rec.matched_rules)}]"
                if b_rec.matched_rules
                else ""
            )
            guard_lines.append(
                f"  - BLOCKED {b_rec.device_id}:{b_rec.port_name} ({b_rec.port_id}): "
                f"{b_rec.block_reason}{rules_str}"
            )
        guard_summary_text = "\n".join(guard_lines)

        # Forward implementation plan including ExtremeXOS and VOSS commands
        forward_script = plan_obj.format_cli_script(active_dialect).strip()
        impl_lines: list[str] = [
            f"1. Verify change ticket approval and plan SHA-256 digest ({plan_sha}).",
            "2. Confirm LLDP Uplink Guard audit checks pass prior to switch CLI session.",
            guard_summary_text,
            "",
            f"3. Apply staged Extreme Networks ({active_dialect.value.upper()}) port & PoE disable commands "
            f"({len(candidates)} eligible port(s), estimated PoE savings: {plan_obj.estimated_poe_watts_saved:.2f}W):",
            forward_script,
        ]
        if active_dialect is ExtremeCliDialect.EXOS and plan_obj.voss_commands:
            impl_lines.extend(
                [
                    "",
                    "Equivalent Extreme VOSS Commands:",
                    *plan_obj.voss_commands,
                ]
            )
        elif active_dialect is ExtremeCliDialect.VOSS and plan_obj.exos_commands:
            impl_lines.extend(
                [
                    "",
                    "Equivalent ExtremeXOS Commands:",
                    *plan_obj.exos_commands,
                ]
            )

        # Backout / Rollback plan including 1-command rollback strings and full rollback script
        rollback_script = plan_obj.format_rollback_script(active_dialect).strip()
        backout_lines: list[str] = [
            f"1. Execute 1-command per-port rollback or staged rollback script on affected Extreme switches ({', '.join(device_ids) or primary_ci}):",
        ]
        for cand in candidates:
            one_cmd = (
                cand.voss_rollback_command
                if active_dialect is ExtremeCliDialect.VOSS
                else cand.exos_rollback_command
            )
            backout_lines.append(
                f"   - {cand.device_id}:{cand.port_name} ({cand.port_id}) 1-command rollback: {one_cmd}"
            )
        backout_lines.extend(
            [
                "",
                f"Staged {active_dialect.value.upper()} Rollback Script:",
                rollback_script,
            ]
        )

        target_label = (
            device_ids[0]
            if len(device_ids) == 1
            else (site_ids[0] if len(site_ids) == 1 else f"{len(device_ids) or 1} switch(es)")
        )
        title = (
            f"[Extreme Port Reclamation] Disable {len(candidates)} stale access port(s) & reclaim "
            f"{plan_obj.estimated_poe_watts_saved:.2f}W PoE on {target_label} ({plan_obj.plan_id})"
        )
        description = (
            f"Phase 4/6 Extreme Networks Switch Port & PoE Reclamation Change Request.\n"
            f"Plan ID: {plan_obj.plan_id}\n"
            f"Plan SHA-256: {plan_sha}\n"
            f"CLI Dialect: {active_dialect.value.upper()}\n"
            f"Eligible Ports: {len(candidates)} | Blocked by LLDP Uplink Guard: {len(blocked_ports)}\n"
            f"Estimated PoE Power Saved: {plan_obj.estimated_poe_watts_saved:.2f}W\n"
            f"Thresholds: min_inactive_runs={plan_obj.min_inactive_runs}, "
            f"min_inactive_days={plan_obj.min_inactive_days:.1f}\n\n"
            f"{guard_summary_text}"
        )

        risk = (
            TicketRisk.MODERATE.value
            if len(candidates) <= 24
            else TicketRisk.HIGH.value
        )
        priority = (
            TicketPriority.MEDIUM.value
            if risk == TicketRisk.MODERATE.value
            else TicketPriority.HIGH.value
        )

        resolved_ticket_id = (
            ticket_id.strip()
            if ticket_id and ticket_id.strip()
            else _deterministic_ticket_id(
                "CHG",
                ItsmWorkflowType.PORT_RECLAMATION,
                f"{plan_obj.plan_id}:{plan_sha}",
            )
        )

        return ItsmTicketRequest(
            ticket_id=resolved_ticket_id,
            workflow_type=ItsmWorkflowType.PORT_RECLAMATION,
            title=title,
            description=description,
            category="Network Switching / Extreme Networks",
            risk=risk,
            priority=priority,
            implementation_plan="\n".join(impl_lines),
            backout_plan="\n".join(backout_lines),
            cmdb_ci=primary_ci,
            affected_cis=affected_cis,
            site_ids=site_ids,
            item_ids=port_ids,
            artifact_id=plan_obj.plan_id,
            artifact_sha256=plan_sha,
            approval_status=approval_status,
            approved_by=approved_by,
            approved_at=approved_at,
            labels=[
                "sot-validator",
                "port-reclamation",
                "extreme-networks",
                f"dialect:{active_dialect.value}",
                *(f"site:{s}" for s in site_ids),
            ],
            project_key=project_key or self.default_project_key,
            issue_type="Change",
            created_at=self._resolve_timestamp(plan_obj.generated_at),
            dry_run=plan_obj.dry_run,
            metadata={
                "plan_id": plan_obj.plan_id,
                "plan_sha256": plan_sha,
                "dialect": active_dialect.value,
                "eligible_port_count": len(candidates),
                "blocked_port_count": len(blocked_ports),
                "estimated_poe_watts_saved": plan_obj.estimated_poe_watts_saved,
                "exos_commands": list(plan_obj.exos_commands),
                "exos_rollback_commands": list(plan_obj.exos_rollback_commands),
                "voss_commands": list(plan_obj.voss_commands),
                "voss_rollback_commands": list(plan_obj.voss_rollback_commands),
                "one_command_rollbacks": [
                    {
                        "port_id": c.port_id,
                        "device_id": c.device_id,
                        "port_name": c.port_name,
                        "exos_rollback_command": c.exos_rollback_command,
                        "voss_rollback_command": c.voss_rollback_command,
                    }
                    for c in candidates
                ],
                "lldp_guard_blocked_ports": [
                    {
                        "port_id": b.port_id,
                        "device_id": b.device_id,
                        "port_name": b.port_name,
                        "block_reason": b.block_reason,
                        "matched_rules": list(b.matched_rules),
                    }
                    for b in blocked_ports
                ],
            },
        )

    from_port_reclamation_plan = build_port_reclamation_ticket
    build_port_reclamation_change_request = build_port_reclamation_ticket
