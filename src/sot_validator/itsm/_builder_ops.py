"""ITSM payload builder mixin: Shadow IT onboarding tasks and UPS incident tickets."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
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
from sot_validator.reconciliation.reconciler import (
    ALL_DISCREPANCY_TYPES,
    DiscrepancyType,
    ReconciliationReport,
)
from sot_validator.signals.ups_health import (
    UpsAdvisoryCode,
    UpsFleetHealthReport,
    UpsHealthRecord,
    UpsHealthStatus,
)


class _OpsTicketBuilderMixin:
    """Workflow 3 (onboarding) and Workflow 4 (UPS incident) ticket builders."""

    # ------------------------------------------------------------------
    # Workflow 3: Shadow IT Asset Onboarding Task
    # ------------------------------------------------------------------

    def build_onboarding_ticket(
        self,
        report: ReconciliationReport | Mapping[str, Any],
        *,
        ticket_id: Optional[str] = None,
        site_id: Optional[str] = None,
        approval_status: TicketApprovalStatus | str = TicketApprovalStatus.PENDING,
        approved_by: Optional[str] = None,
        approved_at: Optional[datetime | str] = None,
        project_key: Optional[str] = None,
        cmdb_ci: Optional[str] = None,
    ) -> ItsmTicketRequest:
        """Build a Shadow IT Asset Onboarding Task ticket from a ReconciliationReport."""
        report_obj = (
            report
            if isinstance(report, ReconciliationReport)
            else ReconciliationReport.from_dict(report)
        )
        if site_id is not None:
            clean_site = site_id.strip()
            scoped_discs = [
                d for d in report_obj.discrepancies if d.site_id == clean_site
            ]
            scoped_report = ReconciliationReport(
                discrepancies=scoped_discs,
                generated_at=report_obj.generated_at,
            )
        else:
            scoped_report = report_obj

        report_sha = compute_artifact_sha256(scoped_report)
        discrepancies = scoped_report.discrepancies
        site_ids = sorted({d.site_id for d in discrepancies})
        if not site_ids and site_id:
            site_ids = [site_id.strip()]
        item_ids = [d.discrepancy_id for d in discrepancies]

        by_type = scoped_report.summary_by_type
        untracked_count = (
            by_type.get(DiscrepancyType.UNTRACKED_VM.value, 0)
            + by_type.get(DiscrepancyType.UNTRACKED_DEVICE.value, 0)
            + by_type.get(DiscrepancyType.UNTRACKED_IP.value, 0)
        )
        mismatch_count = by_type.get(DiscrepancyType.ATTRIBUTE_MISMATCH.value, 0)

        primary_ci = (
            cmdb_ci.strip()
            if cmdb_ci and cmdb_ci.strip()
            else (site_ids[0] if len(site_ids) == 1 else self.default_cmdb_ci)
        )
        affected_cis = [
            primary_ci,
            *site_ids,
            *(
                d.observed_hostname or d.observed_ip or d.observed_identifier
                for d in discrepancies
            ),
        ]

        onboarding_sql = scoped_report.generate_onboarding_sql().strip()
        onboarding_csv = scoped_report.generate_onboarding_csv().strip()

        impl_lines: list[str] = [
            f"1. Review {len(discrepancies)} discovered Shadow IT discrepancy record(s) "
            f"({untracked_count} untracked asset(s), {mismatch_count} attribute mismatch(es)):",
        ]
        for disc in discrepancies:
            host_or_id = disc.observed_hostname or disc.observed_identifier
            ip_part = f" (IP: {disc.observed_ip})" if disc.observed_ip else ""
            mac_part = f" [MAC: {disc.observed_mac}]" if disc.observed_mac else ""
            action_part = (
                f" -> {disc.recommended_onboarding_action}"
                if disc.recommended_onboarding_action
                else ""
            )
            impl_lines.append(
                f"   - [{disc.site_id}] {disc.discrepancy_type.value} ({disc.discrepancy_id}): "
                f"{host_or_id}{ip_part}{mac_part} via {disc.source}{action_part}"
            )
        if onboarding_sql:
            impl_lines.extend(
                [
                    "",
                    "2. Execute SoT Onboarding SQL INSERT Statements:",
                    onboarding_sql,
                ]
            )
        if onboarding_csv:
            impl_lines.extend(
                [
                    "",
                    "3. Onboarding CSV Import Template:",
                    onboarding_csv,
                ]
            )

        backout_lines: list[str] = [
            "1. If any onboarded asset was registered in error, remove the newly inserted SoT records by primary key:",
        ]
        for entry in scoped_report._build_onboarding_entries():
            table = entry.get("target_table")
            rec_id = entry.get("item_id")
            rec_site = entry.get("site_id")
            if table == "equipment":
                backout_lines.append(
                    f"   DELETE FROM equipment WHERE equipment_id = '{rec_id}' AND site_id = '{rec_site}';"
                )
            elif table == "network_devices":
                backout_lines.append(
                    f"   DELETE FROM network_devices WHERE device_id = '{rec_id}' AND site_id = '{rec_site}';"
                )
            elif table == "ip_arp_entries":
                backout_lines.append(
                    f"   DELETE FROM ip_arp_entries WHERE ip_id = '{rec_id}' AND site_id = '{rec_site}';"
                )
        if len(backout_lines) == 1:
            backout_lines.append(
                "   Revert any manual attribute mismatch updates in the SoT database."
            )

        site_label = (
            site_ids[0]
            if len(site_ids) == 1
            else f"{len(site_ids) or 1} site(s)"
        )
        title = (
            f"[Shadow IT Onboarding] Reconcile {len(discrepancies)} untracked/mismatched inventory asset(s) "
            f"at {site_label}"
        )
        type_summary_str = ", ".join(
            f"{dtype.value}={by_type.get(dtype.value, 0)}"
            for dtype in ALL_DISCREPANCY_TYPES
        )
        description = (
            f"Phase 3/6 Reverse Discovery & Shadow IT Asset Onboarding Task.\n"
            f"Reconciliation Digest SHA-256: {report_sha}\n"
            f"Total Discrepancies: {len(discrepancies)} ({type_summary_str})\n"
            f"Sites Affected: {', '.join(site_ids) if site_ids else 'N/A'}\n"
            f"Untracked VMs, switches, UPS units, and active /24 IPs detected across live vCenter, ARP, SNMP, and ICMP feeds."
        )

        artifact_id = f"recon-{report_sha[:12]}"
        resolved_ticket_id = (
            ticket_id.strip()
            if ticket_id and ticket_id.strip()
            else _deterministic_ticket_id(
                "TASK",
                ItsmWorkflowType.SHADOW_IT_ONBOARDING,
                report_sha,
            )
        )

        risk = (
            TicketRisk.MODERATE.value
            if by_type.get(DiscrepancyType.UNTRACKED_DEVICE.value, 0) > 0
            or len(discrepancies) >= 5
            else TicketRisk.LOW.value
        )
        priority = (
            TicketPriority.HIGH.value
            if by_type.get(DiscrepancyType.UNTRACKED_DEVICE.value, 0) > 0
            else TicketPriority.MEDIUM.value
        )

        return ItsmTicketRequest(
            ticket_id=resolved_ticket_id,
            workflow_type=ItsmWorkflowType.SHADOW_IT_ONBOARDING,
            title=title,
            description=description,
            category="Inventory Reconciliation / Shadow IT",
            risk=risk,
            priority=priority,
            implementation_plan="\n".join(impl_lines),
            backout_plan="\n".join(backout_lines),
            cmdb_ci=primary_ci,
            affected_cis=affected_cis,
            site_ids=site_ids,
            item_ids=item_ids,
            artifact_id=artifact_id,
            artifact_sha256=report_sha,
            approval_status=approval_status,
            approved_by=approved_by,
            approved_at=approved_at,
            labels=[
                "sot-validator",
                "shadow-it",
                "onboarding",
                "reconciliation",
                *(f"site:{s}" for s in site_ids),
            ],
            project_key=project_key or self.default_project_key,
            issue_type="Task",
            created_at=self._resolve_timestamp(scoped_report.generated_at),
            dry_run=True,
            metadata={
                "total_discrepancies": len(discrepancies),
                "summary_by_type": dict(by_type),
                "summary_by_site": dict(scoped_report.summary_by_site),
                "onboarding_sql": onboarding_sql,
                "onboarding_csv": onboarding_csv,
            },
        )

    from_reconciliation_report = build_onboarding_ticket
    build_shadow_it_onboarding_ticket = build_onboarding_ticket

    # ------------------------------------------------------------------
    # Workflow 4: APC UPS Battery / Hardware Incident Alert
    # ------------------------------------------------------------------

    @staticmethod
    def _coerce_ups_report(
        report: (
            UpsFleetHealthReport
            | UpsHealthRecord
            | Sequence[UpsHealthRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ),
    ) -> UpsFleetHealthReport:
        if isinstance(report, UpsFleetHealthReport):
            return report
        if isinstance(report, UpsHealthRecord):
            return UpsFleetHealthReport(
                records=[report], evaluated_at=report.evaluated_at
            )
        if isinstance(report, Mapping):
            if "records" in report:
                return UpsFleetHealthReport.from_dict(report)
            if "equipment_id" in report and "status" in report:
                rec = UpsHealthRecord.from_dict(report)
                return UpsFleetHealthReport(
                    records=[rec], evaluated_at=rec.evaluated_at
                )
        if isinstance(report, Sequence) and not isinstance(report, (str, bytes)):
            recs = [
                r if isinstance(r, UpsHealthRecord) else UpsHealthRecord.from_dict(r)
                for r in report
            ]
            eval_at = next(
                (r.evaluated_at for r in recs if r.evaluated_at is not None),
                None,
            )
            return UpsFleetHealthReport(records=recs, evaluated_at=eval_at)
        raise TypeError(
            f"Unsupported UPS health report input: {type(report)!r}"
        )

    def build_ups_incident_ticket(
        self,
        report: (
            UpsFleetHealthReport
            | UpsHealthRecord
            | Sequence[UpsHealthRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ),
        *,
        ticket_id: Optional[str] = None,
        site_id: Optional[str] = None,
        include_warnings: bool = True,
        approval_status: TicketApprovalStatus | str = TicketApprovalStatus.PENDING,
        approved_by: Optional[str] = None,
        approved_at: Optional[datetime | str] = None,
        project_key: Optional[str] = None,
        cmdb_ci: Optional[str] = None,
    ) -> ItsmTicketRequest:
        """Build an APC UPS Battery / Hardware Incident Alert ticket from a UpsFleetHealthReport."""
        fleet_report = self._coerce_ups_report(report)

        candidate_records = fleet_report.records
        if site_id is not None:
            clean_site = site_id.strip()
            candidate_records = [
                r for r in candidate_records if r.site_id == clean_site
            ]

        actionable_records: list[UpsHealthRecord] = []
        for rec in candidate_records:
            if rec.status in (UpsHealthStatus.CRITICAL, UpsHealthStatus.UNREACHABLE):
                actionable_records.append(rec)
            elif include_warnings and (
                rec.status is UpsHealthStatus.WARNING or bool(rec.advisories)
            ):
                actionable_records.append(rec)

        actionable_records.sort(
            key=lambda r: (
                0
                if r.status is UpsHealthStatus.CRITICAL
                else (
                    1
                    if r.status is UpsHealthStatus.WARNING
                    else (2 if r.status is UpsHealthStatus.UNREACHABLE else 3)
                ),
                r.site_id,
                r.equipment_id,
            )
        )

        scoped_fleet = UpsFleetHealthReport(
            records=actionable_records,
            evaluated_at=fleet_report.evaluated_at,
        )
        report_sha = compute_artifact_sha256(scoped_fleet)

        site_ids = sorted({r.site_id for r in actionable_records})
        if not site_ids and site_id:
            site_ids = [site_id.strip()]
        item_ids = [r.equipment_id for r in actionable_records]

        all_advisories: list[str] = []
        seen_adv: set[str] = set()
        for rec in actionable_records:
            for adv in rec.advisories:
                if adv not in seen_adv:
                    seen_adv.add(adv)
                    all_advisories.append(adv)

        primary_ci = (
            cmdb_ci.strip()
            if cmdb_ci and cmdb_ci.strip()
            else (
                actionable_records[0].name
                if len(actionable_records) == 1
                else (site_ids[0] if len(site_ids) == 1 else self.default_cmdb_ci)
            )
        )
        affected_cis = [
            primary_ci,
            *(r.name for r in actionable_records),
            *item_ids,
            *site_ids,
        ]

        has_critical = any(
            r.status is UpsHealthStatus.CRITICAL
            or r.on_battery
            or r.needs_battery_replacement
            or UpsAdvisoryCode.BATTERY_REPLACEMENT_NEEDED.value in r.advisories
            or UpsAdvisoryCode.ON_BATTERY_ALERT.value in r.advisories
            or UpsAdvisoryCode.CRITICAL_RUNTIME.value in r.advisories
            for r in actionable_records
        )
        risk = (
            TicketRisk.CRITICAL.value
            if has_critical
            else TicketRisk.HIGH.value
        )
        priority = (
            TicketPriority.CRITICAL.value
            if has_critical
            else TicketPriority.HIGH.value
        )

        impl_lines: list[str] = [
            f"1. Dispatch facility/field operations for {len(actionable_records)} APC UPS unit(s) with active PowerNet-MIB health advisories:",
        ]
        for rec in actionable_records:
            adv_str = ", ".join(rec.advisories) if rec.advisories else rec.status.value
            metrics_parts: list[str] = []
            if rec.model:
                metrics_parts.append(f"model={rec.model}")
            if rec.ip_address:
                metrics_parts.append(f"ip={rec.ip_address}")
            if rec.runtime_remaining_minutes is not None:
                metrics_parts.append(
                    f"runtime={rec.runtime_remaining_minutes:.1f}min"
                )
            if rec.temperature_celsius is not None:
                metrics_parts.append(f"temp={rec.temperature_celsius:.1f}C")
            if rec.output_load_pct is not None:
                metrics_parts.append(f"load={rec.output_load_pct:.1f}%")
            if rec.output_status:
                metrics_parts.append(f"output={rec.output_status}")
            metrics_suffix = (
                f" ({', '.join(metrics_parts)})" if metrics_parts else ""
            )
            impl_lines.append(
                f"   - [{rec.site_id}] {rec.name} ({rec.equipment_id}) [{rec.status.value}]: "
                f"advisories=[{adv_str}]{metrics_suffix}"
            )
            if rec.needs_battery_replacement or (
                UpsAdvisoryCode.BATTERY_REPLACEMENT_NEEDED.value in rec.advisories
            ):
                impl_lines.append(
                    f"     * Action: Replace hot-swappable APC RBC battery cartridge on {rec.name} and run UPS self-test."
                )
            if rec.on_battery or (
                UpsAdvisoryCode.ON_BATTERY_ALERT.value in rec.advisories
            ):
                impl_lines.append(
                    f"     * Action: Verify utility AC input feed for {rec.name} (fail cause: {rec.input_line_fail_cause or 'unknown'})."
                )
            if rec.is_low_runtime:
                impl_lines.append(
                    f"     * Action: Inspect battery capacity and shed non-critical load on {rec.name}."
                )
            if rec.is_high_temperature:
                impl_lines.append(
                    f"     * Action: Check MDF/IDF room HVAC and UPS fan airflow for {rec.name}."
                )

        impl_lines.append(
            "2. Run post-maintenance SNMP PowerNet-MIB verification (`sot-validator ups-health`) to confirm HEALTHY status."
        )

        backout_lines: list[str] = [
            "1. If APC UPS battery module replacement causes a fault alarm, engage maintenance bypass (if equipped) or reinstall prior battery tray while keeping utility AC online.",
            "2. Escalate to APC/Schneider Electric field service if hardware fault persists (`upsBasicBatteryStatus = batteryInFaultCondition(4)`).",
        ]

        site_label = (
            site_ids[0]
            if len(site_ids) == 1
            else f"{len(site_ids) or 1} site(s)"
        )
        title = (
            f"[APC UPS Hardware Alert] {len(actionable_records)} UPS unit(s) require maintenance/intervention "
            f"at {site_label} ({', '.join(all_advisories[:3]) or 'HEALTH_ALERT'})"
        )
        description = (
            f"Phase 6 APC UPS Fleet Health Telemetry Incident / Maintenance Request.\n"
            f"Health Report SHA-256: {report_sha}\n"
            f"Actionable Units: {len(actionable_records)} "
            f"(Critical: {scoped_fleet.critical_count}, Warning: {scoped_fleet.warning_count}, "
            f"Unreachable: {scoped_fleet.unreachable_count}, Healthy Filtered Out: {fleet_report.healthy_count})\n"
            f"Battery Replacement Needed: {len(scoped_fleet.battery_replacement_units)} | "
            f"Low Runtime: {len(scoped_fleet.low_runtime_units)} | "
            f"On Battery: {len(scoped_fleet.on_battery_units)} | "
            f"Thermal Alerts: {len(scoped_fleet.thermal_alert_units)}\n"
            f"Active Advisory Codes: {', '.join(all_advisories) if all_advisories else 'NONE'}\n"
            f"Sites Affected: {', '.join(site_ids) if site_ids else 'N/A'}"
        )

        artifact_id = f"ups-health-{report_sha[:12]}"
        resolved_ticket_id = (
            ticket_id.strip()
            if ticket_id and ticket_id.strip()
            else _deterministic_ticket_id(
                "INC",
                ItsmWorkflowType.UPS_HARDWARE_INCIDENT,
                report_sha,
            )
        )

        return ItsmTicketRequest(
            ticket_id=resolved_ticket_id,
            workflow_type=ItsmWorkflowType.UPS_HARDWARE_INCIDENT,
            title=title,
            description=description,
            category="Facility Power / APC UPS",
            risk=risk,
            priority=priority,
            implementation_plan="\n".join(impl_lines),
            backout_plan="\n".join(backout_lines),
            cmdb_ci=primary_ci,
            affected_cis=affected_cis,
            site_ids=site_ids,
            item_ids=item_ids,
            artifact_id=artifact_id,
            artifact_sha256=report_sha,
            approval_status=approval_status,
            approved_by=approved_by,
            approved_at=approved_at,
            labels=[
                "sot-validator",
                "apc-ups",
                "hardware-incident",
                *(adv.lower().replace("_", "-") for adv in all_advisories),
                *(f"site:{s}" for s in site_ids),
            ],
            project_key=project_key or self.default_project_key,
            issue_type="Incident",
            created_at=self._resolve_timestamp(fleet_report.evaluated_at),
            dry_run=True,
            metadata={
                "actionable_unit_count": len(actionable_records),
                "healthy_filtered_count": fleet_report.healthy_count,
                "critical_count": scoped_fleet.critical_count,
                "warning_count": scoped_fleet.warning_count,
                "unreachable_count": scoped_fleet.unreachable_count,
                "battery_replacement_count": len(
                    scoped_fleet.battery_replacement_units
                ),
                "low_runtime_count": len(scoped_fleet.low_runtime_units),
                "thermal_alert_count": len(scoped_fleet.thermal_alert_units),
                "on_battery_count": len(scoped_fleet.on_battery_units),
                "advisories": all_advisories,
                "units": [r.to_dict() for r in actionable_records],
            },
        )

    from_ups_health_report = build_ups_incident_ticket
    build_ups_hardware_incident = build_ups_incident_ticket

    def build_ups_incident_tickets(
        self,
        report: UpsFleetHealthReport | Sequence[UpsHealthRecord] | Mapping[str, Any],
        *,
        per_site: bool = False,
        include_warnings: bool = True,
        **kwargs: Any,
    ) -> list[ItsmTicketRequest]:
        """Build individual APC UPS incident tickets per actionable unit or per site."""
        fleet_report = self._coerce_ups_report(report)
        actionable = [
            r
            for r in fleet_report.records
            if r.status in (UpsHealthStatus.CRITICAL, UpsHealthStatus.UNREACHABLE)
            or (include_warnings and (r.status is UpsHealthStatus.WARNING or bool(r.advisories)))
        ]
        if not actionable:
            return []
        if per_site:
            by_site: dict[str, list[UpsHealthRecord]] = {}
            for rec in actionable:
                by_site.setdefault(rec.site_id, []).append(rec)
            return [
                self.build_ups_incident_ticket(
                    site_recs,
                    site_id=s_id,
                    include_warnings=include_warnings,
                    **kwargs,
                )
                for s_id, site_recs in sorted(by_site.items())
            ]
        return [
            self.build_ups_incident_ticket(
                rec,
                include_warnings=include_warnings,
                **kwargs,
            )
            for rec in actionable
        ]
