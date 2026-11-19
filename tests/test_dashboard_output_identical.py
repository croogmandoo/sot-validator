"""The HTML dashboard renders byte-identical output to the pre-split reference fixtures."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from sot_validator.history.ledger import ItemStreakSummary, SubnetUtilizationSummary
from sot_validator.itsm.tickets import (
    ItsmTicketRequest,
    ItsmWorkflowType,
    TicketApprovalStatus,
)
from sot_validator.migration.parity import (
    CutoverRecommendation,
    ParityDiscrepancy,
    ParityDiscrepancyType,
    ParityValidationReport,
    SiteMigrationReadinessScorecard,
)
from sot_validator.models import (
    Site,
    ValidationClassification,
    ValidationResult,
    ValidationSignal,
)
from sot_validator.reconciliation.reconciler import (
    DiscrepancyRecord,
    DiscrepancyType,
    ReconciliationReport,
)
from sot_validator.remediation.port_reclamation import (
    BlockedPortRecord,
    PortReclamationCandidate,
    PortReclamationPlan,
)
from sot_validator.remediation.quarantine import (
    ApprovalStatus,
    QuarantineGraduationStatus,
    QuarantineManifestEntry,
    RemediationApprovalManifest,
    RemediationOperation,
)
from sot_validator.remediation.sink import (
    DryRunActionPlan,
    ProposedRemediationAction,
    RemediationActionType,
)
from sot_validator.reporting.dashboard import (
    HtmlDashboardGenerator,
    generate_html_dashboard,
)
from sot_validator.signals.ups_health import (
    UpsFleetHealthReport,
    UpsHealthRecord,
    UpsHealthStatus,
)

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "dashboard"
GENERATED_AT = "2026-01-01T00:00:00Z"
FIXED_DT = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

HOSTILE = (
    "</script><script>alert(1)</script> <!-- "
    "\"><img src=x onerror=alert(1)> ' \" &amp; &    "
)


def _full_inputs() -> dict[str, Any]:
    site = Site(site_id="site-001", name=f"Site One {HOSTILE}")
    results = [
        ValidationResult(
            item_type="Equipment",
            item_id=f"eq-active-{HOSTILE}",
            site_id="site-001",
            name=f"host-active {HOSTILE}",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            confidence=0.95,
            signals=[
                ValidationSignal(
                    signal_type="ARP_RECENCY",
                    status="ACTIVE",
                    observed_at=FIXED_DT,
                    age_seconds=120.0,
                    source="arp-table",
                    details=f"seen {HOSTILE}",
                )
            ],
            rationale=f"Active {HOSTILE}",
            evaluated_at=FIXED_DT,
        ),
        ValidationResult(
            item_type="NetworkDevice",
            item_id="dev-stale-1",
            site_id="site-001",
            name="sw-stale-1",
            classification=ValidationClassification.STALE_LIKELY_UNUSED,
            confidence=0.9,
            rationale="Stale switch",
            evaluated_at=FIXED_DT,
        ),
        ValidationResult(
            item_type="Equipment",
            item_id="eq-unreach-1",
            site_id="site-002",
            name="san-1",
            classification=ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
            confidence=0.5,
            rationale="Unreachable",
            evaluated_at=FIXED_DT,
        ),
        ValidationResult(
            item_type="Equipment",
            item_id="eq-insuff-1",
            site_id="site-002",
            name="spare-1",
            classification=ValidationClassification.INSUFFICIENT_DATA,
            confidence=0.0,
            rationale="No signals",
            evaluated_at=FIXED_DT,
        ),
    ]
    action_plan = DryRunActionPlan(
        generated_at=FIXED_DT,
        total_evaluated=4,
        actions=[
            ProposedRemediationAction(
                action_type=RemediationActionType.MARK_STALE_CANDIDATE,
                site_id="site-001",
                item_type="NetworkDevice",
                item_id="dev-stale-1",
                name="sw-stale-1",
                classification=ValidationClassification.STALE_LIKELY_UNUSED,
                confidence=0.9,
                rationale=f"Plan {HOSTILE}",
                proposed_at=FIXED_DT,
            )
        ],
    )
    manifest = RemediationApprovalManifest(
        manifest_id=f"manifest-{HOSTILE}",
        generated_at=FIXED_DT,
        entries=[
            QuarantineManifestEntry(
                site_id="site-001",
                item_type="NetworkDevice",
                item_id=f"dev-stale-{HOSTILE}",
                name=f"sw-stale {HOSTILE}",
                classification=ValidationClassification.STALE_LIKELY_UNUSED,
                confidence=0.9,
                consecutive_stale_runs=4,
                stale_duration_days=45.0,
                target_operation=RemediationOperation.FLAG_STALE_IN_SOT,
                graduation_status=QuarantineGraduationStatus.ELIGIBLE,
                approval_status=ApprovalStatus.APPROVED,
                reviewed_by="reviewer",
                review_note=f"Approved {HOSTILE}",
                proposed_at=FIXED_DT,
            )
        ],
    )
    streaks = [
        ItemStreakSummary(
            site_id="site-001",
            item_type="NetworkDevice",
            item_id="dev-stale-1",
            name=f"sw-stale {HOSTILE}",
            current_classification=ValidationClassification.STALE_LIKELY_UNUSED,
            current_confidence=0.9,
            consecutive_stale_runs=4,
            total_runs_seen=4,
            first_seen_at=FIXED_DT,
            first_stale_at=FIXED_DT,
            stale_duration_days=45.0,
        )
    ]
    reconciliation = ReconciliationReport(
        generated_at=FIXED_DT,
        discrepancies=[
            DiscrepancyRecord(
                discrepancy_id=f"disc-{HOSTILE}",
                discrepancy_type=DiscrepancyType.UNTRACKED_VM,
                site_id="site-001",
                observed_identifier="vm-9999",
                observed_ip="10.1.10.250",
                observed_mac="00:50:56:aa:bb:cc",
                observed_hostname=f"shadow {HOSTILE}",
                source="vcenter",
                details=f"Untracked {HOSTILE}",
                recommended_onboarding_action=f"Onboard {HOSTILE}",
            )
        ],
    )
    subnets = [
        SubnetUtilizationSummary(
            subnet_id=f"subnet-{HOSTILE}",
            cidr="10.1.10.0/24",
            total_assigned_ips=10,
            confirmed_active_ips=7,
            stale_reclaimable_ips=3,
            active_utilization_pct=70.0,
            site_id="site-001",
        ),
        SubnetUtilizationSummary(
            subnet_id="subnet-full",
            cidr="10.1.20.0/24",
            total_assigned_ips=1,
            confirmed_active_ips=1,
            stale_reclaimable_ips=0,
            active_utilization_pct=100.0,
        ),
    ]
    port_plan = PortReclamationPlan(
        plan_id=f"port-plan-{HOSTILE}",
        generated_at=FIXED_DT,
        estimated_poe_watts_saved=15.4,
        candidates=(
            PortReclamationCandidate(
                port_id="port-1",
                device_id=f"sw-{HOSTILE}",
                port_name="1:5",
                site_id="site-001",
                inactive_runs=4,
                inactive_days=45.0,
                estimated_poe_watts_saved=15.4,
                exos_disable_commands=("disable port 1:5", f"# {HOSTILE}"),
                exos_rollback_command="enable port 1:5",
                voss_disable_commands=("interface gigabitEthernet 1/5", "shutdown"),
            ),
        ),
        blocked_ports=(
            BlockedPortRecord(
                port_id="port-2",
                device_id="sw-1",
                port_name="1:48",
                site_id="site-001",
                block_reason=f"LLDP uplink {HOSTILE}",
                matched_rules=("lldp-bridge", "keyword-uplink"),
            ),
        ),
    )
    parity = ParityValidationReport(
        generated_at=FIXED_DT,
        scorecards=[
            SiteMigrationReadinessScorecard(
                site_id="site-001",
                site_name=f"Site One {HOSTILE}",
                readiness_score=82.5,
                recommendation=CutoverRecommendation.NEEDS_REMEDIATION,
                parity_match_percentage=90.0,
                expected_golden_items=10,
                matched_modern_items=9,
                unresolved_untracked_count=1,
                blocking_reasons=[f"Blocker {HOSTILE}"],
                evaluated_at=FIXED_DT,
                discrepancies=[
                    ParityDiscrepancy(
                        discrepancy_id="pdisc-1",
                        discrepancy_type=ParityDiscrepancyType.ATTRIBUTE_MISMATCH,
                        site_id="site-001",
                        entity_type="devices",
                        item_identifier="sw-1",
                        attribute_name="role",
                        expected_value="access",
                        actual_value=HOSTILE,
                        details=f"Mismatch {HOSTILE}",
                    )
                ],
            ),
            SiteMigrationReadinessScorecard(
                site_id="site-002",
                site_name="Site Two",
                readiness_score=100.0,
                recommendation=CutoverRecommendation.READY_FOR_CUTOVER,
                parity_match_percentage=100.0,
                expected_golden_items=2,
                matched_modern_items=2,
                evaluated_at=FIXED_DT,
            ),
        ],
    )
    ups = UpsFleetHealthReport(
        evaluated_at=FIXED_DT,
        records=[
            UpsHealthRecord(
                equipment_id="ups-1",
                site_id="site-001",
                name=f"ups-1 {HOSTILE}",
                status=UpsHealthStatus.CRITICAL,
                ip_address="10.1.10.50",
                model="Smart-UPS 3000",
                battery_status="batteryLow",
                needs_battery_replacement=True,
                runtime_remaining_minutes=4.5,
                temperature_celsius=41.0,
                output_load_pct=88.0,
                output_status="onLine",
                advisories=[f"Replace battery {HOSTILE}"],
                evaluated_at=FIXED_DT,
            ),
            UpsHealthRecord(
                equipment_id="ups-2",
                site_id="site-002",
                name="ups-2",
                status=UpsHealthStatus.HEALTHY,
                evaluated_at=FIXED_DT,
            ),
        ],
    )
    tickets = [
        ItsmTicketRequest(
            ticket_id="CHG0001",
            workflow_type=ItsmWorkflowType.PORT_RECLAMATION,
            title=f"Reclaim ports {HOSTILE}",
            description=f"Description {HOSTILE}",
            implementation_plan="Disable idle ports",
            backout_plan="Re-enable ports",
            cmdb_ci=f"CI-{HOSTILE}",
            site_ids=["site-001"],
            artifact_id="port-plan-1",
            artifact_sha256="ab" * 32,
            approval_status=TicketApprovalStatus.APPROVED,
            approved_by=f"approver {HOSTILE}",
            created_at=FIXED_DT,
        ),
        ItsmTicketRequest(
            ticket_id="INC0002",
            workflow_type=ItsmWorkflowType.UPS_HARDWARE_INCIDENT,
            title="UPS incident",
            description="UPS critical",
            implementation_plan="Replace battery",
            backout_plan="None",
            created_at=FIXED_DT,
        ),
    ]
    return {
        "results": results,
        "sites": [site],
        "action_plan": action_plan,
        "approval_manifest": manifest,
        "streaks": streaks,
        "reconciliation_report": reconciliation,
        "subnet_utilization": subnets,
        "port_reclamation_plan": port_plan,
        "migration_parity_report": parity,
        "ups_health_report": ups,
        "itsm_tickets": tickets,
        "generated_at": GENERATED_AT,
        "title": f"Ops Dashboard {HOSTILE}",
    }


def _empty_inputs() -> dict[str, Any]:
    return {"results": [], "generated_at": GENERATED_AT}


CASES = {
    "full": _full_inputs,
    "empty": _empty_inputs,
}


def _fixture_text(case: str) -> str:
    return (FIXTURE_DIR / f"{case}.html").read_text(encoding="utf-8", newline="")


@pytest.mark.parametrize("case", sorted(CASES))
def test_generate_html_dashboard_matches_fixture(case: str) -> None:
    inputs = CASES[case]()
    results = inputs.pop("results")
    assert generate_html_dashboard(results, **inputs) == _fixture_text(case)


@pytest.mark.parametrize("case", sorted(CASES))
def test_generator_render_and_write_match_fixture(case: str, tmp_path: Path) -> None:
    expected = _fixture_text(case)
    inputs = CASES[case]()
    results = inputs.pop("results")
    assert HtmlDashboardGenerator().render(results, **inputs) == expected

    inputs = CASES[case]()
    results = inputs.pop("results")
    target = tmp_path / f"{case}.html"
    written = HtmlDashboardGenerator().write(results, target, **inputs)
    assert written == target
    assert target.read_text(encoding="utf-8", newline="") == expected


def test_full_fixture_escapes_hostile_markup() -> None:
    text = _fixture_text("full")
    assert "<img src=x onerror" not in text
    assert "&lt;img src=x onerror" in text
