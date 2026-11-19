"""Deterministic ITSM ticket payload builder combining the per-workflow mixins."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Optional

from sot_validator.itsm._builder_change import _ChangeTicketBuilderMixin
from sot_validator.itsm._builder_ops import _OpsTicketBuilderMixin
from sot_validator.itsm._enums import ItsmWorkflowType, _coerce_workflow_type
from sot_validator.itsm._request import ItsmTicketRequest
from sot_validator.models import _require_non_empty_str
from sot_validator.reconciliation.reconciler import ReconciliationReport
from sot_validator.remediation.port_reclamation import PortReclamationPlan
from sot_validator.remediation.quarantine import RemediationApprovalManifest
from sot_validator.signals.base import resolve_evaluation_time
from sot_validator.signals.ups_health import UpsFleetHealthReport, UpsHealthRecord


class ItsmTicketPayloadBuilder(_ChangeTicketBuilderMixin, _OpsTicketBuilderMixin):
    """Deterministic ITSM change-ticket, onboarding task, and hardware incident payload builder."""

    def __init__(
        self,
        *,
        default_project_key: str = "NETOPS",
        default_cmdb_ci: str = "sot-inventory",
        evaluation_time: Optional[datetime | str] = None,
    ) -> None:
        self.default_project_key = _require_non_empty_str(
            default_project_key, "default_project_key"
        ).strip()
        self.default_cmdb_ci = _require_non_empty_str(
            default_cmdb_ci, "default_cmdb_ci"
        ).strip()
        self.evaluation_time: Optional[datetime] = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else None
        )

    def _resolve_timestamp(
        self, fallback: Optional[datetime | str] = None
    ) -> datetime:
        if self.evaluation_time is not None:
            return self.evaluation_time
        if fallback is not None:
            return resolve_evaluation_time(fallback)
        return datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Unified Dispatch & Provider Formatters
    # ------------------------------------------------------------------

    def build_ticket(
        self,
        artifact: Any,
        workflow_type: Optional[ItsmWorkflowType | str] = None,
        **kwargs: Any,
    ) -> ItsmTicketRequest:
        """Auto-detect or dispatch ticket generation for any supported Phase 2-6 workflow artifact."""
        resolved_wf: Optional[ItsmWorkflowType] = (
            _coerce_workflow_type(workflow_type)
            if workflow_type is not None
            else None
        )
        if resolved_wf is None:
            if isinstance(artifact, RemediationApprovalManifest):
                resolved_wf = ItsmWorkflowType.QUARANTINE_DECOMMISSION
            elif isinstance(artifact, PortReclamationPlan):
                resolved_wf = ItsmWorkflowType.PORT_RECLAMATION
            elif isinstance(artifact, ReconciliationReport):
                resolved_wf = ItsmWorkflowType.SHADOW_IT_ONBOARDING
            elif isinstance(artifact, (UpsFleetHealthReport, UpsHealthRecord)):
                resolved_wf = ItsmWorkflowType.UPS_HARDWARE_INCIDENT
            elif isinstance(artifact, Mapping):
                if "entries" in artifact or "manifest_id" in artifact:
                    resolved_wf = ItsmWorkflowType.QUARANTINE_DECOMMISSION
                elif "candidates" in artifact or "plan_id" in artifact:
                    resolved_wf = ItsmWorkflowType.PORT_RECLAMATION
                elif "discrepancies" in artifact:
                    resolved_wf = ItsmWorkflowType.SHADOW_IT_ONBOARDING
                elif "records" in artifact or "equipment_id" in artifact:
                    resolved_wf = ItsmWorkflowType.UPS_HARDWARE_INCIDENT

        if resolved_wf is ItsmWorkflowType.QUARANTINE_DECOMMISSION:
            return self.build_quarantine_ticket(artifact, **kwargs)
        if resolved_wf is ItsmWorkflowType.PORT_RECLAMATION:
            return self.build_port_reclamation_ticket(artifact, **kwargs)
        if resolved_wf is ItsmWorkflowType.SHADOW_IT_ONBOARDING:
            return self.build_onboarding_ticket(artifact, **kwargs)
        if resolved_wf is ItsmWorkflowType.UPS_HARDWARE_INCIDENT:
            return self.build_ups_incident_ticket(artifact, **kwargs)

        raise ValueError(
            f"Could not determine ITSM workflow type for artifact {type(artifact)!r}"
        )

    @staticmethod
    def format_servicenow(
        ticket: ItsmTicketRequest | Mapping[str, Any]
    ) -> dict[str, Any]:
        """Format an ItsmTicketRequest into a ServiceNow change_request / incident dictionary."""
        ticket_obj = (
            ticket
            if isinstance(ticket, ItsmTicketRequest)
            else ItsmTicketRequest.from_dict(ticket)
        )
        return ticket_obj.to_servicenow_payload()

    @staticmethod
    def format_jira(
        ticket: ItsmTicketRequest | Mapping[str, Any],
        *,
        project_key: Optional[str] = None,
    ) -> dict[str, Any]:
        """Format an ItsmTicketRequest into a Jira issue creation dictionary."""
        ticket_obj = (
            ticket
            if isinstance(ticket, ItsmTicketRequest)
            else ItsmTicketRequest.from_dict(ticket)
        )
        return ticket_obj.to_jira_payload(project_key=project_key)

    @staticmethod
    def format_webhook(
        ticket: ItsmTicketRequest | Mapping[str, Any]
    ) -> dict[str, Any]:
        """Format an ItsmTicketRequest into a generic webhook payload dictionary."""
        ticket_obj = (
            ticket
            if isinstance(ticket, ItsmTicketRequest)
            else ItsmTicketRequest.from_dict(ticket)
        )
        return ticket_obj.to_webhook_payload()
