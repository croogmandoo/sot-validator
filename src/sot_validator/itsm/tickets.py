"""Phase 6 ITSM Change-Ticket & Approval Governance Sink (ServiceNow, Jira, and Webhook).

Public facade: the implementation lives in the private ``_enums``, ``_request``,
``_builder_change``, ``_builder_ops``, ``_builder``, ``_sinks`` and ``_gate`` modules.
"""

from __future__ import annotations

from sot_validator.itsm._builder import ItsmTicketPayloadBuilder
from sot_validator.itsm._enums import (
    ItsmApprovalStatus,
    ItsmProvider,
    ItsmWorkflowType,
    TicketApprovalStatus,
    TicketPriority,
    TicketRisk,
    _coerce_priority,
    _coerce_provider,
    _coerce_risk,
    _coerce_ticket_approval_status,
    _coerce_workflow_type,
    _normalize_str_list,
)
from sot_validator.itsm._gate import (
    ItsmGateVerificationError,
    ItsmGateVerificationResult,
    ItsmGateVerifier,
)
from sot_validator.itsm._request import (
    ItsmTicketRequest,
    QuarantineReport,
    _deterministic_ticket_id,
    compute_artifact_sha256,
)
from sot_validator.itsm._sinks import (
    InMemoryItsmSink,
    ItsmSink,
    ItsmWebhookSerializer,
    JsonFileItsmSink,
    WebhookItsmSink,
)


__all__ = [
    "InMemoryItsmSink",
    "ItsmApprovalStatus",
    "ItsmGateVerificationError",
    "ItsmGateVerificationResult",
    "ItsmGateVerifier",
    "ItsmProvider",
    "ItsmSink",
    "ItsmTicketPayloadBuilder",
    "ItsmTicketRequest",
    "ItsmWebhookSerializer",
    "ItsmWorkflowType",
    "JsonFileItsmSink",
    "QuarantineReport",
    "TicketApprovalStatus",
    "TicketPriority",
    "TicketRisk",
    "WebhookItsmSink",
    "compute_artifact_sha256",
]
