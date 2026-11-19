"""ITSM workflow, provider, approval, risk and priority enums plus coercion helpers."""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum
from typing import Any, Optional


class ItsmWorkflowType(str, Enum):
    """Supported Phase 6 ITSM operational change, onboarding, and incident workflows."""

    QUARANTINE_DECOMMISSION = "QUARANTINE_DECOMMISSION"
    PORT_RECLAMATION = "PORT_RECLAMATION"
    SHADOW_IT_ONBOARDING = "SHADOW_IT_ONBOARDING"
    UPS_HARDWARE_INCIDENT = "UPS_HARDWARE_INCIDENT"

    @classmethod
    def _missing_(cls, value: object) -> Optional[ItsmWorkflowType]:
        if isinstance(value, str):
            norm = value.strip().lower().replace("-", "_").replace(" ", "_")
            if norm in (
                "quarantine_decommission",
                "quarantine",
                "stale_quarantine",
                "decommission",
                "sot_quarantine",
                "remediation",
            ):
                return cls.QUARANTINE_DECOMMISSION
            if norm in (
                "port_reclamation",
                "port_shutdown",
                "port_shutdowns",
                "extreme_port_reclamation",
                "reclaim_ports",
                "switch_port_reclamation",
                "poe_reclamation",
            ):
                return cls.PORT_RECLAMATION
            if norm in (
                "shadow_it_onboarding",
                "onboarding",
                "reconciliation",
                "shadow_it",
                "asset_onboarding",
                "untracked_inventory",
            ):
                return cls.SHADOW_IT_ONBOARDING
            if norm in (
                "ups_hardware_incident",
                "ups_incident",
                "ups_health",
                "apc_ups_alert",
                "ups_alert",
                "battery_replacement",
                "ups",
            ):
                return cls.UPS_HARDWARE_INCIDENT
        return None


class ItsmProvider(str, Enum):
    """Supported ITSM payload and webhook target providers."""

    SERVICENOW = "servicenow"
    JIRA = "jira"
    WEBHOOK = "webhook"

    @classmethod
    def _missing_(cls, value: object) -> Optional[ItsmProvider]:
        if isinstance(value, str):
            norm = value.strip().lower().replace("-", "_")
            if norm in ("servicenow", "service_now", "snow"):
                return cls.SERVICENOW
            if norm in ("jira", "jira_cloud", "jira_server", "atlassian"):
                return cls.JIRA
            if norm in ("webhook", "generic", "json", "generic_webhook"):
                return cls.WEBHOOK
        return None


class TicketApprovalStatus(str, Enum):
    """Standardized ITSM change-ticket and task approval states."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    SCHEDULED = "SCHEDULED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"
    IMPLEMENTED = "IMPLEMENTED"

    @classmethod
    def _missing_(cls, value: object) -> Optional[TicketApprovalStatus]:
        if isinstance(value, str):
            norm = value.strip().upper().replace("-", "_").replace(" ", "_")
            if norm in ("PENDING", "REQUESTED", "NOT_YET_REQUESTED", "NEW", "OPEN", "REVIEW"):
                return cls.PENDING
            if norm in ("APPROVED", "AUTHORIZED", "CAB_APPROVED"):
                return cls.APPROVED
            if norm in ("SCHEDULED", "PLANNED", "READY"):
                return cls.SCHEDULED
            if norm in ("REJECTED", "DENIED", "DECLINED"):
                return cls.REJECTED
            if norm in ("CANCELLED", "CANCELED", "WITHDRAWN"):
                return cls.CANCELLED
            if norm in ("IMPLEMENTED", "CLOSED", "COMPLETED", "DONE", "RESOLVED"):
                return cls.IMPLEMENTED
        return None


# Alias for callers importing ItsmApprovalStatus.
ItsmApprovalStatus = TicketApprovalStatus


class TicketRisk(str, Enum):
    """Standardized ServiceNow / ITSM change risk levels."""

    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def _missing_(cls, value: object) -> Optional[TicketRisk]:
        if isinstance(value, str):
            norm = value.strip().lower()
            if norm in ("low", "minor", "4"):
                return cls.LOW
            if norm in ("moderate", "medium", "normal", "3"):
                return cls.MODERATE
            if norm in ("high", "major", "2"):
                return cls.HIGH
            if norm in ("critical", "very_high", "very high", "1"):
                return cls.CRITICAL
        return None


class TicketPriority(str, Enum):
    """Standardized Jira / ITSM priority levels."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @classmethod
    def _missing_(cls, value: object) -> Optional[TicketPriority]:
        if isinstance(value, str):
            norm = value.strip().lower()
            if norm in ("low", "minor", "4", "p4"):
                return cls.LOW
            if norm in ("medium", "moderate", "normal", "3", "p3"):
                return cls.MEDIUM
            if norm in ("high", "major", "2", "p2"):
                return cls.HIGH
            if norm in ("critical", "highest", "blocker", "1", "p1"):
                return cls.CRITICAL
        return None


def _coerce_workflow_type(
    value: ItsmWorkflowType | str,
    field_name: str = "workflow_type",
) -> ItsmWorkflowType:
    if isinstance(value, ItsmWorkflowType):
        return value
    if isinstance(value, str):
        try:
            return ItsmWorkflowType(value)
        except ValueError as exc:
            raise ValueError(f"Invalid {field_name}: {value!r}") from exc
    raise ValueError(f"Invalid {field_name}: {value!r}")


def _coerce_provider(
    value: ItsmProvider | str,
    field_name: str = "provider",
) -> ItsmProvider:
    if isinstance(value, ItsmProvider):
        return value
    if isinstance(value, str):
        try:
            return ItsmProvider(value)
        except ValueError as exc:
            raise ValueError(f"Invalid {field_name}: {value!r}") from exc
    raise ValueError(f"Invalid {field_name}: {value!r}")


def _coerce_ticket_approval_status(
    value: TicketApprovalStatus | str,
    field_name: str = "approval_status",
) -> TicketApprovalStatus:
    if isinstance(value, TicketApprovalStatus):
        return value
    if isinstance(value, str):
        try:
            return TicketApprovalStatus(value)
        except ValueError as exc:
            raise ValueError(f"Invalid {field_name}: {value!r}") from exc
    raise ValueError(f"Invalid {field_name}: {value!r}")


def _coerce_risk(value: TicketRisk | str) -> str:
    if isinstance(value, TicketRisk):
        return value.value
    if isinstance(value, str):
        try:
            return TicketRisk(value).value
        except ValueError:
            cleaned = value.strip().lower()
            if cleaned:
                return cleaned
    raise ValueError(f"Invalid risk: {value!r}")


def _coerce_priority(value: TicketPriority | str) -> str:
    if isinstance(value, TicketPriority):
        return value.value
    if isinstance(value, str):
        try:
            return TicketPriority(value).value
        except ValueError:
            cleaned = value.strip()
            if cleaned:
                return cleaned
    raise ValueError(f"Invalid priority: {value!r}")


def _normalize_str_list(values: Optional[Iterable[Any]]) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        cleaned = values.strip()
        return [cleaned] if cleaned else []
    result: list[str] = []
    seen: set[str] = set()
    for item in values:
        if item is None:
            continue
        text = str(item.value if isinstance(item, Enum) else item).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result
