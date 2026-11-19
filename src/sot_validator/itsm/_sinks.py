"""Protocol-based offline ITSM sinks and webhook serializer."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Optional, Protocol, runtime_checkable

from sot_validator.itsm._enums import (
    ItsmProvider,
    ItsmWorkflowType,
    TicketApprovalStatus,
    _coerce_provider,
    _coerce_ticket_approval_status,
    _coerce_workflow_type,
)
from sot_validator.itsm._request import ItsmTicketRequest
from sot_validator.models import _require_non_empty_str
from sot_validator.signals.base import normalize_utc_datetime


# ---------------------------------------------------------------------------
# Protocol-Based Offline ITSM Sinks & Webhook Serializer
# ---------------------------------------------------------------------------


@runtime_checkable
class ItsmSink(Protocol):
    """Protocol for offline-capable ITSM change-ticket governance sinks."""

    def submit_ticket(self, ticket: ItsmTicketRequest) -> ItsmTicketRequest:
        """Persist or emit a change ticket request and return the stored ticket."""
        ...

    def get_ticket(self, ticket_id: str) -> Optional[ItsmTicketRequest]:
        """Retrieve a stored ticket by its ticket_id, or None if not found."""
        ...

    def list_tickets(
        self,
        workflow_type: Optional[ItsmWorkflowType | str] = None,
        approval_status: Optional[TicketApprovalStatus | str] = None,
    ) -> list[ItsmTicketRequest]:
        """List stored tickets, optionally filtered by workflow_type and/or approval_status."""
        ...

    def update_approval_status(
        self,
        ticket_id: str,
        approval_status: TicketApprovalStatus | str,
        *,
        approved_by: Optional[str] = None,
        approved_at: Optional[datetime | str] = None,
        artifact_sha256: Optional[str] = None,
    ) -> ItsmTicketRequest:
        """Transition a stored ticket's approval status and return the updated ticket."""
        ...


class ItsmWebhookSerializer:
    """Deterministic JSON serializer for ServiceNow, Jira, and generic ITSM webhooks."""

    @staticmethod
    def format_payload(
        ticket: ItsmTicketRequest | Mapping[str, Any],
        provider: ItsmProvider | str = ItsmProvider.WEBHOOK,
        *,
        project_key: Optional[str] = None,
    ) -> dict[str, Any]:
        ticket_obj = (
            ticket
            if isinstance(ticket, ItsmTicketRequest)
            else ItsmTicketRequest.from_dict(ticket)
        )
        return ticket_obj.format_for_provider(provider, project_key=project_key)

    @classmethod
    def serialize(
        cls,
        ticket: ItsmTicketRequest | Mapping[str, Any],
        provider: ItsmProvider | str = ItsmProvider.WEBHOOK,
        *,
        project_key: Optional[str] = None,
        indent: Optional[int] = 2,
    ) -> str:
        payload = cls.format_payload(
            ticket, provider=provider, project_key=project_key
        )
        return json.dumps(payload, indent=indent, sort_keys=True)


class InMemoryItsmSink:
    """In-memory ITSM ticket governance sink for offline execution and unit testing."""

    def __init__(
        self,
        tickets: Optional[
            Sequence[ItsmTicketRequest | Mapping[str, Any]]
            | Mapping[str, ItsmTicketRequest | Mapping[str, Any]]
        ] = None,
    ) -> None:
        self._tickets_by_id: dict[str, ItsmTicketRequest] = {}
        if tickets is not None:
            if isinstance(tickets, Mapping):
                for key, raw in tickets.items():
                    t_obj = (
                        raw
                        if isinstance(raw, ItsmTicketRequest)
                        else ItsmTicketRequest.from_dict(
                            {**raw, "ticket_id": raw.get("ticket_id", key)}
                        )
                    )
                    self._tickets_by_id[t_obj.ticket_id] = t_obj
            else:
                for raw in tickets:
                    t_obj = (
                        raw
                        if isinstance(raw, ItsmTicketRequest)
                        else ItsmTicketRequest.from_dict(raw)
                    )
                    self._tickets_by_id[t_obj.ticket_id] = t_obj

    @property
    def tickets(self) -> list[ItsmTicketRequest]:
        """Return all stored tickets in insertion order."""
        return list(self._tickets_by_id.values())

    def submit_ticket(
        self, ticket: ItsmTicketRequest | Mapping[str, Any]
    ) -> ItsmTicketRequest:
        t_obj = (
            ticket
            if isinstance(ticket, ItsmTicketRequest)
            else ItsmTicketRequest.from_dict(ticket)
        )
        self._tickets_by_id[t_obj.ticket_id] = t_obj
        return t_obj

    emit = submit_ticket
    create_ticket = submit_ticket

    def get_ticket(self, ticket_id: str) -> Optional[ItsmTicketRequest]:
        if not isinstance(ticket_id, str) or not ticket_id.strip():
            return None
        return self._tickets_by_id.get(ticket_id.strip())

    def list_tickets(
        self,
        workflow_type: Optional[ItsmWorkflowType | str] = None,
        approval_status: Optional[TicketApprovalStatus | str] = None,
    ) -> list[ItsmTicketRequest]:
        resolved_wf = (
            _coerce_workflow_type(workflow_type)
            if workflow_type is not None
            else None
        )
        resolved_status = (
            _coerce_ticket_approval_status(approval_status)
            if approval_status is not None
            else None
        )
        results: list[ItsmTicketRequest] = []
        for ticket in self._tickets_by_id.values():
            if resolved_wf is not None and ticket.workflow_type is not resolved_wf:
                continue
            if (
                resolved_status is not None
                and ticket.approval_status is not resolved_status
            ):
                continue
            results.append(ticket)
        return results

    def update_approval_status(
        self,
        ticket_id: str,
        approval_status: TicketApprovalStatus | str,
        *,
        approved_by: Optional[str] = None,
        approved_at: Optional[datetime | str] = None,
        artifact_sha256: Optional[str] = None,
    ) -> ItsmTicketRequest:
        ticket = self.get_ticket(ticket_id)
        if ticket is None:
            raise KeyError(f"ITSM ticket {ticket_id!r} not found in sink")
        ticket.approval_status = _coerce_ticket_approval_status(approval_status)
        if approved_by is not None:
            ticket.approved_by = approved_by.strip() or None
        if approved_at is not None:
            ticket.approved_at = normalize_utc_datetime(
                approved_at, field_name="approved_at"
            )
        elif ticket.approval_status in (
            TicketApprovalStatus.APPROVED,
            TicketApprovalStatus.SCHEDULED,
        ) and ticket.approved_at is None:
            ticket.approved_at = datetime.now(timezone.utc)
        if artifact_sha256 is not None:
            ticket.artifact_sha256 = artifact_sha256.strip().lower() or None
        return ticket

    def approve_ticket(
        self,
        ticket_id: str,
        *,
        approved_by: str = "cab-approver",
        approved_at: Optional[datetime | str] = None,
        artifact_sha256: Optional[str] = None,
    ) -> ItsmTicketRequest:
        return self.update_approval_status(
            ticket_id,
            TicketApprovalStatus.APPROVED,
            approved_by=approved_by,
            approved_at=approved_at,
            artifact_sha256=artifact_sha256,
        )

    def reject_ticket(
        self,
        ticket_id: str,
        *,
        approved_by: str = "cab-approver",
        approved_at: Optional[datetime | str] = None,
    ) -> ItsmTicketRequest:
        return self.update_approval_status(
            ticket_id,
            TicketApprovalStatus.REJECTED,
            approved_by=approved_by,
            approved_at=approved_at,
        )

    def clear(self) -> None:
        self._tickets_by_id.clear()


class JsonFileItsmSink(InMemoryItsmSink):
    """Offline ITSM change-ticket sink backed by a local JSON or JSON Lines file."""

    def __init__(
        self,
        file_path: Path | str,
        *,
        jsonl: bool = False,
        indent: Optional[int] = 2,
    ) -> None:
        super().__init__()
        if isinstance(file_path, Path):
            self.file_path = file_path
        elif isinstance(file_path, str) and file_path.strip():
            self.file_path = Path(file_path.strip())
        else:
            raise ValueError("file_path must be a non-empty Path or string")
        self.jsonl = bool(jsonl)
        self.indent = indent
        self._load_from_disk()

    def _load_from_disk(self) -> None:
        if not self.file_path.exists():
            return
        raw_text = self.file_path.read_text(encoding="utf-8").strip()
        if not raw_text:
            return
        self._tickets_by_id.clear()
        if self.jsonl:
            for line in raw_text.splitlines():
                stripped = line.strip()
                if stripped:
                    ticket = ItsmTicketRequest.from_json(stripped)
                    self._tickets_by_id[ticket.ticket_id] = ticket
            return

        parsed = json.loads(raw_text)
        if isinstance(parsed, list):
            for item in parsed:
                ticket = ItsmTicketRequest.from_dict(item)
                self._tickets_by_id[ticket.ticket_id] = ticket
        elif isinstance(parsed, Mapping):
            if "tickets" in parsed and isinstance(parsed["tickets"], list):
                for item in parsed["tickets"]:
                    ticket = ItsmTicketRequest.from_dict(item)
                    self._tickets_by_id[ticket.ticket_id] = ticket
            elif "ticket_id" in parsed:
                ticket = ItsmTicketRequest.from_dict(parsed)
                self._tickets_by_id[ticket.ticket_id] = ticket

    def _flush_to_disk(self) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        if self.jsonl:
            lines = [
                t.to_json(indent=None) for t in self._tickets_by_id.values()
            ]
            content = "\n".join(lines) + ("\n" if lines else "")
            self.file_path.write_text(content, encoding="utf-8")
            return

        payload = [t.to_dict() for t in self._tickets_by_id.values()]
        self.file_path.write_text(
            json.dumps(payload, indent=self.indent),
            encoding="utf-8",
        )

    def submit_ticket(
        self, ticket: ItsmTicketRequest | Mapping[str, Any]
    ) -> ItsmTicketRequest:
        self._load_from_disk()
        stored = super().submit_ticket(ticket)
        self._flush_to_disk()
        return stored

    emit = submit_ticket
    create_ticket = submit_ticket

    def get_ticket(self, ticket_id: str) -> Optional[ItsmTicketRequest]:
        self._load_from_disk()
        return super().get_ticket(ticket_id)

    def list_tickets(
        self,
        workflow_type: Optional[ItsmWorkflowType | str] = None,
        approval_status: Optional[TicketApprovalStatus | str] = None,
    ) -> list[ItsmTicketRequest]:
        self._load_from_disk()
        return super().list_tickets(
            workflow_type=workflow_type, approval_status=approval_status
        )

    def update_approval_status(
        self,
        ticket_id: str,
        approval_status: TicketApprovalStatus | str,
        *,
        approved_by: Optional[str] = None,
        approved_at: Optional[datetime | str] = None,
        artifact_sha256: Optional[str] = None,
    ) -> ItsmTicketRequest:
        self._load_from_disk()
        updated = super().update_approval_status(
            ticket_id,
            approval_status,
            approved_by=approved_by,
            approved_at=approved_at,
            artifact_sha256=artifact_sha256,
        )
        self._flush_to_disk()
        return updated

    def read_tickets(self) -> list[ItsmTicketRequest]:
        """Reload and return all tickets persisted in file_path."""
        self._load_from_disk()
        return self.tickets


class WebhookItsmSink(InMemoryItsmSink):
    """Offline ITSM webhook sink that serializes submitted tickets into provider webhook payloads."""

    def __init__(
        self,
        *,
        provider: ItsmProvider | str = ItsmProvider.WEBHOOK,
        project_key: str = "NETOPS",
        callback: Optional[Callable[[dict[str, Any]], None]] = None,
        output_path: Optional[Path | str] = None,
    ) -> None:
        super().__init__()
        self.provider = _coerce_provider(provider)
        self.project_key = _require_non_empty_str(
            project_key, "project_key"
        ).strip()
        self.callback = callback
        self.output_path = Path(output_path) if output_path is not None else None
        self.payloads: list[dict[str, Any]] = []
        self.serialized_payloads: list[str] = []

    def submit_ticket(
        self, ticket: ItsmTicketRequest | Mapping[str, Any]
    ) -> ItsmTicketRequest:
        stored = super().submit_ticket(ticket)
        self._record_webhook_payload(stored)
        return stored

    emit = submit_ticket
    create_ticket = submit_ticket

    def update_approval_status(
        self,
        ticket_id: str,
        approval_status: TicketApprovalStatus | str,
        *,
        approved_by: Optional[str] = None,
        approved_at: Optional[datetime | str] = None,
        artifact_sha256: Optional[str] = None,
    ) -> ItsmTicketRequest:
        updated = super().update_approval_status(
            ticket_id,
            approval_status,
            approved_by=approved_by,
            approved_at=approved_at,
            artifact_sha256=artifact_sha256,
        )
        self._record_webhook_payload(updated)
        return updated

    def _record_webhook_payload(self, ticket: ItsmTicketRequest) -> None:
        payload = ItsmWebhookSerializer.format_payload(
            ticket, provider=self.provider, project_key=self.project_key
        )
        serialized = ItsmWebhookSerializer.serialize(
            ticket, provider=self.provider, project_key=self.project_key
        )
        self.payloads.append(payload)
        self.serialized_payloads.append(serialized)
        if self.callback is not None:
            self.callback(payload)
        if self.output_path is not None:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            self.output_path.write_text(
                json.dumps(self.payloads, indent=2),
                encoding="utf-8",
            )
