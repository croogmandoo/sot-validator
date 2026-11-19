"""ITSM approval gate verifier for gated remediation execution."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hmac
from typing import Any, Optional

from sot_validator.itsm._enums import TicketApprovalStatus
from sot_validator.itsm._request import ItsmTicketRequest, compute_artifact_sha256
from sot_validator.itsm._sinks import InMemoryItsmSink, ItsmSink
from sot_validator.models import _format_optional_datetime
from sot_validator.remediation.executor import RemediationExecutionError
from sot_validator.remediation.quarantine import RemediationApprovalManifest


# ---------------------------------------------------------------------------
# ITSM Approval Gate Verifier
# ---------------------------------------------------------------------------


class ItsmGateVerificationError(RemediationExecutionError):
    """Raised when an ITSM change ticket is missing, unapproved, or fails SHA-256 digest verification."""


@dataclass(frozen=True)
class ItsmGateVerificationResult:
    """Structured result of verifying an ITSM change ticket against a remediation manifest or plan."""

    approved: bool
    ticket_id: str
    approval_status: str
    expected_sha256: Optional[str] = None
    actual_sha256: Optional[str] = None
    digest_matches: bool = False
    reason: str = ""
    verified_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    ticket: Optional[ItsmTicketRequest] = None

    @property
    def is_approved(self) -> bool:
        """Alias for approved."""
        return self.approved

    @property
    def valid(self) -> bool:
        """Alias for approved."""
        return self.approved

    def __bool__(self) -> bool:
        return self.approved

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "ticket_id": self.ticket_id,
            "approval_status": self.approval_status,
            "expected_sha256": self.expected_sha256,
            "actual_sha256": self.actual_sha256,
            "digest_matches": self.digest_matches,
            "reason": self.reason,
            "verified_at": _format_optional_datetime(self.verified_at),
            "ticket": self.ticket.to_dict() if self.ticket is not None else None,
        }


class ItsmGateVerifier:
    """Verifies that a change ticket is APPROVED (or SCHEDULED) and matches the target SHA-256 digest."""

    def __init__(
        self,
        sink: Optional[ItsmSink] = None,
        *,
        tickets: Optional[
            Sequence[ItsmTicketRequest | Mapping[str, Any]]
            | Mapping[str, ItsmTicketRequest | Mapping[str, Any]]
        ] = None,
        allow_scheduled: bool = False,
        raise_on_failure: bool = False,
    ) -> None:
        if sink is not None:
            self.sink: ItsmSink = sink
            if tickets is not None:
                temp_sink = InMemoryItsmSink(tickets)
                for t in temp_sink.tickets:
                    self.sink.submit_ticket(t)
        else:
            self.sink = InMemoryItsmSink(tickets)
        self.allow_scheduled = bool(allow_scheduled)
        self.raise_on_failure = bool(raise_on_failure)

    def register_ticket(
        self, ticket: ItsmTicketRequest | Mapping[str, Any]
    ) -> ItsmTicketRequest:
        """Register or update a ticket in the verifier's backing sink."""
        t_obj = (
            ticket
            if isinstance(ticket, ItsmTicketRequest)
            else ItsmTicketRequest.from_dict(ticket)
        )
        return self.sink.submit_ticket(t_obj)

    def _resolve_ticket(
        self,
        ticket_or_id: Optional[ItsmTicketRequest | Mapping[str, Any] | str],
        *,
        sink: Optional[ItsmSink] = None,
    ) -> tuple[Optional[ItsmTicketRequest], str]:
        if ticket_or_id is None:
            return None, ""
        if isinstance(ticket_or_id, ItsmTicketRequest):
            return ticket_or_id, ticket_or_id.ticket_id
        if isinstance(ticket_or_id, Mapping):
            t_obj = ItsmTicketRequest.from_dict(ticket_or_id)
            return t_obj, t_obj.ticket_id
        if isinstance(ticket_or_id, str):
            clean_id = ticket_or_id.strip()
            if not clean_id:
                return None, ""
            active_sink = sink if sink is not None else self.sink
            found = active_sink.get_ticket(clean_id)
            return found, clean_id
        raise TypeError(f"Unsupported ticket reference: {type(ticket_or_id)!r}")

    @staticmethod
    def _resolve_expected_digest(
        expected_sha256: Optional[Any] = None,
        *,
        manifest: Optional[Any] = None,
        plan: Optional[Any] = None,
        artifact: Optional[Any] = None,
    ) -> tuple[Optional[str], Optional[str]]:
        """Return (expected_sha256, integrity_error_message)."""
        target = (
            manifest
            if manifest is not None
            else (plan if plan is not None else artifact)
        )
        if target is None and expected_sha256 is not None and not isinstance(
            expected_sha256, str
        ):
            target = expected_sha256
            expected_sha256 = None

        if isinstance(target, RemediationApprovalManifest):
            if not target.verify_digest():
                return (
                    target.manifest_sha256,
                    f"Manifest {target.manifest_id!r} failed SHA-256 integrity verification",
                )
            if expected_sha256 is None:
                expected_sha256 = target.manifest_sha256
        elif target is not None and expected_sha256 is None:
            expected_sha256 = compute_artifact_sha256(target)

        if isinstance(expected_sha256, str) and expected_sha256.strip():
            return expected_sha256.strip().lower(), None
        return None, None

    def verify_change_ticket_approved(
        self,
        ticket_or_id: Optional[ItsmTicketRequest | Mapping[str, Any] | str],
        expected_sha256: Optional[Any] = None,
        *,
        manifest: Optional[Any] = None,
        plan: Optional[Any] = None,
        artifact: Optional[Any] = None,
        allow_scheduled: Optional[bool] = None,
        raise_on_failure: Optional[bool] = None,
        sink: Optional[ItsmSink] = None,
    ) -> ItsmGateVerificationResult:
        """Verify that a change ticket is APPROVED (or SCHEDULED) and matches the expected SHA-256 digest."""
        effective_allow_scheduled = (
            self.allow_scheduled if allow_scheduled is None else bool(allow_scheduled)
        )
        effective_raise = (
            self.raise_on_failure if raise_on_failure is None else bool(raise_on_failure)
        )
        now = datetime.now(timezone.utc)

        resolved_expected_sha, integrity_error = self._resolve_expected_digest(
            expected_sha256,
            manifest=manifest,
            plan=plan,
            artifact=artifact,
        )

        ticket, lookup_id = self._resolve_ticket(ticket_or_id, sink=sink)
        if ticket is None:
            reason = f"Change ticket {lookup_id!r} not found in ITSM governance sink"
            result = ItsmGateVerificationResult(
                approved=False,
                ticket_id=lookup_id,
                approval_status="MISSING",
                expected_sha256=resolved_expected_sha,
                actual_sha256=None,
                digest_matches=False,
                reason=reason,
                verified_at=now,
                ticket=None,
            )
            if effective_raise:
                raise ItsmGateVerificationError(reason)
            return result

        actual_sha = (
            ticket.artifact_sha256.strip().lower()
            if ticket.artifact_sha256 and ticket.artifact_sha256.strip()
            else None
        )

        if integrity_error is not None:
            result = ItsmGateVerificationResult(
                approved=False,
                ticket_id=ticket.ticket_id,
                approval_status=ticket.approval_status.value,
                expected_sha256=resolved_expected_sha,
                actual_sha256=actual_sha,
                digest_matches=False,
                reason=integrity_error,
                verified_at=now,
                ticket=ticket,
            )
            if effective_raise:
                raise ItsmGateVerificationError(integrity_error)
            return result

        allowed_statuses = {TicketApprovalStatus.APPROVED}
        if effective_allow_scheduled:
            allowed_statuses.add(TicketApprovalStatus.SCHEDULED)

        status_ok = ticket.approval_status in allowed_statuses

        if resolved_expected_sha is not None:
            digest_ok = bool(
                actual_sha is not None
                and hmac.compare_digest(actual_sha, resolved_expected_sha)
            )
        else:
            digest_ok = bool(actual_sha)

        if not status_ok:
            allowed_names = ", ".join(s.value for s in sorted(allowed_statuses, key=lambda x: x.value))
            reason = (
                f"Change ticket {ticket.ticket_id!r} has approval_status={ticket.approval_status.value!r}; "
                f"requires {allowed_names}"
            )
            result = ItsmGateVerificationResult(
                approved=False,
                ticket_id=ticket.ticket_id,
                approval_status=ticket.approval_status.value,
                expected_sha256=resolved_expected_sha,
                actual_sha256=actual_sha,
                digest_matches=digest_ok,
                reason=reason,
                verified_at=now,
                ticket=ticket,
            )
            if effective_raise:
                raise ItsmGateVerificationError(reason)
            return result

        if not digest_ok:
            if actual_sha is None:
                reason = (
                    f"Change ticket {ticket.ticket_id!r} is missing artifact_sha256 digest "
                    f"(expected {resolved_expected_sha!r})"
                )
            else:
                reason = (
                    f"Change ticket {ticket.ticket_id!r} SHA-256 digest mismatch: "
                    f"ticket has {actual_sha!r}, expected {resolved_expected_sha!r}"
                )
            result = ItsmGateVerificationResult(
                approved=False,
                ticket_id=ticket.ticket_id,
                approval_status=ticket.approval_status.value,
                expected_sha256=resolved_expected_sha,
                actual_sha256=actual_sha,
                digest_matches=False,
                reason=reason,
                verified_at=now,
                ticket=ticket,
            )
            if effective_raise:
                raise ItsmGateVerificationError(reason)
            return result

        ok_reason = (
            f"Change ticket {ticket.ticket_id!r} verified ({ticket.approval_status.value}, "
            f"sha256={actual_sha})"
        )
        return ItsmGateVerificationResult(
            approved=True,
            ticket_id=ticket.ticket_id,
            approval_status=ticket.approval_status.value,
            expected_sha256=resolved_expected_sha or actual_sha,
            actual_sha256=actual_sha,
            digest_matches=True,
            reason=ok_reason,
            verified_at=now,
            ticket=ticket,
        )

    def require_change_ticket_approved(
        self,
        ticket_or_id: Optional[ItsmTicketRequest | Mapping[str, Any] | str],
        expected_sha256: Optional[Any] = None,
        **kwargs: Any,
    ) -> ItsmGateVerificationResult:
        """Verify change ticket approval and always raise ItsmGateVerificationError on failure."""
        kwargs["raise_on_failure"] = True
        return self.verify_change_ticket_approved(
            ticket_or_id, expected_sha256, **kwargs
        )
