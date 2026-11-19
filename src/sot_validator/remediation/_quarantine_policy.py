"""Quarantine graduation policy and approval manifest entry records."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
from typing import Any, ClassVar, Optional

from sot_validator.history.ledger import ItemStreakSummary
from sot_validator.models import (
    ValidationClassification,
    _format_optional_datetime,
    _parse_optional_datetime,
    _require_non_empty_str,
)
from sot_validator.remediation._quarantine_common import (
    ApprovalStatus,
    QuarantineGraduationStatus,
    RemediationOperation,
    _coerce_approval_status,
    _coerce_graduation_status,
    _coerce_remediation_operation,
    _default_operation_for_item,
    _normalize_string_tuple,
    _normalize_subnets_tuple,
)
from sot_validator.remediation.sink import (
    ProposedRemediationAction,
    RemediationActionType,
    _enforce_dry_run_only,
)


@dataclass(init=False)
class QuarantinePolicy:
    """Configurable rules governing when a Stale / Likely Unused item graduates to cleanup eligibility."""

    min_consecutive_stale_runs: int = 3
    min_stale_days: float = 30.0
    min_confidence: float = 0.85
    protected_item_ids: tuple[str, ...] = ()
    protected_categories: tuple[str, ...] = ()
    protected_subnets: tuple[str, ...] = ()
    protected_vendors: tuple[str, ...] = ()
    allow_protected_override: bool = False

    def __init__(
        self,
        min_consecutive_stale_runs: int = 3,
        min_stale_days: float = 30.0,
        min_confidence: float = 0.85,
        protected_item_ids: Iterable[str] = (),
        protected_categories: Iterable[str | Enum] = (),
        protected_subnets: Iterable[str] = (),
        protected_Subnets: Optional[Iterable[str]] = None,
        protected_vendors: Iterable[str] = (),
        allow_protected_override: bool = False,
    ) -> None:
        if (
            isinstance(min_consecutive_stale_runs, bool)
            or not isinstance(min_consecutive_stale_runs, int)
            or min_consecutive_stale_runs < 1
        ):
            raise ValueError(
                "min_consecutive_stale_runs must be an integer >= 1"
            )
        self.min_consecutive_stale_runs = min_consecutive_stale_runs

        if isinstance(min_stale_days, bool) or not isinstance(
            min_stale_days, (int, float)
        ):
            raise ValueError("min_stale_days must be a non-negative number")
        self.min_stale_days = float(min_stale_days)
        if self.min_stale_days < 0.0:
            raise ValueError("min_stale_days must be non-negative")

        if isinstance(min_confidence, bool) or not isinstance(
            min_confidence, (int, float)
        ):
            raise ValueError("min_confidence must be a number between 0.0 and 1.0")
        self.min_confidence = float(min_confidence)
        if not (0.0 <= self.min_confidence <= 1.0):
            raise ValueError("min_confidence must be between 0.0 and 1.0")

        self.protected_item_ids = _normalize_string_tuple(
            protected_item_ids, "protected_item_ids", lowercase=False
        )
        self.protected_categories = _normalize_string_tuple(
            protected_categories, "protected_categories", lowercase=True
        )

        combined_subnets: list[str] = []
        if protected_subnets:
            if isinstance(protected_subnets, (str, bytes)):
                raise ValueError("protected_subnets must be an iterable of CIDR strings")
            combined_subnets.extend(protected_subnets)
        if protected_Subnets is not None:
            if isinstance(protected_Subnets, (str, bytes)):
                raise ValueError("protected_Subnets must be an iterable of CIDR strings")
            combined_subnets.extend(protected_Subnets)
        self.protected_subnets = _normalize_subnets_tuple(
            combined_subnets, "protected_subnets"
        )

        self.protected_vendors = _normalize_string_tuple(
            protected_vendors, "protected_vendors", lowercase=True
        )
        if not isinstance(allow_protected_override, bool):
            raise ValueError("allow_protected_override must be a boolean")
        self.allow_protected_override = allow_protected_override

    @property
    def protected_Subnets(self) -> tuple[str, ...]:
        """Alias for protected_subnets matching Issue #21 casing."""
        return self.protected_subnets

    @protected_Subnets.setter
    def protected_Subnets(self, value: Iterable[str]) -> None:
        self.protected_subnets = _normalize_subnets_tuple(
            value, "protected_Subnets"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "min_consecutive_stale_runs": self.min_consecutive_stale_runs,
            "min_stale_days": self.min_stale_days,
            "min_confidence": self.min_confidence,
            "protected_item_ids": list(self.protected_item_ids),
            "protected_categories": list(self.protected_categories),
            "protected_subnets": list(self.protected_subnets),
            "protected_vendors": list(self.protected_vendors),
            "allow_protected_override": self.allow_protected_override,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> QuarantinePolicy:
        return cls(
            min_consecutive_stale_runs=int(
                data.get("min_consecutive_stale_runs", 3)
            ),
            min_stale_days=float(data.get("min_stale_days", 30.0)),
            min_confidence=float(data.get("min_confidence", 0.85)),
            protected_item_ids=data.get("protected_item_ids", ()),
            protected_categories=data.get("protected_categories", ()),
            protected_subnets=data.get("protected_subnets", ()),
            protected_Subnets=data.get("protected_Subnets"),
            protected_vendors=data.get("protected_vendors", ()),
            allow_protected_override=bool(
                data.get("allow_protected_override", False)
            ),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> QuarantinePolicy:
        return cls.from_dict(json.loads(raw))


@dataclass(init=False)
class QuarantineManifestEntry:
    """Single item entry in a RemediationApprovalManifest linking action, streak, and review state."""

    FLAG_STALE_IN_SOT: ClassVar[RemediationOperation] = (
        RemediationOperation.FLAG_STALE_IN_SOT
    )
    RECLAIM_STALE_IP: ClassVar[RemediationOperation] = (
        RemediationOperation.RECLAIM_STALE_IP
    )
    DECOMMISSION_VM_RECORD: ClassVar[RemediationOperation] = (
        RemediationOperation.DECOMMISSION_VM_RECORD
    )
    PROPOSE_PORT_SHUTDOWN: ClassVar[RemediationOperation] = (
        RemediationOperation.PROPOSE_PORT_SHUTDOWN
    )
    EXEMPT_PROTECTED: ClassVar[RemediationOperation] = (
        RemediationOperation.EXEMPT_PROTECTED
    )

    action: ProposedRemediationAction
    site_id: str
    item_type: str
    item_id: str
    name: str
    classification: ValidationClassification
    confidence: float
    consecutive_stale_runs: int
    stale_duration_days: float
    target_operation: RemediationOperation
    graduation_status: QuarantineGraduationStatus = (
        QuarantineGraduationStatus.ELIGIBLE
    )
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    reviewed_by: Optional[str] = None
    review_note: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    exemption_reason: Optional[str] = None
    rationale: Optional[str] = None
    proposed_at: Optional[datetime] = None
    dry_run: bool = True
    streak: Optional[ItemStreakSummary] = field(default=None, repr=False, compare=False)

    def __init__(
        self,
        action: Optional[ProposedRemediationAction | Mapping[str, Any]] = None,
        *,
        streak: Optional[ItemStreakSummary | Mapping[str, Any]] = None,
        site_id: Optional[str] = None,
        item_type: Optional[str] = None,
        item_id: Optional[str] = None,
        name: Optional[str] = None,
        classification: Optional[ValidationClassification | str] = None,
        confidence: Optional[float] = None,
        consecutive_stale_runs: Optional[int] = None,
        stale_duration_days: Optional[float] = None,
        target_operation: Optional[RemediationOperation | str] = None,
        operation: Optional[RemediationOperation | str] = None,
        graduation_status: Optional[QuarantineGraduationStatus | str] = None,
        approval_status: ApprovalStatus | str = ApprovalStatus.PENDING,
        reviewed_by: Optional[str] = None,
        review_note: Optional[str] = None,
        reviewed_at: Optional[datetime | str] = None,
        exemption_reason: Optional[str] = None,
        rationale: Optional[str] = None,
        proposed_at: Optional[datetime | str] = None,
        dry_run: bool = True,
    ) -> None:
        self.dry_run = _enforce_dry_run_only(dry_run, "QuarantineManifestEntry")

        resolved_streak: Optional[ItemStreakSummary] = None
        if streak is not None:
            resolved_streak = (
                streak
                if isinstance(streak, ItemStreakSummary)
                else ItemStreakSummary.from_dict(streak)
            )
        self.streak = resolved_streak

        resolved_action: Optional[ProposedRemediationAction] = None
        if action is not None:
            resolved_action = (
                action
                if isinstance(action, ProposedRemediationAction)
                else ProposedRemediationAction.from_dict(action)
            )

        res_site_id = (
            site_id
            or (resolved_action.site_id if resolved_action is not None else None)
            or (resolved_streak.site_id if resolved_streak is not None else None)
        )
        res_item_type = (
            item_type
            or (resolved_action.item_type if resolved_action is not None else None)
            or (resolved_streak.item_type if resolved_streak is not None else None)
        )
        res_item_id = (
            item_id
            or (resolved_action.item_id if resolved_action is not None else None)
            or (resolved_streak.item_id if resolved_streak is not None else None)
        )
        res_name = (
            name
            or (resolved_action.name if resolved_action is not None else None)
            or (resolved_streak.name if resolved_streak is not None else None)
            or res_item_id
        )
        res_cls_raw = (
            classification
            if classification is not None
            else (
                resolved_action.classification
                if resolved_action is not None
                else (
                    resolved_streak.current_classification
                    if resolved_streak is not None
                    else ValidationClassification.STALE_LIKELY_UNUSED
                )
            )
        )
        res_conf_raw = (
            confidence
            if confidence is not None
            else (
                resolved_action.confidence
                if resolved_action is not None
                else (
                    resolved_streak.current_confidence
                    if resolved_streak is not None
                    else 0.0
                )
            )
        )
        res_runs_raw = (
            consecutive_stale_runs
            if consecutive_stale_runs is not None
            else (
                resolved_streak.consecutive_stale_runs
                if resolved_streak is not None
                else 0
            )
        )
        res_days_raw = (
            stale_duration_days
            if stale_duration_days is not None
            else (
                resolved_streak.stale_duration_days
                if resolved_streak is not None
                else 0.0
            )
        )
        res_rationale = (
            rationale
            if rationale is not None
            else (resolved_action.rationale if resolved_action is not None else None)
        )
        res_proposed_at = (
            _parse_optional_datetime(proposed_at, "proposed_at")
            if proposed_at is not None
            else (
                resolved_action.proposed_at if resolved_action is not None else None
            )
        )

        self.site_id = _require_non_empty_str(res_site_id, "site_id")
        self.item_type = _require_non_empty_str(res_item_type, "item_type")
        self.item_id = _require_non_empty_str(res_item_id, "item_id")
        self.name = _require_non_empty_str(res_name, "name")

        if isinstance(res_cls_raw, ValidationClassification):
            self.classification = res_cls_raw
        else:
            try:
                self.classification = ValidationClassification(res_cls_raw)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid classification: {res_cls_raw!r}"
                ) from exc

        if isinstance(res_conf_raw, bool) or not isinstance(
            res_conf_raw, (int, float)
        ):
            raise ValueError("confidence must be a number between 0.0 and 1.0")
        self.confidence = float(res_conf_raw)
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be between 0.0 and 1.0")

        if (
            isinstance(res_runs_raw, bool)
            or not isinstance(res_runs_raw, int)
            or res_runs_raw < 0
        ):
            raise ValueError(
                "consecutive_stale_runs must be a non-negative integer"
            )
        self.consecutive_stale_runs = res_runs_raw

        if isinstance(res_days_raw, bool) or not isinstance(
            res_days_raw, (int, float)
        ):
            raise ValueError("stale_duration_days must be a non-negative number")
        self.stale_duration_days = float(res_days_raw)
        if self.stale_duration_days < 0.0:
            raise ValueError("stale_duration_days must be non-negative")

        op_raw = target_operation if target_operation is not None else operation
        if op_raw is not None:
            self.target_operation = _coerce_remediation_operation(
                op_raw, "target_operation"
            )
        else:
            self.target_operation = _default_operation_for_item(self.item_type)

        self.approval_status = _coerce_approval_status(
            approval_status, "approval_status"
        )

        if graduation_status is not None:
            self.graduation_status = _coerce_graduation_status(
                graduation_status, "graduation_status"
            )
        elif (
            self.approval_status is ApprovalStatus.EXEMPT
            or self.target_operation is RemediationOperation.EXEMPT_PROTECTED
            or exemption_reason is not None
        ):
            self.graduation_status = QuarantineGraduationStatus.EXEMPT_PROTECTED
        else:
            self.graduation_status = QuarantineGraduationStatus.ELIGIBLE

        if reviewed_by is not None:
            self.reviewed_by = _require_non_empty_str(
                reviewed_by, "reviewed_by"
            ).strip()
        else:
            self.reviewed_by = None

        self.review_note = review_note
        self.reviewed_at = _parse_optional_datetime(reviewed_at, "reviewed_at")
        self.exemption_reason = exemption_reason
        self.rationale = res_rationale
        self.proposed_at = res_proposed_at

        if resolved_action is None:
            action_type = (
                RemediationActionType.MARK_STALE_CANDIDATE
                if self.classification
                is ValidationClassification.STALE_LIKELY_UNUSED
                else RemediationActionType.FLAG_FOR_REVIEW
            )
            resolved_action = ProposedRemediationAction(
                action_type=action_type,
                site_id=self.site_id,
                item_type=self.item_type,
                item_id=self.item_id,
                name=self.name,
                classification=self.classification,
                confidence=self.confidence,
                rationale=self.rationale,
                proposed_at=self.proposed_at,
                dry_run=True,
            )
        self.action = resolved_action
        self._initial_action_snapshot = (
            self.action.site_id,
            self.action.item_type,
            self.action.item_id,
            self.action.name,
            self.action.classification,
            self.action.confidence,
            self.action.dry_run,
        )

    @property
    def operation(self) -> RemediationOperation:
        """Alias for target_operation."""
        return self.target_operation

    @operation.setter
    def operation(self, value: RemediationOperation | str) -> None:
        self.target_operation = _coerce_remediation_operation(value, "operation")

    def canonical_payload(self) -> dict[str, Any]:
        """Return deterministic dictionary of entry fields covered by the SHA-256 manifest digest."""
        init_snap = getattr(self, "_initial_action_snapshot", None)
        site_id = self.site_id
        item_type = self.item_type
        item_id = self.item_id
        name = self.name
        classification = self.classification
        confidence = self.confidence
        dry_run = self.dry_run

        if init_snap is not None and hasattr(self, "action") and self.action is not None:
            if self.action.site_id != init_snap[0] and site_id == init_snap[0]:
                site_id = self.action.site_id
            if self.action.item_type != init_snap[1] and item_type == init_snap[1]:
                item_type = self.action.item_type
            if self.action.item_id != init_snap[2] and item_id == init_snap[2]:
                item_id = self.action.item_id
            if self.action.name != init_snap[3] and name == init_snap[3]:
                name = self.action.name
            if self.action.classification != init_snap[4] and classification == init_snap[4]:
                classification = self.action.classification
            if self.action.confidence != init_snap[5] and confidence == init_snap[5]:
                confidence = self.action.confidence
            if self.action.dry_run != init_snap[6] and dry_run == init_snap[6]:
                dry_run = self.action.dry_run

        cls_val = (
            classification.value
            if isinstance(classification, Enum)
            else str(classification)
        )
        op_val = (
            self.target_operation.value
            if isinstance(self.target_operation, Enum)
            else str(self.target_operation)
        )
        grad_val = (
            self.graduation_status.value
            if isinstance(self.graduation_status, Enum)
            else str(self.graduation_status)
        )
        app_val = (
            self.approval_status.value
            if isinstance(self.approval_status, Enum)
            else str(self.approval_status)
        )

        return {
            "site_id": str(site_id),
            "item_type": str(item_type),
            "item_id": str(item_id),
            "name": str(name),
            "classification": cls_val,
            "confidence": round(float(confidence), 6),
            "consecutive_stale_runs": int(self.consecutive_stale_runs),
            "stale_duration_days": round(float(self.stale_duration_days), 6),
            "target_operation": op_val,
            "graduation_status": grad_val,
            "approval_status": app_val,
            "reviewed_by": self.reviewed_by,
            "review_note": self.review_note,
            "exemption_reason": self.exemption_reason,
            "dry_run": bool(dry_run),
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self.canonical_payload()
        payload.update(
            {
                "reviewed_at": _format_optional_datetime(self.reviewed_at),
                "rationale": self.rationale,
                "proposed_at": _format_optional_datetime(self.proposed_at),
                "action": self.action.to_dict(),
            }
        )
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> QuarantineManifestEntry:
        raw_action = data.get("action")
        action_obj = (
            raw_action
            if isinstance(raw_action, ProposedRemediationAction) or raw_action is None
            else ProposedRemediationAction.from_dict(raw_action)
        )
        raw_streak = data.get("streak")
        streak_obj = (
            raw_streak
            if isinstance(raw_streak, ItemStreakSummary) or raw_streak is None
            else ItemStreakSummary.from_dict(raw_streak)
        )
        return cls(
            action=action_obj,
            streak=streak_obj,
            site_id=data.get("site_id"),
            item_type=data.get("item_type"),
            item_id=data.get("item_id"),
            name=data.get("name"),
            classification=data.get("classification"),
            confidence=(
                float(data["confidence"])
                if data.get("confidence") is not None
                else None
            ),
            consecutive_stale_runs=(
                int(data["consecutive_stale_runs"])
                if data.get("consecutive_stale_runs") is not None
                else None
            ),
            stale_duration_days=(
                float(data["stale_duration_days"])
                if data.get("stale_duration_days") is not None
                else None
            ),
            target_operation=data.get("target_operation") or data.get("operation"),
            graduation_status=data.get("graduation_status"),
            approval_status=data.get("approval_status", ApprovalStatus.PENDING),
            reviewed_by=data.get("reviewed_by") or None,
            review_note=data.get("review_note") or None,
            reviewed_at=data.get("reviewed_at") or None,
            exemption_reason=data.get("exemption_reason") or None,
            rationale=data.get("rationale") or None,
            proposed_at=data.get("proposed_at") or None,
            dry_run=data.get("dry_run", True),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> QuarantineManifestEntry:
        return cls.from_dict(json.loads(raw))
