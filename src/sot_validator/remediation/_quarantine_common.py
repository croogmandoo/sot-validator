"""Quarantine approval/operation/graduation enums and shared coercion helpers."""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum
import ipaddress
import re
from typing import Any, Optional

from sot_validator.models import EquipmentCategory


class ApprovalStatus(str, Enum):
    """Operator review and approval states for quarantine manifest entries."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXEMPT = "EXEMPT"
    EXEMPT_PROTECTED = "EXEMPT"


class RemediationOperation(str, Enum):
    """Target Phase 2 remediation operations for quarantined inventory records."""

    FLAG_STALE_IN_SOT = "FLAG_STALE_IN_SOT"
    RECLAIM_STALE_IP = "RECLAIM_STALE_IP"
    DECOMMISSION_VM_RECORD = "DECOMMISSION_VM_RECORD"
    PROPOSE_PORT_SHUTDOWN = "PROPOSE_PORT_SHUTDOWN"
    EXEMPT_PROTECTED = "EXEMPT_PROTECTED"


class QuarantineGraduationStatus(str, Enum):
    """Quarantine policy evaluation outcome for a stale inventory candidate."""

    ELIGIBLE = "ELIGIBLE"
    EXEMPT_PROTECTED = "EXEMPT_PROTECTED"
    BELOW_THRESHOLD = "BELOW_THRESHOLD"


def _coerce_approval_status(
    value: ApprovalStatus | str, field_name: str = "approval_status"
) -> ApprovalStatus:
    if isinstance(value, ApprovalStatus):
        return value
    if isinstance(value, str):
        cleaned = value.strip().upper()
        if cleaned == "EXEMPT_PROTECTED":
            return ApprovalStatus.EXEMPT
        try:
            return ApprovalStatus(cleaned)
        except ValueError as exc:
            raise ValueError(f"Invalid {field_name}: {value!r}") from exc
    raise ValueError(f"Invalid {field_name}: {value!r}")


def _coerce_remediation_operation(
    value: RemediationOperation | str, field_name: str = "target_operation"
) -> RemediationOperation:
    if isinstance(value, RemediationOperation):
        return value
    if isinstance(value, str):
        cleaned = value.strip().upper()
        try:
            return RemediationOperation(cleaned)
        except ValueError as exc:
            raise ValueError(f"Invalid {field_name}: {value!r}") from exc
    raise ValueError(f"Invalid {field_name}: {value!r}")


def _coerce_graduation_status(
    value: QuarantineGraduationStatus | str,
    field_name: str = "graduation_status",
) -> QuarantineGraduationStatus:
    if isinstance(value, QuarantineGraduationStatus):
        return value
    if isinstance(value, str):
        cleaned = value.strip().upper()
        if cleaned == "EXEMPT":
            return QuarantineGraduationStatus.EXEMPT_PROTECTED
        try:
            return QuarantineGraduationStatus(cleaned)
        except ValueError as exc:
            raise ValueError(f"Invalid {field_name}: {value!r}") from exc
    raise ValueError(f"Invalid {field_name}: {value!r}")


def _normalize_string_tuple(
    values: Optional[Iterable[Any]],
    field_name: str,
    *,
    lowercase: bool = False,
) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{field_name} must be an iterable of strings, not a single string")
    result: list[str] = []
    seen: set[str] = set()
    for raw in values:
        if isinstance(raw, Enum):
            raw_str = str(raw.value)
        elif isinstance(raw, str):
            raw_str = raw
        else:
            raise ValueError(f"{field_name} entries must be strings")
        cleaned = raw_str.strip()
        if not cleaned:
            raise ValueError(f"{field_name} entries must be non-empty strings")
        if lowercase:
            cleaned = cleaned.lower()
        if cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return tuple(result)


def _normalize_subnets_tuple(
    values: Optional[Iterable[Any]],
    field_name: str = "protected_subnets",
) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{field_name} must be an iterable of CIDR strings")
    result: list[str] = []
    seen: set[str] = set()
    for raw in values:
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError(f"{field_name} entries must be non-empty CIDR strings")
        try:
            net = ipaddress.ip_network(raw.strip(), strict=False)
        except ValueError as exc:
            raise ValueError(
                f"Invalid subnet CIDR in {field_name}: {raw!r}"
            ) from exc
        cidr_str = str(net)
        if cidr_str not in seen:
            seen.add(cidr_str)
            result.append(cidr_str)
    return tuple(result)


def _canonical_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _word_tokens(value: str) -> set[str]:
    return {tok for tok in re.split(r"[^a-z0-9]+", value.lower()) if tok}


def _default_operation_for_item(
    item_type: str,
    *,
    category: Optional[EquipmentCategory | str] = None,
    is_vm: bool = False,
) -> RemediationOperation:
    norm_type = _canonical_token(item_type)
    if norm_type in ("ipaddress", "ip"):
        return RemediationOperation.RECLAIM_STALE_IP
    if norm_type == "port":
        return RemediationOperation.PROPOSE_PORT_SHUTDOWN
    if is_vm or norm_type in ("vm", "virtualmachine"):
        return RemediationOperation.DECOMMISSION_VM_RECORD
    if category is not None:
        cat_val = category.value if isinstance(category, Enum) else str(category)
        if _canonical_token(cat_val) in ("vm", "virtualmachine"):
            return RemediationOperation.DECOMMISSION_VM_RECORD
    return RemediationOperation.FLAG_STALE_IN_SOT
