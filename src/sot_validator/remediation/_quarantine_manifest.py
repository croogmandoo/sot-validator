"""SHA-256 signed remediation approval manifest with JSON/CSV import and export."""

from __future__ import annotations

from collections.abc import Mapping
import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
import io
import json
from pathlib import Path
from typing import Any, Optional
import uuid

from sot_validator.models import (
    ValidationClassification,
    _format_optional_datetime,
    _require_non_empty_str,
)
from sot_validator.remediation._quarantine_common import (
    ApprovalStatus,
    QuarantineGraduationStatus,
    RemediationOperation,
    _coerce_approval_status,
    _default_operation_for_item,
)
from sot_validator.remediation._quarantine_policy import (
    QuarantineManifestEntry,
    QuarantinePolicy,
)
from sot_validator.remediation.sink import (
    _enforce_dry_run_only,
    _resolve_plan_timestamp,
)


class _HybridManifestMethod:
    """Descriptor allowing import_json / import_csv to be called on class or instance."""

    def __init__(self, func: Any) -> None:
        self._func = func

    def __get__(self, instance: Any, owner: Any = None) -> Any:
        target = owner if instance is None else instance

        def _bound(*args: Any, **kwargs: Any) -> RemediationApprovalManifest:
            return self._func(target, *args, **kwargs)

        return _bound


_CSV_FIELDNAMES: tuple[str, ...] = (
    "site_id",
    "item_type",
    "item_id",
    "name",
    "classification",
    "confidence",
    "consecutive_stale_runs",
    "stale_duration_days",
    "target_operation",
    "graduation_status",
    "approval_status",
    "reviewed_by",
    "review_note",
    "reviewed_at",
    "exemption_reason",
    "rationale",
    "proposed_at",
    "dry_run",
)


@dataclass
class RemediationApprovalManifest:
    """Operator-reviewable Phase 2 quarantine manifest with SHA-256 integrity verification."""

    entries: list[QuarantineManifestEntry] = field(default_factory=list)
    policy: QuarantinePolicy = field(default_factory=QuarantinePolicy)
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    manifest_id: str = field(
        default_factory=lambda: f"manifest-{uuid.uuid4().hex[:12]}"
    )
    dry_run: bool = True
    manifest_sha256: str = ""

    def __post_init__(self) -> None:
        self.dry_run = _enforce_dry_run_only(
            self.dry_run, "RemediationApprovalManifest"
        )
        if not isinstance(self.policy, QuarantinePolicy):
            if isinstance(self.policy, Mapping):
                self.policy = QuarantinePolicy.from_dict(self.policy)
            else:
                raise ValueError("policy must be a QuarantinePolicy instance")
        self.generated_at = _resolve_plan_timestamp(self.generated_at)
        _require_non_empty_str(self.manifest_id, "manifest_id")
        self.entries = [
            e
            if isinstance(e, QuarantineManifestEntry)
            else QuarantineManifestEntry.from_dict(e)
            for e in self.entries
        ]
        if not self.manifest_sha256:
            self.manifest_sha256 = self.compute_digest()

    @property
    def eligible_entries(self) -> list[QuarantineManifestEntry]:
        """Return entries that graduated as ELIGIBLE for remediation."""
        return [
            e
            for e in self.entries
            if e.graduation_status is QuarantineGraduationStatus.ELIGIBLE
        ]

    @property
    def exempt_entries(self) -> list[QuarantineManifestEntry]:
        """Return entries marked EXEMPT_PROTECTED / EXEMPT."""
        return [
            e
            for e in self.entries
            if e.graduation_status is QuarantineGraduationStatus.EXEMPT_PROTECTED
            or e.approval_status is ApprovalStatus.EXEMPT
        ]

    @property
    def approved_entries(self) -> list[QuarantineManifestEntry]:
        """Return entries with ApprovalStatus.APPROVED."""
        return [
            e
            for e in self.entries
            if e.approval_status is ApprovalStatus.APPROVED
        ]

    @property
    def pending_entries(self) -> list[QuarantineManifestEntry]:
        """Return entries with ApprovalStatus.PENDING."""
        return [
            e
            for e in self.entries
            if e.approval_status is ApprovalStatus.PENDING
        ]

    @property
    def rejected_entries(self) -> list[QuarantineManifestEntry]:
        """Return entries with ApprovalStatus.REJECTED."""
        return [
            e
            for e in self.entries
            if e.approval_status is ApprovalStatus.REJECTED
        ]

    @property
    def summary_by_status(self) -> dict[str, int]:
        counts: dict[str, int] = {
            ApprovalStatus.PENDING.value: 0,
            ApprovalStatus.APPROVED.value: 0,
            ApprovalStatus.REJECTED.value: 0,
            ApprovalStatus.EXEMPT.value: 0,
        }
        for entry in self.entries:
            status_val = (
                entry.approval_status.value
                if isinstance(entry.approval_status, Enum)
                else str(entry.approval_status)
            )
            counts[status_val] = counts.get(status_val, 0) + 1
        return counts

    @property
    def summary_by_operation(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entry in self.entries:
            op_val = (
                entry.target_operation.value
                if isinstance(entry.target_operation, Enum)
                else str(entry.target_operation)
            )
            counts[op_val] = counts.get(op_val, 0) + 1
        return counts

    def canonical_entries_payload(self) -> list[dict[str, Any]]:
        """Return deterministically sorted canonical entry payloads for hashing."""
        payloads = [entry.canonical_payload() for entry in self.entries]
        payloads.sort(
            key=lambda p: (
                p["site_id"],
                p["item_type"],
                p["item_id"],
                p["target_operation"],
                p["approval_status"],
            )
        )
        return payloads

    def compute_digest(self) -> str:
        """Compute deterministic SHA-256 hex digest over canonical JSON of manifest entries."""
        serialized = json.dumps(
            self.canonical_entries_payload(),
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def update_digest(self) -> str:
        """Recompute and update manifest_sha256 in place."""
        self.manifest_sha256 = self.compute_digest()
        return self.manifest_sha256

    def recompute_digest(self) -> str:
        """Alias for update_digest()."""
        return self.update_digest()

    def verify_digest(self) -> bool:
        """Return True iff manifest_sha256 matches the freshly computed canonical SHA-256 digest."""
        if not isinstance(self.manifest_sha256, str) or not self.manifest_sha256:
            return False
        try:
            expected = self.compute_digest()
        except Exception:
            return False
        return hmac.compare_digest(self.manifest_sha256, expected)

    def get_entry(
        self, item_id: str, *, item_type: Optional[str] = None
    ) -> Optional[QuarantineManifestEntry]:
        """Find a manifest entry by item_id (and optional item_type)."""
        for entry in self.entries:
            if entry.item_id == item_id and (
                item_type is None or entry.item_type == item_type
            ):
                return entry
        return None

    def approve_all(
        self, reviewer: str, note: Optional[str] = None
    ) -> RemediationApprovalManifest:
        """Approve all non-exempt entries, record reviewer metadata, and recompute digest."""
        clean_reviewer = _require_non_empty_str(reviewer, "reviewer").strip()
        now = datetime.now(timezone.utc)
        for entry in self.entries:
            if (
                entry.approval_status is ApprovalStatus.EXEMPT
                or entry.graduation_status
                is QuarantineGraduationStatus.EXEMPT_PROTECTED
            ):
                entry.approval_status = ApprovalStatus.EXEMPT
                continue
            entry.approval_status = ApprovalStatus.APPROVED
            entry.reviewed_by = clean_reviewer
            if note is not None:
                entry.review_note = note
            entry.reviewed_at = now
        self.update_digest()
        return self

    def set_entry_decision(
        self,
        item_id: str,
        status: ApprovalStatus | str,
        reviewer: Optional[str] = None,
        note: Optional[str] = None,
        *,
        item_type: Optional[str] = None,
        allow_exempt_override: bool = False,
    ) -> QuarantineManifestEntry:
        """Set approval decision for a specific entry and recompute manifest_sha256."""
        target_status = _coerce_approval_status(status, "status")
        clean_reviewer = (
            _require_non_empty_str(reviewer, "reviewer").strip()
            if reviewer is not None
            else None
        )

        entry = self.get_entry(item_id, item_type=item_type)
        if entry is None:
            raise KeyError(
                f"Manifest entry for item_id={item_id!r} not found in manifest"
            )

        is_exempt = (
            entry.graduation_status
            is QuarantineGraduationStatus.EXEMPT_PROTECTED
            or entry.approval_status is ApprovalStatus.EXEMPT
        )
        if is_exempt and target_status is ApprovalStatus.APPROVED:
            if not (allow_exempt_override or self.policy.allow_protected_override):
                raise ValueError(
                    f"Cannot approve EXEMPT_PROTECTED item {item_id!r} without explicit override"
                )
            entry.graduation_status = QuarantineGraduationStatus.ELIGIBLE
            if entry.target_operation is RemediationOperation.EXEMPT_PROTECTED:
                entry.target_operation = _default_operation_for_item(
                    entry.item_type
                )

        entry.approval_status = target_status
        if clean_reviewer is not None:
            entry.reviewed_by = clean_reviewer
        if note is not None:
            entry.review_note = note
        entry.reviewed_at = datetime.now(timezone.utc)
        self.update_digest()
        return entry

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_id": self.manifest_id,
            "generated_at": _format_optional_datetime(self.generated_at),
            "dry_run": self.dry_run,
            "manifest_sha256": self.manifest_sha256,
            "policy": self.policy.to_dict(),
            "total_entries": len(self.entries),
            "summary_by_status": self.summary_by_status,
            "summary_by_operation": self.summary_by_operation,
            "entries": [e.to_dict() for e in self.entries],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RemediationApprovalManifest:
        dry_run_val = data.get("dry_run", True)
        _enforce_dry_run_only(dry_run_val, "RemediationApprovalManifest")
        raw_policy = data.get("policy")
        policy = (
            raw_policy
            if isinstance(raw_policy, QuarantinePolicy)
            else (
                QuarantinePolicy.from_dict(raw_policy)
                if isinstance(raw_policy, Mapping)
                else QuarantinePolicy()
            )
        )
        entries = [
            e
            if isinstance(e, QuarantineManifestEntry)
            else QuarantineManifestEntry.from_dict(e)
            for e in data.get("entries", [])
        ]
        manifest_id = data.get("manifest_id") or f"manifest-{uuid.uuid4().hex[:12]}"
        stored_digest = data.get("manifest_sha256")
        instance = cls(
            entries=entries,
            policy=policy,
            generated_at=_resolve_plan_timestamp(data.get("generated_at")),
            manifest_id=manifest_id,
            dry_run=dry_run_val,
            manifest_sha256=stored_digest if stored_digest is not None else "",
        )
        if stored_digest is not None:
            instance.manifest_sha256 = str(stored_digest)
        return instance

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> RemediationApprovalManifest:
        return cls.from_dict(json.loads(raw))

    def export_json(self, path: Optional[Path | str] = None) -> str:
        """Serialize manifest to JSON string and optionally write to path."""
        payload = self.to_json(indent=2)
        if path is not None:
            target = Path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(payload, encoding="utf-8")
        return payload

    def _import_json_impl(
        target: Any, path_or_raw: Path | str
    ) -> RemediationApprovalManifest:
        if isinstance(path_or_raw, Path):
            raw_text = path_or_raw.read_text(encoding="utf-8")
        elif isinstance(path_or_raw, str):
            stripped = path_or_raw.lstrip()
            if stripped.startswith("{"):
                raw_text = path_or_raw
            else:
                raw_text = Path(path_or_raw).read_text(encoding="utf-8")
        else:
            raise ValueError("path_or_raw must be a Path or JSON string")

        loaded = RemediationApprovalManifest.from_json(raw_text)
        if isinstance(target, RemediationApprovalManifest):
            target.entries = loaded.entries
            target.policy = loaded.policy
            target.generated_at = loaded.generated_at
            target.manifest_id = loaded.manifest_id
            target.dry_run = loaded.dry_run
            target.manifest_sha256 = loaded.manifest_sha256
        return loaded

    import_json = _HybridManifestMethod(_import_json_impl)

    def export_csv(self, path: Optional[Path | str] = None) -> str:
        """Export manifest entries to CSV format and optionally write to path."""
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf, fieldnames=list(_CSV_FIELDNAMES), lineterminator="\n"
        )
        writer.writeheader()
        for entry in self.entries:
            writer.writerow(
                {
                    "site_id": entry.site_id,
                    "item_type": entry.item_type,
                    "item_id": entry.item_id,
                    "name": entry.name,
                    "classification": entry.classification.value,
                    "confidence": entry.confidence,
                    "consecutive_stale_runs": entry.consecutive_stale_runs,
                    "stale_duration_days": entry.stale_duration_days,
                    "target_operation": entry.target_operation.value,
                    "graduation_status": entry.graduation_status.value,
                    "approval_status": entry.approval_status.value,
                    "reviewed_by": entry.reviewed_by or "",
                    "review_note": entry.review_note or "",
                    "reviewed_at": _format_optional_datetime(entry.reviewed_at) or "",
                    "exemption_reason": entry.exemption_reason or "",
                    "rationale": entry.rationale or "",
                    "proposed_at": _format_optional_datetime(entry.proposed_at) or "",
                    "dry_run": str(entry.dry_run),
                }
            )
        csv_text = buf.getvalue()
        if path is not None:
            target = Path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(csv_text, encoding="utf-8")
        return csv_text

    def _import_csv_impl(
        target: Any,
        path_or_raw: Path | str,
        *,
        policy: Optional[QuarantinePolicy] = None,
        manifest_sha256: Optional[str] = None,
    ) -> RemediationApprovalManifest:
        if isinstance(path_or_raw, Path):
            raw_csv = path_or_raw.read_text(encoding="utf-8")
        elif isinstance(path_or_raw, str):
            first_line = path_or_raw.splitlines()[0] if path_or_raw else ""
            if "\n" in path_or_raw or "\r" in path_or_raw or "," in first_line:
                raw_csv = path_or_raw
            else:
                raw_csv = Path(path_or_raw).read_text(encoding="utf-8")
        else:
            raise ValueError("path_or_raw must be a Path or CSV string")

        reader = csv.DictReader(io.StringIO(raw_csv))
        entries: list[QuarantineManifestEntry] = []
        for row in reader:
            raw_dry = (row.get("dry_run") or "True").strip().lower()
            dry_run_val = raw_dry in ("true", "1", "yes")
            entries.append(
                QuarantineManifestEntry(
                    site_id=row["site_id"],
                    item_type=row["item_type"],
                    item_id=row["item_id"],
                    name=row.get("name") or row["item_id"],
                    classification=row.get(
                        "classification",
                        ValidationClassification.STALE_LIKELY_UNUSED.value,
                    ),
                    confidence=float(row.get("confidence") or 0.0),
                    consecutive_stale_runs=int(
                        row.get("consecutive_stale_runs") or 0
                    ),
                    stale_duration_days=float(
                        row.get("stale_duration_days") or 0.0
                    ),
                    target_operation=row.get("target_operation")
                    or row.get("operation"),
                    graduation_status=row.get("graduation_status") or None,
                    approval_status=row.get(
                        "approval_status", ApprovalStatus.PENDING.value
                    ),
                    reviewed_by=row.get("reviewed_by") or None,
                    review_note=row.get("review_note") or None,
                    reviewed_at=row.get("reviewed_at") or None,
                    exemption_reason=row.get("exemption_reason") or None,
                    rationale=row.get("rationale") or None,
                    proposed_at=row.get("proposed_at") or None,
                    dry_run=dry_run_val,
                )
            )

        resolved_policy = policy
        if resolved_policy is None:
            if isinstance(target, RemediationApprovalManifest):
                resolved_policy = target.policy
            else:
                resolved_policy = QuarantinePolicy()

        loaded = RemediationApprovalManifest(
            entries=entries,
            policy=resolved_policy,
            manifest_sha256=manifest_sha256 if manifest_sha256 is not None else "",
        )
        if manifest_sha256 is not None:
            loaded.manifest_sha256 = manifest_sha256
        if isinstance(target, RemediationApprovalManifest):
            target.entries = loaded.entries
            target.policy = loaded.policy
            target.manifest_sha256 = loaded.manifest_sha256
        return loaded

    import_csv = _HybridManifestMethod(_import_csv_impl)
