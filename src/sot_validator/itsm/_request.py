"""Artifact SHA-256 digests, deterministic ticket ids and the ItsmTicketRequest dataclass."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Optional

from sot_validator.itsm._enums import (
    ItsmProvider,
    ItsmWorkflowType,
    TicketApprovalStatus,
    _coerce_priority,
    _coerce_provider,
    _coerce_risk,
    _coerce_ticket_approval_status,
    _coerce_workflow_type,
    _normalize_str_list,
)
from sot_validator.models import (
    _format_optional_datetime,
    _parse_optional_datetime,
    _require_non_empty_str,
)
from sot_validator.reconciliation.reconciler import ReconciliationReport
from sot_validator.remediation.port_reclamation import PortReclamationPlan
from sot_validator.remediation.quarantine import RemediationApprovalManifest
from sot_validator.signals.base import normalize_utc_datetime
from sot_validator.signals.ups_health import UpsFleetHealthReport, UpsHealthRecord


# Compatibility alias for callers referencing QuarantineReport.
QuarantineReport = RemediationApprovalManifest


def compute_artifact_sha256(
    artifact: (
        RemediationApprovalManifest
        | PortReclamationPlan
        | ReconciliationReport
        | UpsFleetHealthReport
        | UpsHealthRecord
        | Mapping[str, Any]
        | str
    ),
) -> str:
    """Compute or extract a deterministic SHA-256 hex digest for a remediation plan or report."""
    if isinstance(artifact, RemediationApprovalManifest):
        if artifact.manifest_sha256 and len(artifact.manifest_sha256.strip()) == 64:
            return artifact.manifest_sha256.strip().lower()
        return artifact.compute_digest()

    if isinstance(artifact, PortReclamationPlan):
        canonical_candidates = sorted(
            (
                {
                    "port_id": c.port_id,
                    "device_id": c.device_id,
                    "port_name": c.port_name,
                    "site_id": c.site_id,
                    "device_hostname": c.device_hostname,
                    "inactive_runs": c.inactive_runs,
                    "inactive_days": round(float(c.inactive_days), 4),
                    "estimated_poe_watts_saved": round(
                        float(c.estimated_poe_watts_saved), 2
                    ),
                    "exos_disable_commands": list(c.exos_disable_commands),
                    "exos_rollback_commands": list(c.exos_rollback_commands),
                    "exos_rollback_command": c.exos_rollback_command,
                    "voss_disable_commands": list(c.voss_disable_commands),
                    "voss_rollback_commands": list(c.voss_rollback_commands),
                    "voss_rollback_command": c.voss_rollback_command,
                }
                for c in artifact.candidates
            ),
            key=lambda item: (
                str(item["site_id"] or ""),
                str(item["device_id"]),
                str(item["port_id"]),
            ),
        )
        canonical_blocked = sorted(
            (
                {
                    "port_id": b.port_id,
                    "device_id": b.device_id,
                    "port_name": b.port_name,
                    "site_id": b.site_id,
                    "block_reason": b.block_reason,
                    "matched_rules": list(b.matched_rules),
                }
                for b in artifact.blocked_ports
            ),
            key=lambda item: (
                str(item["site_id"] or ""),
                str(item["device_id"]),
                str(item["port_id"]),
            ),
        )
        canonical_payload = {
            "dialect": artifact.dialect.value,
            "min_inactive_runs": artifact.min_inactive_runs,
            "min_inactive_days": round(float(artifact.min_inactive_days), 4),
            "estimated_poe_watts_saved": round(
                float(artifact.estimated_poe_watts_saved), 2
            ),
            "candidates": canonical_candidates,
            "blocked_ports": canonical_blocked,
            "exos_commands": list(artifact.exos_commands),
            "exos_rollback_commands": list(artifact.exos_rollback_commands),
            "voss_commands": list(artifact.voss_commands),
            "voss_rollback_commands": list(artifact.voss_rollback_commands),
        }
        serialized = json.dumps(
            canonical_payload, sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    if isinstance(artifact, ReconciliationReport):
        canonical_discrepancies = sorted(
            (d.to_dict() for d in artifact.discrepancies),
            key=lambda item: (
                str(item.get("site_id") or ""),
                str(item.get("discrepancy_type") or ""),
                str(item.get("discrepancy_id") or ""),
            ),
        )
        serialized = json.dumps(
            canonical_discrepancies, sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    if isinstance(artifact, UpsFleetHealthReport):
        canonical_records = sorted(
            (
                {
                    "equipment_id": r.equipment_id,
                    "site_id": r.site_id,
                    "name": r.name,
                    "status": r.status.value,
                    "advisories": sorted(r.advisories),
                    "needs_battery_replacement": r.needs_battery_replacement,
                    "on_battery": r.on_battery,
                    "is_low_runtime": r.is_low_runtime,
                    "is_high_temperature": r.is_high_temperature,
                    "is_high_load": r.is_high_load,
                }
                for r in artifact.records
            ),
            key=lambda item: (item["site_id"], item["equipment_id"]),
        )
        serialized = json.dumps(
            canonical_records, sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    if isinstance(artifact, UpsHealthRecord):
        payload = {
            "equipment_id": artifact.equipment_id,
            "site_id": artifact.site_id,
            "name": artifact.name,
            "status": artifact.status.value,
            "advisories": sorted(artifact.advisories),
            "needs_battery_replacement": artifact.needs_battery_replacement,
            "on_battery": artifact.on_battery,
        }
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    if isinstance(artifact, str):
        cleaned = artifact.strip()
        if len(cleaned) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in cleaned):
            return cleaned.lower()
        return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()

    if isinstance(artifact, Mapping):
        for digest_key in (
            "artifact_sha256",
            "manifest_sha256",
            "plan_sha256",
            "u_artifact_sha256",
            "sha256",
        ):
            raw_digest = artifact.get(digest_key)
            if isinstance(raw_digest, str) and raw_digest.strip():
                return raw_digest.strip().lower()
        if "entries" in artifact and (
            "manifest_id" in artifact or "policy" in artifact
        ):
            return compute_artifact_sha256(
                RemediationApprovalManifest.from_dict(artifact)
            )
        if "candidates" in artifact or "blocked_ports" in artifact or "plan_id" in artifact:
            return compute_artifact_sha256(PortReclamationPlan.from_dict(artifact))
        if "discrepancies" in artifact:
            return compute_artifact_sha256(ReconciliationReport.from_dict(artifact))
        if "records" in artifact and (
            "critical_count" in artifact or "battery_replacement_units" in artifact
        ):
            return compute_artifact_sha256(UpsFleetHealthReport.from_dict(artifact))
        serialized = json.dumps(
            dict(artifact), sort_keys=True, separators=(",", ":"), default=str
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    raise TypeError(
        f"Unsupported artifact type for SHA-256 computation: {type(artifact)!r}"
    )


def _deterministic_ticket_id(
    prefix: str,
    workflow_type: ItsmWorkflowType,
    seed: str,
) -> str:
    digest = hashlib.sha256(
        f"{workflow_type.value}:{seed}".encode("utf-8")
    ).hexdigest()[:8].upper()
    return f"{prefix}-{digest}"


@dataclass
class ItsmTicketRequest:
    """Provider-agnostic ITSM change request, onboarding task, or hardware incident ticket."""

    ticket_id: str
    workflow_type: ItsmWorkflowType
    title: str
    description: str
    category: str = "Network Source of Truth"
    risk: str = "moderate"
    priority: str = "Medium"
    implementation_plan: str = ""
    backout_plan: str = ""
    cmdb_ci: str = "sot-inventory"
    affected_cis: list[str] = field(default_factory=list)
    site_ids: list[str] = field(default_factory=list)
    item_ids: list[str] = field(default_factory=list)
    artifact_id: Optional[str] = None
    artifact_sha256: Optional[str] = None
    approval_status: TicketApprovalStatus = TicketApprovalStatus.PENDING
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    labels: list[str] = field(default_factory=list)
    project_key: str = "NETOPS"
    issue_type: str = "Change"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    dry_run: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.ticket_id = _require_non_empty_str(self.ticket_id, "ticket_id").strip()
        self.workflow_type = _coerce_workflow_type(
            self.workflow_type, "workflow_type"
        )
        self.title = _require_non_empty_str(self.title, "title").strip()
        self.description = _require_non_empty_str(
            self.description, "description"
        ).strip()
        self.category = _require_non_empty_str(self.category, "category").strip()
        self.risk = _coerce_risk(self.risk)
        self.priority = _coerce_priority(self.priority)
        self.implementation_plan = _require_non_empty_str(
            self.implementation_plan, "implementation_plan"
        ).strip()
        self.backout_plan = _require_non_empty_str(
            self.backout_plan, "backout_plan"
        ).strip()
        self.cmdb_ci = _require_non_empty_str(self.cmdb_ci, "cmdb_ci").strip()

        self.affected_cis = _normalize_str_list(self.affected_cis)
        if self.cmdb_ci not in self.affected_cis:
            self.affected_cis.insert(0, self.cmdb_ci)

        self.site_ids = _normalize_str_list(self.site_ids)
        self.item_ids = _normalize_str_list(self.item_ids)

        if self.artifact_id is not None:
            cleaned_art = str(self.artifact_id).strip()
            self.artifact_id = cleaned_art if cleaned_art else None

        if self.artifact_sha256 is not None:
            cleaned_sha = str(self.artifact_sha256).strip().lower()
            self.artifact_sha256 = cleaned_sha if cleaned_sha else None

        self.approval_status = _coerce_ticket_approval_status(
            self.approval_status, "approval_status"
        )
        if self.approved_by is not None:
            cleaned_by = str(self.approved_by).strip()
            self.approved_by = cleaned_by if cleaned_by else None

        if self.approved_at is not None:
            self.approved_at = normalize_utc_datetime(
                self.approved_at, field_name="approved_at"
            )

        self.labels = _normalize_str_list(self.labels)
        if "sot-validator" not in self.labels:
            self.labels.insert(0, "sot-validator")

        self.project_key = _require_non_empty_str(
            self.project_key, "project_key"
        ).strip()
        self.issue_type = _require_non_empty_str(
            self.issue_type, "issue_type"
        ).strip()

        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)
        else:
            self.created_at = normalize_utc_datetime(
                self.created_at, field_name="created_at"
            )

        if not isinstance(self.dry_run, bool):
            raise ValueError("dry_run must be a boolean")

        if self.metadata is None:
            self.metadata = {}
        elif isinstance(self.metadata, Mapping):
            self.metadata = dict(self.metadata)
        else:
            raise ValueError("metadata must be a mapping")

    @property
    def short_description(self) -> str:
        """ServiceNow alias for title."""
        return self.title

    @property
    def summary(self) -> str:
        """Jira alias for title."""
        return self.title

    @property
    def rollback_plan(self) -> str:
        """Alias for backout_plan."""
        return self.backout_plan

    @property
    def cmdb_cis(self) -> list[str]:
        """Alias for affected_cis."""
        return self.affected_cis

    @property
    def manifest_sha256(self) -> Optional[str]:
        """Alias for artifact_sha256."""
        return self.artifact_sha256

    @property
    def plan_sha256(self) -> Optional[str]:
        """Alias for artifact_sha256."""
        return self.artifact_sha256

    @property
    def sha256(self) -> Optional[str]:
        """Alias for artifact_sha256."""
        return self.artifact_sha256

    @property
    def is_approved(self) -> bool:
        """Return True if approval_status is APPROVED."""
        return self.approval_status is TicketApprovalStatus.APPROVED

    def to_servicenow_payload(self) -> dict[str, Any]:
        """Format this ticket request as a ServiceNow change_request / incident payload dictionary."""
        snow_table = (
            "incident"
            if self.workflow_type is ItsmWorkflowType.UPS_HARDWARE_INCIDENT
            else "change_request"
        )
        desc_lines = [self.description]
        if self.artifact_sha256 and self.artifact_sha256 not in self.description:
            desc_lines.append(f"Artifact SHA-256: {self.artifact_sha256}")
        full_description = "\n\n".join(desc_lines)

        return {
            "ticket_id": self.ticket_id,
            "table": snow_table,
            "short_description": self.title,
            "description": full_description,
            "category": self.category,
            "risk": self.risk,
            "priority": self.priority,
            "implementation_plan": self.implementation_plan,
            "backout_plan": self.backout_plan,
            "cmdb_ci": self.cmdb_ci,
            "approval": self.approval_status.value.lower(),
            "approval_status": self.approval_status.value,
            "u_workflow_type": self.workflow_type.value,
            "u_artifact_id": self.artifact_id,
            "u_artifact_sha256": self.artifact_sha256,
            "u_site_ids": list(self.site_ids),
            "u_item_ids": list(self.item_ids),
            "u_affected_cis": list(self.affected_cis),
            "u_dry_run": self.dry_run,
        }

    def to_jira_payload(self, project_key: Optional[str] = None) -> dict[str, Any]:
        """Format this ticket request as a Jira issue creation payload dictionary."""
        resolved_project_key = (
            _require_non_empty_str(project_key, "project_key").strip()
            if project_key is not None
            else self.project_key
        )
        jira_description_sections = [
            self.description,
            f"h3. Implementation Plan\n{self.implementation_plan}",
            f"h3. Backout / Rollback Plan\n{self.backout_plan}",
            f"*Primary CMDB CI:* {self.cmdb_ci}\n*Category:* {self.category}\n*Risk:* {self.risk}",
        ]
        if self.artifact_id:
            jira_description_sections.append(f"*Artifact ID:* {self.artifact_id}")
        if self.artifact_sha256:
            jira_description_sections.append(
                f"*Artifact SHA-256:* {self.artifact_sha256}"
            )
        jira_description = "\n\n".join(jira_description_sections)

        project_obj = {"key": resolved_project_key}
        issuetype_obj = {"name": self.issue_type}
        priority_obj = {"name": self.priority}
        labels_list = list(self.labels)

        fields_dict: dict[str, Any] = {
            "project": dict(project_obj),
            "summary": self.title,
            "description": jira_description,
            "issuetype": dict(issuetype_obj),
            "priority": dict(priority_obj),
            "labels": list(labels_list),
            "ticket_id": self.ticket_id,
            "workflow_type": self.workflow_type.value,
            "approval_status": self.approval_status.value,
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "cmdb_ci": self.cmdb_ci,
            "site_ids": list(self.site_ids),
            "item_ids": list(self.item_ids),
            "implementation_plan": self.implementation_plan,
            "backout_plan": self.backout_plan,
        }

        return {
            "ticket_id": self.ticket_id,
            "project": project_obj,
            "summary": self.title,
            "description": jira_description,
            "issuetype": issuetype_obj,
            "priority": priority_obj,
            "labels": labels_list,
            "approval_status": self.approval_status.value,
            "workflow_type": self.workflow_type.value,
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "cmdb_ci": self.cmdb_ci,
            "implementation_plan": self.implementation_plan,
            "backout_plan": self.backout_plan,
            "fields": fields_dict,
        }

    def to_webhook_payload(self) -> dict[str, Any]:
        """Format this ticket request as a generic ITSM webhook event payload."""
        return {
            "event_type": f"itsm.{self.workflow_type.value.lower()}",
            "ticket_id": self.ticket_id,
            "workflow_type": self.workflow_type.value,
            "approval_status": self.approval_status.value,
            "approved_by": self.approved_by,
            "approved_at": _format_optional_datetime(self.approved_at),
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "site_ids": list(self.site_ids),
            "item_ids": list(self.item_ids),
            "created_at": _format_optional_datetime(self.created_at),
            "dry_run": self.dry_run,
            "ticket": self.to_dict(),
            "servicenow": self.to_servicenow_payload(),
            "jira": self.to_jira_payload(),
        }

    def format_for_provider(
        self,
        provider: ItsmProvider | str = ItsmProvider.SERVICENOW,
        *,
        project_key: Optional[str] = None,
    ) -> dict[str, Any]:
        """Format this ticket request for the given ITSM provider ('servicenow', 'jira', 'webhook')."""
        coerced = _coerce_provider(provider, "provider")
        if coerced is ItsmProvider.SERVICENOW:
            return self.to_servicenow_payload()
        if coerced is ItsmProvider.JIRA:
            return self.to_jira_payload(project_key=project_key)
        return self.to_webhook_payload()

    def to_dict(self) -> dict[str, Any]:
        return {
            "ticket_id": self.ticket_id,
            "workflow_type": self.workflow_type.value,
            "title": self.title,
            "short_description": self.title,
            "summary": self.title,
            "description": self.description,
            "category": self.category,
            "risk": self.risk,
            "priority": self.priority,
            "implementation_plan": self.implementation_plan,
            "backout_plan": self.backout_plan,
            "cmdb_ci": self.cmdb_ci,
            "affected_cis": list(self.affected_cis),
            "site_ids": list(self.site_ids),
            "item_ids": list(self.item_ids),
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "approval_status": self.approval_status.value,
            "approved_by": self.approved_by,
            "approved_at": _format_optional_datetime(self.approved_at),
            "labels": list(self.labels),
            "project_key": self.project_key,
            "issue_type": self.issue_type,
            "created_at": _format_optional_datetime(self.created_at),
            "dry_run": self.dry_run,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ItsmTicketRequest:
        if isinstance(data, cls):
            return data
        title = (
            data.get("title")
            or data.get("short_description")
            or data.get("summary")
            or ""
        )
        backout = (
            data.get("backout_plan")
            or data.get("rollback_plan")
            or "Restore from pre-change snapshot."
        )
        artifact_sha = (
            data.get("artifact_sha256")
            or data.get("u_artifact_sha256")
            or data.get("manifest_sha256")
            or data.get("plan_sha256")
        )
        raw_created = data.get("created_at")
        created_at = (
            _parse_optional_datetime(raw_created, "created_at")
            if raw_created is not None
            else datetime.now(timezone.utc)
        )
        raw_approved_at = data.get("approved_at")
        approved_at = (
            _parse_optional_datetime(raw_approved_at, "approved_at")
            if raw_approved_at is not None
            else None
        )
        return cls(
            ticket_id=str(data["ticket_id"]),
            workflow_type=data.get(
                "workflow_type",
                data.get("u_workflow_type", ItsmWorkflowType.QUARANTINE_DECOMMISSION),
            ),
            title=str(title),
            description=str(data.get("description") or title),
            category=str(data.get("category") or "Network Source of Truth"),
            risk=str(data.get("risk") or "moderate"),
            priority=str(data.get("priority") or "Medium"),
            implementation_plan=str(
                data.get("implementation_plan") or "Execute approved plan."
            ),
            backout_plan=str(backout),
            cmdb_ci=str(data.get("cmdb_ci") or "sot-inventory"),
            affected_cis=list(
                data.get("affected_cis", data.get("u_affected_cis", []))
            ),
            site_ids=list(data.get("site_ids", data.get("u_site_ids", []))),
            item_ids=list(data.get("item_ids", data.get("u_item_ids", []))),
            artifact_id=data.get("artifact_id", data.get("u_artifact_id")),
            artifact_sha256=artifact_sha,
            approval_status=data.get(
                "approval_status", data.get("approval", TicketApprovalStatus.PENDING)
            ),
            approved_by=data.get("approved_by"),
            approved_at=approved_at,
            labels=list(data.get("labels", [])),
            project_key=str(data.get("project_key") or "NETOPS"),
            issue_type=str(data.get("issue_type") or "Change"),
            created_at=created_at or datetime.now(timezone.utc),
            dry_run=bool(data.get("dry_run", data.get("u_dry_run", True))),
            metadata=dict(data.get("metadata") or {}),
        )

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> ItsmTicketRequest:
        return cls.from_dict(json.loads(raw))
