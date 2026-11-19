"""Approval-gated remediation engine applying manifests to SQLite and snapshots."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Optional
import uuid

from sot_validator.extraction.batch import SnapshotStore
from sot_validator.models import (
    Site,
    _format_optional_datetime,
    _require_non_empty_str,
)
from sot_validator.remediation._executor_common import (
    RemediationExecutionError,
    _resolve_target_table,
)
from sot_validator.remediation._executor_journal import (
    RollbackJournal,
    RollbackJournalEntry,
    RollbackPlan,
)
from sot_validator.remediation._executor_snapshot import (
    _query_sqlite_snapshot,
    _validate_and_filter_manifest_entries,
)
from sot_validator.remediation._executor_sql import SqlRemediationScriptGenerator
from sot_validator.remediation.quarantine import (
    ApprovalStatus,
    QuarantineManifestEntry,
    RemediationApprovalManifest,
)
from sot_validator.remediation.sink import _resolve_plan_timestamp


@dataclass
class RemediationExecutionResult:
    """Outcome summary and artifacts produced by RemediationExecutor.execute()."""

    execution_id: str
    manifest_id: str
    executed_at: datetime
    dry_run: bool
    executed_entries: list[QuarantineManifestEntry]
    skipped_entries: list[QuarantineManifestEntry]
    journal_entries: list[RollbackJournalEntry]
    remediate_sql: str
    rollback_sql: str
    remediate_sql_path: Optional[Path] = None
    rollback_sql_path: Optional[Path] = None
    journal_path: Optional[Path] = None

    @property
    def approved_entries(self) -> list[QuarantineManifestEntry]:
        """Alias for executed_entries."""
        return self.executed_entries

    @property
    def applied_count(self) -> int:
        """Number of approved entries processed."""
        return len(self.executed_entries)

    @property
    def skipped_count(self) -> int:
        """Number of non-approved entries skipped."""
        return len(self.skipped_entries)

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "manifest_id": self.manifest_id,
            "executed_at": _format_optional_datetime(self.executed_at),
            "dry_run": self.dry_run,
            "applied_count": len(self.executed_entries),
            "skipped_count": len(self.skipped_entries),
            "executed_entries": [e.to_dict() for e in self.executed_entries],
            "skipped_entries": [e.to_dict() for e in self.skipped_entries],
            "journal_entries": [j.to_dict() for j in self.journal_entries],
            "remediate_sql": self.remediate_sql,
            "rollback_sql": self.rollback_sql,
            "remediate_sql_path": (
                str(self.remediate_sql_path)
                if self.remediate_sql_path is not None
                else None
            ),
            "rollback_sql_path": (
                str(self.rollback_sql_path)
                if self.rollback_sql_path is not None
                else None
            ),
            "journal_path": (
                str(self.journal_path)
                if self.journal_path is not None
                else None
            ),
        }

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def _apply_remediation_to_site(
    site: Site, entry: QuarantineManifestEntry
) -> None:
    table = _resolve_target_table(entry.item_type, entry.target_operation)
    if table == "equipment":
        for eq in site.equipment:
            if eq.equipment_id == entry.item_id:
                eq.power_state = "QUARANTINED_STALE"
                return
    elif table == "network_devices":
        for dev in site.devices:
            if dev.device_id == entry.item_id:
                dev.role = "QUARANTINED_STALE"
                return
    elif table == "ip_arp_entries":
        for ip_obj in site.ip_addresses:
            if ip_obj.ip == entry.item_id or ip_obj.ip == entry.name:
                ip_obj.assigned_object_type = "unassigned"
                ip_obj.assigned_object_id = ""
                return
        idx_match = re.match(r"^ip-[^-]+-(\d+)$", entry.item_id)
        if idx_match:
            idx = int(idx_match.group(1)) - 1
            if 0 <= idx < len(site.ip_addresses):
                site.ip_addresses[idx].assigned_object_type = "unassigned"
                site.ip_addresses[idx].assigned_object_id = ""
                return
    elif table == "ports":
        for dev in site.devices:
            for port in dev.ports:
                if port.port_id == entry.item_id:
                    port.admin_status = "down"
                    return


def _restore_site_from_journal_entry(
    site: Site, entry: RollbackJournalEntry
) -> None:
    table = _resolve_target_table(entry.item_type, entry.operation)
    snap = entry.pre_change_snapshot
    if table == "equipment":
        for eq in site.equipment:
            if eq.equipment_id == entry.item_id:
                eq.power_state = snap.get("power_state")
                if "name" in snap or "hostname" in snap:
                    eq.name = str(snap.get("name") or snap.get("hostname"))
                return
    elif table == "network_devices":
        for dev in site.devices:
            if dev.device_id == entry.item_id:
                dev.role = snap.get("role")
                return
    elif table == "ip_arp_entries":
        target_ip = snap.get("ip_address") or snap.get("ip") or entry.item_id
        for ip_obj in site.ip_addresses:
            if ip_obj.ip == target_ip or ip_obj.ip == entry.item_id:
                ip_obj.assigned_object_type = snap.get(
                    "assigned_object_type", snap.get("assigned_target_type")
                )
                ip_obj.assigned_object_id = snap.get(
                    "assigned_object_id", snap.get("assigned_target_id")
                )
                return
    elif table == "ports":
        for dev in site.devices:
            for port in dev.ports:
                if port.port_id == entry.item_id:
                    port.admin_status = snap.get("admin_status")
                    return


class RemediationExecutor:
    """Strictly gated Phase 2 remediation executor with SHA-256 verification and rollback journal."""

    def __init__(
        self,
        *,
        dry_run: bool = True,
        confirm_write: bool = False,
        journal: Optional[RollbackJournal | Path | str] = None,
        journal_path: Optional[Path | str] = None,
        script_generator: Optional[SqlRemediationScriptGenerator] = None,
        strict_approval: bool = False,
        require_itsm_approval: bool = False,
        itsm_sink: Optional[Any] = None,
        itsm_verifier: Optional[Any] = None,
        itsm_ticket_id: Optional[str] = None,
        itsm_ticket: Optional[Any] = None,
        allow_scheduled_ticket: bool = False,
    ) -> None:
        if not isinstance(dry_run, bool):
            raise RemediationExecutionError("dry_run must be a boolean")
        if not isinstance(confirm_write, bool):
            raise RemediationExecutionError("confirm_write must be a boolean")
        if dry_run is False and confirm_write is not True:
            raise RemediationExecutionError(
                "RemediationExecutor requires confirm_write=True when dry_run=False"
            )

        self.dry_run = dry_run
        self.confirm_write = confirm_write
        self.strict_approval = bool(strict_approval)
        self.require_itsm_approval = bool(require_itsm_approval)
        self.itsm_sink = itsm_sink
        self.itsm_verifier = itsm_verifier
        self.itsm_ticket_id = itsm_ticket_id
        self.itsm_ticket = itsm_ticket
        self.allow_scheduled_ticket = bool(allow_scheduled_ticket)

        resolved_journal_arg = journal if journal is not None else journal_path
        if isinstance(resolved_journal_arg, RollbackJournal):
            self.journal = resolved_journal_arg
        elif resolved_journal_arg is not None:
            self.journal = RollbackJournal(resolved_journal_arg)
        else:
            self.journal = RollbackJournal()

        self.script_generator = (
            script_generator
            if script_generator is not None
            else SqlRemediationScriptGenerator()
        )

    def execute(
        self,
        manifest: RemediationApprovalManifest,
        sites: Optional[
            Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        *,
        sqlite_conn: Optional[sqlite3.Connection] = None,
        snapshot_store: Optional[SnapshotStore] = None,
        sql_output_dir: Optional[Path | str] = None,
        dry_run: Optional[bool] = None,
        confirm_write: Optional[bool] = None,
        strict_approval: Optional[bool] = None,
        execution_id: Optional[str] = None,
        executed_at: Optional[datetime | str] = None,
        reviewer: Optional[str] = None,
        require_itsm_approval: Optional[bool] = None,
        itsm_sink: Optional[Any] = None,
        itsm_verifier: Optional[Any] = None,
        itsm_ticket_id: Optional[str] = None,
        itsm_ticket: Optional[Any] = None,
        allow_scheduled_ticket: Optional[bool] = None,
    ) -> RemediationExecutionResult:
        """Execute an operator-approved RemediationApprovalManifest after gate verification."""
        effective_dry_run = self.dry_run if dry_run is None else dry_run
        effective_confirm_write = (
            self.confirm_write if confirm_write is None else confirm_write
        )
        effective_strict_approval = (
            self.strict_approval if strict_approval is None else strict_approval
        )
        effective_require_itsm = (
            self.require_itsm_approval
            if require_itsm_approval is None
            else bool(require_itsm_approval)
        )
        effective_itsm_sink = (
            itsm_sink if itsm_sink is not None else self.itsm_sink
        )
        effective_itsm_verifier = (
            itsm_verifier if itsm_verifier is not None else self.itsm_verifier
        )
        effective_allow_scheduled = (
            self.allow_scheduled_ticket
            if allow_scheduled_ticket is None
            else bool(allow_scheduled_ticket)
        )
        effective_ticket_ref = (
            itsm_ticket
            if itsm_ticket is not None
            else (
                itsm_ticket_id
                if itsm_ticket_id is not None
                else (
                    self.itsm_ticket
                    if self.itsm_ticket is not None
                    else self.itsm_ticket_id
                )
            )
        )

        if not isinstance(effective_dry_run, bool):
            raise RemediationExecutionError("dry_run must be a boolean")
        if effective_dry_run is False and effective_confirm_write is not True:
            raise RemediationExecutionError(
                "confirm_write=True is required when executing with dry_run=False"
            )

        approved_entries, skipped_entries = _validate_and_filter_manifest_entries(
            manifest, strict_approval=bool(effective_strict_approval)
        )

        if (
            effective_require_itsm
            or effective_ticket_ref is not None
            or effective_itsm_verifier is not None
        ):
            from sot_validator.itsm.tickets import ItsmGateVerifier

            verifier = (
                effective_itsm_verifier
                if isinstance(effective_itsm_verifier, ItsmGateVerifier)
                else ItsmGateVerifier(
                    sink=effective_itsm_sink,
                    allow_scheduled=effective_allow_scheduled,
                )
            )
            verifier.require_change_ticket_approved(
                effective_ticket_ref,
                expected_sha256=manifest.manifest_sha256,
                manifest=manifest,
                sink=effective_itsm_sink,
                allow_scheduled=effective_allow_scheduled,
            )

        resolved_exec_id = (
            _require_non_empty_str(execution_id, "execution_id").strip()
            if execution_id is not None
            else f"exec-{uuid.uuid4().hex[:12]}"
        )
        resolved_executed_at = _resolve_plan_timestamp(executed_at)

        effective_sites = sites
        if effective_sites is None and snapshot_store is not None:
            loaded_sites = snapshot_store.load_all_sites()
            if loaded_sites:
                effective_sites = loaded_sites

        scripts = self.script_generator.generate(
            manifest,
            sites=effective_sites,
            sqlite_conn=sqlite_conn,
            execution_id=resolved_exec_id,
            executed_at=resolved_executed_at,
            reviewer=reviewer,
            strict_approval=bool(effective_strict_approval),
        )

        remediate_sql_path: Optional[Path] = None
        rollback_sql_path: Optional[Path] = None
        journal_path: Optional[Path] = None

        if not effective_dry_run:
            if sql_output_dir is not None:
                remediate_sql_path, rollback_sql_path = scripts.write_scripts(
                    sql_output_dir
                )

            if sqlite_conn is not None:
                sqlite_conn.executescript(scripts.remediate_sql)
                for j_entry, m_entry in zip(
                    scripts.journal_entries, approved_entries
                ):
                    table = _resolve_target_table(
                        m_entry.item_type, m_entry.target_operation
                    )
                    j_entry.post_change_state = _query_sqlite_snapshot(
                        sqlite_conn, table, m_entry
                    )

            if snapshot_store is not None:
                affected_site_ids = {e.site_id for e in approved_entries}
                for site_id in sorted(affected_site_ids):
                    if snapshot_store.is_completed(site_id):
                        site_obj = snapshot_store.load_site(site_id)
                        for m_entry in approved_entries:
                            if m_entry.site_id == site_id:
                                _apply_remediation_to_site(site_obj, m_entry)
                        snapshot_store.save_site(site_obj)

            self.journal.append_entries(scripts.journal_entries)
            journal_path = self.journal.journal_path

        return RemediationExecutionResult(
            execution_id=resolved_exec_id,
            manifest_id=manifest.manifest_id,
            executed_at=resolved_executed_at,
            dry_run=effective_dry_run,
            executed_entries=approved_entries,
            skipped_entries=skipped_entries,
            journal_entries=scripts.journal_entries,
            remediate_sql=scripts.remediate_sql,
            rollback_sql=scripts.rollback_sql,
            remediate_sql_path=remediate_sql_path,
            rollback_sql_path=rollback_sql_path,
            journal_path=journal_path,
        )

    def execute_entry(
        self,
        entry: QuarantineManifestEntry,
        *,
        dry_run: Optional[bool] = None,
        confirm_write: Optional[bool] = None,
        sites: Optional[
            Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        sqlite_conn: Optional[sqlite3.Connection] = None,
        snapshot_store: Optional[SnapshotStore] = None,
        sql_output_dir: Optional[Path | str] = None,
        execution_id: Optional[str] = None,
        executed_at: Optional[datetime | str] = None,
        reviewer: Optional[str] = None,
    ) -> RemediationExecutionResult:
        """Execute a single QuarantineManifestEntry, raising RemediationExecutionError if not APPROVED."""
        if not isinstance(entry, QuarantineManifestEntry):
            raise RemediationExecutionError(
                "entry must be a QuarantineManifestEntry instance"
            )
        if entry.approval_status is not ApprovalStatus.APPROVED:
            raise RemediationExecutionError(
                f"Cannot execute manifest entry {entry.item_id!r} with approval_status={entry.approval_status.value!r}; "
                "ApprovalStatus.APPROVED is required"
            )
        manifest = RemediationApprovalManifest(entries=[entry])
        return self.execute(
            manifest,
            sites=sites,
            sqlite_conn=sqlite_conn,
            snapshot_store=snapshot_store,
            sql_output_dir=sql_output_dir,
            dry_run=dry_run,
            confirm_write=confirm_write,
            strict_approval=True,
            execution_id=execution_id,
            executed_at=executed_at,
            reviewer=reviewer,
        )

    def generate_rollback_plan(self, execution_id: str) -> RollbackPlan:
        """Generate a RollbackPlan for execution_id from the rollback journal."""
        return self.journal.generate_rollback_plan(execution_id)

    def rollback(
        self,
        execution_id: str,
        *,
        sqlite_conn: Optional[sqlite3.Connection] = None,
        snapshot_store: Optional[SnapshotStore] = None,
    ) -> RollbackPlan:
        """Generate and optionally execute a RollbackPlan for execution_id against sqlite_conn/snapshot_store."""
        plan = self.journal.generate_rollback_plan(execution_id)
        if sqlite_conn is not None:
            sqlite_conn.executescript(plan.rollback_sql)
        if snapshot_store is not None:
            affected_site_ids = {e.site_id for e in plan.entries}
            for site_id in sorted(affected_site_ids):
                if snapshot_store.is_completed(site_id):
                    site_obj = snapshot_store.load_site(site_id)
                    for j_entry in plan.entries:
                        if j_entry.site_id == site_id:
                            _restore_site_from_journal_entry(site_obj, j_entry)
                    snapshot_store.save_site(site_obj)
        return plan
