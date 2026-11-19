"""Reversible SQL remediation and rollback script generator."""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import sqlite3
from typing import Any, Optional
import uuid

from sot_validator.models import Site, _require_non_empty_str
from sot_validator.remediation._executor_common import (
    RemediationExecutionError,
    _TABLE_SQL_COLUMNS,
    _resolve_target_table,
    _sql_literal,
)
from sot_validator.remediation._executor_journal import (
    RollbackJournalEntry,
    _build_rollback_transaction_sql,
)
from sot_validator.remediation._executor_snapshot import (
    _normalize_sites_lookup,
    _query_sqlite_snapshot,
    _resolve_fallback_snapshot,
    _resolve_site_snapshot,
    _table_has_column,
    _validate_and_filter_manifest_entries,
)
from sot_validator.remediation.quarantine import (
    QuarantineManifestEntry,
    RemediationApprovalManifest,
)
from sot_validator.remediation.sink import _resolve_plan_timestamp


@dataclass
class SqlRemediationScripts:
    """Paired forward (`remediate.sql`) and reverse (`rollback.sql`) SQL scripts."""

    remediate_sql: str
    rollback_sql: str
    entries: list[QuarantineManifestEntry] = field(default_factory=list)
    journal_entries: list[RollbackJournalEntry] = field(default_factory=list)

    def __iter__(self) -> Iterator[str]:
        yield self.remediate_sql
        yield self.rollback_sql

    def write_scripts(
        self,
        output_dir: Path | str,
        *,
        remediate_filename: str = "remediate.sql",
        rollback_filename: str = "rollback.sql",
    ) -> tuple[Path, Path]:
        """Write remediate.sql and rollback.sql to output_dir and return their Paths."""
        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        remediate_path = target_dir / remediate_filename
        rollback_path = target_dir / rollback_filename
        remediate_path.write_text(self.remediate_sql, encoding="utf-8")
        rollback_path.write_text(self.rollback_sql, encoding="utf-8")
        return remediate_path, rollback_path

    def to_dict(self) -> dict[str, Any]:
        return {
            "remediate_sql": self.remediate_sql,
            "rollback_sql": self.rollback_sql,
            "entries": [e.to_dict() for e in self.entries],
            "journal_entries": [j.to_dict() for j in self.journal_entries],
        }


def _build_remediate_and_rollback_row_sql(
    table: str,
    entry: QuarantineManifestEntry,
    pre_snapshot: Mapping[str, Any],
    *,
    from_sqlite: bool,
) -> tuple[str, str, dict[str, Any]]:
    site_lit = _sql_literal(entry.site_id)
    item_lit = _sql_literal(entry.item_id)

    if table == "equipment":
        where_clause = f"equipment_id = {item_lit} AND site_id = {site_lit}"
        remediate_stmt = (
            f"UPDATE equipment SET status = 'QUARANTINED_STALE' WHERE {where_clause};"
        )
        post_state = {**pre_snapshot, "status": "QUARANTINED_STALE"}
    elif table == "network_devices":
        where_clause = f"device_id = {item_lit} AND site_id = {site_lit}"
        remediate_stmt = (
            f"UPDATE network_devices SET status = 'QUARANTINED_STALE' WHERE {where_clause};"
        )
        post_state = {**pre_snapshot, "status": "QUARANTINED_STALE"}
    elif table == "ip_arp_entries":
        where_clause = (
            f"site_id = {site_lit} AND (ip_id = {item_lit} OR ip_address = {item_lit})"
        )
        remediate_stmt = (
            "UPDATE ip_arp_entries SET status = 'AVAILABLE_RECLAIMED', "
            f"assigned_target_type = 'unassigned', assigned_target_id = '' WHERE {where_clause};"
        )
        post_state = {
            **pre_snapshot,
            "status": "AVAILABLE_RECLAIMED",
            "assigned_target_type": "unassigned",
            "assigned_target_id": "",
        }
        if "assigned_object_type" in post_state:
            post_state["assigned_object_type"] = "unassigned"
        if "assigned_object_id" in post_state:
            post_state["assigned_object_id"] = ""
    elif table == "ports":
        where_clause = f"port_id = {item_lit}"
        remediate_stmt = (
            f"UPDATE ports SET admin_status = 'down', status = 'QUARANTINED_STALE' WHERE {where_clause};"
        )
        post_state = {
            **pre_snapshot,
            "admin_status": "down",
            "status": "QUARANTINED_STALE",
        }
    else:
        raise RemediationExecutionError(f"Unsupported table: {table!r}")

    allowed_cols = _TABLE_SQL_COLUMNS[table]
    ordered_cols: list[str] = [c for c in allowed_cols if c in pre_snapshot]
    if from_sqlite:
        for extra_col in pre_snapshot:
            if extra_col not in ordered_cols:
                ordered_cols.append(extra_col)

    assignments: list[str] = []
    for col in ordered_cols:
        val = pre_snapshot[col]
        if not from_sqlite and val is None:
            continue
        assignments.append(f"{col} = {_sql_literal(val)}")

    if not assignments:
        if table == "equipment":
            assignments.append(f"equipment_id = {item_lit}")
        elif table == "network_devices":
            assignments.append(f"device_id = {item_lit}")
        elif table == "ip_arp_entries":
            assignments.append(f"site_id = {site_lit}")
        elif table == "ports":
            assignments.append(f"port_id = {item_lit}")

    set_clause = ", ".join(assignments)
    rollback_stmt = f"UPDATE {table} SET {set_clause} WHERE {where_clause};"
    return remediate_stmt, rollback_stmt, post_state


class SqlRemediationScriptGenerator:
    """Generates transaction-wrapped paired `remediate.sql` and `rollback.sql` scripts."""

    def generate(
        self,
        manifest: RemediationApprovalManifest,
        sites: Optional[
            Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        *,
        sqlite_conn: Optional[sqlite3.Connection] = None,
        execution_id: Optional[str] = None,
        executed_at: Optional[datetime | str] = None,
        reviewer: Optional[str] = None,
        strict_approval: bool = False,
    ) -> SqlRemediationScripts:
        """Build deterministic forward and rollback SQL scripts from an approved manifest."""
        approved_entries, _ = _validate_and_filter_manifest_entries(
            manifest, strict_approval=strict_approval
        )
        sites_by_id = _normalize_sites_lookup(sites)
        resolved_exec_id = (
            _require_non_empty_str(execution_id, "execution_id").strip()
            if execution_id is not None
            else f"exec-{uuid.uuid4().hex[:12]}"
        )
        resolved_executed_at = _resolve_plan_timestamp(executed_at)

        tables_needing_status_col: list[str] = []
        remediate_updates: list[str] = []
        journal_entries: list[RollbackJournalEntry] = []

        for entry in approved_entries:
            table = _resolve_target_table(entry.item_type, entry.target_operation)
            from_sqlite = False
            if sqlite_conn is not None:
                pre_snapshot = _query_sqlite_snapshot(sqlite_conn, table, entry)
                from_sqlite = True
            elif sites is not None:
                pre_snapshot = _resolve_site_snapshot(sites_by_id, table, entry)
            else:
                pre_snapshot = _resolve_fallback_snapshot(table, entry)

            if (
                "status" not in pre_snapshot
                and table not in tables_needing_status_col
            ):
                if sqlite_conn is None or not _table_has_column(
                    sqlite_conn, table, "status"
                ):
                    tables_needing_status_col.append(table)

            remediate_stmt, rollback_stmt, post_state = (
                _build_remediate_and_rollback_row_sql(
                    table, entry, pre_snapshot, from_sqlite=from_sqlite
                )
            )
            remediate_updates.append(remediate_stmt)

            entry_reviewer = (
                reviewer
                or entry.reviewed_by
                or "system"
            )
            journal_entries.append(
                RollbackJournalEntry(
                    execution_id=resolved_exec_id,
                    executed_at=resolved_executed_at,
                    reviewer=entry_reviewer,
                    item_type=entry.item_type,
                    item_id=entry.item_id,
                    site_id=entry.site_id,
                    operation=entry.target_operation,
                    pre_change_snapshot=pre_snapshot,
                    post_change_state=post_state,
                    rollback_sql=rollback_stmt,
                )
            )

        remediate_lines: list[str] = ["BEGIN TRANSACTION;"]
        for table in tables_needing_status_col:
            remediate_lines.append(
                f"ALTER TABLE {table} ADD COLUMN status TEXT DEFAULT 'ACTIVE';"
            )
        remediate_lines.extend(remediate_updates)
        remediate_lines.append("COMMIT;")
        remediate_sql = "\n".join(remediate_lines) + "\n"

        rollback_sql = _build_rollback_transaction_sql(
            list(reversed(journal_entries))
        )

        return SqlRemediationScripts(
            remediate_sql=remediate_sql,
            rollback_sql=rollback_sql,
            entries=approved_entries,
            journal_entries=journal_entries,
        )

    def generate_scripts(
        self,
        manifest: RemediationApprovalManifest,
        sites: Optional[
            Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        **kwargs: Any,
    ) -> SqlRemediationScripts:
        """Alias for generate()."""
        return self.generate(manifest, sites=sites, **kwargs)
