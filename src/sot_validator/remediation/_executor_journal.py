"""Append-only remediation rollback journal, journal entries and rollback plans."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
from typing import Any, Optional

from sot_validator.models import (
    _format_optional_datetime,
    _parse_optional_datetime,
    _require_non_empty_str,
)
from sot_validator.remediation._executor_common import (
    RemediationExecutionError,
    _UnknownExecutionIdError,
    _resolve_target_table,
)
from sot_validator.remediation.quarantine import (
    RemediationOperation,
    _coerce_remediation_operation,
)
from sot_validator.remediation.sink import _resolve_plan_timestamp


@dataclass(init=False)
class RollbackJournalEntry:
    """Single audit and rollback record persisted in the append-only remediation journal."""

    execution_id: str
    executed_at: datetime
    reviewer: str
    item_type: str
    item_id: str
    site_id: str
    operation: RemediationOperation
    pre_change_snapshot: dict[str, Any]
    post_change_state: dict[str, Any]
    rollback_sql: str

    def __init__(
        self,
        execution_id: str,
        executed_at: Optional[datetime | str] = None,
        reviewer: Optional[str] = None,
        item_type: str = "",
        item_id: str = "",
        site_id: str = "",
        operation: RemediationOperation | str = RemediationOperation.FLAG_STALE_IN_SOT,
        pre_change_snapshot: Optional[Mapping[str, Any]] = None,
        post_change_state: Optional[Mapping[str, Any]] = None,
        rollback_sql: str = "",
        *,
        target_operation: Optional[RemediationOperation | str] = None,
    ) -> None:
        self.execution_id = _require_non_empty_str(
            execution_id, "execution_id"
        ).strip()
        self.executed_at = _resolve_plan_timestamp(executed_at)
        resolved_reviewer = reviewer if reviewer is not None else "system"
        self.reviewer = _require_non_empty_str(
            resolved_reviewer, "reviewer"
        ).strip()
        self.item_type = _require_non_empty_str(item_type, "item_type").strip()
        self.item_id = _require_non_empty_str(item_id, "item_id").strip()
        self.site_id = _require_non_empty_str(site_id, "site_id").strip()
        op_raw = target_operation if target_operation is not None else operation
        self.operation = _coerce_remediation_operation(op_raw, "operation")
        if pre_change_snapshot is None or not isinstance(
            pre_change_snapshot, Mapping
        ):
            raise ValueError("pre_change_snapshot must be a mapping")
        if post_change_state is None or not isinstance(
            post_change_state, Mapping
        ):
            raise ValueError("post_change_state must be a mapping")
        self.pre_change_snapshot = dict(pre_change_snapshot)
        self.post_change_state = dict(post_change_state)
        self.rollback_sql = _require_non_empty_str(
            rollback_sql, "rollback_sql"
        ).strip()

    @property
    def target_operation(self) -> RemediationOperation:
        """Alias for operation."""
        return self.operation

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "executed_at": _format_optional_datetime(self.executed_at),
            "reviewer": self.reviewer,
            "item_type": self.item_type,
            "item_id": self.item_id,
            "site_id": self.site_id,
            "operation": self.operation.value,
            "pre_change_snapshot": dict(self.pre_change_snapshot),
            "post_change_state": dict(self.post_change_state),
            "rollback_sql": self.rollback_sql,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RollbackJournalEntry:
        op_val = data.get("operation") or data.get("target_operation")
        if op_val is None:
            raise ValueError("Missing operation in RollbackJournalEntry data")
        return cls(
            execution_id=data["execution_id"],
            executed_at=_parse_optional_datetime(
                data.get("executed_at"), "executed_at"
            ),
            reviewer=data.get("reviewer") or "system",
            item_type=data["item_type"],
            item_id=data["item_id"],
            site_id=data["site_id"],
            operation=op_val,
            pre_change_snapshot=data.get("pre_change_snapshot", {}),
            post_change_state=data.get("post_change_state", {}),
            rollback_sql=data["rollback_sql"],
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> RollbackJournalEntry:
        return cls.from_dict(json.loads(raw))


class RollbackPlan(str):
    """Transaction-wrapped rollback SQL script with journal entries and pre-change snapshots."""

    execution_id: str
    entries: list[RollbackJournalEntry]
    rollback_sql: str
    pre_change_snapshots: list[dict[str, Any]]

    def __new__(
        cls,
        rollback_sql_or_execution_id: str = "",
        *,
        execution_id: Optional[str] = None,
        entries: Optional[Sequence[RollbackJournalEntry]] = None,
        rollback_sql: Optional[str] = None,
        pre_change_snapshots: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> RollbackPlan:
        if rollback_sql is not None:
            sql_str = rollback_sql
            exec_id = (
                execution_id
                if execution_id is not None
                else rollback_sql_or_execution_id
            )
        else:
            sql_str = rollback_sql_or_execution_id
            exec_id = execution_id or ""

        resolved_entries = list(entries) if entries is not None else []
        if not exec_id and resolved_entries:
            exec_id = resolved_entries[0].execution_id

        instance = super().__new__(cls, sql_str)
        instance.execution_id = exec_id
        instance.entries = resolved_entries
        instance.rollback_sql = sql_str
        if pre_change_snapshots is not None:
            instance.pre_change_snapshots = [
                dict(s) for s in pre_change_snapshots
            ]
        else:
            instance.pre_change_snapshots = [
                dict(e.pre_change_snapshot) for e in resolved_entries
            ]
        return instance

    @property
    def sql(self) -> str:
        """Alias for rollback_sql."""
        return self.rollback_sql

    @property
    def statements(self) -> list[str]:
        """Individual per-item rollback SQL statements in execution order of the plan."""
        return [e.rollback_sql for e in self.entries]

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "rollback_sql": self.rollback_sql,
            "entries": [e.to_dict() for e in self.entries],
            "pre_change_snapshots": [dict(s) for s in self.pre_change_snapshots],
        }


def _build_rollback_transaction_sql(
    entries_in_reverse_order: Sequence[RollbackJournalEntry],
) -> str:
    lines: list[str] = ["BEGIN TRANSACTION;"]
    tables_to_drop_status: list[str] = []

    for entry in entries_in_reverse_order:
        stmt = entry.rollback_sql.strip()
        if not stmt.endswith(";"):
            stmt += ";"
        lines.append(stmt)
        table = _resolve_target_table(entry.item_type, entry.operation)
        if (
            "status" not in entry.pre_change_snapshot
            and table not in tables_to_drop_status
        ):
            tables_to_drop_status.append(table)

    for table in tables_to_drop_status:
        lines.append(f"ALTER TABLE {table} DROP COLUMN status;")

    lines.append("COMMIT;")
    return "\n".join(lines) + "\n"


class RollbackJournal:
    """Append-only JSONL journal (`remediation_journal.jsonl`) for remediation audit and rollback."""

    DEFAULT_FILENAME = "remediation_journal.jsonl"

    def __init__(
        self,
        journal_path: Path | str = Path(DEFAULT_FILENAME),
    ) -> None:
        candidate = Path(journal_path)
        if candidate.exists() and candidate.is_dir():
            self.journal_path = candidate / self.DEFAULT_FILENAME
        else:
            self.journal_path = candidate

    @property
    def path(self) -> Path:
        """Alias for journal_path."""
        return self.journal_path

    def append(self, entry: RollbackJournalEntry) -> RollbackJournalEntry:
        """Append a single RollbackJournalEntry to the JSONL journal file."""
        if not isinstance(entry, RollbackJournalEntry):
            entry = RollbackJournalEntry.from_dict(entry)
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        with self.journal_path.open("a", encoding="utf-8") as handle:
            handle.write(entry.to_json(indent=None) + "\n")
        return entry

    def record(self, entry: RollbackJournalEntry) -> RollbackJournalEntry:
        """Alias for append()."""
        return self.append(entry)

    def append_entries(
        self, entries: Iterable[RollbackJournalEntry]
    ) -> list[RollbackJournalEntry]:
        """Append multiple RollbackJournalEntry items atomically in append-only mode."""
        normalized: list[RollbackJournalEntry] = [
            e
            if isinstance(e, RollbackJournalEntry)
            else RollbackJournalEntry.from_dict(e)
            for e in entries
        ]
        if not normalized:
            return []
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        with self.journal_path.open("a", encoding="utf-8") as handle:
            for entry in normalized:
                handle.write(entry.to_json(indent=None) + "\n")
        return normalized

    def read_entries(
        self, execution_id: Optional[str] = None
    ) -> list[RollbackJournalEntry]:
        """Read all journal entries from disk, optionally filtered by execution_id."""
        if not self.journal_path.exists():
            return []
        entries: list[RollbackJournalEntry] = []
        with self.journal_path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                stripped = raw_line.strip()
                if not stripped:
                    continue
                entry = RollbackJournalEntry.from_json(stripped)
                if execution_id is None or entry.execution_id == execution_id:
                    entries.append(entry)
        return entries

    def list_entries(
        self, execution_id: Optional[str] = None
    ) -> list[RollbackJournalEntry]:
        """Alias for read_entries()."""
        return self.read_entries(execution_id=execution_id)

    def get_entries(
        self, execution_id: Optional[str] = None
    ) -> list[RollbackJournalEntry]:
        """Alias for read_entries()."""
        return self.read_entries(execution_id=execution_id)

    def generate_rollback_plan(self, execution_id: str) -> RollbackPlan:
        """Generate a transaction-wrapped RollbackPlan restoring all items from execution_id."""
        if not isinstance(execution_id, str) or not execution_id.strip():
            raise RemediationExecutionError(
                "execution_id must be a non-empty string"
            )
        clean_id = execution_id.strip()
        matching = self.read_entries(execution_id=clean_id)
        if not matching:
            raise _UnknownExecutionIdError(
                f"No rollback journal entries found for execution_id={clean_id!r}"
            )
        reversed_entries = list(reversed(matching))
        rollback_sql = _build_rollback_transaction_sql(reversed_entries)
        return RollbackPlan(
            rollback_sql,
            execution_id=clean_id,
            entries=reversed_entries,
            pre_change_snapshots=[
                dict(e.pre_change_snapshot) for e in reversed_entries
            ],
        )
