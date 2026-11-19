"""Multi-run validation history ledger, stale streak tracker, and drift analyzer."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import ipaddress
import json
from pathlib import Path
import sqlite3
from typing import Any, ClassVar, Optional
import uuid

from sot_validator.history._records import (
    ALL_CLASSIFICATION_VALUES,
    DriftEvent,
    DriftTransitionType,
    ItemStreakSummary,
    SubnetUtilizationSummary,
    ValidationRunRecord,
    _DRIFT_TRANSITION_MAP,
    _HybridImportMethod,
    _coerce_classification,
    _coerce_sites,
    _coerce_transition_type,
    _normalize_optional_utc_datetime,
    _require_confidence,
    _require_non_negative_int,
    _try_parse_ipv4,
    _try_parse_slash24_ipv4,
)
from sot_validator.history._store_analysis import _AnalysisMixin
from sot_validator.history._store_core import _StoreCore
from sot_validator.history._store_io import _IoMixin
from sot_validator.history._store_runs import _PRUNE_CHUNK_SIZE, _RunsMixin
from sot_validator.history.retention import PruneReport, RetentionPolicy
from sot_validator.models import (
    Site,
    ValidationClassification,
    ValidationResult,
    _format_optional_datetime,
    _require_non_empty_str,
)
from sot_validator.signals.base import SECONDS_PER_DAY, normalize_utc_datetime


class HistorySchemaVersionError(RuntimeError):
    """Raised when a history database has a newer schema than this code supports."""


def _migration_1_create_base_tables(conn: sqlite3.Connection) -> None:
    """Create the v1 ledger tables; also stamps pre-versioning databases unchanged."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS validation_runs (
            run_seq INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL UNIQUE,
            recorded_at TEXT NOT NULL,
            site_ids_json TEXT NOT NULL,
            total_items INTEGER NOT NULL,
            classification_counts_json TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS item_streaks (
            item_type TEXT NOT NULL,
            item_id TEXT NOT NULL,
            site_id TEXT NOT NULL,
            name TEXT NOT NULL,
            current_classification TEXT NOT NULL,
            current_confidence REAL NOT NULL,
            consecutive_stale_runs INTEGER NOT NULL,
            total_runs_seen INTEGER NOT NULL,
            first_seen_at TEXT NOT NULL,
            first_stale_at TEXT,
            last_confirmed_active_at TEXT,
            stale_duration_days REAL NOT NULL,
            previous_classification TEXT,
            transition_type TEXT,
            PRIMARY KEY (item_type, item_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS drift_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            site_id TEXT NOT NULL,
            item_type TEXT NOT NULL,
            item_id TEXT NOT NULL,
            name TEXT NOT NULL,
            previous_classification TEXT NOT NULL,
            new_classification TEXT NOT NULL,
            transition_type TEXT NOT NULL,
            confidence REAL NOT NULL
        )
        """
    )


# Ordered schema migrations: entry ``i`` upgrades ``user_version`` ``i`` to ``i + 1``.
# Add schema changes as new entries; never edit an existing migration.
_MIGRATIONS: list[Callable[[sqlite3.Connection], None]] = [
    _migration_1_create_base_tables,
]

HISTORY_SCHEMA_VERSION: int = len(_MIGRATIONS)


class HistoryStore(_RunsMixin, _AnalysisMixin, _IoMixin, _StoreCore):
    """SQLite-backed multi-run validation history ledger, streak tracker, and drift analyzer."""

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        if isinstance(db_path, Path):
            self.db_path: Path | str = db_path
            db_path.parent.mkdir(parents=True, exist_ok=True)
            conn_target = str(db_path)
        elif isinstance(db_path, str):
            raw = db_path.strip()
            if not raw:
                raise ValueError("db_path must not be an empty string")
            if raw == ":memory:":
                self.db_path = ":memory:"
                conn_target = ":memory:"
            else:
                path_obj = Path(raw)
                path_obj.parent.mkdir(parents=True, exist_ok=True)
                self.db_path = path_obj
                conn_target = str(path_obj)
        else:
            raise ValueError("db_path must be a Path or string")

        self._conn = sqlite3.connect(conn_target)
        self._conn.row_factory = sqlite3.Row
        try:
            self._init_schema()
        except BaseException:
            self._conn.close()
            raise

    def _init_schema(self) -> None:
        migrations = list(_MIGRATIONS)
        supported = len(migrations)
        current = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
        if current > supported:
            raise HistorySchemaVersionError(
                f"history database schema version {current} is newer than the "
                f"highest version this code supports ({supported})"
            )
        for version in range(current + 1, supported + 1):
            self._conn.execute("BEGIN")
            try:
                migrations[version - 1](self._conn)
                self._conn.execute(f"PRAGMA user_version = {version}")
                self._conn.execute("COMMIT")
            except BaseException:
                if self._conn.in_transaction:
                    self._conn.execute("ROLLBACK")
                raise

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        db_path: Path | str = ":memory:",
    ) -> HistoryStore:
        """Create and populate a HistoryStore from a serialized state dictionary."""
        store = cls(db_path=db_path)
        store._load_state_from_mapping(data)
        return store

    @classmethod
    def from_json(
        cls,
        raw: str,
        db_path: Path | str = ":memory:",
    ) -> HistoryStore:
        """Create and populate a HistoryStore from a JSON string."""
        return cls.from_dict(json.loads(raw), db_path=db_path)

    def _import_json_impl(
        target: Any,
        path: Path | str,
        db_path: Path | str = ":memory:",
    ) -> HistoryStore:
        raw = Path(path).read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(target, HistoryStore):
            target._load_state_from_mapping(data)
            return target
        return target.from_dict(data, db_path=db_path)

    import_json = _HybridImportMethod(_import_json_impl)


__all__ = [
    "HISTORY_SCHEMA_VERSION",
    "DriftEvent",
    "DriftTransitionType",
    "HistorySchemaVersionError",
    "HistoryStore",
    "ItemStreakSummary",
    "SubnetUtilizationSummary",
    "ValidationRunRecord",
]
