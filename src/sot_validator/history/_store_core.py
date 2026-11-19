"""Connection lifecycle, run-ID generation, and row decoding base for HistoryStore."""

from __future__ import annotations

import json
import sqlite3
from typing import TYPE_CHECKING, Any
import uuid

from sot_validator.history._records import (
    DriftEvent,
    DriftTransitionType,
    ItemStreakSummary,
    ValidationRunRecord,
    _normalize_optional_utc_datetime,
)
from sot_validator.models import ValidationClassification
from sot_validator.signals.base import normalize_utc_datetime

if TYPE_CHECKING:
    from sot_validator.history.ledger import HistoryStore


class _StoreCore:
    """Connection lifecycle, run-ID generation, and row decoding helpers for HistoryStore."""

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()

    def __enter__(self) -> HistoryStore:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _next_generated_run_id(self) -> str:
        # Base the sequence on the highest run_seq ever issued, not the row
        # count, so pruned runs can never make a generated ID repeat.
        row = self._conn.execute(
            """
            SELECT MAX(
                COALESCE((SELECT MAX(run_seq) FROM validation_runs), 0),
                COALESCE(
                    (SELECT seq FROM sqlite_sequence WHERE name = 'validation_runs'),
                    0
                )
            ) AS last_seq
            """
        ).fetchone()
        seq = int(row["last_seq"]) + 1
        while True:
            candidate = f"run-{seq:04d}-{uuid.uuid4().hex[:8]}"
            taken = self._conn.execute(
                "SELECT 1 FROM validation_runs WHERE run_id = ?", (candidate,)
            ).fetchone()
            if taken is None:
                return candidate

    @staticmethod
    def _row_to_run_record(row: sqlite3.Row) -> ValidationRunRecord:
        return ValidationRunRecord(
            run_id=row["run_id"],
            recorded_at=normalize_utc_datetime(
                row["recorded_at"], field_name="recorded_at"
            ),
            site_ids=json.loads(row["site_ids_json"]),
            total_items=int(row["total_items"]),
            classification_counts=json.loads(row["classification_counts_json"]),
        )

    @staticmethod
    def _row_to_streak(row: sqlite3.Row) -> ItemStreakSummary:
        return ItemStreakSummary(
            site_id=row["site_id"],
            item_type=row["item_type"],
            item_id=row["item_id"],
            name=row["name"],
            current_classification=ValidationClassification(
                row["current_classification"]
            ),
            current_confidence=float(row["current_confidence"]),
            consecutive_stale_runs=int(row["consecutive_stale_runs"]),
            total_runs_seen=int(row["total_runs_seen"]),
            first_seen_at=normalize_utc_datetime(
                row["first_seen_at"], field_name="first_seen_at"
            ),
            first_stale_at=_normalize_optional_utc_datetime(
                row["first_stale_at"], "first_stale_at"
            ),
            last_confirmed_active_at=_normalize_optional_utc_datetime(
                row["last_confirmed_active_at"], "last_confirmed_active_at"
            ),
            stale_duration_days=float(row["stale_duration_days"]),
            previous_classification=(
                ValidationClassification(row["previous_classification"])
                if row["previous_classification"] is not None
                else None
            ),
            transition_type=(
                DriftTransitionType(row["transition_type"])
                if row["transition_type"] is not None
                else None
            ),
        )

    @staticmethod
    def _row_to_drift_event(row: sqlite3.Row) -> DriftEvent:
        return DriftEvent(
            run_id=row["run_id"],
            recorded_at=normalize_utc_datetime(
                row["recorded_at"], field_name="recorded_at"
            ),
            site_id=row["site_id"],
            item_type=row["item_type"],
            item_id=row["item_id"],
            name=row["name"],
            previous_classification=ValidationClassification(
                row["previous_classification"]
            ),
            new_classification=ValidationClassification(
                row["new_classification"]
            ),
            transition_type=DriftTransitionType(row["transition_type"]),
            confidence=float(row["confidence"]),
        )

    def _list_all_drift_events(self) -> list[DriftEvent]:
        rows = self._conn.execute(
            "SELECT * FROM drift_events ORDER BY event_id ASC"
        ).fetchall()
        return [self._row_to_drift_event(r) for r in rows]
