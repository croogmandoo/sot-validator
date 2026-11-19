"""JSON serialization and state import mixin for HistoryStore."""

from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
from typing import Any, Optional

from sot_validator.history._records import (
    DriftEvent,
    ItemStreakSummary,
    ValidationRunRecord,
)
from sot_validator.models import _format_optional_datetime


class _IoMixin:
    """JSON serialization and state import for HistoryStore."""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the complete history ledger state to a dictionary."""
        return {
            "runs": [r.to_dict() for r in self.list_runs()],
            "streaks": [s.to_dict() for s in self.list_streaks()],
            "drift_events": [e.to_dict() for e in self._list_all_drift_events()],
        }

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        """Serialize the complete history ledger state to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def export_json(
        self, path: Path | str, *, indent: Optional[int] = 2
    ) -> Path:
        """Write the complete history ledger state to a JSON file on disk."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.to_json(indent=indent), encoding="utf-8")
        return target

    def _load_state_from_mapping(self, data: Mapping[str, Any]) -> None:
        if not isinstance(data, Mapping):
            raise ValueError("HistoryStore state data must be a mapping")

        runs = [
            r
            if isinstance(r, ValidationRunRecord)
            else ValidationRunRecord.from_dict(r)
            for r in data.get("runs", [])
        ]
        streaks = [
            s
            if isinstance(s, ItemStreakSummary)
            else ItemStreakSummary.from_dict(s)
            for s in data.get("streaks", [])
        ]
        drift_events = [
            e if isinstance(e, DriftEvent) else DriftEvent.from_dict(e)
            for e in data.get("drift_events", [])
        ]

        with self._conn:
            self._conn.execute("DELETE FROM drift_events")
            self._conn.execute("DELETE FROM item_streaks")
            self._conn.execute("DELETE FROM validation_runs")

            for run in runs:
                self._conn.execute(
                    """
                    INSERT INTO validation_runs (
                        run_id, recorded_at, site_ids_json, total_items, classification_counts_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        run.run_id,
                        run.recorded_at.isoformat(),
                        json.dumps(run.site_ids),
                        run.total_items,
                        json.dumps(run.classification_counts),
                    ),
                )

            for streak in streaks:
                self._conn.execute(
                    """
                    INSERT INTO item_streaks (
                        item_type, item_id, site_id, name,
                        current_classification, current_confidence,
                        consecutive_stale_runs, total_runs_seen,
                        first_seen_at, first_stale_at, last_confirmed_active_at,
                        stale_duration_days, previous_classification, transition_type
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        streak.item_type,
                        streak.item_id,
                        streak.site_id,
                        streak.name,
                        streak.current_classification.value,
                        streak.current_confidence,
                        streak.consecutive_stale_runs,
                        streak.total_runs_seen,
                        streak.first_seen_at.isoformat(),
                        _format_optional_datetime(streak.first_stale_at),
                        _format_optional_datetime(
                            streak.last_confirmed_active_at
                        ),
                        streak.stale_duration_days,
                        (
                            streak.previous_classification.value
                            if streak.previous_classification is not None
                            else None
                        ),
                        (
                            streak.transition_type.value
                            if streak.transition_type is not None
                            else None
                        ),
                    ),
                )

            for event in drift_events:
                self._conn.execute(
                    """
                    INSERT INTO drift_events (
                        run_id, recorded_at, site_id, item_type, item_id, name,
                        previous_classification, new_classification,
                        transition_type, confidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.run_id,
                        event.recorded_at.isoformat(),
                        event.site_id,
                        event.item_type,
                        event.item_id,
                        event.name,
                        event.previous_classification.value,
                        event.new_classification.value,
                        event.transition_type.value,
                        event.confidence,
                    ),
                )
