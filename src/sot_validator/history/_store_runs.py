"""Run recording, retention pruning, streak lookup, and drift detection mixin for HistoryStore."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
import json
from typing import Any, Optional

from sot_validator.history._records import (
    ALL_CLASSIFICATION_VALUES,
    DriftEvent,
    DriftTransitionType,
    ItemStreakSummary,
    ValidationRunRecord,
    _DRIFT_TRANSITION_MAP,
    _coerce_classification,
    _coerce_transition_type,
    _require_non_negative_int,
)
from sot_validator.history.retention import PruneReport, RetentionPolicy
from sot_validator.models import (
    ValidationClassification,
    ValidationResult,
    _format_optional_datetime,
    _require_non_empty_str,
)
from sot_validator.signals.base import SECONDS_PER_DAY, normalize_utc_datetime

# Bound on SQL parameters per IN (...) clause when selecting or deleting pruned runs.
_PRUNE_CHUNK_SIZE = 500


class _RunsMixin:
    """Run recording, retention pruning, streak lookup, and drift detection for HistoryStore."""

    def record_run(
        self,
        results: Sequence[ValidationResult | Mapping[str, Any]],
        run_id: Optional[str] = None,
        recorded_at: Optional[datetime | str] = None,
    ) -> ValidationRunRecord:
        """Persist a validation run, update per-item stale streaks, and record drift events."""
        resolved_run_id = (
            _require_non_empty_str(run_id, "run_id").strip()
            if run_id is not None
            else self._next_generated_run_id()
        )
        existing_run = self._conn.execute(
            "SELECT 1 FROM validation_runs WHERE run_id = ?",
            (resolved_run_id,),
        ).fetchone()
        if existing_run is not None:
            raise ValueError(
                f"Validation run {resolved_run_id!r} already exists in HistoryStore"
            )

        run_dt = (
            normalize_utc_datetime(recorded_at, field_name="recorded_at")
            if recorded_at is not None
            else datetime.now(timezone.utc)
        )

        normalized_results: list[ValidationResult] = [
            r if isinstance(r, ValidationResult) else ValidationResult.from_dict(r)
            for r in results
        ]

        counts: dict[str, int] = {
            cls_val: 0 for cls_val in ALL_CLASSIFICATION_VALUES
        }
        site_ids: set[str] = set()

        for res in normalized_results:
            counts[res.classification.value] = (
                counts.get(res.classification.value, 0) + 1
            )
            site_ids.add(res.site_id)

        run_record = ValidationRunRecord(
            run_id=resolved_run_id,
            recorded_at=run_dt,
            site_ids=sorted(site_ids),
            total_items=len(normalized_results),
            classification_counts=counts,
        )

        with self._conn:
            self._conn.execute(
                """
                INSERT INTO validation_runs (
                    run_id, recorded_at, site_ids_json, total_items, classification_counts_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    run_record.run_id,
                    run_record.recorded_at.isoformat(),
                    json.dumps(run_record.site_ids),
                    run_record.total_items,
                    json.dumps(run_record.classification_counts),
                ),
            )

            for res in normalized_results:
                prior_row = self._conn.execute(
                    """
                    SELECT * FROM item_streaks
                    WHERE item_type = ? AND item_id = ?
                    """,
                    (res.item_type, res.item_id),
                ).fetchone()

                prior = (
                    self._row_to_streak(prior_row)
                    if prior_row is not None
                    else None
                )

                first_seen_at = (
                    prior.first_seen_at if prior is not None else run_dt
                )
                total_runs_seen = (
                    prior.total_runs_seen + 1 if prior is not None else 1
                )
                previous_classification = (
                    prior.current_classification if prior is not None else None
                )
                last_confirmed_active_at = (
                    prior.last_confirmed_active_at if prior is not None else None
                )

                if (
                    res.classification
                    is ValidationClassification.STALE_LIKELY_UNUSED
                ):
                    consecutive_stale = (
                        prior.consecutive_stale_runs + 1
                        if prior is not None
                        else 1
                    )
                    first_stale_at = (
                        prior.first_stale_at
                        if (prior is not None and prior.first_stale_at is not None)
                        else run_dt
                    )
                    stale_duration_days = round(
                        max(
                            0.0,
                            (run_dt - first_stale_at).total_seconds()
                            / SECONDS_PER_DAY,
                        ),
                        4,
                    )
                elif (
                    res.classification
                    is ValidationClassification.CONFIRMED_ACTIVE
                ):
                    consecutive_stale = 0
                    first_stale_at = None
                    stale_duration_days = 0.0
                    last_confirmed_active_at = run_dt
                else:
                    consecutive_stale = 0
                    first_stale_at = None
                    stale_duration_days = 0.0

                transition_type: Optional[DriftTransitionType] = None
                if previous_classification is not None:
                    transition_type = _DRIFT_TRANSITION_MAP.get(
                        (previous_classification, res.classification)
                    )

                updated_streak = ItemStreakSummary(
                    site_id=res.site_id,
                    item_type=res.item_type,
                    item_id=res.item_id,
                    name=res.name,
                    current_classification=res.classification,
                    current_confidence=res.confidence,
                    consecutive_stale_runs=consecutive_stale,
                    total_runs_seen=total_runs_seen,
                    first_seen_at=first_seen_at,
                    first_stale_at=first_stale_at,
                    last_confirmed_active_at=last_confirmed_active_at,
                    stale_duration_days=stale_duration_days,
                    previous_classification=previous_classification,
                    transition_type=transition_type,
                )

                self._conn.execute(
                    """
                    INSERT INTO item_streaks (
                        item_type, item_id, site_id, name,
                        current_classification, current_confidence,
                        consecutive_stale_runs, total_runs_seen,
                        first_seen_at, first_stale_at, last_confirmed_active_at,
                        stale_duration_days, previous_classification, transition_type
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(item_type, item_id) DO UPDATE SET
                        site_id = excluded.site_id,
                        name = excluded.name,
                        current_classification = excluded.current_classification,
                        current_confidence = excluded.current_confidence,
                        consecutive_stale_runs = excluded.consecutive_stale_runs,
                        total_runs_seen = excluded.total_runs_seen,
                        first_seen_at = excluded.first_seen_at,
                        first_stale_at = excluded.first_stale_at,
                        last_confirmed_active_at = excluded.last_confirmed_active_at,
                        stale_duration_days = excluded.stale_duration_days,
                        previous_classification = excluded.previous_classification,
                        transition_type = excluded.transition_type
                    """,
                    (
                        updated_streak.item_type,
                        updated_streak.item_id,
                        updated_streak.site_id,
                        updated_streak.name,
                        updated_streak.current_classification.value,
                        updated_streak.current_confidence,
                        updated_streak.consecutive_stale_runs,
                        updated_streak.total_runs_seen,
                        updated_streak.first_seen_at.isoformat(),
                        _format_optional_datetime(updated_streak.first_stale_at),
                        _format_optional_datetime(
                            updated_streak.last_confirmed_active_at
                        ),
                        updated_streak.stale_duration_days,
                        (
                            updated_streak.previous_classification.value
                            if updated_streak.previous_classification is not None
                            else None
                        ),
                        (
                            updated_streak.transition_type.value
                            if updated_streak.transition_type is not None
                            else None
                        ),
                    ),
                )

                if (
                    transition_type is not None
                    and previous_classification is not None
                ):
                    drift_event = DriftEvent(
                        run_id=run_record.run_id,
                        recorded_at=run_dt,
                        site_id=res.site_id,
                        item_type=res.item_type,
                        item_id=res.item_id,
                        name=res.name,
                        previous_classification=previous_classification,
                        new_classification=res.classification,
                        transition_type=transition_type,
                        confidence=res.confidence,
                    )
                    self._conn.execute(
                        """
                        INSERT INTO drift_events (
                            run_id, recorded_at, site_id, item_type, item_id, name,
                            previous_classification, new_classification,
                            transition_type, confidence
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            drift_event.run_id,
                            drift_event.recorded_at.isoformat(),
                            drift_event.site_id,
                            drift_event.item_type,
                            drift_event.item_id,
                            drift_event.name,
                            drift_event.previous_classification.value,
                            drift_event.new_classification.value,
                            drift_event.transition_type.value,
                            drift_event.confidence,
                        ),
                    )

        return run_record

    def get_run(self, run_id: str) -> Optional[ValidationRunRecord]:
        """Return the ValidationRunRecord for `run_id`, or None if not found."""
        row = self._conn.execute(
            "SELECT * FROM validation_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_run_record(row)

    def list_runs(self) -> list[ValidationRunRecord]:
        """Return all recorded ValidationRunRecord entries ordered by recording sequence."""
        rows = self._conn.execute(
            "SELECT * FROM validation_runs ORDER BY run_seq ASC"
        ).fetchall()
        return [self._row_to_run_record(r) for r in rows]

    def _select_prunable_runs(
        self, policy: RetentionPolicy, age_cutoff: Optional[datetime]
    ) -> list[str]:
        rows = self._conn.execute(
            """
            SELECT run_seq, run_id, recorded_at, site_ids_json
            FROM validation_runs ORDER BY run_seq DESC
            """
        ).fetchall()
        kept_per_site: dict[str, int] = {}
        selected: list[str] = []
        for index, row in enumerate(rows):
            site_ids = set(json.loads(row["site_ids_json"]))
            marked = False
            if age_cutoff is not None:
                recorded_at = normalize_utc_datetime(
                    row["recorded_at"], field_name="recorded_at"
                )
                marked = recorded_at < age_cutoff
            if policy.max_runs_per_site is not None and site_ids:
                protected = False
                for site_id in site_ids:
                    kept_per_site[site_id] = kept_per_site.get(site_id, 0) + 1
                    if kept_per_site[site_id] <= policy.max_runs_per_site:
                        protected = True
                marked = marked or not protected
            # The run with the highest run_seq is always kept.
            if marked and index > 0:
                selected.append(row["run_id"])
        selected.reverse()
        return selected

    def _count_or_delete_drift_events(
        self, run_ids: Sequence[str], *, delete: bool
    ) -> int:
        total = 0
        for start in range(0, len(run_ids), _PRUNE_CHUNK_SIZE):
            chunk = list(run_ids[start : start + _PRUNE_CHUNK_SIZE])
            placeholders = ", ".join("?" for _ in chunk)
            if delete:
                cursor = self._conn.execute(
                    f"DELETE FROM drift_events WHERE run_id IN ({placeholders})",
                    chunk,
                )
                total += cursor.rowcount
            else:
                row = self._conn.execute(
                    "SELECT COUNT(*) AS cnt FROM drift_events "
                    f"WHERE run_id IN ({placeholders})",
                    chunk,
                ).fetchone()
                total += int(row["cnt"])
        return total

    def prune_runs(
        self,
        policy: RetentionPolicy,
        *,
        now: Optional[datetime | str] = None,
        dry_run: bool = True,
    ) -> PruneReport:
        """Select, and unless ``dry_run`` delete, runs and drift rows outside ``policy``.

        The newest run (highest ``run_seq``) is always kept and ``item_streaks``
        is never read or written.
        """
        if not isinstance(policy, RetentionPolicy):
            raise ValueError("policy must be a RetentionPolicy")
        now_dt = (
            normalize_utc_datetime(now, field_name="now")
            if now is not None
            else datetime.now(timezone.utc)
        )
        age_cutoff = (
            now_dt - timedelta(days=policy.max_age_days)
            if policy.max_age_days is not None
            else None
        )

        if dry_run:
            run_ids = self._select_prunable_runs(policy, age_cutoff)
            drift_count = self._count_or_delete_drift_events(run_ids, delete=False)
        else:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                run_ids = self._select_prunable_runs(policy, age_cutoff)
                drift_count = self._count_or_delete_drift_events(
                    run_ids, delete=True
                )
                for start in range(0, len(run_ids), _PRUNE_CHUNK_SIZE):
                    chunk = run_ids[start : start + _PRUNE_CHUNK_SIZE]
                    placeholders = ", ".join("?" for _ in chunk)
                    self._conn.execute(
                        f"DELETE FROM validation_runs WHERE run_id IN ({placeholders})",
                        chunk,
                    )
                self._conn.execute("COMMIT")
            except BaseException:
                if self._conn.in_transaction:
                    self._conn.execute("ROLLBACK")
                raise

        return PruneReport(
            dry_run=dry_run,
            policy=policy,
            now=now_dt,
            age_cutoff=age_cutoff,
            run_ids=run_ids,
            run_count=len(run_ids),
            drift_event_count=drift_count,
        )

    def get_item_streak(
        self,
        item_type: str,
        item_id: str,
        site_id: Optional[str] = None,
    ) -> Optional[ItemStreakSummary]:
        """Return the current ItemStreakSummary for `(item_type, item_id)` or None."""
        if site_id is not None:
            row = self._conn.execute(
                """
                SELECT * FROM item_streaks
                WHERE item_type = ? AND item_id = ? AND site_id = ?
                """,
                (item_type, item_id, site_id),
            ).fetchone()
        else:
            row = self._conn.execute(
                """
                SELECT * FROM item_streaks
                WHERE item_type = ? AND item_id = ?
                """,
                (item_type, item_id),
            ).fetchone()

        if row is None:
            return None
        return self._row_to_streak(row)

    def list_streaks(
        self,
        site_id: Optional[str] = None,
        min_consecutive_stale: int = 0,
        item_type: Optional[str] = None,
        classification: Optional[ValidationClassification | str] = None,
    ) -> list[ItemStreakSummary]:
        """Return tracked ItemStreakSummary records matching the given filters."""
        _require_non_negative_int(min_consecutive_stale, "min_consecutive_stale")

        clauses: list[str] = ["consecutive_stale_runs >= ?"]
        params: list[Any] = [min_consecutive_stale]

        if site_id is not None:
            clauses.append("site_id = ?")
            params.append(site_id)
        if item_type is not None:
            clauses.append("item_type = ?")
            params.append(item_type)
        if classification is not None:
            cls_enum = _coerce_classification(classification, "classification")
            clauses.append("current_classification = ?")
            params.append(cls_enum.value)

        where_sql = " AND ".join(clauses)
        rows = self._conn.execute(
            f"""
            SELECT * FROM item_streaks
            WHERE {where_sql}
            ORDER BY site_id ASC, item_type ASC, item_id ASC
            """,
            params,
        ).fetchall()
        return [self._row_to_streak(r) for r in rows]

    def detect_drift(
        self,
        run_id: Optional[str] = None,
        site_id: Optional[str] = None,
        transition_type: Optional[DriftTransitionType | str] = None,
    ) -> list[DriftEvent]:
        """Return DriftEvent records for `run_id` (or the latest recorded run when `run_id` is None)."""
        if run_id is None:
            latest_row = self._conn.execute(
                "SELECT run_id FROM validation_runs ORDER BY run_seq DESC LIMIT 1"
            ).fetchone()
            if latest_row is None:
                return []
            target_run_id = str(latest_row["run_id"])
        else:
            run_row = self._conn.execute(
                "SELECT run_id FROM validation_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if run_row is None:
                raise KeyError(
                    f"Validation run {run_id!r} not found in HistoryStore"
                )
            target_run_id = run_id

        clauses: list[str] = ["run_id = ?"]
        params: list[Any] = [target_run_id]

        if site_id is not None:
            clauses.append("site_id = ?")
            params.append(site_id)
        if transition_type is not None:
            trans_enum = _coerce_transition_type(
                transition_type, "transition_type"
            )
            clauses.append("transition_type = ?")
            params.append(trans_enum.value)

        where_sql = " AND ".join(clauses)
        rows = self._conn.execute(
            f"""
            SELECT * FROM drift_events
            WHERE {where_sql}
            ORDER BY event_id ASC
            """,
            params,
        ).fetchall()
        return [self._row_to_drift_event(r) for r in rows]
