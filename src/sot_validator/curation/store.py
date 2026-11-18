"""Curation overlay store, modifiable inventory CRUD operations, and immutable audit log."""

from __future__ import annotations

from sot_validator.curation._audit_chain import (
    AuditChainReport,
    _chain_entries,
    _compute_entry_hash,
    _validate_anchor,
    verify_audit_chain,
)
from sot_validator.curation._overlay import _format_pin_rationale, apply_curation_overlay
from sot_validator.curation._records import (
    GENESIS_HASH,
    VALID_TARGET_TYPES,
    AuditLogEntry,
    ItemEditPatch,
    _AUDIT_LOG_TARGET_TYPE,
    _CANONICAL_TARGET_TYPES,
    _HASH_PATTERN,
    _MIGRATION_REASON,
    _coerce_equipment_category,
    _coerce_validation_classification,
    _normalize_optional_hash,
    _normalize_optional_str,
    _normalize_optional_utc_datetime,
    _normalize_target_type,
    _require_non_negative_int,
)
from sot_validator.curation._store_core import _StoreCore
from sot_validator.curation._store_crud import _PATCH_MERGEABLE_FIELDS, _CrudMixin
from sot_validator.curation._store_io import _HybridImportMethod, _IoMixin


class CurationStore(_CrudMixin, _IoMixin, _StoreCore):
    """SQLite-backed curation overlay store for inventory edits, custom items, and audit logs."""

    def _migrate_legacy_audit_log(self) -> None:
        """Add hash columns to a legacy audit_log and chain its rows in place, once."""
        if self._audit_log_has_hash_columns():
            return
        with self._write_transaction():
            columns = {
                str(row[1])
                for row in self._conn.execute("PRAGMA table_info(audit_log)").fetchall()
            }
            if "prev_hash" in columns and "entry_hash" in columns:
                return
            for column in ("prev_hash", "entry_hash"):
                if column not in columns:
                    self._conn.execute(f"ALTER TABLE audit_log ADD COLUMN {column} TEXT")
            rows = self._conn.execute(
                "SELECT * FROM audit_log ORDER BY seq ASC"
            ).fetchall()
            legacy = [self._row_to_audit_entry(r) for r in rows]
            chained = _chain_entries(legacy)
            for row, entry in zip(rows, chained):
                self._conn.execute(
                    "UPDATE audit_log SET prev_hash = ?, entry_hash = ? WHERE seq = ? AND entry_hash IS NULL",
                    (entry.prev_hash, entry.entry_hash, row["seq"]),
                )
            if chained:
                self._record_migration_marker(chained, source="sqlite")


__all__ = [
    "AuditLogEntry",
    "CurationStore",
    "ItemEditPatch",
    "apply_curation_overlay",
]
