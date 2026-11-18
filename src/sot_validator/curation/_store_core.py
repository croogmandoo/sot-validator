"""Connection, schema, transaction, and audit-recording core of CurationStore."""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import TYPE_CHECKING, Any, Optional
import uuid

from sot_validator.curation._audit_chain import _compute_entry_hash
from sot_validator.curation._records import (
    AuditLogEntry,
    GENESIS_HASH,
    _AUDIT_LOG_TARGET_TYPE,
    _MIGRATION_REASON,
)
from sot_validator.extraction.sql_export import open_read_only_sqlite

if TYPE_CHECKING:
    from sot_validator.curation.store import CurationStore


class _StoreCore:
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
        self._init_schema()

    @classmethod
    def open_read_only(cls, db_path: Path | str) -> CurationStore:
        """Open an existing curation DB read-only: no schema creation, migration, or writes."""
        path = Path(db_path)
        if not path.is_file():
            raise ValueError(f"curation database {str(path)!r} does not exist or is not a file")
        store = cls.__new__(cls)
        store.db_path = path
        store._conn = open_read_only_sqlite(path)
        store._conn.row_factory = sqlite3.Row
        return store

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS item_patches (
                    target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    site_id TEXT,
                    patch_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (target_type, target_id)
                );

                CREATE TABLE IF NOT EXISTS custom_devices (
                    device_id TEXT PRIMARY KEY,
                    site_id TEXT NOT NULL,
                    device_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS custom_equipment (
                    equipment_id TEXT PRIMARY KEY,
                    site_id TEXT NOT NULL,
                    equipment_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS custom_vlans (
                    site_id TEXT NOT NULL,
                    vlan_id TEXT NOT NULL,
                    vlan_json TEXT NOT NULL,
                    PRIMARY KEY (site_id, vlan_id)
                );

                CREATE TABLE IF NOT EXISTS custom_subnets (
                    site_id TEXT NOT NULL,
                    subnet_id TEXT NOT NULL,
                    subnet_json TEXT NOT NULL,
                    PRIMARY KEY (site_id, subnet_id)
                );

                CREATE TABLE IF NOT EXISTS custom_ports (
                    device_id TEXT NOT NULL,
                    port_id TEXT NOT NULL,
                    site_id TEXT,
                    port_json TEXT NOT NULL,
                    PRIMARY KEY (device_id, port_id)
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_id TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    changes_json TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    site_id TEXT,
                    prev_hash TEXT,
                    entry_hash TEXT
                );
                """
            )
        self._migrate_legacy_audit_log()

    def _audit_log_has_hash_columns(self) -> bool:
        columns = {
            str(row[1])
            for row in self._conn.execute("PRAGMA table_info(audit_log)").fetchall()
        }
        return "prev_hash" in columns and "entry_hash" in columns

    def _record_migration_marker(
        self, chained_legacy: Sequence[AuditLogEntry], *, source: str
    ) -> AuditLogEntry:
        return self._record_audit(
            actor="system",
            action="migration",
            target_type=_AUDIT_LOG_TARGET_TYPE,
            target_id="audit_log",
            changes={
                "legacy_entries": len(chained_legacy),
                "legacy_head_hash": chained_legacy[-1].entry_hash,
                "source": source,
            },
            reason=_MIGRATION_REASON,
            site_id=None,
        )

    @contextmanager
    def _write_transaction(self) -> Iterator[sqlite3.Connection]:
        """Run a block inside one `BEGIN IMMEDIATE` transaction on the current connection."""
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()

    def __enter__(self) -> CurationStore:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _next_entry_id(self) -> str:
        row = self._conn.execute("SELECT COUNT(*) AS cnt FROM audit_log").fetchone()
        seq = (int(row["cnt"]) if row is not None else 0) + 1
        return f"audit-{seq:04d}-{uuid.uuid4().hex[:8]}"

    def _chain_head_hash(self) -> str:
        row = self._conn.execute(
            "SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return GENESIS_HASH
        head = row["entry_hash"]
        if head is None:
            raise ValueError(
                "audit_log head entry has no entry_hash; refusing to extend an unattested chain"
            )
        return str(head)

    def export_chain_head(self) -> tuple[int, str]:
        """Return `(entry_count, head_hash)` for the whole audit log, to be recorded as an external anchor."""
        row = self._conn.execute("SELECT COUNT(*) AS cnt FROM audit_log").fetchone()
        count = int(row["cnt"]) if row is not None else 0
        return count, self._chain_head_hash()

    def _insert_audit_entry(self, entry: AuditLogEntry) -> None:
        self._conn.execute(
            """
            INSERT INTO audit_log (
                entry_id, timestamp, actor, action, target_type, target_id,
                changes_json, reason, site_id, prev_hash, entry_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.entry_id,
                entry.timestamp.isoformat(),
                entry.actor,
                entry.action,
                entry.target_type,
                entry.target_id,
                json.dumps(entry.changes),
                entry.reason,
                entry.site_id,
                entry.prev_hash,
                entry.entry_hash,
            ),
        )

    def _infer_site_id(
        self, target_type: str, target_id: str, explicit_site_id: Optional[str] = None
    ) -> Optional[str]:
        if explicit_site_id is not None and explicit_site_id.strip():
            return explicit_site_id.strip()

        patch_row = self._conn.execute(
            "SELECT site_id FROM item_patches WHERE target_type = ? AND target_id = ?",
            (target_type, target_id),
        ).fetchone()
        if patch_row is not None and patch_row["site_id"]:
            return str(patch_row["site_id"])

        if target_type == "NetworkDevice":
            row = self._conn.execute(
                "SELECT site_id FROM custom_devices WHERE device_id = ?",
                (target_id,),
            ).fetchone()
            if row is not None and row["site_id"]:
                return str(row["site_id"])
        elif target_type == "Equipment":
            row = self._conn.execute(
                "SELECT site_id FROM custom_equipment WHERE equipment_id = ?",
                (target_id,),
            ).fetchone()
            if row is not None and row["site_id"]:
                return str(row["site_id"])
        elif target_type == "VLAN":
            row = self._conn.execute(
                "SELECT site_id FROM custom_vlans WHERE vlan_id = ? LIMIT 1",
                (target_id,),
            ).fetchone()
            if row is not None and row["site_id"]:
                return str(row["site_id"])
        elif target_type == "Subnet":
            row = self._conn.execute(
                "SELECT site_id FROM custom_subnets WHERE subnet_id = ? LIMIT 1",
                (target_id,),
            ).fetchone()
            if row is not None and row["site_id"]:
                return str(row["site_id"])
        elif target_type == "Port":
            row = self._conn.execute(
                "SELECT site_id, device_id FROM custom_ports WHERE port_id = ? LIMIT 1",
                (target_id,),
            ).fetchone()
            if row is not None:
                if row["site_id"]:
                    return str(row["site_id"])
                dev_row = self._conn.execute(
                    "SELECT site_id FROM custom_devices WHERE device_id = ?",
                    (row["device_id"],),
                ).fetchone()
                if dev_row is not None and dev_row["site_id"]:
                    return str(dev_row["site_id"])

        return None

    def _record_audit(
        self,
        *,
        actor: str,
        action: str,
        target_type: str,
        target_id: str,
        changes: Mapping[str, Any],
        reason: str = "",
        site_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> AuditLogEntry:
        """Append a chained audit row; callers must already hold a `_write_transaction`."""
        unhashed = AuditLogEntry(
            entry_id=self._next_entry_id(),
            timestamp=timestamp or datetime.now(timezone.utc),
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            changes=dict(changes),
            reason=reason,
            site_id=site_id,
            prev_hash=self._chain_head_hash(),
        )
        entry = replace(unhashed, entry_hash=_compute_entry_hash(unhashed))
        self._insert_audit_entry(entry)
        return entry
