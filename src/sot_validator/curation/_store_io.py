"""Listing and JSON import/export mixin for CurationStore."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import TYPE_CHECKING, Any, Optional

from sot_validator.curation._audit_chain import _chain_entries, _compute_entry_hash
from sot_validator.curation._records import (
    AuditLogEntry,
    GENESIS_HASH,
    ItemEditPatch,
    _require_non_negative_int,
)
from sot_validator.models import (
    Equipment,
    NetworkDevice,
    Port,
    Subnet,
    VLAN,
    _require_non_empty_str,
)
from sot_validator.signals.base import normalize_utc_datetime

if TYPE_CHECKING:
    from sot_validator.curation.store import CurationStore


class _HybridImportMethod:
    """Descriptor allowing import_json to be invoked on either CurationStore class or instance."""

    def __init__(self, func: Any) -> None:
        self._func = func

    def __get__(self, instance: Any, owner: Any = None) -> Any:
        target = owner if instance is None else instance

        def _bound(*args: Any, **kwargs: Any) -> CurationStore:
            return self._func(target, *args, **kwargs)

        return _bound



class _IoMixin:
    def list_patches(self, site_id: Optional[str] = None) -> list[ItemEditPatch]:
        """Return stored ItemEditPatch records, filtered to `site_id` when provided."""
        if site_id is not None:
            clean_site = _require_non_empty_str(site_id, "site_id").strip()
            rows = self._conn.execute(
                """
                SELECT patch_json FROM item_patches
                WHERE site_id = ?
                ORDER BY target_type ASC, target_id ASC
                """,
                (clean_site,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT patch_json FROM item_patches
                ORDER BY target_type ASC, target_id ASC
                """
            ).fetchall()
        return [ItemEditPatch.from_json(r["patch_json"]) for r in rows]

    @staticmethod
    def _row_to_audit_entry(row: sqlite3.Row) -> AuditLogEntry:
        return AuditLogEntry(
            entry_id=row["entry_id"],
            timestamp=normalize_utc_datetime(
                row["timestamp"], field_name="timestamp"
            ),
            actor=row["actor"],
            action=row["action"],
            target_type=row["target_type"],
            target_id=row["target_id"],
            changes=json.loads(row["changes_json"]),
            reason=row["reason"],
            site_id=row["site_id"],
            prev_hash=row["prev_hash"],
            entry_hash=row["entry_hash"],
        )

    def list_audit_log(
        self, site_id: Optional[str] = None, limit: int = 100
    ) -> list[AuditLogEntry]:
        """Return recorded AuditLogEntry items in chronological order, filtered by `site_id` and bounded by `limit`."""
        _require_non_negative_int(limit, "limit")
        if limit == 0:
            return []

        if site_id is None:
            rows = self._conn.execute(
                "SELECT * FROM audit_log ORDER BY seq ASC LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._row_to_audit_entry(r) for r in rows]

        clean_site = _require_non_empty_str(site_id, "site_id").strip()
        all_rows = self._conn.execute(
            "SELECT * FROM audit_log ORDER BY seq ASC"
        ).fetchall()
        matched: list[AuditLogEntry] = []
        for row in all_rows:
            row_site = row["site_id"] or self._infer_site_id(
                row["target_type"], row["target_id"]
            )
            if row_site == clean_site:
                matched.append(self._row_to_audit_entry(row))
                if len(matched) >= limit:
                    break
        return matched

    def _list_custom_devices(
        self, site_id: Optional[str] = None
    ) -> list[NetworkDevice]:
        if site_id is not None:
            rows = self._conn.execute(
                "SELECT device_json FROM custom_devices WHERE site_id = ? ORDER BY device_id ASC",
                (site_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT device_json FROM custom_devices ORDER BY device_id ASC"
            ).fetchall()
        return [NetworkDevice.from_json(r["device_json"]) for r in rows]

    def _list_custom_equipment(
        self, site_id: Optional[str] = None
    ) -> list[Equipment]:
        if site_id is not None:
            rows = self._conn.execute(
                "SELECT equipment_json FROM custom_equipment WHERE site_id = ? ORDER BY equipment_id ASC",
                (site_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT equipment_json FROM custom_equipment ORDER BY equipment_id ASC"
            ).fetchall()
        return [Equipment.from_json(r["equipment_json"]) for r in rows]

    def _list_custom_vlans(self, site_id: Optional[str] = None) -> list[VLAN]:
        if site_id is not None:
            rows = self._conn.execute(
                "SELECT vlan_json FROM custom_vlans WHERE site_id = ? ORDER BY vlan_id ASC",
                (site_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT vlan_json FROM custom_vlans ORDER BY site_id ASC, vlan_id ASC"
            ).fetchall()
        return [VLAN.from_json(r["vlan_json"]) for r in rows]

    def _list_custom_subnets(self, site_id: Optional[str] = None) -> list[Subnet]:
        if site_id is not None:
            rows = self._conn.execute(
                "SELECT subnet_json FROM custom_subnets WHERE site_id = ? ORDER BY subnet_id ASC",
                (site_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT subnet_json FROM custom_subnets ORDER BY site_id ASC, subnet_id ASC"
            ).fetchall()
        return [Subnet.from_json(r["subnet_json"]) for r in rows]

    def _list_custom_ports(
        self, site_id: Optional[str] = None
    ) -> list[tuple[str, Optional[str], Port]]:
        if site_id is not None:
            rows = self._conn.execute(
                """
                SELECT device_id, site_id, port_json FROM custom_ports
                WHERE site_id IS NULL OR site_id = ?
                ORDER BY device_id ASC, port_id ASC
                """,
                (site_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT device_id, site_id, port_json FROM custom_ports ORDER BY device_id ASC, port_id ASC"
            ).fetchall()
        return [
            (str(r["device_id"]), r["site_id"], Port.from_json(r["port_json"]))
            for r in rows
        ]

    def _list_all_audit_log(self) -> list[AuditLogEntry]:
        rows = self._conn.execute(
            "SELECT * FROM audit_log ORDER BY seq ASC"
        ).fetchall()
        return [self._row_to_audit_entry(r) for r in rows]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the complete CurationStore state to a dictionary."""
        return {
            "patches": [p.to_dict() for p in self.list_patches()],
            "custom_devices": [d.to_dict() for d in self._list_custom_devices()],
            "custom_equipment": [e.to_dict() for e in self._list_custom_equipment()],
            "custom_vlans": [v.to_dict() for v in self._list_custom_vlans()],
            "custom_subnets": [s.to_dict() for s in self._list_custom_subnets()],
            "custom_ports": [
                {
                    "device_id": dev_id,
                    "site_id": s_id,
                    "port": port.to_dict(),
                }
                for dev_id, s_id, port in self._list_custom_ports()
            ],
            "audit_log": [a.to_dict() for a in self._list_all_audit_log()],
        }

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        """Serialize the complete CurationStore state to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def export_json(
        self, path: Path | str, *, indent: Optional[int] = 2
    ) -> Path:
        """Write the complete CurationStore state to a JSON file on disk."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.to_json(indent=indent), encoding="utf-8")
        return target

    def _load_state_from_mapping(self, data: Mapping[str, Any]) -> None:
        if not isinstance(data, Mapping):
            raise ValueError("CurationStore state data must be a mapping")

        patches = [
            p if isinstance(p, ItemEditPatch) else ItemEditPatch.from_dict(p)
            for p in data.get("patches", [])
        ]
        devices = [
            d if isinstance(d, NetworkDevice) else NetworkDevice.from_dict(d)
            for d in data.get("custom_devices", [])
        ]
        equipment = [
            e if isinstance(e, Equipment) else Equipment.from_dict(e)
            for e in data.get("custom_equipment", [])
        ]
        vlans = [
            v if isinstance(v, VLAN) else VLAN.from_dict(v)
            for v in data.get("custom_vlans", [])
        ]
        subnets = [
            s if isinstance(s, Subnet) else Subnet.from_dict(s)
            for s in data.get("custom_subnets", [])
        ]
        raw_ports = data.get("custom_ports", [])
        ports: list[tuple[str, Optional[str], Port]] = []
        for item in raw_ports:
            if isinstance(item, Port):
                ports.append((item.device_id, None, item))
            elif isinstance(item, Mapping) and "port" in item:
                p_obj = (
                    item["port"]
                    if isinstance(item["port"], Port)
                    else Port.from_dict(item["port"])
                )
                dev_id = str(item.get("device_id") or p_obj.device_id)
                if p_obj.device_id != dev_id:
                    p_obj = replace(p_obj, device_id=dev_id)
                ports.append((dev_id, item.get("site_id"), p_obj))
            elif isinstance(item, Mapping):
                p_obj = Port.from_dict(item)
                ports.append((p_obj.device_id, item.get("site_id"), p_obj))
            else:
                raise ValueError(f"Invalid custom_ports entry: {item!r}")

        audit_entries = [
            a if isinstance(a, AuditLogEntry) else AuditLogEntry.from_dict(a)
            for a in data.get("audit_log", [])
        ]
        hashed_flags = [
            a.prev_hash is not None and a.entry_hash is not None for a in audit_entries
        ]
        unhashed_flags = [
            a.prev_hash is None and a.entry_hash is None for a in audit_entries
        ]
        if all(hashed_flags):
            expected_prev = GENESIS_HASH
            for idx, entry in enumerate(audit_entries):
                if entry.prev_hash != expected_prev or (
                    _compute_entry_hash(entry) != entry.entry_hash
                ):
                    raise ValueError(
                        f"audit_log hash chain is broken at index {idx}; refusing import"
                    )
                expected_prev = entry.entry_hash
            legacy_import = False
        elif all(unhashed_flags):
            audit_entries = _chain_entries(audit_entries)
            legacy_import = True
        else:
            raise ValueError(
                "audit_log mixes hash-chained and unhashed entries; refusing import"
            )

        with self._write_transaction():
            count_row = self._conn.execute(
                "SELECT COUNT(*) AS cnt FROM audit_log"
            ).fetchone()
            if int(count_row["cnt"]) > 0:
                raise ValueError(
                    "Refusing to import curation state into a store that already has "
                    "audit log entries; the audit log is append-only"
                )
            self._conn.execute("DELETE FROM custom_ports")
            self._conn.execute("DELETE FROM custom_subnets")
            self._conn.execute("DELETE FROM custom_vlans")
            self._conn.execute("DELETE FROM custom_equipment")
            self._conn.execute("DELETE FROM custom_devices")
            self._conn.execute("DELETE FROM item_patches")

            for p in patches:
                updated_ts = (
                    p.updated_at.isoformat()
                    if p.updated_at is not None
                    else datetime.now(timezone.utc).isoformat()
                )
                self._conn.execute(
                    """
                    INSERT INTO item_patches (
                        target_type, target_id, site_id, patch_json, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        p.target_type,
                        p.target_id,
                        p.site_id,
                        p.to_json(),
                        updated_ts,
                    ),
                )

            for d in devices:
                self._conn.execute(
                    """
                    INSERT INTO custom_devices (device_id, site_id, device_json)
                    VALUES (?, ?, ?)
                    """,
                    (d.device_id, d.site_id, d.to_json()),
                )

            for e in equipment:
                self._conn.execute(
                    """
                    INSERT INTO custom_equipment (equipment_id, site_id, equipment_json)
                    VALUES (?, ?, ?)
                    """,
                    (e.equipment_id, e.site_id, e.to_json()),
                )

            for v in vlans:
                self._conn.execute(
                    """
                    INSERT INTO custom_vlans (site_id, vlan_id, vlan_json)
                    VALUES (?, ?, ?)
                    """,
                    (v.site_id, v.vlan_id, v.to_json()),
                )

            for s in subnets:
                self._conn.execute(
                    """
                    INSERT INTO custom_subnets (site_id, subnet_id, subnet_json)
                    VALUES (?, ?, ?)
                    """,
                    (s.site_id, s.subnet_id, s.to_json()),
                )

            for dev_id, s_id, port_obj in ports:
                self._conn.execute(
                    """
                    INSERT INTO custom_ports (device_id, port_id, site_id, port_json)
                    VALUES (?, ?, ?, ?)
                    """,
                    (dev_id, port_obj.port_id, s_id, port_obj.to_json()),
                )

            for entry in audit_entries:
                self._insert_audit_entry(entry)
            if legacy_import and audit_entries:
                self._record_migration_marker(audit_entries, source="json")

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        db_path: Path | str = ":memory:",
    ) -> CurationStore:
        """Create and populate a CurationStore from a serialized dictionary."""
        store = cls(db_path=db_path)
        store._load_state_from_mapping(data)
        return store

    @classmethod
    def from_json(
        cls,
        raw: str,
        db_path: Path | str = ":memory:",
    ) -> CurationStore:
        """Create and populate a CurationStore from a JSON string."""
        return cls.from_dict(json.loads(raw), db_path=db_path)

    def _import_json_impl(
        target: Any,
        path: Path | str,
        db_path: Path | str = ":memory:",
    ) -> CurationStore:
        from sot_validator.curation.store import CurationStore

        raw = Path(path).read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(target, CurationStore):
            target._load_state_from_mapping(data)
            return target
        return target.from_dict(data, db_path=db_path)

    import_json = _HybridImportMethod(_import_json_impl)
