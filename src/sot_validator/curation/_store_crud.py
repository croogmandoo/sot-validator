"""Patch and custom-item CRUD mixin for CurationStore."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Optional

from sot_validator.curation._records import (
    AuditLogEntry,
    ItemEditPatch,
    _normalize_optional_str,
    _normalize_target_type,
)
from sot_validator.models import (
    Equipment,
    NetworkDevice,
    Port,
    Subnet,
    VLAN,
    _require_non_empty_str,
)

_PATCH_MERGEABLE_FIELDS: tuple[str, ...] = (
    "site_id",
    "name",
    "hostname",
    "category",
    "role",
    "vendor",
    "model",
    "vlan_id",
    "subnet_id",
    "room",
    "notes",
    "pinned_classification",
)


class _CrudMixin:
    def get_patch(
        self, target_type: str, target_id: str
    ) -> Optional[ItemEditPatch]:
        """Return the stored ItemEditPatch for `(target_type, target_id)`, or None."""
        norm_type = _normalize_target_type(target_type, "target_type")
        clean_id = _require_non_empty_str(target_id, "target_id").strip()
        row = self._conn.execute(
            "SELECT patch_json FROM item_patches WHERE target_type = ? AND target_id = ?",
            (norm_type, clean_id),
        ).fetchone()
        if row is None:
            return None
        return ItemEditPatch.from_json(row["patch_json"])

    def upsert_patch(
        self,
        patch: ItemEditPatch | Mapping[str, Any],
        actor: str = "operator",
        reason: str = "",
    ) -> AuditLogEntry:
        """Insert or merge an ItemEditPatch and record an AuditLogEntry."""
        incoming = (
            patch
            if isinstance(patch, ItemEditPatch)
            else ItemEditPatch.from_dict(patch)
        )
        now = incoming.updated_at or datetime.now(timezone.utc)

        with self._write_transaction():
            return self._upsert_patch_locked(incoming, now, actor, reason)

    def _upsert_patch_locked(
        self,
        incoming: ItemEditPatch,
        now: datetime,
        actor: str,
        reason: str,
        *,
        batch_id: Optional[str] = None,
    ) -> AuditLogEntry:
        existing = self.get_patch(incoming.target_type, incoming.target_id)
        resolved_site_id = self._infer_site_id(
            incoming.target_type, incoming.target_id, incoming.site_id
        )

        if existing is not None:
            merged_kwargs: dict[str, Any] = {
                "target_type": incoming.target_type,
                "target_id": incoming.target_id,
                "site_id": resolved_site_id or existing.site_id,
                "updated_at": now,
                "deleted": incoming.deleted,
            }
            for fname in _PATCH_MERGEABLE_FIELDS:
                if fname == "site_id":
                    continue
                inc_val = getattr(incoming, fname)
                merged_kwargs[fname] = (
                    inc_val if inc_val is not None else getattr(existing, fname)
                )
            merged_custom = dict(existing.custom_attributes)
            merged_custom.update(incoming.custom_attributes)
            merged_kwargs["custom_attributes"] = merged_custom
            stored_patch = ItemEditPatch(**merged_kwargs)
        else:
            stored_patch = replace(
                incoming,
                site_id=resolved_site_id,
                updated_at=now,
            )

        changes: dict[str, Any] = {}
        patch_dict = incoming.to_dict()
        for fname in _PATCH_MERGEABLE_FIELDS:
            if patch_dict.get(fname) is not None:
                changes[fname] = patch_dict[fname]
        if incoming.custom_attributes:
            changes["custom_attributes"] = dict(incoming.custom_attributes)
        if incoming.deleted or (existing is not None and existing.deleted != incoming.deleted):
            changes["deleted"] = incoming.deleted
        if batch_id is not None:
            changes["batch_id"] = batch_id

        self._conn.execute(
            """
            INSERT INTO item_patches (
                target_type, target_id, site_id, patch_json, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(target_type, target_id) DO UPDATE SET
                site_id = excluded.site_id,
                patch_json = excluded.patch_json,
                updated_at = excluded.updated_at
            """,
            (
                stored_patch.target_type,
                stored_patch.target_id,
                stored_patch.site_id,
                stored_patch.to_json(),
                now.isoformat(),
            ),
        )
        return self._record_audit(
            actor=actor,
            action="UPSERT_PATCH",
            target_type=stored_patch.target_type,
            target_id=stored_patch.target_id,
            changes=changes,
            reason=reason,
            site_id=stored_patch.site_id,
            timestamp=now,
        )

    def add_custom_device(
        self,
        device: NetworkDevice | Mapping[str, Any],
        actor: str = "operator",
        reason: str = "",
    ) -> AuditLogEntry:
        """Persist a custom NetworkDevice and record an AuditLogEntry."""
        dev = (
             NetworkDevice.from_dict(device.to_dict())
            if isinstance(device, NetworkDevice)
            else NetworkDevice.from_dict(device)
        )
        with self._write_transaction():
            existing_patch = self.get_patch("NetworkDevice", dev.device_id)
            self._conn.execute(
                """
                INSERT INTO custom_devices (device_id, site_id, device_json)
                VALUES (?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    site_id = excluded.site_id,
                    device_json = excluded.device_json
                """,
                (dev.device_id, dev.site_id, dev.to_json()),
            )
            for p in dev.ports:
                norm_port = (
                    p
                    if p.device_id == dev.device_id
                    else replace(p, device_id=dev.device_id)
                )
                self._conn.execute(
                    """
                    INSERT INTO custom_ports (device_id, port_id, site_id, port_json)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(device_id, port_id) DO UPDATE SET
                        site_id = excluded.site_id,
                        port_json = excluded.port_json
                    """,
                    (
                        dev.device_id,
                        norm_port.port_id,
                        dev.site_id,
                        norm_port.to_json(),
                    ),
                )
            if existing_patch is not None and existing_patch.deleted:
                undeleted = replace(
                    existing_patch,
                    site_id=existing_patch.site_id or dev.site_id,
                    deleted=False,
                    updated_at=datetime.now(timezone.utc),
                )
                self._conn.execute(
                    """
                    UPDATE item_patches
                    SET site_id = ?, patch_json = ?, updated_at = ?
                    WHERE target_type = 'NetworkDevice' AND target_id = ?
                    """,
                    (
                        undeleted.site_id,
                        undeleted.to_json(),
                        undeleted.updated_at.isoformat() if undeleted.updated_at else "",
                        dev.device_id,
                    ),
                )
            return self._record_audit(
                actor=actor,
                action="ADD_DEVICE",
                target_type="NetworkDevice",
                target_id=dev.device_id,
                changes=dev.to_dict(),
                reason=reason,
                site_id=dev.site_id,
            )

    def add_custom_equipment(
        self,
        equipment: Equipment | Mapping[str, Any],
        actor: str = "operator",
        reason: str = "",
    ) -> AuditLogEntry:
        """Persist a custom Equipment item and record an AuditLogEntry."""
        eq = (
            Equipment.from_dict(equipment.to_dict())
            if isinstance(equipment, Equipment)
            else Equipment.from_dict(equipment)
        )
        with self._write_transaction():
            existing_patch = self.get_patch("Equipment", eq.equipment_id)
            self._conn.execute(
                """
                INSERT INTO custom_equipment (equipment_id, site_id, equipment_json)
                VALUES (?, ?, ?)
                ON CONFLICT(equipment_id) DO UPDATE SET
                    site_id = excluded.site_id,
                    equipment_json = excluded.equipment_json
                """,
                (eq.equipment_id, eq.site_id, eq.to_json()),
            )
            if existing_patch is not None and existing_patch.deleted:
                undeleted = replace(
                    existing_patch,
                    site_id=existing_patch.site_id or eq.site_id,
                    deleted=False,
                    updated_at=datetime.now(timezone.utc),
                )
                self._conn.execute(
                    """
                    UPDATE item_patches
                    SET site_id = ?, patch_json = ?, updated_at = ?
                    WHERE target_type = 'Equipment' AND target_id = ?
                    """,
                    (
                        undeleted.site_id,
                        undeleted.to_json(),
                        undeleted.updated_at.isoformat() if undeleted.updated_at else "",
                        eq.equipment_id,
                    ),
                )
            return self._record_audit(
                actor=actor,
                action="ADD_EQUIPMENT",
                target_type="Equipment",
                target_id=eq.equipment_id,
                changes=eq.to_dict(),
                reason=reason,
                site_id=eq.site_id,
            )

    def add_custom_vlan(
        self,
        vlan: VLAN | Mapping[str, Any],
        subnet: Optional[Subnet | Mapping[str, Any]] = None,
        actor: str = "operator",
        reason: str = "",
    ) -> AuditLogEntry:
        """Persist a custom VLAN and optional associated Subnet, recording an AuditLogEntry."""
        vlan_obj = (
            VLAN.from_dict(vlan.to_dict())
            if isinstance(vlan, VLAN)
            else VLAN.from_dict(vlan)
        )
        subnet_obj: Optional[Subnet] = None
        if subnet is not None:
            subnet_obj = (
                Subnet.from_dict(subnet.to_dict())
                if isinstance(subnet, Subnet)
                else Subnet.from_dict(subnet)
            )

        with self._write_transaction():
            existing_vlan_patch = self.get_patch("VLAN", vlan_obj.vlan_id)
            self._conn.execute(
                """
                INSERT INTO custom_vlans (site_id, vlan_id, vlan_json)
                VALUES (?, ?, ?)
                ON CONFLICT(site_id, vlan_id) DO UPDATE SET
                    vlan_json = excluded.vlan_json
                """,
                (vlan_obj.site_id, vlan_obj.vlan_id, vlan_obj.to_json()),
            )
            if existing_vlan_patch is not None and existing_vlan_patch.deleted:
                undeleted = replace(
                    existing_vlan_patch,
                    site_id=existing_vlan_patch.site_id or vlan_obj.site_id,
                    deleted=False,
                    updated_at=datetime.now(timezone.utc),
                )
                self._conn.execute(
                    """
                    UPDATE item_patches
                    SET site_id = ?, patch_json = ?, updated_at = ?
                    WHERE target_type = 'VLAN' AND target_id = ?
                    """,
                    (
                        undeleted.site_id,
                        undeleted.to_json(),
                        undeleted.updated_at.isoformat() if undeleted.updated_at else "",
                        vlan_obj.vlan_id,
                    ),
                )
            if subnet_obj is not None:
                self._conn.execute(
                    """
                    INSERT INTO custom_subnets (site_id, subnet_id, subnet_json)
                    VALUES (?, ?, ?)
                    ON CONFLICT(site_id, subnet_id) DO UPDATE SET
                        subnet_json = excluded.subnet_json
                    """,
                    (
                        subnet_obj.site_id,
                        subnet_obj.subnet_id,
                        subnet_obj.to_json(),
                    ),
                )

            changes: dict[str, Any] = {"vlan": vlan_obj.to_dict()}
            if subnet_obj is not None:
                changes["subnet"] = subnet_obj.to_dict()

            return self._record_audit(
                actor=actor,
                action="ADD_VLAN",
                target_type="VLAN",
                target_id=vlan_obj.vlan_id,
                changes=changes,
                reason=reason,
                site_id=vlan_obj.site_id,
            )

    def add_or_update_port(
        self,
        device_id: str,
        port: Port | Mapping[str, Any],
        actor: str = "operator",
        reason: str = "",
        site_id: Optional[str] = None,
    ) -> AuditLogEntry:
        """Persist a custom or updated Port on `device_id` and record an AuditLogEntry."""
        clean_dev_id = _require_non_empty_str(device_id, "device_id").strip()
        port_obj = (
            Port.from_dict(port.to_dict())
            if isinstance(port, Port)
            else Port.from_dict(port)
        )
        if port_obj.device_id != clean_dev_id:
            port_obj = replace(port_obj, device_id=clean_dev_id)

        explicit_site_id = _normalize_optional_str(site_id, "site_id")

        with self._write_transaction():
            resolved_site_id = (
                explicit_site_id
                or self._infer_site_id("NetworkDevice", clean_dev_id)
                or self._infer_site_id("Port", port_obj.port_id)
            )
            existing_patch = self.get_patch("Port", port_obj.port_id)

            self._conn.execute(
                """
                INSERT INTO custom_ports (device_id, port_id, site_id, port_json)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(device_id, port_id) DO UPDATE SET
                    site_id = COALESCE(excluded.site_id, custom_ports.site_id),
                    port_json = excluded.port_json
                """,
                (
                    clean_dev_id,
                    port_obj.port_id,
                    resolved_site_id,
                    port_obj.to_json(),
                ),
            )
            dev_row = self._conn.execute(
                "SELECT device_json FROM custom_devices WHERE device_id = ?",
                (clean_dev_id,),
            ).fetchone()
            if dev_row is not None:
                dev = NetworkDevice.from_json(dev_row["device_json"])
                updated_ports: list[Port] = []
                replaced = False
                for existing_p in dev.ports:
                    if existing_p.port_id == port_obj.port_id:
                        updated_ports.append(port_obj)
                        replaced = True
                    else:
                        updated_ports.append(existing_p)
                if not replaced:
                    updated_ports.append(port_obj)
                dev.ports = updated_ports
                self._conn.execute(
                    "UPDATE custom_devices SET device_json = ? WHERE device_id = ?",
                    (dev.to_json(), clean_dev_id),
                )
            if existing_patch is not None and existing_patch.deleted:
                undeleted = replace(
                    existing_patch,
                    site_id=existing_patch.site_id or resolved_site_id,
                    deleted=False,
                    updated_at=datetime.now(timezone.utc),
                )
                self._conn.execute(
                    """
                    UPDATE item_patches
                    SET site_id = ?, patch_json = ?, updated_at = ?
                    WHERE target_type = 'Port' AND target_id = ?
                    """,
                    (
                        undeleted.site_id,
                        undeleted.to_json(),
                        undeleted.updated_at.isoformat() if undeleted.updated_at else "",
                        port_obj.port_id,
                    ),
                )
            return self._record_audit(
                actor=actor,
                action="UPSERT_PORT",
                target_type="Port",
                target_id=port_obj.port_id,
                changes=port_obj.to_dict(),
                reason=reason,
                site_id=resolved_site_id,
            )

    def delete_item(
        self,
        target_type: str,
        target_id: str,
        actor: str = "operator",
        reason: str = "",
        site_id: Optional[str] = None,
    ) -> AuditLogEntry:
        """Mark `(target_type, target_id)` as deleted and record an AuditLogEntry."""
        norm_type = _normalize_target_type(target_type, "target_type")
        clean_id = _require_non_empty_str(target_id, "target_id").strip()

        with self._write_transaction():
            return self._delete_item_locked(
                norm_type, clean_id, actor, reason, site_id
            )

    def _delete_item_locked(
        self,
        norm_type: str,
        clean_id: str,
        actor: str,
        reason: str,
        site_id: Optional[str],
        *,
        batch_id: Optional[str] = None,
    ) -> AuditLogEntry:
        resolved_site_id = self._infer_site_id(norm_type, clean_id, site_id)
        existing = self.get_patch(norm_type, clean_id)
        now = datetime.now(timezone.utc)

        if existing is not None:
            deleted_patch = replace(
                existing,
                site_id=resolved_site_id or existing.site_id,
                deleted=True,
                updated_at=now,
            )
        else:
            deleted_patch = ItemEditPatch(
                target_type=norm_type,
                target_id=clean_id,
                site_id=resolved_site_id,
                deleted=True,
                updated_at=now,
            )

        self._conn.execute(
            """
            INSERT INTO item_patches (
                target_type, target_id, site_id, patch_json, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(target_type, target_id) DO UPDATE SET
                site_id = excluded.site_id,
                patch_json = excluded.patch_json,
                updated_at = excluded.updated_at
            """,
            (
                deleted_patch.target_type,
                deleted_patch.target_id,
                deleted_patch.site_id,
                deleted_patch.to_json(),
                now.isoformat(),
            ),
        )

        if norm_type == "NetworkDevice":
            self._conn.execute(
                "DELETE FROM custom_devices WHERE device_id = ?",
                (clean_id,),
            )
            self._conn.execute(
                "DELETE FROM custom_ports WHERE device_id = ?",
                (clean_id,),
            )
        elif norm_type == "Equipment":
            self._conn.execute(
                "DELETE FROM custom_equipment WHERE equipment_id = ?",
                (clean_id,),
            )
        elif norm_type == "VLAN":
            if resolved_site_id is not None:
                self._conn.execute(
                    "DELETE FROM custom_vlans WHERE site_id = ? AND vlan_id = ?",
                    (resolved_site_id, clean_id),
                )
            else:
                self._conn.execute(
                    "DELETE FROM custom_vlans WHERE vlan_id = ?",
                    (clean_id,),
                )
        elif norm_type == "Subnet":
            if resolved_site_id is not None:
                self._conn.execute(
                    "DELETE FROM custom_subnets WHERE site_id = ? AND subnet_id = ?",
                    (resolved_site_id, clean_id),
                )
            else:
                self._conn.execute(
                    "DELETE FROM custom_subnets WHERE subnet_id = ?",
                    (clean_id,),
                )
        elif norm_type == "Port":
            self._conn.execute(
                "DELETE FROM custom_ports WHERE port_id = ?",
                (clean_id,),
            )
            dev_rows = self._conn.execute(
                "SELECT device_id, device_json FROM custom_devices"
            ).fetchall()
            for dev_row in dev_rows:
                dev = NetworkDevice.from_json(dev_row["device_json"])
                filtered_ports = [
                    p for p in dev.ports if p.port_id != clean_id
                ]
                if len(filtered_ports) != len(dev.ports):
                    dev.ports = filtered_ports
                    self._conn.execute(
                        "UPDATE custom_devices SET device_json = ? WHERE device_id = ?",
                        (dev.to_json(), dev.device_id),
                    )

        changes: dict[str, Any] = {"deleted": True}
        if batch_id is not None:
            changes["batch_id"] = batch_id
        return self._record_audit(
            actor=actor,
            action="DELETE_ITEM",
            target_type=norm_type,
            target_id=clean_id,
            changes=changes,
            reason=reason,
            site_id=deleted_patch.site_id,
            timestamp=now,
        )
