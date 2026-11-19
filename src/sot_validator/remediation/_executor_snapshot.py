"""Site snapshot resolution and approval manifest filtering for remediation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import re
import sqlite3
from typing import Any, Optional

from sot_validator.models import IPAddress, Site
from sot_validator.remediation._executor_common import (
    ManifestVerificationError,
    RemediationExecutionError,
    _format_sql_datetime,
)
from sot_validator.remediation.quarantine import (
    ApprovalStatus,
    QuarantineManifestEntry,
    RemediationApprovalManifest,
)


def _normalize_sites_lookup(
    sites: Optional[Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]],
) -> dict[str, Site]:
    if sites is None:
        return {}
    if isinstance(sites, Site):
        return {sites.site_id: sites}
    if isinstance(sites, Mapping):
        if "site_id" in sites and "name" in sites:
            site_obj = Site.from_dict(sites)
            return {site_obj.site_id: site_obj}
        result: dict[str, Site] = {}
        for key, val in sites.items():
            if isinstance(val, Site):
                result[val.site_id] = val
            elif isinstance(val, Mapping) and "site_id" in val:
                site_obj = Site.from_dict(val)
                result[site_obj.site_id] = site_obj
            else:
                raise ValueError(f"Unsupported site mapping value for {key!r}")
        return result
    if isinstance(sites, Sequence) and not isinstance(sites, (str, bytes)):
        result = {}
        for item in sites:
            site_obj = item if isinstance(item, Site) else Site.from_dict(item)
            result[site_obj.site_id] = site_obj
        return result
    raise ValueError(f"Unsupported sites argument: {type(sites)!r}")


def _validate_and_filter_manifest_entries(
    manifest: RemediationApprovalManifest,
    *,
    strict_approval: bool = False,
) -> tuple[list[QuarantineManifestEntry], list[QuarantineManifestEntry]]:
    if not isinstance(manifest, RemediationApprovalManifest):
        raise ManifestVerificationError(
            "manifest must be a RemediationApprovalManifest instance"
        )
    if not manifest.verify_digest():
        raise ManifestVerificationError(
            f"Manifest {manifest.manifest_id!r} failed SHA-256 digest verification; "
            "manifest content or signature has been tampered with"
        )

    if strict_approval:
        unapproved = [
            e
            for e in manifest.entries
            if e.approval_status not in (ApprovalStatus.APPROVED, ApprovalStatus.EXEMPT)
        ]
        if unapproved:
            ids = ", ".join(e.item_id for e in unapproved)
            raise RemediationExecutionError(
                f"Manifest {manifest.manifest_id!r} contains unapproved entries under strict_approval=True: {ids}"
            )

    approved = [
        e
        for e in manifest.entries
        if e.approval_status is ApprovalStatus.APPROVED
    ]
    skipped = [
        e
        for e in manifest.entries
        if e.approval_status is not ApprovalStatus.APPROVED
    ]
    if not approved:
        raise RemediationExecutionError(
            f"Manifest {manifest.manifest_id!r} has no APPROVED entries to execute"
        )

    approved.sort(key=lambda e: (e.site_id, e.item_type, e.item_id))
    return approved, skipped


def _table_has_column(conn: sqlite3.Connection, table: str, column: str) -> bool:
    cursor = conn.execute(f'PRAGMA table_info("{table}")')
    for row in cursor.fetchall():
        col_name = row[1] if not isinstance(row, sqlite3.Row) else row["name"]
        if str(col_name).lower() == column.lower():
            return True
    return False


def _query_sqlite_snapshot(
    conn: sqlite3.Connection,
    table: str,
    entry: QuarantineManifestEntry,
) -> dict[str, Any]:
    if table == "equipment":
        cursor = conn.execute(
            "SELECT * FROM equipment WHERE equipment_id = ? AND site_id = ?",
            (entry.item_id, entry.site_id),
        )
    elif table == "network_devices":
        cursor = conn.execute(
            "SELECT * FROM network_devices WHERE device_id = ? AND site_id = ?",
            (entry.item_id, entry.site_id),
        )
    elif table == "ip_arp_entries":
        cursor = conn.execute(
            "SELECT * FROM ip_arp_entries WHERE site_id = ? AND (ip_id = ? OR ip_address = ?)",
            (entry.site_id, entry.item_id, entry.item_id),
        )
    elif table == "ports":
        cursor = conn.execute(
            "SELECT * FROM ports WHERE port_id = ?",
            (entry.item_id,),
        )
    else:
        raise RemediationExecutionError(f"Unsupported SQL table: {table!r}")

    row = cursor.fetchone()
    if row is None:
        raise RemediationExecutionError(
            f"Target {entry.item_type} {entry.item_id!r} in site {entry.site_id!r} not found in table {table!r}"
        )
    col_names = [desc[0] for desc in cursor.description]
    return dict(zip(col_names, row))


def _resolve_site_snapshot(
    sites_by_id: Mapping[str, Site],
    table: str,
    entry: QuarantineManifestEntry,
) -> dict[str, Any]:
    site = sites_by_id.get(entry.site_id)
    if site is None:
        raise RemediationExecutionError(
            f"Site {entry.site_id!r} not found in provided sites for item {entry.item_id!r}"
        )

    if table == "equipment":
        for eq in site.equipment:
            if eq.equipment_id == entry.item_id:
                snap: dict[str, Any] = {
                    "equipment_id": eq.equipment_id,
                    "site_id": eq.site_id,
                    "hostname": eq.name,
                    "name": eq.name,
                    "category": eq.category.value,
                    "assigned_ips": list(eq.assigned_ips),
                    "connected_ports": list(eq.connected_ports),
                    "hypervisor_id": eq.hypervisor_id,
                    "power_state": eq.power_state,
                    "last_seen": _format_sql_datetime(eq.last_seen),
                }
                if eq.assigned_ips:
                    snap["primary_ip"] = eq.assigned_ips[0]
                if eq.connected_ports:
                    snap["connected_port_id"] = eq.connected_ports[0]
                if eq.hypervisor_id is not None:
                    snap["vcenter_instance"] = eq.hypervisor_id
                return snap
        raise RemediationExecutionError(
            f"Equipment {entry.item_id!r} not found in site {entry.site_id!r}"
        )

    if table == "network_devices":
        for dev in site.devices:
            if dev.device_id == entry.item_id:
                snap = {
                    "device_id": dev.device_id,
                    "site_id": dev.site_id,
                    "hostname": dev.hostname,
                    "management_ip": dev.management_ip,
                    "vendor": dev.vendor,
                    "model": dev.model,
                    "role": dev.role,
                    "last_seen": _format_sql_datetime(dev.last_seen),
                }
                if dev.management_ip is not None:
                    snap["mgmt_ip"] = dev.management_ip
                return snap
        raise RemediationExecutionError(
            f"NetworkDevice {entry.item_id!r} not found in site {entry.site_id!r}"
        )

    if table == "ip_arp_entries":
        matched_ip: Optional[IPAddress] = None
        for ip_obj in site.ip_addresses:
            if ip_obj.ip == entry.item_id or ip_obj.ip == entry.name:
                matched_ip = ip_obj
                break
        if matched_ip is None:
            idx_match = re.match(r"^ip-[^-]+-(\d+)$", entry.item_id)
            if idx_match:
                idx = int(idx_match.group(1)) - 1
                if 0 <= idx < len(site.ip_addresses):
                    matched_ip = site.ip_addresses[idx]
        if matched_ip is None:
            for ip_obj in site.ip_addresses:
                if ip_obj.assigned_object_id == entry.item_id:
                    matched_ip = ip_obj
                    break
        if matched_ip is None:
            raise RemediationExecutionError(
                f"IPAddress {entry.item_id!r} not found in site {entry.site_id!r}"
            )
        snap = {
            "site_id": site.site_id,
            "subnet_id": matched_ip.subnet_id,
            "ip": matched_ip.ip,
            "ip_address": matched_ip.ip,
            "mac_address": matched_ip.arp_mac,
            "arp_mac": matched_ip.arp_mac,
            "assigned_object_type": matched_ip.assigned_object_type,
            "assigned_object_id": matched_ip.assigned_object_id,
            "assigned_target_type": matched_ip.assigned_object_type or "unassigned",
            "assigned_target_id": matched_ip.assigned_object_id or "",
            "arp_last_seen": _format_sql_datetime(matched_ip.arp_last_seen),
            "arp_source_device_id": matched_ip.arp_source_device_id,
        }
        if entry.item_id.startswith("ip-"):
            snap["ip_id"] = entry.item_id
        return snap

    if table == "ports":
        for dev in site.devices:
            for port in dev.ports:
                if port.port_id == entry.item_id:
                    vlan_val: Any = port.vlan_id
                    if isinstance(vlan_val, str) and vlan_val.isdigit():
                        vlan_val = int(vlan_val)
                    return {
                        "port_id": port.port_id,
                        "device_id": port.device_id,
                        "name": port.name,
                        "port_name": port.name,
                        "admin_status": port.admin_status or "up",
                        "oper_status": port.oper_status,
                        "poe_status": port.poe_status,
                        "vlan_id": vlan_val,
                        "connected_device_id": port.connected_device_id,
                        "connected_equipment_id": port.connected_device_id,
                        "connected_mac": port.connected_mac,
                    }
        raise RemediationExecutionError(
            f"Port {entry.item_id!r} not found in site {entry.site_id!r}"
        )

    raise RemediationExecutionError(f"Unsupported table: {table!r}")


def _resolve_fallback_snapshot(
    table: str, entry: QuarantineManifestEntry
) -> dict[str, Any]:
    if table == "equipment":
        snap: dict[str, Any] = {
            "equipment_id": entry.item_id,
            "site_id": entry.site_id,
        }
        if entry.name and entry.name != entry.item_id:
            snap["hostname"] = entry.name
        return snap
    if table == "network_devices":
        snap = {
            "device_id": entry.item_id,
            "site_id": entry.site_id,
        }
        if entry.name and entry.name != entry.item_id:
            snap["hostname"] = entry.name
        return snap
    if table == "ip_arp_entries":
        snap = {
            "site_id": entry.site_id,
            "assigned_target_type": "equipment",
            "assigned_target_id": (
                entry.name if entry.name and entry.name != entry.item_id else ""
            ),
        }
        if entry.item_id.startswith("ip-"):
            snap["ip_id"] = entry.item_id
        else:
            snap["ip_address"] = entry.item_id
        return snap
    if table == "ports":
        snap = {
            "port_id": entry.item_id,
            "admin_status": "up",
        }
        if entry.name and entry.name != entry.item_id:
            snap["port_name"] = entry.name
        return snap
    raise RemediationExecutionError(f"Unsupported table: {table!r}")
