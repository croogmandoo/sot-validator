"""Remediation executor errors, SQL table metadata and SQL literal helpers."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
import re
from typing import Any, Optional

from sot_validator.remediation.quarantine import RemediationOperation


class RemediationExecutionError(Exception):
    """Raised when remediation execution gates fail or an unapproved/invalid action is requested."""


class ManifestVerificationError(RemediationExecutionError):
    """Raised when a RemediationApprovalManifest fails SHA-256 digest verification."""


class _UnknownExecutionIdError(RemediationExecutionError, KeyError):
    """Raised when an execution_id is not found in the rollback journal."""


_TABLE_SQL_COLUMNS: dict[str, tuple[str, ...]] = {
    "equipment": (
        "equipment_id",
        "site_id",
        "hostname",
        "equipment_type",
        "vendor",
        "model",
        "primary_ip",
        "mac_address",
        "vcenter_instance",
        "vcenter_bios_uuid",
        "vcenter_moref",
        "connected_port_id",
        "last_seen",
        "status",
    ),
    "network_devices": (
        "device_id",
        "site_id",
        "hostname",
        "vendor",
        "model",
        "role",
        "mgmt_ip",
        "mac_address",
        "room",
        "os_version",
        "serial_number",
        "last_seen",
        "status",
    ),
    "ip_arp_entries": (
        "ip_id",
        "site_id",
        "subnet_id",
        "ip_address",
        "mac_address",
        "assigned_target_type",
        "assigned_target_id",
        "arp_last_seen",
        "arp_source_device_id",
        "status",
    ),
    "ports": (
        "port_id",
        "device_id",
        "port_name",
        "if_index",
        "admin_status",
        "oper_status",
        "poe_status",
        "poe_power_w",
        "vlan_id",
        "connected_equipment_id",
        "connected_mac",
        "description",
        "last_change",
        "status",
    ),
}

_TABLE_ORDER: tuple[str, ...] = (
    "equipment",
    "network_devices",
    "ip_arp_entries",
    "ports",
)


def _format_sql_datetime(value: Optional[datetime | str]) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    iso = value.isoformat()
    if iso.endswith("+00:00"):
        return iso[:-6] + "Z"
    return iso


def _sql_literal(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, datetime):
        formatted = _format_sql_datetime(value) or ""
        return "'" + formatted.replace("'", "''") + "'"
    if isinstance(value, Enum):
        return "'" + str(value.value).replace("'", "''") + "'"
    return "'" + str(value).replace("'", "''") + "'"


def _resolve_target_table(
    item_type: str, operation: RemediationOperation
) -> str:
    norm_type = re.sub(r"[^a-z0-9]+", "", item_type.lower())
    if (
        norm_type in ("ipaddress", "ip", "iparpentry", "iparpentries")
        or operation is RemediationOperation.RECLAIM_STALE_IP
    ):
        return "ip_arp_entries"
    if (
        norm_type in ("port", "ports", "switchport")
        or operation is RemediationOperation.PROPOSE_PORT_SHUTDOWN
    ):
        return "ports"
    if norm_type in ("networkdevice", "device", "switch", "router"):
        return "network_devices"
    if norm_type in (
        "equipment",
        "vm",
        "virtualmachine",
        "server",
        "san",
        "nas",
        "ups",
    ) or operation in (
        RemediationOperation.FLAG_STALE_IN_SOT,
        RemediationOperation.DECOMMISSION_VM_RECORD,
    ):
        return "equipment"
    raise RemediationExecutionError(
        f"Unsupported item_type={item_type!r} (operation={operation.value!r}) for SQL remediation"
    )
