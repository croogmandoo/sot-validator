"""Shared constants, CLI dialect and helpers for the port reclamation planner."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from enum import Enum
import re
from typing import Any, Optional

from sot_validator.models import Port


DEFAULT_CRITICAL_INFRASTRUCTURE_KEYWORDS: tuple[str, ...] = (
    "uplink",
    "trunk",
    "core",
    "wan",
    "wap",
    "ap-",
    "ups",
    "apc",
    "vcenter",
    "esxi",
)

DEFAULT_BLOCKED_LLDP_CAPABILITIES: tuple[str, ...] = (
    "bridge",
    "switch",
    "router",
    "wlan",
    "wlan-ap",
    "access-point",
    "ap",
    "repeater",
)

_LLDP_INFRASTRUCTURE_ROLES_AND_KEYWORDS: tuple[str, ...] = (
    "switch",
    "bridge",
    "router",
    "core",
    "distribution",
    "wan",
    "firewall",
    "wap",
    "ap-",
    "access-point",
    "wlan",
    "ups",
    "apc",
    "uplink",
    "trunk",
    "vcenter",
    "esxi",
    "extremexos",
    "voss",
)

_IEEE_8021AB_CAPABILITY_BITS: tuple[tuple[int, str], ...] = (
    (0x01, "other"),
    (0x02, "repeater"),
    (0x04, "bridge"),
    (0x08, "wlan"),
    (0x10, "router"),
    (0x20, "telephone"),
    (0x40, "docsis"),
    (0x80, "station"),
)

_MILLIWATT_PATTERN = re.compile(r"(\d+(?:\.\d+)?)\s*mw\b", re.IGNORECASE)
_VLAN_RANGE_PATTERN = re.compile(r"^\d+\s*-\s*\d+$")
_PORT_TRAILING_DIGITS_PATTERN = re.compile(r"(\d+)$")
_SLOT_PORT_PATTERN = re.compile(r"^(\d+)[:/](\d+)$")


class ExtremeCliDialect(str, Enum):
    """Supported Extreme Networks switch CLI dialects for staged port reclamation."""

    EXOS = "exos"
    VOSS = "voss"

    @classmethod
    def _missing_(cls, value: object) -> Optional[ExtremeCliDialect]:
        if isinstance(value, str):
            cleaned = value.strip().lower().replace("-", "_")
            if cleaned in ("exos", "extreme_xos", "extremexos", "xos"):
                return cls.EXOS
            if cleaned in ("voss", "extreme_voss", "extremevoss", "fabric_engine"):
                return cls.VOSS
        return None


def _coerce_cli_dialect(
    value: ExtremeCliDialect | str, field_name: str = "dialect"
) -> ExtremeCliDialect:
    if isinstance(value, ExtremeCliDialect):
        return value
    if isinstance(value, str):
        try:
            return ExtremeCliDialect(value)
        except ValueError as exc:
            raise ValueError(f"Invalid {field_name}: {value!r}") from exc
    raise ValueError(f"Invalid {field_name}: {value!r}")


def _clean_optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped else None
    text = str(value).strip()
    return text if text else None


def _normalize_str_tuple(values: Optional[Iterable[Any]]) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        stripped = values.strip()
        return (stripped,) if stripped else ()
    result: list[str] = []
    seen: set[str] = set()
    for item in values:
        cleaned = _clean_optional_str(item)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return tuple(result)


def _preserve_str_tuple(values: Optional[Iterable[Any]]) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        stripped = values.strip()
        return (stripped,) if stripped else ()
    return tuple(
        cleaned
        for item in values
        if (cleaned := _clean_optional_str(item)) is not None
    )


def _decode_lldp_capabilities(raw: Any) -> tuple[str, ...]:
    """Normalize LLDP/CDP capabilities from sequences, delimited strings, or IEEE 802.1AB bitmasks."""
    if raw is None or isinstance(raw, bool):
        return ()

    if isinstance(raw, int):
        if raw <= 0:
            return ()
        decoded = [
            name for bit, name in _IEEE_8021AB_CAPABILITY_BITS if (raw & bit) != 0
        ]
        return tuple(decoded)

    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return ()
        # Check hex or integer bitmask string
        if stripped.lower().startswith("0x") or stripped.isdigit():
            try:
                mask = int(stripped, 0)
                if mask > 0:
                    decoded = [
                        name
                        for bit, name in _IEEE_8021AB_CAPABILITY_BITS
                        if (mask & bit) != 0
                    ]
                    if decoded:
                        return tuple(decoded)
            except ValueError:
                pass

        normalized_text = re.sub(
            r"\bwlan\s+access\s+point\b",
            "wlan-ap",
            stripped,
            flags=re.IGNORECASE,
        )
        normalized_text = re.sub(
            r"\baccess\s+point\b",
            "access-point",
            normalized_text,
            flags=re.IGNORECASE,
        )
        if any(sep in normalized_text for sep in (",", ";", "|", "/")):
            parts = re.split(r"[,;|/]+", normalized_text)
        else:
            parts = normalized_text.split()
        result: list[str] = []
        seen: set[str] = set()
        for part in parts:
            token = part.strip().lower()
            if token and token not in seen:
                seen.add(token)
                result.append(token)
        return tuple(result)

    if isinstance(raw, Iterable):
        result = []
        seen = set()
        for item in raw:
            for sub in _decode_lldp_capabilities(item):
                if sub not in seen:
                    seen.add(sub)
                    result.append(sub)
        return tuple(result)

    return ()


def _coerce_port_and_extras(
    raw_port: Port | Mapping[str, Any],
    default_device_id: Optional[str] = None,
) -> tuple[Port, dict[str, Any]]:
    """Coerce a Port or mapping into a canonical Port and a dictionary of extra metadata."""
    extras: dict[str, Any] = {}
    if isinstance(raw_port, Port):
        for attr in (
            "description",
            "tagged_vlans",
            "is_trunk",
            "vlan_mode",
            "lldp_neighbors",
            "lldp_neighbor",
            "poe_power_w",
            "poe_watts",
            "poe_power_mw",
            "poe_restore_limit_mw",
            "poe_limit_mw",
            "if_index",
            "inactive_runs",
            "consecutive_stale_runs",
            "inactive_days",
            "stale_duration_days",
            "site_id",
            "device_hostname",
            "has_recent_arp_activity",
            "has_recent_mac_activity",
        ):
            if hasattr(raw_port, attr):
                extras[attr] = getattr(raw_port, attr)
        return raw_port, extras

    if isinstance(raw_port, Mapping):
        extras = dict(raw_port)
        port_id = _clean_optional_str(
            raw_port.get("port_id") or raw_port.get("id")
        )
        device_id = _clean_optional_str(
            raw_port.get("device_id") or default_device_id or "unknown-device"
        )
        name = _clean_optional_str(
            raw_port.get("name") or raw_port.get("port_name") or port_id
        )
        if not port_id and device_id and name:
            port_id = f"{device_id}:{name}"
        if not port_id or not device_id or not name:
            raise ValueError(
                "Port mapping must include port_id, device_id, and name/port_name"
            )
        port = Port(
            port_id=port_id,
            device_id=device_id,
            name=name,
            admin_status=_clean_optional_str(raw_port.get("admin_status")),
            oper_status=_clean_optional_str(raw_port.get("oper_status")),
            poe_status=_clean_optional_str(raw_port.get("poe_status")),
            connected_device_id=_clean_optional_str(
                raw_port.get("connected_device_id")
                or raw_port.get("connected_equipment_id")
            ),
            connected_mac=_clean_optional_str(raw_port.get("connected_mac")),
            vlan_id=_clean_optional_str(raw_port.get("vlan_id")),
        )
        return port, extras

    raise ValueError(f"Unsupported port representation: {raw_port!r}")


def _port_matches_identifier(port: Port, identifier: str) -> bool:
    cleaned = identifier.strip()
    if not cleaned:
        return False
    return cleaned in (
        port.port_id,
        port.name,
        f"{port.device_id}:{port.name}",
        f"{port.device_id}:{port.port_id}",
    )
