"""Shared constants, normalisation helpers and power/Guest Tools enums for the hypervisor collector."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from enum import Enum
import json
import re
from typing import Any, Optional

_UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

_MOREF_PATTERN = re.compile(r"^vm-[0-9a-zA-Z_-]+$", re.IGNORECASE)

_ALLOWED_READONLY_MODES: frozenset[str] = frozenset(
    {
        "readonly",
        "read_only",
        "read-only",
        "ro",
    }
)


def _require_non_empty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _clean_optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned if cleaned else None
    text = str(value).strip()
    return text if text else None


def _normalize_mac(mac: Optional[str]) -> Optional[str]:
    if not isinstance(mac, str):
        return None
    cleaned = mac.strip().lower()
    if not cleaned:
        return None
    hex_only = "".join(ch for ch in cleaned if ch not in (":", "-", "."))
    return hex_only or cleaned


def _format_mac_canonical(mac: Optional[str]) -> Optional[str]:
    if not isinstance(mac, str):
        return None
    cleaned = mac.strip().lower()
    if not cleaned:
        return None
    hex_only = "".join(ch for ch in cleaned if ch not in (":", "-", "."))
    if len(hex_only) == 12 and all(c in "0123456789abcdef" for c in hex_only):
        return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))
    return cleaned


def _normalize_ip(ip: Optional[str]) -> Optional[str]:
    if not isinstance(ip, str):
        return None
    cleaned = ip.strip()
    return cleaned if cleaned else None


def _normalize_uuid(value: Optional[str]) -> Optional[str]:
    cleaned = _clean_optional_str(value)
    if cleaned is None:
        return None
    lower = cleaned.lower()
    if lower.startswith("uuid:"):
        lower = lower[5:].strip()
    return lower if lower else None


def _looks_like_uuid(value: Optional[str]) -> bool:
    norm = _normalize_uuid(value)
    if norm is None:
        return False
    return bool(_UUID_PATTERN.match(norm))


def _normalize_instance_key(instance: Optional[str]) -> Optional[str]:
    cleaned = _clean_optional_str(instance)
    if cleaned is None:
        return None
    return cleaned.lower()


def _short_instance_key(instance: Optional[str]) -> Optional[str]:
    norm = _normalize_instance_key(instance)
    if norm is None:
        return None
    return norm.split(".", 1)[0]


def _instances_match(inst_a: Optional[str], inst_b: Optional[str]) -> bool:
    norm_a = _normalize_instance_key(inst_a)
    norm_b = _normalize_instance_key(inst_b)
    if norm_a is None or norm_b is None:
        return False
    if norm_a == norm_b:
        return True
    short_a = _short_instance_key(norm_a)
    short_b = _short_instance_key(norm_b)
    return bool(short_a and short_a == short_b)


def _parse_optional_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        cleaned = value.strip().lower()
        if not cleaned:
            return None
        if cleaned in ("true", "1", "yes", "y", "connected", "up", "on"):
            return True
        if cleaned in ("false", "0", "no", "n", "disconnected", "down", "off"):
            return False
    return None


def _split_str_items(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        if stripped.startswith("[") and stripped.endswith("]"):
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, list):
                    return [str(x).strip() for x in parsed if str(x).strip()]
            except ValueError:
                pass
        sep = ";" if ";" in stripped else ","
        return [part.strip() for part in stripped.split(sep) if part.strip()]
    if isinstance(value, Iterable) and not isinstance(value, (bytes, Mapping)):
        result: list[str] = []
        for item in value:
            result.extend(_split_str_items(item))
        return result
    cleaned = _clean_optional_str(value)
    return [cleaned] if cleaned else []


class VmPowerState(str, Enum):
    """Normalized VMware vCenter virtual machine power state."""

    POWERED_ON = "POWERED_ON"
    POWERED_OFF = "POWERED_OFF"
    SUSPENDED = "SUSPENDED"

    @classmethod
    def from_raw(cls, value: Any) -> VmPowerState:
        """Normalize raw vCenter or RVTools power state string to VmPowerState."""
        if isinstance(value, VmPowerState):
            return value
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Invalid VM power state: {value!r}")
        token = (
            value.strip()
            .lower()
            .replace("-", "_")
            .replace(" ", "_")
        )
        if token in ("poweredon", "powered_on", "on", "running", "active", "up"):
            return cls.POWERED_ON
        if token in ("poweredoff", "powered_off", "off", "halted", "stopped", "down", "shut_off"):
            return cls.POWERED_OFF
        if token in ("suspended", "suspend", "paused"):
            return cls.SUSPENDED
        raise ValueError(f"Unsupported VM power state: {value!r}")


def normalize_vm_power_state(value: Any) -> VmPowerState:
    """Normalize a raw power state string or VmPowerState enum."""
    return VmPowerState.from_raw(value)


class GuestToolsStatus(str, Enum):
    """Normalized VMware Guest Tools operational status."""

    TOOLS_OK = "toolsOk"
    TOOLS_OLD = "toolsOld"
    TOOLS_NOT_RUNNING = "toolsNotRunning"
    TOOLS_NOT_INSTALLED = "toolsNotInstalled"

    @classmethod
    def from_raw(cls, value: Any) -> Optional[GuestToolsStatus]:
        """Normalize raw vCenter or RVTools Guest Tools status string to GuestToolsStatus."""
        if value is None:
            return None
        if isinstance(value, GuestToolsStatus):
            return value
        if not isinstance(value, str):
            raise ValueError(f"Invalid Guest Tools status: {value!r}")
        cleaned = value.strip()
        if not cleaned:
            return None
        token = (
            cleaned.lower()
            .replace("-", "")
            .replace("_", "")
            .replace(" ", "")
        )
        if token in ("toolsok", "guesttoolsrunning", "ok", "running", "current"):
            return cls.TOOLS_OK
        if token in ("toolsold", "guesttoolsoutofdate", "old", "outofdate", "needupgrade"):
            return cls.TOOLS_OLD
        if token in (
            "toolsnotrunning",
            "guesttoolsnotrunning",
            "notrunning",
            "stopped",
            "unmanaged",
        ):
            return cls.TOOLS_NOT_RUNNING
        if token in (
            "toolsnotinstalled",
            "guesttoolsnotinstalled",
            "notinstalled",
            "none",
            "absent",
        ):
            return cls.TOOLS_NOT_INSTALLED
        raise ValueError(f"Unsupported Guest Tools status: {value!r}")


def normalize_guest_tools_status(value: Any) -> Optional[GuestToolsStatus]:
    """Normalize a raw Guest Tools status string or GuestToolsStatus enum."""
    return GuestToolsStatus.from_raw(value)


def _infer_guest_os_family(
    os_family: Optional[str], os_full_name: Optional[str]
) -> Optional[str]:
    fam = _clean_optional_str(os_family)
    if fam:
        lower = fam.lower()
        if "win" in lower:
            return "windows"
        if any(k in lower for k in ("linux", "ubuntu", "rhel", "centos", "debian", "suse", "rocky", "alma")):
            return "linux"
        return lower

    full = _clean_optional_str(os_full_name)
    if full:
        lower_full = full.lower()
        if "windows" in lower_full or "microsoft" in lower_full:
            return "windows"
        if any(
            k in lower_full
            for k in ("linux", "ubuntu", "red hat", "rhel", "centos", "debian", "suse", "rocky", "alma")
        ):
            return "linux"
    return None
