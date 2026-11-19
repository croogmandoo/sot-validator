"""Shared OID constants, regexes and normalizers for the router ARP/DHCP lease collector."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import ipaddress
import re
from typing import Any, Optional

from sot_validator.discovery.scanner import _infer_vlan_id_from_subnet

IP_MIB_NET_TO_MEDIA_NET_ADDRESS_PREFIX = "1.3.6.1.2.1.4.22.1.3"
IP_MIB_NET_TO_MEDIA_TYPE_PREFIX = "1.3.6.1.2.1.4.22.1.4"
IF_MIB_IF_DESCR_PREFIX = "1.3.6.1.2.1.2.2.1.2"
IF_MIB_IF_NAME_PREFIX = "1.3.6.1.2.1.31.1.1.1.1"

_MAC_NULL_TOKENS: frozenset[str] = frozenset(
    {"incomplete", "(incomplete)", "<incomplete>", "failed", "none", "(none)", "-"}
)
_ZERO_MAC = "00:00:00:00:00:00"
_MAC_OCTET_RE = re.compile(r"^[0-9a-f]{1,2}$")
_MAC_GROUP_RE = re.compile(r"^[0-9a-f]{4}$")
_HEX12_RE = re.compile(r"^[0-9a-f]{12}$")
_NUMERIC_RE = re.compile(r"^-?\d+(?:\.\d+)?$")
_ISC_TS_RE = re.compile(
    r"^(?:\d\s+)?(\d{4})/(\d{1,2})/(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})$"
)
_IFACE_DOT_VLAN_RE = re.compile(r"\.(\d+)$")
_IFACE_NAMED_VLAN_RE = re.compile(r"^(?:vlan|br|vl|v)[._-]?(\d+)$", re.IGNORECASE)
_DIGITS_RE = re.compile(r"(\d+)")
_SNMP_TYPE_PREFIX_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*:\s+")
_SNMP_TYPE_NAMES: dict[int, str] = {1: "OTHER", 2: "INVALID", 3: "DYNAMIC", 4: "STATIC"}
_EXOS_STATIC_TOKENS: frozenset[str] = frozenset({"YES", "NO", "STATIC", "DYNAMIC"})
_EXOS_NUMERIC_STATIC_TOKENS: frozenset[str] = frozenset({"1", "0"})
_VOSS_TYPES: frozenset[str] = frozenset(
    {"DYNAMIC", "STATIC", "LOCAL", "INVALID", "OTHER"}
)
_LEASE_NULL_TOKENS: frozenset[str] = frozenset({"", "0", "infinite", "never"})
_ISC_LEASE_START_RE = re.compile(r"^\s*lease\s+\S+\s*\{", re.MULTILINE)
_ISC_LEASE_BLOCK_RE = re.compile(r"lease\s+(\S+)\s*\{(.*?)\}", re.DOTALL)
_ISC_STATEMENT_RE = re.compile(r'\s*((?:[^;"]|"(?:[^"\\]|\\.)*")*);')
_KEA_INFINITE_LFT = 0xFFFFFFFF

_ARP_STATE_RANK: dict[str, int] = {
    "REACHABLE": 2,
    "PERMANENT": 2,
    "DYNAMIC": 2,
    "STATIC": 2,
    "LOCAL": 2,
    "STALE": 1,
    "INCOMPLETE": 0,
    "FAILED": 0,
    "INVALID": 0,
    "NONE": 0,
}

_LEASE_IP_KEYS = ("ip", "ip-address", "ip_address", "address", "ipaddress")
_LEASE_MAC_KEYS = (
    "mac_address",
    "hw-address",
    "hw_address",
    "mac",
    "hardware",
    "hwaddr",
)
_LEASE_HOSTNAME_KEYS = ("hostname", "client-hostname", "client_hostname", "fqdn")
_LEASE_EXPIRY_KEYS = ("lease_expires_at", "expire", "expires_at", "expires", "ends")
_LEASE_SUBNET_KEYS = ("subnet_id", "subnet-id")
_LEASE_CLIENT_ID_KEYS = ("client_id", "client-id")


def _normalize_router_mac(value: Any) -> Optional[str]:
    """Strictly normalize a MAC address to lowercase ``aa:bb:cc:dd:ee:ff`` or None."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("mac_address must be a string or None")
    cleaned = value.strip().lower()
    if not cleaned or cleaned in _MAC_NULL_TOKENS:
        return None
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:].strip()

    hex_digits: Optional[str] = None
    if any(sep in cleaned for sep in (":", "-", " ")):
        parts = re.split(r"[:\- ]+", cleaned)
        if len(parts) == 6 and all(_MAC_OCTET_RE.match(p) for p in parts):
            hex_digits = "".join(p.zfill(2) for p in parts)
    elif "." in cleaned:
        groups = cleaned.split(".")
        if len(groups) == 3 and all(_MAC_GROUP_RE.match(g) for g in groups):
            hex_digits = "".join(groups)
    elif _HEX12_RE.match(cleaned):
        hex_digits = cleaned

    if hex_digits is None:
        raise ValueError(f"Invalid MAC address: {value!r}")
    mac = ":".join(hex_digits[i : i + 2] for i in range(0, 12, 2))
    return None if mac == _ZERO_MAC else mac


def _canonical_ipv4(value: Any, field_name: str = "ip") -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty IPv4 address string")
    return str(ipaddress.IPv4Address(value.strip()))


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def _optional_token(value: Any, field_name: str) -> Optional[str]:
    """Normalize an int or string identifier to a stripped string or None."""
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned if cleaned else None
    raise ValueError(f"{field_name} must be a string, integer, or None")


def _optional_name(value: Any, field_name: str) -> Optional[str]:
    """Normalize a hostname/client-id string, treating ``""`` and ``"*"`` as None."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string or None")
    cleaned = value.strip()
    return None if cleaned in ("", "*") else cleaned


def _coerce_datetime(value: Any, field_name: str) -> Optional[datetime]:
    """Parse a datetime, ISO-8601/ISC string, or Unix epoch into an aware datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be a datetime, string, number, or None")
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError(f"{field_name} epoch value out of range: {value!r}") from exc
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a datetime, string, number, or None")

    cleaned = value.strip()
    if not cleaned:
        return None
    if _NUMERIC_RE.match(cleaned):
        return _coerce_datetime(float(cleaned), field_name)
    isc_match = _ISC_TS_RE.match(cleaned)
    if isc_match is not None:
        year, month, day, hour, minute, second = (int(g) for g in isc_match.groups())
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    iso_text = cleaned[:-1] + "+00:00" if cleaned.endswith(("Z", "z")) else cleaned
    try:
        parsed = datetime.fromisoformat(iso_text)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid timestamp, got {value!r}") from exc
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _parse_lease_expiry(value: Any) -> Optional[datetime]:
    if isinstance(value, str) and value.strip().lower() in _LEASE_NULL_TOKENS:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value == 0:
        return None
    return _coerce_datetime(value, "lease_expires_at")


def _format_dt(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


def _vlan_from_interface(interface: Optional[str]) -> Optional[str]:
    """Infer a VLAN ID from tagged interface names such as ``eth1.10`` or ``vlan20``."""
    if not interface:
        return None
    name = interface.strip()
    match = _IFACE_DOT_VLAN_RE.search(name) or _IFACE_NAMED_VLAN_RE.match(name)
    if match is None:
        return None
    vid = int(match.group(1))
    return str(vid) if 1 <= vid <= 4094 else None


def _vlan_from_number(token: Optional[str], *, max_vid: int = 4095) -> Optional[str]:
    if token is None:
        return None
    match = _DIGITS_RE.search(token)
    if match is None:
        return None
    vid = int(match.group(1))
    return str(vid) if 1 <= vid <= max_vid else None


def _vlan_from_ip(ip: str) -> str:
    return _infer_vlan_id_from_subnet(f"{ip}/24")


def _snmp_text(value: Any) -> Optional[str]:
    """Strip net-snmp style type prefixes (``Hex-STRING: ``) and quotes from a value."""
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if not isinstance(value, str):
        return None
    cleaned = _SNMP_TYPE_PREFIX_RE.sub("", value.strip()).strip().strip('"').strip()
    return cleaned if cleaned else None


def _snmp_type_state(value: Any) -> Optional[str]:
    """Map an ``ipNetToMediaType`` value (``3``, ``"dynamic(3)"``) to a state name."""
    if isinstance(value, int) and not isinstance(value, bool):
        return _SNMP_TYPE_NAMES.get(value)
    text = _snmp_text(value)
    if text is None:
        return None
    match = re.search(r"\((\d+)\)", text)
    if match is not None:
        return _SNMP_TYPE_NAMES.get(int(match.group(1)))
    if text.isdigit():
        return _SNMP_TYPE_NAMES.get(int(text))
    upper = text.upper()
    return upper if upper in _SNMP_TYPE_NAMES.values() else None


def _first_value(row: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        value = row.get(key)
        if value is not None and value != "":
            return value
    return None
