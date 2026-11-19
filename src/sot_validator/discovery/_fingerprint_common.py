"""Shared fingerprinter constants, limits, regexes and cleaning/IP/datetime helpers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
import ipaddress
import re
from typing import Any, Optional
import unicodedata

from sot_validator.models import _parse_optional_datetime
from sot_validator.topology.device_types import DeviceTypeCatalog

SSH_BANNER_PORTS: tuple[int, ...] = (22,)
HTTP_BANNER_PORTS: tuple[int, ...] = (80, 5000, 8000, 8080, 8123, 9000)
TLS_BANNER_PORTS: tuple[int, ...] = (443, 5001, 8006, 8443, 9443)

_MAX_TEXT_LEN = 256
_MAX_HEADERS = 32
_MAX_TITLES = 16
_MAX_SAN_NAMES = 32
_MAX_TLS_CERTIFICATES = 16
_SSH_READ_LIMIT = 256
_HTTP_HEADER_LIMIT = 64 * 1024
_HTTP_BODY_LIMIT = 64 * 1024
_DER_MAX_INPUT = 16 * 1024

_FINGERPRINT_ROLES: frozenset[str] = frozenset(
    {
        "switch",
        "router",
        "ups",
        "hypervisor",
        "nas_storage",
        "dns_server",
        "automation_hub",
        "iot_device",
        "server",
        "host",
    }
)
_TEMPLATE_CATALOG = DeviceTypeCatalog()

_WHITESPACE_RE = re.compile(r"\s+")
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_EXOS_MODEL_RE = re.compile(r"extremexos\s*\(\s*([^()]+?)\s*\)", re.IGNORECASE)
_HTML_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title\s*>", re.IGNORECASE | re.DOTALL)


def _clean_text(value: Any, field_name: str) -> Optional[str]:
    """Strip control characters, collapse whitespace and cap a text value."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string or None")
    chars: list[str] = []
    for ch in value:
        if ch in "\t\r\n":
            chars.append(" ")
        elif unicodedata.category(ch) != "Cc":
            chars.append(ch)
    cleaned = _WHITESPACE_RE.sub(" ", "".join(chars)).strip()[:_MAX_TEXT_LEN].rstrip()
    return cleaned or None


def _clean_text_list(values: Any, field_name: str, limit: int) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes)) or not isinstance(values, (list, tuple)):
        raise ValueError(f"{field_name} must be a list of strings")
    cleaned_list: list[str] = []
    for raw in values:
        if raw is None:
            continue
        cleaned = _clean_text(raw, field_name)
        if cleaned is not None and cleaned not in cleaned_list:
            cleaned_list.append(cleaned)
    return cleaned_list[:limit]


def _clean_headers(headers: Any) -> dict[str, str]:
    if headers is None:
        return {}
    if not isinstance(headers, Mapping):
        raise ValueError("http_headers must be a mapping of strings to strings")
    cleaned_headers: dict[str, str] = {}
    for raw_key, raw_value in headers.items():
        key = _clean_text(raw_key, "http_headers key")
        value = _clean_text(raw_value, "http_headers value")
        if key is None or value is None:
            continue
        key = key.lower()
        if key not in cleaned_headers:
            cleaned_headers[key] = value
    return dict(list(cleaned_headers.items())[:_MAX_HEADERS])


def _canonical_ipv4(ip: Any) -> str:
    if not isinstance(ip, str) or not ip.strip():
        raise ValueError("ip must be a non-empty IPv4 string")
    return str(ipaddress.IPv4Address(ip.strip()))


def _ip_or_none(value: Any) -> Optional[str]:
    try:
        return _canonical_ipv4(value)
    except ValueError:
        return None


def _utc_datetime(value: Any, field_name: str) -> Optional[datetime]:
    """Parse a datetime or ISO-8601 string into aware UTC, treating naive as UTC."""
    parsed = _parse_optional_datetime(value, field_name)
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _str_or_none(value: Any) -> Optional[str]:
    return value if isinstance(value, str) else None


def _pair(value: Any) -> Optional[tuple[Any, Any]]:
    if isinstance(value, (tuple, list)) and len(value) == 2:
        return value[0], value[1]
    return None


def _normalize_ports(open_ports: Iterable[int]) -> list[int]:
    if isinstance(open_ports, (str, bytes)) or not isinstance(open_ports, Iterable):
        raise ValueError("open_ports must be a sequence of integers in 1..65535")
    ports: set[int] = set()
    for port in open_ports:
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not (1 <= port <= 65535)
        ):
            raise ValueError(f"Invalid TCP port: {port!r}")
        ports.add(port)
    return sorted(ports)
