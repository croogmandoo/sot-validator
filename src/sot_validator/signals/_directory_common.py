"""Shared hostname normalisation and boolean flag helpers for the directory and DNS/DHCP collectors."""

from __future__ import annotations

from functools import lru_cache
import ipaddress
from typing import Any, Optional


def _clean_optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned if cleaned else None
    text = str(value).strip()
    return text if text else None


def _parse_bool_flag(value: Any, *, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        token = value.strip().lower()
        if not token:
            return default
        if token in ("true", "1", "yes", "y", "enabled", "enable", "active", "on"):
            return True
        if token in ("false", "0", "no", "n", "disabled", "disable", "inactive", "off"):
            return False
    raise ValueError(f"Invalid boolean flag value: {value!r}")


def normalize_hostname(hostname: Optional[str]) -> Optional[str]:
    """Normalize a hostname case-insensitively, stripping domain suffixes and trailing '$'."""
    if hostname is None or not isinstance(hostname, str):
        return None
    return _normalize_hostname_str(hostname)


# Called for every lease and target hostname on every target, so cache the string work
@lru_cache(maxsize=65536)
def _normalize_hostname_str(hostname: str) -> Optional[str]:
    cleaned = hostname.strip().rstrip(".")
    if not cleaned:
        return None
    try:
        addr = ipaddress.ip_address(cleaned)
        return str(addr).lower()
    except ValueError:
        pass
    short = cleaned.split(".", 1)[0].strip().rstrip("$").strip().lower()
    return short if short else None


def _normalize_fqdn(hostname: Optional[str]) -> Optional[str]:
    """Normalize a hostname or FQDN to lowercase without trailing root dot or machine '$'."""
    if hostname is None or not isinstance(hostname, str):
        return None
    cleaned = hostname.strip().rstrip(".")
    if not cleaned:
        return None
    try:
        addr = ipaddress.ip_address(cleaned)
        return str(addr).lower()
    except ValueError:
        pass
    parts = cleaned.split(".")
    first = parts[0].strip().rstrip("$").strip().lower()
    if not first:
        return None
    rest = [p.strip().lower() for p in parts[1:] if p.strip()]
    if rest:
        return ".".join([first, *rest])
    return first
