"""Role identifier constants and helpers: host roles, OUI vendors, MAC/IP and hostname parsing."""

from __future__ import annotations

from collections.abc import Sequence
import ipaddress
import re
from typing import Optional

from sot_validator.topology.device_types import (
    _HEX_DIGITS,
    normalize_mac_address,
)

VALID_HOST_ROLES: tuple[str, ...] = (
    "router",
    "switch",
    "hypervisor",
    "dns_server",
    "nas_storage",
    "automation_hub",
    "iot_device",
    "workstation_server",
)

KNOWN_SCAN_TCP_PORTS: tuple[int, ...] = (
    22,
    53,
    80,
    443,
    445,
    5000,
    8000,
    8006,
    8080,
    8123,
    8443,
    9000,
    9090,
)

KNOWN_OUI_VENDORS: dict[str, tuple[str, str]] = {
    "bc:24:11": ("Proxmox", "hypervisor"),
    "00:04:96": ("Extreme Networks", "switch"),
    "00:c0:b7": ("APC", "iot_device"),
    "aa:9c:6c": ("Ubiquiti UniFi", "router"),
    "44:61:32": ("Ecobee", "iot_device"),
}

_TOKEN_SPLIT_PATTERN = re.compile(r"[^a-z0-9]+")
_TRAILING_DIGITS_PATTERN = re.compile(r"^([a-z]+)\d+$")


def _normalize_optional_mac(mac: Optional[str]) -> Optional[str]:
    if not isinstance(mac, str) or not mac.strip():
        return None
    try:
        return normalize_mac_address(mac)
    except ValueError:
        cleaned = mac.strip().lower()
        hex_only = "".join(
            ch for ch in cleaned if ch not in (":", "-", ".", " ")
        )
        if len(hex_only) >= 6 and all(ch in _HEX_DIGITS for ch in hex_only):
            pairs = [
                hex_only[i : i + 2] for i in range(0, len(hex_only) - 1, 2)
            ]
            return ":".join(pairs)
        return cleaned


def _extract_oui_prefix(mac: Optional[str]) -> Optional[str]:
    norm = _normalize_optional_mac(mac)
    if not norm:
        return None
    parts = norm.split(":")
    if len(parts) >= 3 and all(len(p) == 2 for p in parts[:3]):
        return ":".join(parts[:3])
    return None


def _parse_ipv4_octets(ip_str: str) -> Optional[tuple[int, int, int, int]]:
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return None
    if not isinstance(ip_obj, ipaddress.IPv4Address):
        return None
    parts = str(ip_obj).split(".")
    return (int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]))


def _infer_subnet_cidr(ip_str: str, explicit_cidr: Optional[str] = None) -> Optional[str]:
    if explicit_cidr and explicit_cidr.strip():
        return explicit_cidr.strip()
    octets = _parse_ipv4_octets(ip_str)
    if octets is None:
        return None
    return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"


def _infer_vlan_id(
    ip_str: str,
    explicit_vlan_id: Optional[str] = None,
    subnet_cidr: Optional[str] = None,
) -> Optional[str]:
    if explicit_vlan_id is not None and str(explicit_vlan_id).strip():
        return str(explicit_vlan_id).strip()
    octets = _parse_ipv4_octets(ip_str)
    if octets is not None:
        return str(octets[2])
    if subnet_cidr:
        net_ip = subnet_cidr.split("/")[0].strip()
        net_octets = _parse_ipv4_octets(net_ip)
        if net_octets is not None:
            return str(net_octets[2])
    return None


def _hostname_tokens(hostname: Optional[str]) -> tuple[str, set[str]]:
    if not isinstance(hostname, str) or not hostname.strip():
        return "", set()
    lower = hostname.strip().lower()
    raw_tokens = [tok for tok in _TOKEN_SPLIT_PATTERN.split(lower) if tok]
    tokens: set[str] = set(raw_tokens)
    for tok in raw_tokens:
        m = _TRAILING_DIGITS_PATTERN.match(tok)
        if m:
            tokens.add(m.group(1))
    return lower, tokens


def _matches_hostname(
    hostname_lower: str,
    tokens: set[str],
    *,
    exact_tokens: Sequence[str] = (),
    substrings: Sequence[str] = (),
) -> Optional[str]:
    if not hostname_lower:
        return None
    for substr in substrings:
        if substr in hostname_lower:
            return substr
    for tok in exact_tokens:
        if tok in tokens:
            return tok
    return None
