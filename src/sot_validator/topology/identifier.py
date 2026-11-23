"""Heuristic router, switch, VLAN/subnet, and host role identifier for sot-validator."""

from __future__ import annotations

from sot_validator.topology._identifier_engine import NetworkRoleIdentifier
from sot_validator.topology._identifier_helpers import (
    KNOWN_OUI_VENDORS,
    KNOWN_SCAN_TCP_PORTS,
    VALID_HOST_ROLES,
    _TOKEN_SPLIT_PATTERN,
    _TRAILING_DIGITS_PATTERN,
    _extract_oui_prefix,
    _hostname_tokens,
    _infer_subnet_cidr,
    _infer_vlan_id,
    _matches_hostname,
    _normalize_optional_mac,
    _parse_ipv4_octets,
)
from sot_validator.topology._identifier_models import (
    ConsolidatedRouter,
    HostIdentification,
)

__all__ = [
    "ConsolidatedRouter",
    "HostIdentification",
    "KNOWN_OUI_VENDORS",
    "KNOWN_SCAN_TCP_PORTS",
    "NetworkRoleIdentifier",
    "VALID_HOST_ROLES",
]
