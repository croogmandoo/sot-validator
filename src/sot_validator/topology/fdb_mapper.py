"""Switch Bridge-MIB / FDB MAC-to-port parser, trunk/access inferrer, and Site port auto-mapper."""

from __future__ import annotations

from sot_validator.topology._fdb_parser import FdbTableParser
from sot_validator.topology._fdb_port_mapper import SwitchFdbPortMapper
from sot_validator.topology._fdb_records import (
    VALID_PORT_MODES,
    FdbEntry,
    PortClassificationResult,
    _BRIDGE_FDB_OID_PATTERN,
    _HOSTNAME_TRAILING_DIGITS_PATTERN,
    _IGNORED_PORT_TOKENS,
    _MAC_CANDIDATE_PATTERN,
    _PAREN_VLAN_PATTERN,
    _QBRIDGE_FDB_OID_PATTERN,
    _ROUTER_HOSTNAME_TOKENS,
    _ROUTER_ROLES,
    _SWITCH_HOSTNAME_TOKENS,
    _VLAN_SUFFIX_PATTERN,
    _VOSS_PORT_PREFIX_PATTERN,
    _deduplicate_entries,
    _is_ignored_port_token,
    _looks_like_port_name,
    _normalize_vlan_id,
    _normalize_voss_port_name,
    _parse_mac_token,
    _parse_static_flag,
    _site_gateway_ips,
    _unlink_port_from_equipment,
)

__all__ = [
    "FdbEntry",
    "FdbTableParser",
    "PortClassificationResult",
    "SwitchFdbPortMapper",
    "VALID_PORT_MODES",
]
