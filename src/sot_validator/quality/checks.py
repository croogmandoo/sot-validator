"""Deterministic SoT data-quality conflict detection rules."""

from __future__ import annotations

from sot_validator.quality._checker import DataQualityChecker
from sot_validator.quality._records import (
    ALL_RULE_NAMES,
    CROSS_SITE_RULES,
    RULE_CROSS_SITE_DUPLICATE_IP,
    RULE_CROSS_SITE_DUPLICATE_MAC,
    RULE_DUPLICATE_IP,
    RULE_DUPLICATE_MAC,
    RULE_HOSTNAME_MISMATCH,
    RULE_IP_OUTSIDE_ACTIVE_SUBNET,
    RULE_IP_OUTSIDE_SITE_BLOCK,
    RULE_ORPHAN_REFERENCE,
    SINGLE_SITE_RULES,
    VALID_SEVERITIES,
    _MAC_PATTERN,
    _TRUNK_PORT_MODES,
    QualityFinding,
    _canonical_ip_key,
    _compute_finding_id,
    _derive_site_block,
    _ip_assignment_ref,
    _lookup_name,
    _normalized_ip,
    _normalized_mac,
    _normalized_network,
    _parse_name_map,
    _parse_port_modes,
    _parse_site_block,
)
