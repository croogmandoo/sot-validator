"""Phase 4 LLDP Uplink Guard and Staged Extreme Switch Port & PoE Reclamation Planner."""

from __future__ import annotations

from sot_validator.remediation._port_reclamation_common import (
    DEFAULT_BLOCKED_LLDP_CAPABILITIES,
    DEFAULT_CRITICAL_INFRASTRUCTURE_KEYWORDS,
    ExtremeCliDialect,
    _IEEE_8021AB_CAPABILITY_BITS,
    _LLDP_INFRASTRUCTURE_ROLES_AND_KEYWORDS,
    _MILLIWATT_PATTERN,
    _PORT_TRAILING_DIGITS_PATTERN,
    _SLOT_PORT_PATTERN,
    _VLAN_RANGE_PATTERN,
    _clean_optional_str,
    _coerce_cli_dialect,
    _coerce_port_and_extras,
    _decode_lldp_capabilities,
    _normalize_str_tuple,
    _port_matches_identifier,
    _preserve_str_tuple,
)
from sot_validator.remediation._port_reclamation_guard import LldpUplinkGuard
from sot_validator.remediation._port_reclamation_plan import (
    PortReclamationCandidate,
    PortReclamationPlan,
    _render_staged_cli_script,
)
from sot_validator.remediation._port_reclamation_planner import (
    ExtremePortReclamationPlanner,
)
from sot_validator.remediation._port_reclamation_records import (
    BlockedPortRecord,
    LldpGuardDecision,
    LldpNeighborRecord,
)


__all__ = [
    "BlockedPortRecord",
    "DEFAULT_BLOCKED_LLDP_CAPABILITIES",
    "DEFAULT_CRITICAL_INFRASTRUCTURE_KEYWORDS",
    "ExtremeCliDialect",
    "ExtremePortReclamationPlanner",
    "LldpGuardDecision",
    "LldpNeighborRecord",
    "LldpUplinkGuard",
    "PortReclamationCandidate",
    "PortReclamationPlan",
]
