"""Tests for the port reclamation facade: re-exported names and module size limit."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import sot_validator.remediation as remediation
import sot_validator.remediation.port_reclamation as port_reclamation

REMEDIATION_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "remediation"
)

PUBLIC_NAMES = [
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

# Name -> private module that defines it.
REEXPORTED_NAMES = {
    "BlockedPortRecord": "_port_reclamation_records",
    "DEFAULT_BLOCKED_LLDP_CAPABILITIES": "_port_reclamation_common",
    "DEFAULT_CRITICAL_INFRASTRUCTURE_KEYWORDS": "_port_reclamation_common",
    "ExtremeCliDialect": "_port_reclamation_common",
    "ExtremePortReclamationPlanner": "_port_reclamation_planner",
    "LldpGuardDecision": "_port_reclamation_records",
    "LldpNeighborRecord": "_port_reclamation_records",
    "LldpUplinkGuard": "_port_reclamation_guard",
    "PortReclamationCandidate": "_port_reclamation_plan",
    "PortReclamationPlan": "_port_reclamation_plan",
    "_LLDP_INFRASTRUCTURE_ROLES_AND_KEYWORDS": "_port_reclamation_common",
    "_IEEE_8021AB_CAPABILITY_BITS": "_port_reclamation_common",
    "_MILLIWATT_PATTERN": "_port_reclamation_common",
    "_VLAN_RANGE_PATTERN": "_port_reclamation_common",
    "_PORT_TRAILING_DIGITS_PATTERN": "_port_reclamation_common",
    "_SLOT_PORT_PATTERN": "_port_reclamation_common",
    "_coerce_cli_dialect": "_port_reclamation_common",
    "_clean_optional_str": "_port_reclamation_common",
    "_normalize_str_tuple": "_port_reclamation_common",
    "_preserve_str_tuple": "_port_reclamation_common",
    "_decode_lldp_capabilities": "_port_reclamation_common",
    "_coerce_port_and_extras": "_port_reclamation_common",
    "_port_matches_identifier": "_port_reclamation_common",
    "_render_staged_cli_script": "_port_reclamation_plan",
}


@pytest.mark.parametrize("name", sorted(REEXPORTED_NAMES))
def test_name_importable_from_port_reclamation(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(
        f"from sot_validator.remediation.port_reclamation import {name}", namespace
    )
    defining = importlib.import_module(
        f"sot_validator.remediation.{REEXPORTED_NAMES[name]}"
    )
    assert namespace[name] is getattr(defining, name)
    assert namespace[name] is getattr(port_reclamation, name)
    if callable(namespace[name]):
        assert namespace[name].__module__ == defining.__name__


@pytest.mark.parametrize(
    "method",
    [
        "__init__",
        "evaluate_port",
        "_keyword_matches_text",
        "_match_blocked_capabilities",
        "_match_neighbor_infrastructure_indicators",
        "_resolve_port_lldp_neighbors",
        "_coerce_neighbor_list",
        "_iter_raw_mappings",
        "_resolve_connected_peers",
        "_check_tagged_trunk",
        "_check_recent_arp_or_mac_activity",
    ],
)
def test_lldp_uplink_guard_methods_reachable(method: str) -> None:
    assert callable(getattr(port_reclamation.LldpUplinkGuard, method))


@pytest.mark.parametrize(
    "method",
    [
        "__init__",
        "plan",
        "_normalize_sites",
        "_is_extreme_switch",
        "_collect_candidate_ports",
        "_build_streak_lookup",
        "_resolve_port_streak",
        "_lookup_by_port",
        "_resolve_device_oids",
        "_lookup_snmp_oid_for_port",
        "_resolve_poe_watts",
        "_resolve_poe_restore_limit_mw",
    ],
)
def test_planner_methods_reachable(method: str) -> None:
    assert callable(getattr(port_reclamation.ExtremePortReclamationPlanner, method))


def test_port_reclamation_all_unchanged() -> None:
    assert port_reclamation.__all__ == PUBLIC_NAMES


def test_package_names_are_same_objects() -> None:
    for name in PUBLIC_NAMES:
        assert getattr(remediation, name) is getattr(port_reclamation, name)


def test_port_reclamation_modules_under_800_lines() -> None:
    files = [REMEDIATION_DIR / "port_reclamation.py"] + sorted(
        REMEDIATION_DIR.glob("_port_reclamation_*.py")
    )
    assert len(files) > 1
    for path in files:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
