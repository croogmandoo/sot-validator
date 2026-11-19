"""Tests for the discovery scanner facade: re-exported names and module size limit."""

from __future__ import annotations

from pathlib import Path

import pytest

import sot_validator.discovery as discovery
import sot_validator.discovery._scanner_common as scanner_common
import sot_validator.discovery._scanner_engine as scanner_engine
import sot_validator.discovery._scanner_models as scanner_models
import sot_validator.discovery._scanner_probes as scanner_probes
import sot_validator.discovery.scanner as scanner

DISCOVERY_DIR = Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "discovery"

REEXPORTED_NAMES = [
    ("DEFAULT_GATEWAY_OCTETS", scanner_common),
    ("DEFAULT_TCP_PORTS", scanner_common),
    ("_SERVER_TCP_PORTS", scanner_common),
    ("_NEIGH_STATES", scanner_common),
    ("_PING_RTT_PATTERN", scanner_common),
    ("_HEX_RE", scanner_common),
    ("_normalize_mac", scanner_common),
    ("_infer_vlan_id_from_subnet", scanner_common),
    ("parse_ip_neigh_output", scanner_common),
    ("_infer_host_role", scanner_common),
    ("_role_to_equipment_category", scanner_common),
    ("DiscoveredHost", scanner_models),
    ("DiscoveryConfig", scanner_models),
    ("_run_coro_sync", scanner_probes),
    ("_DEFAULT_CHILD_PATH", scanner_probes),
    ("_minimal_child_env", scanner_probes),
    ("_default_async_ping", scanner_probes),
    ("_default_async_tcp_probe", scanner_probes),
    ("_default_arp_table_reader", scanner_probes),
    ("_default_async_rdns", scanner_probes),
    ("SubnetDiscoveryScanner", scanner_engine),
]

PACKAGE_NAMES = [
    "DEFAULT_GATEWAY_OCTETS",
    "DEFAULT_TCP_PORTS",
    "DiscoveredHost",
    "DiscoveryConfig",
    "SubnetDiscoveryScanner",
    "parse_ip_neigh_output",
]


@pytest.mark.parametrize(
    ("name", "module"), REEXPORTED_NAMES, ids=[name for name, _ in REEXPORTED_NAMES]
)
def test_name_importable_from_scanner(name: str, module: object) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.discovery.scanner import {name}", namespace)
    assert namespace[name] is getattr(module, name)


@pytest.mark.parametrize("name", PACKAGE_NAMES)
def test_package_export_is_facade_object(name: str) -> None:
    assert getattr(discovery, name) is getattr(scanner, name)


def test_scanner_all_is_unchanged() -> None:
    assert scanner.__all__ == PACKAGE_NAMES


def test_scanner_modules_under_800_lines() -> None:
    private = sorted(DISCOVERY_DIR.glob("_scanner_*.py"))
    assert [path.name for path in private] == [
        "_scanner_common.py",
        "_scanner_engine.py",
        "_scanner_models.py",
        "_scanner_probes.py",
    ]
    for path in [DISCOVERY_DIR / "scanner.py", *private]:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
