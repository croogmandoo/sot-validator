"""Tests for the router_tables facade: re-exported names and module size limit."""

from __future__ import annotations

from pathlib import Path

import pytest

import sot_validator.discovery as discovery
import sot_validator.discovery._router_collector as router_collector
import sot_validator.discovery._router_common as router_common
import sot_validator.discovery._router_parsers as router_parsers
import sot_validator.discovery._router_records as router_records
import sot_validator.discovery.router_tables as router_tables

DISCOVERY_DIR = Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "discovery"

REEXPORTED_NAMES = [
    ("RouterArpRecord", router_records),
    ("DhcpLeaseRecord", router_records),
    ("RouterTableParsers", router_parsers),
    ("RouterArpDhcpCollector", router_collector),
    ("IP_MIB_NET_TO_MEDIA_NET_ADDRESS_PREFIX", router_common),
    ("IP_MIB_NET_TO_MEDIA_TYPE_PREFIX", router_common),
    ("IF_MIB_IF_DESCR_PREFIX", router_common),
    ("IF_MIB_IF_NAME_PREFIX", router_common),
    ("_coerce_datetime", router_common),
    ("_vlan_from_interface", router_common),
    ("_vlan_from_ip", router_common),
    ("_is_synthetic_device_hostname", router_collector),
    ("_is_synthetic_equipment_name", router_collector),
]

PACKAGE_NAMES = [
    "DhcpLeaseRecord",
    "RouterArpDhcpCollector",
    "RouterArpRecord",
    "RouterTableParsers",
]


@pytest.mark.parametrize(
    ("name", "module"), REEXPORTED_NAMES, ids=[name for name, _ in REEXPORTED_NAMES]
)
def test_name_importable_from_router_tables(name: str, module: object) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.discovery.router_tables import {name}", namespace)
    assert namespace[name] is getattr(module, name)


@pytest.mark.parametrize("name", PACKAGE_NAMES)
def test_package_export_is_facade_object(name: str) -> None:
    assert getattr(discovery, name) is getattr(router_tables, name)


def test_router_tables_all_unchanged() -> None:
    assert router_tables.__all__ == [
        "DhcpLeaseRecord",
        "RouterArpDhcpCollector",
        "RouterArpRecord",
        "RouterTableParsers",
    ]


def test_router_tables_modules_under_800_lines() -> None:
    private = sorted(DISCOVERY_DIR.glob("_router_*.py"))
    assert [path.name for path in private] == [
        "_router_collector.py",
        "_router_common.py",
        "_router_parsers.py",
        "_router_records.py",
    ]
    for path in [DISCOVERY_DIR / "router_tables.py", *private]:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
