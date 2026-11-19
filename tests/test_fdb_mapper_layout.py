"""Tests for the FDB mapper facade: re-exported names and module size limit."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import sot_validator.topology as topology
import sot_validator.topology.fdb_mapper as fdb_mapper

TOPOLOGY_DIR = Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "topology"

PUBLIC_NAMES = [
    "FdbEntry",
    "FdbTableParser",
    "PortClassificationResult",
    "SwitchFdbPortMapper",
    "VALID_PORT_MODES",
]

# Name -> private module that defines it.
REEXPORTED_NAMES = {
    "VALID_PORT_MODES": "_fdb_records",
    "FdbEntry": "_fdb_records",
    "PortClassificationResult": "_fdb_records",
    "FdbTableParser": "_fdb_parser",
    "SwitchFdbPortMapper": "_fdb_port_mapper",
    "_ROUTER_ROLES": "_fdb_records",
    "_ROUTER_HOSTNAME_TOKENS": "_fdb_records",
    "_SWITCH_HOSTNAME_TOKENS": "_fdb_records",
    "_IGNORED_PORT_TOKENS": "_fdb_records",
    "_MAC_CANDIDATE_PATTERN": "_fdb_records",
    "_PAREN_VLAN_PATTERN": "_fdb_records",
    "_VLAN_SUFFIX_PATTERN": "_fdb_records",
    "_VOSS_PORT_PREFIX_PATTERN": "_fdb_records",
    "_QBRIDGE_FDB_OID_PATTERN": "_fdb_records",
    "_BRIDGE_FDB_OID_PATTERN": "_fdb_records",
    "_HOSTNAME_TRAILING_DIGITS_PATTERN": "_fdb_records",
    "_parse_mac_token": "_fdb_records",
    "_parse_static_flag": "_fdb_records",
    "_normalize_vlan_id": "_fdb_records",
    "_normalize_voss_port_name": "_fdb_records",
    "_is_ignored_port_token": "_fdb_records",
    "_looks_like_port_name": "_fdb_records",
    "_site_gateway_ips": "_fdb_records",
    "_unlink_port_from_equipment": "_fdb_records",
    "_deduplicate_entries": "_fdb_records",
}

FDB_MODULE_FILES = [
    "fdb_mapper.py",
    "_fdb_records.py",
    "_fdb_parser.py",
    "_fdb_port_mapper.py",
]


@pytest.mark.parametrize("name", sorted(REEXPORTED_NAMES))
def test_name_importable_from_fdb_mapper(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.topology.fdb_mapper import {name}", namespace)
    defining = importlib.import_module(
        f"sot_validator.topology.{REEXPORTED_NAMES[name]}"
    )
    assert namespace[name] is getattr(defining, name)
    assert namespace[name] is getattr(fdb_mapper, name)
    if callable(namespace[name]):
        assert namespace[name].__module__ == defining.__name__


def test_fdb_mapper_all_unchanged() -> None:
    assert fdb_mapper.__all__ == PUBLIC_NAMES


def test_package_names_same_objects() -> None:
    for name in PUBLIC_NAMES:
        assert getattr(topology, name) is getattr(fdb_mapper, name)


def test_apply_to_site_alias_kept() -> None:
    mapper_cls = fdb_mapper.SwitchFdbPortMapper
    assert mapper_cls.apply_to_site is mapper_cls.map_site_ports


@pytest.mark.parametrize("filename", FDB_MODULE_FILES)
def test_fdb_modules_under_800_lines(filename: str) -> None:
    path = TOPOLOGY_DIR / filename
    line_count = len(path.read_text(encoding="utf-8").splitlines())
    assert line_count < 800, f"{filename} has {line_count} lines"
