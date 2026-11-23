"""Tests for the role identifier facade: re-exported names and module size limit."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import sot_validator.topology as topology
import sot_validator.topology.identifier as identifier

TOPOLOGY_DIR = Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "topology"

PUBLIC_NAMES = [
    "ConsolidatedRouter",
    "HostIdentification",
    "KNOWN_OUI_VENDORS",
    "KNOWN_SCAN_TCP_PORTS",
    "NetworkRoleIdentifier",
    "VALID_HOST_ROLES",
]

# Name -> private module that defines it.
REEXPORTED_NAMES = {
    "VALID_HOST_ROLES": "_identifier_helpers",
    "KNOWN_SCAN_TCP_PORTS": "_identifier_helpers",
    "KNOWN_OUI_VENDORS": "_identifier_helpers",
    "_TOKEN_SPLIT_PATTERN": "_identifier_helpers",
    "_TRAILING_DIGITS_PATTERN": "_identifier_helpers",
    "_normalize_optional_mac": "_identifier_helpers",
    "_extract_oui_prefix": "_identifier_helpers",
    "_parse_ipv4_octets": "_identifier_helpers",
    "_infer_subnet_cidr": "_identifier_helpers",
    "_infer_vlan_id": "_identifier_helpers",
    "_hostname_tokens": "_identifier_helpers",
    "_matches_hostname": "_identifier_helpers",
    "HostIdentification": "_identifier_models",
    "ConsolidatedRouter": "_identifier_models",
    "NetworkRoleIdentifier": "_identifier_engine",
}

IDENTIFIER_MODULE_FILES = [
    "identifier.py",
    "_identifier_helpers.py",
    "_identifier_models.py",
    "_identifier_engine.py",
]


@pytest.mark.parametrize("name", sorted(REEXPORTED_NAMES))
def test_name_importable_from_identifier(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.topology.identifier import {name}", namespace)
    defining = importlib.import_module(
        f"sot_validator.topology.{REEXPORTED_NAMES[name]}"
    )
    assert namespace[name] is getattr(defining, name)
    assert namespace[name] is getattr(identifier, name)
    if callable(namespace[name]):
        assert namespace[name].__module__ == defining.__name__


def test_identifier_all_unchanged() -> None:
    assert identifier.__all__ == PUBLIC_NAMES


def test_package_names_same_objects() -> None:
    for name in PUBLIC_NAMES:
        assert getattr(topology, name) is getattr(identifier, name)


@pytest.mark.parametrize("filename", IDENTIFIER_MODULE_FILES)
def test_identifier_modules_under_800_lines(filename: str) -> None:
    path = TOPOLOGY_DIR / filename
    line_count = len(path.read_text(encoding="utf-8").splitlines())
    assert line_count < 800, f"{filename} has {line_count} lines"
