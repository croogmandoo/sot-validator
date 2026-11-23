"""Tests for the quality.checks facade: re-exported names and module size limit."""

from __future__ import annotations

from pathlib import Path

import pytest

import sot_validator.quality._checker as quality_checker
import sot_validator.quality._records as quality_records

QUALITY_DIR = Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "quality"

REEXPORTED_NAMES = [
    ("RULE_DUPLICATE_IP", quality_records),
    ("RULE_DUPLICATE_MAC", quality_records),
    ("RULE_IP_OUTSIDE_SITE_BLOCK", quality_records),
    ("RULE_IP_OUTSIDE_ACTIVE_SUBNET", quality_records),
    ("RULE_ORPHAN_REFERENCE", quality_records),
    ("RULE_HOSTNAME_MISMATCH", quality_records),
    ("RULE_CROSS_SITE_DUPLICATE_IP", quality_records),
    ("RULE_CROSS_SITE_DUPLICATE_MAC", quality_records),
    ("SINGLE_SITE_RULES", quality_records),
    ("CROSS_SITE_RULES", quality_records),
    ("ALL_RULE_NAMES", quality_records),
    ("VALID_SEVERITIES", quality_records),
    ("_TRUNK_PORT_MODES", quality_records),
    ("_MAC_PATTERN", quality_records),
    ("_compute_finding_id", quality_records),
    ("QualityFinding", quality_records),
    ("DataQualityChecker", quality_checker),
    ("_canonical_ip_key", quality_records),
    ("_normalized_ip", quality_records),
    ("_normalized_network", quality_records),
    ("_normalized_mac", quality_records),
    ("_ip_assignment_ref", quality_records),
    ("_parse_site_block", quality_records),
    ("_parse_port_modes", quality_records),
    ("_parse_name_map", quality_records),
    ("_lookup_name", quality_records),
    ("_derive_site_block", quality_records),
]


@pytest.mark.parametrize(
    ("name", "module"), REEXPORTED_NAMES, ids=[name for name, _ in REEXPORTED_NAMES]
)
def test_name_importable_from_quality_checks(name: str, module: object) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.quality.checks import {name}", namespace)
    assert namespace[name] is getattr(module, name)


@pytest.mark.parametrize("filename", ["_records.py", "_checker.py"])
def test_private_modules_do_not_import_facade_or_package(filename: str) -> None:
    source = (QUALITY_DIR / filename).read_text(encoding="utf-8")
    assert "sot_validator.quality.checks" not in source
    assert "from sot_validator.quality import" not in source


def test_records_does_not_import_checker() -> None:
    source = (QUALITY_DIR / "_records.py").read_text(encoding="utf-8")
    assert "_checker" not in source


def test_quality_modules_under_800_lines() -> None:
    paths = sorted(QUALITY_DIR.glob("*.py"))
    assert {"checks.py", "_records.py", "_checker.py"} <= {path.name for path in paths}
    for path in paths:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
