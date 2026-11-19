"""Tests for the migration exporter facade: re-exported names and module size limit."""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path

import pytest

import sot_validator.migration as migration
import sot_validator.migration.exporter as exporter

MIGRATION_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "migration"
)

PUBLIC_NAMES = [
    "CSV_COLUMNS_BY_ENTITY",
    "ENTITY_COLLECTION_KEYS",
    "GoldenInventoryFilter",
    "ModernSoTExporter",
    "SUPPORTED_TARGET_PLATFORMS",
    "slugify",
]

PACKAGE_NAMES = [
    "ALL_CUTOVER_RECOMMENDATIONS",
    "ALL_PARITY_DISCREPANCY_TYPES",
    "CSV_COLUMNS_BY_ENTITY",
    "CutoverRecommendation",
    "DualRunParityChecker",
    "ENTITY_COLLECTION_KEYS",
    "GoldenInventoryFilter",
    "MigrationParityReport",
    "ModernSoTExporter",
    "ModernSoTParityValidator",
    "ModernSoTPlatform",
    "NAUTOBOT_CSV_SCHEMAS",
    "NETBOX_CSV_SCHEMAS",
    "PARITY_ENTITY_COLLECTIONS",
    "ParityDiscrepancy",
    "ParityDiscrepancyType",
    "ParityValidationReport",
    "SUPPORTED_TARGET_PLATFORMS",
    "SiteMigrationReadinessScorecard",
    "TargetPlatform",
    "slugify",
    "slugify_identifier",
]

PACKAGE_EXPORTER_NAMES = [
    "CSV_COLUMNS_BY_ENTITY",
    "ENTITY_COLLECTION_KEYS",
    "SUPPORTED_TARGET_PLATFORMS",
    "GoldenInventoryFilter",
    "ModernSoTExporter",
    "TargetPlatform",
    "slugify",
]

# Name -> private module that defines it.
REEXPORTED_NAMES = {
    "TargetPlatform": "_exporter_helpers",
    "SUPPORTED_TARGET_PLATFORMS": "_exporter_helpers",
    "ENTITY_COLLECTION_KEYS": "_exporter_helpers",
    "CSV_COLUMNS_BY_ENTITY": "_exporter_helpers",
    "_LINUX_NAME_INDICATORS": "_exporter_helpers",
    "slugify": "_exporter_helpers",
    "_resolve_timestamp": "_exporter_helpers",
    "_strip_ip_mask": "_exporter_helpers",
    "_parse_vlan_vid": "_exporter_helpers",
    "_parse_contact_info": "_exporter_helpers",
    "_infer_equipment_manufacturer_and_model": "_exporter_helpers",
    "_infer_vm_os_family": "_exporter_helpers",
    "_normalize_sites_input": "_exporter_helpers",
    "_normalize_validation_results": "_exporter_helpers",
    "_normalize_discrepancies": "_exporter_helpers",
    "GoldenInventoryFilter": "_exporter_filter",
    "ModernSoTExporter": "_exporter_bundle",
}

SPLIT_FILES = [
    "_exporter_helpers.py",
    "_exporter_filter.py",
    "_exporter_bundle.py",
]


@pytest.mark.parametrize("name", sorted(REEXPORTED_NAMES))
def test_name_importable_from_exporter(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.migration.exporter import {name}", namespace)
    defining = importlib.import_module(
        f"sot_validator.migration.{REEXPORTED_NAMES[name]}"
    )
    assert namespace[name] is getattr(defining, name)
    assert namespace[name] is getattr(exporter, name)
    if inspect.isfunction(namespace[name]) or inspect.isclass(namespace[name]):
        assert namespace[name].__module__ == defining.__name__


def test_exporter_all_unchanged() -> None:
    assert exporter.__all__ == PUBLIC_NAMES


def test_package_all_unchanged_and_same_objects() -> None:
    assert migration.__all__ == PACKAGE_NAMES
    for name in PACKAGE_EXPORTER_NAMES:
        assert getattr(migration, name) is getattr(exporter, name)


def test_migration_modules_under_800_lines() -> None:
    files = sorted(MIGRATION_DIR.glob("*.py"))
    assert files
    for path in files:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"


@pytest.mark.parametrize("filename", SPLIT_FILES)
def test_private_modules_do_not_import_facade(filename: str) -> None:
    text = (MIGRATION_DIR / filename).read_text(encoding="utf-8")
    assert "migration.exporter" not in text
    assert "from sot_validator.migration import" not in text
    assert "parity" not in text
