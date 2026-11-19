"""Tests for the reconciler facade: re-exported names and module size limit."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import sot_validator.reconciliation as reconciliation
import sot_validator.reconciliation.reconciler as reconciler

RECONCILIATION_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "reconciliation"
)

PUBLIC_NAMES = [
    "ALL_DISCREPANCY_TYPES",
    "DISCREPANCY_CSV_COLUMNS",
    "DISCREPANCY_OUI_CSV_COLUMNS",
    "DiscrepancyRecord",
    "DiscrepancyType",
    "InventoryReconciler",
    "ONBOARDING_CSV_COLUMNS",
    "ReconciliationReport",
    "VALID_DISCREPANCY_SOURCES",
]

# Name -> private module that defines it.
REEXPORTED_NAMES = {
    "ALL_DISCREPANCY_TYPES": "_records",
    "DISCREPANCY_CSV_COLUMNS": "_records",
    "DISCREPANCY_OUI_CSV_COLUMNS": "_records",
    "DiscrepancyRecord": "_records",
    "DiscrepancyType": "_records",
    "InventoryReconciler": "_engine",
    "ONBOARDING_CSV_COLUMNS": "_records",
    "ReconciliationReport": "_report",
    "VALID_DISCREPANCY_SOURCES": "_records",
    "_clean_optional_str": "_records",
    "_resolve_timestamp": "_records",
    "_normalize_hostname": "_records",
    "_short_hostname": "_records",
    "_hostnames_match": "_records",
    "_slugify_id": "_records",
    "_sql_literal": "_records",
    "_extract_detail_kv": "_records",
    "_infer_subnet_id": "_records",
    "_NormalizedArpObservation": "_normalizers",
    "_NormalizedSnmpObservation": "_normalizers",
}


@pytest.mark.parametrize("name", sorted(REEXPORTED_NAMES))
def test_name_importable_from_reconciler(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.reconciliation.reconciler import {name}", namespace)
    defining = importlib.import_module(
        f"sot_validator.reconciliation.{REEXPORTED_NAMES[name]}"
    )
    assert namespace[name] is getattr(defining, name)
    assert namespace[name] is getattr(reconciler, name)
    if callable(namespace[name]):
        assert namespace[name].__module__ == defining.__name__


@pytest.mark.parametrize(
    "method",
    [
        "_normalize_sites",
        "_build_subnet_index",
        "_match_ip_to_allocated_subnet",
        "_normalize_vm_records",
        "_normalize_arp_observations",
        "_normalize_snmp_observations",
        "_normalize_icmp_reachable_ips",
        "_collect_equipment_ips_and_macs",
        "_match_vm_to_equipment",
        "reconcile",
    ],
)
def test_reconciler_methods_reachable(method: str) -> None:
    assert callable(getattr(reconciler.InventoryReconciler, method))


def test_reconciler_all_unchanged() -> None:
    assert reconciler.__all__ == PUBLIC_NAMES


def test_package_all_unchanged_and_same_objects() -> None:
    assert reconciliation.__all__ == PUBLIC_NAMES
    for name in reconciliation.__all__:
        assert getattr(reconciliation, name) is getattr(reconciler, name)


def test_reconciliation_modules_under_800_lines() -> None:
    files = sorted(RECONCILIATION_DIR.glob("*.py"))
    assert files
    for path in files:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
