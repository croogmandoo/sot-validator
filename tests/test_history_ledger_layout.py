"""Tests for the history ledger facade: re-exported names and module size limit."""

from __future__ import annotations

import importlib
from pathlib import Path
import sqlite3
import uuid

import pytest

import sot_validator.history as history
import sot_validator.history.ledger as ledger

HISTORY_DIR = Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "history"

PUBLIC_NAMES = [
    "HISTORY_SCHEMA_VERSION",
    "DriftEvent",
    "DriftTransitionType",
    "HistorySchemaVersionError",
    "HistoryStore",
    "ItemStreakSummary",
    "SubnetUtilizationSummary",
    "ValidationRunRecord",
]

# Name -> private module that defines it.
REEXPORTED_NAMES = {
    "ALL_CLASSIFICATION_VALUES": "_records",
    "DriftTransitionType": "_records",
    "_DRIFT_TRANSITION_MAP": "_records",
    "_normalize_optional_utc_datetime": "_records",
    "_require_non_negative_int": "_records",
    "_require_confidence": "_records",
    "_coerce_classification": "_records",
    "_coerce_transition_type": "_records",
    "ValidationRunRecord": "_records",
    "ItemStreakSummary": "_records",
    "DriftEvent": "_records",
    "SubnetUtilizationSummary": "_records",
    "_HybridImportMethod": "_records",
    "_coerce_sites": "_records",
    "_try_parse_ipv4": "_records",
    "_try_parse_slash24_ipv4": "_records",
    "_StoreCore": "_store_core",
    "_RunsMixin": "_store_runs",
    "_PRUNE_CHUNK_SIZE": "_store_runs",
    "_AnalysisMixin": "_store_analysis",
    "_IoMixin": "_store_io",
}


@pytest.mark.parametrize("name", sorted(REEXPORTED_NAMES))
def test_name_importable_from_ledger(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.history.ledger import {name}", namespace)
    defining = importlib.import_module(
        f"sot_validator.history.{REEXPORTED_NAMES[name]}"
    )
    assert namespace[name] is getattr(defining, name)
    assert namespace[name] is getattr(ledger, name)
    if callable(namespace[name]):
        assert namespace[name].__module__ == defining.__name__


@pytest.mark.parametrize(
    "name",
    [
        "HISTORY_SCHEMA_VERSION",
        "HistorySchemaVersionError",
        "HistoryStore",
        "_MIGRATIONS",
        "_migration_1_create_base_tables",
    ],
)
def test_names_defined_in_ledger(name: str) -> None:
    value = getattr(ledger, name)
    if callable(value):
        assert value.__module__ == "sot_validator.history.ledger"


def test_history_store_module_and_bases() -> None:
    assert ledger.HistoryStore.__module__ == "sot_validator.history.ledger"
    assert issubclass(ledger.HistoryStore, ledger._StoreCore)
    assert ledger.HISTORY_SCHEMA_VERSION == len(ledger._MIGRATIONS)


@pytest.mark.parametrize(
    "method",
    [
        "__init__",
        "_init_schema",
        "close",
        "__enter__",
        "__exit__",
        "_next_generated_run_id",
        "_row_to_run_record",
        "_row_to_streak",
        "_row_to_drift_event",
        "record_run",
        "get_run",
        "list_runs",
        "_select_prunable_runs",
        "_count_or_delete_drift_events",
        "prune_runs",
        "get_item_streak",
        "list_streaks",
        "detect_drift",
        "compute_subnet_utilization",
        "_list_all_drift_events",
        "to_dict",
        "to_json",
        "export_json",
        "_load_state_from_mapping",
        "from_dict",
        "from_json",
        "_import_json_impl",
        "import_json",
    ],
)
def test_history_store_methods_reachable(method: str) -> None:
    assert callable(getattr(ledger.HistoryStore, method))


def test_import_json_works_on_class_and_instance(tmp_path: Path) -> None:
    source = ledger.HistoryStore()
    path = source.export_json(tmp_path / "history.json")
    source.close()
    from_class = ledger.HistoryStore.import_json(path)
    assert isinstance(from_class, ledger.HistoryStore)
    target = ledger.HistoryStore()
    assert target.import_json(path) is target
    from_class.close()
    target.close()


def test_ledger_all_unchanged() -> None:
    assert ledger.__all__ == PUBLIC_NAMES


def test_package_all_same_objects() -> None:
    for name in history.__all__:
        assert getattr(history, name) is getattr(ledger, name)


def test_stdlib_modules_still_reachable_from_ledger() -> None:
    assert ledger.sqlite3 is sqlite3
    assert ledger.uuid is uuid


def test_history_modules_under_800_lines() -> None:
    files = sorted(HISTORY_DIR.glob("*.py"))
    assert files
    for path in files:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
