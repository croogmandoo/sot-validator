"""Tests for the executor facade: re-exported names and module size limit."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import sot_validator.remediation as remediation
import sot_validator.remediation.executor as executor

REMEDIATION_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "remediation"
)

PUBLIC_NAMES = [
    "ManifestVerificationError",
    "RemediationExecutionError",
    "RemediationExecutionResult",
    "RemediationExecutor",
    "RollbackJournal",
    "RollbackJournalEntry",
    "RollbackPlan",
    "SqlRemediationScriptGenerator",
    "SqlRemediationScripts",
]

# Name -> private module that defines it.
REEXPORTED_NAMES = {
    "RemediationExecutionError": "_executor_common",
    "ManifestVerificationError": "_executor_common",
    "_UnknownExecutionIdError": "_executor_common",
    "_TABLE_SQL_COLUMNS": "_executor_common",
    "_TABLE_ORDER": "_executor_common",
    "_format_sql_datetime": "_executor_common",
    "_sql_literal": "_executor_common",
    "_resolve_target_table": "_executor_common",
    "RollbackJournalEntry": "_executor_journal",
    "RollbackPlan": "_executor_journal",
    "_build_rollback_transaction_sql": "_executor_journal",
    "RollbackJournal": "_executor_journal",
    "_normalize_sites_lookup": "_executor_snapshot",
    "_validate_and_filter_manifest_entries": "_executor_snapshot",
    "_table_has_column": "_executor_snapshot",
    "_query_sqlite_snapshot": "_executor_snapshot",
    "_resolve_site_snapshot": "_executor_snapshot",
    "_resolve_fallback_snapshot": "_executor_snapshot",
    "SqlRemediationScripts": "_executor_sql",
    "_build_remediate_and_rollback_row_sql": "_executor_sql",
    "SqlRemediationScriptGenerator": "_executor_sql",
    "RemediationExecutionResult": "_executor_engine",
    "_apply_remediation_to_site": "_executor_engine",
    "_restore_site_from_journal_entry": "_executor_engine",
    "RemediationExecutor": "_executor_engine",
}


@pytest.mark.parametrize("name", sorted(REEXPORTED_NAMES))
def test_name_importable_from_executor(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.remediation.executor import {name}", namespace)
    defining = importlib.import_module(
        f"sot_validator.remediation.{REEXPORTED_NAMES[name]}"
    )
    assert namespace[name] is getattr(defining, name)
    assert namespace[name] is getattr(executor, name)
    if callable(namespace[name]):
        assert namespace[name].__module__ == defining.__name__


@pytest.mark.parametrize(
    ("class_name", "method"),
    [
        ("RemediationExecutor", "execute"),
        ("RemediationExecutor", "execute_entry"),
        ("RemediationExecutor", "generate_rollback_plan"),
        ("RemediationExecutor", "rollback"),
        ("RollbackJournal", "append"),
        ("RollbackJournal", "record"),
        ("RollbackJournal", "append_entries"),
        ("RollbackJournal", "read_entries"),
        ("RollbackJournal", "list_entries"),
        ("RollbackJournal", "get_entries"),
        ("RollbackJournal", "generate_rollback_plan"),
        ("SqlRemediationScriptGenerator", "generate"),
        ("SqlRemediationScriptGenerator", "generate_scripts"),
        ("RollbackJournalEntry", "to_dict"),
        ("RollbackJournalEntry", "from_dict"),
        ("RollbackJournalEntry", "to_json"),
        ("RollbackJournalEntry", "from_json"),
    ],
)
def test_methods_reachable(class_name: str, method: str) -> None:
    assert callable(getattr(getattr(executor, class_name), method))


def test_executor_all_unchanged() -> None:
    assert executor.__all__ == PUBLIC_NAMES


def test_package_names_are_same_objects() -> None:
    executor_names = [name for name in remediation.__all__ if name in PUBLIC_NAMES]
    assert sorted(executor_names) == sorted(PUBLIC_NAMES)
    for name in executor_names:
        assert getattr(remediation, name) is getattr(executor, name)


def test_remediation_modules_under_800_lines() -> None:
    files = sorted(REMEDIATION_DIR.glob("*.py"))
    assert REMEDIATION_DIR / "executor.py" in files
    assert len(list(REMEDIATION_DIR.glob("_executor_*.py"))) == 5
    for path in files:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
