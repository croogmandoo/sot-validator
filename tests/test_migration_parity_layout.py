"""Tests for the migration parity facade: re-exported names, aliases and module size limit."""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path

import pytest

import sot_validator.migration as migration
import sot_validator.migration.parity as parity

MIGRATION_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "migration"
)

PUBLIC_NAMES = [
    "ALL_CUTOVER_RECOMMENDATIONS",
    "ALL_PARITY_DISCREPANCY_TYPES",
    "CutoverRecommendation",
    "DualRunParityChecker",
    "MigrationParityReport",
    "ModernSoTParityValidator",
    "PARITY_ENTITY_COLLECTIONS",
    "ParityDiscrepancy",
    "ParityDiscrepancyType",
    "ParityValidationReport",
    "SiteMigrationReadinessScorecard",
]

# Name -> private module that defines it.
REEXPORTED_NAMES = {
    "PARITY_ENTITY_COLLECTIONS": "_parity_records",
    "_STALE_MODERN_STATUSES": "_parity_records",
    "_UNTRACKED_DISCREPANCY_TYPES": "_parity_records",
    "ParityDiscrepancyType": "_parity_records",
    "CutoverRecommendation": "_parity_records",
    "ALL_PARITY_DISCREPANCY_TYPES": "_parity_records",
    "ALL_CUTOVER_RECOMMENDATIONS": "_parity_records",
    "_clean_optional_str": "_parity_records",
    "_clamp_percentage": "_parity_records",
    "_extract_legacy_id": "_parity_records",
    "_extract_explicit_ip": "_parity_records",
    "_extract_record_identifier": "_parity_records",
    "_record_candidate_tokens": "_parity_records",
    "ParityDiscrepancy": "_parity_models",
    "SiteMigrationReadinessScorecard": "_parity_models",
    "MigrationParityReport": "_parity_models",
    "_ParityMatchingMixin": "_parity_matching",
    "_ParityEvaluateMixin": "_parity_evaluate",
    "DualRunParityChecker": "_parity_checker",
}

ALIASES = {
    "ParityValidationReport": "MigrationParityReport",
    "ModernSoTParityValidator": "DualRunParityChecker",
}

STATIC_HELPERS = [
    "_is_bundle_mapping",
    "_expand_waived_tokens",
    "_collect_stale_tokens",
    "_filter_bundle_for_site",
    "_records_match_exact",
    "_records_match_fallback",
    "_compare_matched_records",
    "_is_untracked_resolved_in_bundle",
]

# Methods that take ``self``; ``_coerce_to_bundle`` was never a staticmethod.
INSTANCE_METHODS = [
    "__init__",
    "_coerce_to_bundle",
    "evaluate_site",
    "evaluate_sites",
    "evaluate",
    "check_parity",
]

SPLIT_FILES = [
    "parity.py",
    "_parity_records.py",
    "_parity_models.py",
    "_parity_matching.py",
    "_parity_evaluate.py",
    "_parity_checker.py",
]


@pytest.mark.parametrize("name", sorted(REEXPORTED_NAMES))
def test_name_importable_from_parity(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.migration.parity import {name}", namespace)
    defining = importlib.import_module(
        f"sot_validator.migration.{REEXPORTED_NAMES[name]}"
    )
    assert namespace[name] is getattr(defining, name)
    assert namespace[name] is getattr(parity, name)
    if inspect.isclass(namespace[name]) or inspect.isfunction(namespace[name]):
        assert namespace[name].__module__ == defining.__name__


@pytest.mark.parametrize("alias", sorted(ALIASES))
def test_aliases_are_targets(alias: str) -> None:
    assert getattr(parity, alias) is getattr(parity, ALIASES[alias])


def test_parity_all_unchanged() -> None:
    assert parity.__all__ == PUBLIC_NAMES


def test_package_exposes_same_objects() -> None:
    for name in PUBLIC_NAMES:
        assert getattr(migration, name) is getattr(parity, name)


def test_checker_bases() -> None:
    checker = parity.DualRunParityChecker
    assert checker.__bases__ == (
        parity._ParityEvaluateMixin,
        parity._ParityMatchingMixin,
    )


@pytest.mark.parametrize("method", STATIC_HELPERS)
def test_static_helpers_reachable(method: str) -> None:
    checker = parity.DualRunParityChecker
    assert callable(getattr(checker, method))
    assert isinstance(inspect.getattr_static(checker, method), staticmethod)


@pytest.mark.parametrize("method", INSTANCE_METHODS)
def test_instance_methods_reachable(method: str) -> None:
    checker = parity.DualRunParityChecker
    assert callable(getattr(checker, method))
    assert inspect.isfunction(inspect.getattr_static(checker, method))


@pytest.mark.parametrize("filename", SPLIT_FILES)
def test_split_files_under_800_lines(filename: str) -> None:
    path = MIGRATION_DIR / filename
    line_count = len(path.read_text(encoding="utf-8").splitlines())
    assert line_count < 800, f"{filename} has {line_count} lines"


@pytest.mark.parametrize("filename", SPLIT_FILES[1:])
def test_private_modules_do_not_import_facade(filename: str) -> None:
    text = (MIGRATION_DIR / filename).read_text(encoding="utf-8")
    assert "migration.parity" not in text
    assert "from sot_validator.migration import" not in text
