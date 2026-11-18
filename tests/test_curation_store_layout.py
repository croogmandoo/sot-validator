"""Tests for the curation store facade: re-exported names and module size limit."""

from __future__ import annotations

from pathlib import Path

import pytest

import sot_validator.curation.store as store

CURATION_DIR = Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "curation"

REEXPORTED_NAMES = [
    "_CANONICAL_TARGET_TYPES",
    "VALID_TARGET_TYPES",
    "GENESIS_HASH",
    "_AUDIT_LOG_TARGET_TYPE",
    "_HASH_PATTERN",
    "_MIGRATION_REASON",
    "_PATCH_MERGEABLE_FIELDS",
    "_normalize_target_type",
    "_normalize_optional_hash",
    "_normalize_optional_str",
    "_normalize_optional_utc_datetime",
    "_coerce_equipment_category",
    "_coerce_validation_classification",
    "_require_non_negative_int",
    "ItemEditPatch",
    "AuditLogEntry",
    "_compute_entry_hash",
    "_chain_entries",
    "AuditChainReport",
    "_validate_anchor",
    "verify_audit_chain",
    "_HybridImportMethod",
    "CurationStore",
    "_format_pin_rationale",
    "apply_curation_overlay",
]


@pytest.mark.parametrize("name", REEXPORTED_NAMES)
def test_name_importable_from_store(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.curation.store import {name}", namespace)
    assert namespace[name] is getattr(store, name)


def test_curation_store_module_path() -> None:
    assert store.CurationStore.__module__ == "sot_validator.curation.store"


def test_store_all_unchanged() -> None:
    assert store.__all__ == [
        "AuditLogEntry",
        "CurationStore",
        "ItemEditPatch",
        "apply_curation_overlay",
    ]


def test_curation_modules_under_800_lines() -> None:
    files = sorted(CURATION_DIR.glob("*.py"))
    assert files
    for path in files:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
