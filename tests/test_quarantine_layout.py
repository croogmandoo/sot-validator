"""Tests for the quarantine facade: re-exported names and module size limit."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
import importlib
from pathlib import Path

import pytest

from sot_validator.models import ValidationClassification
import sot_validator.remediation as remediation
import sot_validator.remediation.quarantine as quarantine

REMEDIATION_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "remediation"
)

PUBLIC_NAMES = [
    "ApprovalStatus",
    "QuarantineEngine",
    "QuarantineGraduationStatus",
    "QuarantineManifestEntry",
    "QuarantinePolicy",
    "RemediationApprovalManifest",
    "RemediationOperation",
]

# Name -> private module that defines it.
REEXPORTED_NAMES = {
    "ApprovalStatus": "_quarantine_common",
    "RemediationOperation": "_quarantine_common",
    "QuarantineGraduationStatus": "_quarantine_common",
    "_coerce_approval_status": "_quarantine_common",
    "_coerce_remediation_operation": "_quarantine_common",
    "_coerce_graduation_status": "_quarantine_common",
    "_normalize_string_tuple": "_quarantine_common",
    "_normalize_subnets_tuple": "_quarantine_common",
    "_canonical_token": "_quarantine_common",
    "_word_tokens": "_quarantine_common",
    "_default_operation_for_item": "_quarantine_common",
    "QuarantinePolicy": "_quarantine_policy",
    "QuarantineManifestEntry": "_quarantine_policy",
    "_HybridManifestMethod": "_quarantine_manifest",
    "_CSV_FIELDNAMES": "_quarantine_manifest",
    "RemediationApprovalManifest": "_quarantine_manifest",
    "_SiteInventoryIndex": "_quarantine_engine",
    "_try_parse_ip_addr": "_quarantine_engine",
    "QuarantineEngine": "_quarantine_engine",
}

FIXED_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("name", sorted(REEXPORTED_NAMES))
def test_name_importable_from_quarantine(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.remediation.quarantine import {name}", namespace)
    defining = importlib.import_module(
        f"sot_validator.remediation.{REEXPORTED_NAMES[name]}"
    )
    assert namespace[name] is getattr(defining, name)
    assert namespace[name] is getattr(quarantine, name)
    if callable(namespace[name]):
        assert namespace[name].__module__ == defining.__name__


@pytest.mark.parametrize(
    "method",
    [
        "compute_digest",
        "update_digest",
        "recompute_digest",
        "verify_digest",
        "canonical_entries_payload",
        "set_entry_decision",
        "approve_all",
        "to_dict",
        "from_dict",
        "export_json",
        "export_csv",
        "import_json",
        "import_csv",
    ],
)
def test_manifest_methods_reachable(method: str) -> None:
    assert callable(getattr(quarantine.RemediationApprovalManifest, method))


@pytest.mark.parametrize(
    "method",
    [
        "__init__",
        "map_target_operation",
        "check_protection",
        "_resolve_streak_lookup",
        "evaluate",
        "build_manifest",
    ],
)
def test_engine_methods_reachable(method: str) -> None:
    assert callable(getattr(quarantine.QuarantineEngine, method))


def _make_manifest() -> quarantine.RemediationApprovalManifest:
    policy = quarantine.QuarantinePolicy(
        min_consecutive_stale_runs=3,
        min_stale_days=30.0,
        min_confidence=0.85,
        protected_categories=("ups",),
    )
    entries = [
        quarantine.QuarantineManifestEntry(
            site_id="site-001",
            item_type="IPAddress",
            item_id="10.1.10.55",
            name="10.1.10.55",
            classification=ValidationClassification.STALE_LIKELY_UNUSED,
            confidence=0.92,
            consecutive_stale_runs=4,
            stale_duration_days=38.0,
            target_operation=quarantine.RemediationOperation.RECLAIM_STALE_IP,
            graduation_status=quarantine.QuarantineGraduationStatus.ELIGIBLE,
            approval_status=quarantine.ApprovalStatus.APPROVED,
            reviewed_by="netops-lead",
            reviewed_at=FIXED_TIME,
        ),
        quarantine.QuarantineManifestEntry(
            site_id="site-001",
            item_type="Equipment",
            item_id="eq-001-ups-01",
            name="apc-ups-01.site001.local",
            classification=ValidationClassification.STALE_LIKELY_UNUSED,
            confidence=0.90,
            consecutive_stale_runs=4,
            stale_duration_days=40.0,
            target_operation=quarantine.RemediationOperation.EXEMPT_PROTECTED,
            graduation_status=quarantine.QuarantineGraduationStatus.EXEMPT_PROTECTED,
            approval_status=quarantine.ApprovalStatus.EXEMPT,
            exemption_reason="Protected critical infrastructure category: ups",
        ),
    ]
    return quarantine.RemediationApprovalManifest(
        entries=entries,
        policy=policy,
        generated_at=FIXED_TIME,
        manifest_id="manifest-layout",
    )


@pytest.mark.parametrize("on_instance", [False, True])
def test_hybrid_import_on_class_and_instance(on_instance: bool) -> None:
    manifest = _make_manifest()
    assert manifest.verify_digest() is True
    target = _make_manifest() if on_instance else quarantine.RemediationApprovalManifest

    from_json = target.import_json(manifest.export_json())
    assert from_json.manifest_sha256 == manifest.manifest_sha256
    assert from_json.verify_digest() is True

    from_csv = target.import_csv(
        manifest.export_csv(),
        policy=manifest.policy,
        manifest_sha256=manifest.manifest_sha256,
    )
    assert from_csv.manifest_sha256 == manifest.manifest_sha256
    assert from_csv.verify_digest() is True


def test_manifest_entry_classvars_are_not_fields() -> None:
    field_names = {
        f.name for f in dataclasses.fields(quarantine.QuarantineManifestEntry)
    }
    for name in (
        "FLAG_STALE_IN_SOT",
        "RECLAIM_STALE_IP",
        "DECOMMISSION_VM_RECORD",
        "PROPOSE_PORT_SHUTDOWN",
        "EXEMPT_PROTECTED",
    ):
        assert name not in field_names
        assert hasattr(quarantine.QuarantineManifestEntry, name)


def test_quarantine_all_unchanged() -> None:
    assert quarantine.__all__ == PUBLIC_NAMES


def test_package_names_are_same_objects() -> None:
    for name in PUBLIC_NAMES:
        assert getattr(remediation, name) is getattr(quarantine, name)


def test_quarantine_modules_under_800_lines() -> None:
    files = [REMEDIATION_DIR / "quarantine.py"] + sorted(
        REMEDIATION_DIR.glob("_quarantine_*.py")
    )
    assert len(files) > 1
    for path in files:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
