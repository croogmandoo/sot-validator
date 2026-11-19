"""Tests for the classifier engine facade: re-exported names, aliases and module size limit."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import sot_validator.classifier as classifier
import sot_validator.classifier.engine as engine
import sot_validator.scoring.engine as scoring_engine

CLASSIFIER_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "classifier"
)

DEFINING_MODULES = {
    "DEFAULT_SIGNAL_WEIGHTS": "_policy",
    "_SUBSTANTIVE_STALE_SIGNAL_TYPES": "_policy",
    "_HIGH_CONFIDENCE_ACTIVE_SIGNAL_TYPES": "_policy",
    "_ACTIVE_PROBE_SIGNAL_TYPES": "_policy",
    "_default_signal_weights": "_policy",
    "ClassificationPolicy": "_policy",
    "_EvaluatedSignalView": "_helpers",
    "_has_healthy_tools_detail": "_helpers",
    "_is_windows_context": "_helpers",
    "_sot_power_state_is_active": "_helpers",
    "_has_actionable_identifiers": "_helpers",
    "_index_kwargs": "_helpers",
    "_CollectMixin": "_collect",
    "_ScoringMixin": "_scoring",
    "ClassificationEngine": "engine",
    "ScoringConfig": "engine",
    "ValidationScorer": "engine",
}


@pytest.mark.parametrize("name", sorted(DEFINING_MODULES))
def test_name_importable_from_engine(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.classifier.engine import {name}", namespace)
    assert namespace[name] is getattr(engine, name)
    module = importlib.import_module(
        f"sot_validator.classifier.{DEFINING_MODULES[name]}"
    )
    assert namespace[name] is getattr(module, name)


def test_engine_all_unchanged() -> None:
    assert engine.__all__ == [
        "ClassificationEngine",
        "ClassificationPolicy",
        "DEFAULT_SIGNAL_WEIGHTS",
        "ScoringConfig",
        "ValidationScorer",
    ]


def test_legacy_aliases() -> None:
    assert engine.ScoringConfig is engine.ClassificationPolicy
    assert engine.ValidationScorer is engine.ClassificationEngine


def test_classification_engine_module_path() -> None:
    assert engine.ClassificationEngine.__module__ == "sot_validator.classifier.engine"


def test_score_method_aliases() -> None:
    cls = engine.ClassificationEngine
    assert cls.score is cls.classify
    assert cls.score_signals is cls.classify_signals


def test_package_reexports_are_engine_objects() -> None:
    assert classifier.ClassificationEngine is engine.ClassificationEngine
    assert scoring_engine.ClassificationEngine is engine.ClassificationEngine


def test_classifier_modules_under_800_lines() -> None:
    files = sorted(CLASSIFIER_DIR.glob("*.py"))
    assert files
    for path in files:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
