"""Tests for the campaign orchestrator facade: re-exported names and module size limit."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import sot_validator.campaign as campaign
import sot_validator.campaign.orchestrator as orchestrator

CAMPAIGN_DIR = Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "campaign"

ORCHESTRATOR_ALL = [
    "CampaignConfig",
    "CampaignOrchestrator",
    "CampaignRunSummary",
    "CircuitBreakerTrippedError",
    "DEFAULT_CRITICAL_CATEGORIES",
    "SiteWaveResult",
    "SiteWaveStatus",
]

PACKAGE_ALL = [
    "AlertEvent",
    "AlertSeverity",
    "AlertSink",
    "AlertType",
    "CampaignConfig",
    "CampaignOrchestrator",
    "CampaignRunSummary",
    "CircuitBreakerTrippedError",
    "InMemoryAlertSink",
    "JsonFileAlertSink",
    "SiteWaveResult",
    "SiteWaveStatus",
    "WebhookPayloadFormatter",
]

# Name -> module that defines it.
DEFINING_MODULES = {
    "CampaignConfig": "_records",
    "CampaignOrchestrator": "orchestrator",
    "CampaignRunSummary": "_records",
    "CircuitBreakerTrippedError": "_records",
    "DEFAULT_CRITICAL_CATEGORIES": "_records",
    "SiteWaveResult": "_records",
    "SiteWaveStatus": "_records",
}


@pytest.mark.parametrize("name", ORCHESTRATOR_ALL)
def test_name_importable_from_orchestrator(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.campaign.orchestrator import {name}", namespace)
    defining = importlib.import_module(
        f"sot_validator.campaign.{DEFINING_MODULES[name]}"
    )
    assert namespace[name] is getattr(defining, name)
    assert namespace[name] is getattr(orchestrator, name)
    if isinstance(namespace[name], type):
        assert namespace[name].__module__ == defining.__name__


@pytest.mark.parametrize(
    "method",
    [
        "run",
        "iter_cohorts",
        "_resolve_eval_time",
        "_dispatch_alerts",
        "_resolve_item_category",
        "_evaluate_critical_infra_alerts",
    ],
)
def test_orchestrator_methods_reachable(method: str) -> None:
    assert callable(getattr(orchestrator.CampaignOrchestrator, method))


def test_orchestrator_all_unchanged() -> None:
    assert orchestrator.__all__ == ORCHESTRATOR_ALL
    assert sorted(DEFINING_MODULES) == ORCHESTRATOR_ALL


def test_package_all_unchanged_and_same_objects() -> None:
    assert campaign.__all__ == PACKAGE_ALL
    for name in campaign.__all__:
        if name in DEFINING_MODULES:
            assert getattr(campaign, name) is getattr(orchestrator, name)


def test_records_does_not_import_orchestrator_or_package() -> None:
    source = (CAMPAIGN_DIR / "_records.py").read_text(encoding="utf-8")
    assert "sot_validator.campaign.orchestrator" not in source
    assert "from . import" not in source
    assert "from .orchestrator" not in source
    for line in source.splitlines():
        stripped = line.strip()
        assert not stripped.startswith("from sot_validator.campaign import")
        assert stripped != "import sot_validator.campaign"
        assert not stripped.startswith("import sot_validator.campaign ")
    # The only campaign import allowed is the leaf alerts module (AlertEvent).
    campaign_imports = [
        line.strip()
        for line in source.splitlines()
        if line.strip().startswith(("from sot_validator.campaign", "import sot_validator.campaign"))
        or line.strip().startswith("from .")
    ]
    assert campaign_imports == ["from sot_validator.campaign.alerts import AlertEvent"]


def test_campaign_modules_under_800_lines() -> None:
    files = sorted(CAMPAIGN_DIR.glob("*.py"))
    assert files
    for path in files:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
