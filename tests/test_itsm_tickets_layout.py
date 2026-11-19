"""Tests for the ITSM tickets facade: re-exported names and module size limit."""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path

import pytest

import sot_validator.itsm as itsm
import sot_validator.itsm.tickets as tickets

ITSM_DIR = Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "itsm"

PUBLIC_NAMES = [
    "InMemoryItsmSink",
    "ItsmApprovalStatus",
    "ItsmGateVerificationError",
    "ItsmGateVerificationResult",
    "ItsmGateVerifier",
    "ItsmProvider",
    "ItsmSink",
    "ItsmTicketPayloadBuilder",
    "ItsmTicketRequest",
    "ItsmWebhookSerializer",
    "ItsmWorkflowType",
    "JsonFileItsmSink",
    "QuarantineReport",
    "TicketApprovalStatus",
    "TicketPriority",
    "TicketRisk",
    "WebhookItsmSink",
    "compute_artifact_sha256",
]

# Name -> private module that defines it.
REEXPORTED_NAMES = {
    "InMemoryItsmSink": "_sinks",
    "ItsmApprovalStatus": "_enums",
    "ItsmGateVerificationError": "_gate",
    "ItsmGateVerificationResult": "_gate",
    "ItsmGateVerifier": "_gate",
    "ItsmProvider": "_enums",
    "ItsmSink": "_sinks",
    "ItsmTicketPayloadBuilder": "_builder",
    "ItsmTicketRequest": "_request",
    "ItsmWebhookSerializer": "_sinks",
    "ItsmWorkflowType": "_enums",
    "JsonFileItsmSink": "_sinks",
    "QuarantineReport": "_request",
    "TicketApprovalStatus": "_enums",
    "TicketPriority": "_enums",
    "TicketRisk": "_enums",
    "WebhookItsmSink": "_sinks",
    "compute_artifact_sha256": "_request",
    "_coerce_workflow_type": "_enums",
    "_coerce_provider": "_enums",
    "_coerce_ticket_approval_status": "_enums",
    "_coerce_risk": "_enums",
    "_coerce_priority": "_enums",
    "_normalize_str_list": "_enums",
    "_deterministic_ticket_id": "_request",
}

# Aliases of objects defined outside the itsm package.
EXTERNAL_ALIASES = {"QuarantineReport"}

BUILDER_STATIC_METHODS = [
    "_coerce_ups_report",
    "format_servicenow",
    "format_jira",
    "format_webhook",
]

BUILDER_INSTANCE_METHODS = [
    "__init__",
    "_resolve_timestamp",
    "build_quarantine_ticket",
    "build_port_reclamation_ticket",
    "build_onboarding_ticket",
    "build_ups_incident_ticket",
    "build_ups_incident_tickets",
    "build_ticket",
]


@pytest.mark.parametrize("name", sorted(REEXPORTED_NAMES))
def test_name_importable_from_tickets(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.itsm.tickets import {name}", namespace)
    defining = importlib.import_module(f"sot_validator.itsm.{REEXPORTED_NAMES[name]}")
    assert namespace[name] is getattr(defining, name)
    assert namespace[name] is getattr(tickets, name)
    if callable(namespace[name]) and name not in EXTERNAL_ALIASES:
        assert namespace[name].__module__ == defining.__name__


def test_quarantine_report_alias() -> None:
    from sot_validator.remediation.quarantine import RemediationApprovalManifest

    assert tickets.QuarantineReport is RemediationApprovalManifest
    assert tickets.ItsmApprovalStatus is tickets.TicketApprovalStatus


@pytest.mark.parametrize("method", BUILDER_INSTANCE_METHODS)
def test_builder_instance_methods_reachable(method: str) -> None:
    builder = tickets.ItsmTicketPayloadBuilder
    assert callable(getattr(builder, method))
    assert inspect.isfunction(inspect.getattr_static(builder, method))


@pytest.mark.parametrize("method", BUILDER_STATIC_METHODS)
def test_builder_static_methods_reachable(method: str) -> None:
    builder = tickets.ItsmTicketPayloadBuilder
    assert callable(getattr(builder, method))
    assert isinstance(inspect.getattr_static(builder, method), staticmethod)


def test_tickets_all_unchanged() -> None:
    assert tickets.__all__ == PUBLIC_NAMES


def test_package_all_unchanged_and_same_objects() -> None:
    assert itsm.__all__ == PUBLIC_NAMES
    for name in itsm.__all__:
        assert getattr(itsm, name) is getattr(tickets, name)


def test_itsm_modules_under_800_lines() -> None:
    files = sorted(ITSM_DIR.glob("*.py"))
    assert files
    for path in files:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
