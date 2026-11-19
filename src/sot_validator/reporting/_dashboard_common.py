"""Constants, escaping, badge, inventory-payload and input coercion helpers for the HTML dashboard."""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
import gzip
import html
import json
from typing import Any, Optional

from sot_validator.history.ledger import (
    HistoryStore,
    ItemStreakSummary,
    SubnetUtilizationSummary,
)
from sot_validator.itsm.tickets import (
    InMemoryItsmSink,
    ItsmTicketRequest,
    TicketApprovalStatus,
)
from sot_validator.migration.parity import (
    CutoverRecommendation,
    ParityValidationReport,
    SiteMigrationReadinessScorecard,
)
from sot_validator.models import (
    Site,
    ValidationClassification,
    ValidationResult,
)
from sot_validator.reconciliation.reconciler import ReconciliationReport
from sot_validator.remediation.port_reclamation import (
    PortReclamationPlan,
)
from sot_validator.remediation.quarantine import (
    ApprovalStatus,
    RemediationApprovalManifest,
)
from sot_validator.signals.ups_health import (
    UpsFleetHealthReport,
    UpsHealthRecord,
    UpsHealthStatus,
)

DEFAULT_DASHBOARD_FILENAME = "validation_dashboard.html"
DEFAULT_DASHBOARD_TITLE = "SoT Inventory Validation & Operations Dashboard"


def _esc(value: Any) -> str:
    """Escape any value for safe inclusion in HTML text or quoted attributes."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _classification_badge_class(classification: str) -> str:
    if classification == ValidationClassification.CONFIRMED_ACTIVE.value:
        return "badge-active"
    if classification == ValidationClassification.STALE_LIKELY_UNUSED.value:
        return "badge-stale"
    if classification == ValidationClassification.UNREACHABLE_NEEDS_REVIEW.value:
        return "badge-unreachable"
    return "badge-insufficient"


def _inventory_record(item: Mapping[str, Any]) -> dict[str, Any]:
    sid = str(item.get("site_id") or "")
    ips_list = item.get("ip_addresses") or []
    cls_str = str(item.get("classification") or "")
    return {
        "site_id": sid,
        "site_name": str(item.get("site_name") or sid),
        "item_type": str(item.get("item_type") or ""),
        "item_id": str(item.get("item_id") or ""),
        "name": str(item.get("name") or ""),
        "category": str(item.get("category") or "-"),
        "ips": ", ".join(str(ip) for ip in ips_list) if ips_list else "-",
        "classification": cls_str,
        "badge": _classification_badge_class(cls_str),
        "confidence": f"{float(item.get('confidence') or 0.0):.2f}",
        "rationale": str(item.get("rationale") or ""),
        "signals": [
            {
                "type": str(sig.get("signal_type", "")),
                "status": str(sig.get("status", "")),
                "source": str(sig.get("source") or "n/a"),
                "age": (
                    f"{float(sig['age_seconds']):.1f}s"
                    if sig.get("age_seconds") is not None
                    else "n/a"
                ),
                "details": str(sig.get("details") or ""),
            }
            for sig in item.get("signals") or []
        ],
    }


def _encode_inventory_payload(enriched_results: Sequence[Mapping[str, Any]]) -> str:
    """Encode display-ready inventory rows as base64 gzip JSON for client-side rendering."""
    # Same bytes as json.dumps(records, separators=(",", ":")), but one record
    # at a time so the per-row dicts never pile up for the garbage collector.
    encoder = json.JSONEncoder(separators=(",", ":"))
    raw = (
        "["
        + ",".join(encoder.encode(_inventory_record(item)) for item in enriched_results)
        + "]"
    ).encode("utf-8")
    # Level 2 keeps the 100-site render inside its budget: gzip.compress's
    # default level 9 adds ~0.8 s there for ~25% smaller output.
    compressed = gzip.compress(raw, compresslevel=2, mtime=0)
    return base64.b64encode(compressed).decode("ascii")


def _approval_badge_class(status: str) -> str:
    upper = status.upper()
    if upper in (
        ApprovalStatus.APPROVED.value,
        TicketApprovalStatus.APPROVED.value,
        TicketApprovalStatus.IMPLEMENTED.value,
    ):
        return "badge-active"
    if upper in (
        ApprovalStatus.PENDING.value,
        TicketApprovalStatus.PENDING.value,
        TicketApprovalStatus.SCHEDULED.value,
    ):
        return "badge-unreachable"
    if upper in (
        ApprovalStatus.REJECTED.value,
        TicketApprovalStatus.REJECTED.value,
        TicketApprovalStatus.CANCELLED.value,
    ):
        return "badge-stale"
    return "badge-insufficient"


def _ups_status_badge_class(status: str) -> str:
    upper = status.upper()
    if upper == UpsHealthStatus.HEALTHY.value:
        return "badge-active"
    if upper == UpsHealthStatus.WARNING.value:
        return "badge-unreachable"
    if upper == UpsHealthStatus.CRITICAL.value:
        return "badge-stale"
    return "badge-insufficient"


def _cutover_badge_class(recommendation: str) -> str:
    upper = recommendation.upper()
    if upper == CutoverRecommendation.READY_FOR_CUTOVER.value:
        return "badge-active"
    if upper == CutoverRecommendation.NEEDS_REMEDIATION.value:
        return "badge-unreachable"
    return "badge-stale"


def _coerce_manifest(
    raw_manifest: Optional[RemediationApprovalManifest | Mapping[str, Any]],
) -> Optional[RemediationApprovalManifest]:
    if raw_manifest is None:
        return None
    if isinstance(raw_manifest, RemediationApprovalManifest):
        return raw_manifest
    if isinstance(raw_manifest, Mapping):
        return RemediationApprovalManifest.from_dict(raw_manifest)
    raise ValueError(f"Unsupported approval_manifest type: {type(raw_manifest)!r}")


def _coerce_streaks(
    raw_streaks: Optional[
        Sequence[ItemStreakSummary | Mapping[str, Any]] | HistoryStore
    ],
) -> Optional[list[ItemStreakSummary]]:
    if raw_streaks is None:
        return None
    if isinstance(raw_streaks, HistoryStore):
        return raw_streaks.list_streaks()
    if isinstance(raw_streaks, Sequence):
        return [
            s if isinstance(s, ItemStreakSummary) else ItemStreakSummary.from_dict(s)
            for s in raw_streaks
        ]
    raise ValueError(f"Unsupported streaks type: {type(raw_streaks)!r}")


def _coerce_reconciliation(
    raw_reconciliation: Optional[ReconciliationReport | Mapping[str, Any]],
) -> Optional[ReconciliationReport]:
    if raw_reconciliation is None:
        return None
    if isinstance(raw_reconciliation, ReconciliationReport):
        return raw_reconciliation
    if isinstance(raw_reconciliation, Mapping):
        return ReconciliationReport.from_dict(raw_reconciliation)
    raise ValueError(
        f"Unsupported reconciliation_report type: {type(raw_reconciliation)!r}"
    )


def _coerce_subnet_utilization(
    raw_subnets: Optional[Sequence[SubnetUtilizationSummary | Mapping[str, Any]]],
    sites_by_id: Mapping[str, Site],
    results: Sequence[ValidationResult | Mapping[str, Any]],
) -> list[SubnetUtilizationSummary]:
    if raw_subnets is not None:
        return [
            s
            if isinstance(s, SubnetUtilizationSummary)
            else SubnetUtilizationSummary.from_dict(s)
            for s in raw_subnets
        ]
    if sites_by_id:
        return HistoryStore.compute_subnet_utilization(
            list(sites_by_id.values()), results
        )
    return []


def _coerce_port_reclamation_plan(
    raw_plan: Optional[PortReclamationPlan | Mapping[str, Any]],
) -> Optional[PortReclamationPlan]:
    if raw_plan is None:
        return None
    if isinstance(raw_plan, PortReclamationPlan):
        return raw_plan
    if isinstance(raw_plan, Mapping):
        return PortReclamationPlan.from_dict(raw_plan)
    raise ValueError(
        f"Unsupported port_reclamation_plan type: {type(raw_plan)!r}"
    )


def _coerce_parity_report(
    raw_parity: Optional[
        ParityValidationReport
        | SiteMigrationReadinessScorecard
        | Sequence[SiteMigrationReadinessScorecard | Mapping[str, Any]]
        | Mapping[str, Any]
    ],
) -> Optional[ParityValidationReport]:
    if raw_parity is None:
        return None
    if isinstance(raw_parity, ParityValidationReport):
        return raw_parity
    if isinstance(raw_parity, SiteMigrationReadinessScorecard):
        return ParityValidationReport(
            scorecards=[raw_parity], evaluated_at=raw_parity.evaluated_at
        )
    if isinstance(raw_parity, Mapping):
        if "scorecards" in raw_parity or "sites" in raw_parity:
            return ParityValidationReport.from_dict(raw_parity)
        if "site_id" in raw_parity and (
            "readiness_score" in raw_parity or "recommendation" in raw_parity
        ):
            sc = SiteMigrationReadinessScorecard.from_dict(raw_parity)
            return ParityValidationReport(
                scorecards=[sc], evaluated_at=sc.evaluated_at
            )
    if isinstance(raw_parity, Sequence) and not isinstance(
        raw_parity, (str, bytes)
    ):
        cards = [
            c
            if isinstance(c, SiteMigrationReadinessScorecard)
            else SiteMigrationReadinessScorecard.from_dict(c)
            for c in raw_parity
        ]
        return ParityValidationReport(scorecards=cards)
    raise ValueError(f"Unsupported parity_report type: {type(raw_parity)!r}")


def _coerce_ups_health_report(
    raw_ups: Optional[
        UpsFleetHealthReport
        | UpsHealthRecord
        | Sequence[UpsHealthRecord | Mapping[str, Any]]
        | Mapping[str, Any]
    ],
) -> Optional[UpsFleetHealthReport]:
    if raw_ups is None:
        return None
    if isinstance(raw_ups, UpsFleetHealthReport):
        return raw_ups
    if isinstance(raw_ups, UpsHealthRecord):
        return UpsFleetHealthReport(
            records=[raw_ups], evaluated_at=raw_ups.evaluated_at
        )
    if isinstance(raw_ups, Mapping):
        if "records" in raw_ups:
            return UpsFleetHealthReport.from_dict(raw_ups)
        if "equipment_id" in raw_ups and "status" in raw_ups:
            rec = UpsHealthRecord.from_dict(raw_ups)
            return UpsFleetHealthReport(records=[rec], evaluated_at=rec.evaluated_at)
    if isinstance(raw_ups, Sequence) and not isinstance(raw_ups, (str, bytes)):
        recs = [
            r if isinstance(r, UpsHealthRecord) else UpsHealthRecord.from_dict(r)
            for r in raw_ups
        ]
        return UpsFleetHealthReport(records=recs)
    raise ValueError(f"Unsupported ups_health_report type: {type(raw_ups)!r}")


def _coerce_itsm_tickets(
    raw_tickets: Optional[
        Sequence[ItsmTicketRequest | Mapping[str, Any]]
        | Mapping[str, Any]
        | ItsmTicketRequest
        | InMemoryItsmSink
    ],
) -> list[ItsmTicketRequest]:
    if raw_tickets is None:
        return []
    if isinstance(raw_tickets, InMemoryItsmSink):
        return list(raw_tickets.tickets)
    if isinstance(raw_tickets, ItsmTicketRequest):
        return [raw_tickets]
    if isinstance(raw_tickets, Mapping):
        if "ticket_id" in raw_tickets:
            return [ItsmTicketRequest.from_dict(raw_tickets)]
        if "tickets" in raw_tickets and isinstance(raw_tickets["tickets"], Sequence):
            return [
                t
                if isinstance(t, ItsmTicketRequest)
                else ItsmTicketRequest.from_dict(t)
                for t in raw_tickets["tickets"]
            ]
        return [
            v
            if isinstance(v, ItsmTicketRequest)
            else ItsmTicketRequest.from_dict({**v, "ticket_id": v.get("ticket_id", k)})
            for k, v in raw_tickets.items()
            if isinstance(v, (ItsmTicketRequest, Mapping))
        ]
    if isinstance(raw_tickets, Sequence) and not isinstance(
        raw_tickets, (str, bytes)
    ):
        return [
            t if isinstance(t, ItsmTicketRequest) else ItsmTicketRequest.from_dict(t)
            for t in raw_tickets
        ]
    raise ValueError(f"Unsupported itsm_tickets type: {type(raw_tickets)!r}")
