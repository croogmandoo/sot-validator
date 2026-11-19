"""Reverse discovery and untracked inventory (Shadow IT) reconciler."""

from __future__ import annotations

from sot_validator.reconciliation._engine import InventoryReconciler
from sot_validator.reconciliation._normalizers import (
    _NormalizedArpObservation,
    _NormalizedSnmpObservation,
)
from sot_validator.reconciliation._records import (
    ALL_DISCREPANCY_TYPES,
    DISCREPANCY_CSV_COLUMNS,
    DISCREPANCY_OUI_CSV_COLUMNS,
    ONBOARDING_CSV_COLUMNS,
    VALID_DISCREPANCY_SOURCES,
    DiscrepancyRecord,
    DiscrepancyType,
    _clean_optional_str,
    _extract_detail_kv,
    _hostnames_match,
    _infer_subnet_id,
    _normalize_hostname,
    _resolve_timestamp,
    _short_hostname,
    _slugify_id,
    _sql_literal,
)
from sot_validator.reconciliation._report import ReconciliationReport

__all__ = [
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
