"""Dual-Run Parity Checker and Site Migration Readiness Scorecard for NetBox and Nautobot."""

from __future__ import annotations

from sot_validator.migration._parity_checker import DualRunParityChecker
from sot_validator.migration._parity_evaluate import _ParityEvaluateMixin
from sot_validator.migration._parity_matching import _ParityMatchingMixin
from sot_validator.migration._parity_models import (
    MigrationParityReport,
    ParityDiscrepancy,
    SiteMigrationReadinessScorecard,
)
from sot_validator.migration._parity_records import (
    _STALE_MODERN_STATUSES,
    _UNTRACKED_DISCREPANCY_TYPES,
    ALL_CUTOVER_RECOMMENDATIONS,
    ALL_PARITY_DISCREPANCY_TYPES,
    PARITY_ENTITY_COLLECTIONS,
    CutoverRecommendation,
    ParityDiscrepancyType,
    _clamp_percentage,
    _clean_optional_str,
    _extract_explicit_ip,
    _extract_legacy_id,
    _extract_record_identifier,
    _record_candidate_tokens,
)


ParityValidationReport = MigrationParityReport
ModernSoTParityValidator = DualRunParityChecker

__all__ = [
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
