"""DualRunParityChecker: constructor and the evaluate_sites / evaluate / check_parity entry points."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any, Optional

from sot_validator.migration._parity_evaluate import _ParityEvaluateMixin
from sot_validator.migration._parity_matching import _ParityMatchingMixin
from sot_validator.migration._parity_models import MigrationParityReport
from sot_validator.migration._parity_records import (
    _clean_optional_str,
    _extract_legacy_id,
)
from sot_validator.migration.exporter import (
    ModernSoTExporter,
    _normalize_sites_input,
    _resolve_timestamp,
    slugify,
)
from sot_validator.models import Site, ValidationResult
from sot_validator.reconciliation.reconciler import (
    DiscrepancyRecord,
    ReconciliationReport,
)


class DualRunParityChecker(_ParityEvaluateMixin, _ParityMatchingMixin):
    """Compares validated Golden Inventory against target NetBox/Nautobot state and computes readiness scorecards."""

    def __init__(
        self,
        golden_bundle: Optional[Mapping[str, Any] | ModernSoTExporter] = None,
        modern_bundle: Optional[
            Mapping[str, Any]
            | ModernSoTExporter
            | Sequence[Site | Mapping[str, Any]]
            | Site
        ] = None,
        *,
        target_bundle: Optional[
            Mapping[str, Any]
            | ModernSoTExporter
            | Sequence[Site | Mapping[str, Any]]
            | Site
        ] = None,
        sites: Optional[
            Sequence[Site | Mapping[str, Any]] | Mapping[str, Any] | Site
        ] = None,
        validation_results: Optional[
            Sequence[ValidationResult | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        reconciliation_report: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        stale_item_ids: Optional[Iterable[str]] = None,
        approved_discrepancy_ids: Optional[Iterable[str]] = None,
        unresolved_untracked_discrepancies: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        waived_discrepancy_ids: Optional[Iterable[str]] = None,
        waive_all_parity_discrepancies: bool = False,
        merge_untracked: bool = True,
        target_platform: str = "netbox",
        ready_score_threshold: float = 95.0,
        blocked_parity_threshold: float = 50.0,
        blocked_score_threshold: float = 50.0,
        evaluated_at: Optional[datetime | str] = None,
    ) -> None:
        self._golden_bundle = golden_bundle
        self._modern_bundle = (
            modern_bundle if modern_bundle is not None else target_bundle
        )
        self._sites = sites
        self._validation_results = validation_results
        self._reconciliation_report = reconciliation_report
        self._stale_item_ids: set[str] = (
            {str(x).strip() for x in stale_item_ids if str(x).strip()}
            if stale_item_ids is not None
            else set()
        )
        self._approved_discrepancy_ids: Optional[set[str]] = (
            {str(x).strip() for x in approved_discrepancy_ids if str(x).strip()}
            if approved_discrepancy_ids is not None
            else None
        )
        self._unresolved_untracked_discrepancies = unresolved_untracked_discrepancies
        self._waived_discrepancy_ids: set[str] = (
            {str(x).strip() for x in waived_discrepancy_ids if str(x).strip()}
            if waived_discrepancy_ids is not None
            else set()
        )
        self.waive_all_parity_discrepancies = bool(waive_all_parity_discrepancies)
        self.merge_untracked = bool(merge_untracked)
        self.target_platform = target_platform
        self.ready_score_threshold = float(ready_score_threshold)
        self.blocked_parity_threshold = float(blocked_parity_threshold)
        self.blocked_score_threshold = float(blocked_score_threshold)
        self._evaluated_at = evaluated_at

    def evaluate_sites(
        self,
        golden_or_sites: Optional[Any] = None,
        modern_bundle: Optional[Any] = None,
        *,
        golden_bundle: Optional[Mapping[str, Any] | ModernSoTExporter] = None,
        target_bundle: Optional[Any] = None,
        sites: Optional[
            Sequence[Site | Mapping[str, Any]] | Mapping[str, Any] | Site
        ] = None,
        validation_results: Optional[
            Sequence[ValidationResult | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        reconciliation_report: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        stale_item_ids: Optional[Iterable[str]] = None,
        approved_discrepancy_ids: Optional[Iterable[str]] = None,
        unresolved_untracked_discrepancies: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        waived_discrepancy_ids: Optional[Iterable[str]] = None,
        waive_all_parity_discrepancies: Optional[bool] = None,
        merge_untracked: Optional[bool] = None,
        generated_at: Optional[datetime | str] = None,
    ) -> MigrationParityReport:
        """Evaluate dual-run parity across all sites and return a MigrationParityReport."""
        if golden_or_sites is not None:
            if self._is_bundle_mapping(golden_or_sites):
                golden_bundle = (
                    golden_bundle if golden_bundle is not None else golden_or_sites
                )
            else:
                sites = sites if sites is not None else golden_or_sites

        eff_golden = (
            golden_bundle if golden_bundle is not None else self._golden_bundle
        )
        eff_modern = (
            modern_bundle
            if modern_bundle is not None
            else (
                target_bundle
                if target_bundle is not None
                else self._modern_bundle
            )
        )
        eff_sites = sites if sites is not None else self._sites
        if eff_sites is None and isinstance(eff_golden, ModernSoTExporter):
            eff_sites = eff_golden._raw_sites

        norm_sites = _normalize_sites_input(eff_sites)
        site_ids_ordered: list[str] = []
        seen_slugs: set[str] = set()

        for s_obj in sorted(norm_sites, key=lambda s: slugify(s.site_id)):
            s_slug = slugify(s_obj.site_id)
            if s_slug not in seen_slugs:
                seen_slugs.add(s_slug)
                site_ids_ordered.append(s_obj.site_id)

        if not site_ids_ordered and eff_golden is not None:
            coerced_golden = self._coerce_to_bundle(eff_golden)
            for s_rec in coerced_golden.get("sites", ()):
                sid = (
                    _extract_legacy_id(s_rec)
                    or _clean_optional_str(s_rec.get("slug"))
                    or _clean_optional_str(s_rec.get("name"))
                )
                if sid:
                    s_slug = slugify(sid)
                    if s_slug not in seen_slugs:
                        seen_slugs.add(s_slug)
                        site_ids_ordered.append(sid)

        if not site_ids_ordered and eff_modern is not None:
            coerced_modern = self._coerce_to_bundle(eff_modern)
            for s_rec in coerced_modern.get("sites", ()):
                sid = (
                    _extract_legacy_id(s_rec)
                    or _clean_optional_str(s_rec.get("slug"))
                    or _clean_optional_str(s_rec.get("name"))
                )
                if sid:
                    s_slug = slugify(sid)
                    if s_slug not in seen_slugs:
                        seen_slugs.add(s_slug)
                        site_ids_ordered.append(sid)

        resolved_ts = _resolve_timestamp(
            generated_at if generated_at is not None else self._evaluated_at
        )

        scorecards = [
            self.evaluate_site(
                site_id=sid,
                golden_bundle=eff_golden,
                modern_bundle=eff_modern,
                sites=eff_sites,
                validation_results=validation_results,
                reconciliation_report=reconciliation_report,
                stale_item_ids=stale_item_ids,
                approved_discrepancy_ids=approved_discrepancy_ids,
                unresolved_untracked_discrepancies=unresolved_untracked_discrepancies,
                waived_discrepancy_ids=waived_discrepancy_ids,
                waive_all_parity_discrepancies=waive_all_parity_discrepancies,
                merge_untracked=merge_untracked,
                evaluated_at=resolved_ts,
            )
            for sid in site_ids_ordered
        ]

        return MigrationParityReport(
            scorecards=scorecards,
            generated_at=resolved_ts,
        )

    def evaluate(
        self,
        golden_or_sites: Optional[Any] = None,
        modern_bundle: Optional[Any] = None,
        **kwargs: Any,
    ) -> MigrationParityReport:
        """Alias for evaluate_sites returning a MigrationParityReport."""
        return self.evaluate_sites(golden_or_sites, modern_bundle, **kwargs)

    def check_parity(
        self,
        golden_or_sites: Optional[Any] = None,
        modern_bundle: Optional[Any] = None,
        **kwargs: Any,
    ) -> MigrationParityReport:
        """Alias for evaluate_sites returning a MigrationParityReport."""
        return self.evaluate_sites(golden_or_sites, modern_bundle, **kwargs)

