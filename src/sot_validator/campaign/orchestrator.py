"""Multi-site campaign orchestrator, rolling wave execution, and outage circuit breakers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Optional

from sot_validator.campaign._records import (
    DEFAULT_CRITICAL_CATEGORIES,
    CampaignConfig,
    CampaignRunSummary,
    CircuitBreakerTrippedError,
    SiteWaveResult,
    SiteWaveStatus,
)
from sot_validator.campaign.alerts import (
    AlertEvent,
    AlertSeverity,
    AlertSink,
    AlertType,
)
from sot_validator.classifier.engine import ClassificationEngine
from sot_validator.models import (
    Site,
    ValidationClassification,
    ValidationResult,
    _require_non_empty_str,
)
from sot_validator.signals.base import resolve_evaluation_time


class CampaignOrchestrator:
    """Orchestrates rolling multi-site validation waves with outage circuit breakers and alerting."""

    def __init__(
        self,
        config: Optional[CampaignConfig] = None,
        *,
        engine: Optional[ClassificationEngine] = None,
        alert_sinks: Optional[Sequence[AlertSink]] = None,
        evaluation_time: Optional[datetime | str] = None,
    ) -> None:
        if config is not None and not isinstance(config, CampaignConfig):
            raise ValueError("config must be a CampaignConfig instance")
        self.config: CampaignConfig = config or CampaignConfig()
        self.evaluation_time: Optional[datetime] = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else None
        )
        self.engine: ClassificationEngine = engine or ClassificationEngine(
            evaluation_time=self.evaluation_time
        )
        self.alert_sinks: list[AlertSink] = (
            list(alert_sinks) if alert_sinks is not None else []
        )
        for sink in self.alert_sinks:
            if not isinstance(sink, AlertSink):
                raise ValueError(
                    "All alert_sinks items must be AlertSink instances"
                )

    def iter_cohorts(self, sites: Sequence[Site]) -> list[list[Site]]:
        """Partition a sequence of sites into cohort waves of size config.cohort_size."""
        site_list = list(sites)
        size = self.config.cohort_size
        return [
            site_list[idx : idx + size]
            for idx in range(0, len(site_list), size)
        ]

    def _resolve_eval_time(
        self, evaluation_time: Optional[datetime | str] = None
    ) -> datetime:
        if evaluation_time is not None:
            return resolve_evaluation_time(evaluation_time)
        if self.evaluation_time is not None:
            return self.evaluation_time
        return resolve_evaluation_time(None)

    def _dispatch_alerts(self, events: Sequence[AlertEvent]) -> None:
        if not events:
            return
        for sink in self.alert_sinks:
            sink.emit_many(events)

    @staticmethod
    def _resolve_item_category(
        result: ValidationResult,
        site: Site,
    ) -> Optional[str]:
        item_type_lower = result.item_type.strip().lower()
        if item_type_lower in ("networkdevice", "network_device"):
            return "network_device"
        if item_type_lower == "ipaddress":
            return "ip_address"
        if item_type_lower == "equipment":
            for eq in site.equipment:
                if eq.equipment_id == result.item_id:
                    return eq.category.value.lower()
            name_lower = result.name.lower()
            if "ups" in name_lower or "apc" in name_lower:
                return "ups"
            if "san" in name_lower:
                return "san"
            return "other"
        return item_type_lower

    def _evaluate_critical_infra_alerts(
        self,
        *,
        site: Site,
        wave_index: int,
        results: Sequence[ValidationResult],
        eval_dt: datetime,
    ) -> list[AlertEvent]:
        critical_set = set(self.config.critical_categories)
        alerts: list[AlertEvent] = []

        for res in results:
            if (
                res.classification
                is not ValidationClassification.UNREACHABLE_NEEDS_REVIEW
            ):
                continue
            category = self._resolve_item_category(res, site)
            if category is None or category not in critical_set:
                continue

            msg = (
                f"Critical infrastructure unreachable at site {site.site_id} "
                f"({site.name}): {res.item_type} {res.name} ({res.item_id}) "
                f"[category={category}] classified as {res.classification.value}."
            )
            alerts.append(
                AlertEvent(
                    alert_type=AlertType.CRITICAL_INFRA_UNREACHABLE,
                    severity=AlertSeverity.CRITICAL,
                    message=msg,
                    site_id=site.site_id,
                    wave_index=wave_index,
                    item_type=res.item_type,
                    item_id=res.item_id,
                    item_name=res.name,
                    category=category,
                    created_at=eval_dt,
                    details={
                        "classification": res.classification.value,
                        "confidence": res.confidence,
                        "rationale": res.rationale,
                        "site_name": site.name,
                    },
                )
            )
        return alerts

    def run(
        self,
        sites: Sequence[Site],
        *,
        precomputed_results: Optional[
            Mapping[str, Sequence[ValidationResult]]
        ] = None,
        campaign_id: str = "campaign-run",
        evaluation_time: Optional[datetime | str] = None,
        raise_on_circuit_breaker: Optional[bool] = None,
    ) -> CampaignRunSummary:
        """Execute a rolling multi-site validation campaign across site cohorts."""
        _require_non_empty_str(campaign_id, "campaign_id")
        eval_dt = self._resolve_eval_time(evaluation_time)
        should_raise = (
            self.config.raise_on_circuit_breaker
            if raise_on_circuit_breaker is None
            else bool(raise_on_circuit_breaker)
        )

        site_list = list(sites)
        cohorts = self.iter_cohorts(site_list)

        committed_site_ids: list[str] = []
        quarantined_site_ids: list[str] = []
        skipped_site_ids: list[str] = []
        site_results: list[SiteWaveResult] = []
        committed_validation_results: list[ValidationResult] = []
        all_alerts: list[AlertEvent] = []

        consecutive_aborted_sites = 0
        trailing_aborted_site_ids: list[str] = []
        circuit_breaker_tripped = False
        tripped_wave_index = 0
        waves_executed = 0

        for wave_index, cohort in enumerate(cohorts):
            if circuit_breaker_tripped:
                for skipped_site in cohort:
                    skipped_site_ids.append(skipped_site.site_id)
                continue

            waves_executed += 1
            for site_idx, site in enumerate(cohort):
                if circuit_breaker_tripped:
                    skipped_site_ids.append(site.site_id)
                    continue

                if (
                    precomputed_results is not None
                    and site.site_id in precomputed_results
                ):
                    raw_results = list(precomputed_results[site.site_id])
                else:
                    raw_results = self.engine.classify_site(
                        site,
                        evaluation_time=eval_dt,
                        include_ip_addresses=self.config.include_ip_addresses,
                    )

                total_items = len(raw_results)
                confirmed_active_count = sum(
                    1
                    for r in raw_results
                    if r.classification
                    is ValidationClassification.CONFIRMED_ACTIVE
                )
                stale_count = sum(
                    1
                    for r in raw_results
                    if r.classification
                    is ValidationClassification.STALE_LIKELY_UNUSED
                )
                unreachable_count = sum(
                    1
                    for r in raw_results
                    if r.classification
                    is ValidationClassification.UNREACHABLE_NEEDS_REVIEW
                )
                insufficient_data_count = sum(
                    1
                    for r in raw_results
                    if r.classification
                    is ValidationClassification.INSUFFICIENT_DATA
                )

                unreachable_ratio = (
                    round(unreachable_count / total_items, 4)
                    if total_items > 0
                    else 0.0
                )
                stale_ratio = (
                    round(stale_count / total_items, 4)
                    if total_items > 0
                    else 0.0
                )

                site_alerts: list[AlertEvent] = (
                    self._evaluate_critical_infra_alerts(
                        site=site,
                        wave_index=wave_index,
                        results=raw_results,
                        eval_dt=eval_dt,
                    )
                )

                is_outage_quarantined = (
                    total_items > 0
                    and unreachable_ratio
                    > self.config.max_unreachable_ratio_per_site
                )

                if is_outage_quarantined:
                    status = SiteWaveStatus.QUARANTINED_OUTAGE_SUSPECTED
                    quarantined = True
                    eligible_for_streak = False
                    site_committed_results: list[ValidationResult] = []
                    quarantined_site_ids.append(site.site_id)
                    consecutive_aborted_sites += 1
                    trailing_aborted_site_ids.append(site.site_id)

                    outage_msg = (
                        f"Suspected site or collector outage at site {site.site_id} "
                        f"({site.name}): unreachable ratio {unreachable_ratio:.2%} "
                        f"({unreachable_count}/{total_items}) exceeds threshold "
                        f"{self.config.max_unreachable_ratio_per_site:.2%}. "
                        "Site results quarantined from stale streak tracking."
                    )
                    site_alerts.append(
                        AlertEvent(
                            alert_type=AlertType.SITE_OUTAGE_SUSPECTED,
                            severity=AlertSeverity.CRITICAL,
                            message=outage_msg,
                            site_id=site.site_id,
                            wave_index=wave_index,
                            created_at=eval_dt,
                            details={
                                "site_name": site.name,
                                "unreachable_ratio": unreachable_ratio,
                                "unreachable_count": unreachable_count,
                                "total_items": total_items,
                                "threshold": self.config.max_unreachable_ratio_per_site,
                            },
                        )
                    )
                else:
                    status = SiteWaveStatus.COMMITTED
                    quarantined = False
                    eligible_for_streak = True
                    site_committed_results = list(raw_results)
                    committed_site_ids.append(site.site_id)
                    committed_validation_results.extend(site_committed_results)
                    consecutive_aborted_sites = 0
                    trailing_aborted_site_ids.clear()

                    if (
                        total_items > 0
                        and stale_ratio > self.config.high_stale_ratio_threshold
                    ):
                        stale_msg = (
                            f"High stale ratio detected at site {site.site_id} "
                            f"({site.name}): stale ratio {stale_ratio:.2%} "
                            f"({stale_count}/{total_items}) exceeds threshold "
                            f"{self.config.high_stale_ratio_threshold:.2%}."
                        )
                        site_alerts.append(
                            AlertEvent(
                                alert_type=AlertType.HIGH_STALE_RATIO_DETECTED,
                                severity=AlertSeverity.WARNING,
                                message=stale_msg,
                                site_id=site.site_id,
                                wave_index=wave_index,
                                created_at=eval_dt,
                                details={
                                    "site_name": site.name,
                                    "stale_ratio": stale_ratio,
                                    "stale_count": stale_count,
                                    "total_items": total_items,
                                    "threshold": self.config.high_stale_ratio_threshold,
                                },
                            )
                        )

                wave_result = SiteWaveResult(
                    site_id=site.site_id,
                    site_name=site.name,
                    wave_index=wave_index,
                    status=status,
                    total_items=total_items,
                    confirmed_active_count=confirmed_active_count,
                    stale_count=stale_count,
                    unreachable_count=unreachable_count,
                    insufficient_data_count=insufficient_data_count,
                    unreachable_ratio=unreachable_ratio,
                    stale_ratio=stale_ratio,
                    quarantined=quarantined,
                    eligible_for_streak_tracking=eligible_for_streak,
                    results=raw_results,
                    committed_results=site_committed_results,
                    alerts=list(site_alerts),
                    evaluated_at=eval_dt,
                )
                site_results.append(wave_result)
                all_alerts.extend(site_alerts)
                self._dispatch_alerts(site_alerts)

                if (
                    consecutive_aborted_sites
                    >= self.config.max_consecutive_aborted_sites
                ):
                    circuit_breaker_tripped = True
                    tripped_wave_index = wave_index
                    cb_msg = (
                        f"Campaign circuit breaker tripped at wave {wave_index} "
                        f"after {consecutive_aborted_sites} consecutive quarantined sites "
                        f"({', '.join(trailing_aborted_site_ids)})."
                    )
                    cb_alert = AlertEvent(
                        alert_type=AlertType.CAMPAIGN_CIRCUIT_BREAKER_TRIPPED,
                        severity=AlertSeverity.CRITICAL,
                        message=cb_msg,
                        site_id=site.site_id,
                        wave_index=wave_index,
                        created_at=eval_dt,
                        details={
                            "consecutive_aborted_sites": consecutive_aborted_sites,
                            "max_consecutive_aborted_sites": self.config.max_consecutive_aborted_sites,
                            "aborted_site_ids": list(trailing_aborted_site_ids),
                        },
                    )
                    wave_result.alerts.append(cb_alert)
                    all_alerts.append(cb_alert)
                    self._dispatch_alerts([cb_alert])

                    # Mark remaining sites in current cohort as skipped
                    for remaining_site in cohort[site_idx + 1 :]:
                        skipped_site_ids.append(remaining_site.site_id)
                    break

        summary = CampaignRunSummary(
            campaign_id=campaign_id,
            config=self.config,
            started_at=eval_dt,
            completed_at=eval_dt,
            total_sites_scheduled=len(site_list),
            total_sites_evaluated=len(site_results),
            total_waves_executed=waves_executed,
            committed_site_ids=committed_site_ids,
            quarantined_site_ids=quarantined_site_ids,
            skipped_site_ids=skipped_site_ids,
            circuit_breaker_tripped=circuit_breaker_tripped,
            consecutive_aborted_sites=consecutive_aborted_sites,
            site_results=site_results,
            committed_validation_results=committed_validation_results,
            alerts=all_alerts,
        )

        if circuit_breaker_tripped and should_raise:
            raise CircuitBreakerTrippedError(
                f"Campaign {campaign_id!r} circuit breaker tripped after "
                f"{consecutive_aborted_sites} consecutive quarantined sites: "
                f"{', '.join(trailing_aborted_site_ids)}",
                consecutive_aborted_sites=consecutive_aborted_sites,
                aborted_site_ids=trailing_aborted_site_ids,
                wave_index=tripped_wave_index,
                summary=summary,
            )

        return summary


__all__ = [
    "CampaignConfig",
    "CampaignOrchestrator",
    "CampaignRunSummary",
    "CircuitBreakerTrippedError",
    "DEFAULT_CRITICAL_CATEGORIES",
    "SiteWaveResult",
    "SiteWaveStatus",
]
