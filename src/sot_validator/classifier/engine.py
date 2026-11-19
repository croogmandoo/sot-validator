"""Multi-signal classification engine and calibrated confidence scoring."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from sot_validator.classifier._collect import _CollectMixin
from sot_validator.classifier._helpers import (
    _EvaluatedSignalView,
    _has_actionable_identifiers,
    _has_healthy_tools_detail,
    _index_kwargs,
    _is_windows_context,
    _sot_power_state_is_active,
)
from sot_validator.classifier._policy import (
    _ACTIVE_PROBE_SIGNAL_TYPES,
    _HIGH_CONFIDENCE_ACTIVE_SIGNAL_TYPES,
    _SUBSTANTIVE_STALE_SIGNAL_TYPES,
    DEFAULT_SIGNAL_WEIGHTS,
    ClassificationPolicy,
    _default_signal_weights,
)
from sot_validator.classifier._scoring import _ScoringMixin
from sot_validator.models import (
    ArpEntry,
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    SignalStatus,
    SignalType,
    Site,
    ValidationClassification,
    ValidationResult,
    ValidationSignal,
)
from sot_validator.signals._site_index import SiteRecordIndex
from sot_validator.signals.arp import ArpSignalEvaluator
from sot_validator.signals.base import (
    SECONDS_PER_DAY,
    normalize_utc_datetime,
    resolve_evaluation_time,
    validate_recency_thresholds,
)
from sot_validator.signals.directory_dns import (
    ActiveDirectoryCollector,
    DnsDhcpLeaseCollector,
)
from sot_validator.signals.hypervisor import (
    HypervisorInventoryProvider,
    VmPowerState,
    VmPowerStateCollector,
    _extract_equipment_vm_hints,
    normalize_vm_power_state,
)
from sot_validator.signals.icmp import IcmpProbeCollector
from sot_validator.signals.last_seen import LastSeenSignalEvaluator
from sot_validator.signals.management import ManagementProbeCollector
from sot_validator.signals.port_state import PortStateSignalEvaluator


class ClassificationEngine(_CollectMixin, _ScoringMixin):
    """Rule-based multi-signal classification engine producing ValidationResult records."""

    def __init__(
        self,
        policy: Optional[ClassificationPolicy] = None,
        *,
        arp_evaluator: Optional[ArpSignalEvaluator] = None,
        port_evaluator: Optional[PortStateSignalEvaluator] = None,
        last_seen_evaluator: Optional[LastSeenSignalEvaluator] = None,
        icmp_collector: Optional[IcmpProbeCollector] = None,
        management_collector: Optional[ManagementProbeCollector] = None,
        vm_collector: Optional[VmPowerStateCollector] = None,
        hypervisor_provider: Optional[HypervisorInventoryProvider] = None,
        ad_collector: Optional[ActiveDirectoryCollector] = None,
        dns_dhcp_collector: Optional[DnsDhcpLeaseCollector] = None,
        evaluation_time: Optional[datetime | str] = None,
    ) -> None:
        if policy is not None and not isinstance(policy, ClassificationPolicy):
            raise ValueError("policy must be a ClassificationPolicy instance")
        self.policy: ClassificationPolicy = policy or ClassificationPolicy()
        self.evaluation_time: Optional[datetime] = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else None
        )
        self.arp_evaluator: ArpSignalEvaluator = arp_evaluator or ArpSignalEvaluator(
            active_within_days=self.policy.active_within_days,
            stale_after_days=self.policy.stale_after_days,
            evaluation_time=self.evaluation_time,
        )
        self.port_evaluator: PortStateSignalEvaluator = (
            port_evaluator
            or PortStateSignalEvaluator(evaluation_time=self.evaluation_time)
        )
        self.last_seen_evaluator: LastSeenSignalEvaluator = (
            last_seen_evaluator
            or LastSeenSignalEvaluator(
                active_within_days=self.policy.active_within_days,
                stale_after_days=self.policy.stale_after_days,
                evaluation_time=self.evaluation_time,
            )
        )
        self.icmp_collector: Optional[IcmpProbeCollector] = icmp_collector
        self.management_collector: Optional[ManagementProbeCollector] = (
            management_collector
        )
        self.hypervisor_provider: Optional[HypervisorInventoryProvider] = (
            hypervisor_provider
            if hypervisor_provider is not None
            else (vm_collector.provider if vm_collector is not None else None)
        )
        self.vm_collector: Optional[VmPowerStateCollector] = vm_collector or (
            VmPowerStateCollector(
                provider=self.hypervisor_provider,
                evaluation_time=self.evaluation_time,
            )
            if self.hypervisor_provider is not None
            else None
        )
        self.ad_collector: Optional[ActiveDirectoryCollector] = ad_collector
        self.dns_dhcp_collector: Optional[DnsDhcpLeaseCollector] = dns_dhcp_collector

    def classify_device(
        self,
        device: NetworkDevice,
        signals: Optional[Sequence[ValidationSignal]] = None,
        *,
        site: Optional[Site] = None,
        evaluation_time: Optional[datetime | str] = None,
        **kwargs: Any,
    ) -> ValidationResult:
        """Classify a NetworkDevice (e.g. Extreme Networks switch)."""
        resolved_signals = (
            list(signals)
            if signals is not None
            else self.collect_signals(
                device,
                site=site,
                evaluation_time=evaluation_time,
                **kwargs,
            )
        )
        site_id = device.site_id or (site.site_id if site is not None else "unknown")
        return self.classify_signals(
            resolved_signals,
            item_type="NetworkDevice",
            item_id=device.device_id,
            site_id=site_id,
            name=device.hostname,
            target=device,
            site=site,
            evaluation_time=evaluation_time,
        )

    def classify_ip(
        self,
        ip_address: IPAddress,
        signals: Optional[Sequence[ValidationSignal]] = None,
        *,
        site: Optional[Site] = None,
        site_id: Optional[str] = None,
        evaluation_time: Optional[datetime | str] = None,
        **kwargs: Any,
    ) -> ValidationResult:
        """Classify an IPAddress record."""
        resolved_signals = (
            list(signals)
            if signals is not None
            else self.collect_signals(
                ip_address,
                site=site,
                evaluation_time=evaluation_time,
                **kwargs,
            )
        )
        resolved_site_id = (
            site_id
            or (site.site_id if site is not None else None)
            or ip_address.subnet_id
            or "unknown"
        )
        return self.classify_signals(
            resolved_signals,
            item_type="IPAddress",
            item_id=ip_address.ip,
            site_id=resolved_site_id,
            name=ip_address.ip,
            target=ip_address,
            site=site,
            evaluation_time=evaluation_time,
        )

    def classify_equipment(
        self,
        equipment: Equipment,
        signals: Optional[Sequence[ValidationSignal]] = None,
        *,
        site: Optional[Site] = None,
        evaluation_time: Optional[datetime | str] = None,
        **kwargs: Any,
    ) -> ValidationResult:
        """Classify an Equipment record (Server, SAN, APC UPS, VM, etc.)."""
        resolved_signals = (
            list(signals)
            if signals is not None
            else self.collect_signals(
                equipment,
                site=site,
                evaluation_time=evaluation_time,
                **kwargs,
            )
        )
        site_id = equipment.site_id or (site.site_id if site is not None else "unknown")
        return self.classify_signals(
            resolved_signals,
            item_type="Equipment",
            item_id=equipment.equipment_id,
            site_id=site_id,
            name=equipment.name,
            target=equipment,
            site=site,
            evaluation_time=evaluation_time,
        )

    def classify(
        self,
        target: Any,
        signals: Optional[Sequence[ValidationSignal]] = None,
        *,
        site: Optional[Site] = None,
        evaluation_time: Optional[datetime | str] = None,
        **kwargs: Any,
    ) -> ValidationResult:
        """Classify a domain record (NetworkDevice, IPAddress, Equipment) or signal sequence."""
        if isinstance(target, NetworkDevice):
            return self.classify_device(
                target,
                signals=signals,
                site=site,
                evaluation_time=evaluation_time,
                **kwargs,
            )
        if isinstance(target, IPAddress):
            return self.classify_ip(
                target,
                signals=signals,
                site=site,
                evaluation_time=evaluation_time,
                **kwargs,
            )
        if isinstance(target, Equipment):
            return self.classify_equipment(
                target,
                signals=signals,
                site=site,
                evaluation_time=evaluation_time,
                **kwargs,
            )
        if (
            isinstance(target, Sequence)
            and not isinstance(target, (str, bytes))
            and all(isinstance(s, ValidationSignal) for s in target)
        ):
            return self.classify_signals(
                target,
                site=site,
                evaluation_time=evaluation_time,
                **kwargs,
            )
        if signals is not None:
            item_type = kwargs.pop("item_type", type(target).__name__)
            item_id = kwargs.pop("item_id", str(getattr(target, "id", "unknown")))
            site_id = kwargs.pop(
                "site_id",
                getattr(target, "site_id", site.site_id if site is not None else "unknown"),
            )
            name = kwargs.pop("name", getattr(target, "name", item_id))
            return self.classify_signals(
                signals,
                item_type=item_type,
                item_id=item_id,
                site_id=site_id,
                name=name,
                target=target,
                site=site,
                evaluation_time=evaluation_time,
            )
        raise ValueError(
            f"Unsupported target type for classification: {type(target).__name__}"
        )

    def classify_site(
        self,
        site: Site,
        *,
        evaluation_time: Optional[datetime | str] = None,
        include_ip_addresses: bool = True,
        **kwargs: Any,
    ) -> list[ValidationResult]:
        """Classify all devices, equipment, and (optionally) IP addresses in a Site batch."""
        results: list[ValidationResult] = []
        # One lookup index per call so a site mutated between calls is never served stale
        ip_addresses = kwargs.get("ip_addresses")
        ports = kwargs.get("ports")
        if isinstance(ip_addresses, (list, tuple, type(None))) and isinstance(
            ports, (list, tuple, type(None))
        ):
            kwargs["_site_index"] = SiteRecordIndex(
                site, ip_addresses=ip_addresses, ports=ports
            )
        for device in site.devices:
            results.append(
                self.classify_device(
                    device,
                    site=site,
                    evaluation_time=evaluation_time,
                    **kwargs,
                )
            )
        for equipment in site.equipment:
            results.append(
                self.classify_equipment(
                    equipment,
                    site=site,
                    evaluation_time=evaluation_time,
                    **kwargs,
                )
            )
        if include_ip_addresses:
            for ip_rec in site.ip_addresses:
                results.append(
                    self.classify_ip(
                        ip_rec,
                        site=site,
                        site_id=site.site_id,
                        evaluation_time=evaluation_time,
                        **kwargs,
                    )
                )
        return results

    score = classify


ScoringConfig = ClassificationPolicy
ValidationScorer = ClassificationEngine

__all__ = [
    "ClassificationEngine",
    "ClassificationPolicy",
    "DEFAULT_SIGNAL_WEIGHTS",
    "ScoringConfig",
    "ValidationScorer",
]
