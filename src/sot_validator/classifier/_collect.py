"""Signal collection mixin for ClassificationEngine: evaluation time, port/IP gathering, collect_signals, _normalize_signals."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, Optional

from sot_validator.classifier._helpers import (
    _EvaluatedSignalView,
    _has_actionable_identifiers,
    _index_kwargs,
)
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
    ValidationSignal,
)
from sot_validator.signals._site_index import SiteRecordIndex
from sot_validator.signals.arp import ArpSignalEvaluator
from sot_validator.signals.base import (
    normalize_utc_datetime,
    resolve_evaluation_time,
)
from sot_validator.signals.directory_dns import DnsDhcpLeaseCollector
from sot_validator.signals.hypervisor import (
    HypervisorInventoryProvider,
    VmPowerStateCollector,
    _extract_equipment_vm_hints,
)
from sot_validator.signals.port_state import PortStateSignalEvaluator

class _CollectMixin:
    """Signal collection and normalization methods for ClassificationEngine."""

    def _resolve_eval_time(
        self, evaluation_time: Optional[datetime | str] = None
    ) -> datetime:
        if evaluation_time is not None:
            return resolve_evaluation_time(evaluation_time)
        if self.evaluation_time is not None:
            return self.evaluation_time
        return resolve_evaluation_time(None)

    @staticmethod
    def _gather_ports(
        site: Optional[Site], ports: Optional[Sequence[Port]]
    ) -> list[Port]:
        collected: list[Port] = []
        seen: set[tuple[str, str, str]] = set()

        def _add(port: Port) -> None:
            key = (port.device_id, port.port_id, port.name)
            if key not in seen:
                seen.add(key)
                collected.append(port)

        if ports:
            for p in ports:
                _add(p)
        if site is not None:
            for dev in site.devices:
                for p in dev.ports:
                    _add(p)
        return collected

    @staticmethod
    def _gather_ips(
        site: Optional[Site], ip_addresses: Optional[Sequence[IPAddress]]
    ) -> list[IPAddress]:
        collected: list[IPAddress] = []
        seen: set[int] = set()
        if ip_addresses:
            for ip_rec in ip_addresses:
                if id(ip_rec) not in seen:
                    seen.add(id(ip_rec))
                    collected.append(ip_rec)
        if site is not None:
            for ip_rec in site.ip_addresses:
                if id(ip_rec) not in seen:
                    seen.add(id(ip_rec))
                    collected.append(ip_rec)
        return collected

    def collect_signals(
        self,
        target: Any,
        *,
        site: Optional[Site] = None,
        evaluation_time: Optional[datetime | str] = None,
        **kwargs: Any,
    ) -> list[ValidationSignal]:
        """Collect all applicable passive, hypervisor, and active signals for a target."""
        eval_dt = self._resolve_eval_time(evaluation_time)
        ip_addresses: Optional[Sequence[IPAddress]] = kwargs.get("ip_addresses")
        arp_entries: Optional[Sequence[ArpEntry]] = kwargs.get("arp_entries")
        ports: Optional[Sequence[Port]] = kwargs.get("ports")
        scope_guard = kwargs.get("scope_guard")
        provider: Optional[HypervisorInventoryProvider] = (
            kwargs.get("provider") or self.hypervisor_provider
        )
        index: Optional[SiteRecordIndex] = kwargs.get("_site_index")
        arp_index = _index_kwargs(index, self.arp_evaluator, ArpSignalEvaluator)
        port_index = _index_kwargs(index, self.port_evaluator, PortStateSignalEvaluator)
        dns_index = _index_kwargs(index, self.dns_dhcp_collector, DnsDhcpLeaseCollector)

        if isinstance(target, NetworkDevice):
            signals: list[ValidationSignal] = [
                self.arp_evaluator.evaluate(
                    target,
                    site=site,
                    ip_addresses=ip_addresses,
                    arp_entries=arp_entries,
                    ports=ports,
                    evaluation_time=eval_dt,
                    active_within_days=self.policy.active_within_days,
                    stale_after_days=self.policy.stale_after_days,
                    **arp_index,
                ),
                self.port_evaluator.evaluate(
                    target,
                    site=site,
                    ports=ports,
                    evaluation_time=eval_dt,
                    **port_index,
                ),
                self.last_seen_evaluator.evaluate(
                    target,
                    evaluation_time=eval_dt,
                    active_within_days=self.policy.active_within_days,
                    stale_after_days=self.policy.stale_after_days,
                ),
            ]
            if self.ad_collector is not None:
                signals.append(
                    self.ad_collector.evaluate(
                        target, site=site, evaluation_time=eval_dt
                    )
                )
            if self.dns_dhcp_collector is not None:
                signals.append(
                    self.dns_dhcp_collector.evaluate(
                        target,
                        site=site,
                        ip_addresses=ip_addresses,
                        scope_guard=scope_guard,
                        evaluation_time=eval_dt,
                        **dns_index,
                    )
                )
            if self.icmp_collector is not None:
                signals.append(
                    self.icmp_collector.collect_for_device(
                        target, site=site, scope_guard=scope_guard
                    )
                )
            if self.management_collector is not None:
                signals.append(
                    self.management_collector.collect_for_device(
                        target, site=site, scope_guard=scope_guard
                    )
                )
            return signals

        if isinstance(target, IPAddress):
            signals = [
                self.arp_evaluator.evaluate(
                    target,
                    site=site,
                    ip_addresses=ip_addresses,
                    arp_entries=arp_entries,
                    ports=ports,
                    evaluation_time=eval_dt,
                    active_within_days=self.policy.active_within_days,
                    stale_after_days=self.policy.stale_after_days,
                ),
            ]
            if getattr(target, "last_seen", None) is not None:
                signals.append(
                    self.last_seen_evaluator.evaluate(
                        target,
                        evaluation_time=eval_dt,
                        active_within_days=self.policy.active_within_days,
                        stale_after_days=self.policy.stale_after_days,
                    )
                )
            if self.ad_collector is not None:
                signals.append(
                    self.ad_collector.evaluate(
                        target, site=site, evaluation_time=eval_dt
                    )
                )
            if self.dns_dhcp_collector is not None:
                signals.append(
                    self.dns_dhcp_collector.evaluate(
                        target,
                        site=site,
                        ip_addresses=ip_addresses,
                        scope_guard=scope_guard,
                        evaluation_time=eval_dt,
                        **dns_index,
                    )
                )
            if self.icmp_collector is not None:
                signals.append(
                    self.icmp_collector.collect_for_ip(
                        target, site=site, scope_guard=scope_guard
                    )
                )
            if self.management_collector is not None:
                signals.append(
                    self.management_collector.collect_for_ip(
                        target, site=site, scope_guard=scope_guard
                    )
                )
            return signals

        if isinstance(target, Equipment):
            if (
                not _has_actionable_identifiers(target, site=site)
                and provider is None
                and self.ad_collector is None
                and self.dns_dhcp_collector is None
            ):
                return [
                    self.arp_evaluator.evaluate(
                        target,
                        site=site,
                        ip_addresses=ip_addresses,
                        arp_entries=arp_entries,
                        ports=ports,
                        evaluation_time=eval_dt,
                        active_within_days=self.policy.active_within_days,
                        stale_after_days=self.policy.stale_after_days,
                        **arp_index,
                    ),
                    self.port_evaluator.evaluate(
                        target,
                        site=site,
                        ports=ports,
                        evaluation_time=eval_dt,
                        **port_index,
                    ),
                    self.last_seen_evaluator.evaluate(
                        target,
                        evaluation_time=eval_dt,
                        active_within_days=self.policy.active_within_days,
                        stale_after_days=self.policy.stale_after_days,
                    ),
                ]

            is_vm = target.category is EquipmentCategory.VM
            # The index can only stand in for the VM's dedicated port/IP lists when both evaluators use it
            vm_indexed = (
                is_vm
                and bool(arp_index)
                and bool(port_index)
                and index is not None
                and index.matches(site, ip_addresses, ports)
            )
            if is_vm and not vm_indexed:
                all_ports = self._gather_ports(site, ports)
                dedicated_ports = [
                    p
                    for p in all_ports
                    if not (
                        p.connected_device_id is not None
                        and p.connected_device_id.strip() != ""
                        and p.connected_device_id != target.equipment_id
                    )
                ]
                all_ips = self._gather_ips(site, ip_addresses)
                arp_sig = self.arp_evaluator.evaluate(
                    target,
                    site=None,
                    ip_addresses=all_ips,
                    arp_entries=arp_entries,
                    ports=dedicated_ports,
                    evaluation_time=eval_dt,
                    active_within_days=self.policy.active_within_days,
                    stale_after_days=self.policy.stale_after_days,
                )
                port_sig = self.port_evaluator.evaluate(
                    target,
                    site=None,
                    ports=dedicated_ports,
                    evaluation_time=eval_dt,
                )
            else:
                dedicated: dict[str, Any] = (
                    {"_dedicated_ports": True} if vm_indexed else {}
                )
                arp_sig = self.arp_evaluator.evaluate(
                    target,
                    site=site,
                    ip_addresses=ip_addresses,
                    arp_entries=arp_entries,
                    ports=ports,
                    evaluation_time=eval_dt,
                    active_within_days=self.policy.active_within_days,
                    stale_after_days=self.policy.stale_after_days,
                    **arp_index,
                    **dedicated,
                )
                port_sig = self.port_evaluator.evaluate(
                    target,
                    site=site,
                    ports=ports,
                    evaluation_time=eval_dt,
                    **port_index,
                    **dedicated,
                )

            last_seen_sig = self.last_seen_evaluator.evaluate(
                target,
                evaluation_time=eval_dt,
                active_within_days=self.policy.active_within_days,
                stale_after_days=self.policy.stale_after_days,
            )

            signals = [arp_sig, port_sig, last_seen_sig]

            _, _, _, _, has_vm_hint = _extract_equipment_vm_hints(
                target,
                bios_uuid=kwargs.get("bios_uuid"),
                vcenter_instance=kwargs.get("vcenter_instance"),
                vm_moref=kwargs.get("vm_moref"),
                mac_addresses=kwargs.get("mac_addresses"),
            )
            if (
                self.vm_collector is not None
                or provider is not None
                or has_vm_hint
            ):
                vm_collector = self.vm_collector or VmPowerStateCollector(
                    provider=provider,
                    evaluation_time=eval_dt,
                )
                signals.append(
                    vm_collector.evaluate(
                        target,
                        provider=provider,
                        site=site,
                        ip_addresses=ip_addresses,
                        arp_entries=arp_entries,
                        ports=ports,
                        bios_uuid=kwargs.get("bios_uuid"),
                        vcenter_instance=kwargs.get("vcenter_instance"),
                        vm_moref=kwargs.get("vm_moref"),
                        mac_addresses=kwargs.get("mac_addresses"),
                        inactive_threshold_days=kwargs.get("inactive_threshold_days"),
                        evaluation_time=eval_dt,
                    )
                )

            if self.ad_collector is not None:
                signals.append(
                    self.ad_collector.evaluate(
                        target, site=site, evaluation_time=eval_dt
                    )
                )
            if self.dns_dhcp_collector is not None:
                signals.append(
                    self.dns_dhcp_collector.evaluate(
                        target,
                        site=site,
                        ip_addresses=ip_addresses,
                        scope_guard=scope_guard,
                        evaluation_time=eval_dt,
                        **dns_index,
                    )
                )
            if self.icmp_collector is not None:
                signals.append(
                    self.icmp_collector.collect_for_equipment(
                        target, site=site, scope_guard=scope_guard
                    )
                )
            if self.management_collector is not None:
                signals.append(
                    self.management_collector.collect_for_equipment(
                        target, site=site, scope_guard=scope_guard
                    )
                )
            return signals

        raise ValueError(
            f"Unsupported target type for signal collection: {type(target).__name__}"
        )

    def _normalize_signals(
        self,
        signals: Sequence[ValidationSignal],
        eval_dt: datetime,
    ) -> list[_EvaluatedSignalView]:
        active_sec = self.policy.active_threshold_seconds
        stale_sec = self.policy.stale_threshold_seconds

        preliminary: list[_EvaluatedSignalView] = []
        for raw_sig in signals:
            sig = (
                raw_sig
                if isinstance(raw_sig, ValidationSignal)
                else ValidationSignal.from_dict(raw_sig)
            )
            status = sig.status
            age_sec = sig.age_seconds
            if (
                age_sec is None
                and sig.observed_at is not None
                and status in (SignalStatus.ACTIVE, SignalStatus.INACTIVE)
                and sig.signal_type
                in (SignalType.ARP_RECENCY, SignalType.LAST_SEEN_TIMESTAMP)
            ):
                obs_utc = normalize_utc_datetime(
                    sig.observed_at, field_name="observed_at"
                )
                age_sec = max(0.0, (eval_dt - obs_utc).total_seconds())

            details_lower = (sig.details or "").lower()
            is_intermediate = False
            is_stale = False

            if sig.signal_type in (
                SignalType.ARP_RECENCY,
                SignalType.LAST_SEEN_TIMESTAMP,
            ):
                if status in (SignalStatus.ACTIVE, SignalStatus.INACTIVE):
                    if age_sec is not None:
                        if age_sec <= active_sec:
                            status = SignalStatus.ACTIVE
                        elif age_sec <= stale_sec:
                            status = SignalStatus.INACTIVE
                            is_intermediate = True
                        else:
                            status = SignalStatus.INACTIVE
                            is_stale = True
                    elif status is SignalStatus.INACTIVE:
                        if "intermediate" in details_lower or "<= stale threshold" in details_lower:
                            is_intermediate = True
                        else:
                            is_stale = True
            elif sig.signal_type is SignalType.VM_POWER_STATE:
                if status is SignalStatus.INACTIVE:
                    if "<= threshold" in details_lower or "intermediate" in details_lower:
                        is_intermediate = True
                    else:
                        is_stale = True
            elif sig.signal_type is SignalType.PORT_STATE:
                if status is SignalStatus.INACTIVE:
                    if age_sec is not None:
                        if age_sec <= active_sec:
                            status = SignalStatus.ACTIVE
                        elif age_sec <= stale_sec:
                            is_intermediate = True
                        else:
                            is_stale = True
                    elif "intermediate" in details_lower or "<= threshold" in details_lower:
                        is_intermediate = True
                    else:
                        is_stale = True
            elif sig.signal_type is SignalType.AD_COMPUTER_ACCOUNT:
                if status is SignalStatus.INACTIVE:
                    if (
                        sig.metadata.get("enabled") is False
                        or "disabled" in details_lower
                        or "enabled=false" in details_lower
                        or sig.metadata.get("account_stale") is True
                    ):
                        is_stale = True
                    elif "intermediate" in details_lower or "<= stale threshold" in details_lower:
                        is_intermediate = True
                    else:
                        is_stale = True
            elif sig.signal_type is SignalType.DNS_DHCP_LEASE:
                if status is SignalStatus.INACTIVE:
                    if (
                        sig.metadata.get("dns_mismatch") is True
                        or "dns_mismatch=true" in details_lower
                    ):
                        is_intermediate = True
                    else:
                        is_stale = True

            normalized_sig = (
                sig
                if status is sig.status and age_sec == sig.age_seconds
                else ValidationSignal(
                    signal_type=sig.signal_type,
                    status=status,
                    observed_at=sig.observed_at,
                    age_seconds=age_sec,
                    details=sig.details,
                    source=sig.source,
                    metadata=sig.metadata,
                )
            )
            preliminary.append(
                _EvaluatedSignalView(
                    signal=normalized_sig,
                    effective_status=status,
                    is_intermediate=is_intermediate,
                    is_stale=is_stale,
                    discounted=False,
                )
            )

        # Discount shared physical host trunk PORT_STATE == ACTIVE when VM_POWER_STATE == INACTIVE
        has_vm_inactive = any(
            v.signal.signal_type is SignalType.VM_POWER_STATE
            and v.effective_status is SignalStatus.INACTIVE
            for v in preliminary
        )
        if not has_vm_inactive:
            return preliminary

        final_views: list[_EvaluatedSignalView] = []
        for view in preliminary:
            if (
                view.signal.signal_type is SignalType.PORT_STATE
                and view.effective_status is SignalStatus.ACTIVE
            ):
                final_views.append(
                    _EvaluatedSignalView(
                        signal=view.signal,
                        effective_status=view.effective_status,
                        is_intermediate=view.is_intermediate,
                        is_stale=view.is_stale,
                        discounted=True,
                    )
                )
            else:
                final_views.append(view)
        return final_views

