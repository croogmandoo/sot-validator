"""VM power state and Guest Tools heartbeat signal collector across multiple vCenter instances."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, Optional

from sot_validator.models import (
    ArpEntry,
    Equipment,
    IPAddress,
    NetworkDevice,
    Port,
    SignalStatus,
    SignalType,
    Site,
    ValidationSignal,
)
from sot_validator.signals._hypervisor_common import VmPowerState, _instances_match
from sot_validator.signals._hypervisor_providers import (
    HypervisorInventoryProvider,
    MultiVCenterInventoryProvider,
)
from sot_validator.signals._hypervisor_records import (
    HypervisorVmRecord,
    _extract_equipment_vm_hints,
)
from sot_validator.signals.base import (
    SECONDS_PER_DAY,
    SignalCollector,
    normalize_utc_datetime,
    resolve_evaluation_time,
)


class VmPowerStateCollector(SignalCollector):
    """Evaluate VM power state and Guest Tools heartbeat across multiple vCenter instances."""

    signal_type = SignalType.VM_POWER_STATE

    def __init__(
        self,
        provider: Optional[HypervisorInventoryProvider] = None,
        *,
        inactive_threshold_days: Optional[float] = None,
        evaluation_time: Optional[datetime | str] = None,
        source: str = "vcenter.vm_power_state",
    ) -> None:
        if inactive_threshold_days is not None:
            if isinstance(inactive_threshold_days, bool) or not isinstance(
                inactive_threshold_days, (int, float)
            ):
                raise ValueError("inactive_threshold_days must be a non-negative number")
            if float(inactive_threshold_days) < 0.0:
                raise ValueError("inactive_threshold_days must be non-negative")
            self.inactive_threshold_days: Optional[float] = float(
                inactive_threshold_days
            )
        else:
            self.inactive_threshold_days = None

        self.provider = provider
        self.evaluation_time: Optional[datetime] = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else None
        )
        self.source = source

    def evaluate(
        self,
        target: Any,
        *,
        provider: Optional[HypervisorInventoryProvider] = None,
        site: Optional[Site] = None,
        ip_addresses: Optional[Sequence[IPAddress]] = None,
        arp_entries: Optional[Sequence[ArpEntry]] = None,
        ports: Optional[Sequence[Port]] = None,
        bios_uuid: Optional[str] = None,
        vcenter_instance: Optional[str] = None,
        vm_moref: Optional[str] = None,
        mac_addresses: Optional[Sequence[str]] = None,
        inactive_threshold_days: Optional[float] = None,
        evaluation_time: Optional[datetime | str] = None,
        **kwargs: Any,
    ) -> ValidationSignal:
        """Evaluate VM power state and Guest Tools correlation for an inventory target."""
        eval_dt = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else (
                self.evaluation_time
                if self.evaluation_time is not None
                else resolve_evaluation_time(None)
            )
        )

        threshold_days = (
            self.inactive_threshold_days
            if inactive_threshold_days is None
            else float(inactive_threshold_days)
        )
        if threshold_days is not None and threshold_days < 0.0:
            raise ValueError("inactive_threshold_days must be non-negative")

        active_provider = provider if provider is not None else self.provider

        # Direct HypervisorVmRecord evaluation support
        if isinstance(target, HypervisorVmRecord):
            return self._build_signal_for_matched_vms(
                matched_vms=[target],
                correlation_key="direct_vm_record",
                eval_dt=eval_dt,
                threshold_days=threshold_days,
            )

        # Non-Equipment physical network entities (NetworkDevice, Port, etc.)
        if isinstance(target, (NetworkDevice, Port)):
            label = (
                f"NetworkDevice {target.hostname} ({target.device_id})"
                if isinstance(target, NetworkDevice)
                else f"Port {target.device_id}:{target.name} ({target.port_id})"
            )
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=None,
                age_seconds=None,
                details=f"{label}: physical network hardware; VM power state is not applicable",
                source=self.source,
            )

        if not isinstance(target, Equipment):
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=None,
                age_seconds=None,
                details=f"Target {type(target).__name__} is not a virtual machine Equipment record",
                source=self.source,
            )

        uuids, inst_hint, moref_hint, _, has_vm_hint = _extract_equipment_vm_hints(
            target,
            bios_uuid=bios_uuid,
            vcenter_instance=vcenter_instance,
            vm_moref=vm_moref,
            mac_addresses=mac_addresses,
        )

        # If provider is missing
        if active_provider is None:
            if has_vm_hint:
                return ValidationSignal(
                    signal_type=self.signal_type,
                    status=SignalStatus.UNREACHABLE,
                    observed_at=None,
                    age_seconds=None,
                    details=(
                        f"Equipment {target.name} ({target.equipment_id}): "
                        "no vCenter inventory provider available to query VM power state"
                    ),
                    source=self.source,
                )
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=None,
                age_seconds=None,
                details=(
                    f"Equipment {target.name} ({target.equipment_id}) "
                    f"[category={target.category.value}]: physical/non-VM equipment"
                ),
                source=self.source,
            )

        matched_vms, correlation_key = active_provider.correlate_vms(
            target,
            site=site,
            ip_addresses=ip_addresses,
            arp_entries=arp_entries,
            ports=ports,
            bios_uuid=bios_uuid,
            vcenter_instance=vcenter_instance,
            vm_moref=vm_moref,
            mac_addresses=mac_addresses,
        )

        # If physical hardware (non-VM category, no VM hints) and not found in vCenter -> NOT_APPLICABLE
        if not matched_vms and not has_vm_hint:
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=None,
                age_seconds=None,
                details=(
                    f"Equipment {target.name} ({target.equipment_id}) "
                    f"[category={target.category.value}]: physical/non-VM equipment "
                    "with no matching vCenter record"
                ),
                source=self.source,
            )

        unreachable_set = active_provider.unreachable_instances()
        configured_set = active_provider.configured_instances()

        # Check if any matched VM is POWERED_ON
        powered_on_vms = [
            vm for vm in matched_vms if vm.power_state is VmPowerState.POWERED_ON
        ]
        if powered_on_vms:
            return self._build_signal_for_matched_vms(
                matched_vms=matched_vms,
                correlation_key=correlation_key or "vcenter",
                eval_dt=eval_dt,
                threshold_days=threshold_days,
            )

        # Check if target's pinned vCenter instance or candidate vCenter instances are unreachable
        target_inst_unreachable = False
        if inst_hint:
            if isinstance(active_provider, MultiVCenterInventoryProvider):
                target_inst_unreachable = active_provider.is_instance_unreachable(
                    inst_hint
                )
            else:
                target_inst_unreachable = any(
                    _instances_match(inst_hint, u) for u in unreachable_set
                )

        if matched_vms:
            # All matched VMs are POWERED_OFF or SUSPENDED.
            # If the target's explicitly associated vCenter is unreachable or another configured
            # vCenter is unreachable (where a migrated active copy could live), check reachability.
            if target_inst_unreachable:
                return ValidationSignal(
                    signal_type=self.signal_type,
                    status=SignalStatus.UNREACHABLE,
                    observed_at=None,
                    age_seconds=None,
                    details=(
                        f"Equipment {target.name} ({target.equipment_id}): "
                        f"target vCenter instance {inst_hint!r} is unreachable "
                        f"(only inactive copy found on reachable vCenter)"
                    ),
                    source=self.source,
                )
            return self._build_signal_for_matched_vms(
                matched_vms=matched_vms,
                correlation_key=correlation_key or "vcenter",
                eval_dt=eval_dt,
                threshold_days=threshold_days,
            )

        # No matched VMs found across reachable vCenter instances
        if target_inst_unreachable:
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.UNREACHABLE,
                observed_at=None,
                age_seconds=None,
                details=(
                    f"Equipment {target.name} ({target.equipment_id}): "
                    f"vCenter instance {inst_hint!r} is unreachable"
                ),
                source=self.source,
            )

        if unreachable_set:
            unreach_list = ", ".join(sorted(unreachable_set))
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.UNREACHABLE,
                observed_at=None,
                age_seconds=None,
                details=(
                    f"Equipment {target.name} ({target.equipment_id}): "
                    f"not found in reachable vCenter instances and vCenter instance(s) "
                    f"[{unreach_list}] are unreachable"
                ),
                source=self.source,
            )

        if not configured_set:
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.UNREACHABLE,
                observed_at=None,
                age_seconds=None,
                details=(
                    f"Equipment {target.name} ({target.equipment_id}): "
                    "no configured vCenter instances available"
                ),
                source=self.source,
            )

        # All configured vCenter instances are reachable and the VM is absent from all of them
        checked_instances = ", ".join(sorted(configured_set))
        hint_parts: list[str] = []
        if uuids:
            hint_parts.append(f"bios_uuid={uuids[0]}")
        if inst_hint:
            hint_parts.append(f"vcenter_instance={inst_hint}")
        if moref_hint:
            hint_parts.append(f"vm_moref={moref_hint}")
        hint_summary = f" ({', '.join(hint_parts)})" if hint_parts else ""

        return ValidationSignal(
            signal_type=self.signal_type,
            status=SignalStatus.INACTIVE,
            observed_at=eval_dt,
            age_seconds=None,
            details=(
                f"Equipment {target.name} ({target.equipment_id}){hint_summary}: "
                f"orphaned/missing VM not found in any reachable vCenter instance [{checked_instances}]"
            ),
            source=self.source,
        )

    def _build_signal_for_matched_vms(
        self,
        *,
        matched_vms: Sequence[HypervisorVmRecord],
        correlation_key: str,
        eval_dt: datetime,
        threshold_days: Optional[float],
    ) -> ValidationSignal:
        powered_on = [
            vm for vm in matched_vms if vm.power_state is VmPowerState.POWERED_ON
        ]

        if powered_on:
            # Prefer a POWERED_ON VM with healthy Guest Tools heartbeat and latest timestamp
            chosen = max(
                powered_on,
                key=lambda vm: (
                    1 if vm.has_healthy_tools_heartbeat else 0,
                    vm.last_updated.timestamp() if vm.last_updated is not None else 0.0,
                ),
            )
            obs_at, age_sec = self._resolve_observation_age(chosen, eval_dt)

            tools_str = (
                chosen.guest_tools_status.value
                if chosen.guest_tools_status is not None
                else "unknown"
            )
            hb_str = chosen.tools_heartbeat or "unknown"
            os_str = chosen.guest_os_family or "unknown"

            extra_notes: list[str] = []
            if chosen.has_healthy_tools_heartbeat:
                extra_notes.append(
                    f"Guest Tools heartbeat active ({tools_str}, heartbeat={hb_str}; bonus confidence)"
                )
            else:
                extra_notes.append(
                    f"Guest Tools status={tools_str}, heartbeat={hb_str}"
                )

            if chosen.is_windows:
                if chosen.icmp_blocked_by_host_firewall:
                    extra_notes.append(
                        "Windows VM with host firewall blocking ICMP (vCenter power state + Guest Tools authoritative)"
                    )
                else:
                    extra_notes.append("Windows VM")
            elif chosen.icmp_blocked_by_host_firewall:
                extra_notes.append("host firewall blocks ICMP")

            if len(matched_vms) > 1:
                all_insts = ", ".join(
                    f"{vm.vcenter_instance}:{vm.vm_moref}({vm.power_state.value})"
                    for vm in matched_vms
                )
                extra_notes.append(f"multi-vCenter matches=[{all_insts}]")

            notes_suffix = f"; {'; '.join(extra_notes)}" if extra_notes else ""
            details = (
                f"VM {chosen.vm_name} ({chosen.vm_moref}) on {chosen.vcenter_instance} "
                f"is {chosen.power_state.value} [matched by {correlation_key}, os={os_str}]"
                f"{notes_suffix}"
            )
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.ACTIVE,
                observed_at=obs_at,
                age_seconds=age_sec,
                details=details,
                source=self.source,
            )

        # Otherwise all matched VMs are POWERED_OFF or SUSPENDED
        chosen = max(
            matched_vms,
            key=lambda vm: (
                1 if vm.power_state is VmPowerState.SUSPENDED else 0,
                vm.last_updated.timestamp() if vm.last_updated is not None else 0.0,
            ),
        )
        obs_at, age_sec = self._resolve_observation_age(chosen, eval_dt)

        tools_str = (
            chosen.guest_tools_status.value
            if chosen.guest_tools_status is not None
            else "unknown"
        )
        hb_str = chosen.tools_heartbeat or "unknown"
        os_str = chosen.guest_os_family or "unknown"

        inactivity_ref_dt = chosen.power_state_changed_at or chosen.last_updated
        threshold_note = ""
        if threshold_days is not None and inactivity_ref_dt is not None:
            inactivity_seconds = max(0.0, (eval_dt - inactivity_ref_dt).total_seconds())
            inactivity_days = inactivity_seconds / SECONDS_PER_DAY
            if inactivity_days > threshold_days:
                threshold_note = (
                    f"; inactive for {inactivity_days:.2f}d (> threshold {threshold_days:g}d)"
                )
            else:
                threshold_note = (
                    f"; inactive for {inactivity_days:.2f}d (<= threshold {threshold_days:g}d)"
                )

        details = (
            f"VM {chosen.vm_name} ({chosen.vm_moref}) on {chosen.vcenter_instance} "
            f"is {chosen.power_state.value} [matched by {correlation_key}, os={os_str}, "
            f"tools={tools_str}, heartbeat={hb_str}]{threshold_note}"
        )
        return ValidationSignal(
            signal_type=self.signal_type,
            status=SignalStatus.INACTIVE,
            observed_at=obs_at,
            age_seconds=age_sec,
            details=details,
            source=self.source,
        )

    @staticmethod
    def _resolve_observation_age(
        vm: HypervisorVmRecord, eval_dt: datetime
    ) -> tuple[Optional[datetime], Optional[float]]:
        ref_dt = vm.last_updated or vm.power_state_changed_at
        if ref_dt is None:
            return None, None
        obs_utc = normalize_utc_datetime(ref_dt, field_name="last_updated")
        age_seconds = max(0.0, (eval_dt - obs_utc).total_seconds())
        return obs_utc, age_seconds
