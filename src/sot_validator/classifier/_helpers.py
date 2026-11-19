"""Module-level classification helpers used by the ClassificationEngine mixins."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Optional

from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    SignalStatus,
    SignalType,
    Site,
    ValidationSignal,
)
from sot_validator.signals._site_index import SiteRecordIndex
from sot_validator.signals.hypervisor import (
    VmPowerState,
    _extract_equipment_vm_hints,
    normalize_vm_power_state,
)


@dataclass(frozen=True)
class _EvaluatedSignalView:
    """Internal normalized view of a ValidationSignal under a ClassificationPolicy."""

    signal: ValidationSignal
    effective_status: SignalStatus
    is_intermediate: bool = False
    is_stale: bool = False
    discounted: bool = False


def _has_healthy_tools_detail(details: Optional[str]) -> bool:
    if not details:
        return False
    lower = details.lower()
    return any(
        token in lower
        for token in (
            "toolsok",
            "toolsold",
            "heartbeat=green",
            "bonus confidence",
            "guest tools heartbeat active",
        )
    )


def _is_windows_context(
    target: Optional[Any], signals: Sequence[_EvaluatedSignalView]
) -> bool:
    for view in signals:
        if view.signal.signal_type is SignalType.AD_COMPUTER_ACCOUNT:
            return True
        details_lower = (view.signal.details or "").lower()
        if "windows" in details_lower or "os=windows" in details_lower:
            return True
        os_meta = str(
            view.signal.metadata.get("operatingSystem")
            or view.signal.metadata.get("operating_system")
            or ""
        ).lower()
        if "windows" in os_meta:
            return True
    if isinstance(target, Equipment):
        if target.category is EquipmentCategory.VM:
            name_lower = target.name.lower()
            if "win" in name_lower:
                return True
    return False


def _sot_power_state_is_active(equipment: Equipment) -> bool:
    if not equipment.power_state or not equipment.power_state.strip():
        return False
    try:
        return normalize_vm_power_state(equipment.power_state) is VmPowerState.POWERED_ON
    except ValueError:
        return False


def _has_actionable_identifiers(
    target: Optional[Any], site: Optional[Site] = None
) -> bool:
    """Return True if the inventory target has at least one actionable identifier."""
    if target is None:
        return True

    if isinstance(target, IPAddress):
        return bool(target.ip and target.ip.strip())

    if isinstance(target, NetworkDevice):
        if target.management_ip and target.management_ip.strip():
            return True
        if target.ports:
            return True
        if target.last_seen is not None:
            return True
        if site is not None:
            for ip_rec in site.ip_addresses:
                if ip_rec.assigned_object_id == target.device_id:
                    return True
            for dev in site.devices:
                for port in dev.ports:
                    if (
                        port.device_id == target.device_id
                        or port.connected_device_id == target.device_id
                    ):
                        return True
        return False

    if isinstance(target, Equipment):
        if any(ip and ip.strip() for ip in target.assigned_ips):
            return True
        if any(p and p.strip() for p in target.connected_ports):
            return True
        if target.last_seen is not None:
            return True
        if target.hypervisor_id and target.hypervisor_id.strip():
            return True
        if target.power_state and target.power_state.strip():
            return True
        uuids, inst_hint, moref_hint, macs, _ = _extract_equipment_vm_hints(target)
        if uuids or inst_hint or moref_hint or macs:
            return True
        if site is not None:
            for ip_rec in site.ip_addresses:
                if ip_rec.assigned_object_id == target.equipment_id:
                    return True
            for dev in site.devices:
                for port in dev.ports:
                    if port.connected_device_id == target.equipment_id:
                        return True
        return False

    return True


def _index_kwargs(
    index: Optional[SiteRecordIndex], collector: Any, builtin: type
) -> dict[str, Any]:
    """Pass classify_site's index only to collectors using the built-in evaluate()."""
    if index is None or getattr(type(collector), "evaluate", None) is not builtin.evaluate:
        return {}
    return {"_site_index": index}

