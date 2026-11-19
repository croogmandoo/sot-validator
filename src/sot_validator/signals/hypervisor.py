"""Multi-vCenter VM power state and Guest Tools correlation collector."""

from __future__ import annotations

from sot_validator.signals._hypervisor_collector import VmPowerStateCollector
from sot_validator.signals._hypervisor_common import (
    _ALLOWED_READONLY_MODES,
    _MOREF_PATTERN,
    _UUID_PATTERN,
    GuestToolsStatus,
    VmPowerState,
    _clean_optional_str,
    _format_mac_canonical,
    _infer_guest_os_family,
    _instances_match,
    _looks_like_uuid,
    _normalize_instance_key,
    _normalize_ip,
    _normalize_mac,
    _normalize_uuid,
    _parse_optional_bool,
    _require_non_empty_str,
    _short_instance_key,
    _split_str_items,
    normalize_guest_tools_status,
    normalize_vm_power_state,
)
from sot_validator.signals._hypervisor_providers import (
    HypervisorInventoryProvider,
    MultiVCenterInventoryProvider,
)
from sot_validator.signals._hypervisor_records import (
    HypervisorVmRecord,
    VmNicBinding,
    _extract_equipment_vm_hints,
)

__all__ = [
    "GuestToolsStatus",
    "HypervisorInventoryProvider",
    "HypervisorVmRecord",
    "MultiVCenterInventoryProvider",
    "VmNicBinding",
    "VmPowerState",
    "VmPowerStateCollector",
    "normalize_guest_tools_status",
    "normalize_vm_power_state",
]
