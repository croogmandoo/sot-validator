"""Tests for the hypervisor facade: re-exported names and module size limit."""

from __future__ import annotations

from pathlib import Path

import pytest

import sot_validator.signals as signals
import sot_validator.signals._hypervisor_collector as hypervisor_collector
import sot_validator.signals._hypervisor_common as hypervisor_common
import sot_validator.signals._hypervisor_providers as hypervisor_providers
import sot_validator.signals._hypervisor_records as hypervisor_records
import sot_validator.signals.hypervisor as hypervisor

SIGNALS_DIR = Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "signals"

EXPECTED_ALL = [
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

REEXPORTED_NAMES = [
    ("_UUID_PATTERN", hypervisor_common),
    ("_MOREF_PATTERN", hypervisor_common),
    ("_ALLOWED_READONLY_MODES", hypervisor_common),
    ("_require_non_empty_str", hypervisor_common),
    ("_clean_optional_str", hypervisor_common),
    ("_normalize_mac", hypervisor_common),
    ("_format_mac_canonical", hypervisor_common),
    ("_normalize_ip", hypervisor_common),
    ("_normalize_uuid", hypervisor_common),
    ("_looks_like_uuid", hypervisor_common),
    ("_normalize_instance_key", hypervisor_common),
    ("_short_instance_key", hypervisor_common),
    ("_instances_match", hypervisor_common),
    ("_parse_optional_bool", hypervisor_common),
    ("_split_str_items", hypervisor_common),
    ("VmPowerState", hypervisor_common),
    ("normalize_vm_power_state", hypervisor_common),
    ("GuestToolsStatus", hypervisor_common),
    ("normalize_guest_tools_status", hypervisor_common),
    ("_infer_guest_os_family", hypervisor_common),
    ("VmNicBinding", hypervisor_records),
    ("HypervisorVmRecord", hypervisor_records),
    ("_extract_equipment_vm_hints", hypervisor_records),
    ("HypervisorInventoryProvider", hypervisor_providers),
    ("MultiVCenterInventoryProvider", hypervisor_providers),
    ("VmPowerStateCollector", hypervisor_collector),
]


@pytest.mark.parametrize(
    ("name", "module"), REEXPORTED_NAMES, ids=[name for name, _ in REEXPORTED_NAMES]
)
def test_name_importable_from_hypervisor(name: str, module: object) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.signals.hypervisor import {name}", namespace)
    assert namespace[name] is getattr(module, name)


def test_hypervisor_all_unchanged() -> None:
    assert hypervisor.__all__ == EXPECTED_ALL


@pytest.mark.parametrize("name", EXPECTED_ALL)
def test_signals_package_reexports_same_object(name: str) -> None:
    assert getattr(signals, name) is getattr(hypervisor, name)


def test_hypervisor_modules_under_800_lines() -> None:
    private = sorted(SIGNALS_DIR.glob("_hypervisor_*.py"))
    assert len(private) == 4
    for path in [SIGNALS_DIR / "hypervisor.py", *private]:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
