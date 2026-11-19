"""Tests for the proxmox_containers facade: re-exported names and module size limit."""

from __future__ import annotations

from pathlib import Path

import pytest

import sot_validator.signals as signals
import sot_validator.signals._proxmox_collector as proxmox_collector
import sot_validator.signals._proxmox_hosts as proxmox_hosts
import sot_validator.signals._proxmox_parsing as proxmox_parsing
import sot_validator.signals._proxmox_records as proxmox_records
import sot_validator.signals._proxmox_snapshot as proxmox_snapshot
import sot_validator.signals.proxmox_containers as proxmox_containers

SIGNALS_DIR = Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "signals"

REEXPORTED_NAMES = [
    ("PROXMOX_MAC_OUI", proxmox_parsing),
    ("_MAC_COLON_RE", proxmox_parsing),
    ("_MAC_DOT_RE", proxmox_parsing),
    ("_HWADDR_KV_RE", proxmox_parsing),
    ("_IP_KV_RE", proxmox_parsing),
    ("_NON_IP_PLACEHOLDERS", proxmox_parsing),
    ("_require_non_empty_str", proxmox_parsing),
    ("_clean_optional_str", proxmox_parsing),
    ("_is_ip_literal", proxmox_parsing),
    ("normalize_mac_address", proxmox_parsing),
    ("extract_mac_addresses", proxmox_parsing),
    ("is_proxmox_mac", proxmox_parsing),
    ("normalize_ip_address", proxmox_parsing),
    ("extract_ip_addresses", proxmox_parsing),
    ("normalize_proxmox_guest_type", proxmox_parsing),
    ("normalize_proxmox_guest_status", proxmox_parsing),
    ("normalize_container_state", proxmox_parsing),
    ("_parse_tags", proxmox_parsing),
    ("_coerce_positive_int", proxmox_parsing),
    ("_coerce_optional_non_negative_int", proxmox_parsing),
    ("_parse_interface_payload", proxmox_parsing),
    ("ProxmoxGuestRecord", proxmox_records),
    ("_parse_published_ports", proxmox_records),
    ("ContainerEndpointRecord", proxmox_records),
    ("_names_match", proxmox_records),
    ("ProxmoxClusterSnapshot", proxmox_snapshot),
    ("_extract_vmid_hint", proxmox_hosts),
    ("_proxmox_host_refs", proxmox_hosts),
    ("_matches_proxmox_host", proxmox_hosts),
    ("_hypervisor_is_proxmox", proxmox_hosts),
    ("_resolve_parent_hypervisor_id", proxmox_hosts),
    ("_collect_host_ips_in_site", proxmox_hosts),
    ("_weak_match_allowed", proxmox_hosts),
    ("ProxmoxContainerCollector", proxmox_collector),
    ("ProxmoxContainerCorrelator", proxmox_collector),
]


@pytest.mark.parametrize(
    ("name", "module"), REEXPORTED_NAMES, ids=[name for name, _ in REEXPORTED_NAMES]
)
def test_name_importable_from_proxmox_containers(name: str, module: object) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.signals.proxmox_containers import {name}", namespace)
    assert namespace[name] is getattr(module, name)


def test_proxmox_containers_all_unchanged() -> None:
    assert proxmox_containers.__all__ == [
        "PROXMOX_MAC_OUI",
        "ContainerEndpointRecord",
        "ProxmoxClusterSnapshot",
        "ProxmoxContainerCollector",
        "ProxmoxContainerCorrelator",
        "ProxmoxGuestRecord",
        "extract_ip_addresses",
        "extract_mac_addresses",
        "is_proxmox_mac",
        "normalize_container_state",
        "normalize_ip_address",
        "normalize_mac_address",
        "normalize_proxmox_guest_status",
        "normalize_proxmox_guest_type",
    ]


def test_signals_package_correlator_alias() -> None:
    assert signals.ProxmoxContainerCorrelator is proxmox_collector.ProxmoxContainerCollector


def test_proxmox_containers_modules_under_800_lines() -> None:
    private = sorted(SIGNALS_DIR.glob("_proxmox_*.py"))
    assert len(private) == 6
    for path in [SIGNALS_DIR / "proxmox_containers.py", *private]:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
