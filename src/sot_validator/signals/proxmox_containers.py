"""Proxmox VE (:8006) & Docker/Portainer (:9000) hypervisor and container correlator."""

from __future__ import annotations

from sot_validator.signals._proxmox_collector import (
    ProxmoxContainerCollector,
    ProxmoxContainerCorrelator,
)
from sot_validator.signals._proxmox_hosts import (
    _collect_host_ips_in_site,
    _extract_vmid_hint,
    _hypervisor_is_proxmox,
    _matches_proxmox_host,
    _proxmox_host_refs,
    _resolve_parent_hypervisor_id,
    _weak_match_allowed,
)
from sot_validator.signals._proxmox_parsing import (
    PROXMOX_MAC_OUI,
    _HWADDR_KV_RE,
    _IP_KV_RE,
    _MAC_COLON_RE,
    _MAC_DOT_RE,
    _NON_IP_PLACEHOLDERS,
    _clean_optional_str,
    _coerce_optional_non_negative_int,
    _coerce_positive_int,
    _is_ip_literal,
    _parse_interface_payload,
    _parse_tags,
    _require_non_empty_str,
    extract_ip_addresses,
    extract_mac_addresses,
    is_proxmox_mac,
    normalize_container_state,
    normalize_ip_address,
    normalize_mac_address,
    normalize_proxmox_guest_status,
    normalize_proxmox_guest_type,
)
from sot_validator.signals._proxmox_records import (
    ContainerEndpointRecord,
    ProxmoxGuestRecord,
    _names_match,
    _parse_published_ports,
)
from sot_validator.signals._proxmox_snapshot import ProxmoxClusterSnapshot

__all__ = [
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
