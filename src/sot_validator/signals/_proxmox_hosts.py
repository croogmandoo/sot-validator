"""Proxmox VE / Docker host-resolution and weak-match helpers."""

from __future__ import annotations

from collections.abc import Iterable
import re
from typing import Any, Optional

from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    Site,
)
from sot_validator.signals._proxmox_parsing import (
    _clean_optional_str,
    _is_ip_literal,
    normalize_ip_address,
)
from sot_validator.signals._proxmox_records import _names_match
from sot_validator.signals._proxmox_snapshot import ProxmoxClusterSnapshot


def _extract_vmid_hint(text: Any, *, allow_bare: bool = False) -> Optional[int]:
    cleaned = _clean_optional_str(text)
    if not cleaned:
        return None
    # Bare digits only count from an explicit vmid field; numeric SoT/VMware IDs are not Proxmox evidence.
    # Generic "vm-<n>" names are VMware-style too, so only explicit Proxmox prefixes count.
    # Proxmox VMIDs start at 100, which keeps node names such as "pve-01" from reading as VMIDs.
    if cleaned.isdigit():
        val = int(cleaned)
        return val if allow_bare and val >= 100 else None
    m = re.search(r"(?:^|[-_:/])(?:qemu|lxc|ct|pve)[-_:/]?(\d{3,9})$", cleaned, re.IGNORECASE)
    if m:
        return int(m.group(1))
    return None


def _proxmox_host_refs(snapshot: ProxmoxClusterSnapshot) -> set[str]:
    """Lowercase node names and host IPs of every Proxmox node and Docker/Portainer host in the snapshot."""
    refs: set[str] = set()
    for node_name, node_ip in snapshot.node_ips.items():
        refs.add(node_name.lower())
        refs.add(node_ip)
    for g in snapshot.guests:
        refs.add(g.node.lower())
        if g.host_ip:
            refs.add(g.host_ip)
    for c in snapshot.containers:
        if c.host_ip:
            refs.add(c.host_ip)
    return refs


def _matches_proxmox_host(
    *,
    ref_ids: Iterable[Optional[str]],
    ref_names: Iterable[Optional[str]],
    ref_ips: Iterable[Optional[str]],
    host_refs: set[str],
) -> bool:
    for ref in ref_ids:
        if ref and ref.lower() in host_refs:
            return True
    for ip in ref_ips:
        norm = normalize_ip_address(ip)
        if norm and norm in host_refs:
            return True
    node_names = [r for r in host_refs if not _is_ip_literal(r)]
    for name in ref_names:
        if name and not _is_ip_literal(name) and any(_names_match(name, n) for n in node_names):
            return True
    return False


def _hypervisor_is_proxmox(
    hypervisor_id: str, *, host_refs: set[str], site: Optional[Site]
) -> bool:
    """Return True when hypervisor_id names a snapshot Proxmox/Docker host, directly or via a site record."""
    if _matches_proxmox_host(
        ref_ids=[hypervisor_id], ref_names=[hypervisor_id], ref_ips=[hypervisor_id], host_refs=host_refs
    ):
        return True
    if site is None:
        return False
    ref = hypervisor_id.lower()
    for eq in site.equipment:
        if eq.equipment_id.lower() == ref and _matches_proxmox_host(
            ref_ids=[], ref_names=[eq.name], ref_ips=eq.assigned_ips, host_refs=host_refs
        ):
            return True
    for dev in site.devices:
        if dev.device_id.lower() == ref and _matches_proxmox_host(
            ref_ids=[], ref_names=[dev.hostname], ref_ips=[dev.management_ip], host_refs=host_refs
        ):
            return True
    return False


def _resolve_parent_hypervisor_id(
    *,
    site: Site,
    host_ip: Optional[str],
    node_name: Optional[str],
    exclude_equipment_id: Optional[str] = None,
) -> Optional[str]:
    norm_hip = normalize_ip_address(host_ip) if host_ip else None
    clean_node = _clean_optional_str(node_name)

    if norm_hip:
        for eq in site.equipment:
            if eq.equipment_id == exclude_equipment_id:
                continue
            if eq.category is EquipmentCategory.VM and eq.hypervisor_id:
                continue
            if norm_hip in [normalize_ip_address(ip) for ip in eq.assigned_ips]:
                return eq.equipment_id
        for dev in site.devices:
            if normalize_ip_address(dev.management_ip) == norm_hip:
                return dev.device_id

    if clean_node:
        for eq in site.equipment:
            if eq.equipment_id == exclude_equipment_id:
                continue
            if eq.equipment_id.lower() == clean_node.lower() or _names_match(eq.name, clean_node):
                return eq.equipment_id
        for dev in site.devices:
            if dev.device_id.lower() == clean_node.lower() or _names_match(dev.hostname, clean_node):
                return dev.device_id

    return clean_node or norm_hip


def _collect_host_ips_in_site(site: Site, snapshot: ProxmoxClusterSnapshot) -> set[str]:
    host_ips: set[str] = set()
    for ip in snapshot.node_ips.values():
        norm = normalize_ip_address(ip)
        if norm:
            host_ips.add(norm)
    for g in snapshot.guests:
        if g.host_ip:
            host_ips.add(g.host_ip)
    for c in snapshot.containers:
        if c.host_ip:
            host_ips.add(c.host_ip)
    return host_ips


def _weak_match_allowed(
    eq: Equipment, parent_refs: set[str], *, vmid: Optional[int] = None
) -> bool:
    """Return True when an IP, VMID or name match may adopt eq during enrichment.

    Records already hosted by this parent may be adopted. An unhosted record is only adopted when it
    is a VM whose ID or name carries this guest's Proxmox-format VMID; unhosted VMs are mostly vCenter
    VMs without a SoT hypervisor_id, and physical records must never be rewritten.
    """
    if eq.hypervisor_id:
        return eq.hypervisor_id.lower() in parent_refs
    if eq.category is not EquipmentCategory.VM or vmid is None:
        return False
    return vmid in (_extract_vmid_hint(eq.equipment_id), _extract_vmid_hint(eq.name))
