"""Equipment correlation and site enrichment bodies for ProxmoxContainerCollector."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
import re
from typing import Optional

from sot_validator.models import (
    ArpEntry,
    Equipment,
    EquipmentCategory,
    IPAddress,
    Port,
    SignalStatus,
    SignalType,
    Site,
    ValidationSignal,
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
    extract_mac_addresses,
    is_proxmox_mac,
    normalize_ip_address,
    normalize_mac_address,
)
from sot_validator.signals._proxmox_records import (
    ContainerEndpointRecord,
    ProxmoxGuestRecord,
    _names_match,
)
from sot_validator.signals._proxmox_snapshot import ProxmoxClusterSnapshot


def _evaluate_equipment_target(
    collector,
    equipment: Equipment,
    *,
    snapshot: Optional[ProxmoxClusterSnapshot],
    site: Optional[Site],
    ip_addresses: Optional[Sequence[IPAddress]],
    arp_entries: Optional[Sequence[ArpEntry]],
    ports: Optional[Sequence[Port]],
    eval_dt: datetime,
) -> ValidationSignal:
    candidate_ips: list[str] = []
    for raw_ip in equipment.assigned_ips:
        norm_ip = normalize_ip_address(raw_ip)
        if norm_ip and norm_ip not in candidate_ips:
            candidate_ips.append(norm_ip)

    candidate_macs: list[str] = []
    for attr in ("mac_address", "mac_addresses"):
        for m in extract_mac_addresses(getattr(equipment, attr, None)):
            if m not in candidate_macs:
                candidate_macs.append(m)

    all_ips: list[IPAddress] = []
    if ip_addresses:
        all_ips.extend(ip_addresses)
    if site is not None:
        all_ips.extend(site.ip_addresses)

    for ip_rec in all_ips:
        norm_rec_ip = normalize_ip_address(ip_rec.ip)
        if ip_rec.assigned_object_id == equipment.equipment_id or (
            norm_rec_ip and norm_rec_ip in candidate_ips
        ):
            if norm_rec_ip and norm_rec_ip not in candidate_ips:
                candidate_ips.append(norm_rec_ip)
            for raw_m in (
                ip_rec.arp_mac,
                ip_rec.arp_entry.arp_mac if isinstance(ip_rec.arp_entry, ArpEntry) else None,
            ):
                nm = normalize_mac_address(raw_m)
                if nm and nm not in candidate_macs:
                    candidate_macs.append(nm)

    if arp_entries:
        for entry in arp_entries:
            if normalize_ip_address(entry.ip) in candidate_ips:
                nm = normalize_mac_address(entry.arp_mac)
                if nm and nm not in candidate_macs:
                    candidate_macs.append(nm)

    all_ports: list[Port] = []
    if ports:
        all_ports.extend(ports)
    if site is not None:
        for dev in site.devices:
            all_ports.extend(dev.ports)

    conn_refs = {r.strip() for r in equipment.connected_ports if r and r.strip()}
    for port in all_ports:
        if (
            port.connected_device_id == equipment.equipment_id
            or port.port_id in conn_refs
            or port.name in conn_refs
            or f"{port.device_id}:{port.name}" in conn_refs
        ):
            nm = normalize_mac_address(port.connected_mac)
            if nm and nm not in candidate_macs:
                candidate_macs.append(nm)

    # Weak correlation (VMID parsed from name/ID, name or container-ID match) is skipped for
    # Proxmox/Docker host records and for records hosted by a non-Proxmox hypervisor (e.g. vCenter).
    host_refs = _proxmox_host_refs(snapshot) if snapshot is not None else set()
    is_proxmox_host = equipment.category is not EquipmentCategory.VM and _matches_proxmox_host(
        ref_ids=[equipment.equipment_id],
        ref_names=[equipment.name],
        ref_ips=candidate_ips,
        host_refs=host_refs,
    )
    hypervisor_is_proxmox = bool(
        equipment.hypervisor_id
        and _hypervisor_is_proxmox(equipment.hypervisor_id, host_refs=host_refs, site=site)
    )
    foreign_hypervisor = bool(
        snapshot is not None and equipment.hypervisor_id and not hypervisor_is_proxmox
    )
    allow_weak_match = not is_proxmox_host and not foreign_hypervisor

    vmid_hint = _extract_vmid_hint(getattr(equipment, "vmid", None), allow_bare=True)
    if vmid_hint is None and allow_weak_match:
        vmid_hint = _extract_vmid_hint(equipment.equipment_id) or _extract_vmid_hint(equipment.name)
    pve_mac_detected = any(is_proxmox_mac(m) for m in candidate_macs)
    has_vm_hint = bool(
        equipment.category is EquipmentCategory.VM
        or equipment.hypervisor_id
        or vmid_hint is not None
        or pve_mac_detected
    )

    if snapshot is None:
        if has_vm_hint:
            return ValidationSignal(
                signal_type=SignalType.VM_POWER_STATE,
                status=SignalStatus.UNREACHABLE,
                observed_at=eval_dt,
                age_seconds=0.0,
                details=f"Equipment {equipment.name} ({equipment.equipment_id}) is a VM/container candidate, but no Proxmox/container snapshot is available",
                source=collector.source,
                metadata={
                    "equipment_id": equipment.equipment_id,
                    "proxmox_mac_detected": pve_mac_detected,
                },
            )
        return ValidationSignal(
            signal_type=SignalType.VM_POWER_STATE,
            status=SignalStatus.NOT_APPLICABLE,
            observed_at=eval_dt,
            age_seconds=0.0,
            details=f"Equipment {equipment.name} ({equipment.equipment_id}) is not a VM/container and no snapshot is configured",
            source=collector.source,
            metadata={
                "equipment_id": equipment.equipment_id,
                "proxmox_mac_detected": False,
            },
        )

    matched_guests: list[ProxmoxGuestRecord] = []
    matched_containers: list[ContainerEndpointRecord] = []
    correlation_key: Optional[str] = None

    if vmid_hint is not None:
        for g in snapshot.find_guests(vmid=vmid_hint):
            if g not in matched_guests:
                matched_guests.append(g)
                correlation_key = correlation_key or "vmid"

    for mac in candidate_macs:
        for g in snapshot.find_guests(mac=mac):
            if g not in matched_guests:
                matched_guests.append(g)
                correlation_key = correlation_key or "mac"

    for ip_str in candidate_ips:
        for g in snapshot.find_guests(ip=ip_str):
            if g not in matched_guests:
                matched_guests.append(g)
                correlation_key = correlation_key or "ip"
        for c in snapshot.find_containers(ip=ip_str):
            if c not in matched_containers:
                matched_containers.append(c)
                correlation_key = correlation_key or "ip"

    if not matched_guests and not matched_containers and allow_weak_match:
        for g in snapshot.find_guests(name=equipment.name):
            if g not in matched_guests:
                matched_guests.append(g)
                correlation_key = correlation_key or "name"
        for c in snapshot.find_containers(name=equipment.name):
            if c not in matched_containers:
                matched_containers.append(c)
                correlation_key = correlation_key or "name"
        for c in snapshot.find_containers(container_id=equipment.equipment_id):
            if c not in matched_containers:
                matched_containers.append(c)
                correlation_key = correlation_key or "container_id"

    if matched_guests or matched_containers:
        return collector._build_correlated_signal(
            target_label=f"Equipment {equipment.name} ({equipment.equipment_id})",
            matched_guests=matched_guests,
            matched_containers=matched_containers,
            correlation_key=correlation_key or "name",
            pve_mac_detected=pve_mac_detected or any(g.has_proxmox_mac for g in matched_guests),
            eval_dt=eval_dt,
        )

    # A generic VM (e.g. VMware) with no match is out of scope for this collector; only
    # Proxmox-specific evidence lets a reachable snapshot confirm the guest is gone.
    has_proxmox_evidence = bool(
        pve_mac_detected or vmid_hint is not None or hypervisor_is_proxmox
    )

    if has_vm_hint:
        if snapshot.unreachable_hosts or (not snapshot.guests and not snapshot.containers):
            return ValidationSignal(
                signal_type=SignalType.VM_POWER_STATE,
                status=SignalStatus.UNREACHABLE,
                observed_at=eval_dt,
                age_seconds=0.0,
                details=(
                    f"Equipment {equipment.name} ({equipment.equipment_id}) has VM/Proxmox hints, "
                    "but Proxmox/container host is unreachable"
                ),
                source=collector.source,
                metadata={
                    "equipment_id": equipment.equipment_id,
                    "proxmox_mac_detected": pve_mac_detected,
                    "unreachable_hosts": sorted(snapshot.unreachable_hosts),
                },
            )
        if has_proxmox_evidence:
            return ValidationSignal(
                signal_type=SignalType.VM_POWER_STATE,
                status=SignalStatus.INACTIVE,
                observed_at=eval_dt,
                age_seconds=0.0,
                details=(
                    f"Equipment {equipment.name} ({equipment.equipment_id}) has Proxmox hints, "
                    "but no matching guest or container was found in snapshot"
                ),
                source=collector.source,
                metadata={
                    "equipment_id": equipment.equipment_id,
                    "proxmox_mac_detected": pve_mac_detected,
                },
            )

    return ValidationSignal(
        signal_type=SignalType.VM_POWER_STATE,
        status=SignalStatus.NOT_APPLICABLE,
        observed_at=eval_dt,
        age_seconds=0.0,
        details=f"Equipment {equipment.name} ({equipment.equipment_id}) did not match any Proxmox guest or container",
        source=collector.source,
        metadata={
            "equipment_id": equipment.equipment_id,
            "proxmox_mac_detected": pve_mac_detected,
        },
    )


def enrich_site_with_guests(
    collector,
    site: Site,
    *,
    snapshot: Optional[ProxmoxClusterSnapshot] = None,
) -> Site:
    active_snapshot = snapshot if snapshot is not None else collector.snapshot
    cloned_site = Site.from_dict(site.to_dict())
    if active_snapshot is None:
        return cloned_site

    host_ips = _collect_host_ips_in_site(cloned_site, active_snapshot)

    # Map normalized MACs from site.ip_addresses and switch ports to equipment_id
    mac_to_eq_id: dict[str, str] = {}
    mac_to_ip_rec: dict[str, IPAddress] = {}
    for ip_rec in cloned_site.ip_addresses:
        for raw_m in (
            ip_rec.arp_mac,
            ip_rec.arp_entry.arp_mac if isinstance(ip_rec.arp_entry, ArpEntry) else None,
        ):
            nm = normalize_mac_address(raw_m)
            if nm:
                mac_to_ip_rec[nm] = ip_rec
                if ip_rec.assigned_object_id:
                    mac_to_eq_id[nm] = ip_rec.assigned_object_id

    for dev in cloned_site.devices:
        for port in dev.ports:
            nm = normalize_mac_address(port.connected_mac)
            if nm and port.connected_device_id:
                mac_to_eq_id.setdefault(nm, port.connected_device_id)

    # Identify which existing Equipment records represent hypervisor/container hosts themselves
    host_equipment_ids: set[str] = set()
    for eq in cloned_site.equipment:
        eq_ips = {normalize_ip_address(ip) for ip in eq.assigned_ips}
        eq_ips.discard(None)
        if (eq_ips & host_ips) and eq.category is not EquipmentCategory.VM:
            host_equipment_ids.add(eq.equipment_id)
        elif any(_names_match(eq.name, node_name) for node_name in active_snapshot.node_ips):
            host_equipment_ids.add(eq.equipment_id)

    # Equipment matched or created for a Proxmox guest; containers must not merge into these.
    guest_linked_ids: set[str] = set()

    # 1. Enrich or add ProxmoxGuestRecords
    for guest in active_snapshot.guests:
        matched_eq: Optional[Equipment] = None

        # Match by MAC first
        for g_mac in guest.mac_addresses:
            eq_id = mac_to_eq_id.get(g_mac)
            if eq_id and eq_id not in host_equipment_ids:
                matched_eq = next(
                    (e for e in cloned_site.equipment if e.equipment_id == eq_id),
                    None,
                )
                if matched_eq is not None:
                    break

        # IP, VMID and name matches only adopt records that _weak_match_allowed permits; a physical
        # or other-platform record that merely shares an IP or name gets a separate child record.
        guest_host_refs = {
            ref.lower()
            for ref in (
                guest.node,
                guest.host_ip,
                _resolve_parent_hypervisor_id(
                    site=cloned_site, host_ip=guest.host_ip, node_name=guest.node
                ),
            )
            if ref
        }

        # Match by guest IP
        if matched_eq is None and guest.ip_addresses:
            for eq in cloned_site.equipment:
                if eq.equipment_id in host_equipment_ids:
                    continue
                if not _weak_match_allowed(eq, guest_host_refs, vmid=guest.vmid):
                    continue
                eq_ips = {normalize_ip_address(ip) for ip in eq.assigned_ips}
                if any(g_ip in eq_ips for g_ip in guest.ip_addresses):
                    matched_eq = eq
                    break

        # Match by VMID or name
        if matched_eq is None:
            for eq in cloned_site.equipment:
                if eq.equipment_id in host_equipment_ids:
                    continue
                if not _weak_match_allowed(eq, guest_host_refs, vmid=guest.vmid):
                    continue
                if (
                    _extract_vmid_hint(eq.equipment_id) == guest.vmid
                    or _extract_vmid_hint(eq.name) == guest.vmid
                    or _names_match(eq.name, guest.name)
                ):
                    matched_eq = eq
                    break

        parent_id = _resolve_parent_hypervisor_id(
            site=cloned_site,
            host_ip=guest.host_ip or active_snapshot.node_ips.get(guest.node.lower()),
            node_name=guest.node,
            exclude_equipment_id=matched_eq.equipment_id if matched_eq else None,
        )

        if matched_eq is not None:
            guest_linked_ids.add(matched_eq.equipment_id)
            matched_eq.category = EquipmentCategory.VM
            matched_eq.power_state = guest.status
            if parent_id and parent_id != matched_eq.equipment_id:
                matched_eq.hypervisor_id = parent_id
            if matched_eq.name in (matched_eq.equipment_id, *(matched_eq.assigned_ips or [])):
                matched_eq.name = guest.name
            for g_ip in guest.ip_addresses:
                if g_ip != guest.host_ip and g_ip not in matched_eq.assigned_ips:
                    matched_eq.assigned_ips.append(g_ip)
        else:
            new_eq_id = f"{cloned_site.site_id}-pve-{guest.guest_type}-{guest.vmid}"
            existing_ids = {e.equipment_id for e in cloned_site.equipment}
            if new_eq_id in existing_ids:
                new_eq_id = f"{new_eq_id}-{guest.node}"
            guest_ips = [ip for ip in guest.ip_addresses if ip != guest.host_ip]
            new_eq = Equipment(
                equipment_id=new_eq_id,
                site_id=cloned_site.site_id,
                name=guest.name,
                category=EquipmentCategory.VM,
                assigned_ips=guest_ips,
                connected_ports=[],
                hypervisor_id=parent_id,
                power_state=guest.status,
            )
            cloned_site.equipment.append(new_eq)
            guest_linked_ids.add(new_eq_id)
            for g_mac in guest.mac_addresses:
                ip_rec = mac_to_ip_rec.get(g_mac)
                if ip_rec and not ip_rec.assigned_object_id:
                    ip_rec.assigned_object_type = "equipment"
                    ip_rec.assigned_object_id = new_eq_id

    # 2. Enrich or add ContainerEndpointRecords
    for container in active_snapshot.containers:
        matched_eq = None

        # Match by dedicated non-host container IP or name/id
        non_host_c_ips = [
            ip
            for ip in container.ip_addresses
            if ip != container.host_ip and ip not in host_ips
        ]
        # Containers have no VMID, so only records already hosted by this container's host are adopted.
        container_host_refs = {
            ref.lower()
            for ref in (
                container.host_ip,
                _resolve_parent_hypervisor_id(
                    site=cloned_site, host_ip=container.host_ip, node_name=None
                ),
            )
            if ref
        }
        if non_host_c_ips:
            for eq in cloned_site.equipment:
                if eq.equipment_id in host_equipment_ids or eq.equipment_id in guest_linked_ids:
                    continue
                if not _weak_match_allowed(eq, container_host_refs):
                    continue
                eq_ips = {normalize_ip_address(ip) for ip in eq.assigned_ips}
                if any(c_ip in eq_ips for c_ip in non_host_c_ips):
                    matched_eq = eq
                    break

        if matched_eq is None:
            for eq in cloned_site.equipment:
                if eq.equipment_id in host_equipment_ids:
                    continue
                if eq.equipment_id in guest_linked_ids:
                    continue
                if not _weak_match_allowed(eq, container_host_refs):
                    continue
                if (
                    _names_match(eq.name, container.name)
                    or eq.equipment_id.lower() == container.container_id.lower()
                ):
                    matched_eq = eq
                    break

        parent_id = _resolve_parent_hypervisor_id(
            site=cloned_site,
            host_ip=container.host_ip,
            node_name=None,
            exclude_equipment_id=matched_eq.equipment_id if matched_eq else None,
        )

        if matched_eq is not None:
            matched_eq.category = EquipmentCategory.VM
            matched_eq.power_state = container.state
            if parent_id and parent_id != matched_eq.equipment_id:
                matched_eq.hypervisor_id = parent_id
            for c_ip in non_host_c_ips:
                if c_ip not in matched_eq.assigned_ips:
                    matched_eq.assigned_ips.append(c_ip)
        else:
            slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", container.name).strip("-") or container.container_id[:12]
            new_eq_id = f"{cloned_site.site_id}-ct-{slug}"
            existing_ids = {e.equipment_id for e in cloned_site.equipment}
            if new_eq_id in existing_ids:
                new_eq_id = f"{new_eq_id}-{container.container_id[:8]}"
            new_eq = Equipment(
                equipment_id=new_eq_id,
                site_id=cloned_site.site_id,
                name=container.name,
                category=EquipmentCategory.VM,
                assigned_ips=list(non_host_c_ips),
                connected_ports=[],
                hypervisor_id=parent_id,
                power_state=container.state,
            )
            cloned_site.equipment.append(new_eq)

    return cloned_site
