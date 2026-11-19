"""TopologyGraphBuilder node phases 1-7 over a _GraphBuildContext."""

from __future__ import annotations

from typing import Optional

from sot_validator.topology._graph_context import _GraphBuildContext
from sot_validator.topology._graph_models import (
    _ACTIVE_POE_STATES,
    _ROUTER_DEVICE_ROLES,
    _is_router_hostname,
    _normalize_optional_mac,
)


def _add_site_node(ctx: _GraphBuildContext) -> None:
    # 1. Site node
    site = ctx.site
    ctx.site_node = ctx.register_node(
        site.site_id,
        "site",
        site.name,
        metadata={
            "address": site.address,
            "contact_info": site.contact_info,
            "rooms": list(site.rooms),
        },
    )


def _add_device_nodes(ctx: _GraphBuildContext) -> None:
    # 2. Router and Switch nodes
    site = ctx.site
    register_node = ctx.register_node
    extract_ip_mac = ctx.extract_ip_mac
    site_gateway_ips = ctx.site_gateway_ips
    ip_rec_by_ip = ctx.ip_rec_by_ip
    device_node_id_by_dev_id = ctx.device_node_id_by_dev_id
    router_dev_ids = ctx.router_dev_ids
    switch_dev_ids = ctx.switch_dev_ids

    for dev in site.devices:
        role_lower = (dev.role or "").strip().lower()
        mgmt_ip = dev.management_ip.strip() if dev.management_ip else None
        is_router = (
            role_lower in _ROUTER_DEVICE_ROLES
            or (mgmt_ip is not None and mgmt_ip in site_gateway_ips)
            or (not role_lower and _is_router_hostname(dev.hostname))
        )
        dev_node_type = "router" if is_router else "switch"

        dev_mac: Optional[str] = None
        if mgmt_ip and mgmt_ip in ip_rec_by_ip:
            dev_mac = extract_ip_mac(ip_rec_by_ip[mgmt_ip])
        if dev_mac is None:
            for ip_rec in site.ip_addresses:
                if ip_rec.assigned_object_id == dev.device_id:
                    dev_mac = extract_ip_mac(ip_rec)
                    if dev_mac:
                        break

        _, dev_vlan_id = ctx.infer_subnet_and_vlan_for_ip(mgmt_ip)
        if dev_vlan_id is None:
            for p in dev.ports:
                if p.vlan_id:
                    dev_vlan_id = p.vlan_id
                    break

        dev_node = register_node(
            dev.device_id,
            dev_node_type,
            dev.hostname,
            ip=mgmt_ip,
            mac=dev_mac,
            vlan_id=dev_vlan_id,
            metadata={
                "vendor": dev.vendor,
                "model": dev.model,
                "role": dev.role,
                "port_count": len(dev.ports),
            },
        )
        device_node_id_by_dev_id[dev.device_id] = dev_node.node_id
        if is_router:
            router_dev_ids.append(dev.device_id)
        else:
            switch_dev_ids.append(dev.device_id)


def _add_vlan_nodes(ctx: _GraphBuildContext) -> None:
    # 3. VLAN nodes (from site.vlans + any referenced VLAN IDs in subnets/ports)
    site = ctx.site
    register_node = ctx.register_node
    vlan_node_id_by_vlan_id = ctx.vlan_node_id_by_vlan_id
    for vlan in site.vlans:
        v_node = register_node(
            vlan.vlan_id,
            "vlan",
            vlan.name or f"VLAN {vlan.vlan_id}",
            vlan_id=vlan.vlan_id,
            metadata={
                "subnet_id": vlan.subnet_id,
                "cidr": vlan.cidr,
                "gateway": vlan.gateway,
            },
        )
        vlan_node_id_by_vlan_id[vlan.vlan_id] = v_node.node_id

    referenced_vlan_ids: list[str] = []
    for sub in site.subnets:
        if sub.vlan_id and sub.vlan_id not in vlan_node_id_by_vlan_id:
            if sub.vlan_id not in referenced_vlan_ids:
                referenced_vlan_ids.append(sub.vlan_id)
    for dev in site.devices:
        for port in dev.ports:
            if port.vlan_id and port.vlan_id not in vlan_node_id_by_vlan_id:
                if port.vlan_id not in referenced_vlan_ids:
                    referenced_vlan_ids.append(port.vlan_id)

    for ref_vlan_id in referenced_vlan_ids:
        matching_sub = next(
            (s for s in site.subnets if s.vlan_id == ref_vlan_id), None
        )
        v_node = register_node(
            ref_vlan_id,
            "vlan",
            (
                matching_sub.name
                if matching_sub and matching_sub.name
                else f"VLAN {ref_vlan_id}"
            ),
            vlan_id=ref_vlan_id,
            metadata={
                "subnet_id": matching_sub.subnet_id if matching_sub else None,
                "cidr": matching_sub.cidr if matching_sub else None,
                "gateway": matching_sub.gateway if matching_sub else None,
            },
        )
        vlan_node_id_by_vlan_id[ref_vlan_id] = v_node.node_id


def _add_subnet_nodes(ctx: _GraphBuildContext) -> None:
    # 4. Subnet nodes
    subnet_node_id_by_subnet_id = ctx.subnet_node_id_by_subnet_id
    for sub in ctx.site.subnets:
        resolved_vlan = sub.vlan_id or ctx.infer_vlan_for_subnet_id(sub.subnet_id)
        s_node = ctx.register_node(
            sub.subnet_id,
            "subnet",
            sub.name or sub.cidr,
            ip=sub.gateway,
            vlan_id=resolved_vlan,
            metadata={
                "cidr": sub.cidr,
                "gateway": sub.gateway,
            },
        )
        subnet_node_id_by_subnet_id[sub.subnet_id] = s_node.node_id


def _collect_referenced_port_refs(ctx: _GraphBuildContext) -> None:
    # Collect all port references from Equipment.connected_ports
    referenced_port_refs = ctx.referenced_port_refs
    for eq in ctx.site.equipment:
        for p_ref in eq.connected_ports:
            if p_ref and p_ref.strip():
                referenced_port_refs.add(p_ref.strip())


def _add_port_nodes(ctx: _GraphBuildContext) -> None:
    # 5. Port nodes
    referenced_port_refs = ctx.referenced_port_refs
    val_by_id = ctx.val_by_id
    val_by_name = ctx.val_by_name
    include_all_ports = ctx.include_all_ports
    port_node_id_by_port_id = ctx.port_node_id_by_port_id
    included_ports = ctx.included_ports

    for dev in ctx.site.devices:
        for port in dev.ports:
            oper_lower = (port.oper_status or "").strip().lower()
            poe_lower = (port.poe_status or "").strip().lower()
            is_referenced_by_eq = (
                port.port_id in referenced_port_refs
                or port.name in referenced_port_refs
                or f"{dev.device_id}:{port.name}" in referenced_port_refs
                or f"{dev.hostname}:{port.name}" in referenced_port_refs
            )
            has_validation = (
                port.port_id in val_by_id
                or f"{dev.hostname}:{port.name}" in val_by_name
            )
            is_active_or_connected = (
                bool(port.connected_device_id and port.connected_device_id.strip())
                or bool(port.connected_mac and port.connected_mac.strip())
                or oper_lower == "up"
                or poe_lower in _ACTIVE_POE_STATES
                or is_referenced_by_eq
                or has_validation
            )

            if include_all_ports or is_active_or_connected:
                p_node = ctx.register_node(
                    port.port_id,
                    "port",
                    f"{dev.hostname}:{port.name}",
                    mac=port.connected_mac,
                    vlan_id=port.vlan_id,
                    status=port.oper_status,
                    metadata={
                        "device_id": port.device_id,
                        "name": port.name,
                        "admin_status": port.admin_status,
                        "oper_status": port.oper_status,
                        "poe_status": port.poe_status,
                        "connected_device_id": port.connected_device_id,
                    },
                )
                port_node_id_by_port_id[port.port_id] = p_node.node_id
                included_ports.append((dev, port, p_node.node_id))


def _add_equipment_nodes(ctx: _GraphBuildContext) -> None:
    # 6. Equipment nodes
    site = ctx.site
    extract_ip_mac = ctx.extract_ip_mac
    infer_vlan_for_subnet_id = ctx.infer_vlan_for_subnet_id
    infer_subnet_and_vlan_for_ip = ctx.infer_subnet_and_vlan_for_ip
    eq_node_id_by_eq_id = ctx.eq_node_id_by_eq_id
    ctx.eq_by_id = {eq.equipment_id: eq for eq in site.equipment}
    eq_mac_by_eq_id = ctx.eq_mac_by_eq_id
    eq_vlans_by_eq_id = ctx.eq_vlans_by_eq_id

    for eq in site.equipment:
        primary_ip = eq.assigned_ips[0] if eq.assigned_ips else None
        resolved_mac: Optional[str] = None
        eq_vlans: list[str] = []

        # Check ports connected to this equipment
        for dev in site.devices:
            for port in dev.ports:
                if (
                    port.connected_device_id == eq.equipment_id
                    or port.port_id in eq.connected_ports
                    or port.name in eq.connected_ports
                    or f"{dev.device_id}:{port.name}" in eq.connected_ports
                    or f"{dev.hostname}:{port.name}" in eq.connected_ports
                ):
                    if resolved_mac is None and port.connected_mac:
                        resolved_mac = _normalize_optional_mac(port.connected_mac)
                    if port.vlan_id and port.vlan_id not in eq_vlans:
                        eq_vlans.append(port.vlan_id)

        # Check IPAddress records matching this equipment
        for ip_rec in site.ip_addresses:
            if (
                ip_rec.assigned_object_id == eq.equipment_id
                or ip_rec.ip in eq.assigned_ips
            ):
                if resolved_mac is None:
                    resolved_mac = extract_ip_mac(ip_rec)
                v_id = infer_vlan_for_subnet_id(ip_rec.subnet_id)
                if v_id and v_id not in eq_vlans:
                    eq_vlans.append(v_id)

        # Check assigned IPs against subnets/VLANs
        for ip_str in eq.assigned_ips:
            _, v_id = infer_subnet_and_vlan_for_ip(ip_str)
            if v_id and v_id not in eq_vlans:
                eq_vlans.append(v_id)

        # If resolved_mac matches a switch port with a VLAN, record that VLAN too
        if resolved_mac:
            for dev in site.devices:
                for port in dev.ports:
                    if (
                        _normalize_optional_mac(port.connected_mac) == resolved_mac
                        and port.vlan_id
                        and port.vlan_id not in eq_vlans
                    ):
                        eq_vlans.append(port.vlan_id)

        primary_vlan = eq_vlans[0] if eq_vlans else None
        eq_mac_by_eq_id[eq.equipment_id] = resolved_mac
        eq_vlans_by_eq_id[eq.equipment_id] = eq_vlans

        category_val = (
            eq.category.value
            if hasattr(eq.category, "value")
            else str(eq.category)
        )
        eq_node = ctx.register_node(
            eq.equipment_id,
            "equipment",
            eq.name,
            ip=primary_ip,
            mac=resolved_mac,
            vlan_id=primary_vlan,
            status=eq.power_state,
            metadata={
                "category": category_val,
                "assigned_ips": list(eq.assigned_ips),
                "connected_ports": list(eq.connected_ports),
                "hypervisor_id": eq.hypervisor_id,
                "power_state": eq.power_state,
            },
        )
        eq_node_id_by_eq_id[eq.equipment_id] = eq_node.node_id


def _add_ip_nodes(ctx: _GraphBuildContext) -> None:
    # 7. IP nodes (from site.ip_addresses + any Equipment.assigned_ips not in site.ip_addresses)
    site = ctx.site
    register_node = ctx.register_node
    infer_subnet_and_vlan_for_ip = ctx.infer_subnet_and_vlan_for_ip
    eq_mac_by_eq_id = ctx.eq_mac_by_eq_id
    ip_node_id_by_ip = ctx.ip_node_id_by_ip
    for ip_rec in site.ip_addresses:
        _, v_id = infer_subnet_and_vlan_for_ip(ip_rec.ip)
        ip_mac = ctx.extract_ip_mac(ip_rec)
        ip_node = register_node(
            ip_rec.ip,
            "ip",
            ip_rec.ip,
            ip=ip_rec.ip,
            mac=ip_mac,
            vlan_id=v_id,
            metadata={
                "subnet_id": ip_rec.subnet_id,
                "assigned_object_type": ip_rec.assigned_object_type,
                "assigned_object_id": ip_rec.assigned_object_id,
                "arp_source_device_id": ip_rec.arp_source_device_id,
            },
        )
        ip_node_id_by_ip[ip_rec.ip] = ip_node.node_id

    for eq in site.equipment:
        for ip_str in eq.assigned_ips:
            cleaned_ip = ip_str.strip()
            if not cleaned_ip or cleaned_ip in ip_node_id_by_ip:
                continue
            sub_id, v_id = infer_subnet_and_vlan_for_ip(cleaned_ip)
            ip_node = register_node(
                cleaned_ip,
                "ip",
                cleaned_ip,
                ip=cleaned_ip,
                mac=eq_mac_by_eq_id.get(eq.equipment_id),
                vlan_id=v_id,
                metadata={
                    "subnet_id": sub_id,
                    "assigned_object_type": "equipment",
                    "assigned_object_id": eq.equipment_id,
                    "arp_source_device_id": None,
                },
            )
            ip_node_id_by_ip[cleaned_ip] = ip_node.node_id
