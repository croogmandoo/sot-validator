"""TopologyGraphBuilder edge groups A-F over a _GraphBuildContext."""

from __future__ import annotations

from typing import Optional

from sot_validator.topology._graph_context import _GraphBuildContext
from sot_validator.topology._graph_models import _normalize_optional_mac


def _add_uplink_edges(ctx: _GraphBuildContext) -> None:
    # Edge group A: uplink_to (Site -> Routers, Switch -> Router/Switch)
    site = ctx.site
    add_edge = ctx.add_edge
    site_node = ctx.site_node
    router_dev_ids = ctx.router_dev_ids
    switch_dev_ids = ctx.switch_dev_ids
    device_node_id_by_dev_id = ctx.device_node_id_by_dev_id
    if router_dev_ids:
        for r_dev_id in router_dev_ids:
            add_edge(
                site_node.node_id,
                device_node_id_by_dev_id[r_dev_id],
                "uplink_to",
            )
    else:
        for sw_dev_id in switch_dev_ids:
            add_edge(
                site_node.node_id,
                device_node_id_by_dev_id[sw_dev_id],
                "uplink_to",
            )

    # Track which switches have an explicit device-to-device uplink
    switches_with_uplink: set[str] = set()
    router_id_set = set(router_dev_ids)
    switch_id_set = set(switch_dev_ids)

    for dev in site.devices:
        for port in dev.ports:
            conn_id = (
                port.connected_device_id.strip()
                if port.connected_device_id
                else None
            )
            if not conn_id or conn_id not in device_node_id_by_dev_id:
                continue

            if dev.device_id in switch_id_set and conn_id in router_id_set:
                add_edge(
                    device_node_id_by_dev_id[dev.device_id],
                    device_node_id_by_dev_id[conn_id],
                    "uplink_to",
                    port_name=port.name,
                    vlan_id=port.vlan_id,
                    poe_status=port.poe_status,
                )
                switches_with_uplink.add(dev.device_id)
            elif dev.device_id in router_id_set and conn_id in switch_id_set:
                add_edge(
                    device_node_id_by_dev_id[conn_id],
                    device_node_id_by_dev_id[dev.device_id],
                    "uplink_to",
                    port_name=port.name,
                    vlan_id=port.vlan_id,
                    poe_status=port.poe_status,
                )
                switches_with_uplink.add(conn_id)
            elif (
                dev.device_id in switch_id_set
                and conn_id in switch_id_set
                and dev.device_id != conn_id
            ):
                add_edge(
                    device_node_id_by_dev_id[dev.device_id],
                    device_node_id_by_dev_id[conn_id],
                    "uplink_to",
                    port_name=port.name,
                    vlan_id=port.vlan_id,
                    poe_status=port.poe_status,
                )
                switches_with_uplink.add(dev.device_id)

    # Fallback uplink: if a switch has no explicit device-to-device uplink, connect to site router
    if router_dev_ids:
        primary_router_node_id = device_node_id_by_dev_id[router_dev_ids[0]]
        for sw_dev_id in switch_dev_ids:
            if sw_dev_id not in switches_with_uplink:
                add_edge(
                    device_node_id_by_dev_id[sw_dev_id],
                    primary_router_node_id,
                    "uplink_to",
                )


def _add_routes_vlan_edges(ctx: _GraphBuildContext) -> None:
    # Edge group B: routes_vlan (Router -> VLAN, VLAN -> Subnet)
    site = ctx.site
    add_edge = ctx.add_edge
    router_dev_ids = ctx.router_dev_ids
    device_node_id_by_dev_id = ctx.device_node_id_by_dev_id
    vlan_node_id_by_vlan_id = ctx.vlan_node_id_by_vlan_id
    vlan_by_id = ctx.vlan_by_id
    subnet_node_id_by_subnet_id = ctx.subnet_node_id_by_subnet_id
    router_served_vlans: dict[str, set[str]] = {
        r_id: set() for r_id in router_dev_ids
    }
    ctx.dev_by_id = {d.device_id: d for d in site.devices}
    dev_by_id = ctx.dev_by_id

    for r_id in router_dev_ids:
        r_dev = dev_by_id[r_id]
        r_ips: set[str] = set()
        if r_dev.management_ip:
            r_ips.add(r_dev.management_ip.strip())
        for ip_rec in site.ip_addresses:
            if ip_rec.assigned_object_id == r_id:
                r_ips.add(ip_rec.ip)

        for port in r_dev.ports:
            if port.vlan_id and port.vlan_id in vlan_node_id_by_vlan_id:
                router_served_vlans[r_id].add(port.vlan_id)

        for v_id in vlan_node_id_by_vlan_id:
            v_obj = vlan_by_id.get(v_id)
            if v_obj and v_obj.gateway and v_obj.gateway.strip() in r_ips:
                router_served_vlans[r_id].add(v_id)
            for sub in site.subnets:
                if (
                    sub.vlan_id == v_id
                    and sub.gateway
                    and sub.gateway.strip() in r_ips
                ):
                    router_served_vlans[r_id].add(v_id)

        for r_ip in r_ips:
            _, v_id = ctx.infer_subnet_and_vlan_for_ip(r_ip)
            if v_id and v_id in vlan_node_id_by_vlan_id:
                router_served_vlans[r_id].add(v_id)

    # Any VLAN not explicitly matched to a specific router is routed by the site's router(s)
    if router_dev_ids:
        explicitly_routed_vlans: set[str] = set()
        for v_set in router_served_vlans.values():
            explicitly_routed_vlans.update(v_set)
        for v_id in vlan_node_id_by_vlan_id:
            if v_id not in explicitly_routed_vlans:
                for r_id in router_dev_ids:
                    router_served_vlans[r_id].add(v_id)

        for r_id, v_ids in router_served_vlans.items():
            r_node_id = device_node_id_by_dev_id[r_id]
            for v_id in v_ids:
                if v_id in vlan_node_id_by_vlan_id:
                    add_edge(
                        r_node_id,
                        vlan_node_id_by_vlan_id[v_id],
                        "routes_vlan",
                        vlan_id=v_id,
                    )

    # VLAN -> Subnet edges (or Router -> Subnet if subnet has no VLAN)
    for sub in site.subnets:
        sub_node_id = subnet_node_id_by_subnet_id[sub.subnet_id]
        matched_vlan_ids: list[str] = []
        if sub.vlan_id and sub.vlan_id in vlan_node_id_by_vlan_id:
            matched_vlan_ids.append(sub.vlan_id)
        for v in site.vlans:
            if (
                v.subnet_id == sub.subnet_id
                or (v.cidr and v.cidr == sub.cidr)
            ) and v.vlan_id not in matched_vlan_ids:
                matched_vlan_ids.append(v.vlan_id)

        if matched_vlan_ids:
            for v_id in matched_vlan_ids:
                add_edge(
                    vlan_node_id_by_vlan_id[v_id],
                    sub_node_id,
                    "routes_vlan",
                    vlan_id=v_id,
                )
        elif router_dev_ids:
            add_edge(
                device_node_id_by_dev_id[router_dev_ids[0]],
                sub_node_id,
                "routes_vlan",
            )


def _add_connected_port_edges(ctx: _GraphBuildContext) -> None:
    # Edge group C: connected_port (Device -> Port, Port -> Equipment / Device / IP)
    site = ctx.site
    add_edge = ctx.add_edge
    extract_ip_mac = ctx.extract_ip_mac
    device_node_id_by_dev_id = ctx.device_node_id_by_dev_id
    eq_node_id_by_eq_id = ctx.eq_node_id_by_eq_id
    eq_mac_by_eq_id = ctx.eq_mac_by_eq_id
    ip_node_id_by_ip = ctx.ip_node_id_by_ip
    for dev, port, p_node_id in ctx.included_ports:
        dev_node_id = device_node_id_by_dev_id[dev.device_id]
        add_edge(
            dev_node_id,
            p_node_id,
            "connected_port",
            port_name=port.name,
            vlan_id=port.vlan_id,
            poe_status=port.poe_status,
        )

        downstream_targets: list[str] = []

        # 1. port.connected_device_id
        if port.connected_device_id:
            conn_id = port.connected_device_id.strip()
            if conn_id in eq_node_id_by_eq_id:
                downstream_targets.append(eq_node_id_by_eq_id[conn_id])
            elif conn_id in device_node_id_by_dev_id:
                downstream_targets.append(device_node_id_by_dev_id[conn_id])

        # 2. Equipment.connected_ports referencing this port
        for eq in site.equipment:
            if (
                port.port_id in eq.connected_ports
                or port.name in eq.connected_ports
                or f"{dev.device_id}:{port.name}" in eq.connected_ports
                or f"{dev.hostname}:{port.name}" in eq.connected_ports
            ):
                eq_target = eq_node_id_by_eq_id[eq.equipment_id]
                if eq_target not in downstream_targets:
                    downstream_targets.append(eq_target)

        # 3. port.connected_mac correlation against equipment and IP ARP entries
        norm_port_mac = _normalize_optional_mac(port.connected_mac)
        if norm_port_mac:
            for eq_id, eq_mac in eq_mac_by_eq_id.items():
                if eq_mac == norm_port_mac:
                    eq_target = eq_node_id_by_eq_id[eq_id]
                    if eq_target not in downstream_targets:
                        downstream_targets.append(eq_target)

            for ip_rec in site.ip_addresses:
                if extract_ip_mac(ip_rec) == norm_port_mac:
                    obj_id = ip_rec.assigned_object_id
                    if obj_id and obj_id in eq_node_id_by_eq_id:
                        eq_target = eq_node_id_by_eq_id[obj_id]
                        if eq_target not in downstream_targets:
                            downstream_targets.append(eq_target)
                    elif obj_id and obj_id in device_node_id_by_dev_id:
                        dev_target = device_node_id_by_dev_id[obj_id]
                        if dev_target not in downstream_targets:
                            downstream_targets.append(dev_target)
                    elif ip_rec.ip in ip_node_id_by_ip:
                        ip_target = ip_node_id_by_ip[ip_rec.ip]
                        if ip_target not in downstream_targets:
                            downstream_targets.append(ip_target)

        for target_node_id in downstream_targets:
            add_edge(
                p_node_id,
                target_node_id,
                "connected_port",
                port_name=port.name,
                vlan_id=port.vlan_id,
                poe_status=port.poe_status,
            )


def _add_member_of_vlan_edges(ctx: _GraphBuildContext) -> None:
    # Edge group D: member_of_vlan (VLAN -> Equipment, Switch, unassigned IP)
    site = ctx.site
    add_edge = ctx.add_edge
    infer_subnet_and_vlan_for_ip = ctx.infer_subnet_and_vlan_for_ip
    dev_by_id = ctx.dev_by_id
    device_node_id_by_dev_id = ctx.device_node_id_by_dev_id
    vlan_node_id_by_vlan_id = ctx.vlan_node_id_by_vlan_id
    eq_node_id_by_eq_id = ctx.eq_node_id_by_eq_id
    eq_vlans_by_eq_id = ctx.eq_vlans_by_eq_id
    ip_node_id_by_ip = ctx.ip_node_id_by_ip
    for eq in site.equipment:
        eq_node_id = eq_node_id_by_eq_id[eq.equipment_id]
        for v_id in eq_vlans_by_eq_id.get(eq.equipment_id, []):
            if v_id in vlan_node_id_by_vlan_id:
                add_edge(
                    vlan_node_id_by_vlan_id[v_id],
                    eq_node_id,
                    "member_of_vlan",
                    vlan_id=v_id,
                )

    for sw_id in ctx.switch_dev_ids:
        sw_dev = dev_by_id[sw_id]
        sw_node_id = device_node_id_by_dev_id[sw_id]
        sw_vlans: list[str] = []
        _, mgmt_vlan = infer_subnet_and_vlan_for_ip(sw_dev.management_ip)
        if mgmt_vlan and mgmt_vlan in vlan_node_id_by_vlan_id:
            sw_vlans.append(mgmt_vlan)
        for port in sw_dev.ports:
            if (
                port.vlan_id
                and port.vlan_id in vlan_node_id_by_vlan_id
                and port.vlan_id not in sw_vlans
            ):
                sw_vlans.append(port.vlan_id)
        for v_id in sw_vlans:
            add_edge(
                vlan_node_id_by_vlan_id[v_id],
                sw_node_id,
                "member_of_vlan",
                vlan_id=v_id,
            )

    # Unassigned IP nodes -> member_of_vlan
    assigned_ip_set: set[str] = set()
    for eq in site.equipment:
        for ip_str in eq.assigned_ips:
            assigned_ip_set.add(ip_str.strip())

    for ip_rec in site.ip_addresses:
        obj_id = ip_rec.assigned_object_id
        is_assigned_to_known = bool(
            (obj_id and (obj_id in eq_node_id_by_eq_id or obj_id in device_node_id_by_dev_id))
            or ip_rec.ip in assigned_ip_set
        )
        if not is_assigned_to_known:
            _, v_id = infer_subnet_and_vlan_for_ip(ip_rec.ip)
            if v_id and v_id in vlan_node_id_by_vlan_id:
                add_edge(
                    vlan_node_id_by_vlan_id[v_id],
                    ip_node_id_by_ip[ip_rec.ip],
                    "member_of_vlan",
                    vlan_id=v_id,
                )


def _add_assigned_ip_edges(ctx: _GraphBuildContext) -> None:
    # Edge group E: assigned_ip (Equipment / Device -> IP)
    site = ctx.site
    add_edge = ctx.add_edge
    device_node_id_by_dev_id = ctx.device_node_id_by_dev_id
    eq_node_id_by_eq_id = ctx.eq_node_id_by_eq_id
    ip_node_id_by_ip = ctx.ip_node_id_by_ip
    for eq in site.equipment:
        eq_node_id = eq_node_id_by_eq_id[eq.equipment_id]
        for ip_str in eq.assigned_ips:
            cleaned_ip = ip_str.strip()
            if cleaned_ip in ip_node_id_by_ip:
                add_edge(
                    eq_node_id,
                    ip_node_id_by_ip[cleaned_ip],
                    "assigned_ip",
                )

    for ip_rec in site.ip_addresses:
        ip_node_id = ip_node_id_by_ip[ip_rec.ip]
        obj_id = ip_rec.assigned_object_id
        if obj_id and obj_id in eq_node_id_by_eq_id:
            add_edge(
                eq_node_id_by_eq_id[obj_id],
                ip_node_id,
                "assigned_ip",
            )
        elif obj_id and obj_id in device_node_id_by_dev_id:
            add_edge(
                device_node_id_by_dev_id[obj_id],
                ip_node_id,
                "assigned_ip",
            )

    for dev in site.devices:
        if dev.management_ip and dev.management_ip.strip() in ip_node_id_by_ip:
            add_edge(
                device_node_id_by_dev_id[dev.device_id],
                ip_node_id_by_ip[dev.management_ip.strip()],
                "assigned_ip",
            )


def _add_hosts_vm_edges(ctx: _GraphBuildContext) -> None:
    # Edge group F: hosts_vm (Hypervisor -> VM Equipment)
    site = ctx.site
    device_node_id_by_dev_id = ctx.device_node_id_by_dev_id
    eq_node_id_by_eq_id = ctx.eq_node_id_by_eq_id
    eq_node_id_by_name_lower: dict[str, str] = {
        eq.name.strip().lower(): eq_node_id_by_eq_id[eq.equipment_id]
        for eq in site.equipment
    }
    dev_node_id_by_hostname_lower: dict[str, str] = {
        dev.hostname.strip().lower(): device_node_id_by_dev_id[dev.device_id]
        for dev in site.devices
    }

    for eq in site.equipment:
        if not eq.hypervisor_id or not eq.hypervisor_id.strip():
            continue
        hv_ref = eq.hypervisor_id.strip()
        hv_node_id: Optional[str] = None
        if hv_ref in eq_node_id_by_eq_id:
            hv_node_id = eq_node_id_by_eq_id[hv_ref]
        elif hv_ref in device_node_id_by_dev_id:
            hv_node_id = device_node_id_by_dev_id[hv_ref]
        elif hv_ref.lower() in eq_node_id_by_name_lower:
            hv_node_id = eq_node_id_by_name_lower[hv_ref.lower()]
        elif hv_ref.lower() in dev_node_id_by_hostname_lower:
            hv_node_id = dev_node_id_by_hostname_lower[hv_ref.lower()]

        if hv_node_id is not None and hv_node_id != eq_node_id_by_eq_id[eq.equipment_id]:
            ctx.add_edge(
                hv_node_id,
                eq_node_id_by_eq_id[eq.equipment_id],
                "hosts_vm",
            )
