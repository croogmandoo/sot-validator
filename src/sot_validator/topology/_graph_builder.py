"""TopologyGraphBuilder: runs the node phases and edge groups for one Site."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Optional

from sot_validator.models import Site, ValidationResult
from sot_validator.topology._graph_context import _GraphBuildContext
from sot_validator.topology._graph_edges import (
    _add_assigned_ip_edges,
    _add_connected_port_edges,
    _add_hosts_vm_edges,
    _add_member_of_vlan_edges,
    _add_routes_vlan_edges,
    _add_uplink_edges,
)
from sot_validator.topology._graph_models import TopologyGraph
from sot_validator.topology._graph_nodes import (
    _add_device_nodes,
    _add_equipment_nodes,
    _add_ip_nodes,
    _add_port_nodes,
    _add_site_node,
    _add_subnet_nodes,
    _add_vlan_nodes,
    _collect_referenced_port_refs,
)


class TopologyGraphBuilder:
    """Builds a deterministic TopologyGraph from a Site snapshot and optional ValidationResults."""

    def __init__(self, *, include_unconnected_ports: bool = False) -> None:
        self.include_unconnected_ports = include_unconnected_ports

    def build(
        self,
        site: Site,
        validation_results: Optional[Sequence[ValidationResult]] = None,
        *,
        include_unconnected_ports: Optional[bool] = None,
    ) -> TopologyGraph:
        """Construct a TopologyGraph for the given Site and optional ValidationResult sequence."""
        if not isinstance(site, Site):
            raise ValueError("site must be a Site instance")

        include_all_ports = (
            self.include_unconnected_ports
            if include_unconnected_ports is None
            else include_unconnected_ports
        )

        val_by_id: dict[str, ValidationResult] = {}
        val_by_name: dict[str, ValidationResult] = {}
        if validation_results:
            for res in validation_results:
                val_by_id[res.item_id] = res
                val_by_name[res.name] = res

        ctx = _GraphBuildContext(site, val_by_id, val_by_name, include_all_ports)

        _add_site_node(ctx)
        ctx.build_lookups()
        _add_device_nodes(ctx)
        _add_vlan_nodes(ctx)
        _add_subnet_nodes(ctx)
        _collect_referenced_port_refs(ctx)
        _add_port_nodes(ctx)
        _add_equipment_nodes(ctx)
        _add_ip_nodes(ctx)

        _add_uplink_edges(ctx)
        _add_routes_vlan_edges(ctx)
        _add_connected_port_edges(ctx)
        _add_member_of_vlan_edges(ctx)
        _add_assigned_ip_edges(ctx)
        _add_hosts_vm_edges(ctx)

        return TopologyGraph(
            site_id=site.site_id,
            nodes=ctx.nodes,
            edges=ctx.edges,
        )
