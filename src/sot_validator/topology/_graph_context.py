"""Per-build state for TopologyGraphBuilder: node/edge registries and site lookups."""

from __future__ import annotations

import ipaddress
from typing import Any, Optional

from sot_validator.models import (
    Equipment,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    Subnet,
    VLAN,
    ValidationResult,
)
from sot_validator.topology._graph_models import (
    TopologyEdge,
    TopologyNode,
    _normalize_optional_mac,
)


class _GraphBuildContext:
    """Shared local state of one TopologyGraphBuilder.build call."""

    def __init__(
        self,
        site: Site,
        val_by_id: dict[str, ValidationResult],
        val_by_name: dict[str, ValidationResult],
        include_all_ports: bool,
    ) -> None:
        self.site = site
        self.val_by_id = val_by_id
        self.val_by_name = val_by_name
        self.include_all_ports = include_all_ports

        self.nodes: list[TopologyNode] = []
        self.node_by_id: dict[str, TopologyNode] = {}

        # Set by the node phases, in build order
        self.site_node: TopologyNode
        self.subnet_by_id: dict[str, Subnet] = {}
        self.parsed_subnets: list[tuple[ipaddress._BaseNetwork, Subnet]] = []
        self.vlan_by_id: dict[str, VLAN] = {}
        self.parsed_vlans: list[tuple[ipaddress._BaseNetwork, VLAN]] = []
        self.site_gateway_ips: set[str] = set()
        self.ip_rec_by_ip: dict[str, IPAddress] = {}
        self.device_node_id_by_dev_id: dict[str, str] = {}
        self.router_dev_ids: list[str] = []
        self.switch_dev_ids: list[str] = []
        self.vlan_node_id_by_vlan_id: dict[str, str] = {}
        self.subnet_node_id_by_subnet_id: dict[str, str] = {}
        self.referenced_port_refs: set[str] = set()
        self.port_node_id_by_port_id: dict[str, str] = {}
        self.included_ports: list[tuple[NetworkDevice, Port, str]] = []
        self.eq_node_id_by_eq_id: dict[str, str] = {}
        self.eq_by_id: dict[str, Equipment] = {}
        self.eq_mac_by_eq_id: dict[str, Optional[str]] = {}
        self.eq_vlans_by_eq_id: dict[str, list[str]] = {}
        self.ip_node_id_by_ip: dict[str, str] = {}

        # Edge management (deduplicated by (source_id, target_id, relation))
        self.edges: list[TopologyEdge] = []
        self.edge_by_key: dict[tuple[str, str, str], TopologyEdge] = {}

        # Set by edge group B, used by edge group D
        self.dev_by_id: dict[str, NetworkDevice] = {}

    def register_node(
        self,
        raw_id: str,
        node_type: str,
        label: str,
        *,
        ip: Optional[str] = None,
        mac: Optional[str] = None,
        vlan_id: Optional[str] = None,
        status: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        entity_id_for_validation: Optional[str] = None,
    ) -> TopologyNode:
        node_by_id = self.node_by_id
        val_by_id = self.val_by_id
        val_by_name = self.val_by_name
        candidate_id = (
            raw_id if raw_id not in node_by_id else f"{node_type}:{raw_id}"
        )
        if candidate_id in node_by_id:
            return node_by_id[candidate_id]

        meta = dict(metadata) if metadata else {}
        resolved_status = status

        lookup_keys = [raw_id, candidate_id]
        if entity_id_for_validation:
            lookup_keys.insert(0, entity_id_for_validation)
        if ip:
            lookup_keys.append(ip)

        matched_val: Optional[ValidationResult] = None
        for key in lookup_keys:
            if key in val_by_id:
                matched_val = val_by_id[key]
                break
        if matched_val is None and label in val_by_name:
            matched_val = val_by_name[label]

        if matched_val is not None:
            resolved_status = matched_val.classification.value
            meta["confidence"] = matched_val.confidence

        node = TopologyNode(
            node_id=candidate_id,
            node_type=node_type,
            label=label,
            ip=ip,
            mac=mac,
            vlan_id=vlan_id,
            status=resolved_status,
            metadata=meta,
        )
        self.nodes.append(node)
        node_by_id[candidate_id] = node
        return node

    def build_lookups(self) -> None:
        """Helper lookups for subnets, VLANs, IPs, and MACs."""
        site = self.site
        self.subnet_by_id = {s.subnet_id: s for s in site.subnets}
        parsed_subnets = self.parsed_subnets
        for s in site.subnets:
            try:
                parsed_subnets.append((ipaddress.ip_network(s.cidr, strict=False), s))
            except ValueError:
                continue

        self.vlan_by_id = {v.vlan_id: v for v in site.vlans}
        parsed_vlans = self.parsed_vlans
        for v in site.vlans:
            if v.cidr:
                try:
                    parsed_vlans.append((ipaddress.ip_network(v.cidr, strict=False), v))
                except ValueError:
                    continue

        site_gateway_ips = self.site_gateway_ips
        for v in site.vlans:
            if v.gateway and v.gateway.strip():
                site_gateway_ips.add(v.gateway.strip())
        for s in site.subnets:
            if s.gateway and s.gateway.strip():
                site_gateway_ips.add(s.gateway.strip())

        self.ip_rec_by_ip = {ip_rec.ip: ip_rec for ip_rec in site.ip_addresses}

    def infer_vlan_for_subnet_id(self, subnet_id: Optional[str]) -> Optional[str]:
        if not subnet_id:
            return None
        sub = self.subnet_by_id.get(subnet_id)
        if sub and sub.vlan_id:
            return sub.vlan_id
        for v in self.site.vlans:
            if v.subnet_id == subnet_id:
                return v.vlan_id
            if sub and v.cidr and v.cidr == sub.cidr:
                return v.vlan_id
        return None

    def infer_subnet_and_vlan_for_ip(
        self,
        ip_str: Optional[str],
    ) -> tuple[Optional[str], Optional[str]]:
        infer_vlan_for_subnet_id = self.infer_vlan_for_subnet_id
        if not ip_str or not ip_str.strip():
            return None, None
        cleaned = ip_str.strip()
        for ip_rec in self.site.ip_addresses:
            if ip_rec.ip == cleaned:
                return ip_rec.subnet_id, infer_vlan_for_subnet_id(ip_rec.subnet_id)
        try:
            ip_obj = ipaddress.ip_address(cleaned)
        except ValueError:
            return None, None
        for net, sub in self.parsed_subnets:
            if ip_obj in net:
                return sub.subnet_id, sub.vlan_id or infer_vlan_for_subnet_id(
                    sub.subnet_id
                )
        for net, v in self.parsed_vlans:
            if ip_obj in net:
                return v.subnet_id, v.vlan_id
        return None, None

    def extract_ip_mac(self, ip_rec: IPAddress) -> Optional[str]:
        raw_mac = ip_rec.arp_mac or (
            ip_rec.arp_entry.arp_mac if ip_rec.arp_entry is not None else None
        )
        return _normalize_optional_mac(raw_mac)

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        *,
        port_name: Optional[str] = None,
        vlan_id: Optional[str] = None,
        poe_status: Optional[str] = None,
    ) -> TopologyEdge:
        edge_by_key = self.edge_by_key
        key = (source_id, target_id, relation)
        if key in edge_by_key:
            existing = edge_by_key[key]
            if existing.port_name is None and port_name is not None:
                existing.port_name = port_name
            if existing.vlan_id is None and vlan_id is not None:
                existing.vlan_id = vlan_id
            if existing.poe_status is None and poe_status is not None:
                existing.poe_status = poe_status
            return existing
        edge = TopologyEdge(
            source_id=source_id,
            target_id=target_id,
            relation=relation,
            port_name=port_name,
            vlan_id=vlan_id,
            poe_status=poe_status,
        )
        self.edges.append(edge)
        edge_by_key[key] = edge
        return edge
