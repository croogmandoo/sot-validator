"""Topology graph constants, helpers, and the node, edge, and graph records."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import json
import re
from typing import Any, Optional

from sot_validator.models import _require_non_empty_str
from sot_validator.topology.device_types import normalize_mac_address

VALID_NODE_TYPES: tuple[str, ...] = (
    "site",
    "router",
    "switch",
    "vlan",
    "subnet",
    "port",
    "equipment",
    "ip",
)

VALID_EDGE_RELATIONS: tuple[str, ...] = (
    "routes_vlan",
    "uplink_to",
    "member_of_vlan",
    "connected_port",
    "assigned_ip",
    "hosts_vm",
)

_ROUTER_DEVICE_ROLES: frozenset[str] = frozenset(
    {"router", "l3_switch", "firewall", "gateway"}
)
_ROUTER_HOSTNAME_TOKENS: frozenset[str] = frozenset(
    {"router", "gw", "gateway", "rtr", "udm", "edge"}
)
_ACTIVE_POE_STATES: frozenset[str] = frozenset(
    {"delivering", "active", "on", "searching", "fault"}
)
_MERMAID_RESERVED_WORDS: frozenset[str] = frozenset(
    {"end", "subgraph", "flowchart", "graph", "style", "class", "click", "default"}
)
_NON_ALNUM_PATTERN = re.compile(r"[^a-zA-Z0-9_]+")
_TOKEN_SPLIT_PATTERN = re.compile(r"[^a-z0-9]+")


def _normalize_optional_mac(mac: Optional[str]) -> Optional[str]:
    if not isinstance(mac, str) or not mac.strip():
        return None
    try:
        return normalize_mac_address(mac)
    except ValueError:
        return mac.strip().lower()


def _is_router_hostname(hostname: str) -> bool:
    lower = hostname.strip().lower()
    if any(sub in lower for sub in ("router", "gateway", "udm")):
        return True
    tokens = {tok for tok in _TOKEN_SPLIT_PATTERN.split(lower) if tok}
    return bool(tokens & _ROUTER_HOSTNAME_TOKENS)


def _sanitize_mermaid_id(raw_id: str) -> str:
    cleaned = _NON_ALNUM_PATTERN.sub("_", raw_id.strip()).strip("_")
    if not cleaned:
        cleaned = "node"
    if cleaned[0].isdigit() or cleaned.lower() in _MERMAID_RESERVED_WORDS:
        cleaned = f"n_{cleaned}"
    return cleaned


def _escape_mermaid_label(text: str) -> str:
    return (
        text.replace("\\", "\\\\")
        .replace('"', "'")
        .replace("\n", " ")
        .replace("\r", " ")
    )


def _escape_mermaid_edge_label(text: str) -> str:
    return (
        text.replace("|", "/")
        .replace('"', "'")
        .replace("\n", " ")
        .replace("\r", " ")
    )


@dataclass
class TopologyNode:
    """Single vertex in a site network topology graph."""

    node_id: str
    node_type: str
    label: str
    ip: Optional[str] = None
    mac: Optional[str] = None
    vlan_id: Optional[str] = None
    status: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_non_empty_str(self.node_id, "node_id")
        _require_non_empty_str(self.node_type, "node_type")
        _require_non_empty_str(self.label, "label")

        normalized_type = self.node_type.strip().lower()
        if normalized_type not in VALID_NODE_TYPES:
            raise ValueError(
                f"Invalid node_type {self.node_type!r}; must be one of {VALID_NODE_TYPES}"
            )
        self.node_type = normalized_type
        self.mac = _normalize_optional_mac(self.mac)

        if self.metadata is None:
            self.metadata = {}
        elif isinstance(self.metadata, Mapping):
            self.metadata = dict(self.metadata)
        else:
            raise ValueError("metadata must be a mapping or None")

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "label": self.label,
            "ip": self.ip,
            "mac": self.mac,
            "vlan_id": self.vlan_id,
            "status": self.status,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TopologyNode:
        return cls(
            node_id=data["node_id"],
            node_type=data["node_type"],
            label=data["label"],
            ip=data.get("ip"),
            mac=data.get("mac"),
            vlan_id=data.get("vlan_id"),
            status=data.get("status"),
            metadata=data.get("metadata") or {},
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> TopologyNode:
        return cls.from_dict(json.loads(raw))


@dataclass
class TopologyEdge:
    """Directed relationship between two TopologyNode records."""

    source_id: str
    target_id: str
    relation: str
    port_name: Optional[str] = None
    vlan_id: Optional[str] = None
    poe_status: Optional[str] = None

    def __post_init__(self) -> None:
        _require_non_empty_str(self.source_id, "source_id")
        _require_non_empty_str(self.target_id, "target_id")
        _require_non_empty_str(self.relation, "relation")

        normalized_relation = self.relation.strip().lower()
        if normalized_relation not in VALID_EDGE_RELATIONS:
            raise ValueError(
                f"Invalid edge relation {self.relation!r}; must be one of {VALID_EDGE_RELATIONS}"
            )
        self.relation = normalized_relation

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation": self.relation,
            "port_name": self.port_name,
            "vlan_id": self.vlan_id,
            "poe_status": self.poe_status,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TopologyEdge:
        return cls(
            source_id=data["source_id"],
            target_id=data["target_id"],
            relation=data["relation"],
            port_name=data.get("port_name"),
            vlan_id=data.get("vlan_id"),
            poe_status=data.get("poe_status"),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> TopologyEdge:
        return cls.from_dict(json.loads(raw))


@dataclass
class TopologyGraph:
    """Complete site network topology graph with nodes, directed edges, and summary counts."""

    site_id: str
    nodes: list[TopologyNode] = field(default_factory=list)
    edges: list[TopologyEdge] = field(default_factory=list)
    summary_counts: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_non_empty_str(self.site_id, "site_id")
        self.nodes = [
            n if isinstance(n, TopologyNode) else TopologyNode.from_dict(n)
            for n in self.nodes
        ]
        self.edges = [
            e if isinstance(e, TopologyEdge) else TopologyEdge.from_dict(e)
            for e in self.edges
        ]
        self.summary_counts = self.compute_summary_counts()

    def compute_summary_counts(self) -> dict[str, int]:
        """Compute node type, edge relation, and total counts for the graph."""
        counts: dict[str, int] = {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
        }
        for node_type in VALID_NODE_TYPES:
            counts[node_type] = 0
        for relation in VALID_EDGE_RELATIONS:
            counts[relation] = 0

        for node in self.nodes:
            counts[node.node_type] = counts.get(node.node_type, 0) + 1
        for edge in self.edges:
            counts[edge.relation] = counts.get(edge.relation, 0) + 1

        self.summary_counts = counts
        return counts

    def get_node(self, node_id: str) -> Optional[TopologyNode]:
        """Return the TopologyNode matching node_id, or None if not found."""
        for node in self.nodes:
            if node.node_id == node_id:
                return node
        return None

    def get_edges_for_node(self, node_id: str) -> list[TopologyEdge]:
        """Return all TopologyEdge instances where node_id is the source or target."""
        return [
            edge
            for edge in self.edges
            if edge.source_id == node_id or edge.target_id == node_id
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "summary_counts": dict(self. compute_summary_counts()),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TopologyGraph:
        return cls(
            site_id=data["site_id"],
            nodes=[
                n if isinstance(n, TopologyNode) else TopologyNode.from_dict(n)
                for n in data.get("nodes", [])
            ],
            edges=[
                e if isinstance(e, TopologyEdge) else TopologyEdge.from_dict(e)
                for e in data.get("edges", [])
            ],
            summary_counts=dict(data.get("summary_counts") or {}),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> TopologyGraph:
        return cls.from_dict(json.loads(raw))

    def to_mermaid(self) -> str:
        """Serialize the topology graph to a Mermaid flowchart LR diagram."""
        lines: list[str] = ["flowchart LR"]
        mermaid_ids: dict[str, str] = {}
        used_ids: set[str] = set()

        def resolve_mermaid_id(raw_node_id: str) -> str:
            if raw_node_id in mermaid_ids:
                return mermaid_ids[raw_node_id]
            base = _sanitize_mermaid_id(raw_node_id)
            candidate = base
            suffix = 2
            while candidate in used_ids:
                candidate = f"{base}_{suffix}"
                suffix += 1
            used_ids.add(candidate)
            mermaid_ids[raw_node_id] = candidate
            return candidate

        for node in self.nodes:
            m_id = resolve_mermaid_id(node.node_id)
            label_parts = [node.label]
            if node.ip and node.ip != node.label:
                label_parts.append(node.ip)
            escaped_label = _escape_mermaid_label(" - ".join(label_parts))
            lines.append(f'    {m_id}["{escaped_label}"]')

        for edge in self.edges:
            src_id = resolve_mermaid_id(edge.source_id)
            dst_id = resolve_mermaid_id(edge.target_id)
            details: list[str] = [edge.relation]
            if edge.port_name:
                details.append(edge.port_name)
            if edge.vlan_id:
                details.append(f"VLAN {edge.vlan_id}")
            if edge.poe_status:
                details.append(f"PoE:{edge.poe_status}")
            edge_label = _escape_mermaid_edge_label(" ".join(details))
            lines.append(f"    {src_id} -->|{edge_label}| {dst_id}")

        return "\n".join(lines)

