"""Network topology graph builder for routers, switches, VLANs, ports, and hosts."""

from __future__ import annotations

from sot_validator.topology._graph_builder import TopologyGraphBuilder
from sot_validator.topology._graph_models import (
    VALID_EDGE_RELATIONS,
    VALID_NODE_TYPES,
    TopologyEdge,
    TopologyGraph,
    TopologyNode,
    _ACTIVE_POE_STATES,
    _MERMAID_RESERVED_WORDS,
    _NON_ALNUM_PATTERN,
    _ROUTER_DEVICE_ROLES,
    _ROUTER_HOSTNAME_TOKENS,
    _TOKEN_SPLIT_PATTERN,
    _escape_mermaid_edge_label,
    _escape_mermaid_label,
    _is_router_hostname,
    _normalize_optional_mac,
    _sanitize_mermaid_id,
)

__all__ = [
    "TopologyEdge",
    "TopologyGraph",
    "TopologyGraphBuilder",
    "TopologyNode",
    "VALID_EDGE_RELATIONS",
    "VALID_NODE_TYPES",
]
