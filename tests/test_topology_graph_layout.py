"""Tests for the topology graph facade: re-exported names, signatures and module size limit."""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path

import pytest

import sot_validator.topology as topology
import sot_validator.topology.graph as graph

TOPOLOGY_DIR = Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "topology"

PUBLIC_NAMES = [
    "TopologyEdge",
    "TopologyGraph",
    "TopologyGraphBuilder",
    "TopologyNode",
    "VALID_EDGE_RELATIONS",
    "VALID_NODE_TYPES",
]

# Name -> private module that defines it.
REEXPORTED_NAMES = {
    "VALID_NODE_TYPES": "_graph_models",
    "VALID_EDGE_RELATIONS": "_graph_models",
    "TopologyNode": "_graph_models",
    "TopologyEdge": "_graph_models",
    "TopologyGraph": "_graph_models",
    "TopologyGraphBuilder": "_graph_builder",
    "_ROUTER_DEVICE_ROLES": "_graph_models",
    "_ROUTER_HOSTNAME_TOKENS": "_graph_models",
    "_ACTIVE_POE_STATES": "_graph_models",
    "_MERMAID_RESERVED_WORDS": "_graph_models",
    "_NON_ALNUM_PATTERN": "_graph_models",
    "_TOKEN_SPLIT_PATTERN": "_graph_models",
    "_normalize_optional_mac": "_graph_models",
    "_is_router_hostname": "_graph_models",
    "_sanitize_mermaid_id": "_graph_models",
    "_escape_mermaid_label": "_graph_models",
    "_escape_mermaid_edge_label": "_graph_models",
}

GRAPH_MODULE_FILES = [
    "graph.py",
    "_graph_models.py",
    "_graph_context.py",
    "_graph_nodes.py",
    "_graph_edges.py",
    "_graph_builder.py",
]

P = inspect.Parameter


@pytest.mark.parametrize("name", sorted(REEXPORTED_NAMES))
def test_name_importable_from_graph(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.topology.graph import {name}", namespace)
    defining = importlib.import_module(
        f"sot_validator.topology.{REEXPORTED_NAMES[name]}"
    )
    assert namespace[name] is getattr(defining, name)
    assert namespace[name] is getattr(graph, name)
    if callable(namespace[name]):
        assert namespace[name].__module__ == defining.__name__


def test_graph_all_unchanged() -> None:
    assert graph.__all__ == PUBLIC_NAMES


def test_package_names_same_objects() -> None:
    for name in PUBLIC_NAMES:
        assert getattr(topology, name) is getattr(graph, name)


def _shape(func: object) -> list[tuple[str, inspect._ParameterKind, object]]:
    return [
        (param.name, param.kind, param.default)
        for param in inspect.signature(func).parameters.values()
    ]


def test_builder_init_signature_kept() -> None:
    assert _shape(graph.TopologyGraphBuilder.__init__) == [
        ("self", P.POSITIONAL_OR_KEYWORD, P.empty),
        ("include_unconnected_ports", P.KEYWORD_ONLY, False),
    ]
    assert graph.TopologyGraphBuilder().include_unconnected_ports is False
    assert (
        graph.TopologyGraphBuilder(include_unconnected_ports=True).include_unconnected_ports
        is True
    )


def test_builder_build_signature_kept() -> None:
    assert _shape(graph.TopologyGraphBuilder.build) == [
        ("self", P.POSITIONAL_OR_KEYWORD, P.empty),
        ("site", P.POSITIONAL_OR_KEYWORD, P.empty),
        ("validation_results", P.POSITIONAL_OR_KEYWORD, None),
        ("include_unconnected_ports", P.KEYWORD_ONLY, None),
    ]
    assert graph.TopologyGraphBuilder.build.__doc__ == (
        "Construct a TopologyGraph for the given Site and optional ValidationResult sequence."
    )


@pytest.mark.parametrize("filename", GRAPH_MODULE_FILES)
def test_graph_modules_under_800_lines(filename: str) -> None:
    path = TOPOLOGY_DIR / filename
    line_count = len(path.read_text(encoding="utf-8").splitlines())
    assert line_count < 800, f"{filename} has {line_count} lines"
