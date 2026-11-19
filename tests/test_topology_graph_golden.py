"""Golden-output tests for TopologyGraphBuilder on a seeded synthetic site.

The fixtures were recorded from the unsplit ``topology/graph.py``. Router ->
VLAN edges are emitted by iterating a set of VLAN ids, so the edge order
depends on string hashing; each case is built in a subprocess with a fixed
``PYTHONHASHSEED`` to keep the output byte-for-byte comparable.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "topology_graph"
HASH_SEED = "0"

_RENDER_SCRIPT = """
import sys
from sot_validator.testing.synthetic import SyntheticFleetGenerator
from sot_validator.topology.graph import TopologyGraphBuilder

include_all, output = sys.argv[1] == "1", sys.argv[2]
site = SyntheticFleetGenerator(
    seed=7, sites=1, subnets_per_site=2, hosts_per_subnet=6
).generate().sites[0]
builder = TopologyGraphBuilder()
graph = (
    builder.build(site, include_unconnected_ports=True)
    if include_all
    else builder.build(site)
)
text = graph.to_json(indent=2) if output == "json" else graph.to_mermaid()
sys.stdout.write(text)
"""

# (fixture file, include_unconnected_ports, output format)
CASES = [
    ("seed7_default.json", False, "json"),
    ("seed7_default.mmd", False, "mermaid"),
    ("seed7_all_ports.json", True, "json"),
    ("seed7_all_ports.mmd", True, "mermaid"),
]


def render_case(include_all: bool, output: str) -> str:
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = HASH_SEED
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(REPO_ROOT / "src"), env.get("PYTHONPATH")) if p
    )
    completed = subprocess.run(
        [sys.executable, "-c", _RENDER_SCRIPT, "1" if include_all else "0", output],
        capture_output=True,
        check=True,
        cwd=REPO_ROOT,
        env=env,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout


@pytest.mark.parametrize(("fixture", "include_all", "output"), CASES)
def test_build_output_matches_golden_fixture(
    fixture: str, include_all: bool, output: str
) -> None:
    expected = (FIXTURE_DIR / fixture).read_text(encoding="utf-8")
    assert render_case(include_all, output) == expected
