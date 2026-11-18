"""Offline UPS power-dependency subcommands (`power blast-radius`, `power risk`)."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Optional

from sot_validator.cli._common import (
    INPUT_ERRORS,
    _input_error,
    _load_json_object_list,
    _load_single_site_snapshot,
    _write_report_outputs,
)
from sot_validator.models import Site
from sot_validator.signals.ups_health import UpsHealthRecord
from sot_validator.topology import (
    PowerDependencyGraph,
    PowerMapLoader,
    generate_power_json_report,
    generate_power_markdown_report,
    generate_power_risk_json_report,
    generate_power_risk_markdown_report,
)


def _load_site_and_graph(
    args: argparse.Namespace,
) -> tuple[Optional[Site], Optional[PowerDependencyGraph], int]:
    """Load the snapshot and power map, print map problems as warnings, and build the graph.

    Returns ``(site, graph, 0)`` on success or ``(None, None, 2)`` after printing an error.
    """
    try:
        site = _load_single_site_snapshot(Path(args.snapshot), args)
    except INPUT_ERRORS as exc:
        return None, None, _input_error("--snapshot", args.snapshot, exc)
    try:
        result = PowerMapLoader(site).load(Path(args.power_map))
    except (*INPUT_ERRORS, csv.Error) as exc:
        return None, None, _input_error("--power-map", args.power_map, exc)
    for problem in result.problems:
        print(
            f"warning: power map row {problem.feed_index}: {' '.join(problem.message.split())}",
            file=sys.stderr,
        )
    try:
        graph = PowerDependencyGraph(result.feeds)
    except ValueError as exc:
        return None, None, _input_error("--power-map", args.power_map, exc)
    return site, graph, 0


def cmd_power_blast_radius(args: argparse.Namespace) -> int:
    site, graph, code = _load_site_and_graph(args)
    if site is None or graph is None:
        return code
    ups_ids: Optional[list[str]] = None
    if getattr(args, "ups", None) is not None:
        known = graph.ups_sources()
        if args.ups not in known:
            detail = (
                f"known UPS IDs: {', '.join(known)}"
                if known
                else "the power map has no UPS sources"
            )
            return _input_error(
                "--ups", args.ups, ValueError(f"not a UPS source in the power map ({detail})")
            )
        ups_ids = [args.ups]
    _write_report_outputs(
        args,
        generate_power_json_report(site, graph, ups_ids=ups_ids),
        generate_power_markdown_report(site, graph, ups_ids=ups_ids),
    )
    return 0


def cmd_power_risk(args: argparse.Namespace) -> int:
    site, graph, code = _load_site_and_graph(args)
    if site is None or graph is None:
        return code
    records: list[UpsHealthRecord] = []
    if getattr(args, "ups_health", None) is not None:
        try:
            records = [
                UpsHealthRecord.from_dict(item)
                for item in _load_json_object_list(Path(args.ups_health), key="records")
            ]
        except INPUT_ERRORS as exc:
            return _input_error("--ups-health", args.ups_health, exc)
    _write_report_outputs(
        args,
        generate_power_risk_json_report(site, graph, records),
        generate_power_risk_markdown_report(site, graph, records),
    )
    return 0


def _add_common_arguments(parser: argparse.ArgumentParser, report_name: str) -> None:
    parser.add_argument(
        "--snapshot",
        type=Path,
        required=True,
        help="Site JSON snapshot file or SnapshotStore directory with the site's UPS equipment.",
    )
    parser.add_argument(
        "--power-map",
        type=Path,
        required=True,
        help="Operator power map: .json (list or {\"feeds\": [...]}) or .csv (device_id, psu, source_id, source_type, outlet).",
    )
    parser.add_argument(
        "--site-id",
        type=str,
        default=None,
        help="Site ID to select from --snapshot (default: the first site).",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help=f"Output path for the {report_name} JSON.",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=None,
        help=f"Output path for the {report_name} Markdown.",
    )


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `power` command group and its `blast-radius` / `risk` subcommands."""
    # 29. power (Phase 16)
    power_parser = subparsers.add_parser(
        "power",
        help="Offline UPS power-dependency blast radius and risk ranking from an operator power map (no network I/O).",
    )
    power_subparsers = power_parser.add_subparsers(dest="power_command", required=True)

    blast_parser = power_subparsers.add_parser(
        "blast-radius",
        help="Report which devices lose all power or redundancy when a UPS fails.",
    )
    _add_common_arguments(blast_parser, "power-dependency report")
    blast_parser.add_argument(
        "--ups",
        type=str,
        default=None,
        help="Limit the blast-radius section to this UPS ID (default: every UPS source in the map).",
    )
    blast_parser.set_defaults(func=cmd_power_blast_radius)

    risk_parser = power_subparsers.add_parser(
        "risk",
        help="Rank UPS units by health severity times the critical devices they would take down.",
    )
    _add_common_arguments(risk_parser, "power-risk report")
    risk_parser.add_argument(
        "--ups-health",
        type=Path,
        default=None,
        help='UPS health records from `ups-health` ({"records": [...]}) or a bare list (default: every UPS is UNKNOWN).',
    )
    risk_parser.set_defaults(func=cmd_power_risk)
