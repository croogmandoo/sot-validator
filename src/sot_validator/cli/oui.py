"""Offline IEEE OUI vendor lookup subcommand (`oui lookup`)."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from sot_validator.cli._common import INPUT_ERRORS, _input_error
from sot_validator.enrichment import OuiRegistry, classify_mac, load_oui_directory
from sot_validator.enrichment.oui import MAC_CLASS_INVALID
from sot_validator.topology.device_types import normalize_mac_address

_TEXT_COLUMNS = ("mac", "class", "vendor", "registry", "prefix_bits", "prefix")


def _lookup_row(registry: OuiRegistry, raw: str) -> dict[str, Any]:
    mac_class = classify_mac(raw)
    match = registry.lookup(raw)
    return {
        "input": raw,
        "mac": None if mac_class == MAC_CLASS_INVALID else normalize_mac_address(raw),
        "class": mac_class,
        "vendor": match.vendor if match else None,
        "prefix": match.prefix if match else None,
        "prefix_bits": match.prefix_bits if match else None,
        "registry": match.registry if match else None,
        "role_hint": match.role_hint if match else None,
    }


def _text_cell(value: Any) -> str:
    if value is None or value == "":
        return "-"
    # Escape tabs, newlines and other control characters so each MAC stays on one row.
    return "".join(
        ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii")
        for ch in str(value)
    )


def _render_text(results: list[dict[str, Any]]) -> str:
    lines = ["\t".join(_TEXT_COLUMNS)]
    for row in results:
        # The mac column shows the MAC as given, so invalid inputs stay identifiable.
        cells = [row["input"]] + [row[column] for column in _TEXT_COLUMNS[1:]]
        lines.append("\t".join(_text_cell(cell) for cell in cells))
    return "\n".join(lines)


def cmd_oui_lookup(args: argparse.Namespace) -> int:
    try:
        registry = load_oui_directory(getattr(args, "oui_dir", None))
    except (*INPUT_ERRORS, csv.Error) as exc:
        return _input_error("--oui-dir", args.oui_dir, exc)
    results = [_lookup_row(registry, raw) for raw in args.macs]
    if getattr(args, "json", False):
        print(json.dumps({"results": results}, indent=2, sort_keys=True))
    else:
        print(_render_text(results))
    return 0


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `oui` command group and its `lookup` subcommand."""
    # 27. oui (Phase 15)
    oui_parser = subparsers.add_parser(
        "oui",
        help="Offline IEEE OUI vendor lookup and MAC address classification (no network I/O).",
    )
    oui_subparsers = oui_parser.add_subparsers(dest="oui_command", required=True)

    lookup_parser = oui_subparsers.add_parser(
        "lookup",
        help="Look up the vendor and class of one or more MAC addresses.",
    )
    lookup_parser.add_argument(
        "macs",
        metavar="MAC",
        nargs="+",
        help="MAC address to look up (repeatable; output keeps input order and duplicates).",
    )
    lookup_parser.add_argument(
        "--oui-dir",
        type=Path,
        default=None,
        help="Directory of IEEE MA-L/MA-M/MA-S CSV exports to load (every *.csv, non-recursive; default: builtin vendor table only).",
    )
    lookup_parser.add_argument(
        "--json",
        action="store_true",
        help='Print {"results": [...]} JSON instead of tab-separated text.',
    )
    lookup_parser.set_defaults(func=cmd_oui_lookup)
