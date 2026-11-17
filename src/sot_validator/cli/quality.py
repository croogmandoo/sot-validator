"""SoT data-quality conflict report subcommand (`quality`)."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import asdict
import json
from pathlib import Path
from typing import Any

from sot_validator.cli._common import (
    INPUT_ERRORS,
    _input_error,
    _load_single_site_snapshot,
    _parse_str_list,
    _write_report_outputs,
)
from sot_validator.models import Site
from sot_validator.quality import (
    ALL_RULE_NAMES,
    VALID_SEVERITIES,
    DataQualityChecker,
    QualityFinding,
)
from sot_validator.reporting.generators import _escape_md_cell


def _unknown_rules(names: Sequence[str]) -> list[str]:
    return [name for name in names if name not in ALL_RULE_NAMES]


def _build_quality_report(
    sites: Sequence[Site], rules: Sequence[str], findings: Sequence[QualityFinding]
) -> dict[str, Any]:
    severity_counts = {severity: 0 for severity in VALID_SEVERITIES}
    for finding in findings:
        severity_counts[finding.severity] += 1
    return {
        "site_ids": [site.site_id for site in sites],
        "rules": list(rules),
        "cross_site": len(sites) > 1,
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "findings": [asdict(finding) for finding in findings],
    }


def _render_quality_markdown(report: dict[str, Any]) -> str:
    """Render the data-quality report as Markdown with a findings table in checker order."""
    lines = [
        "# SoT Data-Quality Report",
        "",
        f"- Sites: {_escape_md_cell(', '.join(report['site_ids']))}",
        f"- Total findings: {report['total_findings']}",
        "",
        "## Severity Counts",
        "",
    ]
    for severity, count in report["severity_counts"].items():
        lines.append(f"- {severity}: {count}")
    lines.extend(["", "## Findings", ""])
    if not report["findings"]:
        lines.append("No data-quality findings.")
        return "\n".join(lines) + "\n"
    lines.append("| Site | Rule | Severity | Record Type | Records | Message |")
    lines.append("|---|---|---|---|---|---|")
    for finding in report["findings"]:
        cells = (
            finding["site_id"],
            finding["rule"],
            finding["severity"],
            finding["record_type"],
            ", ".join(finding["record_ids"]),
            finding["message"],
        )
        lines.append("| " + " | ".join(_escape_md_cell(cell) for cell in cells) + " |")
    return "\n".join(lines) + "\n"


def cmd_quality(args: argparse.Namespace) -> int:
    selected = _parse_str_list(getattr(args, "rules", None))
    disabled = _parse_str_list(getattr(args, "disable", None))
    for flag, names in (("--rules", selected), ("--disable", disabled)):
        unknown = _unknown_rules(names)
        if unknown:
            return _input_error(
                flag,
                ",".join(names),
                ValueError(f"Unknown rule name(s): {', '.join(unknown)}"),
            )

    disabled_rules = set(disabled)
    if selected:
        disabled_rules.update(name for name in ALL_RULE_NAMES if name not in selected)
    enabled = [name for name in ALL_RULE_NAMES if name not in disabled_rules]

    sites: list[Site] = []
    for snapshot in args.snapshot:
        try:
            sites.append(_load_single_site_snapshot(Path(snapshot), args))
        except INPUT_ERRORS as exc:
            return _input_error("--snapshot", snapshot, exc)

    checker = DataQualityChecker(
        disabled_rules=[name for name in ALL_RULE_NAMES if name in disabled_rules]
    )
    findings = (
        checker.check_site(sites[0]) if len(sites) == 1 else checker.check_sites(sites)
    )
    report = _build_quality_report(sites, enabled, findings)
    _write_report_outputs(
        args,
        json.dumps(report, indent=2, sort_keys=True),
        _render_quality_markdown(report),
    )
    return 0


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `quality` subcommand."""
    # 23. quality (Phase 13)
    quality_parser = subparsers.add_parser(
        "quality",
        help="Report SoT data-quality conflicts (duplicate IP/MAC, out-of-block IPs, orphans, hostname mismatches) across site snapshots.",
    )
    quality_parser.add_argument(
        "--snapshot",
        type=Path,
        action="append",
        required=True,
        help="Site JSON snapshot file or SnapshotStore directory (repeatable; two or more add the cross-site rules).",
    )
    quality_parser.add_argument(
        "--rules",
        action="append",
        default=None,
        help=f"Comma-separated rule names to run, all others disabled (repeatable). Rules: {', '.join(ALL_RULE_NAMES)}.",
    )
    quality_parser.add_argument(
        "--disable",
        action="append",
        default=None,
        help="Comma-separated rule names to disable (repeatable).",
    )
    quality_parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Output path for the data-quality report JSON.",
    )
    quality_parser.add_argument(
        "--output-md",
        type=Path,
        default=None,
        help="Output path for the data-quality report Markdown.",
    )
    quality_parser.set_defaults(func=cmd_quality)
