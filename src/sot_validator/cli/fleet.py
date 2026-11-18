"""Fleet site health scorecard subcommand (`fleet-summary`)."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from dataclasses import dataclass
import json
from pathlib import Path
import sys
from typing import Any, Optional

from sot_validator.cli._common import (
    INPUT_ERRORS,
    _input_error,
    _json_object_list,
    _load_json_object_list,
    _parse_report_time,
)
from sot_validator.lifecycle.certificates import VALID_SEVERITIES as CERT_SEVERITIES
from sot_validator.lifecycle.firmware import FIRMWARE_STATUSES
from sot_validator.quality.checks import VALID_SEVERITIES as QUALITY_SEVERITIES
from sot_validator.reporting import (
    FleetScorer,
    SiteScorecard,
    render_fleet_html,
    render_fleet_markdown,
)

REPORT_FLAGS: tuple[str, ...] = ("--quality", "--cert-report", "--firmware-check")
OUTPUT_FILES: tuple[str, ...] = ("fleet-summary.md", "fleet-summary.html", "fleet-summary.json")


@dataclass(frozen=True)
class _SeverityFinding:
    """The fields the fleet scorer reads from a quality or certificate finding."""

    site_id: str
    severity: str


@dataclass(frozen=True)
class _StatusFinding:
    """The fields the fleet scorer reads from a firmware finding."""

    site_id: str
    status: str


def _site_id(item: Mapping[str, Any], what: str) -> str:
    site_id = item["site_id"]
    if not isinstance(site_id, str) or not site_id.strip():
        raise ValueError(f"{what} site_id must be a non-empty string, got {site_id!r}")
    return site_id


def _choice(item: Mapping[str, Any], key: str, allowed: tuple[str, ...]) -> str:
    value = item[key]
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{key} must be one of {allowed}, got {value!r}")
    return value


def _severity_findings(items: list[Mapping[str, Any]], allowed: tuple[str, ...]) -> list[_SeverityFinding]:
    return [
        _SeverityFinding(_site_id(item, "finding"), _choice(item, "severity", allowed))
        for item in items
    ]


def _load_quality(path: Path) -> tuple[list[_SeverityFinding], list[str]]:
    """Return the quality findings and the report's `site_ids` (empty for a bare list)."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = _severity_findings(_json_object_list(raw, key="findings", path=path), QUALITY_SEVERITIES)
    site_ids: list[str] = []
    if isinstance(raw, Mapping) and "site_ids" in raw:
        listed = raw["site_ids"]
        if not isinstance(listed, list):
            raise ValueError(f"site_ids must be a list, got {type(listed).__name__}")
        for site_id in listed:
            if not isinstance(site_id, str) or not site_id.strip():
                raise ValueError(f"site_ids entries must be non-empty strings, got {site_id!r}")
            site_ids.append(site_id)
    return findings, site_ids


def _load_firmware(path: Path) -> list[_StatusFinding]:
    return [
        _StatusFinding(_site_id(item, "finding"), _choice(item, "status", FIRMWARE_STATUSES))
        for item in _load_json_object_list(path, key="findings")
    ]


def _load_previous(path: Path) -> list[SiteScorecard]:
    cards: list[SiteScorecard] = []
    for item in _load_json_object_list(path, key="scorecards"):
        _site_id(item, "scorecard")
        cards.append(SiteScorecard.from_dict(item))
    return cards


def cmd_fleet_summary(args: argparse.Namespace) -> int:
    if args.quality is None and args.cert_report is None and args.firmware_check is None:
        print(
            f"error: fleet-summary needs at least one of {', '.join(REPORT_FLAGS)}",
            file=sys.stderr,
        )
        return 2

    quality: Optional[list[_SeverityFinding]] = None
    certificates: Optional[list[_SeverityFinding]] = None
    firmware: Optional[list[_StatusFinding]] = None
    previous: Optional[list[SiteScorecard]] = None
    site_ids: list[str] = []

    if args.quality is not None:
        try:
            quality, site_ids = _load_quality(args.quality)
        except INPUT_ERRORS as exc:
            return _input_error("--quality", args.quality, exc)
    if args.cert_report is not None:
        try:
            certificates = _severity_findings(
                _load_json_object_list(args.cert_report, key="findings"), CERT_SEVERITIES
            )
        except INPUT_ERRORS as exc:
            return _input_error("--cert-report", args.cert_report, exc)
    if args.firmware_check is not None:
        try:
            firmware = _load_firmware(args.firmware_check)
        except INPUT_ERRORS as exc:
            return _input_error("--firmware-check", args.firmware_check, exc)
    if args.previous is not None:
        try:
            previous = _load_previous(args.previous)
        except INPUT_ERRORS as exc:
            return _input_error("--previous", args.previous, exc)
    for site_id in args.site or ():
        if not site_id.strip():
            return _input_error("--site", repr(site_id), ValueError("site id must not be empty"))
        site_ids.append(site_id)

    generated_at = None
    if args.evaluation_time is not None:
        try:
            generated_at = _parse_report_time(args.evaluation_time)
        except ValueError as exc:
            return _input_error("--evaluation-time", args.evaluation_time, exc)

    cards = FleetScorer().score_fleet(
        results=None,
        quality_findings=quality,
        certificate_findings=certificates,
        firmware_findings=firmware,
        drift_events=None,
        previous=previous,
        site_ids=site_ids,
    )
    texts = (
        render_fleet_markdown(cards, generated_at=generated_at),
        render_fleet_html(cards, generated_at=generated_at),
        json.dumps([card.to_dict() for card in cards], indent=2, sort_keys=True) + "\n",
    )
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, text in zip(OUTPUT_FILES, texts):
        (output_dir / name).write_text(text, encoding="utf-8")
    print(f"fleet-summary: {len(cards)} site(s) written to {output_dir} ({', '.join(OUTPUT_FILES)})")
    return 0


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `fleet-summary` subcommand."""
    # 26. fleet-summary
    fleet_parser = subparsers.add_parser(
        "fleet-summary",
        help="Build the fleet site health scorecard from quality / cert-report / firmware-check JSON (no network I/O).",
    )
    fleet_parser.add_argument(
        "--quality",
        type=Path,
        default=None,
        help="JSON written by `quality --output-json`.",
    )
    fleet_parser.add_argument(
        "--cert-report",
        type=Path,
        default=None,
        help="JSON written by `cert-report --output-json`.",
    )
    fleet_parser.add_argument(
        "--firmware-check",
        type=Path,
        default=None,
        help="JSON written by `firmware-check --output-json`.",
    )
    fleet_parser.add_argument(
        "--previous",
        type=Path,
        default=None,
        help="fleet-summary.json from an earlier run; supplies each site's previous score for the trend.",
    )
    fleet_parser.add_argument(
        "--site",
        type=str,
        action="append",
        default=None,
        help="Extra site id to list even without findings (repeatable).",
    )
    fleet_parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory for fleet-summary.md, fleet-summary.html and fleet-summary.json (created if missing).",
    )
    fleet_parser.add_argument(
        "--evaluation-time",
        type=str,
        default=None,
        help="Reference ISO-8601 timestamp (naive means UTC; default: no timestamp).",
    )
    fleet_parser.set_defaults(func=cmd_fleet_summary)
