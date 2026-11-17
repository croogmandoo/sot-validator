"""TLS certificate expiry and weak-crypto inventory subcommand (`cert-report`)."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Optional

from sot_validator.cli._common import (
    INPUT_ERRORS,
    _input_error,
    _load_json_object_list,
    _load_single_site_snapshot,
    _parse_report_time,
    _write_report_outputs,
)
from sot_validator.discovery import RawServiceBanner, TlsCertificate
from sot_validator.lifecycle import (
    DEFAULT_WARN_DAYS,
    CertificateInventory,
    CertificateRecord,
    certificate_records_from_tls,
    generate_certificate_json_report,
    generate_certificate_markdown_report,
)
from sot_validator.models import Site


def _parse_warn_days(raw: str) -> tuple[int, ...]:
    """Parse comma-separated positive integer day thresholds, rejecting blanks and non-digits."""
    values: list[int] = []
    for part in str(raw).split(","):
        cleaned = part.strip()
        if not re.fullmatch(r"[0-9]+", cleaned) or int(cleaned) <= 0:
            raise ValueError(f"warn days must be positive integers, got {cleaned!r}")
        values.append(int(cleaned))
    return tuple(values)


def _sot_hostname(site: Site, ip: str) -> Optional[str]:
    """Return the SoT name at an IP: device hostname by management IP, else equipment name."""
    for device in sorted(site.devices, key=lambda d: d.device_id):
        if device.management_ip == ip:
            return device.hostname
    for equipment in sorted(site.equipment, key=lambda e: e.equipment_id):
        if ip in equipment.assigned_ips:
            return equipment.name
    return None


def _certificate_records(
    banners: list[RawServiceBanner], site_id: str, site: Optional[Site]
) -> list[CertificateRecord]:
    by_ip: dict[str, list[TlsCertificate]] = {}
    for banner in banners:
        for certificate in banner.tls_certificates:
            by_ip.setdefault(certificate.ip, []).append(certificate)
    records: list[CertificateRecord] = []
    for ip, certificates in by_ip.items():
        hostname = _sot_hostname(site, ip) if site is not None else None
        records.extend(
            certificate_records_from_tls(certificates, site_id, sot_hostname=hostname)
        )
    return records


def cmd_cert_report(args: argparse.Namespace) -> int:
    try:
        warn_days = _parse_warn_days(args.warn_days)
    except ValueError as exc:
        return _input_error("--warn-days", args.warn_days, exc)
    try:
        now = _parse_report_time(getattr(args, "evaluation_time", None))
    except ValueError as exc:
        return _input_error("--evaluation-time", args.evaluation_time, exc)

    try:
        banners = [
            RawServiceBanner.from_dict(item)
            for item in _load_json_object_list(Path(args.fingerprints), key="banners")
        ]
    except INPUT_ERRORS as exc:
        return _input_error("--fingerprints", args.fingerprints, exc)

    site: Optional[Site] = None
    site_id = getattr(args, "site_id", None) or "unknown"
    if getattr(args, "snapshot", None) is not None:
        try:
            site = _load_single_site_snapshot(Path(args.snapshot), args)
        except INPUT_ERRORS as exc:
            return _input_error("--snapshot", args.snapshot, exc)
        site_id = site.site_id

    try:
        records = _certificate_records(banners, site_id, site)
    except INPUT_ERRORS as exc:
        return _input_error("--fingerprints", args.fingerprints, exc)
    findings = CertificateInventory().evaluate(records, now=now, warn_days=warn_days)
    _write_report_outputs(
        args,
        generate_certificate_json_report(findings, generated_at=now),
        generate_certificate_markdown_report(findings, generated_at=now),
    )
    return 0


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `cert-report` subcommand."""
    # 24. cert-report (Phase 14)
    cert_parser = subparsers.add_parser(
        "cert-report",
        help="Report TLS certificate expiry and weak-crypto issues from collected banner certificates (no network I/O).",
    )
    cert_parser.add_argument(
        "--fingerprints",
        type=Path,
        required=True,
        help='RawServiceBanner JSON list or {"banners": [...]} with tls_certificates (the fingerprint --banners format).',
    )
    cert_parser.add_argument(
        "--snapshot",
        type=Path,
        default=None,
        help="Optional Site JSON snapshot file or SnapshotStore directory for site ID and SoT hostnames.",
    )
    cert_parser.add_argument(
        "--site-id",
        type=str,
        default=None,
        help="Site ID to select from --snapshot, or to stamp on findings without one (default: unknown).",
    )
    cert_parser.add_argument(
        "--warn-days",
        type=str,
        default=",".join(str(days) for days in DEFAULT_WARN_DAYS),
        help="Comma-separated positive expiry warning thresholds in days (default: %(default)s).",
    )
    cert_parser.add_argument(
        "--evaluation-time",
        type=str,
        default=None,
        help="Reference ISO-8601 timestamp (naive means UTC; default: now).",
    )
    cert_parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Output path for the certificate report JSON.",
    )
    cert_parser.add_argument(
        "--output-md",
        type=Path,
        default=None,
        help="Output path for the certificate report Markdown.",
    )
    cert_parser.set_defaults(func=cmd_cert_report)
