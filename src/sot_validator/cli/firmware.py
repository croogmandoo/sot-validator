"""Firmware lifecycle compliance subcommand (`firmware-check`)."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from sot_validator.cli._common import (
    INPUT_ERRORS,
    _input_error,
    _load_single_site_snapshot,
    _parse_report_time,
    _write_report_outputs,
)
from sot_validator.lifecycle import (
    FirmwareComplianceChecker,
    FirmwareObservation,
    LifecycleCatalog,
    generate_firmware_json_report,
    generate_firmware_markdown_report,
)
from sot_validator.models import Site
from sot_validator.signals.management import (
    SNMPV2_MIB_SYS_DESCR,
    FixtureManagementTransport,
)


class _SysDescrError(ValueError):
    """A fixture sysDescr value that is not a string."""


def _sys_descr(
    transport: Optional[FixtureManagementTransport], ip: Optional[str]
) -> Optional[str]:
    """Return the fixture sysDescr for an IP, or None when there is no fixture, IP or match."""
    if transport is None or not isinstance(ip, str) or not ip.strip():
        return None
    oids = transport.query_snmp(ip)
    if oids is None:
        return None
    value = oids.get(SNMPV2_MIB_SYS_DESCR)
    if value is not None and not isinstance(value, str):
        raise _SysDescrError(f"sysDescr for {ip} is not a string")
    return value if value and value.strip() else None


def _site_observations(
    site: Site, transport: Optional[FixtureManagementTransport]
) -> list[FirmwareObservation]:
    """Observe every network device, plus equipment that has a fixture sysDescr on one of its IPs."""
    observations = [
        FirmwareObservation(
            site_id=site.site_id,
            device=device.hostname,
            ip=device.management_ip,
            sys_descr=_sys_descr(transport, device.management_ip),
        )
        for device in site.devices
    ]
    for equipment in site.equipment:
        for ip in equipment.assigned_ips:
            sys_descr = _sys_descr(transport, ip)
            if sys_descr is not None:
                observations.append(
                    FirmwareObservation(
                        site_id=site.site_id,
                        device=equipment.name,
                        ip=ip,
                        sys_descr=sys_descr,
                    )
                )
                break
    return observations


def cmd_firmware_check(args: argparse.Namespace) -> int:
    try:
        now = _parse_report_time(getattr(args, "evaluation_time", None))
    except ValueError as exc:
        return _input_error("--evaluation-time", args.evaluation_time, exc)
    try:
        catalog = LifecycleCatalog.load(Path(args.catalog))
    except INPUT_ERRORS as exc:
        return _input_error("--catalog", args.catalog, exc)

    transport: Optional[FixtureManagementTransport] = None
    if getattr(args, "snmp_fixture", None) is not None:
        try:
            transport = FixtureManagementTransport.from_file(args.snmp_fixture)
        except INPUT_ERRORS as exc:
            return _input_error("--snmp-fixture", args.snmp_fixture, exc)

    observations: list[FirmwareObservation] = []
    for snapshot in args.snapshot:
        try:
            site = _load_single_site_snapshot(Path(snapshot), args)
            observations.extend(_site_observations(site, transport))
        except _SysDescrError as exc:
            return _input_error("--snmp-fixture", args.snmp_fixture, exc)
        except INPUT_ERRORS as exc:
            return _input_error("--snapshot", snapshot, exc)

    findings = FirmwareComplianceChecker(catalog).evaluate(observations, now=now)
    _write_report_outputs(
        args,
        generate_firmware_json_report(findings, generated_at=now),
        generate_firmware_markdown_report(findings, generated_at=now),
    )
    return 0


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `firmware-check` subcommand."""
    # 25. firmware-check (Phase 14)
    firmware_parser = subparsers.add_parser(
        "firmware-check",
        help="Check device firmware (sysDescr from an SNMP fixture) against a lifecycle catalog (no network I/O).",
    )
    firmware_parser.add_argument(
        "--snapshot",
        type=Path,
        action="append",
        required=True,
        help="Site JSON snapshot file or SnapshotStore directory (repeatable).",
    )
    firmware_parser.add_argument(
        "--catalog",
        type=Path,
        required=True,
        help="Lifecycle catalog JSON of firmware baselines and end-of-sale / end-of-support dates.",
    )
    firmware_parser.add_argument(
        "--snmp-fixture",
        type=Path,
        default=None,
        help="Optional SNMP fixture JSON supplying sysDescr by IP; without it every device is unparsed.",
    )
    firmware_parser.add_argument(
        "--evaluation-time",
        type=str,
        default=None,
        help="Reference ISO-8601 timestamp (naive means UTC; default: now).",
    )
    firmware_parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Output path for the firmware report JSON.",
    )
    firmware_parser.add_argument(
        "--output-md",
        type=Path,
        default=None,
        help="Output path for the firmware report Markdown.",
    )
    firmware_parser.set_defaults(func=cmd_firmware_check)
