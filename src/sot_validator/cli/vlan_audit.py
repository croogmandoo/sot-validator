"""Read-only VLAN consistency audit subcommand (`vlan-audit`)."""

from __future__ import annotations

import argparse
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import asdict
import json
from pathlib import Path
import re
from typing import Any, Optional

from sot_validator.cli._common import (
    INPUT_ERRORS,
    _input_error,
    _json_object_list,
    _load_single_site_snapshot,
    _write_report_outputs,
)
from sot_validator.discovery.router_tables import (
    RouterArpRecord,
    _coerce_datetime,
    _vlan_from_interface,
)
from sot_validator.models import Site
from sot_validator.quality import (
    VALID_SEVERITIES,
    VLAN_RULE_NAMES,
    DhcpScope,
    FdbObservation,
    VlanAuditResult,
    VlanConsistencyAuditor,
)
from sot_validator.reporting.generators import _escape_md_cell
from sot_validator.topology.fdb_mapper import FdbEntry, PortClassificationResult

_ROUTER_ARP_KEYS = ("arp", "records", "arp_records")
_DIGITS_ONLY = re.compile(r"[0-9]+")


def _read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _object_items(value: Any, *, field_name: str, path: Path) -> list[Mapping[str, Any]]:
    """Return ``value`` as a list of JSON objects, rejecting any other shape."""
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a JSON list in {path}")
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError(f"Expected JSON objects in {field_name!r} from {path}")
    return value


def _optional_str(data: Mapping[str, Any], key: str, default: Optional[str]) -> Optional[str]:
    value = data.get(key, default)
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{key} must be a string or null, got {value!r}")
    return value


def _check_vlan_digits(value: Any, field_name: str) -> None:
    """Reject a digit-string VLAN ID too long for ``int()``, which the auditor would crash on."""
    if value is None or isinstance(value, (bool, int)):
        return
    text = str(value).strip()
    if _DIGITS_ONLY.fullmatch(text):
        try:
            int(text)
        except ValueError as exc:
            raise ValueError(f"{field_name} is not a usable VLAN ID ({len(text)} digits)") from exc


def _is_vlan_value(value: Any, field_name: str = "vlan_ids item") -> bool:
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        return False
    _check_vlan_digits(value, field_name)
    return True


def _fdb_entry(data: Mapping[str, Any]) -> FdbEntry:
    vlan_id = data.get("vlan_id")
    if vlan_id is not None and not _is_vlan_value(vlan_id, "vlan_id"):
        raise ValueError(f"vlan_id must be a string, integer or null, got {vlan_id!r}")
    return FdbEntry.from_dict(data)


def _port_classification(data: Mapping[str, Any]) -> PortClassificationResult:
    """Build a classification, rejecting a non-list `vlan_ids` that `from_dict` would split."""
    vlan_ids = data.get("vlan_ids", [])
    if not isinstance(vlan_ids, list):
        raise ValueError(f"vlan_ids must be a JSON list, got {vlan_ids!r}")
    for value in vlan_ids:
        if not _is_vlan_value(value):
            raise ValueError(f"vlan_ids items must be strings or integers, got {value!r}")
    return PortClassificationResult.from_dict(data)


def _fdb_observation(data: Mapping[str, Any], path: Path) -> FdbObservation:
    source = _optional_str(data, "source", "fdb")
    if source is None:
        raise ValueError("source must be a string, got None")
    return FdbObservation(
        device_id=data["device_id"],
        observed_at=_coerce_datetime(data.get("observed_at"), "observed_at"),
        entries=[
            _fdb_entry(item)
            for item in _object_items(data.get("entries", []), field_name="entries", path=path)
        ],
        port_classifications=[
            _port_classification(item)
            for item in _object_items(
                data.get("port_classifications", []),
                field_name="port_classifications",
                path=path,
            )
        ],
        source=source,
    )


def _load_fdb(path: Path) -> list[FdbObservation]:
    """Load FDB observations, or a `map-ports` report grouped into one observation per device."""
    raw = _read_json(path)
    if isinstance(raw, Mapping) and "ports" in raw and "observations" not in raw:
        by_device: dict[str, list[PortClassificationResult]] = defaultdict(list)
        for item in _object_items(raw["ports"], field_name="ports", path=path):
            result = _port_classification(item)
            by_device[result.device_id].append(result)
        return [
            FdbObservation(device_id=device_id, port_classifications=by_device[device_id])
            for device_id in sorted(by_device)
        ]
    return [
        _fdb_observation(item, path)
        for item in _json_object_list(raw, key="observations", path=path)
    ]


def _load_router_arp(path: Path) -> list[RouterArpRecord]:
    raw = _read_json(path)
    key = "arp_records"
    if isinstance(raw, Mapping):
        found = [k for k in _ROUTER_ARP_KEYS if k in raw]
        if not found:
            raise ValueError(
                f"Expected a JSON list or one of the keys {', '.join(_ROUTER_ARP_KEYS)} in {path}"
            )
        key = found[0]
    records = [RouterArpRecord.from_dict(item) for item in _json_object_list(raw, key=key, path=path)]
    for record in records:
        _check_vlan_digits(record.vlan_id, "vlan_id")
        try:
            _vlan_from_interface(record.interface)
        except ValueError as exc:
            raise ValueError("interface has a VLAN number too long to read") from exc
    return records


def _check_site_vlans(site: Site) -> None:
    """Reject SoT VLAN, subnet and port VLAN IDs the auditor cannot compare."""
    for vlan in site.vlans:
        _check_vlan_digits(vlan.vlan_id, "VLAN vlan_id")
    for subnet in site.subnets:
        _check_vlan_digits(subnet.vlan_id, f"subnet {subnet.subnet_id!r} vlan_id")
    for device in site.devices:
        for port in device.ports:
            _check_vlan_digits(port.vlan_id, f"port {port.port_id!r} vlan_id")


def _load_dhcp_scopes(path: Path) -> list[DhcpScope]:
    return [
        DhcpScope(
            cidr=item["cidr"],
            source=_optional_str(item, "source", None),
            observed_at=_coerce_datetime(item.get("observed_at"), "observed_at"),
        )
        for item in _json_object_list(_read_json(path), key="scopes", path=path)
    ]


def _load_dhcp_expected(path: Path) -> list[str]:
    """Load DHCP-expected subnet ids/CIDRs from a `.json` list of strings or a text file."""
    if Path(path).suffix.lower() == ".json":
        raw = _read_json(path)
        if not isinstance(raw, list):
            raise ValueError(f"Expected a JSON list of strings in {path}")
        for item in raw:
            if not isinstance(item, str):
                raise ValueError(f"Expected only strings in {path}, got {item!r}")
        return list(raw)
    lines = (line.strip() for line in Path(path).read_text(encoding="utf-8-sig").splitlines())
    return [line for line in lines if line and not line.startswith("#")]


def _build_vlan_audit_report(result: VlanAuditResult) -> dict[str, Any]:
    severity_counts = {severity: 0 for severity in VALID_SEVERITIES}
    for finding in result.findings:
        severity_counts[finding.severity] += 1
    return {
        "site_id": result.site_id,
        "rules": [rule for rule in VLAN_RULE_NAMES if rule not in result.skipped_rules],
        "skipped_rules": dict(result.skipped_rules),
        "total_findings": len(result.findings),
        "severity_counts": severity_counts,
        "findings": [asdict(finding) for finding in result.findings],
    }


def _render_vlan_audit_markdown(report: dict[str, Any]) -> str:
    """Render the VLAN audit report as Markdown with a findings table in auditor order."""
    lines = [
        "# VLAN Consistency Audit",
        "",
        f"- Site: {_escape_md_cell(report['site_id'])}",
        f"- Total findings: {report['total_findings']}",
        "",
        "## Severity Counts",
        "",
    ]
    for severity, count in report["severity_counts"].items():
        lines.append(f"- {severity}: {count}")
    lines.extend(["", "## Skipped Rules", ""])
    if report["skipped_rules"]:
        for rule, reason in report["skipped_rules"].items():
            lines.append(f"- {_escape_md_cell(rule)}: {_escape_md_cell(reason)}")
    else:
        lines.append("None.")
    lines.extend(["", "## Findings", ""])
    if not report["findings"]:
        lines.append("No VLAN consistency findings.")
        return "\n".join(lines) + "\n"
    lines.append("| Rule | Severity | Record Type | Records | Message |")
    lines.append("|---|---|---|---|---|")
    for finding in report["findings"]:
        cells = (
            finding["rule"],
            finding["severity"],
            finding["record_type"],
            ", ".join(finding["record_ids"]),
            finding["message"],
        )
        lines.append("| " + " | ".join(_escape_md_cell(cell) for cell in cells) + " |")
    return "\n".join(lines) + "\n"


def cmd_vlan_audit(args: argparse.Namespace) -> int:
    try:
        site: Site = _load_single_site_snapshot(Path(args.snapshot), args)
        _check_site_vlans(site)
    except INPUT_ERRORS as exc:
        return _input_error("--snapshot", args.snapshot, exc)
    if args.site_id is not None and site.site_id != args.site_id:
        return _input_error(
            "--snapshot", args.snapshot, ValueError(f"site {args.site_id!r} not found")
        )

    fdb: list[FdbObservation] = []
    for path in args.fdb or []:
        try:
            fdb.extend(_load_fdb(Path(path)))
        except INPUT_ERRORS as exc:
            return _input_error("--fdb", path, exc)

    router_arp: list[RouterArpRecord] = []
    for path in args.router_arp or []:
        try:
            router_arp.extend(_load_router_arp(Path(path)))
        except INPUT_ERRORS as exc:
            return _input_error("--router-arp", path, exc)

    dhcp_scopes: list[DhcpScope] = []
    if args.dhcp_scopes is not None:
        try:
            dhcp_scopes = _load_dhcp_scopes(Path(args.dhcp_scopes))
        except INPUT_ERRORS as exc:
            return _input_error("--dhcp-scopes", args.dhcp_scopes, exc)

    dhcp_expected: list[str] = []
    if args.dhcp_expected is not None:
        try:
            dhcp_expected = _load_dhcp_expected(Path(args.dhcp_expected))
        except INPUT_ERRORS as exc:
            return _input_error("--dhcp-expected", args.dhcp_expected, exc)

    result = VlanConsistencyAuditor().audit(
        site,
        fdb=fdb,
        router_arp=router_arp,
        dhcp_scopes=dhcp_scopes,
        dhcp_expected_subnets=dhcp_expected,
    )
    report = _build_vlan_audit_report(result)
    _write_report_outputs(
        args,
        json.dumps(report, indent=2, sort_keys=True),
        _render_vlan_audit_markdown(report),
    )
    return 0


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `vlan-audit` subcommand."""
    # 30. vlan-audit
    vlan_parser = subparsers.add_parser(
        "vlan-audit",
        help="Audit one site's SoT VLANs against FDB, router ARP and DHCP scope JSON (read-only, local files only).",
    )
    vlan_parser.add_argument(
        "--snapshot",
        type=Path,
        required=True,
        help="Site JSON snapshot file or SnapshotStore directory.",
    )
    vlan_parser.add_argument(
        "--site-id",
        type=str,
        default=None,
        help="Site ID to select from --snapshot; an ID not in the snapshot is an error (default: the first site).",
    )
    vlan_parser.add_argument(
        "--fdb",
        type=Path,
        action="append",
        default=None,
        help=(
            'FDB observations JSON: a list or {"observations": [...]} of objects with device_id, '
            "observed_at, source, entries and port_classifications, or a `map-ports` report "
            '({"ports": [...]}) unchanged (repeatable).'
        ),
    )
    vlan_parser.add_argument(
        "--router-arp",
        type=Path,
        action="append",
        default=None,
        help=(
            'Router ARP records JSON: a list or {"arp": [...]}, {"records": [...]} or '
            '{"arp_records": [...]} (repeatable).'
        ),
    )
    vlan_parser.add_argument(
        "--dhcp-scopes",
        type=Path,
        default=None,
        help='DHCP scopes JSON: a list or {"scopes": [...]} of objects with cidr, source and observed_at.',
    )
    vlan_parser.add_argument(
        "--dhcp-expected",
        type=Path,
        default=None,
        help="Subnets expected to have DHCP: a .json list of subnet IDs/CIDRs, or a text file with one per line (# comments).",
    )
    vlan_parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Output path for the VLAN audit report JSON.",
    )
    vlan_parser.add_argument(
        "--output-md",
        type=Path,
        default=None,
        help="Output path for the VLAN audit report Markdown.",
    )
    vlan_parser.set_defaults(func=cmd_vlan_audit)
