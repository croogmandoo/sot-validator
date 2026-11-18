"""Weekly change digest subcommand (`digest`): render two runs' changes, deliver with `--send`."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Optional
import urllib.parse

from sot_validator.campaign.digest_sinks import (
    DigestDeliveryResult,
    DigestSink,
    SmtpDigestSink,
    WebhookDigestSink,
)
from sot_validator.cli._common import (
    INPUT_ERRORS,
    _input_error,
    _load_json_object_list,
    _load_validation_results_file,
)
from sot_validator.cli._config import config_error, fleet_config
from sot_validator.cli.fleet import _load_previous
from sot_validator.config import AppConfig, ConfigError, DigestWebhookConfig
from sot_validator.discovery.monitor import SEVERITY_LEVELS as DRIFT_SEVERITIES
from sot_validator.quality.checks import VALID_SEVERITIES as QUALITY_SEVERITIES
from sot_validator.reporting import (
    ChangeDigest,
    DigestBuilder,
    DigestRunInput,
    render_digest_html,
    render_digest_markdown,
    render_digest_text,
)
from sot_validator.reporting.digest import DEFAULT_TOP_N, SEND_POLICIES

OUTPUT_FILES: tuple[str, ...] = ("digest.txt", "digest.md", "digest.html", "digest.json")


@dataclass(frozen=True)
class _QualityRecord:
    """The fields the digest builder reads from a quality finding."""

    site_id: str
    finding_id: str
    severity: str
    rule: str
    message: str


@dataclass(frozen=True)
class _CertificateRecord:
    """The fields the digest builder reads from a certificate finding."""

    site_id: str
    ip: str
    port: int
    subject_cn: Optional[str]
    days_remaining: Optional[int]
    issues: tuple[str, ...]


@dataclass(frozen=True)
class _DriftRecord:
    """The fields the digest builder reads from a drift event."""

    site_id: str
    event_id: str
    severity: str
    summary: str


def _required_str(item: Mapping[str, Any], key: str) -> str:
    value = item[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string, got {value!r}")
    return value


def _choice(item: Mapping[str, Any], key: str, allowed: tuple[str, ...]) -> str:
    value = item[key]
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{key} must be one of {allowed}, got {value!r}")
    return value


def _optional_str(item: Mapping[str, Any], key: str) -> Optional[str]:
    value = item.get(key)
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{key} must be a string or null, got {value!r}")
    return value


def _load_quality(path: Path) -> list[_QualityRecord]:
    return [
        _QualityRecord(
            site_id=_required_str(item, "site_id"),
            finding_id=_required_str(item, "finding_id"),
            severity=_choice(item, "severity", QUALITY_SEVERITIES),
            rule=_required_str(item, "rule"),
            message=_required_str(item, "message"),
        )
        for item in _load_json_object_list(path, key="findings")
    ]


def _load_certificates(path: Path) -> list[_CertificateRecord]:
    records: list[_CertificateRecord] = []
    for item in _load_json_object_list(path, key="findings"):
        site_id = _required_str(item, "site_id")
        ip = _required_str(item, "ip")
        port = item["port"]
        if isinstance(port, bool) or not isinstance(port, int):
            raise ValueError(f"port must be an integer, got {port!r}")
        issues = item["issues"]
        if not isinstance(issues, list) or not all(isinstance(flag, str) for flag in issues):
            raise ValueError(f"issues must be a list of strings, got {issues!r}")
        days = item.get("days_remaining")
        if days is not None and (isinstance(days, bool) or not isinstance(days, int)):
            raise ValueError(f"days_remaining must be an integer or null, got {days!r}")
        records.append(
            _CertificateRecord(
                site_id=site_id,
                ip=ip,
                port=port,
                subject_cn=_optional_str(item, "subject_cn"),
                days_remaining=days,
                issues=tuple(issues),
            )
        )
    return records


def _load_drift(path: Path) -> list[_DriftRecord]:
    return [
        _DriftRecord(
            site_id=_required_str(item, "site_id"),
            event_id=_required_str(item, "event_id"),
            severity=_choice(item, "severity", DRIFT_SEVERITIES),
            summary=_required_str(item, "summary"),
        )
        for item in _load_json_object_list(path, key="events")
    ]


# (flag suffix, DigestRunInput field, loader) in DIGEST_CATEGORIES order.
INPUT_PAIRS: tuple[tuple[str, str, Callable[[Path], list[Any]]], ...] = (
    ("results", "results", _load_validation_results_file),
    ("quality", "quality_findings", _load_quality),
    ("certs", "certificate_findings", _load_certificates),
    ("fleet", "scorecards", _load_previous),
    ("drift", "drift_events", _load_drift),
)


def _load_inputs(args: argparse.Namespace) -> tuple[DigestRunInput, DigestRunInput] | int:
    """Load every given input file, or print one `error:` line and return exit code 2."""
    sides: dict[str, dict[str, list[Any]]] = {"previous": {}, "current": {}}
    for suffix, field_name, loader in INPUT_PAIRS:
        for side, values in sides.items():
            path = getattr(args, f"{side}_{suffix}")
            if path is None:
                continue
            try:
                values[field_name] = loader(path)
            except INPUT_ERRORS as exc:
                return _input_error(f"--{side}-{suffix}", path, exc)
    return DigestRunInput(**sides["previous"]), DigestRunInput(**sides["current"])


def _write_outputs(digest: ChangeDigest, output_dir: Optional[Path]) -> Optional[int]:
    """Write the four renders when `--output-dir` is given; return exit code 2 on failure."""
    if output_dir is None:
        return None
    texts = (
        render_digest_text(digest),
        render_digest_markdown(digest),
        render_digest_html(digest),
        json.dumps(digest.to_dict(), indent=2, sort_keys=True) + "\n",
    )
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        for name, text in zip(OUTPUT_FILES, texts):
            (output_dir / name).write_text(text, encoding="utf-8")
    except OSError as exc:
        return _input_error("--output-dir", output_dir, exc)
    return None


def _smtp_sink(config: AppConfig) -> SmtpDigestSink | str | None:
    """Build the SMTP sink (no secret is read), or return the error message."""
    smtp = config.digest.smtp
    if smtp is None:
        return None
    try:
        return SmtpDigestSink(
            smtp.host,
            smtp.port,
            smtp.sender,
            smtp.recipients,
            username_env=None if smtp.username is None else smtp.username.variable,
            password_env=None if smtp.password is None else smtp.password.variable,
            starttls=smtp.starttls,
            allow_insecure_localhost=smtp.allow_insecure_localhost,
            timeout_seconds=smtp.timeout_seconds,
            subject=smtp.subject,
        )
    except ValueError as exc:
        return f"{config.source_path}: [digest.smtp]: {exc}"


def _webhook_sink(hook: DigestWebhookConfig) -> WebhookDigestSink | str:
    """Reveal and check one webhook URL; errors name the table, key and variable only."""
    secret = hook.url
    prefix = f"{secret.source}: [{secret.table}] {secret.key}: environment variable {secret.variable}"
    try:
        url = secret.reveal()
    except ConfigError as exc:
        return str(exc)
    if any(ch.isspace() or not ch.isprintable() for ch in url):
        return f"{prefix} contains whitespace or control characters"
    try:
        parts = urllib.parse.urlsplit(url)
        valid = parts.scheme.lower() in ("http", "https") and bool(parts.hostname)
    except ValueError:
        valid = False
    if not valid:
        return f"{prefix} is not an http or https URL with a host"
    try:
        return WebhookDigestSink(url, timeout_seconds=hook.timeout_seconds, name=hook.name)
    except ValueError:
        return f"{prefix} was rejected as a webhook URL"


def _print_dry_run(
    config: AppConfig,
    smtp: Optional[SmtpDigestSink],
    digest: ChangeDigest,
    policy: str,
) -> None:
    print("digest: dry run, nothing is sent")
    if smtp is not None:
        print(
            f"target {smtp.kind} {smtp.name} {smtp.destination} "
            f"sender={smtp.sender} recipients={', '.join(smtp.recipients)}"
        )
    for hook in config.digest.webhooks:
        print(f"target webhook {hook.name} url=${{env:{hook.url.variable}}}")
    if digest.should_send(policy):
        print(f"policy: {policy}: would send")
    else:
        print(f"policy: {policy}: nothing to send (no new items)")
    if smtp is not None:
        print(f"subject: {smtp.subject}")
    print("---")
    print(render_digest_text(digest))


def _result_line(result: DigestDeliveryResult) -> str:
    line = f"{result.name} {result.kind} {result.status} {result.destination}"
    if result.status != "sent":
        line += f": {' '.join(str(result.detail).split())}"
    return line


def _send(args: argparse.Namespace, config: AppConfig, digest: ChangeDigest) -> int:
    smtp = _smtp_sink(config)
    if isinstance(smtp, str):
        return config_error(smtp)
    policy = args.policy or config.digest.policy
    if args.dry_run:
        failed = _write_outputs(digest, args.output_dir)
        if failed is not None:
            return failed
        _print_dry_run(config, smtp, digest, policy)
        return 0
    if not digest.should_send(policy):
        failed = _write_outputs(digest, args.output_dir)
        if failed is not None:
            return failed
        print(f"digest: nothing to send (policy {policy}, no new items)")
        return 0

    sinks: list[DigestSink] = [] if smtp is None else [smtp]
    # Every webhook URL is revealed and checked before any target is contacted.
    for hook in config.digest.webhooks:
        sink = _webhook_sink(hook)
        if isinstance(sink, str):
            return config_error(sink)
        sinks.append(sink)

    failed = _write_outputs(digest, args.output_dir)
    if failed is not None:
        return failed
    results = [sink.send(digest) for sink in sinks]
    for result in results:
        print(_result_line(result))
    return 0 if all(result.status == "sent" for result in results) else 1


def cmd_digest(args: argparse.Namespace) -> int:
    if args.dry_run and not args.send:
        return config_error("--dry-run is only valid with --send")
    if args.top_n < 1:
        return config_error(f"--top-n must be >= 1, got {args.top_n}")
    config = fleet_config(args) if args.send else None
    if args.send:
        if config is None:
            return config_error("digest --send needs the global --config with a [digest] section")
        if config.digest.smtp is None and not config.digest.webhooks:
            return config_error(
                f"{config.source_path}: digest --send needs [digest.smtp] or [[digest.webhooks]]"
            )
    if not any(
        getattr(args, f"previous_{suffix}") is not None
        and getattr(args, f"current_{suffix}") is not None
        for suffix, _, _ in INPUT_PAIRS
    ):
        return config_error("digest needs at least one complete --previous-*/--current-* pair")

    loaded = _load_inputs(args)
    if isinstance(loaded, int):
        return loaded
    digest = DigestBuilder(*loaded, top_n=args.top_n).build()

    if config is not None:
        return _send(args, config, digest)
    failed = _write_outputs(digest, args.output_dir)
    if failed is not None:
        return failed
    print(render_digest_text(digest))
    return 0


_INPUT_HELP: dict[str, str] = {
    "results": "validation_results.json (stale records)",
    "quality": "JSON written by `quality --output-json` (data-quality errors)",
    "certs": "JSON written by `cert-report --output-json` (certificates)",
    "fleet": "fleet-summary.json (site health drops)",
    "drift": "JSON written by `diff-scans --output-json` (discovery drift)",
}


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `digest` subcommand."""
    # 27. digest
    digest_parser = subparsers.add_parser(
        "digest",
        help=(
            "Render the weekly change digest between a previous and a current run; "
            "deliver it over SMTP / webhook only with --send."
        ),
    )
    for suffix, _, _ in INPUT_PAIRS:
        for side in ("previous", "current"):
            digest_parser.add_argument(
                f"--{side}-{suffix}",
                type=Path,
                default=None,
                help=f"{side.capitalize()} run: {_INPUT_HELP[suffix]}.",
            )
    digest_parser.add_argument(
        "--top-n",
        type=int,
        default=DEFAULT_TOP_N,
        help=f"New items listed per category (default: {DEFAULT_TOP_N}).",
    )
    digest_parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Also write digest.txt, digest.md, digest.html and digest.json here (created if missing).",
    )
    digest_parser.add_argument(
        "--send",
        action="store_true",
        help="Deliver to the [digest.smtp] / [[digest.webhooks]] targets of the global --config.",
    )
    digest_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="With --send: print the targets, policy decision and message; read no secret, open no socket.",
    )
    digest_parser.add_argument(
        "--policy",
        choices=SEND_POLICIES,
        default=None,
        help="Send policy for --send (default: [digest] policy, else on_change).",
    )
    digest_parser.set_defaults(func=cmd_digest)
