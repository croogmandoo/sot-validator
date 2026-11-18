"""Global `--log-format` / `--log-level` / `--metrics-file` wiring used by `main()`."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
import sys
import time
from typing import Any

from sot_validator.observability import (
    MetricsRegistry,
    configure_logging,
    register_starter_metrics,
    write_textfile,
)
from sot_validator.ops import ExitCode

LOG_FORMATS = ("text", "json")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
DEFAULT_LOG_FORMAT = "text"
DEFAULT_LOG_LEVEL = "WARNING"
# Handler exit codes that count as a successful run for the last-success gauge.
SUCCESS_EXIT_CODES = (int(ExitCode.SUCCESS), int(ExitCode.ACTIONABLE))


def add_observability_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the root `--log-format`, `--log-level` and `--metrics-file` flags."""
    parser.add_argument(
        "--log-format",
        dest="global_log_format",
        choices=list(LOG_FORMATS),
        default=None,
        help=(
            "Log line format written to stderr (default: text). Logging is only configured "
            "when --log-format or --log-level is given. Give it before the subcommand."
        ),
    )
    parser.add_argument(
        "--log-level",
        dest="global_log_level",
        type=str.upper,
        choices=list(LOG_LEVELS),
        default=None,
        help="Minimum log level, case-insensitive (default: WARNING). Give it before the subcommand.",
    )
    parser.add_argument(
        "--metrics-file",
        dest="global_metrics_file",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Write Prometheus textfile run metrics atomically to PATH when the command exits "
            "(for node_exporter's textfile collector). Give it before the subcommand."
        ),
    )


def configure_cli_logging(args: argparse.Namespace) -> None:
    """Configure observability logging once, only when a log flag was given."""
    fmt = args.global_log_format
    level = args.global_log_level
    if fmt is None and level is None:
        return
    configure_logging(level or DEFAULT_LOG_LEVEL, fmt or DEFAULT_LOG_FORMAT)


def _record_ops_progress(metrics: dict[str, Any], args: argparse.Namespace) -> None:
    progress = getattr(args, "ops_progress", None)
    if progress is None:
        return
    for site in progress.sites:
        metrics["sot_site_status"].set(1, site=site.site_id, status=site.status)
    for result in progress.results:
        metrics["sot_records_total"].inc(
            site=result.site_id, classification=result.classification.value
        )


def _write_metrics(path: Path, registry: MetricsRegistry) -> bool:
    try:
        write_textfile(path, registry)
    except OSError as exc:
        detail = exc.strerror or type(exc).__name__
        message = f"cannot write metrics file {path}: {detail}"
        print(f"error: {' '.join(message.split())}", file=sys.stderr)
        return False
    return True


def dispatch(handler: Callable[[argparse.Namespace], Any], args: argparse.Namespace) -> int:
    """Run `handler`, writing `--metrics-file` once at exit when it was given."""
    path = args.global_metrics_file
    if path is None:
        return int(handler(args))
    registry = MetricsRegistry()
    metrics = register_starter_metrics(registry)
    started = time.monotonic()
    try:
        rc = int(handler(args))
    except BaseException:
        metrics["sot_run_duration_seconds"].set(time.monotonic() - started)
        _record_ops_progress(metrics, args)
        _write_metrics(path, registry)
        raise
    metrics["sot_run_duration_seconds"].set(time.monotonic() - started)
    if rc in SUCCESS_EXIT_CODES:
        metrics["sot_run_last_success_timestamp_seconds"].set(time.time())
    _record_ops_progress(metrics, args)
    if not _write_metrics(path, registry) and rc == int(ExitCode.SUCCESS):
        return int(ExitCode.FAILED)
    return rc
