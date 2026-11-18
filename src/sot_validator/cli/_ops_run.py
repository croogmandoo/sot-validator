"""Run lock, run manifest and exit-code wrapper shared by the `run` and `campaign` subcommands."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Optional
import uuid

from sot_validator.models import ValidationClassification, ValidationResult
from sot_validator.ops import (
    ExitCode,
    RunLock,
    RunLockHeld,
    RunManifest,
    SiteStatus,
    file_sha256,
    select_exit_code,
    tool_version,
)

DEFAULT_LOCK_FILENAME = ".sot-validator.lock"

EXIT_CODE_EPILOG = (
    "Exit codes: 0 all sites ok or skipped with no findings, 1 actionable stale or "
    "unreachable findings, 2 some sites failed, 3 the run failed as a whole or every "
    "site failed, 4 another run holds the lock and nothing was done."
)

ACTIONABLE_CLASSIFICATIONS = frozenset(
    {
        ValidationClassification.STALE_LIKELY_UNUSED,
        ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
    }
)


@dataclass
class OpsRunProgress:
    """Site statuses and report files a body has recorded so far."""

    sites: list[SiteStatus] = field(default_factory=list)
    output_files: list[str] = field(default_factory=list)


OpsRunBody = Callable[[OpsRunProgress], tuple[list[SiteStatus], list[str], bool]]


def add_lock_file_argument(parser: argparse.ArgumentParser) -> None:
    """Add the shared `--lock-file` option."""
    parser.add_argument(
        "--lock-file",
        type=Path,
        default=None,
        help=(
            f"Run lock file (default: <output-dir>/{DEFAULT_LOCK_FILENAME}). "
            "Exits 4 without doing anything if another run holds the lock."
        ),
    )


def has_actionable_findings(results: Iterable[ValidationResult]) -> bool:
    """True when any result is stale or unreachable."""
    return any(r.classification in ACTIONABLE_CLASSIFICATIONS for r in results)


def _error(message: str) -> None:
    print(f"error: {' '.join(message.split())}", file=sys.stderr)


def _failure_message(command: str, exc: BaseException) -> str:
    detail = str(exc).strip()
    name = type(exc).__name__
    return f"{command} failed: {name}: {detail}" if detail else f"{command} failed: {name}"


def run_with_ops_contract(
    command: str,
    args: argparse.Namespace,
    output_dir: Path,
    body: OpsRunBody,
) -> int:
    """Run `body` under the run lock, write `run_manifest.json` and return the exit code.

    `body` records site statuses and written report files on the progress
    object as it goes, so a whole-run failure still lists what it got done,
    and returns `(sites, output_files, actionable_findings)` when it completes.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    lock_path = (
        Path(args.lock_file)
        if getattr(args, "lock_file", None) is not None
        else output_dir / DEFAULT_LOCK_FILENAME
    )
    run_id = args.campaign_id if command == "campaign" else f"run-{uuid.uuid4().hex}"
    started_at = datetime.now(timezone.utc)
    lock = RunLock(lock_path)
    try:
        lock.acquire()
    except RunLockHeld as exc:
        _error(str(exc))
        return int(ExitCode.LOCK_HELD)
    except OSError as exc:
        _error(f"cannot open run lock {lock_path}: {exc.strerror or type(exc).__name__}")
        return int(ExitCode.FAILED)

    try:
        progress = OpsRunProgress()
        failure_reason: Optional[str] = None
        try:
            sites, output_files, actionable = body(progress)
        except Exception as exc:
            _error(_failure_message(command, exc))
            failure_reason = type(exc).__name__
            sites, output_files, actionable = progress.sites, progress.output_files, False

        config_path = getattr(args, "fleet_config_path", None)
        try:
            RunManifest(
                run_id=run_id,
                started_at=started_at,
                finished_at=datetime.now(timezone.utc),
                tool_version=tool_version(),
                config_sha256=file_sha256(config_path) if config_path else None,
                sites=list(sites),
                output_files=[str(path) for path in output_files],
                failure_reason=failure_reason,
            ).write(output_dir)
        except Exception as exc:
            _error(_failure_message(command, exc))
            return int(ExitCode.FAILED)
    finally:
        lock.release()

    return int(
        select_exit_code(
            sites,
            actionable_findings=actionable,
            run_failed=failure_reason is not None,
        )
    )
