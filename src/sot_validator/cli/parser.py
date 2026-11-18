"""Top-level `sot-validator` argparse parser, subcommand registration order, and `main()`."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
from typing import Optional

from sot_validator.cli import (
    campaign,
    cert_report,
    core,
    discovery,
    firmware,
    history,
    itsm,
    migration,
    ports,
    quality,
    remediation,
    topology,
    ups,
    workbench,
)
from sot_validator.cli._config import config_error, threshold_conflict
from sot_validator.config import ConfigError, load_config

# Registration order is the order subcommands appear in the top-level `--help`.
COMMAND_MODULES = (
    core,
    history,
    remediation,
    campaign,
    ports,
    migration,
    ups,
    itsm,
    discovery,
    workbench,
    topology,
    quality,
    cert_report,
    firmware,
)


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argparse CLI parser for `sot-validator`."""
    parser = argparse.ArgumentParser(
        prog="sot-validator",
        description="Read-only batch inventory validation system for legacy Network Source of Truth.",
    )
    parser.add_argument(
        "--config",
        dest="fleet_config_path",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Fleet TOML configuration file whose [policy] and [[sites]] tables supply defaults "
            "for subcommands; explicit flags always win. Give it before the subcommand."
        ),
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    for module in COMMAND_MODULES:
        module.register(subparsers)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entrypoint returning an exit code (0 on success)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "func", None)
    if handler is None:
        parser.print_help()
        return 2
    if args.fleet_config_path is not None:
        # Loaded once here, before dispatch; a bad file stops every subcommand with exit 2.
        try:
            args.fleet_config = load_config(args.fleet_config_path)
        except ConfigError as exc:
            return config_error(str(exc))
        conflict = threshold_conflict(args)
        if conflict is not None:
            return config_error(conflict)
    return int(handler(args))
