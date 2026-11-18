"""Synthetic fleet snapshot writer subcommand (`synth-fleet`)."""

from __future__ import annotations

import argparse
from pathlib import Path

from sot_validator.cli._common import _input_error
from sot_validator.cli._config import config_error
from sot_validator.testing import SyntheticFleetGenerator


def cmd_synth_fleet(args: argparse.Namespace) -> int:
    try:
        fleet = SyntheticFleetGenerator(
            seed=args.seed,
            sites=args.sites,
            subnets_per_site=args.subnets_per_site,
            hosts_per_subnet=args.hosts_per_subnet,
        ).generate()
    except ValueError as exc:
        return config_error(str(exc))

    output_dir = Path(args.output_dir)
    sites_dir = output_dir / "sites"
    try:
        sites_dir.mkdir(parents=True, exist_ok=True)
        for site in fleet.sites:
            (sites_dir / f"{site.site_id}.json").write_text(site.to_json(indent=2), encoding="utf-8")
    except OSError as exc:
        return _input_error("--output-dir", output_dir, exc)
    print(f"synth-fleet: {len(fleet.sites)} site(s) written to {sites_dir}")
    return 0


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `synth-fleet` subcommand."""
    # 30. synth-fleet
    synth_parser = subparsers.add_parser(
        "synth-fleet",
        help="Write a seeded, deterministic synthetic fleet as a snapshot folder (no network I/O).",
    )
    synth_parser.add_argument(
        "--seed",
        type=int,
        required=True,
        help="Generator seed; the same seed and sizes always write identical files.",
    )
    synth_parser.add_argument(
        "--sites",
        type=int,
        default=100,
        help="Number of sites, 1 to 254 (default: %(default)s).",
    )
    synth_parser.add_argument(
        "--subnets-per-site",
        type=int,
        default=10,
        help="Number of /24 subnets per site, 1 to 256 (default: %(default)s).",
    )
    synth_parser.add_argument(
        "--hosts-per-subnet",
        type=int,
        default=60,
        help="Number of hosts per subnet, 0 to 245 (default: %(default)s).",
    )
    synth_parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Snapshot folder; sites are written to <output-dir>/sites/<site_id>.json (created if missing).",
    )
    synth_parser.set_defaults(func=cmd_synth_fleet)
