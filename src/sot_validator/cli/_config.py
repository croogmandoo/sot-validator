"""Global `--config` helpers: precedence resolution (flag > config file > built-in default)."""

from __future__ import annotations

import argparse
import sys
from typing import Any, Optional

from sot_validator.config import AppConfig

# Built-in defaults for the flags that default to None so `--config` can tell "not given".
DEFAULT_ACTIVE_WITHIN_DAYS = 7.0
DEFAULT_STALE_AFTER_DAYS = 30.0
DEFAULT_HISTORY_MIN_CONSECUTIVE_STALE = 0
DEFAULT_QUARANTINE_MIN_STALE_RUNS = 3
DEFAULT_DISCOVER_MAX_CONCURRENCY = 128


def fleet_config(args: argparse.Namespace) -> Optional[AppConfig]:
    """Return the `AppConfig` loaded by `main()` from the global `--config`, if any."""
    return getattr(args, "fleet_config", None)


def resolve_policy_value(
    args: argparse.Namespace, attr: str, policy_key: str, builtin: Any
) -> Any:
    """Resolve one wired flag: explicit value, else `[policy] <policy_key>`, else `builtin`."""
    value = getattr(args, attr, None)
    if value is not None:
        return value
    config = fleet_config(args)
    if config is not None:
        return getattr(config.policy, policy_key)
    return builtin


def resolve_recency_thresholds(args: argparse.Namespace) -> tuple[float, float]:
    """Return `(active_within_days, stale_after_days)` for the classification engine."""
    active = resolve_policy_value(
        args, "active_within_days", "last_seen_active_within_days", DEFAULT_ACTIVE_WITHIN_DAYS
    )
    stale = resolve_policy_value(
        args, "stale_after_days", "last_seen_stale_after_days", DEFAULT_STALE_AFTER_DAYS
    )
    return float(active), float(stale)


def threshold_conflict(args: argparse.Namespace) -> Optional[str]:
    """Describe an active > stale conflict under `--config`, or return None."""
    config = fleet_config(args)
    if config is None or not hasattr(args, "active_within_days"):
        return None
    active, stale = resolve_recency_thresholds(args)
    if active <= stale:
        return None
    return (
        f"active-within-days {active} is greater than stale-after-days {stale} "
        f"(resolved from flags and --config {config.source_path})"
    )


def default_site_ids(args: argparse.Namespace) -> Optional[list[str]]:
    """Return the `[[sites]]` site_id list when `--site-ids` / `--all-sites` are both absent."""
    config = fleet_config(args)
    if config is None:
        return None
    if getattr(args, "all_sites", False) or getattr(args, "site_ids", None) is not None:
        return None
    return [site.site_id for site in config.sites]


def config_error(message: str) -> int:
    """Print a one-line `error: <message>` to stderr and return exit code 2."""
    print(f"error: {' '.join(str(message).split())}", file=sys.stderr)
    return 2
