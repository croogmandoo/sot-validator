"""Unified CLI runner for sot-validator (`extract`, `validate`, `report`, `run`, `history`, `quarantine`, `remediate`, `reconcile`, `campaign`, `preflight`, `reclaim-ports`, `export-modern-sot`, `parity-check`, `ups-health`, `itsm`, `discover`, `serve`, `curate`, `topology`, `fingerprint`, `map-ports`, `diff-scans`, `quality`, `cert-report`, `firmware-check`, `oui lookup`, `audit verify`, `audit head`, `power blast-radius`, `power risk`)."""

from __future__ import annotations

from sot_validator.cli.parser import build_parser, main
from sot_validator.cli.workbench import _workbench_url

__all__ = ["_workbench_url", "build_parser", "main"]
