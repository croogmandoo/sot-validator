"""Offline MAC enrichment package: IEEE OUI registry and MAC classification."""

from __future__ import annotations

from sot_validator.enrichment.oui import (
    OuiMatch,
    OuiRegistry,
    classify_mac,
    is_locally_administered,
    is_multicast,
    is_randomized_mac,
    load_oui_directory,
    mac_annotation,
)

__all__ = [
    "OuiMatch",
    "OuiRegistry",
    "classify_mac",
    "is_locally_administered",
    "is_multicast",
    "is_randomized_mac",
    "load_oui_directory",
    "mac_annotation",
]
