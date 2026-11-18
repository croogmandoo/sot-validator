"""Opt-in OUI vendor annotation and randomised-MAC exclusion for reconciliation reports."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Optional

from sot_validator.enrichment import OuiRegistry, is_randomized_mac, mac_annotation

OUI_ANNOTATION_KEYS: tuple[str, ...] = ("observed_mac_vendor", "observed_mac_class")
EXCLUDABLE_DISCREPANCY_TYPES: frozenset[str] = frozenset(
    {"UNTRACKED_VM", "UNTRACKED_IP", "UNTRACKED_DEVICE"}
)


def discrepancy_annotation(
    registry: OuiRegistry, observed_mac: Optional[str]
) -> dict[str, Optional[str]]:
    """Return the ``observed_mac_vendor``/``observed_mac_class`` values (both None without a MAC)."""
    if observed_mac is None:
        return {key: None for key in OUI_ANNOTATION_KEYS}
    annotation = mac_annotation(registry, observed_mac)
    return {
        "observed_mac_vendor": annotation["vendor"],
        "observed_mac_class": annotation["class"],
    }


def discrepancy_dict(record: Any, registry: Optional[OuiRegistry]) -> dict[str, Any]:
    """Serialise a discrepancy, appending the annotation keys when ``registry`` is set."""
    data = record.to_dict()
    if registry is not None:
        data.update(discrepancy_annotation(registry, record.observed_mac))
    return data


def discrepancy_csv_cells(record: Any, registry: Optional[OuiRegistry]) -> list[str]:
    """Return the extra CSV cells for a discrepancy (none when ``registry`` is None)."""
    if registry is None:
        return []
    annotation = discrepancy_annotation(registry, record.observed_mac)
    return [annotation[key] or "" for key in OUI_ANNOTATION_KEYS]


def partition_randomized(
    records: Iterable[Any], registry: Optional[OuiRegistry]
) -> tuple[list[Any], list[Any]]:
    """Split untracked discrepancies with a randomised MAC from the counted ones."""
    lookup_registry = registry or OuiRegistry()
    kept: list[Any] = []
    excluded: list[Any] = []
    for record in records:
        if (
            record.discrepancy_type.value in EXCLUDABLE_DISCREPANCY_TYPES
            and record.observed_mac is not None
            and is_randomized_mac(lookup_registry, record.observed_mac)
        ):
            excluded.append(record)
        else:
            kept.append(record)
    return kept, excluded
