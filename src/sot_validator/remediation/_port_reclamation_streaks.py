"""Streak, SNMP OID and PoE lookup helpers mixed into ``ExtremePortReclamationPlanner``."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Optional

from sot_validator.history.ledger import HistoryStore, ItemStreakSummary
from sot_validator.models import Port, Site, ValidationClassification
from sot_validator.remediation._port_reclamation_common import (
    _MILLIWATT_PATTERN,
    _PORT_TRAILING_DIGITS_PATTERN,
    _SLOT_PORT_PATTERN,
    _clean_optional_str,
)
from sot_validator.signals.management import (
    EXTREME_POE_PORT_MEASURED_POWER_PREFIX,
    EXTREME_POE_PORT_OPERATOR_LIMIT_PREFIX,
)
from sot_validator.signals.port_state import _WATTAGE_PATTERN


class _PlannerLookupMixin:
    """Streak, SNMP OID and PoE lookup helpers for ``ExtremePortReclamationPlanner``."""

    @staticmethod
    def _build_streak_lookup(
        *,
        streaks: Optional[
            Sequence[ItemStreakSummary | Mapping[str, Any]] | Mapping[str, Any]
        ],
        history_store: Optional[HistoryStore],
    ) -> dict[str, tuple[int, float, Optional[ValidationClassification]]]:
        lookup: dict[
            str, tuple[int, float, Optional[ValidationClassification]]
        ] = {}

        def _register_entry(
            key: str,
            runs: int,
            days: float,
            cls_val: Optional[ValidationClassification],
        ) -> None:
            cleaned = key.strip()
            if cleaned:
                lookup[cleaned] = (runs, days, cls_val)

        def _ingest_item(key_hint: Optional[str], item: Any) -> None:
            if isinstance(item, ItemStreakSummary):
                entry = (
                    item.consecutive_stale_runs,
                    item.stale_duration_days,
                    item.current_classification,
                )
                _register_entry(item.item_id, *entry)
                _register_entry(f"{item.item_type}:{item.item_id}", *entry)
                if item.name:
                    _register_entry(item.name, *entry)
                if key_hint:
                    _register_entry(key_hint, *entry)
            elif isinstance(item, Mapping):
                runs = int(
                    item.get(
                        "consecutive_stale_runs",
                        item.get("inactive_runs", 0),
                    )
                )
                days = float(
                    item.get(
                        "stale_duration_days",
                        item.get("inactive_days", 0.0),
                    )
                )
                raw_cls = item.get(
                    "current_classification", item.get("classification")
                )
                cls_val: Optional[ValidationClassification] = None
                if raw_cls is not None:
                    cls_val = (
                        raw_cls
                        if isinstance(raw_cls, ValidationClassification)
                        else ValidationClassification(raw_cls)
                    )
                item_id = _clean_optional_str(
                    item.get("item_id") or item.get("port_id") or key_hint
                )
                if item_id:
                    _register_entry(item_id, runs, days, cls_val)
                name = _clean_optional_str(
                    item.get("name") or item.get("port_name")
                )
                if name:
                    _register_entry(name, runs, days, cls_val)
                if key_hint:
                    _register_entry(key_hint, runs, days, cls_val)
            elif (
                isinstance(item, tuple)
                and len(item) >= 2
                and key_hint is not None
            ):
                _register_entry(key_hint, int(item[0]), float(item[1]), None)

        if history_store is not None:
            for streak in history_store.list_streaks():
                _ingest_item(streak.item_id, streak)

        if streaks is not None:
            if isinstance(streaks, Mapping):
                for k, v in streaks.items():
                    key_str = (
                        f"{k[0]}:{k[1]}"
                        if isinstance(k, tuple) and len(k) == 2
                        else str(k)
                    )
                    _ingest_item(key_str, v)
                    if isinstance(k, tuple) and len(k) == 2:
                        _ingest_item(str(k[1]), v)
            elif isinstance(streaks, Sequence):
                for item in streaks:
                    _ingest_item(None, item)

        return lookup

    @staticmethod
    def _resolve_port_streak(
        *,
        port: Port,
        extras: Mapping[str, Any],
        site: Optional[Site],
        streak_lookup: Mapping[
            str, tuple[int, float, Optional[ValidationClassification]]
        ],
    ) -> tuple[int, float, Optional[ValidationClassification]]:
        raw_runs = extras.get(
            "inactive_runs", extras.get("consecutive_stale_runs")
        )
        raw_days = extras.get(
            "inactive_days", extras.get("stale_duration_days")
        )
        if raw_runs is not None or raw_days is not None:
            return (
                int(raw_runs or 0),
                float(raw_days or 0.0),
                None,
            )

        candidate_keys: list[str] = [
            port.port_id,
            f"port:{port.port_id}",
            f"{port.device_id}:{port.name}",
            f"{port.device_id}:{port.port_id}",
            port.name,
        ]
        if port.connected_device_id:
            candidate_keys.append(port.connected_device_id)
            candidate_keys.append(f"equipment:{port.connected_device_id}")

        if site is not None:
            for eq in site.equipment:
                if (
                    port.port_id in eq.connected_ports
                    or port.name in eq.connected_ports
                    or f"{port.device_id}:{port.name}" in eq.connected_ports
                ):
                    candidate_keys.append(eq.equipment_id)
                    candidate_keys.append(f"equipment:{eq.equipment_id}")

        for key in candidate_keys:
            if key in streak_lookup:
                return streak_lookup[key]

        return (0, 0.0, None)

    @staticmethod
    def _lookup_by_port(
        port: Port, mapping: Optional[Mapping[str, Any]]
    ) -> Any:
        if not mapping:
            return None
        for key in (
            port.port_id,
            f"{port.device_id}:{port.name}",
            f"{port.device_id}:{port.port_id}",
            port.name,
        ):
            if key in mapping:
                return mapping[key]
        return None

    @staticmethod
    def _resolve_device_oids(
        *,
        device_id: str,
        snmp_oids_by_device: Optional[Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        if not snmp_oids_by_device:
            return {}
        if "targets" in snmp_oids_by_device and isinstance(
            snmp_oids_by_device["targets"], Mapping
        ):
            target = snmp_oids_by_device["targets"].get(device_id)
            if isinstance(target, Mapping):
                oids = target.get("oids", target)
                if isinstance(oids, Mapping):
                    return oids
        if device_id in snmp_oids_by_device:
            dev_entry = snmp_oids_by_device[device_id]
            if isinstance(dev_entry, Mapping):
                if "oids" in dev_entry and isinstance(
                    dev_entry["oids"], Mapping
                ):
                    return dev_entry["oids"]
                return dev_entry
        # Support flat OID dictionary passed directly
        if any(str(k).startswith("1.3.6.1.") for k in snmp_oids_by_device):
            return snmp_oids_by_device
        return {}

    @staticmethod
    def _lookup_snmp_oid_for_port(
        *,
        port: Port,
        extras: Mapping[str, Any],
        oids: Mapping[str, Any],
        oid_prefix: str,
    ) -> Any:
        if not oids:
            return None

        candidate_indices: list[str] = []
        if_index = extras.get("if_index")
        if if_index is not None:
            candidate_indices.append(str(if_index).strip())

        slot_port_match = _SLOT_PORT_PATTERN.match(port.name.strip())
        if slot_port_match:
            slot_num = int(slot_port_match.group(1))
            port_num = int(slot_port_match.group(2))
            if_idx = slot_num * 1000 + port_num
            candidate_indices.extend(
                [
                    f"{slot_num}.{if_idx}",
                    str(if_idx),
                    f"{slot_num}.{port_num}",
                    str(port_num),
                ]
            )
        else:
            trailing = _PORT_TRAILING_DIGITS_PATTERN.search(port.name.strip())
            if trailing:
                p_num = int(trailing.group(1))
                candidate_indices.extend(
                    [
                        f"1.{1000 + p_num}",
                        str(1000 + p_num),
                        f"1.{p_num}",
                        str(p_num),
                    ]
                )

        id_trailing = _PORT_TRAILING_DIGITS_PATTERN.search(port.port_id.strip())
        if id_trailing:
            p_num = int(id_trailing.group(1))
            for idx in (
                f"1.{1000 + p_num}",
                str(1000 + p_num),
                f"1.{p_num}",
                str(p_num),
            ):
                if idx not in candidate_indices:
                    candidate_indices.append(idx)

        for suffix in candidate_indices:
            full_oid = f"{oid_prefix}.{suffix}"
            if full_oid in oids:
                return oids[full_oid]

        return None

    def _resolve_poe_watts(
        self,
        *,
        port: Port,
        extras: Mapping[str, Any],
        poe_watts_by_port: Optional[Mapping[str, float]],
        device_oids: Mapping[str, Any],
    ) -> float:
        explicit_watts = self._lookup_by_port(port, poe_watts_by_port)
        if explicit_watts is not None:
            return round(max(0.0, float(explicit_watts)), 2)

        for key in (
            "poe_power_w",
            "poe_watts",
            "estimated_poe_watts_saved",
            "poe_draw_watts",
        ):
            val = extras.get(key)
            if val is not None and str(val).strip() != "":
                try:
                    return round(max(0.0, float(val)), 2)
                except ValueError:
                    pass

        mw_val = extras.get("poe_power_mw")
        if mw_val is not None and str(mw_val).strip() != "":
            try:
                return round(max(0.0, float(mw_val) / 1000.0), 2)
            except ValueError:
                pass

        if device_oids:
            oid_mw = self._lookup_snmp_oid_for_port(
                port=port,
                extras=extras,
                oids=device_oids,
                oid_prefix=EXTREME_POE_PORT_MEASURED_POWER_PREFIX,
            )
            if oid_mw is not None:
                try:
                    watts = float(oid_mw) / 1000.0
                    if watts > 0.0:
                        return round(watts, 2)
                except (TypeError, ValueError):
                    pass

        if port.poe_status:
            poe_text = port.poe_status.strip()
            mw_match = _MILLIWATT_PATTERN.search(poe_text)
            if mw_match is not None:
                return round(float(mw_match.group(1)) / 1000.0, 2)
            watt_match = _WATTAGE_PATTERN.search(poe_text)
            if watt_match is not None:
                return round(float(watt_match.group(1)), 2)
            poe_norm = poe_text.lower()
            if poe_norm in (
                "searching",
                "enabled",
                "on",
                "auto",
                "standby",
                "delivering",
            ):
                return round(self.default_searching_poe_watts, 2)

        return 0.0

    def _resolve_poe_restore_limit_mw(
        self,
        *,
        port: Port,
        extras: Mapping[str, Any],
        poe_limit_mw_by_port: Optional[Mapping[str, int]],
        device_oids: Mapping[str, Any],
    ) -> int:
        explicit_limit = self._lookup_by_port(port, poe_limit_mw_by_port)
        if explicit_limit is not None:
            return max(0, int(explicit_limit))

        for key in (
            "poe_restore_limit_mw",
            "poe_operator_limit_mw",
            "poe_limit_mw",
        ):
            val = extras.get(key)
            if val is not None and str(val).strip() != "":
                try:
                    limit_int = int(float(val))
                    if limit_int > 0:
                        return limit_int
                except ValueError:
                    pass

        if device_oids:
            oid_limit = self._lookup_snmp_oid_for_port(
                port=port,
                extras=extras,
                oids=device_oids,
                oid_prefix=EXTREME_POE_PORT_OPERATOR_LIMIT_PREFIX,
            )
            if oid_limit is not None:
                try:
                    limit_int = int(float(oid_limit))
                    if limit_int > 0:
                        return limit_int
                except (TypeError, ValueError):
                    pass

        return self.default_poe_restore_limit_mw
