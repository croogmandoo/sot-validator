"""APC UPS fleet health evaluator (PowerNet-MIB) signal collector."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime
import inspect
import json
import pathlib
from typing import Any, Optional

from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    SignalType,
    Site,
    ValidationSignal,
)
from sot_validator.signals import _ups_evaluation as _evaluation
from sot_validator.signals._ups_powernet import APC_UPS_HEALTH_OIDS, _has_powernet_keys
from sot_validator.signals._ups_records import UpsFleetHealthReport, UpsHealthRecord
from sot_validator.signals.base import SignalCollector, resolve_evaluation_time
from sot_validator.signals.management import validate_readonly_snmp_request


class ApcUpsHealthEvaluator(SignalCollector):
    """APC UPS battery, runtime, load, and environmental health evaluator (PowerNet-MIB)."""

    signal_type: SignalType = SignalType.SNMP_API_REACHABILITY

    def __init__(
        self,
        min_runtime_minutes: float = 15.0,
        critical_runtime_minutes: Optional[float] = 5.0,
        max_temp_celsius: float = 40.0,
        critical_temp_celsius: Optional[float] = 50.0,
        max_load_pct: float = 80.0,
        critical_load_pct: Optional[float] = 95.0,
        *,
        telemetry_by_target: Optional[Mapping[str, Any]] = None,
        telemetry: Optional[Mapping[str, Any]] = None,
        fixtures: Optional[Mapping[str, Any]] = None,
        snmp_connector: Optional[Any] = None,
        transport: Optional[Any] = None,
        snmp_probe_fn: Optional[Callable[..., Optional[Mapping[str, Any]]]] = None,
        evaluation_time: Optional[datetime | str] = None,
        source: str = "apc_ups_health",
    ) -> None:
        if (
            isinstance(min_runtime_minutes, bool)
            or not isinstance(min_runtime_minutes, (int, float))
            or min_runtime_minutes <= 0
        ):
            raise ValueError("min_runtime_minutes must be a number > 0")
        self.min_runtime_minutes: float = float(min_runtime_minutes)

        if critical_runtime_minutes is not None:
            if (
                isinstance(critical_runtime_minutes, bool)
                or not isinstance(critical_runtime_minutes, (int, float))
                or critical_runtime_minutes < 0
                or critical_runtime_minutes > self.min_runtime_minutes
            ):
                raise ValueError(
                    "critical_runtime_minutes must be >= 0 and <= min_runtime_minutes"
                )
            self.critical_runtime_minutes: Optional[float] = float(
                critical_runtime_minutes
            )
        else:
            self.critical_runtime_minutes = None

        if (
            isinstance(max_temp_celsius, bool)
            or not isinstance(max_temp_celsius, (int, float))
            or max_temp_celsius <= 0
        ):
            raise ValueError("max_temp_celsius must be a number > 0")
        self.max_temp_celsius: float = float(max_temp_celsius)

        if critical_temp_celsius is not None:
            if (
                isinstance(critical_temp_celsius, bool)
                or not isinstance(critical_temp_celsius, (int, float))
                or critical_temp_celsius < self.max_temp_celsius
            ):
                raise ValueError(
                    "critical_temp_celsius must be >= max_temp_celsius"
                )
            self.critical_temp_celsius: Optional[float] = float(critical_temp_celsius)
        else:
            self.critical_temp_celsius = None

        if (
            isinstance(max_load_pct, bool)
            or not isinstance(max_load_pct, (int, float))
            or not (0 < max_load_pct <= 100)
        ):
            raise ValueError("max_load_pct must be between 0 (exclusive) and 100")
        self.max_load_pct: float = float(max_load_pct)

        if critical_load_pct is not None:
            if (
                isinstance(critical_load_pct, bool)
                or not isinstance(critical_load_pct, (int, float))
                or critical_load_pct < self.max_load_pct
                or critical_load_pct > 100
            ):
                raise ValueError(
                    "critical_load_pct must be >= max_load_pct and <= 100"
                )
            self.critical_load_pct: Optional[float] = float(critical_load_pct)
        else:
            self.critical_load_pct = None

        self.evaluation_time: Optional[datetime] = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else None
        )
        self.source: str = source
        self.snmp_connector: Optional[Any] = (
            snmp_connector if snmp_connector is not None else transport
        )
        self.snmp_probe_fn: Optional[Callable[..., Optional[Mapping[str, Any]]]] = (
            snmp_probe_fn
        )

        raw_telemetry = (
            telemetry_by_target
            if telemetry_by_target is not None
            else (telemetry if telemetry is not None else fixtures)
        )
        self._telemetry_by_key: dict[str, Mapping[str, Any]] = {}
        self._raw_targets: dict[str, Mapping[str, Any]] = {}
        self._default_site_id: Optional[str] = None
        if isinstance(raw_telemetry, Mapping):
            self._ingest_telemetry_mapping(raw_telemetry)

    def _ingest_telemetry_mapping(self, mapping: Mapping[str, Any]) -> None:
        if "site_id" in mapping and isinstance(mapping.get("site_id"), str):
            self._default_site_id = str(mapping["site_id"])

        targets_dict = (
            mapping["targets"]
            if "targets" in mapping and isinstance(mapping["targets"], Mapping)
            else mapping
        )
        for key, entry in targets_dict.items():
            if not isinstance(entry, Mapping):
                continue
            key_str = str(key).strip()
            self._raw_targets[key_str] = entry
            self._telemetry_by_key[key_str] = entry
            self._telemetry_by_key[key_str.lower()] = entry
            for alias_field in ("target_id", "equipment_id", "hostname", "name", "ip_address", "ip"):
                alias_val = entry.get(alias_field)
                if isinstance(alias_val, str) and alias_val.strip():
                    clean_alias = alias_val.strip()
                    self._telemetry_by_key[clean_alias] = entry
                    self._telemetry_by_key[clean_alias.lower()] = entry

    @classmethod
    def from_fixture_file(
        cls,
        fixture_path: str | pathlib.Path,
        **kwargs: Any,
    ) -> ApcUpsHealthEvaluator:
        """Create an ApcUpsHealthEvaluator loaded from an SNMP discovery fixture JSON file."""
        raw = json.loads(pathlib.Path(fixture_path).read_text(encoding="utf-8"))
        return cls(telemetry_by_target=raw, **kwargs)

    @staticmethod
    def is_apc_ups(
        item: Any,
        telemetry: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """Return True if `item` or `telemetry` represents an APC UPS unit."""
        if isinstance(item, Equipment):
            if item.category is EquipmentCategory.UPS:
                return True
            name_lower = item.name.lower()
            if any(tok in name_lower for tok in ("apc", "smart-ups", "symmetra", "ups")):
                return True
            return _has_powernet_keys(telemetry)

        if isinstance(item, Mapping):
            cat = item.get("category") or item.get("equipment_type") or item.get("type")
            if isinstance(cat, EquipmentCategory) and cat is EquipmentCategory.UPS:
                return True
            if isinstance(cat, str) and cat.strip().lower() == "ups":
                return True
            for field_name in ("vendor", "model", "name", "hostname"):
                val = item.get(field_name)
                if isinstance(val, str) and any(
                    tok in val.lower() for tok in ("apc", "smart-ups", "symmetra")
                ):
                    return True
            if _has_powernet_keys(item):
                return True

        return _has_powernet_keys(telemetry)

    def _extract_equipment_identity(
        self,
        equipment: Any,
        telemetry: Optional[Mapping[str, Any]] = None,
        site_id: Optional[str] = None,
    ) -> tuple[str, str, str, list[str], Optional[str], Optional[str]]:
        """Return (equipment_id, resolved_site_id, name, ips, vendor, model)."""
        ips: list[str] = []
        vendor: Optional[str] = None
        model: Optional[str] = None

        if isinstance(equipment, Equipment):
            eq_id = equipment.equipment_id
            resolved_site = site_id or equipment.site_id or self._default_site_id or "site-unknown"
            name = equipment.name
            ips = [ip.strip() for ip in equipment.assigned_ips if ip and ip.strip()]
        elif isinstance(equipment, Mapping):
            eq_id = str(
                equipment.get("equipment_id")
                or equipment.get("target_id")
                or equipment.get("ups_id")
                or equipment.get("device_id")
                or equipment.get("id")
                or equipment.get("hostname")
                or equipment.get("name")
                or "ups-unknown"
            )
            resolved_site = str(
                site_id
                or equipment.get("site_id")
                or self._default_site_id
                or "site-unknown"
            )
            name = str(
                equipment.get("name")
                or equipment.get("hostname")
                or eq_id
            )
            raw_ips = equipment.get("assigned_ips")
            if isinstance(raw_ips, Sequence) and not isinstance(raw_ips, (str, bytes)):
                ips.extend(str(ip).strip() for ip in raw_ips if ip and str(ip).strip())
            for single_ip_key in ("ip_address", "ip", "management_ip"):
                single_ip = equipment.get(single_ip_key)
                if isinstance(single_ip, str) and single_ip.strip():
                    if single_ip.strip() not in ips:
                        ips.append(single_ip.strip())
            if isinstance(equipment.get("vendor"), str):
                vendor = equipment["vendor"]
            if isinstance(equipment.get("model"), str):
                model = equipment["model"]
        elif isinstance(equipment, str):
            eq_id = equipment.strip()
            resolved_site = site_id or self._default_site_id or "site-unknown"
            name = eq_id
        else:
            raise TypeError(
                f"Unsupported equipment target type: {type(equipment).__name__}"
            )

        if isinstance(telemetry, Mapping):
            if not ips:
                for ip_key in ("ip_address", "ip"):
                    t_ip = telemetry.get(ip_key)
                    if isinstance(t_ip, str) and t_ip.strip():
                        ips.append(t_ip.strip())
            if vendor is None and isinstance(telemetry.get("vendor"), str):
                vendor = telemetry["vendor"]
            if model is None and isinstance(telemetry.get("model"), str):
                model = telemetry["model"]
            if name == eq_id and isinstance(telemetry.get("hostname"), str):
                name = telemetry["hostname"]

        return eq_id, resolved_site, name, ips, vendor, model

    def _resolve_telemetry(
        self,
        equipment_id: str,
        name: str,
        ips: Sequence[str],
        explicit_telemetry: Optional[Mapping[str, Any]],
        equipment_obj: Any,
    ) -> Optional[Mapping[str, Any]]:
        if explicit_telemetry is not None:
            return explicit_telemetry

        if isinstance(equipment_obj, Mapping) and (
            "oids" in equipment_obj
            or "metrics" in equipment_obj
            or _has_powernet_keys(equipment_obj)
            or "snmp_reachable" in equipment_obj
            or "reachable" in equipment_obj
        ):
            return equipment_obj

        lookup_candidates = [equipment_id, name, *ips]
        for cand in lookup_candidates:
            if not cand:
                continue
            matched = self._telemetry_by_key.get(cand) or self._telemetry_by_key.get(
                cand.lower()
            )
            if matched is not None:
                return matched

        if self.snmp_probe_fn is not None:
            validate_readonly_snmp_request(operation="GET", mode="readonly")
            targets_to_try = list(ips) if ips else [equipment_id]
            for target in targets_to_try:
                sig = inspect.signature(self.snmp_probe_fn)
                pos_params = [
                    p
                    for p in sig.parameters.values()
                    if p.kind
                    in (
                        inspect.Parameter.POSITIONAL_ONLY,
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    )
                ]
                has_varargs = any(
                    p.kind == inspect.Parameter.VAR_POSITIONAL
                    for p in sig.parameters.values()
                )
                if len(pos_params) >= 2 or has_varargs:
                    res = self.snmp_probe_fn(target, list(APC_UPS_HEALTH_OIDS))
                else:
                    res = self.snmp_probe_fn(target)
                if res:
                    return res

        if self.snmp_connector is not None:
            targets_to_try = list(ips) if ips else [equipment_id]
            for target in targets_to_try:
                if hasattr(self.snmp_connector, "query_snmp"):
                    res = self.snmp_connector.query_snmp(target, operation="GET")
                    if res:
                        return res
                elif hasattr(self.snmp_connector, "walk_apc_ups"):
                    res = self.snmp_connector.walk_apc_ups(target)
                    if res:
                        return res
                elif hasattr(self.snmp_connector, "get"):
                    res = self.snmp_connector.get(target, APC_UPS_HEALTH_OIDS)
                    if res:
                        return res
                elif hasattr(self.snmp_connector, "query"):
                    res = self.snmp_connector.query(
                        target, APC_UPS_HEALTH_OIDS, operation="GET"
                    )
                    if res:
                        return res
                elif callable(self.snmp_connector):
                    res = self.snmp_connector(target, APC_UPS_HEALTH_OIDS)
                    if res:
                        return res

        return None

    def evaluate_unit(
        self,
        equipment: Any,
        telemetry: Optional[Mapping[str, Any]] = None,
        *,
        site_id: Optional[str] = None,
        evaluation_time: Optional[datetime | str] = None,
    ) -> UpsHealthRecord:
        """Evaluate APC PowerNet-MIB health telemetry for a single UPS unit."""
        return _evaluation.evaluate_unit(
            self, equipment, telemetry, site_id=site_id, evaluation_time=evaluation_time
        )

    evaluate_equipment = evaluate_unit
    evaluate_ups = evaluate_unit

    def evaluate(self, target: Any, **kwargs: Any) -> ValidationSignal:
        """Evaluate the validation signal for an APC UPS inventory target."""
        record = self.evaluate_unit(target, **kwargs)
        assert record.signal is not None
        return record.signal

    def evaluate_site(
        self,
        site: Site | Sequence[Any] | Mapping[str, Any],
        telemetry_by_target: Optional[Mapping[str, Any]] = None,
        *,
        evaluation_time: Optional[datetime | str] = None,
    ) -> UpsFleetHealthReport:
        """Evaluate all APC UPS units in a Site and return an aggregated UpsFleetHealthReport."""
        return self.evaluate_fleet(
            site,
            telemetry_by_target=telemetry_by_target,
            evaluation_time=evaluation_time,
        )

    def evaluate_fleet(
        self,
        sites_or_units: Any = None,
        telemetry_by_target: Optional[Mapping[str, Any]] = None,
        *,
        evaluation_time: Optional[datetime | str] = None,
    ) -> UpsFleetHealthReport:
        """Evaluate APC UPS units across one or more Sites or equipment collections."""
        eval_dt = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else (self.evaluation_time or resolve_evaluation_time(None))
        )

        extra_lookup: dict[str, Mapping[str, Any]] = {}
        if isinstance(telemetry_by_target, Mapping):
            targets_sub = (
                telemetry_by_target["targets"]
                if "targets" in telemetry_by_target
                and isinstance(telemetry_by_target["targets"], Mapping)
                else telemetry_by_target
            )
            for k, v in targets_sub.items():
                if isinstance(v, Mapping):
                    extra_lookup[str(k)] = v
                    extra_lookup[str(k).lower()] = v
                    for alias_field in (
                        "target_id",
                        "equipment_id",
                        "hostname",
                        "name",
                        "ip_address",
                        "ip",
                    ):
                        alias_val = v.get(alias_field)
                        if isinstance(alias_val, str) and alias_val.strip():
                            extra_lookup[alias_val.strip()] = v
                            extra_lookup[alias_val.strip().lower()] = v

        def _find_telemetry_for_item(item: Any) -> Optional[Mapping[str, Any]]:
            eq_id, _, name, ips, _, _ = self._extract_equipment_identity(item)
            for cand in (eq_id, name, *ips):
                if not cand:
                    continue
                if cand in extra_lookup:
                    return extra_lookup[cand]
                if cand.lower() in extra_lookup:
                    return extra_lookup[cand.lower()]
                if cand in self._telemetry_by_key:
                    return self._telemetry_by_key[cand]
                if cand.lower() in self._telemetry_by_key:
                    return self._telemetry_by_key[cand.lower()]
            return None

        records: list[UpsHealthRecord] = []

        def _process_candidate(item: Any, default_site_id: Optional[str] = None) -> None:
            t_data = _find_telemetry_for_item(item)
            if not self.is_apc_ups(item, t_data):
                return
            rec = self.evaluate_unit(
                item,
                telemetry=t_data,
                site_id=default_site_id,
                evaluation_time=eval_dt,
            )
            records.append(rec)

        if sites_or_units is None:
            # Evaluate all APC UPS targets loaded in self._raw_targets
            for target_id, entry in self._raw_targets.items():
                if self.is_apc_ups(entry, entry):
                    target_dict = dict(entry)
                    target_dict.setdefault("equipment_id", target_id)
                    records.append(
                        self.evaluate_unit(
                            target_dict,
                            telemetry=entry,
                            site_id=self._default_site_id,
                            evaluation_time=eval_dt,
                        )
                    )
        elif isinstance(sites_or_units, Site):
            for eq in sites_or_units.equipment:
                _process_candidate(eq, default_site_id=sites_or_units.site_id)
        elif isinstance(sites_or_units, Equipment):
            _process_candidate(sites_or_units)
        elif isinstance(sites_or_units, Mapping):
            if "equipment" in sites_or_units and isinstance(
                sites_or_units["equipment"], Iterable
            ):
                s_id = str(sites_or_units.get("site_id") or "site-unknown")
                for eq in sites_or_units["equipment"]:
                    _process_candidate(eq, default_site_id=s_id)
            elif "targets" in sites_or_units and isinstance(
                sites_or_units["targets"], Mapping
            ):
                s_id = str(sites_or_units.get("site_id") or self._default_site_id or "site-unknown")
                for target_id, entry in sites_or_units["targets"].items():
                    if isinstance(entry, Mapping) and self.is_apc_ups(entry, entry):
                        target_dict = dict(entry)
                        target_dict.setdefault("equipment_id", str(target_id))
                        records.append(
                            self.evaluate_unit(
                                target_dict,
                                telemetry=entry,
                                site_id=s_id,
                                evaluation_time=eval_dt,
                            )
                        )
            else:
                # Mapping of target_id -> telemetry or single equipment dict
                if any(
                    k in sites_or_units
                    for k in ("equipment_id", "target_id", "category", "equipment_type")
                ):
                    _process_candidate(sites_or_units)
                else:
                    for target_id, entry in sites_or_units.items():
                        if isinstance(entry, Mapping):
                            target_dict = dict(entry)
                            target_dict.setdefault("equipment_id", str(target_id))
                            if self.is_apc_ups(target_dict, entry):
                                records.append(
                                    self.evaluate_unit(
                                        target_dict,
                                        telemetry=entry,
                                        evaluation_time=eval_dt,
                                    )
                                )
        elif isinstance(sites_or_units, Iterable):
            for elem in sites_or_units:
                if isinstance(elem, Site):
                    for eq in elem.equipment:
                        _process_candidate(eq, default_site_id=elem.site_id)
                elif isinstance(elem, Mapping) and "equipment" in elem:
                    s_id = str(elem.get("site_id") or "site-unknown")
                    for eq in elem["equipment"]:
                        _process_candidate(eq, default_site_id=s_id)
                else:
                    _process_candidate(elem)
        else:
            raise TypeError(
                f"Unsupported sites_or_units argument: {type(sites_or_units).__name__}"
            )

        return UpsFleetHealthReport(records=records, evaluated_at=eval_dt)
