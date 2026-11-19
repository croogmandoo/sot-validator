"""APC UPS health status enums and evaluated health record / fleet report dataclasses."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
from typing import Any, Optional

from sot_validator.models import ValidationSignal
from sot_validator.signals.base import normalize_utc_datetime

class UpsHealthStatus(str, Enum):
    """Overall health classification for an APC UPS unit."""

    HEALTHY = "HEALTHY"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    UNREACHABLE = "UNREACHABLE"


class UpsAdvisoryCode(str, Enum):
    """Standardized maintenance and environmental advisory codes for APC UPS units."""

    BATTERY_REPLACEMENT_NEEDED = "BATTERY_REPLACEMENT_NEEDED"
    BATTERY_FAULT = "BATTERY_FAULT"
    BATTERY_LOW = "BATTERY_LOW"
    LOW_RUNTIME_WARNING = "LOW_RUNTIME_WARNING"
    CRITICAL_RUNTIME = "CRITICAL_RUNTIME"
    HIGH_TEMP_WARNING = "HIGH_TEMP_WARNING"
    HIGH_TEMP_CRITICAL = "HIGH_TEMP_CRITICAL"
    HIGH_LOAD_WARNING = "HIGH_LOAD_WARNING"
    OVERLOAD_CRITICAL = "OVERLOAD_CRITICAL"
    ON_BATTERY_ALERT = "ON_BATTERY_ALERT"
    INPUT_LINE_FAIL = "INPUT_LINE_FAIL"
    UNREACHABLE = "UNREACHABLE"


@dataclass
class UpsHealthRecord:
    """Evaluated battery, runtime, thermal, and load health record for a single APC UPS unit."""

    equipment_id: str
    site_id: str
    name: str
    status: UpsHealthStatus
    ip_address: Optional[str] = None
    vendor: str = "APC"
    model: Optional[str] = None
    reachable: bool = True
    battery_status: Optional[str] = None
    battery_status_code: Optional[int] = None
    battery_replace_indicator: Optional[int] = None
    needs_battery_replacement: bool = False
    battery_capacity_pct: Optional[float] = None
    runtime_remaining_minutes: Optional[float] = None
    temperature_celsius: Optional[float] = None
    output_load_pct: Optional[float] = None
    output_status: Optional[str] = None
    on_battery: bool = False
    input_line_fail_cause: Optional[str] = None
    input_line_fail_cause_code: Optional[int] = None
    is_low_runtime: bool = False
    is_high_temperature: bool = False
    is_high_load: bool = False
    advisories: list[str] = field(default_factory=list)
    details: Optional[str] = None
    signal: Optional[ValidationSignal] = None
    evaluated_at: Optional[datetime] = None
    raw_oids: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.equipment_id, str) or not self.equipment_id.strip():
            raise ValueError("equipment_id must be a non-empty string")
        if not isinstance(self.site_id, str) or not self.site_id.strip():
            raise ValueError("site_id must be a non-empty string")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("name must be a non-empty string")
        if not isinstance(self.status, UpsHealthStatus):
            self.status = UpsHealthStatus(str(self.status).upper())
        if self.evaluated_at is not None and not isinstance(self.evaluated_at, datetime):
            self.evaluated_at = normalize_utc_datetime(
                self.evaluated_at, field_name="evaluated_at"
            )
        if self.signal is not None and not isinstance(self.signal, ValidationSignal):
            if isinstance(self.signal, Mapping):
                self.signal = ValidationSignal.from_dict(self.signal)
        self.advisories = [
            adv.value if isinstance(adv, UpsAdvisoryCode) else str(adv)
            for adv in self.advisories
        ]
        self.raw_oids = dict(self.raw_oids) if self.raw_oids else {}

    @property
    def ups_id(self) -> str:
        return self.equipment_id

    @property
    def device_id(self) -> str:
        return self.equipment_id

    @property
    def hostname(self) -> str:
        return self.name

    @property
    def health_status(self) -> UpsHealthStatus:
        return self.status

    @property
    def battery_needs_replacing(self) -> bool:
        return self.needs_battery_replacement

    @property
    def replace_battery(self) -> bool:
        return self.needs_battery_replacement

    @property
    def runtime_minutes(self) -> Optional[float]:
        return self.runtime_remaining_minutes

    @property
    def battery_temperature_celsius(self) -> Optional[float]:
        return self.temperature_celsius

    @property
    def temp_celsius(self) -> Optional[float]:
        return self.temperature_celsius

    @property
    def load_pct(self) -> Optional[float]:
        return self.output_load_pct

    @property
    def low_runtime(self) -> bool:
        return self.is_low_runtime

    @property
    def high_temperature(self) -> bool:
        return self.is_high_temperature

    @property
    def thermal_alert(self) -> bool:
        return self.is_high_temperature

    @property
    def high_load(self) -> bool:
        return self.is_high_load

    @property
    def overload_risk(self) -> bool:
        return self.is_high_load

    def to_dict(self) -> dict[str, Any]:
        return {
            "equipment_id": self.equipment_id,
            "site_id": self.site_id,
            "name": self.name,
            "status": self.status.value,
            "ip_address": self.ip_address,
            "vendor": self.vendor,
            "model": self.model,
            "reachable": self.reachable,
            "battery_status": self.battery_status,
            "battery_status_code": self.battery_status_code,
            "battery_replace_indicator": self.battery_replace_indicator,
            "needs_battery_replacement": self.needs_battery_replacement,
            "battery_capacity_pct": self.battery_capacity_pct,
            "runtime_remaining_minutes": self.runtime_remaining_minutes,
            "temperature_celsius": self.temperature_celsius,
            "output_load_pct": self.output_load_pct,
            "output_status": self.output_status,
            "on_battery": self.on_battery,
            "input_line_fail_cause": self.input_line_fail_cause,
            "input_line_fail_cause_code": self.input_line_fail_cause_code,
            "is_low_runtime": self.is_low_runtime,
            "is_high_temperature": self.is_high_temperature,
            "is_high_load": self.is_high_load,
            "advisories": list(self.advisories),
            "details": self.details,
            "signal": self.signal.to_dict() if self.signal is not None else None,
            "evaluated_at": (
                self.evaluated_at.isoformat() if self.evaluated_at is not None else None
            ),
            "raw_oids": dict(self.raw_oids),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> UpsHealthRecord:
        raw_signal = data.get("signal")
        signal = (
            raw_signal
            if isinstance(raw_signal, ValidationSignal) or raw_signal is None
            else ValidationSignal.from_dict(raw_signal)
        )
        raw_eval = data.get("evaluated_at")
        evaluated_at = (
            normalize_utc_datetime(raw_eval, field_name="evaluated_at")
            if raw_eval is not None
            else None
        )
        return cls(
            equipment_id=str(data["equipment_id"]),
            site_id=str(data["site_id"]),
            name=str(data["name"]),
            status=UpsHealthStatus(str(data["status"])),
            ip_address=data.get("ip_address"),
            vendor=str(data.get("vendor", "APC")),
            model=data.get("model"),
            reachable=bool(data.get("reachable", True)),
            battery_status=data.get("battery_status"),
            battery_status_code=data.get("battery_status_code"),
            battery_replace_indicator=data.get("battery_replace_indicator"),
            needs_battery_replacement=bool(data.get("needs_battery_replacement", False)),
            battery_capacity_pct=data.get("battery_capacity_pct"),
            runtime_remaining_minutes=data.get("runtime_remaining_minutes"),
            temperature_celsius=data.get("temperature_celsius"),
            output_load_pct=data.get("output_load_pct"),
            output_status=data.get("output_status"),
            on_battery=bool(data.get("on_battery", False)),
            input_line_fail_cause=data.get("input_line_fail_cause"),
            input_line_fail_cause_code=data.get("input_line_fail_cause_code"),
            is_low_runtime=bool(data.get("is_low_runtime", False)),
            is_high_temperature=bool(data.get("is_high_temperature", False)),
            is_high_load=bool(data.get("is_high_load", False)),
            advisories=list(data.get("advisories", [])),
            details=data.get("details"),
            signal=signal,
            evaluated_at=evaluated_at,
            raw_oids=dict(data.get("raw_oids") or {}),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> UpsHealthRecord:
        return cls.from_dict(json.loads(raw))


@dataclass
class UpsFleetHealthReport:
    """Fleet-wide and per-site aggregated APC UPS health telemetry report."""

    records: list[UpsHealthRecord] = field(default_factory=list)
    total_units: int = 0
    healthy_count: int = 0
    warning_count: int = 0
    critical_count: int = 0
    unreachable_count: int = 0
    battery_replacement_units: list[UpsHealthRecord] = field(default_factory=list)
    low_runtime_units: list[UpsHealthRecord] = field(default_factory=list)
    thermal_alert_units: list[UpsHealthRecord] = field(default_factory=list)
    high_load_units: list[UpsHealthRecord] = field(default_factory=list)
    on_battery_units: list[UpsHealthRecord] = field(default_factory=list)
    by_site: dict[str, dict[str, Any]] = field(default_factory=dict)
    evaluated_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        self.records = [
            r if isinstance(r, UpsHealthRecord) else UpsHealthRecord.from_dict(r)
            for r in self.records
        ]
        if self.evaluated_at is not None and not isinstance(self.evaluated_at, datetime):
            self.evaluated_at = normalize_utc_datetime(
                self.evaluated_at, field_name="evaluated_at"
            )

        if self.records:
            self.total_units = len(self.records)
            self.healthy_count = sum(
                1 for r in self.records if r.status is UpsHealthStatus.HEALTHY
            )
            self.warning_count = sum(
                1 for r in self.records if r.status is UpsHealthStatus.WARNING
            )
            self.critical_count = sum(
                1 for r in self.records if r.status is UpsHealthStatus.CRITICAL
            )
            self.unreachable_count = sum(
                1 for r in self.records if r.status is UpsHealthStatus.UNREACHABLE
            )
            if not self.battery_replacement_units:
                self.battery_replacement_units = [
                    r
                    for r in self.records
                    if r.needs_battery_replacement
                    or UpsAdvisoryCode.BATTERY_REPLACEMENT_NEEDED.value in r.advisories
                ]
            if not self.low_runtime_units:
                self.low_runtime_units = [
                    r
                    for r in self.records
                    if r.is_low_runtime
                    or UpsAdvisoryCode.LOW_RUNTIME_WARNING.value in r.advisories
                    or UpsAdvisoryCode.CRITICAL_RUNTIME.value in r.advisories
                ]
            if not self.thermal_alert_units:
                self.thermal_alert_units = [
                    r
                    for r in self.records
                    if r.is_high_temperature
                    or UpsAdvisoryCode.HIGH_TEMP_WARNING.value in r.advisories
                    or UpsAdvisoryCode.HIGH_TEMP_CRITICAL.value in r.advisories
                ]
            if not self.high_load_units:
                self.high_load_units = [
                    r
                    for r in self.records
                    if r.is_high_load
                    or UpsAdvisoryCode.HIGH_LOAD_WARNING.value in r.advisories
                    or UpsAdvisoryCode.OVERLOAD_CRITICAL.value in r.advisories
                ]
            if not self.on_battery_units:
                self.on_battery_units = [
                    r
                    for r in self.records
                    if r.on_battery
                    or UpsAdvisoryCode.ON_BATTERY_ALERT.value in r.advisories
                ]
            if not self.by_site:
                site_map: dict[str, list[UpsHealthRecord]] = {}
                for rec in self.records:
                    site_map.setdefault(rec.site_id, []).append(rec)
                self.by_site = {
                    site_id: {
                        "site_id": site_id,
                        "total_units": len(site_recs),
                        "healthy_count": sum(
                            1
                            for r in site_recs
                            if r.status is UpsHealthStatus.HEALTHY
                        ),
                        "warning_count": sum(
                            1
                            for r in site_recs
                            if r.status is UpsHealthStatus.WARNING
                        ),
                        "critical_count": sum(
                            1
                            for r in site_recs
                            if r.status is UpsHealthStatus.CRITICAL
                        ),
                        "unreachable_count": sum(
                            1
                            for r in site_recs
                            if r.status is UpsHealthStatus.UNREACHABLE
                        ),
                        "battery_replacement_count": sum(
                            1 for r in site_recs if r.needs_battery_replacement
                        ),
                        "low_runtime_count": sum(
                            1 for r in site_recs if r.is_low_runtime
                        ),
                        "thermal_alert_count": sum(
                            1 for r in site_recs if r.is_high_temperature
                        ),
                        "high_load_count": sum(
                            1 for r in site_recs if r.is_high_load
                        ),
                        "on_battery_count": sum(
                            1 for r in site_recs if r.on_battery
                        ),
                        "equipment_ids": [r.equipment_id for r in site_recs],
                    }
                    for site_id, site_recs in site_map.items()
                }

    @property
    def units(self) -> list[UpsHealthRecord]:
        return self.records

    @property
    def results(self) -> list[UpsHealthRecord]:
        return self.records

    @property
    def total_ups_count(self) -> int:
        return self.total_units

    @property
    def healthy_units(self) -> list[UpsHealthRecord]:
        return [r for r in self.records if r.status is UpsHealthStatus.HEALTHY]

    @property
    def warning_units(self) -> list[UpsHealthRecord]:
        return [r for r in self.records if r.status is UpsHealthStatus.WARNING]

    @property
    def critical_units(self) -> list[UpsHealthRecord]:
        return [r for r in self.records if r.status is UpsHealthStatus.CRITICAL]

    @property
    def unreachable_units(self) -> list[UpsHealthRecord]:
        return [r for r in self.records if r.status is UpsHealthStatus.UNREACHABLE]

    @property
    def units_needing_battery_replacement(self) -> list[UpsHealthRecord]:
        return self.battery_replacement_units

    @property
    def battery_replacement_count(self) -> int:
        return len(self.battery_replacement_units)

    @property
    def low_runtime_count(self) -> int:
        return len(self.low_runtime_units)

    @property
    def thermal_alerts(self) -> list[UpsHealthRecord]:
        return self.thermal_alert_units

    @property
    def high_temperature_units(self) -> list[UpsHealthRecord]:
        return self.thermal_alert_units

    @property
    def high_temp_units(self) -> list[UpsHealthRecord]:
        return self.thermal_alert_units

    @property
    def thermal_alert_count(self) -> int:
        return len(self.thermal_alert_units)

    @property
    def high_temp_count(self) -> int:
        return len(self.thermal_alert_units)

    @property
    def overload_units(self) -> list[UpsHealthRecord]:
        return self.high_load_units

    @property
    def high_load_count(self) -> int:
        return len(self.high_load_units)

    @property
    def overload_count(self) -> int:
        return len(self.high_load_units)

    @property
    def on_battery_count(self) -> int:
        return len(self.on_battery_units)

    @property
    def site_summaries(self) -> dict[str, dict[str, Any]]:
        return self.by_site

    def to_dict(self) -> dict[str, Any]:
        return {
            "records": [r.to_dict() for r in self.records],
            "total_units": self.total_units,
            "healthy_count": self.healthy_count,
            "warning_count": self.warning_count,
            "critical_count": self.critical_count,
            "unreachable_count": self.unreachable_count,
            "battery_replacement_units": [
                r.to_dict() for r in self.battery_replacement_units
            ],
            "low_runtime_units": [r.to_dict() for r in self.low_runtime_units],
            "thermal_alert_units": [r.to_dict() for r in self.thermal_alert_units],
            "high_load_units": [r.to_dict() for r in self.high_load_units],
            "on_battery_units": [r.to_dict() for r in self.on_battery_units],
            "by_site": dict(self.by_site),
            "evaluated_at": (
                self.evaluated_at.isoformat() if self.evaluated_at is not None else None
            ),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> UpsFleetHealthReport:
        records = [
            r if isinstance(r, UpsHealthRecord) else UpsHealthRecord.from_dict(r)
            for r in data.get("records", [])
        ]
        raw_eval = data.get("evaluated_at")
        evaluated_at = (
            normalize_utc_datetime(raw_eval, field_name="evaluated_at")
            if raw_eval is not None
            else None
        )
        return cls(
            records=records,
            evaluated_at=evaluated_at,
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> UpsFleetHealthReport:
        return cls.from_dict(json.loads(raw))
