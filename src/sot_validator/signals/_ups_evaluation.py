"""Single-unit health evaluation body for ApcUpsHealthEvaluator."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional

from sot_validator.models import SignalStatus, SignalType, ValidationSignal
from sot_validator.signals._ups_powernet import parse_powernet_telemetry
from sot_validator.signals._ups_records import (
    UpsAdvisoryCode,
    UpsHealthRecord,
    UpsHealthStatus,
)
from sot_validator.signals.base import resolve_evaluation_time

if TYPE_CHECKING:
    from sot_validator.signals._ups_evaluator import ApcUpsHealthEvaluator


def evaluate_unit(
    evaluator: ApcUpsHealthEvaluator,
    equipment: Any,
    telemetry: Optional[Mapping[str, Any]] = None,
    *,
    site_id: Optional[str] = None,
    evaluation_time: Optional[datetime | str] = None,
) -> UpsHealthRecord:
    """Evaluate APC PowerNet-MIB health telemetry for a single UPS unit."""
    eval_dt = (
        resolve_evaluation_time(evaluation_time)
        if evaluation_time is not None
        else (evaluator.evaluation_time or resolve_evaluation_time(None))
    )

    eq_id, resolved_site_id, name, ips, eq_vendor, eq_model = (
        evaluator._extract_equipment_identity(equipment, telemetry, site_id=site_id)
    )
    resolved_telemetry = evaluator._resolve_telemetry(
        eq_id, name, ips, telemetry, equipment
    )
    # Update ips/vendor/model if resolved_telemetry provided additional metadata
    if isinstance(resolved_telemetry, Mapping):
        if not ips:
            for ip_key in ("ip_address", "ip"):
                t_ip = resolved_telemetry.get(ip_key)
                if isinstance(t_ip, str) and t_ip.strip():
                    ips.append(t_ip.strip())
        if eq_vendor is None and isinstance(resolved_telemetry.get("vendor"), str):
            eq_vendor = resolved_telemetry["vendor"]
        if eq_model is None and isinstance(resolved_telemetry.get("model"), str):
            eq_model = resolved_telemetry["model"]
        if name == eq_id and isinstance(resolved_telemetry.get("hostname"), str):
            name = resolved_telemetry["hostname"]

    primary_ip = ips[0] if ips else None

    # Check reachability
    explicit_unreachable = False
    if resolved_telemetry is not None:
        if resolved_telemetry.get("snmp_reachable") is False or (
            resolved_telemetry.get("reachable") is False
        ):
            explicit_unreachable = True
        elif (
            "oids" in resolved_telemetry
            and isinstance(resolved_telemetry["oids"], Mapping)
            and not resolved_telemetry["oids"]
        ):
            explicit_unreachable = True

    if resolved_telemetry is None or not resolved_telemetry or explicit_unreachable:
        advisories = [UpsAdvisoryCode.UNREACHABLE.value]
        details = (
            f"APC UPS {eq_id} ({name}) at {primary_ip or 'no-ip'} is unreachable via SNMP"
        )
        signal = ValidationSignal(
            signal_type=SignalType.SNMP_API_REACHABILITY,
            status=SignalStatus.UNREACHABLE,
            observed_at=eval_dt,
            age_seconds=0.0,
            details=details,
            source=evaluator.source,
            metadata={
                "equipment_id": eq_id,
                "site_id": resolved_site_id,
                "health_status": UpsHealthStatus.UNREACHABLE.value,
                "advisories": list(advisories),
                "needs_battery_replacement": False,
                "runtime_remaining_minutes": None,
                "temperature_celsius": None,
                "output_load_pct": None,
                "battery_status": None,
                "output_status": None,
                "input_line_fail_cause": None,
            },
        )
        return UpsHealthRecord(
            equipment_id=eq_id,
            site_id=resolved_site_id,
            name=name,
            status=UpsHealthStatus.UNREACHABLE,
            ip_address=primary_ip,
            vendor=eq_vendor or "APC",
            model=eq_model,
            reachable=False,
            advisories=advisories,
            details=details,
            signal=signal,
            evaluated_at=eval_dt,
            raw_oids={},
        )

    parsed = parse_powernet_telemetry(resolved_telemetry)
    raw_oids_dict = (
        dict(resolved_telemetry["oids"])
        if isinstance(resolved_telemetry.get("oids"), Mapping)
        else dict(resolved_telemetry)
    )

    vendor = eq_vendor or parsed.get("vendor") or "APC"
    model = parsed.get("model") or eq_model
    battery_status = parsed.get("battery_status")
    battery_status_code = parsed.get("battery_status_code")
    battery_replace_indicator = parsed.get("battery_replace_indicator")
    needs_battery_replacement = bool(parsed.get("needs_battery_replacement", False))
    battery_capacity_pct = parsed.get("battery_capacity_pct")
    runtime_remaining_minutes = parsed.get("runtime_remaining_minutes")
    temperature_celsius = parsed.get("temperature_celsius")
    output_load_pct = parsed.get("output_load_pct")
    output_status = parsed.get("output_status")
    on_battery = bool(parsed.get("on_battery", False))
    input_line_fail_cause = parsed.get("input_line_fail_cause")
    input_line_fail_cause_code = parsed.get("input_line_fail_cause_code")

    advisories: list[str] = []
    severity_rank = 0  # 0=HEALTHY, 1=WARNING, 2=CRITICAL
    is_low_runtime = False
    is_high_temperature = False
    is_high_load = False

    def _escalate(rank: int) -> None:
        nonlocal severity_rank
        if rank > severity_rank:
            severity_rank = rank

    def _add_advisory(code: UpsAdvisoryCode) -> None:
        if code.value not in advisories:
            advisories.append(code.value)

    # 1. Battery replacement indicator
    if needs_battery_replacement or battery_replace_indicator == 2:
        needs_battery_replacement = True
        _add_advisory(UpsAdvisoryCode.BATTERY_REPLACEMENT_NEEDED)
        _escalate(2)

    # 2. Battery status (1=unknown, 2=batteryNormal, 3=batteryLow, 4=batteryInFaultCondition)
    if battery_status_code == 4 or battery_status == "batteryInFaultCondition":
        _add_advisory(UpsAdvisoryCode.BATTERY_FAULT)
        _escalate(2)
    elif battery_status_code == 3 or battery_status == "batteryLow":
        _add_advisory(UpsAdvisoryCode.BATTERY_LOW)
        if on_battery:
            _escalate(2)
        else:
            _escalate(1)

    # 3. Runtime remaining
    if runtime_remaining_minutes is not None:
        if runtime_remaining_minutes < evaluator.min_runtime_minutes:
            is_low_runtime = True
            _add_advisory(UpsAdvisoryCode.LOW_RUNTIME_WARNING)
            _escalate(1)
        if (
            evaluator.critical_runtime_minutes is not None
            and runtime_remaining_minutes < evaluator.critical_runtime_minutes
        ):
            is_low_runtime = True
            _add_advisory(UpsAdvisoryCode.CRITICAL_RUNTIME)
            _escalate(2)

    # 4. Temperature
    if temperature_celsius is not None:
        if temperature_celsius > evaluator.max_temp_celsius:
            is_high_temperature = True
            _add_advisory(UpsAdvisoryCode.HIGH_TEMP_WARNING)
            _escalate(1)
        if (
            evaluator.critical_temp_celsius is not None
            and temperature_celsius > evaluator.critical_temp_celsius
        ):
            is_high_temperature = True
            _add_advisory(UpsAdvisoryCode.HIGH_TEMP_CRITICAL)
            _escalate(2)

    # 5. Output load
    if output_load_pct is not None:
        if output_load_pct > evaluator.max_load_pct:
            is_high_load = True
            _add_advisory(UpsAdvisoryCode.HIGH_LOAD_WARNING)
            _escalate(1)
        if (
            evaluator.critical_load_pct is not None
            and output_load_pct > evaluator.critical_load_pct
        ):
            is_high_load = True
            _add_advisory(UpsAdvisoryCode.OVERLOAD_CRITICAL)
            _escalate(2)

    # 6. Output status & input line fail cause
    if on_battery:
        _add_advisory(UpsAdvisoryCode.ON_BATTERY_ALERT)
        _escalate(1)

    if (
        input_line_fail_cause is not None
        and input_line_fail_cause not in ("noTransfer", "selfTest")
        and (on_battery or output_status not in ("onLine", None))
    ):
        _add_advisory(UpsAdvisoryCode.INPUT_LINE_FAIL)
        _escalate(1)

    if severity_rank >= 2:
        status = UpsHealthStatus.CRITICAL
    elif severity_rank == 1:
        status = UpsHealthStatus.WARNING
    else:
        status = UpsHealthStatus.HEALTHY

    advisory_str = ", ".join(advisories) if advisories else "none"
    details = (
        f"APC UPS {eq_id} ({name}) status={status.value} "
        f"(model={model or 'unknown'}, output={output_status or 'unknown'}, "
        f"battery_status={battery_status or 'unknown'}, "
        f"replace_battery={needs_battery_replacement}, "
        f"runtime_min={runtime_remaining_minutes}, "
        f"temp_c={temperature_celsius}, "
        f"load_pct={output_load_pct}, "
        f"advisories=[{advisory_str}])"
    )

    signal = ValidationSignal(
        signal_type=SignalType.SNMP_API_REACHABILITY,
        status=SignalStatus.ACTIVE,
        observed_at=eval_dt,
        age_seconds=0.0,
        details=details,
        source=evaluator.source,
        metadata={
            "equipment_id": eq_id,
            "site_id": resolved_site_id,
            "health_status": status.value,
            "advisories": list(advisories),
            "needs_battery_replacement": needs_battery_replacement,
            "runtime_remaining_minutes": runtime_remaining_minutes,
            "temperature_celsius": temperature_celsius,
            "output_load_pct": output_load_pct,
            "battery_capacity_pct": battery_capacity_pct,
            "battery_status": battery_status,
            "output_status": output_status,
            "on_battery": on_battery,
            "input_line_fail_cause": input_line_fail_cause,
        },
    )

    return UpsHealthRecord(
        equipment_id=eq_id,
        site_id=resolved_site_id,
        name=name,
        status=status,
        ip_address=primary_ip,
        vendor=vendor,
        model=model,
        reachable=True,
        battery_status=battery_status,
        battery_status_code=battery_status_code,
        battery_replace_indicator=battery_replace_indicator,
        needs_battery_replacement=needs_battery_replacement,
        battery_capacity_pct=battery_capacity_pct,
        runtime_remaining_minutes=runtime_remaining_minutes,
        temperature_celsius=temperature_celsius,
        output_load_pct=output_load_pct,
        output_status=output_status,
        on_battery=on_battery,
        input_line_fail_cause=input_line_fail_cause,
        input_line_fail_cause_code=input_line_fail_cause_code,
        is_low_runtime=is_low_runtime,
        is_high_temperature=is_high_temperature,
        is_high_load=is_high_load,
        advisories=advisories,
        details=details,
        signal=signal,
        evaluated_at=eval_dt,
        raw_oids=raw_oids_dict,
    )
