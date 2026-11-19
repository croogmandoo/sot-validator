"""APC PowerNet-MIB OID constants, code tables and telemetry parsing helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import re
from typing import Any, Optional

from sot_validator.signals.management import (
    APC_ENTERPRISE_OID_PREFIX,
    APC_UPS_ADV_BATTERY_CAPACITY_OID,
    APC_UPS_ADV_OUTPUT_LOAD_OID,
    APC_UPS_BASIC_IDENT_MODEL_OID,
    APC_UPS_BASIC_STATE_OUTPUT_STATE_OID,
    SNMPV2_MIB_OIDS,
    SNMPV2_MIB_SYS_DESCR,
    SNMPV2_MIB_SYS_NAME,
    SNMPV2_MIB_SYS_UPTIME,
)

# ---------------------------------------------------------------------------
# Canonical APC PowerNet-MIB (1.3.6.1.4.1.318) OID Constants
# ---------------------------------------------------------------------------

APC_UPS_BASIC_BATTERY_STATUS_OID = "1.3.6.1.4.1.318.1.1.1.2.1.1.0"
APC_UPS_ADV_BATTERY_TEMPERATURE_OID = "1.3.6.1.4.1.318.1.1.1.2.2.2.0"
APC_UPS_ADV_BATTERY_RUN_TIME_REMAINING_OID = "1.3.6.1.4.1.318.1.1.1.2.2.3.0"
APC_UPS_ADV_BATTERY_REPLACE_INDICATOR_OID = "1.3.6.1.4.1.318.1.1.1.2.2.4.0"
APC_UPS_ADV_INPUT_LINE_FAIL_CAUSE_OID = "1.3.6.1.4.1.318.1.1.1.3.2.5.0"
APC_UPS_BASIC_OUTPUT_STATUS_OID = "1.3.6.1.4.1.318.1.1.1.4.1.1.0"

APC_UPS_HEALTH_OIDS: tuple[str, ...] = (
    *SNMPV2_MIB_OIDS,
    APC_UPS_BASIC_IDENT_MODEL_OID,
    APC_UPS_BASIC_BATTERY_STATUS_OID,
    APC_UPS_ADV_BATTERY_CAPACITY_OID,
    APC_UPS_ADV_BATTERY_TEMPERATURE_OID,
    APC_UPS_ADV_BATTERY_RUN_TIME_REMAINING_OID,
    APC_UPS_ADV_BATTERY_REPLACE_INDICATOR_OID,
    APC_UPS_ADV_INPUT_LINE_FAIL_CAUSE_OID,
    APC_UPS_BASIC_OUTPUT_STATUS_OID,
    APC_UPS_ADV_OUTPUT_LOAD_OID,
    APC_UPS_BASIC_STATE_OUTPUT_STATE_OID,
)

_BATTERY_STATUS_CODE_TO_NAME: dict[int, str] = {
    1: "unknown",
    2: "batteryNormal",
    3: "batteryLow",
    4: "batteryInFaultCondition",
}

_BATTERY_STATUS_NAME_TO_CODE: dict[str, int] = {
    "unknown": 1,
    "batterynormal": 2,
    "normal": 2,
    "ok": 2,
    "batterylow": 3,
    "low": 3,
    "batteryinfaultcondition": 4,
    "fault": 4,
    "batteryfault": 4,
}

_REPLACE_INDICATOR_CODE_TO_NAME: dict[int, str] = {
    1: "noBatteryNeedsReplacing",
    2: "batteryNeedsReplacing",
}

_REPLACE_INDICATOR_NAME_TO_CODE: dict[str, int] = {
    "nobatteryneedsreplacing": 1,
    "no": 1,
    "false": 1,
    "normal": 1,
    "ok": 1,
    "batteryneedsreplacing": 2,
    "replace": 2,
    "needsreplacement": 2,
    "yes": 2,
    "true": 2,
}

_INPUT_LINE_FAIL_CAUSE_CODE_TO_NAME: dict[int, str] = {
    1: "noTransfer",
    2: "highLineVoltage",
    3: "brownout",
    4: "blackout",
    5: "smallMomentarySag",
    6: "deepMomentarySag",
    7: "smallMomentarySpike",
    8: "largeMomentarySpike",
    9: "selfTest",
    10: "rateOfVoltageChange",
}

_INPUT_LINE_FAIL_CAUSE_NAME_TO_CODE: dict[str, int] = {
    name.lower(): code for code, name in _INPUT_LINE_FAIL_CAUSE_CODE_TO_NAME.items()
}

_OUTPUT_STATUS_CODE_TO_NAME: dict[int, str] = {
    1: "unknown",
    2: "onLine",
    3: "onBattery",
    4: "onSmartBoost",
    5: "timedSleeping",
    6: "softwareBypass",
    7: "off",
    8: "rebooting",
    9: "switchedBypass",
    10: "hardwareFailureBypass",
    11: "sleepingUntilPowerReturn",
    12: "onSmartTrim",
}

_OUTPUT_STATUS_NAME_TO_CANONICAL: dict[str, str] = {
    **{name.lower(): name for name in _OUTPUT_STATUS_CODE_TO_NAME.values()},
    "online": "onLine",
    "on_line": "onLine",
    "onbattery": "onBattery",
    "on_battery": "onBattery",
    "onsmartboost": "onSmartBoost",
    "onsmarttrim": "onSmartTrim",
    "offline": "offLine",
    "off_line": "offLine",
}


def _normalize_lookup_key(key: str) -> str:
    cleaned = str(key).strip().lstrip(".")
    if "::" in cleaned:
        cleaned = cleaned.split("::", 1)[1].strip()
    return cleaned


def _build_lookup_map(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Flatten payload (including nested 'oids' and 'metrics' dicts) into normalized key lookups."""
    flat: dict[str, Any] = {}
    for nested_key in ("metrics", "oids"):
        nested = payload.get(nested_key)
        if isinstance(nested, Mapping):
            for k, v in nested.items():
                flat[str(k)] = v
    for k, v in payload.items():
        if k not in ("metrics", "oids"):
            flat[str(k)] = v

    lookup: dict[str, Any] = {}
    for raw_k, val in flat.items():
        if val is None:
            continue
        lookup[raw_k] = val
        norm_k = _normalize_lookup_key(raw_k)
        lookup[norm_k] = val
        lookup[norm_k.lower()] = val
        if norm_k.endswith(".0"):
            without_zero = norm_k[:-2]
            lookup.setdefault(without_zero, val)
            lookup.setdefault(without_zero.lower(), val)
        else:
            with_zero = f"{norm_k}.0"
            lookup.setdefault(with_zero, val)
            lookup.setdefault(with_zero.lower(), val)
    return lookup


def _lookup_first(
    lookup: Mapping[str, Any],
    candidates: Sequence[str],
) -> tuple[Optional[str], Any]:
    for candidate in candidates:
        if candidate in lookup:
            return candidate, lookup[candidate]
        lower_cand = candidate.lower()
        if lower_cand in lookup:
            return candidate, lookup[lower_cand]
    return None, None


def _parse_float(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        cleaned = re.sub(r"\s*(%|c|°c|degc|celsius)$", "", cleaned, flags=re.IGNORECASE).strip()
        try:
            return float(cleaned)
        except ValueError:
            return None
    return None


def _parse_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        # Handle SNMP enum syntax like "batteryNeedsReplacing(2)"
        match = re.search(r"\((-?\d+)\)\s*$", cleaned)
        if match:
            return int(match.group(1))
        try:
            return int(float(cleaned))
        except ValueError:
            return None
    return None


def _parse_runtime_minutes(raw_value: Any, matched_key: Optional[str]) -> Optional[float]:
    if raw_value is None or isinstance(raw_value, bool):
        return None

    is_snmp_oid_or_mib = False
    if matched_key is not None:
        key_lower = matched_key.lower()
        if (
            "1.3.6.1.4.1.318" in key_lower
            or "upsadvbatteryruntime" in key_lower
            or "timeticks" in key_lower
        ):
            is_snmp_oid_or_mib = True

    if isinstance(raw_value, (int, float)):
        val = float(raw_value)
        if is_snmp_oid_or_mib and val >= 6000.0:
            return round(val / 6000.0, 4)
        return val

    if isinstance(raw_value, str):
        text = raw_value.strip()
        if not text:
            return None

        # Check for SNMP TimeTicks string format: "(72000) 0:12:00.00"
        ticks_match = re.match(r"^\((\d+)\)", text)
        if ticks_match:
            ticks = float(ticks_match.group(1))
            return round(ticks / 6000.0, 4)

        # Check for HH:MM:SS(.cc) or D days, HH:MM:SS
        hms_match = re.search(
            r"(?:(\d+)\s*d(?:ays?)?[,\s]+)?(\d+):(\d{1,2}):(\d{1,2}(?:\.\d+)?)",
            text,
            flags=re.IGNORECASE,
        )
        if hms_match:
            days = float(hms_match.group(1) or 0.0)
            hours = float(hms_match.group(2))
            minutes = float(hms_match.group(3))
            seconds = float(hms_match.group(4))
            return round(days * 1440.0 + hours * 60.0 + minutes + seconds / 60.0, 4)

        # Check for explicit unit suffixes ("12m", "12 min", "720s", "2h")
        unit_match = re.match(
            r"^([+-]?\d+(?:\.\d+)?)\s*(h|hr|hrs|hours?|m|min|mins|minutes?|s|sec|secs|seconds?|ticks|timeticks)$",
            text,
            flags=re.IGNORECASE,
        )
        if unit_match:
            amount = float(unit_match.group(1))
            unit = unit_match.group(2).lower()
            if unit.startswith("h"):
                return round(amount * 60.0, 4)
            if unit.startswith("s"):
                return round(amount / 60.0, 4)
            if unit.startswith("t"):
                return round(amount / 6000.0, 4)
            return amount

        try:
            numeric_val = float(text)
            if is_snmp_oid_or_mib and numeric_val >= 6000.0:
                return round(numeric_val / 6000.0, 4)
            return numeric_val
        except ValueError:
            return None

    return None


def parse_powernet_telemetry(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Parse APC PowerNet-MIB numeric OIDs, symbolic MIB keys, or snake_case telemetry into normalized fields."""
    if not isinstance(payload, Mapping):
        raise TypeError(f"payload must be a Mapping, got {type(payload).__name__}")

    lookup = _build_lookup_map(payload)

    # System & Model identity
    _, raw_sys_name = _lookup_first(
        lookup,
        (
            SNMPV2_MIB_SYS_NAME,
            "sysName",
            "sys_name",
            "hostname",
            "name",
        ),
    )
    _, raw_sys_descr = _lookup_first(
        lookup,
        (
            SNMPV2_MIB_SYS_DESCR,
            "sysDescr",
            "sys_descr",
        ),
    )
    _, raw_sys_uptime = _lookup_first(
        lookup,
        (
            SNMPV2_MIB_SYS_UPTIME,
            "sysUpTime",
            "sys_uptime",
        ),
    )
    _, raw_model = _lookup_first(
        lookup,
        (
            APC_UPS_BASIC_IDENT_MODEL_OID,
            "upsBasicIdentModel",
            "model",
        ),
    )

    # Battery Status (upsBasicBatteryStatus)
    _, raw_batt_status = _lookup_first(
        lookup,
        (
            APC_UPS_BASIC_BATTERY_STATUS_OID,
            "upsBasicBatteryStatus",
            "battery_status_code",
            "battery_status",
        ),
    )
    battery_status_code: Optional[int] = None
    battery_status: Optional[str] = None
    if raw_batt_status is not None:
        parsed_code = _parse_int(raw_batt_status)
        if parsed_code in _BATTERY_STATUS_CODE_TO_NAME:
            battery_status_code = parsed_code
            battery_status = _BATTERY_STATUS_CODE_TO_NAME[parsed_code]
        elif isinstance(raw_batt_status, str):
            clean_str = re.sub(r"\(\d+\)$", "", raw_batt_status.strip()).strip()
            mapped_code = _BATTERY_STATUS_NAME_TO_CODE.get(clean_str.lower().replace("_", ""))
            if mapped_code is not None:
                battery_status_code = mapped_code
                battery_status = _BATTERY_STATUS_CODE_TO_NAME[mapped_code]
            elif clean_str:
                battery_status = clean_str

    # Battery Replace Indicator (upsAdvBatteryReplaceIndicator)
    _, raw_replace = _lookup_first(
        lookup,
        (
            APC_UPS_ADV_BATTERY_REPLACE_INDICATOR_OID,
            "upsAdvBatteryReplaceIndicator",
            "battery_replace_indicator",
            "needs_battery_replacement",
            "battery_needs_replacing",
            "replace_battery",
        ),
    )
    battery_replace_indicator: Optional[int] = None
    needs_battery_replacement: bool = False
    if raw_replace is not None:
        if isinstance(raw_replace, bool):
            needs_battery_replacement = raw_replace
            battery_replace_indicator = 2 if raw_replace else 1
        else:
            parsed_ind = _parse_int(raw_replace)
            if parsed_ind is not None:
                battery_replace_indicator = parsed_ind
                needs_battery_replacement = parsed_ind == 2
            elif isinstance(raw_replace, str):
                clean_rep = re.sub(r"\(\d+\)$", "", raw_replace.strip()).strip().lower()
                mapped_ind = _REPLACE_INDICATOR_NAME_TO_CODE.get(
                    clean_rep.replace("_", "")
                )
                if mapped_ind is not None:
                    battery_replace_indicator = mapped_ind
                    needs_battery_replacement = mapped_ind == 2

    # Battery Capacity (upsAdvBatteryCapacity)
    _, raw_capacity = _lookup_first(
        lookup,
        (
            APC_UPS_ADV_BATTERY_CAPACITY_OID,
            "upsAdvBatteryCapacity",
            "battery_capacity_pct",
            "battery_capacity",
        ),
    )
    battery_capacity_pct = _parse_float(raw_capacity)

    # Battery Temperature (upsAdvBatteryTemperature)
    _, raw_temp = _lookup_first(
        lookup,
        (
            APC_UPS_ADV_BATTERY_TEMPERATURE_OID,
            "upsAdvBatteryTemperature",
            "temperature_celsius",
            "battery_temperature_celsius",
            "temp_celsius",
            "temperature",
        ),
    )
    temperature_celsius = _parse_float(raw_temp)

    # Runtime Remaining (upsAdvBatteryRunTimeRemaining)
    runtime_key, raw_runtime = _lookup_first(
        lookup,
        (
            "runtime_remaining_minutes",
            "runtime_minutes",
            APC_UPS_ADV_BATTERY_RUN_TIME_REMAINING_OID,
            "upsAdvBatteryRunTimeRemaining",
            "runtime_remaining",
        ),
    )
    runtime_remaining_minutes = _parse_runtime_minutes(raw_runtime, runtime_key)

    # Output Load (upsAdvOutputLoad)
    _, raw_load = _lookup_first(
        lookup,
        (
            APC_UPS_ADV_OUTPUT_LOAD_OID,
            "upsAdvOutputLoad",
            "output_load_pct",
            "load_pct",
            "output_load",
        ),
    )
    output_load_pct = _parse_float(raw_load)

    # Input Line Fail Cause (upsAdvInputLineFailCause)
    _, raw_fail_cause = _lookup_first(
        lookup,
        (
            APC_UPS_ADV_INPUT_LINE_FAIL_CAUSE_OID,
            "upsAdvInputLineFailCause",
            "input_line_fail_cause_code",
            "input_line_fail_cause",
        ),
    )
    input_line_fail_cause_code: Optional[int] = None
    input_line_fail_cause: Optional[str] = None
    if raw_fail_cause is not None:
        parsed_cause = _parse_int(raw_fail_cause)
        if parsed_cause in _INPUT_LINE_FAIL_CAUSE_CODE_TO_NAME:
            input_line_fail_cause_code = parsed_cause
            input_line_fail_cause = _INPUT_LINE_FAIL_CAUSE_CODE_TO_NAME[parsed_cause]
        elif isinstance(raw_fail_cause, str):
            clean_cause = re.sub(r"\(\d+\)$", "", raw_fail_cause.strip()).strip()
            mapped_cause = _INPUT_LINE_FAIL_CAUSE_NAME_TO_CODE.get(
                clean_cause.lower().replace("_", "")
            )
            if mapped_cause is not None:
                input_line_fail_cause_code = mapped_cause
                input_line_fail_cause = _INPUT_LINE_FAIL_CAUSE_CODE_TO_NAME[mapped_cause]
            elif clean_cause:
                input_line_fail_cause = clean_cause

    # Output Status & 64-bit State Flags (upsBasicOutputStatus / upsBasicStateOutputState)
    _, raw_output_status = _lookup_first(
        lookup,
        (
            APC_UPS_BASIC_OUTPUT_STATUS_OID,
            "upsBasicOutputStatus",
            "output_status",
        ),
    )
    _, raw_state_flags = _lookup_first(
        lookup,
        (
            APC_UPS_BASIC_STATE_OUTPUT_STATE_OID,
            "upsBasicStateOutputState",
            "output_state_flags",
        ),
    )
    output_state_flags = (
        str(raw_state_flags).strip() if raw_state_flags is not None else ""
    )

    output_status_code: Optional[int] = None
    output_status: Optional[str] = None
    if raw_output_status is not None:
        parsed_out = _parse_int(raw_output_status)
        if parsed_out in _OUTPUT_STATUS_CODE_TO_NAME:
            output_status_code = parsed_out
            output_status = _OUTPUT_STATUS_CODE_TO_NAME[parsed_out]
        elif isinstance(raw_output_status, str):
            clean_out = re.sub(r"\(\d+\)$", "", raw_output_status.strip()).strip()
            canonical_out = _OUTPUT_STATUS_NAME_TO_CANONICAL.get(clean_out.lower())
            output_status = canonical_out if canonical_out is not None else clean_out

    if output_status is None and len(output_state_flags) >= 4:
        if output_state_flags[2] == "1":
            output_status = "onBattery"
            output_status_code = 3
        elif output_state_flags[3] == "1":
            output_status = "onLine"
            output_status_code = 2
        else:
            output_status = "offLine"

    if battery_replace_indicator is None and len(output_state_flags) >= 2:
        if output_state_flags[1] == "1":
            battery_replace_indicator = 2
            needs_battery_replacement = True

    _, raw_on_battery = _lookup_first(lookup, ("on_battery",))
    if isinstance(raw_on_battery, bool):
        on_battery = raw_on_battery
    else:
        on_battery = bool(
            output_status == "onBattery"
            or output_status_code == 3
            or (len(output_state_flags) >= 3 and output_state_flags[2] == "1")
        )

    if on_battery and output_status is None:
        output_status = "onBattery"

    return {
        "vendor": str(payload.get("vendor") or "APC"),
        "sys_name": str(raw_sys_name) if raw_sys_name is not None else None,
        "sys_descr": str(raw_sys_descr) if raw_sys_descr is not None else None,
        "sys_uptime": str(raw_sys_uptime) if raw_sys_uptime is not None else None,
        "model": str(raw_model).strip() if raw_model is not None and str(raw_model).strip() else None,
        "battery_status": battery_status,
        "battery_status_code": battery_status_code,
        "battery_replace_indicator": battery_replace_indicator,
        "needs_battery_replacement": needs_battery_replacement,
        "battery_capacity_pct": battery_capacity_pct,
        "runtime_remaining_minutes": runtime_remaining_minutes,
        "temperature_celsius": temperature_celsius,
        "output_load_pct": output_load_pct,
        "output_status": output_status,
        "output_status_code": output_status_code,
        "output_state_flags": output_state_flags or None,
        "on_battery": on_battery,
        "input_line_fail_cause": input_line_fail_cause,
        "input_line_fail_cause_code": input_line_fail_cause_code,
    }



def _has_powernet_keys(telemetry: Optional[Mapping[str, Any]]) -> bool:
    if not isinstance(telemetry, Mapping):
        return False
    oids = telemetry.get("oids")
    search_space: list[str] = [str(k) for k in telemetry.keys()]
    if isinstance(oids, Mapping):
        search_space.extend(str(k) for k in oids.keys())
    ent_prefix = str(telemetry.get("enterprise_oid_prefix") or "")
    if ent_prefix.startswith(APC_ENTERPRISE_OID_PREFIX):
        return True
    for k in search_space:
        norm = _normalize_lookup_key(k)
        if norm.startswith(APC_ENTERPRISE_OID_PREFIX):
            return True
        lower_k = norm.lower()
        if lower_k.startswith(("upsbasic", "upsadv")):
            return True
    sys_descr = str(
        telemetry.get(SNMPV2_MIB_SYS_DESCR)
        or (oids.get(SNMPV2_MIB_SYS_DESCR) if isinstance(oids, Mapping) else "")
        or telemetry.get("sysDescr")
        or telemetry.get("sys_descr")
        or ""
    ).lower()
    if any(token in sys_descr for token in ("apc", "smart-ups", "symmetra", "powernet")):
        return True
    return False

