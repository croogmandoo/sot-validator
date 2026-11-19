"""APC UPS battery, runtime, load, and environmental health evaluator (PowerNet-MIB)."""

from __future__ import annotations

from sot_validator.models import EquipmentCategory
from sot_validator.signals._ups_evaluator import ApcUpsHealthEvaluator
from sot_validator.signals._ups_powernet import (
    APC_UPS_ADV_BATTERY_REPLACE_INDICATOR_OID,
    APC_UPS_ADV_BATTERY_RUN_TIME_REMAINING_OID,
    APC_UPS_ADV_BATTERY_TEMPERATURE_OID,
    APC_UPS_ADV_INPUT_LINE_FAIL_CAUSE_OID,
    APC_UPS_BASIC_BATTERY_STATUS_OID,
    APC_UPS_BASIC_OUTPUT_STATUS_OID,
    APC_UPS_HEALTH_OIDS,
    _BATTERY_STATUS_CODE_TO_NAME,
    _BATTERY_STATUS_NAME_TO_CODE,
    _INPUT_LINE_FAIL_CAUSE_CODE_TO_NAME,
    _INPUT_LINE_FAIL_CAUSE_NAME_TO_CODE,
    _OUTPUT_STATUS_CODE_TO_NAME,
    _OUTPUT_STATUS_NAME_TO_CANONICAL,
    _REPLACE_INDICATOR_CODE_TO_NAME,
    _REPLACE_INDICATOR_NAME_TO_CODE,
    _build_lookup_map,
    _has_powernet_keys,
    _lookup_first,
    _normalize_lookup_key,
    _parse_float,
    _parse_int,
    _parse_runtime_minutes,
    parse_powernet_telemetry,
)
from sot_validator.signals._ups_records import (
    UpsAdvisoryCode,
    UpsFleetHealthReport,
    UpsHealthRecord,
    UpsHealthStatus,
)
from sot_validator.signals.management import (
    APC_ENTERPRISE_OID_PREFIX,
    APC_UPS_ADV_BATTERY_CAPACITY_OID,
    APC_UPS_ADV_OUTPUT_LOAD_OID,
    APC_UPS_BASIC_IDENT_MODEL_OID,
    APC_UPS_BASIC_STATE_OUTPUT_STATE_OID,
)

# Convenience alias so callers referencing EquipmentType.UPS or EquipmentCategory.UPS both work.
EquipmentType = EquipmentCategory

__all__ = [
    "APC_ENTERPRISE_OID_PREFIX",
    "APC_UPS_ADV_BATTERY_CAPACITY_OID",
    "APC_UPS_ADV_BATTERY_REPLACE_INDICATOR_OID",
    "APC_UPS_ADV_BATTERY_RUN_TIME_REMAINING_OID",
    "APC_UPS_ADV_BATTERY_TEMPERATURE_OID",
    "APC_UPS_ADV_INPUT_LINE_FAIL_CAUSE_OID",
    "APC_UPS_ADV_OUTPUT_LOAD_OID",
    "APC_UPS_BASIC_BATTERY_STATUS_OID",
    "APC_UPS_BASIC_IDENT_MODEL_OID",
    "APC_UPS_BASIC_OUTPUT_STATUS_OID",
    "APC_UPS_BASIC_STATE_OUTPUT_STATE_OID",
    "APC_UPS_HEALTH_OIDS",
    "ApcUpsHealthEvaluator",
    "EquipmentType",
    "UpsAdvisoryCode",
    "UpsFleetHealthReport",
    "UpsHealthRecord",
    "UpsHealthStatus",
    "parse_powernet_telemetry",
]
