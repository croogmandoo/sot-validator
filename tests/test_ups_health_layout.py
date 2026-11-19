"""Tests for the ups_health facade: re-exported names and module size limit."""

from __future__ import annotations

from pathlib import Path

import pytest

import sot_validator.signals as signals
import sot_validator.signals._ups_evaluator as ups_evaluator
import sot_validator.signals._ups_powernet as ups_powernet
import sot_validator.signals._ups_records as ups_records
import sot_validator.signals.management as management
import sot_validator.signals.ups_health as ups_health
from sot_validator.models import EquipmentCategory

SIGNALS_DIR = Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "signals"

EXPECTED_ALL = [
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

REEXPORTED_NAMES = [
    ("APC_ENTERPRISE_OID_PREFIX", management),
    ("APC_UPS_ADV_BATTERY_CAPACITY_OID", management),
    ("APC_UPS_ADV_OUTPUT_LOAD_OID", management),
    ("APC_UPS_BASIC_IDENT_MODEL_OID", management),
    ("APC_UPS_BASIC_STATE_OUTPUT_STATE_OID", management),
    ("APC_UPS_ADV_BATTERY_REPLACE_INDICATOR_OID", ups_powernet),
    ("APC_UPS_ADV_BATTERY_RUN_TIME_REMAINING_OID", ups_powernet),
    ("APC_UPS_ADV_BATTERY_TEMPERATURE_OID", ups_powernet),
    ("APC_UPS_ADV_INPUT_LINE_FAIL_CAUSE_OID", ups_powernet),
    ("APC_UPS_BASIC_BATTERY_STATUS_OID", ups_powernet),
    ("APC_UPS_BASIC_OUTPUT_STATUS_OID", ups_powernet),
    ("APC_UPS_HEALTH_OIDS", ups_powernet),
    ("_BATTERY_STATUS_CODE_TO_NAME", ups_powernet),
    ("_BATTERY_STATUS_NAME_TO_CODE", ups_powernet),
    ("_REPLACE_INDICATOR_CODE_TO_NAME", ups_powernet),
    ("_REPLACE_INDICATOR_NAME_TO_CODE", ups_powernet),
    ("_INPUT_LINE_FAIL_CAUSE_CODE_TO_NAME", ups_powernet),
    ("_INPUT_LINE_FAIL_CAUSE_NAME_TO_CODE", ups_powernet),
    ("_OUTPUT_STATUS_CODE_TO_NAME", ups_powernet),
    ("_OUTPUT_STATUS_NAME_TO_CANONICAL", ups_powernet),
    ("_normalize_lookup_key", ups_powernet),
    ("_build_lookup_map", ups_powernet),
    ("_lookup_first", ups_powernet),
    ("_parse_float", ups_powernet),
    ("_parse_int", ups_powernet),
    ("_parse_runtime_minutes", ups_powernet),
    ("parse_powernet_telemetry", ups_powernet),
    ("_has_powernet_keys", ups_powernet),
    ("UpsHealthStatus", ups_records),
    ("UpsAdvisoryCode", ups_records),
    ("UpsHealthRecord", ups_records),
    ("UpsFleetHealthReport", ups_records),
    ("ApcUpsHealthEvaluator", ups_evaluator),
]

EVALUATOR_METHODS = [
    "from_fixture_file",
    "is_apc_ups",
    "evaluate_unit",
    "evaluate_equipment",
    "evaluate_ups",
    "evaluate",
    "evaluate_site",
    "evaluate_fleet",
]


@pytest.mark.parametrize(
    ("name", "module"), REEXPORTED_NAMES, ids=[name for name, _ in REEXPORTED_NAMES]
)
def test_name_importable_from_ups_health(name: str, module: object) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.signals.ups_health import {name}", namespace)
    assert namespace[name] is getattr(module, name)


def test_equipment_type_alias() -> None:
    assert ups_health.EquipmentType is EquipmentCategory


def test_ups_health_all_unchanged() -> None:
    assert ups_health.__all__ == EXPECTED_ALL


@pytest.mark.parametrize("name", [n for n in EXPECTED_ALL if hasattr(signals, n)])
def test_signals_package_reexports_same_object(name: str) -> None:
    assert getattr(signals, name) is getattr(ups_health, name)


@pytest.mark.parametrize("method", EVALUATOR_METHODS)
def test_evaluator_public_methods_callable(method: str) -> None:
    assert callable(getattr(ups_health.ApcUpsHealthEvaluator, method))


def test_ups_health_modules_under_800_lines() -> None:
    private = sorted(SIGNALS_DIR.glob("_ups_*.py"))
    assert len(private) == 4
    for path in [SIGNALS_DIR / "ups_health.py", *private]:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
