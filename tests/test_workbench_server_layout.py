"""Tests for the workbench server facade: re-exported names and module size limit."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import sot_validator.workbench as workbench
import sot_validator.workbench.server as server

WORKBENCH_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "workbench"
)

SERVER_PUBLIC_NAMES = [
    "WorkbenchBindRefusedError",
    "WorkbenchNotFoundError",
    "WorkbenchRequestHandler",
    "WorkbenchSecurityConfig",
    "WorkbenchServer",
    "WorkbenchState",
    "create_workbench_server",
]

PACKAGE_PUBLIC_NAMES = [
    "DEFAULT_WORKBENCH_TITLE",
    "WorkbenchBindRefusedError",
    "WorkbenchNotFoundError",
    "WorkbenchRequestHandler",
    "WorkbenchSecurityConfig",
    "WorkbenchServer",
    "WorkbenchState",
    "create_workbench_server",
    "render_workbench_html",
]

# Name -> private module that defines it.
REEXPORTED_NAMES = {
    "WorkbenchBindRefusedError": "_server_security",
    "WorkbenchNotFoundError": "_server_common",
    "WorkbenchRequestHandler": "_server_http",
    "WorkbenchSecurityConfig": "_server_security",
    "WorkbenchServer": "_server_http",
    "WorkbenchState": "_server_state",
    "create_workbench_server": "_server_http",
    "_SLUG_RE": "_server_common",
    "_BEARER_PREFIX": "_server_security",
    "_DEFAULT_MAX_BODY_BYTES": "_server_security",
    "_CSP_POLICY": "_server_security",
    "_SECURITY_RESPONSE_HEADERS": "_server_security",
    "_LOOPBACK_HOSTNAMES": "_server_security",
    "_DEFAULT_ALLOWED_HOSTS": "_server_security",
    "_is_loopback_host": "_server_security",
    "_is_valid_token": "_server_security",
    "_normalize_host_name": "_server_security",
    "_host_header_name": "_server_security",
    "_slugify": "_server_common",
    "_optional_str": "_server_common",
    "_bulk_csv_fields": "_server_common",
}


@pytest.mark.parametrize("name", sorted(REEXPORTED_NAMES))
def test_name_importable_from_server(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.workbench.server import {name}", namespace)
    defining = importlib.import_module(
        f"sot_validator.workbench.{REEXPORTED_NAMES[name]}"
    )
    assert namespace[name] is getattr(defining, name)
    assert namespace[name] is getattr(server, name)
    if callable(namespace[name]):
        assert namespace[name].__module__ == defining.__name__


@pytest.mark.parametrize(
    "method",
    [
        "refresh",
        "_build_vlan_subnet_summary",
        "get_state_payload",
        "apply_item_patch",
        "preview_csv",
        "apply_csv",
        "create_device",
        "upsert_device_ports",
        "upsert_vlan",
    ],
)
def test_state_methods_reachable(method: str) -> None:
    assert callable(getattr(server.WorkbenchState, method))


@pytest.mark.parametrize(
    "method",
    [
        "end_headers",
        "_send_json",
        "_send_html",
        "_read_json_body",
        "_token_authorized",
        "_origin_authorized",
        "_body_size_authorized",
        "_host_authorized",
        "_authorize_mutation",
        "_reject_unsupported_mutation",
        "do_GET",
        "do_POST",
        "do_PUT",
        "do_PATCH",
        "do_DELETE",
    ],
)
def test_request_handler_methods_reachable(method: str) -> None:
    assert callable(getattr(server.WorkbenchRequestHandler, method))


def test_server_all_unchanged() -> None:
    assert server.__all__ == SERVER_PUBLIC_NAMES


def test_package_all_unchanged_and_same_objects() -> None:
    assert workbench.__all__ == PACKAGE_PUBLIC_NAMES
    for name in SERVER_PUBLIC_NAMES:
        assert getattr(workbench, name) is getattr(server, name)


def test_workbench_modules_under_800_lines() -> None:
    files = sorted(WORKBENCH_DIR.glob("*.py"))
    assert files
    for path in files:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
