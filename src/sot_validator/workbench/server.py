"""Interactive Web Workbench HTTP server, JSON REST API, and state manager.

Facade over the private ``_server_*`` modules; every name stays importable from here.
"""

from __future__ import annotations

from sot_validator.workbench._server_common import (
    _SLUG_RE,
    WorkbenchNotFoundError,
    _bulk_csv_fields,
    _optional_str,
    _slugify,
)
from sot_validator.workbench._server_http import (
    WorkbenchRequestHandler,
    WorkbenchServer,
    create_workbench_server,
)
from sot_validator.workbench._server_security import (
    _BEARER_PREFIX,
    _CSP_POLICY,
    _DEFAULT_ALLOWED_HOSTS,
    _DEFAULT_MAX_BODY_BYTES,
    _LOOPBACK_HOSTNAMES,
    _SECURITY_RESPONSE_HEADERS,
    WorkbenchBindRefusedError,
    WorkbenchSecurityConfig,
    _host_header_name,
    _is_loopback_host,
    _is_valid_token,
    _normalize_host_name,
)
from sot_validator.workbench._server_state import WorkbenchState

__all__ = [
    "WorkbenchBindRefusedError",
    "WorkbenchNotFoundError",
    "WorkbenchRequestHandler",
    "WorkbenchSecurityConfig",
    "WorkbenchServer",
    "WorkbenchState",
    "create_workbench_server",
]
