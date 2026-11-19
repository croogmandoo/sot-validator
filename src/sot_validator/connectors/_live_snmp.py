"""Read-only SNMP GET/GETNEXT/GETBULK/WALK connector for Extreme switches and APC UPSs."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import inspect
import time
from typing import Any, Optional

from sot_validator.connectors._live_common import (
    _ALLOWED_READONLY_MODES,
    _FORBIDDEN_WRITE_COMMUNITIES,
    APC_UPS_MIB_OIDS,
    EXTREME_SWITCH_MIB_OIDS,
    LLDP_REM_PORT_ID_PREFIX,
    LLDP_REM_SYS_NAME_PREFIX,
    PETH_PSE_PORT_ADMIN_ENABLE_PREFIX,
    PETH_PSE_PORT_DETECTION_STATUS_PREFIX,
    ConnectorReadOnlyError,
    RequestTelemetry,
    _validate_timeout_and_retries,
)
from sot_validator.signals.icmp import (
    ScopeViolationError,
    SubnetScopeGuard,
    _parse_ipv4_host,
)
from sot_validator.signals.management import (
    ALLOWED_SNMP_OPERATIONS,
    SNMPV2_MIB_OIDS,
    parse_apc_ups_oids,
    parse_extreme_switch_oids,
)


def _validate_snmp_readonly_config(
    *,
    operation: str = "GET",
    mode: str = "readonly",
    community: Optional[str] = None,
) -> str:
    if not isinstance(mode, str) or mode.strip().lower() not in _ALLOWED_READONLY_MODES:
        raise ConnectorReadOnlyError(
            f"SNMP mode {mode!r} is prohibited; only read-only mode is allowed"
        )
    if community is not None and isinstance(community, str):
        comm_lower = community.strip().lower()
        if comm_lower in _FORBIDDEN_WRITE_COMMUNITIES or comm_lower.endswith(
            ("-rw", "_rw", "-write", "_write")
        ):
            raise ConnectorReadOnlyError(
                f"SNMP community {community!r} is a write community; strictly read-only community required"
            )
    if not isinstance(operation, str) or not operation.strip():
        raise ConnectorReadOnlyError("SNMP operation must be a non-empty string")
    op_upper = operation.strip().upper()
    if op_upper not in ALLOWED_SNMP_OPERATIONS:
        raise ConnectorReadOnlyError(
            f"SNMP operation {operation!r} is strictly prohibited in read-only mode; "
            f"only {sorted(ALLOWED_SNMP_OPERATIONS)} are allowed"
        )
    return op_upper


class SnmpWalkConnector:
    """Read-only SNMP GET/GETNEXT/GETBULK/WALK connector for Extreme switches and APC UPSs."""

    def __init__(
        self,
        *,
        community: Optional[str] = "public-ro",
        snmp_v3_user: Optional[str] = None,
        version: str = "2c",
        mode: str = "readonly",
        port: int = 161,
        timeout_seconds: float = 2.0,
        max_retries: int = 2,
        backoff_seconds: float = 0.0,
        scope_guard: Optional[SubnetScopeGuard] = None,
        transport: Optional[Callable[..., Optional[Mapping[str, Any]]]] = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        _validate_snmp_readonly_config(
            operation="GET",
            mode=mode,
            community=community,
        )

        norm_version = (
            version.strip().lower().removeprefix("v")
            if isinstance(version, str)
            else ""
        )
        if norm_version not in {"2c", "3"}:
            raise ValueError(
                f"Unsupported SNMP version {version!r}; must be '2c' or '3'"
            )
        if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
            raise ValueError("port must be an integer between 1 and 65535")

        (
            self.timeout_seconds,
            self.max_retries,
            self.backoff_seconds,
        ) = _validate_timeout_and_retries(timeout_seconds, max_retries, backoff_seconds)

        self.community: Optional[str] = (
            community.strip()
            if isinstance(community, str) and community.strip()
            else None
        )
        self.snmp_v3_user: Optional[str] = (
            snmp_v3_user.strip()
            if isinstance(snmp_v3_user, str) and snmp_v3_user.strip()
            else None
        )
        self.version: str = norm_version
        self.mode: str = "readonly"
        self.port: int = port
        self.scope_guard: Optional[SubnetScopeGuard] = scope_guard
        self._transport = transport
        self._sleep_fn = sleep_fn
        self.telemetry = RequestTelemetry()

    @property
    def has_live_transport(self) -> bool:
        """Return True if an active SNMP transport callable has been configured."""
        return self._transport is not None

    @property
    def has_valid_credentials(self) -> bool:
        """Return True if read-only credentials are present for the configured SNMP version."""
        if self.version == "3":
            return bool(self.snmp_v3_user)
        return bool(self.community)

    def _validate_target(
        self,
        target_ip: str,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> str:
        active_guard = scope_guard if scope_guard is not None else self.scope_guard
        if active_guard is not None:
            return active_guard.validate_target_ip(target_ip)
        return str(_parse_ipv4_host(target_ip))

    def _invoke_transport(
        self,
        normalized_ip: str,
        oids: list[str],
        operation: str,
        timeout: float,
    ) -> dict[str, Any]:
        if self._transport is None:
            return {}

        sig = inspect.signature(self._transport)
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
        has_kwargs = any(
            p.kind == inspect.Parameter.VAR_KEYWORD
            for p in sig.parameters.values()
        )

        kwargs: dict[str, Any] = {}
        if "operation" in sig.parameters or has_kwargs:
            if len(pos_params) < 3:
                kwargs["operation"] = operation

        if len(pos_params) >= 4 or has_varargs:
            raw = self._transport(normalized_ip, oids, operation, timeout)
        elif len(pos_params) == 3:
            third_name = pos_params[2].name.lower()
            if third_name in {"operation", "op", "pdu"}:
                raw = self._transport(normalized_ip, oids, operation)
            else:
                raw = self._transport(normalized_ip, oids, timeout, **kwargs)
        elif len(pos_params) == 2:
            second_name = pos_params[1].name.lower()
            if "timeout" in second_name:
                raw = self._transport(normalized_ip, timeout, **kwargs)
            else:
                raw = self._transport(normalized_ip, oids, **kwargs)
        elif len(pos_params) == 1:
            raw = self._transport(normalized_ip, **kwargs)
        else:
            raw = self._transport(**kwargs)

        if raw is None:
            return {}
        if not isinstance(raw, Mapping):
            raise TypeError(
                f"SNMP transport must return a Mapping[str, Any] or None, got {type(raw).__name__}"
            )
        return dict(raw)

    def query(
        self,
        target_ip: str,
        oids: Sequence[str] = SNMPV2_MIB_OIDS,
        *,
        operation: str = "GET",
        timeout_seconds: Optional[float] = None,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> dict[str, Any]:
        """Execute a validated read-only SNMP query against a scoped target IPv4 address."""
        try:
            op_upper = _validate_snmp_readonly_config(
                operation=operation,
                mode=self.mode,
                community=self.community,
            )
        except ConnectorReadOnlyError:
            self.telemetry.blocked_mutations += 1
            raise

        normalized_ip = self._validate_target(target_ip, scope_guard=scope_guard)
        effective_timeout = (
            float(timeout_seconds)
            if timeout_seconds is not None
            else self.timeout_seconds
        )
        if effective_timeout <= 0:
            raise ValueError("timeout_seconds must be > 0")

        oid_list = [str(o).strip() for o in oids if str(o).strip()]
        self.telemetry.total_requests += 1
        self.telemetry.last_target = normalized_ip

        total_attempts = 1 + self.max_retries
        last_exc: Optional[Exception] = None

        for attempt in range(1, total_attempts + 1):
            if attempt > 1:
                self.telemetry.retried_requests += 1
                if self.backoff_seconds > 0:
                    self._sleep_fn(self.backoff_seconds * (2 ** (attempt - 2)))

            start = time.monotonic()
            try:
                result = self._invoke_transport(
                    normalized_ip, oid_list, op_upper, effective_timeout
                )
            except PermissionError as exc:
                self.telemetry.blocked_mutations += 1
                self.telemetry.failed_requests += 1
                if isinstance(exc, ConnectorReadOnlyError):
                    raise
                raise ConnectorReadOnlyError(str(exc)) from exc
            except ScopeViolationError:
                self.telemetry.failed_requests += 1
                raise
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                continue

            elapsed_ms = round((time.monotonic() - start) * 1000.0, 3)
            self.telemetry.latencies_ms.append(elapsed_ms)
            self.telemetry.successful_requests += 1
            return result

        self.telemetry.failed_requests += 1
        assert last_exc is not None
        raise last_exc

    def get(
        self,
        target_ip: str,
        oids: Sequence[str] = SNMPV2_MIB_OIDS,
        *,
        timeout_seconds: Optional[float] = None,
    ) -> dict[str, Any]:
        """Perform a read-only SNMP GET request."""
        return self.query(
            target_ip, oids, operation="GET", timeout_seconds=timeout_seconds
        )

    def get_next(
        self,
        target_ip: str,
        oids: Sequence[str] = SNMPV2_MIB_OIDS,
        *,
        timeout_seconds: Optional[float] = None,
    ) -> dict[str, Any]:
        """Perform a read-only SNMP GETNEXT request."""
        return self.query(
            target_ip, oids, operation="GETNEXT", timeout_seconds=timeout_seconds
        )

    def get_bulk(
        self,
        target_ip: str,
        oids: Sequence[str] = SNMPV2_MIB_OIDS,
        *,
        timeout_seconds: Optional[float] = None,
    ) -> dict[str, Any]:
        """Perform a read-only SNMP GETBULK request."""
        return self.query(
            target_ip, oids, operation="GETBULK", timeout_seconds=timeout_seconds
        )

    def walk(
        self,
        target_ip: str,
        oid_prefixes: Sequence[str] = SNMPV2_MIB_OIDS,
        *,
        timeout_seconds: Optional[float] = None,
    ) -> dict[str, Any]:
        """Perform a read-only SNMP WALK request."""
        return self.query(
            target_ip,
            oid_prefixes,
            operation="WALK",
            timeout_seconds=timeout_seconds,
        )

    def set(self, *args: Any, **kwargs: Any) -> Any:
        """Unconditionally block SNMP SET operations with ConnectorReadOnlyError."""
        _ = (args, kwargs)
        self.telemetry.blocked_mutations += 1
        raise ConnectorReadOnlyError(
            "SNMP SET is strictly prohibited in read-only mode"
        )

    def walk_extreme_switch(
        self,
        target_ip: str,
        *,
        include_parsed: bool = True,
        include_Parsed: Optional[bool] = None,
    ) -> dict[str, Any]:
        """Perform a read-only SNMP WALK of an Extreme switch and parse port/LLDP/PoE metrics."""
        should_parse = include_Parsed if include_Parsed is not None else include_parsed
        raw_oids = self.walk(target_ip, EXTREME_SWITCH_MIB_OIDS)
        if not should_parse:
            return dict(raw_oids)

        metrics = parse_extreme_switch_oids(raw_oids)
        lldp_sys_prefix = f"{LLDP_REM_SYS_NAME_PREFIX}."
        lldp_port_prefix = f"{LLDP_REM_PORT_ID_PREFIX}."
        lldp_neighbors = [
            str(val) for oid, val in raw_oids.items() if oid.startswith(lldp_sys_prefix)
        ]
        if not lldp_neighbors:
            lldp_neighbors = [
                str(val)
                for oid, val in raw_oids.items()
                if oid.startswith(lldp_port_prefix)
            ]

        peth_admin_prefix = f"{PETH_PSE_PORT_ADMIN_ENABLE_PREFIX}."
        peth_detect_prefix = f"{PETH_PSE_PORT_DETECTION_STATUS_PREFIX}."
        peth_admin_enabled_ports = 0
        peth_delivering_ports = 0
        for oid, val in raw_oids.items():
            if oid.startswith(peth_admin_prefix):
                try:
                    if int(val) == 1:
                        peth_admin_enabled_ports += 1
                except (TypeError, ValueError):
                    pass
            elif oid.startswith(peth_detect_prefix):
                try:
                    # IEEE 802.3af pethPsePortDetectionStatus: 3 = deliveringPower
                    if int(val) == 3:
                        peth_delivering_ports += 1
                except (TypeError, ValueError):
                    if str(val).strip().lower() in {"deliveringpower", "delivering"}:
                        peth_delivering_ports += 1

        metrics["lldp_neighbor_count"] = len(lldp_neighbors)
        metrics["lldp_neighbors"] = lldp_neighbors
        metrics["peth_admin_enabled_ports"] = peth_admin_enabled_ports
        metrics["peth_delivering_ports"] = peth_delivering_ports

        return {
            **raw_oids,
            **metrics,
            "oids": dict(raw_oids),
            "metrics": dict(metrics),
        }

    def walk_apc_ups(
        self,
        target_ip: str,
        *,
        include_parsed: bool = True,
    ) -> dict[str, Any]:
        """Perform a read-only SNMP WALK of an APC UPS and parse PowerNet-MIB metrics."""
        raw_oids = self.walk(target_ip, APC_UPS_MIB_OIDS)
        if not include_parsed:
            return dict(raw_oids)
        metrics = parse_apc_ups_oids(raw_oids)
        return {
            **raw_oids,
            **metrics,
            "oids": dict(raw_oids),
            "metrics": dict(metrics),
        }

    def __call__(
        self,
        target_ip: str,
        oids: Sequence[str] = SNMPV2_MIB_OIDS,
        timeout_seconds: Optional[float] = None,
    ) -> dict[str, Any]:
        """Allow SnmpWalkConnector to be passed directly as snmp_probe_fn to ManagementProbeCollector."""
        return self.query(
            target_ip,
            oids,
            operation="GET",
            timeout_seconds=timeout_seconds,
        )
