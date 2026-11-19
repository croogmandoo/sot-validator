"""Scoped read-only SNMP and HTTPS/TCP management probe collector."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import inspect
import ipaddress
import pathlib
import threading
from typing import Any, Callable, Mapping, Optional, Sequence

from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    SignalStatus,
    SignalType,
    Site,
    Subnet,
    ValidationSignal,
)
from sot_validator.signals._management_common import (
    APC_ENTERPRISE_OID_PREFIX,
    APC_POWERNET_MIB_OIDS,
    EXTREME_ENTERPRISE_OID_PREFIX,
    EXTREME_MIB_OIDS,
    IF_MIB_OIDS,
    IP_MIB_OIDS,
    SNMPV2_MIB_OIDS,
    SNMPV2_MIB_SYS_DESCR,
    SNMPV2_MIB_SYS_NAME,
    SNMPV2_MIB_SYS_UPTIME,
    FixtureManagementTransport,
    HttpsProbeResponse,
    ReadOnlyViolationError,
    parse_apc_ups_oids,
    parse_extreme_switch_oids,
    validate_readonly_http_method,
    validate_readonly_snmp_request,
)
from sot_validator.signals.icmp import (
    ScopeViolationError,
    SubnetScopeGuard,
    _parse_allocated_slash24,
    _parse_ipv4_host,
)


class ManagementProbeCollector:
    """Scoped read-only SNMP and HTTPS/TCP management reachability signal collector.

    Tailored for:
    - Extreme Networks switches (`SNMPv2-MIB`, `EXTREME-SYSTEM-MIB`, `EXTREME-POE-MIB`, `IF-MIB`, `IP-MIB`)
    - APC UPS units (`SNMPv2-MIB`, APC `PowerNet-MIB`, and management card HTTPS reachability)
    - General servers / SANs (SNMP and HTTPS/TCP management reachability)
    """

    def __init__(
        self,
        *,
        max_concurrency: int = 16,
        timeout_seconds: float = 2.0,
        retries: int = 2,
        snmp_probe_fn: Optional[Callable[..., Optional[Mapping[str, Any]]]] = None,
        https_probe_fn: Optional[Callable[..., bool | HttpsProbeResponse]] = None,
        transport: Optional[FixtureManagementTransport] = None,
        scope_guard: Optional[SubnetScopeGuard] = None,
        snmp_mode: str = "readonly",
        snmp_operation: str = "GET",
        http_method: str = "GET",
        source: str = "management_probe",
    ) -> None:
        if isinstance(max_concurrency, bool) or not isinstance(max_concurrency, int) or max_concurrency < 1:
            raise ValueError("max_concurrency must be an integer >= 1")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a number > 0")
        if isinstance(retries, bool) or not isinstance(retries, int) or retries < 0:
            raise ValueError("retries must be an integer >= 0")

        validate_readonly_snmp_request(operation=snmp_operation, mode=snmp_mode)
        validate_readonly_http_method(http_method)

        self.max_concurrency: int = max_concurrency
        self.timeout_seconds: float = float(timeout_seconds)
        self.retries: int = retries
        self.snmp_mode: str = snmp_mode
        self.snmp_operation: str = snmp_operation.upper()
        self.http_method: str = http_method.upper()
        self.transport: Optional[FixtureManagementTransport] = transport
        self._snmp_probe_fn = snmp_probe_fn
        self._https_probe_fn = https_probe_fn
        self.scope_guard: Optional[SubnetScopeGuard] = (
            scope_guard
            if scope_guard is not None
            else (transport.build_scope_guard() if transport is not None else None)
        )
        self.source: str = source
        self._semaphore = threading.BoundedSemaphore(self.max_concurrency)

    @classmethod
    def from_fixture_file(
        cls,
        fixture_path: str | pathlib.Path,
        *,
        max_concurrency: Optional[int] = None,
        timeout_seconds: Optional[float] = None,
        retries: Optional[int] = None,
        https_probe_fn: Optional[Callable[..., bool | HttpsProbeResponse]] = None,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> ManagementProbeCollector:
        """Create a ManagementProbeCollector loaded from an SNMP discovery fixture JSON file."""
        transport = FixtureManagementTransport.from_file(fixture_path)
        profile = transport.snmp_profile
        resolved_timeout = (
            timeout_seconds
            if timeout_seconds is not None
            else float(profile.get("timeout_seconds", 2.0))
        )
        resolved_retries = (
            retries if retries is not None else int(profile.get("retries", 2))
        )
        return cls(
            max_concurrency=max_concurrency if max_concurrency is not None else 16,
            timeout_seconds=resolved_timeout,
            retries=resolved_retries,
            transport=transport,
            https_probe_fn=https_probe_fn,
            scope_guard=scope_guard,
            snmp_mode=str(profile.get("mode", "readonly")),
        )

    def _resolve_scope_guard(
        self,
        site: Optional[Site] = None,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> Optional[SubnetScopeGuard]:
        if scope_guard is not None:
            return scope_guard
        if site is not None:
            return SubnetScopeGuard.from_site(site)
        return self.scope_guard

    def validate_target_ip(
        self,
        ip: str,
        *,
        site: Optional[Site] = None,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> str:
        """Validate a target IP against the /24 subnet scope guard or raise ScopeViolationError."""
        guard = self._resolve_scope_guard(site=site, scope_guard=scope_guard)
        if guard is not None:
            return guard.validate_target_ip(ip)
        return str(_parse_ipv4_host(ip))

    def validate_cidr_scope(
        self,
        cidr: str | Subnet,
        *,
        site: Optional[Site] = None,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> ipaddress.IPv4Network:
        """Validate a CIDR block for active management probing; rejects /16 or unallocated /24 sweeps."""
        guard = self._resolve_scope_guard(site=site, scope_guard=scope_guard)
        if guard is not None:
            return guard.validate_cidr_scope(cidr)
        return _parse_allocated_slash24(cidr)

    def execute_snmp_query(
        self,
        target_ip: str,
        oids: Sequence[str] = SNMPV2_MIB_OIDS,
        *,
        operation: Optional[str] = None,
        mode: Optional[str] = None,
        site: Optional[Site] = None,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> Optional[Mapping[str, Any]]:
        """Execute a validated read-only SNMP query; rejects SET operations or write modes."""
        validate_readonly_snmp_request(
            operation=operation or self.snmp_operation,
            mode=mode or self.snmp_mode,
        )
        normalized_ip = self.validate_target_ip(
            target_ip, site=site, scope_guard=scope_guard
        )
        return self._call_snmp_transport(normalized_ip, oids)

    def _call_snmp_transport(
        self,
        normalized_ip: str,
        oids: Sequence[str],
    ) -> Optional[Mapping[str, Any]]:
        validate_readonly_snmp_request(
            operation=self.snmp_operation,
            mode=self.snmp_mode,
        )
        if self._snmp_probe_fn is not None:
            with self._semaphore:
                sig = inspect.signature(self._snmp_probe_fn)
                params = [
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
                if len(params) >= 3 or has_varargs:
                    return self._snmp_probe_fn(
                        normalized_ip, list(oids), self.timeout_seconds
                    )
                if len(params) == 2:
                    return self._snmp_probe_fn(normalized_ip, self.timeout_seconds)
                return self._snmp_probe_fn(normalized_ip)

        if self.transport is not None:
            with self._semaphore:
                return self.transport.query_snmp(
                    normalized_ip,
                    self.timeout_seconds,
                    operation=self.snmp_operation,
                )

        return None

    def _call_https_transport(
        self,
        normalized_ip: str,
    ) -> Optional[HttpsProbeResponse]:
        validate_readonly_http_method(self.http_method)
        if self._https_probe_fn is None:
            return None
        with self._semaphore:
            sig = inspect.signature(self._https_probe_fn)
            params = [
                p
                for p in sig.parameters.values()
                if p.kind
                in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                )
            ]
            if len(params) >= 2:
                raw = self._https_probe_fn(normalized_ip, self.timeout_seconds)
            else:
                raw = self._https_probe_fn(normalized_ip)

        if isinstance(raw, HttpsProbeResponse):
            return raw
        return HttpsProbeResponse(reachable=bool(raw))

    @staticmethod
    def _is_extreme_switch(
        device: Optional[NetworkDevice],
        oids: Mapping[str, Any],
    ) -> bool:
        if device is not None and device.vendor and "extreme" in device.vendor.lower():
            return True
        sys_descr = str(oids.get(SNMPV2_MIB_SYS_DESCR, "")).lower()
        if "extreme" in sys_descr:
            return True
        return any(k.startswith(f"{EXTREME_ENTERPRISE_OID_PREFIX}.") for k in oids)

    @staticmethod
    def _is_apc_ups(
        equipment: Optional[Equipment],
        oids: Mapping[str, Any],
    ) -> bool:
        if equipment is not None and equipment.category is EquipmentCategory.UPS:
            return True
        sys_descr = str(oids.get(SNMPV2_MIB_SYS_DESCR, "")).lower()
        if "apc" in sys_descr or "smart-ups" in sys_descr:
            return True
        return any(k.startswith(f"{APC_ENTERPRISE_OID_PREFIX}.") for k in oids)

    @staticmethod
    def _format_extreme_details(
        ip: str,
        metrics: Mapping[str, Any],
        attempt: int,
        total_attempts: int,
    ) -> str:
        return (
            f"Extreme Networks SNMP GET active on {ip} "
            f"(sysName={metrics['sys_name']}, os_version={metrics['os_version']}, "
            f"serial={metrics['serial_number']}, sysUpTime={metrics['sys_uptime']}, "
            f"ports_up={metrics['ports_up']}/{metrics['ports_total']}, "
            f"ports_down={metrics['ports_down']}, "
            f"poe_active_ports={metrics['poe_active_ports']}, "
            f"poe_power_mw={metrics['poe_total_mw']} ({metrics['poe_total_watts']}W), "
            f"arp_entries={metrics['arp_entries']}, "
            f"attempt={attempt}/{total_attempts})"
        )

    @staticmethod
    def _format_apc_details(
        ip: str,
        metrics: Mapping[str, Any],
        attempt: int,
        total_attempts: int,
    ) -> str:
        return (
            f"APC UPS SNMP GET active on {ip} "
            f"(sysName={metrics['sys_name']}, model={metrics['model']}, "
            f"status={metrics['output_status']}, online={metrics['on_line']}, "
            f"battery_capacity={metrics['battery_capacity_pct']}%, "
            f"output_load={metrics['output_load_pct']}%, "
            f"sysUpTime={metrics['sys_uptime']}, "
            f"attempt={attempt}/{total_attempts})"
        )

    @staticmethod
    def _format_generic_snmp_details(
        ip: str,
        oids: Mapping[str, Any],
        attempt: int,
        total_attempts: int,
    ) -> str:
        sys_name = oids.get(SNMPV2_MIB_SYS_NAME, "unknown")
        sys_descr = oids.get(SNMPV2_MIB_SYS_DESCR, "unknown")
        sys_uptime = oids.get(SNMPV2_MIB_SYS_UPTIME, "unknown")
        return (
            f"SNMP GET active on {ip} "
            f"(sysName={sys_name}, sysDescr={sys_descr}, sysUpTime={sys_uptime}, "
            f"attempt={attempt}/{total_attempts})"
        )

    def _probe_single_ip(
        self,
        normalized_ip: str,
        *,
        device: Optional[NetworkDevice] = None,
        equipment: Optional[Equipment] = None,
        requested_oids: Sequence[str] = SNMPV2_MIB_OIDS,
    ) -> ValidationSignal:
        total_attempts = 1 + self.retries
        last_error: Optional[Exception] = None
        had_timeout_or_empty = False

        for attempt in range(1, total_attempts + 1):
            snmp_oids: Optional[Mapping[str, Any]] = None
            try:
                snmp_oids = self._call_snmp_transport(normalized_ip, requested_oids)
            except ReadOnlyViolationError:
                raise
            except TimeoutError:
                had_timeout_or_empty = True
            except Exception as exc:  # noqa: BLE001
                last_error = exc

            if snmp_oids:
                if self._is_extreme_switch(device, snmp_oids):
                    metrics = parse_extreme_switch_oids(snmp_oids)
                    details = self._format_extreme_details(
                        normalized_ip, metrics, attempt, total_attempts
                    )
                elif self._is_apc_ups(equipment, snmp_oids):
                    metrics = parse_apc_ups_oids(snmp_oids)
                    details = self._format_apc_details(
                        normalized_ip, metrics, attempt, total_attempts
                    )
                else:
                    details = self._format_generic_snmp_details(
                        normalized_ip, snmp_oids, attempt, total_attempts
                    )
                return ValidationSignal(
                    signal_type=SignalType.SNMP_API_REACHABILITY,
                    status=SignalStatus.ACTIVE,
                    observed_at=datetime.now(timezone.utc),
                    age_seconds=0.0,
                    details=details,
                    source=self.source,
                )

            # Fallback to read-only HTTPS management card / BMC probe when configured
            https_resp: Optional[HttpsProbeResponse] = None
            try:
                https_resp = self._call_https_transport(normalized_ip)
            except ReadOnlyViolationError:
                raise
            except TimeoutError:
                had_timeout_or_empty = True
            except Exception as exc:  # noqa: BLE001
                last_error = exc

            if https_resp is not None and https_resp.reachable:
                status_part = (
                    f", status_code={https_resp.status_code}"
                    if https_resp.status_code is not None
                    else ""
                )
                extra_part = f" [{https_resp.detail}]" if https_resp.detail else ""
                target_kind = (
                    "APC NMC HTTPS"
                    if equipment is not None and equipment.category is EquipmentCategory.UPS
                    else "HTTPS management"
                )
                return ValidationSignal(
                    signal_type=SignalType.SNMP_API_REACHABILITY,
                    status=SignalStatus.ACTIVE,
                    observed_at=datetime.now(timezone.utc),
                    age_seconds=0.0,
                    details=(
                        f"{target_kind} reachable on {normalized_ip}:{https_resp.port}"
                        f"{status_part} (attempt={attempt}/{total_attempts}){extra_part}"
                    ),
                    source=self.source,
                )

            if snmp_oids is None and (https_resp is None or not https_resp.reachable):
                if last_error is None:
                    had_timeout_or_empty = True

        if last_error is not None and not had_timeout_or_empty:
            return ValidationSignal(
                signal_type=SignalType.SNMP_API_REACHABILITY,
                status=SignalStatus.ERROR,
                observed_at=datetime.now(timezone.utc),
                age_seconds=0.0,
                details=(
                    f"Management probe error for {normalized_ip} after {total_attempts} "
                    f"attempt(s): {type(last_error).__name__}: {last_error}"
                ),
                source=self.source,
            )

        return ValidationSignal(
            signal_type=SignalType.SNMP_API_REACHABILITY,
            status=SignalStatus.UNREACHABLE,
            observed_at=datetime.now(timezone.utc),
            age_seconds=0.0,
            details=(
                f"SNMP/HTTPS management unreachable for {normalized_ip} after "
                f"{total_attempts} attempt(s) (timeout={self.timeout_seconds}s)"
            ),
            source=self.source,
        )

    def collect_for_device(
        self,
        device: NetworkDevice,
        site: Optional[Site] = None,
        *,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> ValidationSignal:
        """Evaluate SNMP/HTTPS management reachability for a NetworkDevice (e.g. Extreme switch)."""
        if device.management_ip is None or not device.management_ip.strip():
            return ValidationSignal(
                signal_type=SignalType.SNMP_API_REACHABILITY,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=datetime.now(timezone.utc),
                details=f"NetworkDevice {device.device_id} ({device.hostname}) has no management_ip",
                source=self.source,
            )

        try:
            normalized_ip = self.validate_target_ip(
                device.management_ip, site=site, scope_guard=scope_guard
            )
        except ScopeViolationError as exc:
            return ValidationSignal(
                signal_type=SignalType.SNMP_API_REACHABILITY,
                status=SignalStatus.ERROR,
                observed_at=datetime.now(timezone.utc),
                details=f"Scope guard rejected management_ip {device.management_ip!r}: {exc}",
                source=self.source,
            )

        is_extreme = bool(device.vendor and "extreme" in device.vendor.lower())
        oids_to_query: tuple[str, ...] = (
            SNMPV2_MIB_OIDS + EXTREME_MIB_OIDS + IF_MIB_OIDS + IP_MIB_OIDS
            if is_extreme
            else SNMPV2_MIB_OIDS + IF_MIB_OIDS + IP_MIB_OIDS
        )
        return self._probe_single_ip(
            normalized_ip,
            device=device,
            requested_oids=oids_to_query,
        )

    def collect_for_equipment(
        self,
        equipment: Equipment,
        site: Optional[Site] = None,
        *,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> ValidationSignal:
        """Evaluate SNMP/HTTPS management reachability for an Equipment record (APC UPS, Server, SAN)."""
        clean_ips = [ip.strip() for ip in equipment.assigned_ips if ip and ip.strip()]
        if not clean_ips:
            return ValidationSignal(
                signal_type=SignalType.SNMP_API_REACHABILITY,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=datetime.now(timezone.utc),
                details=f"Equipment {equipment.equipment_id} ({equipment.name}) has no assigned_ips",
                source=self.source,
            )

        if equipment.category is EquipmentCategory.UPS:
            requested_oids: tuple[str, ...] = SNMPV2_MIB_OIDS + APC_POWERNET_MIB_OIDS
        else:
            requested_oids = SNMPV2_MIB_OIDS

        signals: list[ValidationSignal] = []
        for raw_ip in clean_ips:
            try:
                normalized_ip = self.validate_target_ip(
                    raw_ip, site=site, scope_guard=scope_guard
                )
            except ScopeViolationError as exc:
                signals.append(
                    ValidationSignal(
                        signal_type=SignalType.SNMP_API_REACHABILITY,
                        status=SignalStatus.ERROR,
                        observed_at=datetime.now(timezone.utc),
                        details=f"Scope guard rejected assigned_ip {raw_ip!r}: {exc}",
                        source=self.source,
                    )
                )
                continue

            sig = self._probe_single_ip(
                normalized_ip,
                equipment=equipment,
                requested_oids=requested_oids,
            )
            if sig.status is SignalStatus.ACTIVE:
                return sig
            signals.append(sig)

        for sig in signals:
            if sig.status is SignalStatus.ERROR:
                return sig

        if equipment.category is EquipmentCategory.VM:
            return ValidationSignal(
                signal_type=SignalType.SNMP_API_REACHABILITY,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=datetime.now(timezone.utc),
                details=(
                    f"VM {equipment.equipment_id} ({equipment.name}) has no dedicated "
                    "SNMP/HTTPS management responder (validated via vCenter/ARP/ICMP)"
                ),
                source=self.source,
            )

        return signals[0]

    def collect_for_ip(
        self,
        ip_record: IPAddress | str,
        site: Optional[Site] = None,
        *,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> ValidationSignal:
        """Evaluate SNMP/HTTPS management reachability for a single IPAddress or IP string."""
        raw_ip = ip_record.ip if isinstance(ip_record, IPAddress) else ip_record
        if raw_ip is None or not str(raw_ip).strip():
            return ValidationSignal(
                signal_type=SignalType.SNMP_API_REACHABILITY,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=datetime.now(timezone.utc),
                details="No IP address provided for management probe",
                source=self.source,
            )

        try:
            normalized_ip = self.validate_target_ip(
                str(raw_ip), site=site, scope_guard=scope_guard
            )
        except ScopeViolationError as exc:
            return ValidationSignal(
                signal_type=SignalType.SNMP_API_REACHABILITY,
                status=SignalStatus.ERROR,
                observed_at=datetime.now(timezone.utc),
                details=f"Scope guard rejected IP {raw_ip!r}: {exc}",
                source=self.source,
            )

        return self._probe_single_ip(normalized_ip, requested_oids=SNMPV2_MIB_OIDS)

    def collect_site(
        self,
        site: Site,
        *,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> dict[str, ValidationSignal]:
        """Collect management reachability signals concurrently across all devices and equipment in a Site."""
        guard = scope_guard or self.scope_guard or SubnetScopeGuard.from_site(site)
        results: dict[str, ValidationSignal] = {}

        with ThreadPoolExecutor(max_workers=self.max_concurrency) as executor:
            future_to_key = {}
            for dev in site.devices:
                fut = executor.submit(
                    self.collect_for_device, dev, scope_guard=guard
                )
                future_to_key[fut] = dev.device_id
            for eq in site.equipment:
                fut = executor.submit(
                    self.collect_for_equipment, eq, scope_guard=guard
                )
                future_to_key[fut] = eq.equipment_id

            for fut in as_completed(future_to_key):
                item_id = future_to_key[fut]
                results[item_id] = fut.result()

        ordered_ids = [d.device_id for d in site.devices] + [
            e.equipment_id for e in site.equipment
        ]
        return {item_id: results[item_id] for item_id in ordered_ids}
