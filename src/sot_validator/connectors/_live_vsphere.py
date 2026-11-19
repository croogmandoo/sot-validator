"""Read-only VMware vCenter REST connector with multi-instance inventory caching."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import inspect
import json
import time
from typing import Any, Optional
from urllib.parse import urlsplit

from sot_validator.connectors._live_common import (
    _ALLOWED_READONLY_MODES,
    _ALLOWED_VCENTER_PATH_PREFIXES,
    _BLOCKED_VCENTER_PATH_SEGMENTS,
    ConnectorReadOnlyError,
    RequestTelemetry,
    _validate_timeout_and_retries,
)
from sot_validator.extraction.client import (
    ReadOnlyViolationError as ExtractionReadOnlyViolationError,
    validate_read_only_request,
)
from sot_validator.signals.hypervisor import (
    HypervisorVmRecord,
    MultiVCenterInventoryProvider,
)
from sot_validator.signals.management import ALLOWED_HTTP_METHODS


class VSphereRestConnector:
    """Read-only VMware vCenter REST connector with multi-instance inventory caching."""

    def __init__(
        self,
        instances: Sequence[str | Mapping[str, Any]],
        *,
        auth_token: Optional[str] = None,
        username: Optional[str] = None,
        role: str = "readonly",
        api_mode: str = "readonly",
        timeout_seconds: float = 10.0,
        max_retries: int = 2,
        backoff_seconds: float = 0.0,
        cache_ttl_seconds: Optional[float] = 300.0,
        transport: Optional[Callable[..., Any]] = None,
        clock_fn: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        if not instances:
            raise ValueError("instances must be a non-empty sequence of vCenter targets")

        if (
            not isinstance(api_mode, str)
            or api_mode.strip().lower() not in _ALLOWED_READONLY_MODES
        ):
            raise ConnectorReadOnlyError(
                f"vCenter api_mode {api_mode!r} is forbidden; must be one of {sorted(_ALLOWED_READONLY_MODES)}"
            )
        if (
            not isinstance(role, str)
            or role.strip().lower() not in _ALLOWED_READONLY_MODES
        ):
            raise ConnectorReadOnlyError(
                f"vCenter role {role!r} is forbidden; must be read-only"
            )

        (
            self.timeout_seconds,
            self.max_retries,
            self.backoff_seconds,
        ) = _validate_timeout_and_retries(timeout_seconds, max_retries, backoff_seconds)

        if cache_ttl_seconds is not None:
            if (
                isinstance(cache_ttl_seconds, bool)
                or not isinstance(cache_ttl_seconds, (int, float))
                or cache_ttl_seconds <= 0
            ):
                raise ValueError("cache_ttl_seconds must be None or a number > 0")
            self.cache_ttl_seconds: Optional[float] = float(cache_ttl_seconds)
        else:
            self.cache_ttl_seconds = None

        self.auth_token: Optional[str] = (
            auth_token.strip()
            if isinstance(auth_token, str) and auth_token.strip()
            else None
        )
        self.username: Optional[str] = (
            username.strip() if isinstance(username, str) and username.strip() else None
        )
        self.role: str = role.strip().lower()
        self.api_mode: str = api_mode.strip().lower()
        self._transport = transport
        self._clock_fn = clock_fn
        self._sleep_fn = sleep_fn
        self.telemetry = RequestTelemetry()

        self._instance_configs: dict[str, dict[str, Any]] = {}
        self._instance_order: list[str] = []
        self.unreachable_instances: set[str] = set()

        for item in instances:
            if isinstance(item, str):
                inst_id = item.strip()
                if not inst_id:
                    raise ValueError("vCenter instance hostname must be non-empty")
                if inst_id not in self._instance_configs:
                    self._instance_order.append(inst_id)
                self._instance_configs[inst_id] = {"vcenter_instance": inst_id}
            elif isinstance(item, Mapping):
                inst_mode = item.get("api_mode") or item.get("mode")
                if (
                    inst_mode is not None
                    and str(inst_mode).strip().lower() not in _ALLOWED_READONLY_MODES
                ):
                    raise ConnectorReadOnlyError(
                        f"vCenter instance mode {inst_mode!r} is forbidden; must be read-only"
                    )
                inst_role = item.get("role")
                if (
                    inst_role is not None
                    and str(inst_role).strip().lower() not in _ALLOWED_READONLY_MODES
                ):
                    raise ConnectorReadOnlyError(
                        f"vCenter instance role {inst_role!r} is forbidden; must be read-only"
                    )
                inst_id_raw = (
                    item.get("vcenter_instance")
                    or item.get("host")
                    or item.get("vcenter_host")
                    or item.get("instance")
                    or item.get("name")
                )
                if not isinstance(inst_id_raw, str) or not inst_id_raw.strip():
                    raise ValueError(
                        f"vCenter instance mapping missing 'vcenter_instance' or 'host': {item!r}"
                    )
                inst_id = inst_id_raw.strip()
                if inst_id not in self._instance_configs:
                    self._instance_order.append(inst_id)
                self._instance_configs[inst_id] = dict(item)
                if item.get("reachable") is False or (
                    isinstance(item.get("status"), str)
                    and item["status"].strip().lower()
                    in {"unreachable", "down", "error", "offline"}
                ):
                    self.unreachable_instances.add(inst_id)
            else:
                raise ValueError(f"Unsupported vCenter instance entry: {item!r}")

        self._vm_cache: dict[str, tuple[float, list[HypervisorVmRecord]]] = {}
        self._host_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}

    @property
    def configured_instances(self) -> list[str]:
        """Return ordered list of configured vCenter instance identifiers."""
        return list(self._instance_order)

    def _build_headers(self, instance: str) -> dict[str, str]:
        cfg = self._instance_configs.get(instance, {})
        token = cfg.get("auth_token") or self.auth_token
        headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "sot-validator/0.1 (vsphere-ro)",
        }
        if token:
            headers["vmware-api-session-id"] = str(token)
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _validate_read_only(self, method: str, path_or_url: str) -> tuple[str, str]:
        if not isinstance(method, str) or not method.strip():
            self.telemetry.blocked_mutations += 1
            raise ConnectorReadOnlyError("HTTP method must be a non-empty string")

        normalized_method = method.strip().upper()
        if normalized_method not in ALLOWED_HTTP_METHODS:
            self.telemetry.blocked_mutations += 1
            raise ConnectorReadOnlyError(
                f"vCenter REST method {normalized_method!r} is forbidden in read-only mode; "
                f"only {sorted(ALLOWED_HTTP_METHODS)} are allowed"
            )

        parsed = urlsplit(path_or_url)
        norm_path = parsed.path or "/"
        if not norm_path.startswith("/"):
            norm_path = "/" + norm_path
        path_lower = norm_path.lower().rstrip("/") or "/"

        if not any(
            path_lower == prefix or path_lower.startswith(prefix + "/")
            for prefix in _ALLOWED_VCENTER_PATH_PREFIXES
        ):
            self.telemetry.blocked_mutations += 1
            raise ConnectorReadOnlyError(
                f"vCenter endpoint {norm_path!r} is outside allowed read-only inventory paths "
                f"{_ALLOWED_VCENTER_PATH_PREFIXES}"
            )

        segments = [seg for seg in path_lower.split("/") if seg]
        for seg in segments:
            if seg in _BLOCKED_VCENTER_PATH_SEGMENTS:
                self.telemetry.blocked_mutations += 1
                raise ConnectorReadOnlyError(
                    f"vCenter endpoint {norm_path!r} contains mutating segment {seg!r}"
                )

        try:
            validate_read_only_request(normalized_method, path_or_url)
        except ExtractionReadOnlyViolationError as exc:
            self.telemetry.blocked_mutations += 1
            raise ConnectorReadOnlyError(str(exc)) from exc

        return normalized_method, norm_path

    def _default_urlopen(
        self,
        method: str,
        full_url: str,
        headers: Mapping[str, str],
        timeout: float,
    ) -> Any:
        from sot_validator.connectors import live as _live

        raw_bytes = _live.ReadOnlyHttpGuard().request(
            method, full_url, headers=headers, timeout=timeout
        )
        text = raw_bytes.decode("utf-8", errors="replace").strip()
        return json.loads(text) if text else []

    def _invoke_transport(
        self,
        method: str,
        instance: str,
        norm_path: str,
        full_url: str,
        timeout: float,
    ) -> Any:
        headers = self._build_headers(instance)
        if self._transport is None:
            return self._default_urlopen(method, full_url, headers, timeout)

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

        if len(pos_params) >= 4 or has_varargs:
            raw = self._transport(method, full_url, headers, timeout)
        elif len(pos_params) == 3:
            first_name = pos_params[0].name.lower()
            if first_name in {"instance", "inst", "vcenter", "vcenter_instance", "host"}:
                raw = self._transport(instance, norm_path, timeout)
            else:
                raw = self._transport(method, full_url, timeout)
        elif len(pos_params) == 2:
            first_name = pos_params[0].name.lower()
            second_name = pos_params[1].name.lower()
            if first_name in {
                "instance",
                "inst",
                "vcenter",
                "vcenter_instance",
                "host",
            } or (
                second_name in {"path", "endpoint"}
                and first_name not in {"method", "verb", "http_method"}
            ):
                raw = self._transport(instance, norm_path)
            else:
                raw = self._transport(method, full_url)
        elif len(pos_params) == 1:
            raw = self._transport(full_url)
        else:
            raw = self._transport()

        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        if isinstance(raw, str):
            stripped = raw.strip()
            if stripped.startswith(("{", "[")):
                return json.loads(stripped)
        return raw

    def request(
        self,
        method: str,
        instance: str,
        path: str = "/api/vcenter/vm",
        *,
        timeout_seconds: Optional[float] = None,
    ) -> Any:
        """Issue a read-only vCenter REST API request with retries and telemetry."""
        if not isinstance(instance, str) or not instance.strip():
            raise ValueError("instance must be a non-empty vCenter hostname/identifier")
        clean_instance = instance.strip()

        normalized_method, norm_path = self._validate_read_only(method, path)
        if path.strip().startswith(("http://", "https://")):
            full_url = path.strip()
        else:
            full_url = f"https://{clean_instance}{norm_path}"

        effective_timeout = (
            float(timeout_seconds)
            if timeout_seconds is not None
            else self.timeout_seconds
        )
        if effective_timeout <= 0:
            raise ValueError("timeout_seconds must be > 0")

        self.telemetry.total_requests += 1
        self.telemetry.last_target = full_url

        if (
            self._transport is None
            and clean_instance in self.unreachable_instances
        ):
            self.telemetry.failed_requests += 1
            raise ConnectionError(
                f"vCenter instance {clean_instance!r} is marked unreachable"
            )

        total_attempts = 1 + self.max_retries
        last_exc: Optional[Exception] = None

        for attempt in range(1, total_attempts + 1):
            if attempt > 1:
                self.telemetry.retried_requests += 1
                if self.backoff_seconds > 0:
                    self._sleep_fn(self.backoff_seconds * (2 ** (attempt - 2)))

            start = self._clock_fn()
            try:
                payload = self._invoke_transport(
                    normalized_method,
                    clean_instance,
                    norm_path,
                    full_url,
                    effective_timeout,
                )
            except PermissionError as exc:
                self.telemetry.blocked_mutations += 1
                self.telemetry.failed_requests += 1
                if isinstance(exc, ConnectorReadOnlyError):
                    raise
                raise ConnectorReadOnlyError(str(exc)) from exc
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                continue

            elapsed_ms = round(max(0.0, (self._clock_fn() - start) * 1000.0), 3)
            self.telemetry.latencies_ms.append(elapsed_ms)
            self.telemetry.successful_requests += 1
            return payload

        self.telemetry.failed_requests += 1
        self.unreachable_instances.add(clean_instance)
        assert last_exc is not None
        raise last_exc

    def _is_cache_valid(self, cached_at: float) -> bool:
        if self.cache_ttl_seconds is None:
            return True
        return (self._clock_fn() - cached_at) < self.cache_ttl_seconds

    def _normalize_vm_payload(
        self,
        instance: str,
        raw_payload: Any,
    ) -> list[HypervisorVmRecord]:
        cfg = self._instance_configs.get(instance, {})
        default_site_id = cfg.get("site_id")

        if isinstance(raw_payload, Mapping):
            if "value" in raw_payload and isinstance(raw_payload["value"], Sequence):
                items = raw_payload["value"]
            elif "vms" in raw_payload and isinstance(raw_payload["vms"], Sequence):
                items = raw_payload["vms"]
            elif "vm_moref" in raw_payload or "vm" in raw_payload or "name" in raw_payload:
                items = [raw_payload]
            else:
                items = []
        elif isinstance(raw_payload, Sequence) and not isinstance(
            raw_payload, (str, bytes)
        ):
            items = raw_payload
        else:
            items = []

        records: list[HypervisorVmRecord] = []
        for item in items:
            if isinstance(item, HypervisorVmRecord):
                records.append(item)
            elif isinstance(item, Mapping):
                vm_dict = dict(item)
                if "vm" in vm_dict and "vm_moref" not in vm_dict:
                    vm_dict["vm_moref"] = vm_dict["vm"]
                if default_site_id and not vm_dict.get("site_id"):
                    vm_dict["site_id"] = default_site_id
                records.append(
                    HypervisorVmRecord.from_dict(
                        vm_dict, default_vcenter_instance=instance
                    )
                )
            else:
                raise ValueError(
                    f"Unsupported VM record in vCenter payload for {instance!r}: {item!r}"
                )
        return records

    def _normalize_host_payload(
        self,
        instance: str,
        raw_payload: Any,
    ) -> list[dict[str, Any]]:
        if isinstance(raw_payload, Mapping):
            if "value" in raw_payload and isinstance(raw_payload["value"], Sequence):
                items = raw_payload["value"]
            elif "hosts" in raw_payload and isinstance(raw_payload["hosts"], Sequence):
                items = raw_payload["hosts"]
            else:
                items = [raw_payload]
        elif isinstance(raw_payload, Sequence) and not isinstance(
            raw_payload, (str, bytes)
        ):
            items = raw_payload
        else:
            items = []

        hosts: list[dict[str, Any]] = []
        for item in items:
            if isinstance(item, Mapping):
                entry = dict(item)
                host_id = (
                    entry.get("host")
                    or entry.get("host_id")
                    or entry.get("name")
                    or "host-unknown"
                )
                entry.setdefault("vcenter_instance", instance)
                entry.setdefault("host", str(host_id))
                entry.setdefault(
                    "connection_state",
                    str(entry.get("connection_state") or "CONNECTED"),
                )
                entry.setdefault(
                    "power_state",
                    str(entry.get("power_state") or "POWERED_ON"),
                )
                hosts.append(entry)
        return hosts

    def fetch_vms(
        self,
        instance: Optional[str] = None,
        *,
        force_refresh: bool = False,
    ) -> list[HypervisorVmRecord]:
        """Fetch and cache normalized HypervisorVmRecord objects for one or all vCenters."""
        if instance is not None:
            clean_inst = instance.strip()
            if not force_refresh and clean_inst in self._vm_cache:
                cached_at, cached_vms = self._vm_cache[clean_inst]
                if self._is_cache_valid(cached_at):
                    self.telemetry.cache_hits += 1
                    return list(cached_vms)

            self.telemetry.cache_misses += 1
            raw = self.request("GET", clean_inst, "/api/vcenter/vm")
            records = self._normalize_vm_payload(clean_inst, raw)
            self._vm_cache[clean_inst] = (self._clock_fn(), records)
            self.unreachable_instances.discard(clean_inst)
            return list(records)

        combined: list[HypervisorVmRecord] = []
        for inst_id in self._instance_order:
            try:
                combined.extend(self.fetch_vms(inst_id, force_refresh=force_refresh))
            except ConnectorReadOnlyError:
                raise
            except Exception:  # noqa: BLE001
                self.unreachable_instances.add(inst_id)
        return combined

    def fetch_hosts(
        self,
        instance: Optional[str] = None,
        *,
        force_refresh: bool = False,
    ) -> list[dict[str, Any]]:
        """Fetch and cache ESXi host summaries (`/api/vcenter/host`) for one or all vCenters."""
        if instance is not None:
            clean_inst = instance.strip()
            if not force_refresh and clean_inst in self._host_cache:
                cached_at, cached_hosts = self._host_cache[clean_inst]
                if self._is_cache_valid(cached_at):
                    self.telemetry.cache_hits += 1
                    return [dict(h) for h in cached_hosts]

            self.telemetry.cache_misses += 1
            raw = self.request("GET", clean_inst, "/api/vcenter/host")
            hosts = self._normalize_host_payload(clean_inst, raw)
            self._host_cache[clean_inst] = (self._clock_fn(), hosts)
            self.unreachable_instances.discard(clean_inst)
            return [dict(h) for h in hosts]

        combined: list[dict[str, Any]] = []
        for inst_id in self._instance_order:
            try:
                combined.extend(self.fetch_hosts(inst_id, force_refresh=force_refresh))
            except ConnectorReadOnlyError:
                raise
            except Exception:  # noqa: BLE001
                self.unreachable_instances.add(inst_id)
        return combined

    def invalidate_cache(self, instance: Optional[str] = None) -> None:
        """Clear cached VM and ESXi host inventory for one or all vCenter instances."""
        if instance is None:
            self._vm_cache.clear()
            self._host_cache.clear()
        else:
            clean_inst = instance.strip()
            self._vm_cache.pop(clean_inst, None)
            self._host_cache.pop(clean_inst, None)

    def to_inventory_provider(
        self,
        *,
        force_refresh: bool = False,
    ) -> MultiVCenterInventoryProvider:
        """Build a MultiVCenterInventoryProvider from cached/fetched vCenter VM inventory."""
        vms = self.fetch_vms(force_refresh=force_refresh)
        return MultiVCenterInventoryProvider(
            vms=vms,
            instances=self._instance_order,
            unreachable_instances=self.unreachable_instances,
        )
