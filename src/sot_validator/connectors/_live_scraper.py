"""Read-only authenticated HTTP GET/HEAD session for the legacy SoT web UI."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import inspect
import json
import time
from typing import Any, Optional
from urllib.parse import urljoin

from sot_validator.connectors._live_common import (
    ConnectorReadOnlyError,
    RequestTelemetry,
    _validate_timeout_and_retries,
)
from sot_validator.extraction.client import (
    ReadOnlyViolationError as ExtractionReadOnlyViolationError,
    validate_read_only_request,
)
from sot_validator.signals.management import ALLOWED_HTTP_METHODS


class AuthenticatedScraperSession:
    """HTTP GET/HEAD-only authenticated session wrapper for the legacy SoT web UI."""

    def __init__(
        self,
        base_url: str = "https://sot.internal",
        *,
        headers: Optional[Mapping[str, str]] = None,
        cookies: Optional[Mapping[str, str]] = None,
        session_token: Optional[str] = None,
        timeout_seconds: float = 10.0,
        max_retries: int = 2,
        backoff_seconds: float = 0.0,
        transport: Optional[Callable[..., str | bytes | Mapping[str, Any]]] = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        if not isinstance(base_url, str) or not base_url.strip():
            raise ValueError("base_url must be a non-empty URL string")
        cleaned_url = base_url.strip().rstrip("/")
        if not cleaned_url.startswith(("http://", "https://")):
            raise ValueError(
                f"base_url must start with 'http://' or 'https://', got {base_url!r}"
            )
        (
            self.timeout_seconds,
            self.max_retries,
            self.backoff_seconds,
        ) = _validate_timeout_and_retries(timeout_seconds, max_retries, backoff_seconds)
        self.base_url: str = cleaned_url
        self._headers: dict[str, str] = (
            {str(k): str(v) for k, v in headers.items()} if headers else {}
        )
        self._cookies: dict[str, str] = (
            {str(k): str(v) for k, v in cookies.items()} if cookies else {}
        )
        self.session_token: Optional[str] = (
            session_token.strip()
            if isinstance(session_token, str) and session_token.strip()
            else None
        )
        self._transport = transport
        self._sleep_fn = sleep_fn
        self.telemetry = RequestTelemetry()

    def build_request_headers(self) -> dict[str, str]:
        """Build merged HTTP headers including User-Agent, Cookie, and Authorization."""
        merged: dict[str, str] = {
            "User-Agent": "sot-validator/0.1 (live-pilot; read-only)",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        }
        merged.update(self._headers)
        if self._cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self._cookies.items())
            if "Cookie" in merged and merged["Cookie"]:
                merged["Cookie"] = f"{merged['Cookie']}; {cookie_str}"
            else:
                merged["Cookie"] = cookie_str
        if self.session_token and "Authorization" not in merged:
            merged["Authorization"] = f"Bearer {self.session_token}"
        return merged

    def _resolve_url(self, path_or_url: str) -> str:
        if not isinstance(path_or_url, str) or not path_or_url.strip():
            raise ValueError("path_or_url must be a non-empty string")
        raw = path_or_url.strip()
        if raw.startswith(("http://", "https://")):
            return raw
        if not raw.startswith("/"):
            raw = "/" + raw
        return urljoin(self.base_url + "/", raw.lstrip("/"))

    def _validate_read_only(self, method: str, full_url: str) -> str:
        if not isinstance(method, str) or not method.strip():
            self.telemetry.blocked_mutations += 1
            raise ConnectorReadOnlyError("HTTP method must be a non-empty string")
        normalized_method = method.strip().upper()
        if normalized_method not in ALLOWED_HTTP_METHODS:
            self.telemetry.blocked_mutations += 1
            raise ConnectorReadOnlyError(
                f"HTTP method {normalized_method!r} is forbidden in read-only scraper session; "
                f"only {sorted(ALLOWED_HTTP_METHODS)} are allowed"
            )
        try:
            validate_read_only_request(normalized_method, full_url)
        except ExtractionReadOnlyViolationError as exc:
            self.telemetry.blocked_mutations += 1
            raise ConnectorReadOnlyError(str(exc)) from exc
        return normalized_method

    def _default_urlopen(
        self,
        method: str,
        full_url: str,
        headers: Mapping[str, str],
        timeout: float,
    ) -> str:
        from sot_validator.connectors import live as _live

        raw_bytes = _live.ReadOnlyHttpGuard().request(
            method, full_url, headers=headers, timeout=timeout
        )
        return raw_bytes.decode("utf-8", errors="replace")

    def _invoke_transport(
        self,
        method: str,
        full_url: str,
        timeout: float,
    ) -> str:
        headers = self.build_request_headers()
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
            third_name = pos_params[2].name.lower()
            if "header" in third_name:
                raw = self._transport(method, full_url, headers)
            else:
                raw = self._transport(method, full_url, timeout)
        else:
            raw = self._transport(method, full_url)

        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        if isinstance(raw, Mapping):
            if "body" in raw:
                return str(raw["body"])
            if "text" in raw:
                return str(raw["text"])
            return json.dumps(dict(raw))
        return str(raw)

    def request(
        self,
        method: str,
        path_or_url: str,
        *,
        timeout_seconds: Optional[float] = None,
    ) -> str:
        """Execute a validated GET or HEAD request with timeout, retries, and telemetry."""
        full_url = self._resolve_url(path_or_url)
        normalized_method = self._validate_read_only(method, full_url)

        effective_timeout = (
            float(timeout_seconds)
            if timeout_seconds is not None
            else self.timeout_seconds
        )
        if effective_timeout <= 0:
            raise ValueError("timeout_seconds must be > 0")

        self.telemetry.total_requests += 1
        self.telemetry.last_target = full_url

        total_attempts = 1 + self.max_retries
        last_exc: Optional[Exception] = None

        for attempt in range(1, total_attempts + 1):
            if attempt > 1:
                self.telemetry.retried_requests += 1
                if self.backoff_seconds > 0:
                    self._sleep_fn(self.backoff_seconds * (2 ** (attempt - 2)))

            start = time.monotonic()
            try:
                response_text = self._invoke_transport(
                    normalized_method, full_url, effective_timeout
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

            elapsed_ms = round((time.monotonic() - start) * 1000.0, 3)
            self.telemetry.latencies_ms.append(elapsed_ms)
            self.telemetry.successful_requests += 1
            return response_text

        self.telemetry.failed_requests += 1
        assert last_exc is not None
        raise last_exc

    def get(
        self,
        path_or_url: str,
        *,
        timeout_seconds: Optional[float] = None,
    ) -> str:
        """Perform a read-only HTTP GET request."""
        return self.request("GET", path_or_url, timeout_seconds=timeout_seconds)

    def head(
        self,
        path_or_url: str,
        *,
        timeout_seconds: Optional[float] = None,
    ) -> str:
        """Perform a read-only HTTP HEAD request."""
        return self.request("HEAD", path_or_url, timeout_seconds=timeout_seconds)

    def __call__(self, method: str, path_or_url: str) -> str:
        """Allow AuthenticatedScraperSession to act directly as HtmlScraperSoTClient transport."""
        return self.request(method, path_or_url)

    def check_health(self, path: str = "/sites") -> bool:
        """Perform a read-only GET probe against `path` and return True when reachable."""
        try:
            body = self.get(path)
            return bool(body and body.strip())
        except ConnectorReadOnlyError:
            raise
        except Exception:  # noqa: BLE001
            return False
