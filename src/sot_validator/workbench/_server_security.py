"""Workbench bearer-token, Host-guard, bind-scope and hardening-header policy."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import ipaddress
import secrets
from typing import Any, Optional

_BEARER_PREFIX = "Bearer "
_DEFAULT_MAX_BODY_BYTES = 1_048_576

# The page is one self-contained inline document, so inline script/style is
# required; the constraint is that no third-party origin can be loaded.
_CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'"
)

_SECURITY_RESPONSE_HEADERS: tuple[tuple[str, str], ...] = (
    ("Content-Security-Policy", _CSP_POLICY),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
)

_LOOPBACK_HOSTNAMES = frozenset({"localhost"})
_DEFAULT_ALLOWED_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _is_loopback_host(host: str) -> bool:
    """Return True for `localhost`, an address in 127.0.0.0/8, or `::1`."""
    if not isinstance(host, str):
        return False
    if host.lower() in _LOOPBACK_HOSTNAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_valid_token(token: Any) -> bool:
    """Return True when `token` can travel verbatim in an `Authorization` header."""
    return (
        isinstance(token, str)
        and bool(token)
        and all("\x21" <= char <= "\x7e" for char in token)
    )


def _normalize_host_name(name: str) -> str:
    """Lowercase a host name and strip IPv6 literal brackets."""
    return name.strip("[]").lower()


def _host_header_name(value: str) -> Optional[str]:
    """Return the host name from a `Host` header value, ignoring any port."""
    if value.startswith("["):
        closing = value.find("]")
        if closing == -1:
            return None
        rest = value[closing + 1:]
        if rest and not rest.startswith(":"):
            return None
        name = value[1:closing]
    else:
        name = value.partition(":")[0]
    return name.lower() or None


@dataclass
class WorkbenchSecurityConfig:
    """Bearer-token, bind-scope and request-size policy for workbench writes."""

    token: Optional[str] = None
    allow_remote: bool = False
    max_body_bytes: int = _DEFAULT_MAX_BODY_BYTES
    allowed_hosts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.allowed_hosts, str) or not isinstance(
            self.allowed_hosts, Iterable
        ):
            raise ValueError("allowed_hosts must be an iterable of host names")
        normalized_hosts: list[str] = []
        for name in self.allowed_hosts:
            if not isinstance(name, str):
                raise ValueError("allowed_hosts entries must be strings")
            normalized = _normalize_host_name(name)
            if not normalized:
                raise ValueError("allowed_hosts entries must be non-empty host names")
            normalized_hosts.append(normalized)
        self.allowed_hosts = tuple(normalized_hosts)
        if (
            isinstance(self.max_body_bytes, bool)
            or not isinstance(self.max_body_bytes, int)
            or self.max_body_bytes <= 0
        ):
            raise ValueError("max_body_bytes must be a positive integer")
        if self.token is None:
            self.token = secrets.token_urlsafe(32)
        elif not _is_valid_token(self.token):
            # Never echo the supplied value: it is a secret.
            raise ValueError(
                "token must be a non-empty string of printable ASCII characters "
                "without whitespace"
            )


class WorkbenchBindRefusedError(ValueError):
    """Raised when the workbench refuses to bind to a non-loopback host."""
