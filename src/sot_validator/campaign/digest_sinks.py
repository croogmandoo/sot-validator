"""Delivery sinks for the weekly change digest: SMTP email and generic webhook.

Sinks only deliver; whether to send is the caller's decision
(`ChangeDigest.should_send`). Runtime delivery failures never raise: `send`
returns a failed `DigestDeliveryResult` with secrets redacted and logs a warning.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import base64
from collections.abc import Sequence
from dataclasses import dataclass
from email.message import EmailMessage
import ipaddress
import json
import logging
import os
import re
import smtplib
import ssl
from typing import Any, Optional
import urllib.parse

from sot_validator.discovery.monitor import (
    DriftAlertTarget,
    DriftSender,
    _default_sender,
    _has_unsafe_chars,
    _redact,
    _redacted_destination,
)
from sot_validator.reporting.digest import (
    ChangeDigest,
    render_digest_html,
    render_digest_text,
)

logger = logging.getLogger(__name__)

DIGEST_EVENT_TYPE = "sot_validator_weekly_digest"
DEFAULT_DIGEST_SUBJECT = "SoT weekly change digest"

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass
class DigestDeliveryResult:
    """Outcome of delivering one digest through one sink (secrets redacted)."""

    name: str
    kind: str
    status: str
    destination: str
    detail: Optional[str]


def _require_timeout(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not value > 0:
        raise ValueError("timeout_seconds must be a number greater than 0")
    return float(value)


def _require_name(value: Any, default: str) -> str:
    if value is None:
        return default
    if not isinstance(value, str) or not value.strip():
        raise ValueError("name must be a non-empty string or None")
    return value


def _require_header_value(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    if "\r" in value or "\n" in value:
        raise ValueError(f"{field_name} must not contain CR or LF characters")
    return value


def _require_env_name(value: Any, field_name: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str) or not _ENV_NAME.fullmatch(value):
        raise ValueError(f"{field_name} must be an environment variable name")
    return value


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class DigestSink(ABC):
    """Abstract base interface for delivering a ChangeDigest."""

    name: str
    kind: str

    @abstractmethod
    def send(self, digest: ChangeDigest) -> DigestDeliveryResult:
        """Deliver the digest; return a failed result instead of raising."""
        raise NotImplementedError

    def _result(self, destination: str, detail: Optional[str]) -> DigestDeliveryResult:
        if detail is not None:
            logger.warning(
                "Digest sink %s (%s, %s) failed: %s",
                self.name,
                self.kind,
                destination,
                detail,
            )
        return DigestDeliveryResult(
            name=self.name,
            kind=self.kind,
            status="sent" if detail is None else "failed",
            destination=destination,
            detail=detail,
        )


def _require_digest(digest: Any) -> ChangeDigest:
    if not isinstance(digest, ChangeDigest):
        raise ValueError("digest must be a ChangeDigest instance")
    return digest


class SmtpDigestSink(DigestSink):
    """Email the digest over SMTP with STARTTLS; credentials come from env vars."""

    kind = "smtp"

    def __init__(
        self,
        host: str,
        port: int,
        sender: str,
        recipients: Sequence[str],
        *,
        username_env: Optional[str] = None,
        password_env: Optional[str] = None,
        starttls: bool = True,
        allow_insecure_localhost: bool = False,
        timeout_seconds: float = 10.0,
        subject: str = DEFAULT_DIGEST_SUBJECT,
        name: Optional[str] = None,
    ) -> None:
        if not isinstance(host, str) or not host or _has_unsafe_chars(host):
            raise ValueError(
                "host must be a non-empty string without whitespace or control characters"
            )
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"port must be an integer from 1 to 65535, got {port!r}")
        _require_header_value(sender, "sender")
        if (
            not isinstance(recipients, Sequence)
            or isinstance(recipients, (str, bytes))
            or not recipients
        ):
            raise ValueError("recipients must be a non-empty sequence of strings")
        for recipient in recipients:
            _require_header_value(recipient, "recipient")
        _require_header_value(subject, "subject")
        username_env = _require_env_name(username_env, "username_env")
        password_env = _require_env_name(password_env, "password_env")
        if (username_env is None) != (password_env is None):
            raise ValueError("username_env and password_env must both be set or both be None")
        if not isinstance(starttls, bool) or not isinstance(allow_insecure_localhost, bool):
            raise ValueError("starttls and allow_insecure_localhost must be booleans")
        if not starttls and not (allow_insecure_localhost and _is_loopback(host)):
            raise ValueError(
                "starttls=False is only allowed with allow_insecure_localhost=True "
                "and a localhost or loopback host"
            )
        self.host = host
        self.port = port
        self.sender = sender
        self.recipients: list[str] = list(recipients)
        self.username_env = username_env
        self.password_env = password_env
        self.starttls = starttls
        self.allow_insecure_localhost = allow_insecure_localhost
        self.timeout_seconds = _require_timeout(timeout_seconds)
        self.subject = subject
        self.name = _require_name(name, self.kind)

    def __repr__(self) -> str:
        return (
            f"SmtpDigestSink(host={self.host!r}, port={self.port}, "
            f"starttls={self.starttls}, username_env={self.username_env!r}, "
            f"password_env={self.password_env!r})"
        )

    __str__ = __repr__

    @property
    def destination(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"smtp://{host}:{self.port}"

    def build_message(self, digest: ChangeDigest) -> EmailMessage:
        _require_digest(digest)
        message = EmailMessage()
        message["From"] = self.sender
        message["To"] = ", ".join(self.recipients)
        message["Subject"] = self.subject
        message.set_content(render_digest_text(digest))
        message.add_alternative(render_digest_html(digest), subtype="html")
        return message

    def _credentials(self) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """Return (username, password, error) read from the configured env vars."""
        if self.username_env is None or self.password_env is None:
            return None, None, None
        values: list[str] = []
        for env_name in (self.username_env, self.password_env):
            value = os.environ.get(env_name)
            if not value:
                return None, None, f"environment variable {env_name} is not set or empty"
            values.append(value)
        return values[0], values[1], None

    def send(self, digest: ChangeDigest) -> DigestDeliveryResult:
        message = self.build_message(digest)
        username, password, error = self._credentials()
        if error is not None:
            return self._result(self.destination, error)
        try:
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout_seconds) as client:
                if self.starttls:
                    client.ehlo()
                    if not client.has_extn("starttls"):
                        raise smtplib.SMTPNotSupportedError(
                            "STARTTLS extension not supported by server"
                        )
                    client.starttls(context=ssl.create_default_context())
                    client.ehlo()
                if username is not None and password is not None:
                    client.login(username, password)
                client.send_message(message)
        except Exception as exc:  # noqa: BLE001 - delivery failures become results
            detail = _redact(
                f"{type(exc).__name__}: {exc}", _smtp_secret_forms(username, password)
            )
            return self._result(self.destination, detail)
        return self._result(self.destination, None)


def _smtp_secret_forms(
    username: Optional[str], password: Optional[str]
) -> list[Optional[str]]:
    """The credentials plus the base64 forms AUTH PLAIN/LOGIN put on the wire."""
    forms: list[Optional[str]] = [username, password]
    if username and password:
        for raw in (username, password, f"\0{username}\0{password}"):
            forms.append(base64.b64encode(raw.encode("utf-8")).decode("ascii"))
    return forms


class WebhookDigestSink(DigestSink):
    """POST the plain-text digest as JSON, reusing the drift dispatcher's sender."""

    kind = "webhook"

    def __init__(
        self,
        url: str,
        *,
        sender: Optional[DriftSender] = None,
        timeout_seconds: float = 10.0,
        name: Optional[str] = None,
    ) -> None:
        # DriftAlertTarget applies the drift dispatcher's http/https-with-host checks.
        self._target = DriftAlertTarget(kind="webhook", destination=url)
        if sender is not None and not callable(sender):
            raise ValueError("sender must be callable or None")
        self._url = url.strip()
        self.sender: DriftSender = sender if sender is not None else _default_sender
        self.timeout_seconds = _require_timeout(timeout_seconds)
        self.name = _require_name(name, self.kind)
        self.destination = _redacted_destination(self._target)

    def __repr__(self) -> str:
        return f"WebhookDigestSink(destination={self.destination!r}, name={self.name!r})"

    __str__ = __repr__

    def _secrets(self) -> list[Optional[str]]:
        parts = urllib.parse.urlsplit(self._url)
        secrets: list[Optional[str]] = [
            self._url,
            parts.netloc.rpartition("@")[0] or None,
            parts.username,
            parts.password,
            parts.query or None,
            parts.fragment or None,
        ]
        if len(parts.path) > 1:
            secrets.append(parts.path)
        return secrets

    def send(self, digest: ChangeDigest) -> DigestDeliveryResult:
        _require_digest(digest)
        payload = {
            "source": "sot-validator",
            "event_type": DIGEST_EVENT_TYPE,
            "text": render_digest_text(digest),
        }
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        try:
            status = self.sender("POST", self._url, headers, body, self.timeout_seconds)
            if isinstance(status, bool) or not isinstance(status, int):
                raise TypeError("sender must return an integer HTTP status code")
            detail = None if 200 <= status < 300 else f"HTTP {status}"
        except Exception as exc:  # noqa: BLE001 - delivery failures become results
            detail = _redact(f"{type(exc).__name__}: {exc}", self._secrets())
        return self._result(self.destination, detail)


__all__ = [
    "DIGEST_EVENT_TYPE",
    "DigestDeliveryResult",
    "DigestSink",
    "SmtpDigestSink",
    "WebhookDigestSink",
]
