"""Drift alert dispatcher, alert targets, default HTTP sender and secret redaction."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
from typing import Any, Optional
import urllib.error
import urllib.parse
import urllib.request

from sot_validator.discovery._monitor_events import SnapshotDiffReport, logger
from sot_validator.models import _require_non_empty_str

DRIFT_TARGET_KINDS: tuple[str, ...] = (
    "json_file",
    "webhook",
    "home_assistant_event",
    "home_assistant_webhook",
)
_URL_TARGET_KINDS: frozenset[str] = frozenset(
    {"webhook", "home_assistant_event", "home_assistant_webhook"}
)
HOME_ASSISTANT_EVENT_TYPE = "sot_validator_drift"

DriftSender = Callable[[str, str, Mapping[str, str], bytes, float], int]


def _has_unsafe_chars(value: str) -> bool:
    """True when the value holds whitespace or control characters (invalid in headers/URLs)."""
    return any(ch.isspace() or not ch.isprintable() for ch in value)


@dataclass
class DriftAlertTarget:
    """Destination for a drift report: JSON file, generic webhook, or Home Assistant."""

    kind: str
    destination: str | os.PathLike[str]
    token: Optional[str] = field(default=None, repr=False)
    name: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or self.kind not in DRIFT_TARGET_KINDS:
            raise ValueError(
                f"Invalid kind: {self.kind!r}; expected one of {DRIFT_TARGET_KINDS}"
            )
        if self.kind == "json_file":
            if not isinstance(self.destination, os.PathLike) and (
                not isinstance(self.destination, str) or not self.destination.strip()
            ):
                raise ValueError("json_file destination must be a non-empty path")
        else:
            if not isinstance(self.destination, str) or not self.destination.strip():
                raise ValueError(f"{self.kind} destination must be a non-empty URL")
            if _has_unsafe_chars(self.destination):
                raise ValueError(
                    f"{self.kind} destination must not contain whitespace or control characters"
                )
            parts = urllib.parse.urlsplit(self.destination.strip())
            if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
                raise ValueError(
                    f"{self.kind} destination must be an http or https URL with a host"
                )
        if self.token is not None and not isinstance(self.token, str):
            raise ValueError("token must be a string or None")
        if self.kind == "home_assistant_event":
            if not self.token or not self.token.strip():
                raise ValueError("home_assistant_event targets require a non-empty token")
            if _has_unsafe_chars(self.token):
                raise ValueError(
                    "home_assistant_event token must not contain whitespace or control characters"
                )
        elif self.token is not None:
            raise ValueError(f"{self.kind} targets do not accept a token")
        if self.name is None:
            self.name = self.kind
        else:
            _require_non_empty_str(self.name, "name")


@dataclass
class DriftDispatchResult:
    """Outcome of sending one drift report to one target (secrets redacted)."""

    name: str
    kind: str
    status: str
    http_status: Optional[int]
    destination: str
    detail: Optional[str]


class _RefuseRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that never follows a redirect, so headers are never forwarded."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _default_sender(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    timeout: float,
) -> int:
    """POST via urllib without following redirects; returns the HTTP status code.

    Standard ``http_proxy``/``https_proxy`` settings apply, so prefer ``https``
    destinations when a bearer token is sent.
    """
    request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
    opener = urllib.request.build_opener(_RefuseRedirectHandler())
    try:
        with opener.open(request, timeout=timeout) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        exc.close()
        return status


def _redacted_destination(target: DriftAlertTarget) -> str:
    if target.kind not in _URL_TARGET_KINDS:
        return os.fspath(target.destination)
    parts = urllib.parse.urlsplit(str(target.destination).strip())
    host_port = parts.netloc.rpartition("@")[2]
    return f"{parts.scheme}://{host_port}"


def _redact(text: str, secrets: Iterable[Optional[str]]) -> str:
    # Also cover the escaped forms that str/bytes reprs put into exception messages.
    forms: set[str] = set()
    for secret in secrets:
        if secret:
            forms.update(
                (
                    secret,
                    repr(secret)[1:-1],
                    repr(secret.encode("utf-8", "backslashreplace"))[2:-1],
                )
            )
    for form in sorted(forms, key=len, reverse=True):
        text = text.replace(form, "***")
    return text


def _drift_payload(report: SnapshotDiffReport) -> dict[str, Any]:
    data = report.to_dict()
    return {
        "source": "sot-validator",
        "event_type": HOME_ASSISTANT_EVENT_TYPE,
        "site_id": data["site_id"],
        "baseline_timestamp": data["baseline_timestamp"],
        "current_timestamp": data["current_timestamp"],
        "highest_severity": data["highest_severity"],
        "event_count": len(data["events"]),
        "summary_counts": data["summary_counts"],
        "events": data["events"],
    }


class DriftAlertDispatcher:
    """Sends a SnapshotDiffReport to JSON file, webhook, and Home Assistant targets."""

    def __init__(
        self,
        targets: Sequence[DriftAlertTarget],
        *,
        sender: Optional[DriftSender] = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        if (
            not isinstance(targets, Sequence)
            or isinstance(targets, (str, bytes))
            or not targets
        ):
            raise ValueError("targets must be a non-empty sequence of DriftAlertTarget")
        for target in targets:
            if not isinstance(target, DriftAlertTarget):
                raise ValueError("targets must contain only DriftAlertTarget instances")
        if sender is not None and not callable(sender):
            raise ValueError("sender must be callable or None")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not timeout_seconds > 0
        ):
            raise ValueError("timeout_seconds must be a number greater than 0")
        self.targets: list[DriftAlertTarget] = list(targets)
        self.sender: DriftSender = sender if sender is not None else _default_sender
        self.timeout_seconds = float(timeout_seconds)

    def __repr__(self) -> str:
        names = ", ".join(f"{t.name}:{t.kind}" for t in self.targets)
        return f"DriftAlertDispatcher(targets=[{names}], timeout_seconds={self.timeout_seconds})"

    def dispatch(self, report: SnapshotDiffReport) -> list[DriftDispatchResult]:
        if not isinstance(report, SnapshotDiffReport):
            raise ValueError("report must be a SnapshotDiffReport instance")
        body = json.dumps(_drift_payload(report)).encode("utf-8")
        return [self._dispatch_one(target, report, body) for target in self.targets]

    def _dispatch_one(
        self, target: DriftAlertTarget, report: SnapshotDiffReport, body: bytes
    ) -> DriftDispatchResult:
        destination = _redacted_destination(target)
        url: Optional[str] = None
        http_status: Optional[int] = None
        try:
            if target.kind == "json_file":
                path = Path(target.destination)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(report.to_json(indent=2), encoding="utf-8")
                detail = None
            else:
                headers = {"Content-Type": "application/json"}
                url = str(target.destination).strip()
                if target.kind == "home_assistant_event":
                    url = f"{url.rstrip('/')}/api/events/{HOME_ASSISTANT_EVENT_TYPE}"
                    headers["Authorization"] = f"Bearer {target.token}"
                status = self.sender("POST", url, headers, body, self.timeout_seconds)
                if isinstance(status, bool) or not isinstance(status, int):
                    raise TypeError("sender must return an integer HTTP status code")
                http_status = status
                detail = None if 200 <= status < 300 else f"HTTP {status}"
        except Exception as exc:  # noqa: BLE001 - one failing target must not stop the rest
            detail = f"{type(exc).__name__}: {exc}"

        if detail is None:
            return DriftDispatchResult(
                name=str(target.name),
                kind=target.kind,
                status="sent",
                http_status=http_status,
                destination=destination,
                detail=None,
            )
        detail = _redact(
            detail,
            (target.token, url, str(target.destination).strip() if url else None),
        )
        logger.warning(
            "Drift alert target %s (%s, %s) failed: %s",
            target.name,
            target.kind,
            destination,
            detail,
        )
        return DriftDispatchResult(
            name=str(target.name),
            kind=target.kind,
            status="failed",
            http_status=http_status,
            destination=destination,
            detail=detail,
        )
