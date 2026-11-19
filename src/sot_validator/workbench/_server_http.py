"""Workbench threaded HTTP server, request handler and server factory."""

from __future__ import annotations

from collections.abc import Mapping
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from sot_validator.curation.bulk import BulkApplyRefused, PatchCsvError
from sot_validator.topology.graph import TopologyGraphBuilder
from sot_validator.workbench._server_common import (
    WorkbenchNotFoundError,
    _bulk_csv_fields,
    _optional_str,
)
from sot_validator.workbench._server_security import (
    _BEARER_PREFIX,
    _DEFAULT_ALLOWED_HOSTS,
    _SECURITY_RESPONSE_HEADERS,
    WorkbenchBindRefusedError,
    WorkbenchSecurityConfig,
    _host_header_name,
    _is_loopback_host,
    _normalize_host_name,
)
from sot_validator.workbench._server_state import WorkbenchState
from sot_validator.workbench.quality_view import build_quality_payload
from sot_validator.workbench.ui import render_workbench_html


class WorkbenchServer(ThreadingHTTPServer):
    """Standard-library threaded HTTP server hosting the interactive workbench."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        state: WorkbenchState,
        RequestHandlerClass: type[BaseHTTPRequestHandler] = None,  # type: ignore[assignment]
        *,
        security: Optional[WorkbenchSecurityConfig] = None,
    ) -> None:
        if not isinstance(state, WorkbenchState):
            raise ValueError("state must be a WorkbenchState instance")
        if security is None:
            security = WorkbenchSecurityConfig()
        if not isinstance(security, WorkbenchSecurityConfig):
            raise ValueError("security must be a WorkbenchSecurityConfig instance")
        bind_host = server_address[0]
        if not security.allow_remote and not _is_loopback_host(bind_host):
            raise WorkbenchBindRefusedError(
                f"Refusing to bind the workbench to non-loopback host {bind_host!r}; "
                "use WorkbenchSecurityConfig(allow_remote=True) to override"
            )
        self.state = state
        self._security = security
        bound_name = _normalize_host_name(str(bind_host))
        self._allowed_hosts = (
            _DEFAULT_ALLOWED_HOSTS
            | ({bound_name} if bound_name else set())
            | set(security.allowed_hosts)
        )
        handler_cls = RequestHandlerClass or WorkbenchRequestHandler
        super().__init__(server_address, handler_cls)

    @property
    def security(self) -> WorkbenchSecurityConfig:
        """Bearer-token, bind-scope and body-size policy for this server."""
        return self._security

    @property
    def allowed_hosts(self) -> frozenset[str]:
        """Effective `Host` header allowlist: loopback names, bound host, extras."""
        return self._allowed_hosts


class WorkbenchRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler serving the workbench UI and JSON REST API."""

    server: WorkbenchServer  # type: ignore[assignment]

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy default stderr logging during automated runs/tests
        return

    def end_headers(self) -> None:
        # Single place every response (success or error) picks up hardening headers.
        for name, value in _SECURITY_RESPONSE_HEADERS:
            self.send_header(name, value)
        super().end_headers()

    def _send_json(
        self,
        status_code: int,
        payload: Mapping[str, Any],
        *,
        close_connection: bool = False,
    ) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        if close_connection:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, status_code: int, html_text: str) -> None:
        raw = html_text.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> dict[str, Any]:
        content_length_str = self.headers.get("Content-Length")
        if not content_length_str:
            raise ValueError("Request body is required")
        try:
            length = int(content_length_str)
        except ValueError as exc:
            raise ValueError("Invalid Content-Length header") from exc
        if length <= 0:
            raise ValueError("Request body must not be empty")
        raw_bytes = self.rfile.read(length)
        try:
            parsed = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid JSON payload: {exc}") from exc
        if not isinstance(parsed, Mapping):
            raise ValueError("JSON body must be an object")
        return dict(parsed)

    def _token_authorized(self) -> bool:
        header = self.headers.get("Authorization") or ""
        if not header.startswith(_BEARER_PREFIX):
            return False
        supplied = header[len(_BEARER_PREFIX):].encode("utf-8", "replace")
        expected = str(self.server.security.token).encode("utf-8")
        return hmac.compare_digest(supplied, expected)

    def _expected_origin(self) -> Optional[str]:
        host = self.headers.get("Host")
        if not host:
            return None
        return f"http://{host.strip()}"

    def _origin_authorized(self) -> bool:
        expected = self._expected_origin()
        origin = self.headers.get("Origin")
        if origin is not None:
            return expected is not None and origin == expected
        referer = self.headers.get("Referer")
        if referer is not None:
            if expected is None:
                return False
            try:
                parsed_referer = urlparse(referer)
            except ValueError:
                return False
            if not parsed_referer.netloc:
                return False
            return f"{parsed_referer.scheme}://{parsed_referer.netloc}" == expected
        return True

    def _body_size_authorized(self) -> bool:
        content_length = self.headers.get("Content-Length")
        if not content_length:
            return True
        try:
            length = int(content_length)
        except ValueError:
            return True
        return length <= self.server.security.max_body_bytes

    def _host_authorized(self) -> bool:
        """Check `Host` against the allowlist; send a 403 and return False on failure."""
        values = self.headers.get_all("Host") or []
        name = _host_header_name(values[0].strip()) if len(values) == 1 else None
        if name is not None and name in self.server.allowed_hosts:
            return True
        self._send_json(
            403,
            {"status": "error", "error": "Host not allowed"},
            close_connection=True,
        )
        return False

    def _authorize_mutation(self) -> bool:
        """Run token, origin and body-size checks; send the rejection and return False on failure."""
        if not self._token_authorized():
            self._send_json(
                401, {"status": "error", "error": "Missing or invalid bearer token"}
            )
            return False
        if not self._origin_authorized():
            self._send_json(
                403, {"status": "error", "error": "Cross-origin write rejected"}
            )
            return False
        if not self._body_size_authorized():
            self._send_json(
                413,
                {"status": "error", "error": "Request body too large"},
                close_connection=True,
            )
            return False
        return True

    def _reject_unsupported_mutation(self) -> None:
        if not self._host_authorized():
            return
        if not self._authorize_mutation():
            return
        self._send_json(
            405,
            {"status": "error", "error": "Method not allowed"},
            close_connection=True,
        )

    def do_GET(self) -> None:
        if not self._host_authorized():
            return
        parsed_url = urlparse(self.path)
        route = parsed_url.path.rstrip("/") or "/"
        query = parse_qs(parsed_url.query)

        try:
            if route in ("/", "/index.html"):
                html_doc = render_workbench_html(self.server.state)
                self._send_html(200, html_doc)
                return

            if route == "/api/health":
                self._send_json(200, {"status": "ok"})
                return

            if route == "/api/state":
                limit = 50
                if "audit_limit" in query and query["audit_limit"]:
                    limit = int(query["audit_limit"][0])
                self._send_json(
                    200, self.server.state.get_state_payload(audit_limit=limit)
                )
                return

            if route == "/api/topology":
                with self.server.state._lock:
                    graph = TopologyGraphBuilder().build(
                        self.server.state.site, self.server.state.results
                    )
                    payload = graph.to_dict()
                    payload["mermaid"] = graph.to_mermaid()
                self._send_json(200, payload)
                return

            if route == "/api/quality":
                rule = query["rule"][0] if query.get("rule") else None
                severity = query["severity"][0] if query.get("severity") else None
                with self.server.state._lock:
                    payload = build_quality_payload(
                        self.server.state.site, rule=rule, severity=severity
                    )
                self._send_json(200, payload)
                return

            if route == "/api/audit-log":
                limit = 100
                if "limit" in query and query["limit"]:
                    limit = int(query["limit"][0])
                site_id: Optional[str] = self.server.state.site.site_id
                if "site_id" in query and query["site_id"]:
                    raw_site = query["site_id"][0].strip()
                    site_id = raw_site if raw_site else None
                with self.server.state._lock:
                    entries = self.server.state.store.list_audit_log(
                        site_id=site_id, limit=limit
                    )
                self._send_json(
                    200,
                    {"audit_log": [entry.to_dict() for entry in entries]},
                )
                return

            self._send_json(404, {"status": "error", "error": "Not found"})
        except (ValueError, KeyError) as exc:
            self._send_json(400, {"status": "error", "error": str(exc)})

    def do_POST(self) -> None:
        if not self._host_authorized():
            return
        if not self._authorize_mutation():
            return

        parsed_url = urlparse(self.path)
        route = parsed_url.path.rstrip("/") or "/"

        if route not in (
            "/api/items/patch",
            "/api/devices",
            "/api/devices/ports",
            "/api/vlans",
            "/api/curation/preview",
            "/api/curation/apply",
        ):
            self._send_json(404, {"status": "error", "error": "Not found"})
            return

        try:
            body = self._read_json_body()
            actor = _optional_str(body.get("actor")) or "operator"
            reason = _optional_str(body.get("reason")) or ""

            if route == "/api/items/patch":
                entry = self.server.state.apply_item_patch(
                    body, actor=actor, reason=reason
                )
                self._send_json(
                    200,
                    {
                        "status": "ok",
                        "audit_entry": entry.to_dict(),
                        "state": self.server.state.get_state_payload(),
                    },
                )
                return

            if route == "/api/devices":
                device, entry = self.server.state.create_device(
                    body, actor=actor, reason=reason
                )
                self._send_json(
                    201,
                    {
                        "status": "ok",
                        "device": device.to_dict(),
                        "audit_entry": entry.to_dict(),
                        "state": self.server.state.get_state_payload(),
                    },
                )
                return

            if route == "/api/devices/ports":
                ports, entries = self.server.state.upsert_device_ports(
                    body, actor=actor, reason=reason
                )
                self._send_json(
                    200,
                    {
                        "status": "ok",
                        "ports": [p.to_dict() for p in ports],
                        "audit_entries": [e.to_dict() for e in entries],
                        "state": self.server.state.get_state_payload(),
                    },
                )
                return

            if route == "/api/vlans":
                vlan, subnet, entry = self.server.state.upsert_vlan(
                    body, actor=actor, reason=reason
                )
                self._send_json(
                    201,
                    {
                        "status": "ok",
                        "vlan": vlan.to_dict(),
                        "subnet": subnet.to_dict() if subnet is not None else None,
                        "audit_entry": entry.to_dict(),
                        "state": self.server.state.get_state_payload(),
                    },
                )
                return

            if route == "/api/curation/preview":
                csv_text, as_of = _bulk_csv_fields(body)
                preview = self.server.state.preview_csv(csv_text, as_of)
                self._send_json(200, {"status": "ok", "preview": preview.to_dict()})
                return

            if route == "/api/curation/apply":
                csv_text, as_of = _bulk_csv_fields(body)
                confirm_token = body.get("confirm_token")
                if not isinstance(confirm_token, str):
                    raise ValueError("confirm_token must be a string")
                result = self.server.state.apply_csv(
                    csv_text, as_of, confirm_token, actor
                )
                self._send_json(
                    200,
                    {
                        "status": "ok",
                        "batch_id": result.batch_id,
                        "applied": len(result.entries),
                        "audit_entries": [e.to_dict() for e in result.entries],
                        "state": self.server.state.get_state_payload(),
                    },
                )
                return
        except PatchCsvError as exc:
            self._send_json(
                400,
                {
                    "status": "error",
                    "error": str(exc),
                    "errors": [
                        {"row": row, "message": message} for row, message in exc.errors
                    ],
                },
            )
        except BulkApplyRefused as exc:
            self._send_json(409, {"status": "error", "error": str(exc)})
        except WorkbenchNotFoundError as exc:
            self._send_json(404, {"status": "error", "error": str(exc)})
        except (ValueError, KeyError, TypeError) as exc:
            self._send_json(400, {"status": "error", "error": str(exc)})

    def do_PUT(self) -> None:
        self._reject_unsupported_mutation()

    def do_PATCH(self) -> None:
        self._reject_unsupported_mutation()

    def do_DELETE(self) -> None:
        self._reject_unsupported_mutation()


def create_workbench_server(
    state: WorkbenchState,
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    security: Optional[WorkbenchSecurityConfig] = None,
) -> WorkbenchServer:
    """Create a WorkbenchServer bound to `(host, port)` for `state`."""
    return WorkbenchServer((host, port), state, security=security)
