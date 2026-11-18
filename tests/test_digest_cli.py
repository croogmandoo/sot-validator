"""End-to-end CLI tests for `digest` (render, `--send` over SMTP / webhook, `--send --dry-run`)."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import http.server
import json
import logging
from pathlib import Path
import socket
import socketserver
import threading
from typing import Any

import pytest

from sot_validator.cli import main
import sot_validator.cli.digest as digest_cli
from sot_validator.discovery.monitor import ScanDriftEvent, SnapshotDiffReport
from sot_validator.lifecycle.certificates import CertificateFinding
from sot_validator.models import ValidationClassification, ValidationResult
from sot_validator.quality.checks import QualityFinding
from sot_validator.reporting import SiteScorecard

OUTPUT_FILES = ("digest.txt", "digest.md", "digest.html", "digest.json")
PROXY_VARS = (
    "http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY",
    "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY",
)
SENTINEL = "S3NT1NEL-x9q"
WHEN = datetime(2026, 11, 1, tzinfo=timezone.utc)


# --- local receivers ---------------------------------------------------------------


class _StubSmtpHandler(socketserver.StreamRequestHandler):
    def _reply(self, line: str) -> None:
        self.wfile.write((line + "\r\n").encode("ascii"))
        self.wfile.flush()

    def handle(self) -> None:
        server = self.server
        server.connections += 1
        self._reply("220 stub ESMTP")
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            verb = line.split(" ", 1)[0].upper()
            if verb in ("EHLO", "HELO"):
                self._reply("250-stub")
                self._reply("250 AUTH PLAIN")
            elif verb == "AUTH":
                server.auth.append(line)
                self._reply("235 2.7.0 Authentication successful")
            elif verb in ("MAIL", "RCPT", "RSET", "NOOP"):
                self._reply("250 OK")
            elif verb == "DATA":
                self._reply("354 End data with <CR><LF>.<CR><LF>")
                chunks = []
                while (data_line := self.rfile.readline()) not in (b"", b".\r\n"):
                    chunks.append(data_line)
                server.messages.append(b"".join(chunks))
                self._reply("250 OK queued")
            elif verb == "QUIT":
                self._reply("221 bye")
                return
            else:
                self._reply("502 not implemented")


class _StubSmtpServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _StubSmtpHandler)
        self.connections = 0
        self.auth: list[str] = []
        self.messages: list[bytes] = []


class _WebhookHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 - http.server API
        length = int(self.headers.get("Content-Length", "0"))
        self.server.posts.append((self.path, self.rfile.read(length)))
        self.send_response(self.server.status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args: Any) -> None:
        pass


class _WebhookServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, status: int) -> None:
        super().__init__(("127.0.0.1", 0), _WebhookHandler)
        self.status = status
        self.posts: list[tuple[str, bytes]] = []


@pytest.fixture
def servers(monkeypatch):
    for name in PROXY_VARS:
        monkeypatch.delenv(name, raising=False)
    started = []

    def start(server):
        threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()
        started.append(server)
        return server

    yield {
        "smtp": lambda: start(_StubSmtpServer()),
        "webhook": lambda status=200: start(_WebhookServer(status)),
    }
    for server in started:
        server.shutdown()
        server.server_close()


@pytest.fixture
def no_connect(monkeypatch):
    def refuse(self, address):
        raise AssertionError(f"unexpected connection to {address}")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)


# --- input fixtures shaped as each producer writes them ----------------------------


def _write_json(path: Path, payload: Any) -> Path:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _quality(finding_ids: list[str], severity: str = "error") -> dict[str, Any]:
    findings = [
        asdict(
            QualityFinding(
                finding_id=fid, site_id="site-001", rule="duplicate_ip", severity=severity,
                record_type="ip_address", record_ids=["10.1.1.20"], message=f"conflict {fid}",
            )
        )
        for fid in finding_ids
    ]
    return {"findings": findings, "site_ids": ["site-001"], "total_findings": len(findings)}


def _results(item_ids: list[str]) -> dict[str, Any]:
    results = [
        ValidationResult(
            item_type="ip_address", item_id=item_id, site_id="site-001", name=f"host-{item_id}",
            classification=ValidationClassification.STALE_LIKELY_UNUSED, confidence=0.9,
            evaluated_at=WHEN,
        ).to_dict()
        for item_id in item_ids
    ]
    return {"generated_at": WHEN.isoformat(), "total_results": len(results), "results": results}


def _certs(ips: list[str]) -> dict[str, Any]:
    findings = [
        CertificateFinding(
            site_id="site-001", ip=ip, port=443, subject_cn="ups.example.internal", issuer=None,
            not_after=WHEN, days_remaining=5, issues=["expiring_30d"], severity="warning",
        ).to_dict()
        for ip in ips
    ]
    return {"generated_at": WHEN.isoformat(), "total_findings": len(findings), "findings": findings}


def _fleet(trend: str) -> list[dict[str, Any]]:
    card = SiteScorecard(site_id="site-001", health_score=60.0, previous_score=90.0, trend=trend)
    return [card.to_dict()]


def _drift(event_ids: list[str]) -> dict[str, Any]:
    events = [
        ScanDriftEvent(
            event_id=eid, event_type="NEW_HOST_JOINED", severity="warning", site_id="site-001",
            target_id="10.1.1.99", ip="10.1.1.99", previous_value=None, current_value="up",
            detected_at=WHEN, summary=f"new host {eid}",
        )
        for eid in event_ids
    ]
    return SnapshotDiffReport(
        site_id="site-001", baseline_timestamp=WHEN, current_timestamp=WHEN, events=events
    ).to_dict()


def _quality_pair(tmp_path: Path, previous=(), current=("q-new",)) -> list[str]:
    prev = _write_json(tmp_path / "prev-quality.json", _quality(list(previous)))
    cur = _write_json(tmp_path / "cur-quality.json", _quality(list(current)))
    return ["--previous-quality", str(prev), "--current-quality", str(cur)]


def _run(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def _files(directory: Path) -> dict[str, bytes]:
    if not directory.exists():
        return {}
    return {path.name: path.read_bytes() for path in sorted(directory.iterdir())}


# --- config ------------------------------------------------------------------------


SITE = """
[[sites]]
site_id = "site-001"
name = "HQ"
block = "10.1.0.0/16"
active_subnets = ["10.1.10.0/24"]
"""


def _config(tmp_path: Path, *, smtp_port: int | None = None, webhooks: int = 1, extra: str = "") -> Path:
    text = SITE + "\n[digest]\n" + extra
    if smtp_port is not None:
        text += (
            "\n[digest.smtp]\n"
            'host = "127.0.0.1"\n'
            f"port = {smtp_port}\n"
            'sender = "sot@example.invalid"\n'
            'recipients = ["ops@example.invalid", "noc@example.invalid"]\n'
            "starttls = false\n"
            "allow_insecure_localhost = true\n"
            "timeout_seconds = 5\n"
            'username = "${env:DIGEST_SMTP_USER}"\n'
            'password = "${env:DIGEST_SMTP_PASS}"\n'
        )
    for index in range(webhooks):
        text += f'\n[[digest.webhooks]]\nname = "hook-{index}"\nurl = "${{env:DIGEST_HOOK_{index}}}"\ntimeout_seconds = 5\n'
    path = tmp_path / "fleet.toml"
    path.write_text(text, encoding="utf-8")
    return path


def _set_secrets(monkeypatch, hook_port: int) -> str:
    monkeypatch.setenv("DIGEST_SMTP_USER", "digest-user")
    monkeypatch.setenv("DIGEST_SMTP_PASS", f"pw-{SENTINEL}")
    url = f"http://127.0.0.1:{hook_port}/hooks/{SENTINEL}/path?token={SENTINEL}q"
    monkeypatch.setenv("DIGEST_HOOK_0", url)
    return url


def _clear_secrets(monkeypatch) -> None:
    for name in ("DIGEST_SMTP_USER", "DIGEST_SMTP_PASS", "DIGEST_HOOK_0", "DIGEST_HOOK_1"):
        monkeypatch.delenv(name, raising=False)


def _assert_no_secret(*texts: str) -> None:
    for text in texts:
        for fragment in (SENTINEL, "/hooks/", "token="):
            assert fragment not in text


# --- 1. render-only ----------------------------------------------------------------


def test_render_only_prints_text_and_writes_identical_files(tmp_path, capsys, no_connect):
    argv = _quality_pair(tmp_path)
    code, out, err = _run(capsys, "digest", *argv)
    assert code == 0, err
    assert out.startswith("SoT weekly change digest")
    assert "Data-quality errors: 1 new" in out

    out_dir = tmp_path / "out" / "nested"
    assert _run(capsys, "digest", *argv, "--output-dir", str(out_dir))[0] == 0
    first = _files(out_dir)
    assert sorted(first) == sorted(OUTPUT_FILES)
    data = json.loads(first["digest.json"])
    assert len(data["categories"]) == 5
    assert first["digest.txt"].decode("utf-8") == out.rstrip("\n")
    assert _run(capsys, "digest", *argv, "--output-dir", str(out_dir))[0] == 0
    assert _files(out_dir) == first


def test_render_only_ignores_digest_config(tmp_path, capsys, no_connect, monkeypatch):
    _clear_secrets(monkeypatch)
    config = _config(tmp_path, smtp_port=1, webhooks=1)
    code, out, err = _run(capsys, "--config", str(config), "digest", *_quality_pair(tmp_path))
    assert code == 0, err
    assert out.startswith("SoT weekly change digest")


# --- 2. all five pairs ---------------------------------------------------------------


PAIR_CASES = [
    ("results", "stale_records", lambda: _results(["ip-1"]), lambda: _results(["ip-1", "ip-2"])),
    ("quality", "quality_errors", lambda: _quality(["q1"]), lambda: _quality(["q1", "q2"])),
    ("certs", "certificates_30d", lambda: _certs(["10.1.1.5"]), lambda: _certs(["10.1.1.5", "10.1.1.6"])),
    ("fleet", "health_drops", lambda: _fleet("stable"), lambda: _fleet("degrading")),
    ("drift", "drift", lambda: _drift([]), lambda: _drift(["e1"])),
]


def test_all_five_pairs_have_data(tmp_path, capsys, no_connect):
    argv: list[str] = []
    for suffix, _, previous, current in PAIR_CASES:
        argv += ["--previous-" + suffix, str(_write_json(tmp_path / f"p-{suffix}.json", previous()))]
        argv += ["--current-" + suffix, str(_write_json(tmp_path / f"c-{suffix}.json", current()))]
    code, out, err = _run(capsys, "digest", *argv, "--output-dir", str(tmp_path / "out"))
    assert code == 0, err
    data = json.loads((tmp_path / "out" / "digest.json").read_text(encoding="utf-8"))
    by_id = {category["category"]: category for category in data["categories"]}
    for _, category_id, _, _ in PAIR_CASES:
        assert by_id[category_id]["has_data"] is True
        assert by_id[category_id]["new"] == 1, category_id
    assert "no data" not in out


@pytest.mark.parametrize(("suffix", "category_id", "previous", "current"), PAIR_CASES)
def test_each_pair_alone_fills_only_its_category(tmp_path, capsys, suffix, category_id, previous, current):
    argv = [
        "--previous-" + suffix, str(_write_json(tmp_path / "p.json", previous())),
        "--current-" + suffix, str(_write_json(tmp_path / "c.json", current())),
    ]
    code, _, err = _run(capsys, "digest", *argv, "--output-dir", str(tmp_path / "out"))
    assert code == 0, err
    data = json.loads((tmp_path / "out" / "digest.json").read_text(encoding="utf-8"))
    has_data = {c["category"]: c["has_data"] for c in data["categories"]}
    assert has_data == {cid: cid == category_id for _, cid, _, _ in PAIR_CASES}


def test_current_only_pair_shows_no_data(tmp_path, capsys):
    cur_certs = _write_json(tmp_path / "c-certs.json", _certs(["10.1.1.5"]))
    code, out, err = _run(capsys, "digest", *_quality_pair(tmp_path), "--current-certs", str(cur_certs))
    assert code == 0, err
    assert "Certificates expired or expiring within 30 days: no data" in out


def test_bare_list_quality_input_is_accepted(tmp_path, capsys):
    prev = _write_json(tmp_path / "p.json", [])
    cur = _write_json(tmp_path / "c.json", _quality(["q1"])["findings"])
    code, out, _ = _run(capsys, "digest", "--previous-quality", str(prev), "--current-quality", str(cur))
    assert code == 0
    assert "Data-quality errors: 1 new" in out


@pytest.mark.parametrize("severity", ["Error", "ERROR", True, 1, None])
def test_lookalike_severity_is_rejected(tmp_path, capsys, severity):
    current = _quality(["q1"])
    current["findings"][0]["severity"] = severity
    prev = _write_json(tmp_path / "p.json", _quality([]))
    cur = _write_json(tmp_path / "c.json", current)
    code, out, err = _run(capsys, "digest", "--previous-quality", str(prev), "--current-quality", str(cur))
    assert code == 2
    assert out == ""
    assert len(err.splitlines()) == 1 and err.startswith(f"error: --current-quality {cur}: severity")


def test_top_n_limits_listed_items(tmp_path, capsys):
    argv = _quality_pair(tmp_path, current=("q1", "q2", "q3"))
    code, out, _ = _run(capsys, "digest", *argv, "--top-n", "1")
    assert code == 0
    assert "and 2 more" in out


@pytest.mark.parametrize("value", ["0", "-3"])
def test_top_n_below_one_exits_2(tmp_path, capsys, value):
    code, out, err = _run(capsys, "digest", *_quality_pair(tmp_path), "--top-n", value)
    assert code == 2
    assert out == ""
    assert len(err.splitlines()) == 1 and err.startswith("error: --top-n")


# --- 3. no complete pair --------------------------------------------------------------


def test_no_complete_pair_exits_2(tmp_path, capsys):
    prev = _write_json(tmp_path / "p.json", _quality([]))
    cur = _write_json(tmp_path / "c.json", _drift([]))
    for argv in ([], ["--previous-quality", str(prev), "--current-drift", str(cur)]):
        code, out, err = _run(capsys, "digest", *argv)
        assert code == 2
        assert out == ""
        assert err.splitlines() == [
            "error: digest needs at least one complete --previous-*/--current-* pair"
        ]


# --- 4. bad input files ---------------------------------------------------------------


def _missing_site_id() -> dict[str, Any]:
    payload = _quality(["q1"])
    del payload["findings"][0]["site_id"]
    return payload


BAD_INPUTS = [
    pytest.param(None, id="missing-file"),
    pytest.param("{not json", id="invalid-json"),
    pytest.param(json.dumps({"rows": []}), id="no-findings-key"),
    pytest.param(json.dumps("findings"), id="string-root"),
    pytest.param(json.dumps({"findings": [1]}), id="non-object-item"),
    pytest.param(json.dumps(_missing_site_id()), id="missing-site-id"),
]


@pytest.mark.parametrize("content", BAD_INPUTS)
def test_bad_quality_input_exits_2_with_one_line(tmp_path, capsys, content):
    prev = _write_json(tmp_path / "p.json", _quality([]))
    cur = tmp_path / "c.json"
    if content is not None:
        cur.write_text(content, encoding="utf-8")
    out_dir = tmp_path / "out"
    code, out, err = _run(
        capsys, "digest", "--previous-quality", str(prev), "--current-quality", str(cur),
        "--output-dir", str(out_dir),
    )
    assert code == 2
    assert out == ""
    assert len(err.splitlines()) == 1
    assert err.startswith(f"error: --current-quality {cur}")
    assert "Traceback" not in err
    assert not out_dir.exists()
    if content == json.dumps(_missing_site_id()):
        assert "missing field 'site_id'" in err


@pytest.mark.parametrize(
    ("suffix", "payload"),
    [
        ("results", {"results": [{"item_id": "x"}]}),
        ("certs", {"findings": [{"site_id": "s", "ip": "1.2.3.4", "port": "443", "issues": []}]}),
        ("certs", {"findings": [{"site_id": "s", "ip": "1.2.3.4", "port": 443, "issues": "expired"}]}),
        ("fleet", [{"site_id": "s", "trend": "sideways"}]),
        ("drift", {"site_id": "s", "summary_counts": {}}),
        ("drift", {"events": [{"site_id": "s", "event_id": "e", "severity": "info"}]}),
    ],
)
def test_bad_previous_inputs_name_their_flag(tmp_path, capsys, suffix, payload):
    prev = _write_json(tmp_path / "p.json", payload)
    cur = _write_json(tmp_path / "c.json", [])
    code, out, err = _run(capsys, "digest", f"--previous-{suffix}", str(prev), f"--current-{suffix}", str(cur))
    assert code == 2
    assert out == ""
    assert len(err.splitlines()) == 1
    assert err.startswith(f"error: --previous-{suffix} {prev}")
    assert "Traceback" not in err


def test_bad_input_after_send_config_sends_nothing(tmp_path, capsys, servers, monkeypatch):
    smtp = servers["smtp"]()
    hook = servers["webhook"]()
    _set_secrets(monkeypatch, hook.server_address[1])
    config = _config(tmp_path, smtp_port=smtp.server_address[1])
    prev = _write_json(tmp_path / "p.json", _quality([]))
    code, _, err = _run(
        capsys, "--config", str(config), "digest", "--previous-quality", str(prev),
        "--current-quality", str(tmp_path / "absent.json"), "--send",
    )
    assert code == 2
    assert err.startswith("error: --current-quality")
    assert smtp.connections == 0 and hook.posts == []


# --- 6./7. delivery ---------------------------------------------------------------------


def test_send_delivers_to_smtp_and_webhook(tmp_path, capsys, servers, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    smtp = servers["smtp"]()
    hook = servers["webhook"]()
    _set_secrets(monkeypatch, hook.server_address[1])
    config = _config(tmp_path, smtp_port=smtp.server_address[1])
    out_dir = tmp_path / "out"
    code, out, err = _run(
        capsys, "--config", str(config), "digest", *_quality_pair(tmp_path), "--send",
        "--output-dir", str(out_dir),
    )
    assert code == 0, err
    assert len(smtp.messages) == 1 and len(smtp.auth) == 1
    message = smtp.messages[0].decode("utf-8", "replace")
    assert "Data-quality errors: 1 new" in message
    assert len(hook.posts) == 1
    payload = json.loads(hook.posts[0][1])
    assert payload["event_type"] == "sot_validator_weekly_digest"
    assert "Data-quality errors: 1 new" in payload["text"]
    lines = out.splitlines()
    port = hook.server_address[1]
    assert lines == [
        f"smtp smtp sent smtp://127.0.0.1:{smtp.server_address[1]}",
        f"hook-0 webhook sent http://127.0.0.1:{port}",
    ]
    assert sorted(_files(out_dir)) == sorted(OUTPUT_FILES)
    _assert_no_secret(out, err, caplog.text, *(b.decode() for b in _files(out_dir).values()))


def test_failing_webhook_still_sends_smtp_and_exits_1(tmp_path, capsys, servers, monkeypatch, caplog):
    smtp = servers["smtp"]()
    hook = servers["webhook"](500)
    _set_secrets(monkeypatch, hook.server_address[1])
    config = _config(tmp_path, smtp_port=smtp.server_address[1])
    code, out, err = _run(capsys, "--config", str(config), "digest", *_quality_pair(tmp_path), "--send")
    assert code == 1
    assert len(smtp.messages) == 1
    lines = out.splitlines()
    assert lines[0].startswith("smtp smtp sent ")
    assert lines[1] == f"hook-0 webhook failed http://127.0.0.1:{hook.server_address[1]}: HTTP 500"
    _assert_no_secret(out, err, caplog.text)


def test_closed_port_webhook_fails_without_leaking(tmp_path, capsys, servers, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    smtp = servers["smtp"]()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
    _set_secrets(monkeypatch, closed_port)
    config = _config(tmp_path, smtp_port=smtp.server_address[1])
    out_dir = tmp_path / "out"
    code, out, err = _run(
        capsys, "--config", str(config), "digest", *_quality_pair(tmp_path), "--send",
        "--output-dir", str(out_dir),
    )
    assert code == 1
    assert len(smtp.messages) == 1
    assert f"hook-0 webhook failed http://127.0.0.1:{closed_port}: " in out
    _assert_no_secret(out, err, caplog.text, *(b.decode() for b in _files(out_dir).values()))


def test_missing_smtp_credentials_is_a_per_target_failure(tmp_path, capsys, servers, monkeypatch):
    smtp = servers["smtp"]()
    hook = servers["webhook"]()
    _set_secrets(monkeypatch, hook.server_address[1])
    monkeypatch.delenv("DIGEST_SMTP_PASS")
    config = _config(tmp_path, smtp_port=smtp.server_address[1])
    code, out, _ = _run(capsys, "--config", str(config), "digest", *_quality_pair(tmp_path), "--send")
    assert code == 1
    assert smtp.connections == 0
    assert "environment variable DIGEST_SMTP_PASS is not set or empty" in out
    assert len(hook.posts) == 1


def test_webhooks_only_config_sends(tmp_path, capsys, servers, monkeypatch):
    first = servers["webhook"]()
    second = servers["webhook"]()
    _set_secrets(monkeypatch, first.server_address[1])
    monkeypatch.setenv("DIGEST_HOOK_1", f"http://127.0.0.1:{second.server_address[1]}/b")
    config = _config(tmp_path, webhooks=2)
    code, out, _ = _run(capsys, "--config", str(config), "digest", *_quality_pair(tmp_path), "--send")
    assert code == 0
    assert [line.split()[0] for line in out.splitlines()] == ["hook-0", "hook-1"]
    assert len(first.posts) == len(second.posts) == 1


# --- 8. dry-run -------------------------------------------------------------------------


def test_dry_run_previews_without_secrets_or_sockets(tmp_path, capsys, servers, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    smtp = servers["smtp"]()
    _clear_secrets(monkeypatch)
    config = _config(tmp_path, smtp_port=smtp.server_address[1], webhooks=2)

    def refuse(self, address):
        raise AssertionError("dry-run opened a connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    code, out, err = _run(
        capsys, "--config", str(config), "digest", *_quality_pair(tmp_path), "--send", "--dry-run"
    )
    assert code == 0, err
    assert f"smtp://127.0.0.1:{smtp.server_address[1]}" in out
    assert "ops@example.invalid, noc@example.invalid" in out
    assert "sot@example.invalid" in out
    assert "url=${env:DIGEST_HOOK_0}" in out
    assert "url=${env:DIGEST_HOOK_1}" in out
    assert "policy: on_change: would send" in out
    assert "subject: SoT weekly change digest" in out
    assert "Data-quality errors: 1 new" in out
    assert smtp.connections == 0
    assert err == ""


def test_dry_run_with_secrets_set_never_shows_them(tmp_path, capsys, servers, monkeypatch, caplog, no_connect):
    caplog.set_level(logging.DEBUG)
    _set_secrets(monkeypatch, 9)
    config = _config(tmp_path, smtp_port=2525)
    out_dir = tmp_path / "out"
    code, out, err = _run(
        capsys, "--config", str(config), "digest", *_quality_pair(tmp_path), "--send", "--dry-run",
        "--output-dir", str(out_dir),
    )
    assert code == 0
    _assert_no_secret(out, err, caplog.text, *(b.decode() for b in _files(out_dir).values()))


def test_dry_run_without_send_exits_2(tmp_path, capsys):
    code, out, err = _run(capsys, "digest", *_quality_pair(tmp_path), "--dry-run")
    assert code == 2
    assert out == ""
    assert len(err.splitlines()) == 1 and err.startswith("error: --dry-run")


# --- 9. empty digest and policy ---------------------------------------------------------


def test_empty_digest_on_change_sends_nothing(tmp_path, capsys, servers, monkeypatch):
    smtp = servers["smtp"]()
    hook = servers["webhook"]()
    _clear_secrets(monkeypatch)
    config = _config(tmp_path, smtp_port=smtp.server_address[1])
    argv = _quality_pair(tmp_path, previous=("q1",), current=("q1",))
    code, out, err = _run(capsys, "--config", str(config), "digest", *argv, "--send")
    assert code == 0, err
    assert out.splitlines() == ["digest: nothing to send (policy on_change, no new items)"]
    assert smtp.connections == 0 and hook.posts == []


@pytest.mark.parametrize("via", ["flag", "config"])
def test_empty_digest_policy_always_delivers(tmp_path, capsys, servers, monkeypatch, via):
    smtp = servers["smtp"]()
    hook = servers["webhook"]()
    _set_secrets(monkeypatch, hook.server_address[1])
    extra = 'policy = "always"\n' if via == "config" else ""
    config = _config(tmp_path, smtp_port=smtp.server_address[1], extra=extra)
    argv = _quality_pair(tmp_path, previous=("q1",), current=("q1",))
    flags = ["--policy", "always"] if via == "flag" else []
    code, out, err = _run(capsys, "--config", str(config), "digest", *argv, "--send", *flags)
    assert code == 0, err
    assert len(smtp.messages) == 1 and len(hook.posts) == 1
    assert "no changes since the previous run" in json.loads(hook.posts[0][1])["text"]


def test_policy_flag_overrides_config(tmp_path, capsys, servers, monkeypatch):
    smtp = servers["smtp"]()
    _clear_secrets(monkeypatch)
    config = _config(tmp_path, smtp_port=smtp.server_address[1], webhooks=0, extra='policy = "always"\n')
    argv = _quality_pair(tmp_path, previous=("q1",), current=("q1",))
    code, out, _ = _run(capsys, "--config", str(config), "digest", *argv, "--send", "--policy", "on_change")
    assert code == 0
    assert "nothing to send" in out
    assert smtp.connections == 0


# --- 10. missing config or targets ------------------------------------------------------


def test_send_without_config_exits_2(tmp_path, capsys, no_connect):
    code, out, err = _run(capsys, "digest", *_quality_pair(tmp_path), "--send")
    assert code == 2
    assert out == ""
    assert len(err.splitlines()) == 1 and err.startswith("error: ")
    assert "--config" in err


@pytest.mark.parametrize("digest_section", ["", "\n[digest]\npolicy = \"always\"\n"])
def test_send_without_targets_exits_2(tmp_path, capsys, no_connect, digest_section):
    config = tmp_path / "fleet.toml"
    config.write_text(SITE + digest_section, encoding="utf-8")
    code, out, err = _run(capsys, "--config", str(config), "digest", *_quality_pair(tmp_path), "--send")
    assert code == 2
    assert out == ""
    assert len(err.splitlines()) == 1 and err.startswith("error: ")
    assert "[digest.smtp]" in err


# --- 11. unsafe revealed URLs -----------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        (f"http://127.0.0.1:1/a b{SENTINEL}", "contains whitespace or control characters"),
        (f"http://127.0.0.1:1/{SENTINEL}\n", "contains whitespace or control characters"),
        (f"http://127.0.0.1:1/{SENTINEL}\x07", "contains whitespace or control characters"),
        (f"ftp://x/{SENTINEL}", "is not an http or https URL with a host"),
        (f"http:///{SENTINEL}", "is not an http or https URL with a host"),
        (f"http://[::1/{SENTINEL}", "is not an http or https URL with a host"),
    ],
)
def test_unsafe_webhook_url_exits_2_before_any_send(tmp_path, capsys, servers, monkeypatch, caplog, value, reason):
    smtp = servers["smtp"]()
    _set_secrets(monkeypatch, 1)
    monkeypatch.setenv("DIGEST_HOOK_0", value)
    config = _config(tmp_path, smtp_port=smtp.server_address[1])
    code, out, err = _run(capsys, "--config", str(config), "digest", *_quality_pair(tmp_path), "--send")
    assert code == 2
    assert out == ""
    assert err.splitlines() == [
        f"error: {config}: [digest.webhooks[0]] url: environment variable DIGEST_HOOK_0 {reason}"
    ]
    assert smtp.connections == 0
    _assert_no_secret(out, err, caplog.text)


def test_unset_webhook_url_names_variable(tmp_path, capsys, servers, monkeypatch):
    smtp = servers["smtp"]()
    _set_secrets(monkeypatch, 1)
    monkeypatch.delenv("DIGEST_HOOK_0")
    config = _config(tmp_path, smtp_port=smtp.server_address[1])
    code, _, err = _run(capsys, "--config", str(config), "digest", *_quality_pair(tmp_path), "--send")
    assert code == 2
    assert len(err.splitlines()) == 1
    assert "[digest.webhooks[0]] url: environment variable DIGEST_HOOK_0 is unset or empty" in err
    assert smtp.connections == 0


def test_second_bad_webhook_blocks_the_first(tmp_path, capsys, servers, monkeypatch):
    first = servers["webhook"]()
    _set_secrets(monkeypatch, first.server_address[1])
    monkeypatch.setenv("DIGEST_HOOK_1", "ftp://nope")
    config = _config(tmp_path, webhooks=2)
    code, _, err = _run(capsys, "--config", str(config), "digest", *_quality_pair(tmp_path), "--send")
    assert code == 2
    assert "[digest.webhooks[1]] url" in err
    assert first.posts == []


def test_smtp_sink_value_error_names_table(tmp_path, capsys, no_connect, monkeypatch):
    # The loader already applies the sink's checks, so force the sink to refuse the config.
    config = _config(tmp_path, smtp_port=25, webhooks=0)

    def boom(*args, **kwargs):
        raise ValueError("recipients must be a non-empty sequence of strings")

    monkeypatch.setattr(digest_cli, "SmtpDigestSink", boom)
    code, out, err = _run(capsys, "--config", str(config), "digest", *_quality_pair(tmp_path), "--send")
    assert code == 2
    assert out == ""
    assert err.splitlines() == [
        f"error: {config}: [digest.smtp]: recipients must be a non-empty sequence of strings"
    ]
