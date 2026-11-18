"""Tests for the weekly change digest and its SMTP and webhook delivery sinks."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import email
import io
from email import policy as email_policy
import json
import logging
import os
from pathlib import Path
import random
import re
import socketserver
import subprocess
import sys
import threading

import pytest

from sot_validator.campaign.digest_sinks import DigestSink, SmtpDigestSink, WebhookDigestSink
from sot_validator.discovery.monitor import ScanDriftEvent
from sot_validator.lifecycle.certificates import CertificateFinding
from sot_validator.models import ValidationClassification, ValidationResult
from sot_validator.observability.logging_setup import configure_logging
from sot_validator.quality.checks import QualityFinding
from sot_validator.reporting import (
    CATEGORY_CERTIFICATES_30D, CATEGORY_DRIFT, CATEGORY_HEALTH_DROPS, CATEGORY_QUALITY_ERRORS,
    CATEGORY_STALE_RECORDS, DIGEST_CATEGORIES, POLICY_ALWAYS, POLICY_ON_CHANGE,
    TREND_DEGRADING, TREND_IMPROVING, TREND_NEW, TREND_STABLE, ChangeDigest, DigestBuilder,
    DigestRunInput, SiteScorecard, render_digest_html, render_digest_markdown,
    render_digest_text,
)

STALE = ValidationClassification.STALE_LIKELY_UNUSED
ACTIVE = ValidationClassification.CONFIRMED_ACTIVE
SRC = Path(__file__).resolve().parents[1] / "src"
FORBIDDEN_HTML = (
    "<script", "<link", "<img", "<iframe", "src=", "href=", "url(", "@import", "http://",
    "https://",
)
NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)


def _stale(item_id, site="s1", classification=STALE, name=None, item_type="IPAddress"):
    return ValidationResult(item_type, item_id, site, name or f"host-{item_id}", classification)


def _quality(finding_id, site="s1", severity="error", message="duplicate IP"):
    return QualityFinding(
        finding_id, site, "duplicate_ip", severity, "IPAddress", [finding_id], message
    )


def _cert(ip, issues, site="s1", port=443, days=10, cn="web.example"):
    return CertificateFinding(site, ip, port, cn, "CA", None, days, issues, "error")


def _card(site, trend, health=50.0, previous=70.0):
    return SiteScorecard(site_id=site, health_score=health, previous_score=previous, trend=trend)


def _drift(event_id, severity="warning", site="s1", summary="host joined"):
    return ScanDriftEvent(
        event_id, "NEW_HOST_JOINED", severity, site, f"t-{event_id}", "10.1.1.1", None, None,
        NOW, summary,
    )


def _build(previous, current, **kwargs) -> ChangeDigest:
    return DigestBuilder(previous, current, **kwargs).build()


def _all_empty_run() -> DigestRunInput:
    return DigestRunInput(**{name: [] for name in vars(DigestRunInput())})


def _empty_digest() -> ChangeDigest:
    return _build(_all_empty_run(), _all_empty_run())


def _counts(digest, category):
    c = digest.category(category)
    return c.new, c.resolved, c.persisting


def test_builder_rejects_bad_arguments():
    run = DigestRunInput()
    for previous, current in (({}, run), (run, None)):
        with pytest.raises(ValueError):
            DigestBuilder(previous, current)
    for bad in (0, -1, True, 2.5, "3"):
        with pytest.raises(ValueError):
            DigestBuilder(run, run, top_n=bad)


def test_categories_are_in_fixed_order():
    digest = _build(DigestRunInput(), DigestRunInput())
    assert [c.category for c in digest.categories] == list(DIGEST_CATEGORIES)
    assert DIGEST_CATEGORIES == (
        "stale_records", "quality_errors", "certificates_30d", "health_drops", "drift"
    )
    assert all(c.title for c in digest.categories)


def test_stale_records_new_resolved_persisting():
    previous = DigestRunInput(results=[_stale("A"), _stale("B"), _stale("X", classification=ACTIVE)])
    current = DigestRunInput(results=[_stale("B"), _stale("C"), _stale("C")])
    digest = _build(previous, current)
    stale = digest.category(CATEGORY_STALE_RECORDS)
    assert (stale.new, stale.resolved, stale.persisting) == (1, 1, 1)
    assert [item.key for item in stale.top_new] == ["s1/IPAddress/C"]
    assert stale.top_new[0].summary == "s1 IPAddress C (host-C)"


def test_stale_key_includes_site():
    previous = DigestRunInput(results=[_stale("A", site="s1")])
    current = DigestRunInput(results=[_stale("A", site="s2")])
    assert _counts(_build(previous, current), CATEGORY_STALE_RECORDS) == (1, 1, 0)


def test_quality_errors_only_count_error_severity_and_dedupe():
    warn = "warning"
    previous = DigestRunInput(
        quality_findings=[_quality("q1"), _quality("q2"), _quality("w1", severity=warn)]
    )
    current = DigestRunInput(
        quality_findings=[_quality("q2"), _quality("q3"), _quality("q3"), _quality("w2", severity=warn)]
    )
    digest = _build(previous, current)
    assert _counts(digest, CATEGORY_QUALITY_ERRORS) == (1, 1, 1)
    item = digest.category(CATEGORY_QUALITY_ERRORS).top_new[0]
    assert (item.key, item.summary) == ("q3", "s1 duplicate_ip: duplicate IP")


def test_certificate_rule_includes_expired_and_30d_only():
    previous = DigestRunInput(certificate_findings=[_cert("10.0.0.1", ["expiring_30d"])])
    current = DigestRunInput(certificate_findings=[
        _cert("10.0.0.1", ["expired", "self_signed"], days=-2),
        _cert("10.0.0.2", ["expiring_60d"], days=45),
        _cert("10.0.0.3", ["expiring_30d"], days=20), _cert("10.0.0.3", ["expiring_30d"], days=20),
    ])
    digest = _build(previous, current)
    certs = digest.category(CATEGORY_CERTIFICATES_30D)
    # 10.0.0.1 moved from expiring_30d to expired: one new, one resolved.
    assert (certs.new, certs.resolved, certs.persisting) == (2, 1, 0)
    assert [item.summary for item in certs.top_new] == [
        "s1 10.0.0.1:443 web.example expired",
        "s1 10.0.0.3:443 web.example expires in 20 days",
    ]
    assert all("10.0.0.2" not in item.key for item in certs.top_new)


def test_certificate_sort_days_ascending_none_last():
    current = DigestRunInput(certificate_findings=[
        _cert("10.0.0.9", ["expiring_30d"], days=None, cn=None),
        _cert("10.0.0.8", ["expiring_30d"], days=25), _cert("10.0.0.7", ["expiring_30d"], days=3),
        _cert("10.0.0.6", ["expired"], days=-1),
    ])
    digest = _build(DigestRunInput(certificate_findings=[]), current)
    ips = [item.key.split("/")[1] for item in digest.category(CATEGORY_CERTIFICATES_30D).top_new]
    assert ips == ["10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9"]
    last = digest.category(CATEGORY_CERTIFICATES_30D).top_new[-1]
    assert last.summary == "s1 10.0.0.9:443 - expires within 30 days"


def test_health_rule_only_degrading_counts_and_largest_drop_first():
    previous = DigestRunInput(scorecards=[_card("s1", TREND_DEGRADING), _card("s2", TREND_DEGRADING)])
    current = DigestRunInput(scorecards=[
        _card("s2", TREND_DEGRADING), _card("s3", TREND_DEGRADING, health=60.0, previous=70.0),
        _card("s4", TREND_DEGRADING, health=10.0, previous=90.0), _card("s5", TREND_STABLE),
        _card("s6", TREND_IMPROVING), _card("s7", TREND_NEW),
    ])
    digest = _build(previous, current)
    health = digest.category(CATEGORY_HEALTH_DROPS)
    assert (health.new, health.resolved, health.persisting) == (2, 1, 1)
    assert [item.summary for item in health.top_new] == ["s4 90.0 -> 10.0", "s3 70.0 -> 60.0"]


def test_drift_keyed_by_event_id_sorted_by_severity():
    previous = DigestRunInput(drift_events=[_drift("e1"), _drift("e2")])
    current = DigestRunInput(drift_events=[
        _drift("e2"), _drift("e5", severity="info"), _drift("e4", severity="warning"),
        _drift("e3", severity="critical"), _drift("e3", severity="critical"),
    ])
    digest = _build(previous, current)
    drift = digest.category(CATEGORY_DRIFT)
    assert (drift.new, drift.resolved, drift.persisting) == (3, 1, 1)
    assert [item.key for item in drift.top_new] == ["e3", "e4", "e5"]
    assert drift.top_new[0].summary == "s1 [critical] host joined"


def test_missing_category_in_either_run_is_no_data():
    previous = DigestRunInput(quality_findings=[_quality("q1")])
    current = DigestRunInput(quality_findings=None, drift_events=[_drift("e1")])
    digest = _build(previous, current)
    assert digest.category(CATEGORY_QUALITY_ERRORS).has_data is False
    assert _counts(digest, CATEGORY_QUALITY_ERRORS) == (None, None, None)
    assert digest.category(CATEGORY_DRIFT).has_data is False and digest.category(CATEGORY_DRIFT).new is None
    assert digest.is_empty
    with_change = _build(
        DigestRunInput(quality_findings=[_quality("q1")], drift_events=[]),
        DigestRunInput(quality_findings=None, drift_events=[_drift("e1")]),
    )
    assert with_change.category(CATEGORY_QUALITY_ERRORS).resolved is None
    text = render_digest_text(with_change)
    assert "Data-quality errors: no data" in text.splitlines()
    assert "Stale records: no data" in text.splitlines()


def test_empty_list_means_data_present():
    digest = _build(DigestRunInput(drift_events=[]), DigestRunInput(drift_events=[]))
    assert digest.category(CATEGORY_DRIFT).has_data is True
    assert _counts(digest, CATEGORY_DRIFT) == (0, 0, 0)


def _mixed_runs():
    previous = DigestRunInput(
        results=[_stale(f"P{i}") for i in range(5)] + [_stale("S0")],
        quality_findings=[_quality("q0")],
        certificate_findings=[_cert("10.0.0.1", ["expiring_30d"])],
        scorecards=[_card("s1", TREND_DEGRADING)],
        drift_events=[_drift("e0")],
    )
    current = DigestRunInput(
        results=[_stale(f"N{i}", site=f"s{i % 3}") for i in range(15)] + [_stale("S0")],
        quality_findings=[_quality(f"q{i}", site=f"s{i % 4}") for i in range(1, 14)],
        certificate_findings=[
            _cert(f"10.0.1.{i}", ["expiring_30d"] if i % 2 else ["expired"], days=i)
            for i in range(14)
        ],
        scorecards=[_card(f"s{i}", TREND_DEGRADING, health=float(i), previous=80.0) for i in range(12)],
        drift_events=[_drift(f"e{i}", severity=("critical", "warning", "info")[i % 3]) for i in range(1, 14)],
    )
    return previous, current


def _shuffled(run: DigestRunInput, seed: int) -> DigestRunInput:
    rng = random.Random(seed)
    return DigestRunInput(**{
        name: rng.sample(list(values), len(values)) for name, values in vars(run).items()
    })


def test_shuffled_input_gives_identical_output():
    previous, current = _mixed_runs()
    baseline = _build(previous, current)
    for seed in range(5):
        other = _build(_shuffled(previous, seed), _shuffled(current, seed + 100))
        assert other.to_dict() == baseline.to_dict()
        assert render_digest_text(other) == render_digest_text(baseline)
        assert render_digest_markdown(other) == render_digest_markdown(baseline)
        assert render_digest_html(other) == render_digest_html(baseline)


def test_top_n_cut_and_more_line():
    previous, current = _mixed_runs()
    digest = _build(previous, current, top_n=3)
    stale = digest.category(CATEGORY_STALE_RECORDS)
    assert stale.new == 15 and len(stale.top_new) == 3 and stale.more_new == 12
    assert "  … and 12 more" in render_digest_text(digest).splitlines()
    assert "and 12 more" in render_digest_markdown(digest)
    assert "and 12 more" in render_digest_html(digest)
    assert len(_build(previous, current).category(CATEGORY_STALE_RECORDS).top_new) == 10


def test_to_dict_is_json_serialisable():
    previous, current = _mixed_runs()
    data = _build(previous, current).to_dict()
    assert json.loads(json.dumps(data)) == data and data["is_empty"] is False
    assert [c["category"] for c in data["categories"]] == list(DIGEST_CATEGORIES)


def test_text_has_header_and_counts_lines():
    previous, current = _mixed_runs()
    text = render_digest_text(_build(previous, current))
    lines = text.splitlines()
    assert lines[0] == "SoT weekly change digest"
    assert lines[1] == "Stale records: 15 new / 5 resolved / 1 persisting"
    assert len(text) <= 4000


def test_text_truncates_500_drift_events_with_exact_notice():
    current = DigestRunInput(drift_events=[_drift(f"e{i:03d}", summary="x" * 150) for i in range(500)])
    digest = _build(DigestRunInput(drift_events=[]), current, top_n=500)
    text = render_digest_text(digest)
    assert len(text) <= 4000
    lines = text.splitlines()
    match = re.fullmatch(r"… (\d+) more item\(s\) omitted \(truncated to 4000 characters\)", lines[-1])
    shown = sum(1 for line in lines if line.startswith("  - "))
    assert match and shown > 0 and int(match.group(1)) == 500 - shown
    # Header and every counts line survive truncation.
    assert lines[0] == "SoT weekly change digest"
    assert "Discovery drift: 500 new / 0 resolved / 0 persisting" in text


def test_text_truncation_with_default_top_n_and_long_values():
    huge = "y" * 20000
    run = DigestRunInput(
        results=[_stale(f"A{i}", name=huge) for i in range(20)],
        quality_findings=[_quality(f"q{i}", message=huge) for i in range(20)],
        certificate_findings=[_cert(f"10.0.0.{i}", ["expired"], cn=huge) for i in range(20)],
        scorecards=[_card(huge + str(i), TREND_DEGRADING) for i in range(20)],
        drift_events=[_drift(f"e{i}", summary=huge) for i in range(20)],
    )
    text = render_digest_text(_build(_all_empty_run(), run))
    assert len(text) <= 4000
    assert all(len(line) <= 200 for line in text.splitlines())
    assert "omitted (truncated to 4000 characters)" in text.splitlines()[-1]


def test_text_one_very_long_value_is_clipped_without_truncation():
    run = DigestRunInput(drift_events=[_drift("e1", summary="z" * 50000)])
    text = render_digest_text(_build(DigestRunInput(drift_events=[]), run))
    assert len(text) <= 4000
    assert "omitted" not in text
    assert any(line.endswith("…") for line in text.splitlines())


def test_text_custom_max_chars_and_validation():
    digest = _build(*_mixed_runs())
    text = render_digest_text(digest, max_chars=600)
    assert len(text) <= 600 and "truncated to 600 characters" in text
    for bad in (0, -5, True, "4000", 50):
        with pytest.raises(ValueError):
            render_digest_text(digest, max_chars=bad)


def test_summaries_are_single_line():
    run = DigestRunInput(quality_findings=[_quality("q1", message="line1\nline2\r\x00end")])
    digest = _build(_all_empty_run(), run)
    summary = digest.category(CATEGORY_QUALITY_ERRORS).top_new[0].summary
    assert summary == "s1 duplicate_ip: line1 line2 end"


def test_empty_digest_renders_one_line_and_send_policy():
    digest = _empty_digest()
    assert digest.is_empty
    text = render_digest_text(digest)
    markdown = render_digest_markdown(digest)
    for output in (text, markdown):
        assert "\n" not in output.strip()
        assert len(output.splitlines()) == 1
        assert "no changes" in output
    assert text == "SoT weekly digest: no changes since the previous run."
    html_doc = render_digest_html(digest)
    body = re.search(r"<body>(.*)</body>", html_doc, re.S).group(1).strip()
    assert body == "<p>SoT weekly digest: no changes since the previous run.</p>"
    assert digest.should_send(POLICY_ON_CHANGE) is False and digest.should_send() is False
    assert digest.should_send(POLICY_ALWAYS) is True
    for bad in ("weekly", "", None, "ALWAYS"):
        with pytest.raises(ValueError):
            digest.should_send(bad)


def test_resolved_only_changes_are_empty():
    digest = _build(DigestRunInput(drift_events=[_drift("e1")]), DigestRunInput(drift_events=[]))
    assert digest.category(CATEGORY_DRIFT).resolved == 1 and digest.is_empty
    assert not digest.should_send()
    assert "no changes" in render_digest_text(digest)


def test_non_empty_digest_should_send_on_change():
    assert _nonempty_digest().should_send("on_change") is True


def test_markdown_escapes_pipe_and_has_counts_table():
    run = DigestRunInput(quality_findings=[_quality("q|1", site="s|1", message="a|b")])
    markdown = render_digest_markdown(_build(DigestRunInput(quality_findings=[]), run))
    assert "| Category | New | Resolved | Persisting |" in markdown
    assert "| Data-quality errors | 1 | 0 | 0 |" in markdown
    assert "| Stale records | no data | no data | no data |" in markdown
    assert "s\\|1" in markdown and "a\\|b" in markdown
    assert "s|1" not in markdown.replace("s\\|1", "")


def test_html_escapes_hostile_values():
    hostile_site, hostile_msg = "<script>alert(1)</script>", '"><img src=x onerror=1>'
    run = DigestRunInput(
        quality_findings=[_quality("q1", site=hostile_site, message=hostile_msg)],
        drift_events=[_drift("e1", site=hostile_msg, summary=hostile_site)],
    )
    doc = render_digest_html(_build(_all_empty_run(), run))
    assert "<script" not in doc.lower() and "<img" not in doc.lower()
    assert "&lt;script&gt;" in doc and "&quot;&gt;&lt;img src=x onerror=1&gt;" in doc


def test_html_benign_contains_no_forbidden_strings():
    previous, current = _mixed_runs()
    for digest in (_build(previous, current), _empty_digest()):
        doc = render_digest_html(digest)
        assert doc.startswith("<!DOCTYPE html>") and "<style>" in doc
        for forbidden in FORBIDDEN_HTML:
            assert forbidden not in doc


def test_renderers_reject_non_digest():
    for renderer in (render_digest_text, render_digest_markdown, render_digest_html):
        with pytest.raises(ValueError):
            renderer({})


def test_digest_module_source_has_no_forbidden_strings():
    source = (SRC / "sot_validator" / "reporting" / "digest.py").read_text(encoding="utf-8")
    assert not re.search(r"<script|<link|<img|<iframe|src=|href=|url\(|@import|https?://", source)


def test_no_import_cycle_in_fresh_interpreter():
    code = (
        "import sot_validator.lifecycle.certificates, sot_validator.reporting as r;"
        "import sot_validator.campaign.digest_sinks;"
        "print(r.DigestBuilder.__name__, r.render_digest_text.__name__)"
    )
    for first in ("", "import sot_validator.reporting;"):
        out = subprocess.run(
            [sys.executable, "-c", first + code],
            env={**os.environ, "PYTHONPATH": str(SRC)}, capture_output=True, text=True, check=True,
        )
        assert out.stdout.strip() == "DigestBuilder render_digest_text"


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
            server.commands.append(line)
            if verb in ("EHLO", "HELO"):
                self._reply("250-stub")
                if server.offer_starttls:
                    self._reply("250-STARTTLS")
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

    def __init__(self, offer_starttls: bool = False) -> None:
        super().__init__(("127.0.0.1", 0), _StubSmtpHandler)
        self.offer_starttls = offer_starttls
        self.connections = 0
        self.commands: list[str] = []
        self.auth: list[str] = []
        self.messages: list[bytes] = []


@pytest.fixture
def smtp_stub():
    servers = []

    def start(offer_starttls: bool = False) -> _StubSmtpServer:
        server = _StubSmtpServer(offer_starttls)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def _nonempty_digest() -> ChangeDigest:
    return _build(DigestRunInput(drift_events=[]), DigestRunInput(drift_events=[_drift("e1")]))


def _all_fields(result) -> str:
    return " ".join(str(value) for value in vars(result).values())


def _sink(port, host="127.0.0.1", creds=("DIGEST_SMTP_USER", "DIGEST_SMTP_PASS"), **kwargs):
    kwargs.setdefault("starttls", False)
    kwargs.setdefault("allow_insecure_localhost", not kwargs["starttls"])
    if creds:
        kwargs.update(username_env=creds[0], password_env=creds[1])
    return SmtpDigestSink(host, port, "a@x", ["b@x"], **kwargs)


class _FakeSMTP:
    """Stands in for smtplib.SMTP and records the call order."""

    calls: list = []
    login_error = None

    def __init__(self, host, port, timeout):
        self.calls.append(("connect", host, port, timeout))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def ehlo(self):
        self.calls.append(("ehlo",))

    def has_extn(self, name):
        return name.lower() == "starttls"

    def starttls(self, context):
        self.calls.append(("starttls", type(context).__name__))

    def login(self, user, password):
        if self.login_error is not None:
            raise self.login_error
        self.calls.append(("login",))

    def send_message(self, message):
        self.calls.append(("send",))


@pytest.fixture
def fake_smtp(monkeypatch):
    monkeypatch.setattr(_FakeSMTP, "calls", [])
    monkeypatch.setattr(_FakeSMTP, "login_error", None)
    monkeypatch.setattr("sot_validator.campaign.digest_sinks.smtplib.SMTP", _FakeSMTP)
    return _FakeSMTP


def test_smtp_plain_loopback_delivery_with_env_credentials(smtp_stub, monkeypatch, caplog):
    monkeypatch.setenv("DIGEST_SMTP_USER", "mailer")
    monkeypatch.setenv("DIGEST_SMTP_PASS", "s3cret-Pa55")
    server = smtp_stub()
    sink = SmtpDigestSink(
        "127.0.0.1", server.server_address[1], "sot@example.test",
        ["ops@example.test", "noc@example.test"], username_env="DIGEST_SMTP_USER",
        password_env="DIGEST_SMTP_PASS", starttls=False, allow_insecure_localhost=True,
    )
    assert isinstance(sink, DigestSink)
    result = sink.send(_nonempty_digest())
    assert result.status == "sent", result.detail
    assert result.kind == "smtp" and result.name == "smtp" and result.detail is None
    assert result.destination == f"smtp://127.0.0.1:{server.server_address[1]}"
    expected = base64.b64encode(b"\0mailer\0s3cret-Pa55").decode("ascii")
    assert server.auth == [f"AUTH PLAIN {expected}"]
    message = email.message_from_bytes(server.messages[0], policy=email_policy.default)
    assert len(server.messages) == 1 and message.is_multipart()
    assert message["Subject"] == "SoT weekly change digest"
    assert message["To"] == "ops@example.test, noc@example.test"
    types = [part.get_content_type() for part in message.walk() if not part.is_multipart()]
    assert types == ["text/plain", "text/html"]
    plain = message.get_body(preferencelist=("plain",)).get_content()
    assert "Discovery drift: 1 new" in plain
    assert len([c for c in server.commands if c.upper().startswith("RCPT")]) == 2
    assert "s3cret-Pa55" not in _all_fields(result) and "s3cret-Pa55" not in caplog.text


def test_smtp_without_credentials_skips_login(smtp_stub):
    server = smtp_stub()
    sink = _sink(server.server_address[1], host="localhost", creds=None)
    assert sink.send(_nonempty_digest()).status == "sent"
    assert server.auth == [] and len(server.messages) == 1


def test_smtp_starttls_required_but_not_offered_fails_before_auth_and_data(
    smtp_stub, monkeypatch, caplog
):
    monkeypatch.setenv("DIGEST_SMTP_USER", "mailer")
    monkeypatch.setenv("DIGEST_SMTP_PASS", "s3cret-Pa55")
    server = smtp_stub(offer_starttls=False)
    sink = _sink(server.server_address[1], starttls=True)
    with caplog.at_level(logging.WARNING):
        result = sink.send(_nonempty_digest())
    assert result.status == "failed" and "STARTTLS" in result.detail
    assert server.connections == 1
    assert server.auth == [] and server.messages == []
    assert not any(c.upper().startswith(("MAIL", "DATA")) for c in server.commands)
    assert "failed" in caplog.text and "s3cret-Pa55" not in caplog.text


@pytest.mark.parametrize("host", ["mail.example.com", "10.1.2.3", "192.168.0.1", "::2"])
def test_smtp_insecure_non_loopback_host_raises(host):
    with pytest.raises(ValueError):
        SmtpDigestSink(host, 25, "a@x", ["b@x"], starttls=False, allow_insecure_localhost=True)


def test_smtp_insecure_requires_explicit_flag():
    with pytest.raises(ValueError):
        SmtpDigestSink("127.0.0.1", 25, "a@x", ["b@x"], starttls=False)
    for host in ("127.0.0.1", "localhost", "::1", "127.0.0.2"):
        SmtpDigestSink(host, 25, "a@x", ["b@x"], starttls=False, allow_insecure_localhost=True)
    # STARTTLS on is fine for any host.
    SmtpDigestSink("mail.example.com", 587, "a@x", ["b@x"])


@pytest.mark.parametrize(
    "kwargs",
    [
        {"host": ""}, {"host": "mail example"}, {"host": "mail\n.example"}, {"port": 0},
        {"port": 65536}, {"port": True}, {"port": "25"}, {"sender": ""},
        {"sender": "a@x\r\nBcc: z@x"}, {"recipients": []}, {"recipients": "b@x"},
        {"recipients": ["b@x", ""]}, {"recipients": ["b@x\nBcc: z@x"]},
        {"timeout_seconds": 0}, {"timeout_seconds": -1}, {"timeout_seconds": True},
        {"username_env": "USER"}, {"password_env": "PASS"},
        {"username_env": "not a name", "password_env": "PASS"},
        {"username_env": "USER", "password_env": "hunter2!"},
        {"username_env": "1USER", "password_env": "PASS"}, {"subject": "x\r\nBcc: z@x"},
        {"name": ""}, {"starttls": "false"},
    ],
)
def test_smtp_invalid_configuration_raises(kwargs):
    args = {"host": "mail.example.com", "port": 587, "sender": "a@x", "recipients": ["b@x"]}
    args.update(kwargs)
    host, port, sender, recipients = (args.pop(k) for k in ("host", "port", "sender", "recipients"))
    with pytest.raises(ValueError):
        SmtpDigestSink(host, port, sender, recipients, **args)


def test_smtp_missing_env_var_fails_without_connecting(smtp_stub, monkeypatch):
    monkeypatch.setenv("DIGEST_SMTP_USER", "mailer")
    monkeypatch.delenv("DIGEST_SMTP_MISSING", raising=False)
    server = smtp_stub()
    sink = _sink(server.server_address[1], creds=("DIGEST_SMTP_USER", "DIGEST_SMTP_MISSING"))
    result = sink.send(_nonempty_digest())
    assert result.status == "failed" and "DIGEST_SMTP_MISSING" in result.detail
    assert server.connections == 0
    monkeypatch.setenv("DIGEST_SMTP_MISSING", "")
    assert sink.send(_nonempty_digest()).status == "failed"
    assert server.connections == 0


def test_smtp_password_never_in_repr_or_result(monkeypatch, caplog):
    password = "pa55word-Secret"
    monkeypatch.setenv("DIGEST_SMTP_USER", "mailer")
    monkeypatch.setenv("DIGEST_SMTP_PASS", password)
    # Nothing listens on port 1, so the connection is refused.
    sink = _sink(1, starttls=True, timeout_seconds=2)
    for text in (repr(sink), str(sink)):
        assert "pa55" not in text and "DIGEST_SMTP_PASS" in text and "127.0.0.1" in text
    with caplog.at_level(logging.WARNING):
        result = sink.send(_nonempty_digest())
    assert result.status == "failed"
    assert "pa55" not in _all_fields(result) and "pa55" not in caplog.text


@pytest.mark.parametrize(
    "user, password",
    [("mailer", "s\u00e9cretp\u00e4ss"), ("m\u00e4iler", "s3cret"), ("mailer", "pa55\nword"),
     ("mail er", "s3cret"), ("mailer", "s3cret\x07")],
)
def test_smtp_unsendable_credentials_fail_before_connecting(
    smtp_stub, monkeypatch, caplog, user, password
):
    monkeypatch.setenv("DIGEST_SMTP_USER", user)
    monkeypatch.setenv("DIGEST_SMTP_PASS", password)
    server = smtp_stub()
    with caplog.at_level(logging.WARNING):
        result = _sink(server.server_address[1]).send(_nonempty_digest())
    assert result.status == "failed" and "cannot send" in result.detail
    assert server.connections == 0 and server.auth == []
    for secret in (user, password, "\u00e9", "\u00e4", "\\xe9", "\\xe4", "position"):
        if secret != "mailer":
            assert secret not in _all_fields(result) and secret not in caplog.text


def test_smtp_unicode_error_detail_is_class_name_only(fake_smtp, monkeypatch, caplog):
    monkeypatch.setenv("DIGEST_SMTP_USER", "mailer")
    monkeypatch.setenv("DIGEST_SMTP_PASS", "s3cret")
    fake_smtp.login_error = UnicodeEncodeError("ascii", "s\u00e9cret", 1, 2, "ordinal not in range")
    with caplog.at_level(logging.WARNING):
        result = _sink(2525, host="localhost").send(_nonempty_digest())
    assert result.status == "failed" and result.detail == "UnicodeEncodeError"
    assert "\\xe9" not in caplog.text and "position" not in caplog.text


def test_smtp_auth_error_echoing_credentials_is_redacted(fake_smtp, monkeypatch, caplog):
    monkeypatch.setenv("DIGEST_SMTP_USER", "mailer")
    monkeypatch.setenv("DIGEST_SMTP_PASS", "s3cret-Pa55")
    encoded = base64.b64encode(b"\0mailer\0s3cret-Pa55").decode("ascii")
    fake_smtp.login_error = RuntimeError(f"bad AUTH PLAIN {encoded} for mailer/s3cret-Pa55")
    sink = _sink(2525, host="localhost")
    with caplog.at_level(logging.WARNING):
        result = sink.send(_nonempty_digest())
    assert result.status == "failed"
    for secret in ("s3cret-Pa55", encoded, "mailer"):
        assert secret not in result.detail and secret not in caplog.text


def test_smtp_starttls_before_login_and_send(fake_smtp, monkeypatch):
    monkeypatch.setenv("U_ENV", "u")
    monkeypatch.setenv("P_ENV", "p")
    sink = _sink(587, host="mail.example.com", creds=("U_ENV", "P_ENV"), starttls=True,
                 timeout_seconds=7)
    assert sink.send(_nonempty_digest()).status == "sent"
    assert fake_smtp.calls == [
        ("connect", "mail.example.com", 587, 7.0), ("ehlo",), ("starttls", "SSLContext"),
        ("ehlo",), ("login",), ("send",),
    ]


SECRET_URL = "https://hookuser:hookpass@hooks.example.test:8443/services/T0K3N?token=q5ecret"


def _recording_sender(status=200, exc=None):
    calls = []

    def sender(method, url, headers, body, timeout):
        calls.append((method, url, dict(headers), body, timeout))
        if exc is not None:
            raise exc
        return status

    return sender, calls


def _assert_no_url_secrets(text: str) -> None:
    for secret in ("hookuser", "hookpass", "/services", "T0K3N", "token=", "q5ecret"):
        assert secret not in text


def test_webhook_payload_and_sent():
    sender, calls = _recording_sender(204)
    sink = WebhookDigestSink(SECRET_URL, sender=sender, timeout_seconds=3)
    digest = _nonempty_digest()
    result = sink.send(digest)
    assert result.status == "sent" and result.detail is None
    assert result.kind == "webhook" and result.name == "webhook"
    assert result.destination == "https://hooks.example.test:8443"
    method, url, headers, body, timeout = calls[0]
    assert method == "POST" and url == SECRET_URL and timeout == 3.0
    assert headers == {"Content-Type": "application/json"}
    assert json.loads(body.decode("utf-8")) == {
        "source": "sot-validator",
        "event_type": "sot_validator_weekly_digest",
        "text": render_digest_text(digest),
    }
    _assert_no_url_secrets(repr(sink) + str(sink))


def test_webhook_non_2xx_fails():
    sender, _ = _recording_sender(500)
    result = WebhookDigestSink(SECRET_URL, sender=sender, name="ops-hook").send(_nonempty_digest())
    assert result.status == "failed" and result.detail == "HTTP 500" and result.name == "ops-hook"
    _assert_no_url_secrets(_all_fields(result))


def test_webhook_exception_fails_and_redacts(caplog):
    sender, _ = _recording_sender(exc=OSError(f"cannot reach {SECRET_URL}"))
    with caplog.at_level(logging.WARNING):
        result = WebhookDigestSink(SECRET_URL, sender=sender).send(_nonempty_digest())
    assert result.status == "failed" and result.detail.startswith("OSError")
    _assert_no_url_secrets(_all_fields(result))
    _assert_no_url_secrets(caplog.text)


def test_webhook_non_int_status_fails():
    sender, _ = _recording_sender(status=True)
    assert WebhookDigestSink(SECRET_URL, sender=sender).send(_nonempty_digest()).status == "failed"


@pytest.mark.parametrize(
    "url",
    ["ftp://x", "http://", "http://exa mple.test/hook", "", "   ", "hooks.example.test/x",
     "https://example.test/hook\n", None, 42],
)
def test_webhook_invalid_url_raises(url):
    with pytest.raises(ValueError):
        WebhookDigestSink(url)


@pytest.mark.parametrize("kwargs", [{"sender": "nope"}, {"timeout_seconds": 0}, {"name": ""}])
def test_webhook_invalid_options_raise(kwargs):
    with pytest.raises(ValueError):
        WebhookDigestSink("https://example.test/hook", **kwargs)


def test_webhook_default_sender_is_drift_sender():
    from sot_validator.discovery import monitor

    sink = WebhookDigestSink("https://example.test/hook")
    assert sink.sender is monitor._default_sender


SENTINEL = "TOK3NSENTINEL"
SENTINEL_URL = f"https://user:{SENTINEL}@hooks.example.test/{SENTINEL}/x?key={SENTINEL}"


@pytest.fixture
def reset_sot_logger():
    logger = logging.getLogger("sot_validator")
    handlers = list(logger.handlers)
    level = logger.level
    yield
    for handler in list(logger.handlers):
        if handler not in handlers:
            logger.removeHandler(handler)
    logger.setLevel(level)


def _capture_logs(fmt) -> io.StringIO:
    stream = io.StringIO()
    configure_logging("WARNING", fmt=fmt, stream=stream)
    return stream


class _DirectResultSink(DigestSink):
    """Hands a raw destination straight to _result, as a careless future sink might."""

    kind = "direct"
    name = "direct"

    def __init__(self, destination):
        self.raw = destination

    def send(self, digest):
        return self._result(self.raw, f"boom {self.raw}")


@pytest.mark.parametrize("fmt", ["text", "json"])
@pytest.mark.parametrize(
    "sender_kwargs", [{"exc": OSError(f"cannot reach {SENTINEL_URL}")}, {"status": 503}],
    ids=["exception", "http-503"],
)
def test_webhook_sentinel_never_logged_or_returned(reset_sot_logger, fmt, sender_kwargs):
    stream = _capture_logs(fmt)
    sender, calls = _recording_sender(**sender_kwargs)
    result = WebhookDigestSink(SENTINEL_URL, sender=sender).send(_nonempty_digest())
    output = stream.getvalue()
    assert calls[0][1] == SENTINEL_URL
    assert result.status == "failed"
    assert result.destination == "https://hooks.example.test"
    for text in (output, result.destination, result.detail):
        assert SENTINEL not in text
    assert "https://hooks.example.test" in output and "failed" in output
    if "status" in sender_kwargs:
        assert result.detail == "HTTP 503"


@pytest.mark.parametrize("fmt", ["text", "json"])
def test_result_boundary_redacts_raw_url_destination(reset_sot_logger, fmt):
    stream = _capture_logs(fmt)
    result = _DirectResultSink(SENTINEL_URL).send(_nonempty_digest())
    output = stream.getvalue()
    assert result.status == "failed"
    assert result.destination == "https://hooks.example.test"
    for text in (output, result.destination, result.detail):
        assert SENTINEL not in text
    assert result.detail.startswith("boom ")
    assert "https://hooks.example.test" in output and "failed" in output


@pytest.mark.parametrize("fmt", ["text", "json"])
@pytest.mark.parametrize(
    "destination",
    [f"{SENTINEL}-not-a-url", f"hooks.example.test/{SENTINEL}", f"mailto:{SENTINEL}@x", ""],
)
def test_result_boundary_redacts_non_url_destination(reset_sot_logger, fmt, destination):
    stream = _capture_logs(fmt)
    result = _DirectResultSink(destination).send(_nonempty_digest())
    output = stream.getvalue()
    assert result.destination == "<redacted>"
    assert SENTINEL not in output and SENTINEL not in result.detail
    assert "<redacted>" in output


def test_result_boundary_keeps_port_and_ipv6_brackets():
    for raw, safe in (
        ("https://u:p@h.example:8443/a?b=c#f", "https://h.example:8443"),
        ("smtp://[::1]:25", "smtp://[::1]:25"),
        ("smtp://[bad", "<redacted>"),
    ):
        assert _DirectResultSink(raw).send(_nonempty_digest()).destination == safe


def test_redact_sentinel_success_result_keeps_destination_and_no_detail():
    sender, _ = _recording_sender(204)
    result = WebhookDigestSink(SENTINEL_URL, sender=sender).send(_nonempty_digest())
    assert (result.status, result.destination, result.detail) == (
        "sent", "https://hooks.example.test", None
    )


@pytest.mark.parametrize("fmt", ["text", "json"])
def test_smtp_failure_redacts_credentials_in_logs(
    reset_sot_logger, fake_smtp, monkeypatch, fmt
):
    monkeypatch.setenv("DIGEST_SMTP_USER", "digest-mailer-SENTINEL")
    monkeypatch.setenv("DIGEST_SMTP_PASS", "Pw-SENTINEL-55")

    def refuse(self, host, port, timeout):
        raise OSError(f"connection to {host}:{port} refused for digest-mailer-SENTINEL")

    monkeypatch.setattr(fake_smtp, "__init__", refuse)
    stream = _capture_logs(fmt)
    sink = _sink(587, host="mail.example.test", starttls=True)
    result = sink.send(_nonempty_digest())
    output = stream.getvalue()
    assert result.status == "failed"
    assert result.destination == "smtp://mail.example.test:587"
    assert "smtp://mail.example.test:587" in output and "failed" in output
    for secret in ("digest-mailer-SENTINEL", "Pw-SENTINEL-55"):
        assert secret not in output and secret not in _all_fields(result)


def test_smtp_ipv6_destination_redact_keeps_brackets(fake_smtp, monkeypatch):
    sink = SmtpDigestSink("::1", 25, "a@x", ["b@x"])
    assert sink.destination == "smtp://[::1]:25"

    def refuse(self, host, port, timeout):
        raise OSError("refused")

    monkeypatch.setattr(fake_smtp, "__init__", refuse)
    result = sink.send(_nonempty_digest())
    assert result.status == "failed" and result.destination == "smtp://[::1]:25"
