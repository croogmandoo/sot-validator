"""HTTP and HTML tests for the workbench Data Quality tab and `/api/quality`."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import json
from pathlib import Path
import re
import threading
from typing import Any, Optional
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from sot_validator.cli import main
from sot_validator.models import IPAddress, NetworkDevice, Site, Subnet
from sot_validator.quality import SINGLE_SITE_RULES, DataQualityChecker
from sot_validator.workbench import (
    WorkbenchSecurityConfig,
    WorkbenchState,
    create_workbench_server,
    render_workbench_html,
)
from sot_validator.workbench.quality_view import QUALITY_SCRIPT

WORKBENCH_TEST_TOKEN = "test-workbench-token"
XSS_SUBNET = "<img src=x onerror=alert(1)>"


def _site(orphan_subnet: Optional[str] = "sub-missing") -> Site:
    """Site with an orphan subnet_id, a duplicate IP and an IP outside every subnet."""
    ip_addresses = [
        IPAddress(
            ip="10.1.10.50",
            subnet_id="sub-10",
            assigned_object_type="NetworkDevice",
            assigned_object_id="dev-a",
        ),
        IPAddress(
            ip="10.1.10.50",
            subnet_id="sub-10",
            assigned_object_type="NetworkDevice",
            assigned_object_id="dev-b",
        ),
        IPAddress(ip="10.1.20.5", subnet_id="sub-10"),
    ]
    if orphan_subnet is not None:
        ip_addresses.append(IPAddress(ip="10.1.10.70", subnet_id=orphan_subnet))
    return Site(
        site_id="site-001",
        name="SF HQ Campus",
        devices=[
            NetworkDevice(
                device_id="dev-a",
                site_id="site-001",
                hostname="sw-a",
                management_ip="10.1.10.50",
            ),
            NetworkDevice(
                device_id="dev-b",
                site_id="site-001",
                hostname="sw-b",
                management_ip="10.1.10.50",
            ),
        ],
        subnets=[
            Subnet(
                subnet_id="sub-10",
                site_id="site-001",
                cidr="10.1.10.0/24",
                vlan_id="10",
            )
        ],
        ip_addresses=ip_addresses,
    )


def _clean_site() -> Site:
    return Site(
        site_id="site-clean",
        name="Clean Site",
        subnets=[Subnet(subnet_id="sub-10", site_id="site-clean", cidr="10.2.10.0/24")],
        ip_addresses=[IPAddress(ip="10.2.10.5", subnet_id="sub-10")],
    )


@contextmanager
def _live(state: WorkbenchState) -> Any:
    server = create_workbench_server(
        state,
        host="127.0.0.1",
        port=0,
        security=WorkbenchSecurityConfig(token=WORKBENCH_TEST_TOKEN),
    )
    host, port = server.server_address[:2]
    base_url = f"http://{host}:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield base_url, server, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3.0)


def _http_get_raw(url: str) -> tuple[int, bytes, str]:
    req = Request(url, method="GET")
    try:
        with urlopen(req, timeout=5) as resp:
            return resp.status, resp.read(), resp.headers.get("Content-Type", "")
    except HTTPError as err:
        return err.code, err.read(), err.headers.get("Content-Type", "")


def _http_get_json(url: str) -> tuple[int, dict[str, Any], str]:
    status, raw, content_type = _http_get_raw(url)
    return status, json.loads(raw.decode("utf-8")), content_type


def _element_by_id(page: str, tag: str, element_id: str) -> str:
    pattern = re.compile(
        rf'<{tag}\b[^>]*\bid="{re.escape(element_id)}"[^>]*>',
        re.IGNORECASE,
    )
    match = pattern.search(page)
    assert match is not None, element_id
    token = re.compile(rf"</?{tag}\b[^>]*>", re.IGNORECASE)
    depth = 0
    for tok in token.finditer(page, match.start()):
        snippet = tok.group(0)
        if snippet.startswith("</"):
            depth -= 1
            if depth == 0:
                return page[match.start() : tok.end()]
        elif snippet.endswith("/>"):
            if depth == 0:
                return page[match.start() : tok.end()]
        else:
            depth += 1
    raise AssertionError(f"unclosed {tag}#{element_id}")


def _expected(state: WorkbenchState) -> list[dict[str, Any]]:
    return [asdict(f) for f in DataQualityChecker().check_site(state.site)]


def test_quality_route_returns_checker_findings_as_json() -> None:
    state = WorkbenchState(_site())
    with _live(state) as (base_url, _server, _state):
        status, body, content_type = _http_get_json(f"{base_url}/api/quality")
    assert status == 200
    assert content_type.startswith("application/json")
    expected = _expected(state)
    assert body["site_id"] == "site-001"
    assert body["findings"] == expected
    assert body["total_findings"] == len(expected)
    rules = {f["rule"] for f in body["findings"]}
    assert "orphan_reference" in rules
    assert "duplicate_ip" in rules
    for finding in body["findings"]:
        assert set(finding) == {
            "finding_id",
            "site_id",
            "rule",
            "severity",
            "record_type",
            "record_ids",
            "message",
            "evidence",
        }


def test_quality_route_is_deterministic_and_read_only() -> None:
    state = WorkbenchState(_site())
    before_state = json.dumps(state.get_state_payload(), sort_keys=True, default=str)
    before_audit = [e.to_dict() for e in state.store.list_audit_log(limit=1000)]
    with _live(state) as (base_url, _server, _state):
        first = _http_get_raw(f"{base_url}/api/quality")
        second = _http_get_raw(f"{base_url}/api/quality")
        filtered = _http_get_raw(f"{base_url}/api/quality?severity=error")
    assert first[0] == second[0] == filtered[0] == 200
    assert first[1] == second[1]
    assert json.dumps(state.get_state_payload(), sort_keys=True, default=str) == before_state
    assert [e.to_dict() for e in state.store.list_audit_log(limit=1000)] == before_audit


def test_quality_route_matches_cli_findings(tmp_path: Path) -> None:
    site = _site()
    snapshot = tmp_path / "site.json"
    snapshot.write_text(site.to_json(indent=2), encoding="utf-8")
    out = tmp_path / "out" / "q.json"
    assert main(["quality", "--snapshot", str(snapshot), "--output-json", str(out)]) == 0
    cli_findings = json.loads(out.read_text(encoding="utf-8"))["findings"]

    state = WorkbenchState(site)
    with _live(state) as (base_url, _server, _state):
        _status, body, _ct = _http_get_json(f"{base_url}/api/quality")
    assert cli_findings
    assert body["findings"] == cli_findings


def test_quality_route_reflects_curated_site() -> None:
    state = WorkbenchState(_site())
    with _live(state) as (base_url, _server, _state):
        _status, before, _ct = _http_get_json(f"{base_url}/api/quality?rule=orphan_reference")
        assert before["total_findings"] >= 1
        state.apply_item_patch(
            {"target_type": "IPAddress", "target_id": "10.1.10.70", "subnet_id": "sub-10"},
            reason="fix orphan",
        )
        _status, after, _ct = _http_get_json(f"{base_url}/api/quality?rule=orphan_reference")
    assert after["total_findings"] == 0
    assert after["findings"] == []
    base_orphans = [
        f for f in DataQualityChecker().check_site(state.base_site) if f.rule == "orphan_reference"
    ]
    assert base_orphans


def test_quality_route_filters_by_rule_and_severity() -> None:
    state = WorkbenchState(_site())
    full = _expected(state)
    with _live(state) as (base_url, _server, _state):
        _s, by_sev, _ct = _http_get_json(f"{base_url}/api/quality?severity=error")
        _s, by_rule, _ct = _http_get_json(f"{base_url}/api/quality?rule=orphan_reference")
        _s, both, _ct = _http_get_json(
            f"{base_url}/api/quality?rule=orphan_reference&severity=warning"
        )
        _s, both_rev, _ct = _http_get_json(
            f"{base_url}/api/quality?severity=warning&rule=orphan_reference"
        )
        _s, blank, _ct = _http_get_json(f"{base_url}/api/quality?rule=&severity=")
        _s, repeated, _ct = _http_get_json(
            f"{base_url}/api/quality?rule=orphan_reference&rule=bogus"
        )
    assert {f["severity"] for f in full} == {"error", "warning"}
    assert by_sev["findings"] == [f for f in full if f["severity"] == "error"]
    assert by_sev["total_findings"] == len(by_sev["findings"])
    assert by_rule["findings"] == [f for f in full if f["rule"] == "orphan_reference"]
    assert by_rule["findings"]
    intersection = [
        f for f in full if f["rule"] == "orphan_reference" and f["severity"] == "warning"
    ]
    assert both["findings"] == intersection
    assert both["total_findings"] == len(intersection)
    assert both_rev == both
    assert blank["findings"] == full
    assert repeated == by_rule


def test_quality_route_rejects_bad_filters() -> None:
    state = WorkbenchState(_site())
    with _live(state) as (base_url, _server, _state):
        for query, bad in (
            ("rule=bogus", "bogus"),
            ("severity=critical", "critical"),
            ("rule=cross_site_duplicate_ip", "cross_site_duplicate_ip"),
            ("severity=ERROR", "ERROR"),
            ("rule=orphan_reference&severity=0", "0"),
        ):
            status, body, content_type = _http_get_json(f"{base_url}/api/quality?{query}")
            assert status == 400, query
            assert content_type.startswith("application/json")
            assert body["status"] == "error"
            assert bad in body["error"]
            assert "Traceback" not in body["error"]
        rule_status, rule_body, _ct = _http_get_json(f"{base_url}/api/quality?rule=bogus")
    assert rule_status == 400
    for name in SINGLE_SITE_RULES:
        assert name in rule_body["error"]


def test_quality_tab_renders_filters_rows_and_badges() -> None:
    state = WorkbenchState(_site())
    page = render_workbench_html(state)
    findings = DataQualityChecker().check_site(state.site)

    nav = re.search(r'<nav class="tabs">(.*?)</nav>', page, re.S)
    assert nav is not None
    last_button = re.findall(r"<button[^>]*>[^<]*</button>", nav.group(1))[-1]
    assert 'data-tab="tab-quality"' in last_button
    assert ">Data Quality</button>" in page
    assert 'id="tab-quality" class="tab-panel"' in page
    assert 'id="tab-quality" class="tab-panel active"' not in page

    section = _element_by_id(page, "section", "tab-quality")
    rule_select = _element_by_id(section, "select", "quality-rule-filter")
    options = re.findall(r'<option value="([^"]*)">([^<]*)</option>', rule_select)
    assert options[0] == ("", "All rules")
    assert [value for value, _label in options[1:]] == list(SINGLE_SITE_RULES)
    sev_select = _element_by_id(section, "select", "quality-severity-filter")
    sev_options = re.findall(r'<option value="([^"]*)">([^<]*)</option>', sev_select)
    assert sev_options == [
        ("", "All severities"),
        ("error", "error"),
        ("warning", "warning"),
        ("info", "info"),
    ]

    assert re.search(r'<div class="quality-scroll">\s*<table id="quality-table">', section)
    headers = re.findall(r"<th>([^<]*)</th>", _element_by_id(section, "table", "quality-table"))
    assert headers == ["Rule", "Severity", "Records", "Message"]
    tbody = _element_by_id(section, "tbody", "quality-tbody")
    rows = re.findall(r'<tr data-rule="([^"]*)" data-severity="([^"]*)">', tbody)
    assert rows == [(f.rule, f.severity) for f in findings]
    dup = next(f for f in findings if f.rule == "duplicate_ip")
    assert ", ".join(dup.record_ids) in tbody

    error_rows = re.findall(r'<tr data-rule="[^"]*" data-severity="error">.*?</tr>', tbody)
    assert error_rows
    for row in error_rows:
        assert 'class="badge badge-stale"' in row
    assert re.search(r"\.quality-scroll \{[^}]*overflow-x: auto;[^}]*\}", page)
    assert re.search(r"#quality-table td \{[^}]*overflow-wrap: anywhere", page)

    empty = _element_by_id(section, "p", "quality-empty")
    assert " hidden" in empty


def test_quality_tab_severity_badge_mapping() -> None:
    from sot_validator.workbench.quality_view import QUALITY_SEVERITY_BADGES

    assert QUALITY_SEVERITY_BADGES == {
        "error": "badge-stale",
        "warning": "badge-unreachable",
        "info": "badge-info",
    }
    assert "error: 'badge-stale'" in QUALITY_SCRIPT
    assert "warning: 'badge-unreachable'" in QUALITY_SCRIPT
    assert "info: 'badge-info'" in QUALITY_SCRIPT


def test_quality_tab_escapes_finding_text() -> None:
    state = WorkbenchState(_site(orphan_subnet=XSS_SUBNET))
    page = render_workbench_html(state)
    section = _element_by_id(page, "section", "tab-quality")
    assert "&lt;img src=x onerror=alert(1)&gt;" in section
    assert "<img src=x" not in section
    assert "<script src=" not in page
    assert "fetch('/api/quality')" in page
    assert QUALITY_SCRIPT in page
    assert "escapeHtml(f.rule)" in QUALITY_SCRIPT
    assert "escapeHtml(f.severity)" in QUALITY_SCRIPT
    assert "escapeHtml(f.message)" in QUALITY_SCRIPT
    assert "escapeHtml((f.record_ids || []).join(', '))" in QUALITY_SCRIPT
    assert "refreshQualityFindings();" in page
    assert re.search(
        r"refreshTopologyMap\(\);\s*refreshQualityFindings\(\);\s*\}", page
    )
    assert "showBanner('Data quality findings could not be refreshed.', true)" in QUALITY_SCRIPT


def test_quality_tab_empty_state_for_clean_site() -> None:
    state = WorkbenchState(_clean_site())
    assert DataQualityChecker().check_site(state.site) == []
    with _live(state) as (base_url, _server, _state):
        status, raw, _ct = _http_get_raw(f"{base_url}/")
        _s, body, _ct = _http_get_json(f"{base_url}/api/quality")
    assert status == 200
    assert body == {"site_id": "site-clean", "total_findings": 0, "findings": []}
    page = raw.decode("utf-8")
    section = _element_by_id(page, "section", "tab-quality")
    empty = _element_by_id(section, "p", "quality-empty")
    assert "No data-quality findings for this site." in empty
    assert "hidden" not in empty
    assert re.search(r'<tbody id="quality-tbody"></tbody>', section)
    assert "No findings match the selected filters." in QUALITY_SCRIPT
    assert "function applyQualityFilters()" in QUALITY_SCRIPT
    assert "tr.dataset.rule === rule" in QUALITY_SCRIPT
    assert "tr.dataset.severity === severity" in QUALITY_SCRIPT


def test_quality_route_does_not_need_token_but_writes_still_do() -> None:
    state = WorkbenchState(_site())
    with _live(state) as (base_url, _server, _state):
        status, _body, _ct = _http_get_json(f"{base_url}/api/quality")
        assert status == 200
        parsed = urlparse(base_url)
        req = Request(
            f"{base_url}/api/items/patch",
            data=json.dumps({"target_type": "IPAddress", "target_id": "10.1.10.70"}).encode(),
            headers={"Content-Type": "application/json", "Origin": f"{parsed.scheme}://{parsed.netloc}"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=5) as resp:
                post_status = resp.status
        except HTTPError as err:
            post_status = err.code
    assert post_status == 401
