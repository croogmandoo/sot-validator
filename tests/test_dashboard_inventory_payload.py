"""Compressed, client-rendered inventory payload embedded in the HTML dashboard."""

from __future__ import annotations

import base64
import gzip
import json
import re
from typing import Any

from sot_validator.models import Site, ValidationResult, ValidationSignal
from sot_validator.reporting.dashboard import generate_html_dashboard
from sot_validator.testing import SyntheticFleetGenerator, run_pipeline

GENERATED_AT = "2026-01-01T00:00:00Z"

# html_length for SyntheticFleetGenerator(7, sites=3, subnets_per_site=2,
# hosts_per_subnet=30) measured on the unmodified, server-rendered dashboard.
BASELINE_SMALL_FLEET_HTML_CHARS = 729_776

HOSTILE = (
    "</script><script>alert(1)</script> <!-- "
    "\"><img src=x onerror=alert(1)> ' \" &amp; &    "
)

SINK_TOKENS = (
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "eval(",
    "new Function",
    'setTimeout("',
    "setTimeout('",
    'setInterval("',
    "setInterval('",
)

_PAYLOAD_RE = re.compile(
    r'<script id="inventory-data" type="application/octet-stream">(.*?)</script>',
    re.S,
)


def _payload_text(html_doc: str) -> str:
    match = _PAYLOAD_RE.search(html_doc)
    assert match is not None, "inventory-data payload not found"
    return match.group(1)


def _decode_payload(html_doc: str) -> list[dict[str, Any]]:
    raw = gzip.decompress(base64.b64decode(_payload_text(html_doc), validate=True))
    return json.loads(raw.decode("utf-8"))


def _field_results() -> list[Any]:
    return [
        ValidationResult(
            item_type="NetworkDevice",
            item_id="dev-1",
            site_id="site-nameless",
            name="core-sw-1",
            classification="Confirmed Active",
            confidence=0.834,
            rationale="ARP seen recently",
            signals=[
                ValidationSignal(
                    signal_type="ARP_RECENCY",
                    status="ACTIVE",
                    age_seconds=8489.04,
                    source="arp-table",
                    details="seen on vlan 10",
                ),
                ValidationSignal(signal_type="ICMP_REACHABILITY", status="UNREACHABLE"),
            ],
        ),
        {
            "item_type": "Equipment",
            "item_id": "eq-1",
            "site_id": "site-named",
            "site_name": "Named Site",
            "name": "printer-1",
            "classification": "Stale / Likely Unused",
            "confidence": 0.5,
            "rationale": "No ARP",
            "ip_addresses": ["10.1.1.5", "10.1.1.6"],
            "signals": [],
        },
        ValidationResult(
            item_type="IPAddress",
            item_id="10.1.2.3",
            site_id="site-named",
            name="10.1.2.3",
            classification="Unreachable / Needs Manual Review",
            confidence=0.0,
        ),
        ValidationResult(
            item_type="NetworkDevice",
            item_id="dev-2",
            site_id="site-nameless",
            name="edge-sw-2",
            classification="Insufficient Data",
            confidence=1.0,
        ),
    ]


def test_payload_field_values_match_display_strings() -> None:
    html_doc = generate_html_dashboard(_field_results(), generated_at=GENERATED_AT)
    records = _decode_payload(html_doc)

    assert [r["item_id"] for r in records] == ["dev-1", "eq-1", "10.1.2.3", "dev-2"]
    assert records[0] == {
        "site_id": "site-nameless",
        "site_name": "site-nameless",
        "item_type": "NetworkDevice",
        "item_id": "dev-1",
        "name": "core-sw-1",
        "category": "-",
        "ips": "-",
        "classification": "Confirmed Active",
        "badge": "badge-active",
        "confidence": "0.83",
        "rationale": "ARP seen recently",
        "signals": [
            {
                "type": "ARP_RECENCY",
                "status": "ACTIVE",
                "source": "arp-table",
                "age": "8489.0s",
                "details": "seen on vlan 10",
            },
            {
                "type": "ICMP_REACHABILITY",
                "status": "UNREACHABLE",
                "source": "n/a",
                "age": "n/a",
                "details": "",
            },
        ],
    }
    assert records[1]["site_name"] == "Named Site"
    assert records[1]["category"] == "other"
    assert records[1]["ips"] == "10.1.1.5, 10.1.1.6"
    assert records[1]["badge"] == "badge-stale"
    assert records[1]["confidence"] == "0.50"
    assert records[1]["signals"] == []
    assert records[2]["ips"] == "10.1.2.3"
    assert records[2]["badge"] == "badge-unreachable"
    assert records[2]["rationale"] == ""
    assert records[2]["confidence"] == "0.00"
    assert records[3]["badge"] == "badge-insufficient"
    assert records[3]["confidence"] == "1.00"

    assert 'class="inventory-row"' not in html_doc
    assert 'id="inventory-status-row"' in html_doc
    assert "data-search" not in html_doc


def test_hostile_strings_stay_inert_and_round_trip() -> None:
    site = Site(site_id="site-h", name="Site " + HOSTILE)
    result = ValidationResult(
        item_type="Equipment",
        item_id="eq-h",
        site_id="site-h",
        name="Name " + HOSTILE,
        classification="Stale / Likely Unused",
        confidence=0.25,
        rationale="Why " + HOSTILE,
        signals=[
            ValidationSignal(
                signal_type="ARP_RECENCY",
                status="ACTIVE",
                age_seconds=1.0,
                source="src " + HOSTILE,
                details="det " + HOSTILE,
            )
        ],
    )
    html_doc = generate_html_dashboard(
        [result], sites=[site], title="Dashboard", generated_at=GENERATED_AT
    )

    assert "<img src=x onerror" not in html_doc
    assert "<script>alert(1)" not in html_doc
    assert "<!--" not in html_doc
    assert html_doc.count("</script>") == html_doc.count("<script")
    assert html_doc.count("<script") == 2
    assert re.fullmatch(r"[A-Za-z0-9+/=]*", _payload_text(html_doc))

    (record,) = _decode_payload(html_doc)
    assert record["site_name"] == "Site " + HOSTILE
    assert record["name"] == "Name " + HOSTILE
    assert record["rationale"] == "Why " + HOSTILE
    assert record["signals"][0]["source"] == "src " + HOSTILE
    assert record["signals"][0]["details"] == "det " + HOSTILE


def test_dashboard_scripts_use_no_html_sinks() -> None:
    html_doc = generate_html_dashboard(_field_results(), generated_at=GENERATED_AT)
    for token in SINK_TOKENS:
        assert token not in html_doc, token
    assert "<script src" not in html_doc
    assert "<link" not in html_doc
    assert re.search(r"https?://", html_doc) is None


def test_empty_results_render_static_empty_row() -> None:
    html_doc = generate_html_dashboard([], generated_at=GENERATED_AT)
    assert 'id="inventory-data"' not in html_doc
    assert 'id="inventory-status-row"' not in html_doc
    assert (
        '<tr><td colspan="11" class="empty-cell">'
        "No inventory validation results available.</td></tr>"
    ) in html_doc


def test_dashboard_output_is_deterministic() -> None:
    first = generate_html_dashboard(_field_results(), generated_at=GENERATED_AT)
    second = generate_html_dashboard(_field_results(), generated_at=GENERATED_AT)
    assert first == second

    raw = gzip.decompress(base64.b64decode(_payload_text(first)))
    assert raw == json.dumps(json.loads(raw), separators=(",", ":")).encode("utf-8")


def test_small_fleet_dashboard_is_five_times_smaller() -> None:
    fleet = SyntheticFleetGenerator(
        7, sites=3, subnets_per_site=2, hosts_per_subnet=30
    ).generate()
    timings = run_pipeline(fleet)
    assert timings.result_count > 0
    assert timings.html_length <= BASELINE_SMALL_FLEET_HTML_CHARS // 5
