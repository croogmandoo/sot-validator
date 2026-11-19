"""Golden-output test: render_workbench_html must stay byte-identical."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re

from sot_validator.classifier.engine import ClassificationEngine
from sot_validator.curation import ItemEditPatch
from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    Subnet,
    VLAN,
)
from sot_validator.workbench import WorkbenchState, render_workbench_html

GOLDEN_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "workbench_ui" / "workbench.golden.html"
)
GOLDEN_TITLE = "Golden <Workbench> & {braces} \"quoted\" 'single' </script>"
FIXED_NOW = datetime(2026, 1, 20, 12, 0, 0, tzinfo=timezone.utc)
NASTY = "<b>&\"'{x}</script>"

# Values that still depend on the wall clock or uuid4 when the page is rendered.
_ISO_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"
)
_AUDIT_ENTRY_ID = re.compile(r"audit-(\d{4})-[0-9a-f]{8}")
_SHA256_HEX = re.compile(r"\b[0-9a-f]{64}\b")


def _normalise(text: str) -> str:
    text = _ISO_TIMESTAMP.sub("<TIMESTAMP>", text)
    text = _AUDIT_ENTRY_ID.sub(r"audit-\1-<UUID>", text)
    return _SHA256_HEX.sub("<SHA256>", text)


def _golden_site() -> Site:
    seen = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    old = datetime(2025, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    return Site(
        site_id="site-001",
        name=f"SF HQ {NASTY}",
        address="100 Market St, San Francisco, CA",
        contact_info="netops@example.com",
        rooms=["MDF-1", "IDF-2"],
        devices=[
            NetworkDevice(
                device_id="dev-core-01",
                site_id="site-001",
                hostname=f"sw-core-01{NASTY}",
                management_ip="10.1.1.2",
                vendor="Extreme Networks",
                model="Summit X440-G2-24p",
                role="switch",
                last_seen=seen,
                ports=[
                    Port(
                        port_id="dev-core-01:1:1",
                        device_id="dev-core-01",
                        name="1:1",
                        admin_status="up",
                        oper_status="up",
                        poe_status="delivering",
                        connected_device_id="eq-win-01",
                        connected_mac="00:11:22:33:44:55",
                        vlan_id="10",
                    ),
                    Port(
                        port_id="dev-core-01:1:2",
                        device_id="dev-core-01",
                        name="1:2",
                        admin_status="up",
                        oper_status="down",
                        poe_status="auto",
                        vlan_id="10",
                    ),
                    Port(
                        port_id="dev-core-01:1:24",
                        device_id="dev-core-01",
                        name="uplink-1:24",
                        admin_status="up",
                        oper_status="up",
                        connected_device_id="dev-acc-02",
                        vlan_id="20",
                    ),
                ],
            ),
            NetworkDevice(
                device_id="dev-acc-02",
                site_id="site-001",
                hostname="sw-access-02",
                management_ip="10.1.10.50",
                vendor="Extreme Networks",
                model="VSP 7400-48Y",
                role="switch",
                last_seen=old,
            ),
        ],
        vlans=[
            VLAN(
                vlan_id="10",
                site_id="site-001",
                name=f"Servers {NASTY}",
                subnet_id="sub-10",
                cidr="10.1.10.0/24",
                gateway="10.1.10.1",
            ),
            VLAN(
                vlan_id="20",
                site_id="site-001",
                name="Uplinks",
                subnet_id="sub-20",
                cidr="10.1.20.0/24",
                gateway="10.1.20.1",
            ),
        ],
        subnets=[
            Subnet(
                subnet_id="sub-10",
                site_id="site-001",
                cidr="10.1.10.0/24",
                vlan_id="10",
                gateway="10.1.10.1",
                name="Servers",
            ),
            Subnet(
                subnet_id="sub-20",
                site_id="site-001",
                cidr="10.1.20.0/24",
                vlan_id="20",
                gateway="10.1.20.1",
                name="Uplinks",
            ),
        ],
        ip_addresses=[
            IPAddress(
                ip="10.1.10.50",
                subnet_id="sub-10",
                assigned_object_type="Equipment",
                assigned_object_id="eq-win-01",
                arp_mac="00:11:22:33:44:55",
                arp_last_seen=seen,
                arp_source_device_id="dev-core-01",
            ),
            IPAddress(
                ip="10.1.10.50",
                subnet_id="sub-10",
                assigned_object_type="NetworkDevice",
                assigned_object_id="dev-acc-02",
            ),
            IPAddress(ip="10.1.30.9", subnet_id="sub-missing"),
        ],
        equipment=[
            Equipment(
                equipment_id="eq-win-01",
                site_id="site-001",
                name=f"win-app-01{NASTY}",
                category=EquipmentCategory.VM,
                assigned_ips=["10.1.10.50"],
                connected_ports=["dev-core-01:1:1"],
                power_state="poweredOn",
                last_seen=seen,
            ),
            Equipment(
                equipment_id="eq-old-01",
                site_id="site-001",
                name="old-printer",
                category=EquipmentCategory.OTHER,
                connected_ports=["dev-core-01:1:2"],
                last_seen=old,
            ),
            Equipment(
                equipment_id="eq-mystery-01",
                site_id="site-001",
                name="unknown-box-99",
                category=EquipmentCategory.OTHER,
            ),
        ],
    )


def _golden_state() -> WorkbenchState:
    state = WorkbenchState(
        _golden_site(),
        classifier=ClassificationEngine(evaluation_time=FIXED_NOW),
    )
    state.apply_item_patch(
        ItemEditPatch(
            target_type="Equipment",
            target_id="eq-win-01",
            site_id="site-001",
            room="MDF-1",
            vlan_id="10",
            notes=f"patched {NASTY}",
            updated_at=FIXED_NOW,
        ),
        actor="golden",
        reason=f"golden reason {NASTY}",
    )
    state.apply_item_patch(
        ItemEditPatch(
            target_type="NetworkDevice",
            target_id="dev-core-01",
            site_id="site-001",
            room="IDF-2",
            notes="core notes",
            updated_at=FIXED_NOW,
        ),
        actor="golden",
        reason="device note",
    )
    return state


def test_render_workbench_html_matches_golden() -> None:
    rendered = _normalise(render_workbench_html(_golden_state(), title=GOLDEN_TITLE))
    if os.environ.get("UPDATE_WORKBENCH_UI_GOLDEN") == "1":
        GOLDEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN_PATH.write_text(rendered, encoding="utf-8")
    golden = GOLDEN_PATH.read_text(encoding="utf-8")
    assert rendered == golden


def test_golden_fixture_exercises_every_branch() -> None:
    golden = GOLDEN_PATH.read_text(encoding="utf-8")
    # Faceplate template, PoE badge and uplink port.
    assert 'data-template-ports="24"' in golden
    assert "faceplate-poe-badge" in golden
    assert "faceplate-port faceplate-uplink" in golden
    assert "faceplate-port faceplate-stale" in golden
    # Patched inventory row and audit row.
    assert "patched &lt;b&gt;&amp;&quot;&#x27;{x}&lt;/script&gt;" in golden
    assert "golden reason &lt;b&gt;" in golden
    # Data-quality finding.
    assert "duplicate_ip" in golden
    # Script embedding escapes the closing tag; HTML escaping covers the title.
    assert "<\\/script>" in golden
    assert "Golden &lt;Workbench&gt; &amp; {braces}" in golden
