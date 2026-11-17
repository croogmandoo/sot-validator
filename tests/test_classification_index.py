"""Indexed per-site classification lookups must not change classification output."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json

from sot_validator.classifier.engine import ClassificationEngine
from sot_validator.models import (
    ArpEntry,
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    SignalType,
    Site,
    Subnet,
)
from sot_validator.signals._site_index import SiteRecordIndex
from sot_validator.signals.arp import ArpSignalEvaluator
from sot_validator.signals.directory_dns import DhcpLeaseRecord, DnsDhcpLeaseCollector
from sot_validator.signals.port_state import PortStateSignalEvaluator
from sot_validator.testing import SyntheticFleetGenerator

# Recorded on the unmodified linear-scan code (origin/main at 2fb47af)
EQUIVALENCE_SEED = 7
EQUIVALENCE_RESULT_COUNT = 384
EQUIVALENCE_DIGEST = "c756d4d1759f72ff56bdea1cff6b6836169ab98dd1fb17b1d01384c766c5d635"


def _equivalence_results() -> list[dict]:
    fleet = SyntheticFleetGenerator(
        EQUIVALENCE_SEED, sites=3, subnets_per_site=2, hosts_per_subnet=30
    ).generate()
    results: list[dict] = []
    for site in fleet.sites:
        engine = ClassificationEngine(
            evaluation_time=fleet.reference_time,
            dns_dhcp_collector=DnsDhcpLeaseCollector(
                dhcp_leases=fleet.dhcp_leases.get(site.site_id, []),
                site=site,
                evaluation_time=fleet.reference_time,
            ),
        )
        results.extend(result.to_dict() for result in engine.classify_site(site))
    return results


def _digest(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def test_synthetic_fleet_results_match_recorded_digest() -> None:
    results = _equivalence_results()
    assert len(results) == EQUIVALENCE_RESULT_COUNT
    assert _digest(results) == EQUIVALENCE_DIGEST


# Edge cases: classify_site (indexed) must equal per-target calls (linear scans)

REF = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
FRESH = REF - timedelta(days=1)
OLD = REF - timedelta(days=60)


def _engine(leases: list[DhcpLeaseRecord] | None = None) -> ClassificationEngine:
    return ClassificationEngine(
        evaluation_time=REF,
        dns_dhcp_collector=DnsDhcpLeaseCollector(
            dhcp_leases=leases or [], evaluation_time=REF
        ),
    )


def _linear_results(
    engine: ClassificationEngine, site: Site, **kwargs: object
) -> list[dict]:
    results = [engine.classify_device(d, site=site, **kwargs) for d in site.devices]
    results += [engine.classify_equipment(e, site=site, **kwargs) for e in site.equipment]
    results += [
        engine.classify_ip(ip, site=site, site_id=site.site_id, **kwargs)
        for ip in site.ip_addresses
    ]
    return [result.to_dict() for result in results]


def _indexed_results(
    engine: ClassificationEngine, site: Site, **kwargs: object
) -> list[dict]:
    return [result.to_dict() for result in engine.classify_site(site, **kwargs)]


def _signal(result: dict, signal_type: SignalType) -> dict:
    return next(s for s in result["signals"] if s["signal_type"] == signal_type.value)


def _result(results: list[dict], item_id: str) -> dict:
    return next(r for r in results if r["item_id"] == item_id)


def _site() -> Site:
    switch = NetworkDevice(
        device_id="sw1",
        site_id="S1",
        hostname="sw1",
        management_ip="10.1.1.2",
        ports=[
            Port("p1", "sw1", "ge-0/1", oper_status="up", connected_mac="AA:BB:CC:00:00:01"),
            Port("p2", "sw1", "ge-0/2", oper_status="down", connected_device_id="vm1"),
            Port("p3", "sw1", "ge-0/3", oper_status="up", connected_device_id="srv9"),
        ],
    )
    return Site(
        site_id="S1",
        name="Site 1",
        devices=[switch],
        subnets=[Subnet("sn1", "S1", "10.1.1.0/24")],
        ip_addresses=[
            IPAddress("10.1.1.10", "sn1", arp_last_seen=OLD),
            IPAddress("10.1.1.2", "sn1", assigned_object_id="sw1", arp_last_seen=FRESH),
            IPAddress("10.1.1.10", "sn1", arp_last_seen=FRESH),
            IPAddress("10.1.1.20", "sn1", assigned_object_id="srv1"),
        ],
        equipment=[
            Equipment("srv1", "S1", "srv1", assigned_ips=["10.1.1.10"], connected_ports=["sw1:ge-0/1"]),
            Equipment(
                "vm1",
                "S1",
                "vm1",
                category=EquipmentCategory.VM,
                assigned_ips=["10.1.1.30"],
                connected_ports=["ge-0/3"],
            ),
        ],
    )


def test_duplicate_ips_are_both_matched_in_order() -> None:
    site = _site()
    engine = _engine()
    indexed = _indexed_results(engine, site)
    assert indexed == _linear_results(engine, site)
    details = _signal(_result(indexed, "srv1"), SignalType.ARP_RECENCY)["details"]
    assert details.count("IP 10.1.1.10") == 2
    assert details.index("IP 10.1.1.10") < details.index("IP 10.1.1.20")


def test_orphan_assignment_does_not_attach_to_other_records() -> None:
    site = _site()
    site.ip_addresses.append(
        IPAddress("10.1.1.99", "sn1", assigned_object_id="ghost", arp_last_seen=FRESH)
    )
    engine = _engine()
    indexed = _indexed_results(engine, site)
    assert indexed == _linear_results(engine, site)
    for item_id in ("sw1", "srv1", "vm1"):
        signal = _signal(_result(indexed, item_id), SignalType.ARP_RECENCY)
        assert "10.1.1.99" not in signal["details"]


def test_mixed_format_macs_match_across_records() -> None:
    site = _site()
    site.ip_addresses.extend(
        [
            IPAddress("10.1.1.41", "sn1", arp_mac="aa-bb-cc-00-00-01", arp_last_seen=OLD),
            IPAddress(
                "10.1.1.42",
                "sn1",
                arp_entry=ArpEntry("10.1.1.42", "aabb.cc00.0001", arp_last_seen=OLD),
            ),
            IPAddress("10.1.1.43", "sn1", arp_mac="10.1.1.43", arp_last_seen=FRESH),
        ]
    )
    explicit_arp = [ArpEntry("10.1.1.44", "AABB.CC00.0001", arp_last_seen=FRESH)]
    engine = _engine()
    indexed = _indexed_results(engine, site, arp_entries=explicit_arp)
    assert indexed == _linear_results(engine, site, arp_entries=explicit_arp)
    details = _signal(_result(indexed, "srv1"), SignalType.ARP_RECENCY)["details"]
    positions = [details.index(f"IP 10.1.1.{n}") for n in (41, 42, 44)]
    assert positions == sorted(positions)
    assert "10.1.1.43" not in details


def test_explicit_records_merge_with_site_records() -> None:
    site = _site()
    shared_ip = site.ip_addresses[2]
    shared_port = site.devices[0].ports[1]
    extra_ips = [
        IPAddress("10.1.1.30", "sn1", arp_mac="aa:bb:cc:00:00:30", arp_last_seen=FRESH),
        shared_ip,
    ]
    extra_ports = [
        Port("x1", "sw2", "ge-1/1", oper_status="up", connected_device_id="vm1"),
        Port("x2", "sw2", "ge-1/2", oper_status="up", connected_mac="aa:bb:cc:00:00:30"),
        shared_port,
    ]
    extra_arp = [ArpEntry("10.1.1.2", "aa:bb:cc:00:00:02", arp_last_seen=OLD)]
    kwargs = {"ip_addresses": extra_ips, "ports": extra_ports, "arp_entries": extra_arp}
    engine = _engine()
    indexed = _indexed_results(engine, site, **kwargs)
    assert indexed == _linear_results(engine, site, **kwargs)
    vm_ports = _signal(_result(indexed, "vm1"), SignalType.PORT_STATE)["details"]
    assert vm_ports.index("sw2:ge-1/1") < vm_ports.index("sw1:ge-0/2")
    assert "srv9" not in vm_ports and "ge-0/3" not in vm_ports
    srv_arp = _signal(_result(indexed, "srv1"), SignalType.ARP_RECENCY)["details"]
    assert srv_arp.count("IP 10.1.1.10") == 2


def test_explicit_dhcp_leases_match_own_pool_behaviour() -> None:
    site = _site()
    pool = [
        DhcpLeaseRecord(ip="10.1.1.10", hostname="other", subnet_cidr="10.1.1.0/24", observed_at=FRESH),
        DhcpLeaseRecord(ip="10.1.1.77", hostname="SRV1.corp.example", observed_at=FRESH),
        DhcpLeaseRecord(ip="10.9.9.10", hostname="srv1", observed_at=FRESH),
        DhcpLeaseRecord(ip="10.1.1.10", hostname="srv1", status="expired", observed_at=OLD),
    ]
    own = DnsDhcpLeaseCollector(dhcp_leases=pool, site=site, evaluation_time=REF)
    other = DnsDhcpLeaseCollector(site=site, evaluation_time=REF)
    index = SiteRecordIndex(site)
    for target in (*site.equipment, *site.ip_addresses, *site.devices):
        expected = other.evaluate(target, site=site, dhcp_leases=pool)
        assert other.evaluate(target, site=site, leases=pool, _site_index=index) == expected
        assert own.evaluate(target, site=site, _site_index=index) == expected
        assert own.evaluate(target, site=site) == expected
    srv = own.evaluate(site.equipment[0], site=site, _site_index=index)
    assert [lease["ip"] for lease in srv.metadata["dhcp_leases"]] == [
        "10.1.1.10",
        "10.1.1.77",
        "10.1.1.10",
    ]


def test_site_mutated_between_calls_is_reflected() -> None:
    site = _site()
    engine = _engine()
    first = _indexed_results(engine, site)
    vm_arp = _signal(_result(first, "vm1"), SignalType.ARP_RECENCY)
    assert vm_arp["status"] == "not_applicable" or "no ARP timestamp" in vm_arp["details"]

    site.ip_addresses.append(
        IPAddress("10.1.1.31", "sn1", assigned_object_id="vm1", arp_last_seen=FRESH)
    )
    site.devices[0].ports.append(
        Port("p4", "sw1", "ge-0/4", oper_status="up", connected_device_id="vm1")
    )
    second = _indexed_results(engine, site)
    assert second == _linear_results(engine, site)
    assert second != first
    assert "IP 10.1.1.31" in _signal(_result(second, "vm1"), SignalType.ARP_RECENCY)["details"]
    assert "ge-0/4" in _signal(_result(second, "vm1"), SignalType.PORT_STATE)["details"]


def test_stale_or_foreign_index_is_ignored() -> None:
    site = _site()
    index = SiteRecordIndex(site)
    copy = Site.from_dict(site.to_dict())
    arp = ArpSignalEvaluator(evaluation_time=REF)
    ports = PortStateSignalEvaluator(evaluation_time=REF)
    extra = [IPAddress("10.1.1.30", "sn1", arp_last_seen=FRESH)]
    for target in (*copy.equipment, *copy.devices):
        assert arp.evaluate(target, site=copy, _site_index=index) == arp.evaluate(target, site=copy)
        assert ports.evaluate(target, site=copy, _site_index=index) == ports.evaluate(target, site=copy)
    vm = site.equipment[1]
    assert arp.evaluate(vm, site=site, ip_addresses=extra, _site_index=index) == arp.evaluate(
        vm, site=site, ip_addresses=extra
    )
