"""Indexed per-site classification lookups must not change classification output."""

from __future__ import annotations

import hashlib
import json

from sot_validator.classifier.engine import ClassificationEngine
from sot_validator.signals.directory_dns import DnsDhcpLeaseCollector
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
