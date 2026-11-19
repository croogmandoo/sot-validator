"""Per-site /24 subnet utilization analysis mixin for HistoryStore."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Optional

from sot_validator.history._records import (
    SubnetUtilizationSummary,
    _coerce_sites,
    _try_parse_ipv4,
    _try_parse_slash24_ipv4,
)
from sot_validator.models import Site, ValidationClassification, ValidationResult


class _AnalysisMixin:
    """Per-site /24 subnet utilization analysis for HistoryStore."""

    @staticmethod
    def compute_subnet_utilization(
        sites: Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any],
        results: Sequence[ValidationResult | Mapping[str, Any]],
    ) -> list[SubnetUtilizationSummary]:
        """Compute per-site /24 subnet IP assignment, active usage, and reclaimable stale IP metrics."""
        site_list = _coerce_sites(sites)
        result_list: list[ValidationResult] = [
            r if isinstance(r, ValidationResult) else ValidationResult.from_dict(r)
            for r in results
        ]

        ip_results_by_site: dict[tuple[str, str], ValidationResult] = {}
        ip_results_global: dict[str, ValidationResult] = {}
        obj_results_by_site: dict[tuple[str, str], ValidationResult] = {}
        obj_results_global: dict[str, ValidationResult] = {}

        for res in result_list:
            if res.item_type == "IPAddress":
                parsed_ip = _try_parse_ipv4(res.item_id)
                norm_ip = str(parsed_ip) if parsed_ip is not None else res.item_id.strip()
                ip_results_by_site[(res.site_id, norm_ip)] = res
                ip_results_global[norm_ip] = res
            else:
                obj_results_by_site[(res.site_id, res.item_id)] = res
                obj_results_global[res.item_id] = res

        summaries: list[SubnetUtilizationSummary] = []

        for site in site_list:
            ip_to_assigned_obj_ids: dict[str, list[str]] = {}

            def _link_ip_obj(ip_val: str, obj_id: Optional[str]) -> None:
                if not obj_id or not obj_id.strip():
                    return
                clean_obj = obj_id.strip()
                bucket = ip_to_assigned_obj_ids.setdefault(ip_val, [])
                if clean_obj not in bucket:
                    bucket.append(clean_obj)

            for ip_rec in site.ip_addresses:
                parsed = _try_parse_ipv4(ip_rec.ip)
                if parsed is not None:
                    _link_ip_obj(str(parsed), ip_rec.assigned_object_id)

            for eq in site.equipment:
                for raw_ip in eq.assigned_ips:
                    parsed = _try_parse_ipv4(raw_ip)
                    if parsed is not None:
                        _link_ip_obj(str(parsed), eq.equipment_id)

            for dev in site.devices:
                parsed = _try_parse_ipv4(dev.management_ip)
                if parsed is not None:
                    _link_ip_obj(str(parsed), dev.device_id)

            for subnet in site.subnets:
                net = _try_parse_slash24_ipv4(subnet.cidr)
                if net is None:
                    continue

                assigned_ips: set[str] = set()
                for ip_rec in site.ip_addresses:
                    parsed = _try_parse_ipv4(ip_rec.ip)
                    if parsed is not None and (
                        ip_rec.subnet_id == subnet.subnet_id or parsed in net
                    ):
                        assigned_ips.add(str(parsed))

                for eq in site.equipment:
                    for raw_ip in eq.assigned_ips:
                        parsed = _try_parse_ipv4(raw_ip)
                        if parsed is not None and parsed in net:
                            assigned_ips.add(str(parsed))

                for dev in site.devices:
                    parsed = _try_parse_ipv4(dev.management_ip)
                    if parsed is not None and parsed in net:
                        assigned_ips.add(str(parsed))

                confirmed_active_count = 0
                stale_reclaimable_count = 0

                for ip_str in sorted(assigned_ips):
                    direct_res = ip_results_by_site.get(
                        (site.site_id, ip_str)
                    ) or ip_results_global.get(ip_str)

                    linked_res: Optional[ValidationResult] = None
                    for obj_id in ip_to_assigned_obj_ids.get(ip_str, ()):
                        candidate = obj_results_by_site.get(
                            (site.site_id, obj_id)
                        ) or obj_results_global.get(obj_id)
                        if candidate is not None:
                            linked_res = candidate
                            if candidate.classification in (
                                ValidationClassification.CONFIRMED_ACTIVE,
                                ValidationClassification.STALE_LIKELY_UNUSED,
                            ):
                                break

                    effective_cls: Optional[ValidationClassification] = None
                    if direct_res is not None and direct_res.classification in (
                        ValidationClassification.CONFIRMED_ACTIVE,
                        ValidationClassification.STALE_LIKELY_UNUSED,
                    ):
                        effective_cls = direct_res.classification
                    elif linked_res is not None and linked_res.classification in (
                        ValidationClassification.CONFIRMED_ACTIVE,
                        ValidationClassification.STALE_LIKELY_UNUSED,
                    ):
                        effective_cls = linked_res.classification
                    elif direct_res is not None:
                        effective_cls = direct_res.classification
                    elif linked_res is not None:
                        effective_cls = linked_res.classification

                    if (
                        effective_cls
                        is ValidationClassification.CONFIRMED_ACTIVE
                    ):
                        confirmed_active_count += 1
                    elif (
                        effective_cls
                        is ValidationClassification.STALE_LIKELY_UNUSED
                    ):
                        stale_reclaimable_count += 1

                total_assigned = len(assigned_ips)
                utilization_pct = (
                    round((confirmed_active_count / total_assigned) * 100.0, 2)
                    if total_assigned > 0
                    else 0.0
                )

                summaries.append(
                    SubnetUtilizationSummary(
                        subnet_id=subnet.subnet_id,
                        site_id=site.site_id,
                        cidr=subnet.cidr,
                        total_assigned_ips=total_assigned,
                        confirmed_active_ips=confirmed_active_count,
                        stale_reclaimable_ips=stale_reclaimable_count,
                        active_utilization_pct=utilization_pct,
                    )
                )

        return summaries
