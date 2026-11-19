"""Staged Extreme Networks switch port and PoE reclamation planner."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any, Optional

from sot_validator.history.ledger import HistoryStore, ItemStreakSummary
from sot_validator.models import (
    ArpEntry,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    ValidationClassification,
)
from sot_validator.remediation._port_reclamation_common import (
    ExtremeCliDialect,
    _clean_optional_str,
    _coerce_cli_dialect,
    _coerce_port_and_extras,
    _port_matches_identifier,
)
from sot_validator.remediation._port_reclamation_guard import LldpUplinkGuard
from sot_validator.remediation._port_reclamation_plan import (
    PortReclamationCandidate,
    PortReclamationPlan,
)
from sot_validator.remediation._port_reclamation_records import (
    BlockedPortRecord,
    LldpNeighborRecord,
)
from sot_validator.remediation._port_reclamation_streaks import _PlannerLookupMixin
from sot_validator.signals.base import resolve_evaluation_time
from sot_validator.signals.management import IF_MIB_IF_ALIAS_PREFIX
from sot_validator.signals.port_state import _ADMIN_DISABLED_VALUES


class ExtremePortReclamationPlanner(_PlannerLookupMixin):
    """Staged Extreme Networks switch port and PoE reclamation planner with LLDP uplink guard."""

    def __init__(
        self,
        *,
        min_inactive_runs: int = 3,
        min_inactive_days: float = 30.0,
        uplink_guard: Optional[LldpUplinkGuard] = None,
        dialect: ExtremeCliDialect | str = ExtremeCliDialect.EXOS,
        default_searching_poe_watts: float = 0.0,
        default_poe_restore_limit_mw: int = 30000,
    ) -> None:
        if isinstance(min_inactive_runs, bool) or not isinstance(
            min_inactive_runs, int
        ) or min_inactive_runs < 1:
            raise ValueError("min_inactive_runs must be an integer >= 1")
        if isinstance(min_inactive_days, bool) or not isinstance(
            min_inactive_days, (int, float)
        ) or float(min_inactive_days) < 0.0:
            raise ValueError("min_inactive_days must be a non-negative number")
        if isinstance(default_searching_poe_watts, bool) or not isinstance(
            default_searching_poe_watts, (int, float)
        ) or float(default_searching_poe_watts) < 0.0:
            raise ValueError(
                "default_searching_poe_watts must be a non-negative number"
            )
        if isinstance(default_poe_restore_limit_mw, bool) or not isinstance(
            default_poe_restore_limit_mw, int
        ) or default_poe_restore_limit_mw < 0:
            raise ValueError(
                "default_poe_restore_limit_mw must be a non-negative integer"
            )

        self.min_inactive_runs: int = min_inactive_runs
        self.min_inactive_days: float = float(min_inactive_days)
        self.uplink_guard: LldpUplinkGuard = (
            uplink_guard
            if uplink_guard is not None
            else LldpUplinkGuard(arp_active_within_days=float(min_inactive_days))
        )
        self.dialect: ExtremeCliDialect = _coerce_cli_dialect(dialect, "dialect")
        self.default_searching_poe_watts: float = float(
            default_searching_poe_watts
        )
        self.default_poe_restore_limit_mw: int = default_poe_restore_limit_mw

    def plan(
        self,
        *,
        sites: Optional[
            Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        ports: Optional[Sequence[Port | Mapping[str, Any]]] = None,
        devices: Optional[Sequence[NetworkDevice | Mapping[str, Any]]] = None,
        streaks: Optional[
            Sequence[ItemStreakSummary | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        history_store: Optional[HistoryStore] = None,
        lldp_neighbors: Optional[
            Mapping[str, Any]
            | Sequence[LldpNeighborRecord | Mapping[str, Any]]
        ] = None,
        port_descriptions: Optional[Mapping[str, str]] = None,
        tagged_vlans_by_port: Optional[
            Mapping[str, Iterable[str | int]]
        ] = None,
        trunk_ports: Optional[Iterable[str]] = None,
        poe_watts_by_port: Optional[Mapping[str, float]] = None,
        poe_limit_mw_by_port: Optional[Mapping[str, int]] = None,
        snmp_oids_by_device: Optional[Mapping[str, Any]] = None,
        ip_addresses: Optional[Sequence[IPAddress | Mapping[str, Any]]] = None,
        arp_entries: Optional[Sequence[ArpEntry | Mapping[str, Any]]] = None,
        active_macs: Optional[Iterable[str]] = None,
        evaluation_time: Optional[datetime | str] = None,
        dialect: Optional[ExtremeCliDialect | str] = None,
        min_inactive_runs: Optional[int] = None,
        min_inactive_days: Optional[float] = None,
    ) -> PortReclamationPlan:
        """Evaluate candidate switch ports and generate a staged PortReclamationPlan."""
        effective_runs = (
            min_inactive_runs
            if min_inactive_runs is not None
            else self.min_inactive_runs
        )
        effective_days = (
            float(min_inactive_days)
            if min_inactive_days is not None
            else self.min_inactive_days
        )
        effective_dialect = (
            _coerce_cli_dialect(dialect, "dialect")
            if dialect is not None
            else self.dialect
        )
        if isinstance(effective_runs, bool) or not isinstance(
            effective_runs, int
        ) or effective_runs < 1:
            raise ValueError("min_inactive_runs must be an integer >= 1")
        if isinstance(effective_days, bool) or not isinstance(
            effective_days, (int, float)
        ) or effective_days < 0.0:
            raise ValueError("min_inactive_days must be a non-negative number")

        eval_dt = resolve_evaluation_time(evaluation_time)
        resolved_sites = self._normalize_sites(sites)
        site_by_id = {s.site_id: s for s in resolved_sites}

        port_entries = self._collect_candidate_ports(
            sites=resolved_sites,
            devices=devices,
            ports=ports,
        )
        streak_lookup = self._build_streak_lookup(
            streaks=streaks,
            history_store=history_store,
        )
        trunk_port_set = {
            p.strip() for p in (trunk_ports or ()) if isinstance(p, str) and p.strip()
        }

        candidates: list[PortReclamationCandidate] = []
        blocked_ports: list[BlockedPortRecord] = []

        for port_obj, extras, parent_dev, parent_site in port_entries:
            site_id = (
                parent_site.site_id
                if parent_site is not None
                else (
                    parent_dev.site_id
                    if parent_dev is not None
                    else _clean_optional_str(extras.get("site_id"))
                )
            )
            if parent_site is None and site_id is not None:
                parent_site = site_by_id.get(site_id)

            device_hostname = (
                parent_dev.hostname
                if parent_dev is not None
                else _clean_optional_str(extras.get("device_hostname"))
            )
            device_oids = self._resolve_device_oids(
                device_id=port_obj.device_id,
                snmp_oids_by_device=snmp_oids_by_device,
            )

            resolved_desc = self._lookup_by_port(
                port_obj, port_descriptions
            ) or _clean_optional_str(extras.get("description"))
            if resolved_desc is None and device_oids:
                alias_val = self._lookup_snmp_oid_for_port(
                    port=port_obj,
                    extras=extras,
                    oids=device_oids,
                    oid_prefix=IF_MIB_IF_ALIAS_PREFIX,
                )
                if alias_val is not None:
                    resolved_desc = _clean_optional_str(alias_val)

            resolved_tagged_vlans = self._lookup_by_port(
                port_obj, tagged_vlans_by_port
            )
            resolved_is_trunk: Optional[bool] = extras.get("is_trunk")
            if any(
                _port_matches_identifier(port_obj, tp) for tp in trunk_port_set
            ):
                resolved_is_trunk = True

            guard_decision = self.uplink_guard.evaluate_port(
                port_obj,
                device=parent_dev,
                site=parent_site,
                description=resolved_desc,
                tagged_vlans=resolved_tagged_vlans,
                is_trunk=resolved_is_trunk,
                vlan_mode=extras.get("vlan_mode"),
                lldp_neighbors=(
                    lldp_neighbors
                    if lldp_neighbors is not None
                    else (
                        extras.get("lldp_neighbors")
                        or extras.get("lldp_neighbor")
                    )
                ),
                ip_addresses=ip_addresses,
                arp_entries=arp_entries,
                has_recent_arp_activity=extras.get("has_recent_arp_activity"),
                has_recent_mac_activity=extras.get("has_recent_mac_activity"),
                active_macs=active_macs,
                evaluation_time=eval_dt,
            )

            inactive_runs, inactive_days, streak_cls = self._resolve_port_streak(
                port=port_obj,
                extras=extras,
                site=parent_site,
                streak_lookup=streak_lookup,
            )

            block_reasons = list(guard_decision.block_reasons)
            matched_rules = list(guard_decision.matched_rules)

            # Check if already administratively disabled
            admin_norm = (
                port_obj.admin_status.strip().lower()
                if isinstance(port_obj.admin_status, str)
                and port_obj.admin_status.strip()
                else None
            )
            if admin_norm is not None and admin_norm in _ADMIN_DISABLED_VALUES:
                matched_rules.append("admin_already_disabled")
                block_reasons.append(
                    f"Port {port_obj.name} is already administratively disabled (admin_status={port_obj.admin_status!r})"
                )

            # Check historical inactivity streak thresholds
            if (
                streak_cls is not None
                and streak_cls is not ValidationClassification.STALE_LIKELY_UNUSED
            ):
                matched_rules.append("below_inactivity_threshold")
                block_reasons.append(
                    f"Port {port_obj.name} classification is {streak_cls.value!r} (requires {ValidationClassification.STALE_LIKELY_UNUSED.value!r})"
                )
            elif (
                inactive_runs < effective_runs
                or inactive_days < effective_days
            ):
                matched_rules.append("below_inactivity_threshold")
                block_reasons.append(
                    f"Port {port_obj.name} inactivity streak ({inactive_runs} runs, {inactive_days:.1f} days) "
                    f"is below threshold (min_inactive_runs={effective_runs}, min_inactive_days={effective_days:.1f})"
                )

            if block_reasons:
                blocked_ports.append(
                    BlockedPortRecord(
                        port_id=port_obj.port_id,
                        device_id=port_obj.device_id,
                        port_name=port_obj.name,
                        site_id=site_id,
                        device_hostname=device_hostname,
                        blocked=True,
                        block_reason="; ".join(block_reasons),
                        block_reasons=tuple(block_reasons),
                        matched_rules=tuple(matched_rules),
                        admin_status=port_obj.admin_status,
                        oper_status=port_obj.oper_status,
                        poe_status=port_obj.poe_status,
                        vlan_id=port_obj.vlan_id,
                        description=resolved_desc,
                        connected_device_id=port_obj.connected_device_id,
                        inactive_runs=inactive_runs,
                        inactive_days=inactive_days,
                    )
                )
                continue

            poe_watts = self._resolve_poe_watts(
                port=port_obj,
                extras=extras,
                poe_watts_by_port=poe_watts_by_port,
                device_oids=device_oids,
            )
            poe_limit_mw = self._resolve_poe_restore_limit_mw(
                port=port_obj,
                extras=extras,
                poe_limit_mw_by_port=poe_limit_mw_by_port,
                device_oids=device_oids,
            )

            candidates.append(
                PortReclamationCandidate(
                    port_id=port_obj.port_id,
                    device_id=port_obj.device_id,
                    port_name=port_obj.name,
                    site_id=site_id,
                    device_hostname=device_hostname,
                    admin_status=port_obj.admin_status,
                    oper_status=port_obj.oper_status,
                    poe_status=port_obj.poe_status,
                    vlan_id=port_obj.vlan_id,
                    description=resolved_desc,
                    connected_device_id=port_obj.connected_device_id,
                    inactive_runs=inactive_runs,
                    inactive_days=inactive_days,
                    estimated_poe_watts_saved=poe_watts,
                    poe_restore_limit_mw=poe_limit_mw,
                    dialect=effective_dialect,
                )
            )

        total_poe_saved = round(
            sum(c.estimated_poe_watts_saved for c in candidates), 2
        )

        return PortReclamationPlan(
            candidates=tuple(candidates),
            blocked_ports=tuple(blocked_ports),
            estimated_poe_watts_saved=total_poe_saved,
            min_inactive_runs=effective_runs,
            min_inactive_days=effective_days,
            dialect=effective_dialect,
            generated_at=eval_dt,
            dry_run=True,
        )

    evaluate = plan

    @staticmethod
    def _normalize_sites(
        sites: Optional[
            Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]
        ],
    ) -> list[Site]:
        if sites is None:
            return []
        if isinstance(sites, Site):
            return [sites]
        if isinstance(sites, Mapping):
            if "site_id" in sites and "name" in sites:
                return [Site.from_dict(sites)]
            return [
                v if isinstance(v, Site) else Site.from_dict(v)
                for v in sites.values()
            ]
        if isinstance(sites, Sequence):
            return [
                s if isinstance(s, Site) else Site.from_dict(s) for s in sites
            ]
        return []

    @staticmethod
    def _is_extreme_switch(device: Optional[NetworkDevice]) -> bool:
        if device is None or not device.vendor or not device.vendor.strip():
            return True
        lowered = device.vendor.strip().lower()
        return any(tok in lowered for tok in ("extreme", "exos", "voss"))

    def _collect_candidate_ports(
        self,
        *,
        sites: Sequence[Site],
        devices: Optional[Sequence[NetworkDevice | Mapping[str, Any]]],
        ports: Optional[Sequence[Port | Mapping[str, Any]]],
    ) -> list[
        tuple[
            Port,
            dict[str, Any],
            Optional[NetworkDevice],
            Optional[Site],
        ]
    ]:
        collected: list[
            tuple[
                Port,
                dict[str, Any],
                Optional[NetworkDevice],
                Optional[Site],
            ]
        ] = []
        seen_keys: set[tuple[str, str]] = set()
        dev_by_id: dict[str, tuple[NetworkDevice, Optional[Site]]] = {}

        for site in sites:
            for dev in site.devices:
                dev_by_id[dev.device_id] = (dev, site)

        normalized_devices: list[NetworkDevice] = []
        if devices is not None:
            for raw_dev in devices:
                dev_obj = (
                    raw_dev
                    if isinstance(raw_dev, NetworkDevice)
                    else NetworkDevice.from_dict(raw_dev)
                )
                normalized_devices.append(dev_obj)
                if dev_obj.device_id not in dev_by_id:
                    dev_by_id[dev_obj.device_id] = (dev_obj, None)

        def _add_port(
            raw_port: Port | Mapping[str, Any],
            parent_dev: Optional[NetworkDevice],
            parent_site: Optional[Site],
        ) -> None:
            if not self._is_extreme_switch(parent_dev):
                return
            port_obj, extras = _coerce_port_and_extras(
                raw_port,
                default_device_id=(
                    parent_dev.device_id if parent_dev is not None else None
                ),
            )
            if parent_dev is None and port_obj.device_id in dev_by_id:
                parent_dev, inferred_site = dev_by_id[port_obj.device_id]
                if parent_site is None:
                    parent_site = inferred_site
                if not self._is_extreme_switch(parent_dev):
                    return
            key = (port_obj.device_id, port_obj.port_id)
            if key not in seen_keys:
                seen_keys.add(key)
                collected.append((port_obj, extras, parent_dev, parent_site))

        if ports is not None:
            for raw_port in ports:
                _add_port(raw_port, None, None)

        for dev_obj in normalized_devices:
            _, parent_site = dev_by_id.get(dev_obj.device_id, (dev_obj, None))
            for port_obj in dev_obj.ports:
                _add_port(port_obj, dev_obj, parent_site)

        for site in sites:
            for dev_obj in site.devices:
                for port_obj in dev_obj.ports:
                    _add_port(port_obj, dev_obj, site)

        return collected
