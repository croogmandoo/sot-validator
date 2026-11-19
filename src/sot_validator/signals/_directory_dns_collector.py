"""/24-scoped DNS/DHCP lease correlation collector."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any, Optional

from sot_validator.models import (
    Equipment,
    IPAddress,
    NetworkDevice,
    SignalStatus,
    SignalType,
    Site,
    Subnet,
    ValidationSignal,
)
from sot_validator.signals._directory_common import (
    _clean_optional_str,
    normalize_hostname,
)
from sot_validator.signals._directory_dns_records import DhcpLeaseRecord, DnsRecord
from sot_validator.signals._site_index import ScopeMemo, SiteRecordIndex
from sot_validator.signals.base import SignalCollector, resolve_evaluation_time
from sot_validator.signals.icmp import (
    ScopeViolationError,
    SubnetScopeGuard,
    _parse_ipv4_host,
)


class DnsDhcpLeaseCollector(SignalCollector):
    """Correlate forward/reverse DNS ('A'/'PTR') and /24-scoped DHCP leases against SoT records."""

    signal_type = SignalType.DNS_DHCP_LEASE

    def __init__(
        self,
        dns_records: Optional[Iterable[DnsRecord | Mapping[str, Any]]] = None,
        dhcp_leases: Optional[Iterable[DhcpLeaseRecord | Mapping[str, Any]]] = None,
        *,
        leases: Optional[Iterable[DhcpLeaseRecord | Mapping[str, Any]]] = None,
        a_records: Optional[Any] = None,
        forward_records: Optional[Any] = None,
        ptr_records: Optional[Any] = None,
        reverse_records: Optional[Any] = None,
        subnets: Optional[Iterable[Subnet | str]] = None,
        scope_guard: Optional[SubnetScopeGuard] = None,
        site: Optional[Site] = None,
        evaluation_time: Optional[datetime | str] = None,
        source: str = "dns_dhcp",
    ) -> None:
        self.evaluation_time: Optional[datetime] = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else None
        )
        self.source = source

        if scope_guard is not None:
            self.scope_guard: Optional[SubnetScopeGuard] = scope_guard
        elif subnets is not None:
            self.scope_guard = SubnetScopeGuard(subnets=subnets)
        elif site is not None and site.subnets:
            self.scope_guard = SubnetScopeGuard.from_site(site)
        else:
            self.scope_guard = None

        self._dns_records: list[DnsRecord] = self._coerce_dns_records(
            dns_records=dns_records,
            a_records=a_records if a_records is not None else forward_records,
            ptr_records=ptr_records if ptr_records is not None else reverse_records,
        )
        raw_leases = dhcp_leases if dhcp_leases is not None else leases
        self._dhcp_leases: list[DhcpLeaseRecord] = self._coerce_dhcp_leases(raw_leases)
        self._scoped_lease_cache: Optional[
            tuple[
                Optional[SubnetScopeGuard],
                list[tuple[DhcpLeaseRecord, Optional[str]]],
                dict[str, list[int]],
                dict[str, list[int]],
            ]
        ] = None
        # Parsed IP and /24 CIDR scope checks, valid only for the same guard object
        self._scope_memo_cache: Optional[
            tuple[Optional[SubnetScopeGuard], ScopeMemo]
        ] = None

    @staticmethod
    def _coerce_dns_records(
        *,
        dns_records: Optional[Iterable[DnsRecord | Mapping[str, Any]]] = None,
        a_records: Optional[Any] = None,
        ptr_records: Optional[Any] = None,
    ) -> list[DnsRecord]:
        out: list[DnsRecord] = []

        if dns_records is not None:
            for item in dns_records:
                if isinstance(item, DnsRecord):
                    out.append(item)
                elif isinstance(item, Mapping):
                    out.append(DnsRecord.from_dict(item))
                else:
                    raise ValueError(f"Unsupported DNS record: {item!r}")

        if a_records is not None:
            if isinstance(a_records, Mapping):
                for host, ip_val in a_records.items():
                    if isinstance(ip_val, str):
                        out.append(
                            DnsRecord(record_type="A", hostname=str(host), ip=ip_val)
                        )
                    elif isinstance(ip_val, Iterable):
                        for ip_str in ip_val:
                            out.append(
                                DnsRecord(
                                    record_type="A",
                                    hostname=str(host),
                                    ip=str(ip_str),
                                )
                            )
            elif isinstance(a_records, Iterable):
                for item in a_records:
                    if isinstance(item, DnsRecord):
                        out.append(item)
                    elif isinstance(item, Mapping):
                        d = dict(item)
                        d.setdefault("record_type", "A")
                        out.append(DnsRecord.from_dict(d))
                    else:
                        raise ValueError(f"Unsupported A record: {item!r}")

        if ptr_records is not None:
            if isinstance(ptr_records, Mapping):
                for ip_key, host_val in ptr_records.items():
                    if isinstance(host_val, str):
                        out.append(
                            DnsRecord(
                                record_type="PTR", hostname=host_val, ip=str(ip_key)
                            )
                        )
                    elif isinstance(host_val, Iterable):
                        for host_str in host_val:
                            out.append(
                                DnsRecord(
                                    record_type="PTR",
                                    hostname=str(host_str),
                                    ip=str(ip_key),
                                )
                            )
            elif isinstance(ptr_records, Iterable):
                for item in ptr_records:
                    if isinstance(item, DnsRecord):
                        out.append(item)
                    elif isinstance(item, Mapping):
                        d = dict(item)
                        d.setdefault("record_type", "PTR")
                        out.append(DnsRecord.from_dict(d))
                    else:
                        raise ValueError(f"Unsupported PTR record: {item!r}")

        return out

    @staticmethod
    def _coerce_dhcp_leases(
        leases: Optional[Iterable[DhcpLeaseRecord | Mapping[str, Any]]],
    ) -> list[DhcpLeaseRecord]:
        if leases is None:
            return []
        if isinstance(leases, Mapping):
            if "leases" in leases and isinstance(leases["leases"], Iterable):
                leases = leases["leases"]
            elif "dhcp_leases" in leases and isinstance(
                leases["dhcp_leases"], Iterable
            ):
                leases = leases["dhcp_leases"]
            else:
                coerced: list[DhcpLeaseRecord] = []
                for ip_key, val in leases.items():
                    if isinstance(val, DhcpLeaseRecord):
                        coerced.append(val)
                    elif isinstance(val, Mapping):
                        d = dict(val)
                        d.setdefault("ip", str(ip_key))
                        coerced.append(DhcpLeaseRecord.from_dict(d))
                return coerced

        out: list[DhcpLeaseRecord] = []
        for item in leases:
            if isinstance(item, DhcpLeaseRecord):
                out.append(item)
            elif isinstance(item, Mapping):
                out.append(DhcpLeaseRecord.from_dict(item))
            else:
                raise ValueError(f"Unsupported DHCP lease record: {item!r}")
        return out

    def _resolve_scope_guard(
        self,
        *,
        site: Optional[Site] = None,
        subnets: Optional[Iterable[Subnet | str]] = None,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> Optional[SubnetScopeGuard]:
        if scope_guard is not None:
            return scope_guard
        if subnets is not None:
            return SubnetScopeGuard(subnets=subnets)
        if self.scope_guard is not None:
            return self.scope_guard
        if site is not None and site.subnets:
            return SubnetScopeGuard.from_site(site)
        return None

    def _scope_memo(self, guard: Optional[SubnetScopeGuard]) -> ScopeMemo:
        cached = self._scope_memo_cache
        if cached is None or cached[0] is not guard:
            cached = (guard, ScopeMemo())
            self._scope_memo_cache = cached
        return cached[1]

    @staticmethod
    def _is_lease_in_slash24_scope(
        lease: DhcpLeaseRecord,
        guard: Optional[SubnetScopeGuard],
        _memo: Optional[ScopeMemo] = None,
    ) -> bool:
        memo = _memo if _memo is not None else ScopeMemo()
        addr, _, ip_in_scope = memo.host_scope(lease.ip, guard)
        if addr is None:
            return False

        if lease.subnet_cidr is not None:
            lease_net, cidr_in_scope = memo.cidr_scope(lease.subnet_cidr, guard)
            if lease_net is None:
                return False
            if addr not in lease_net:
                return False
            if not cidr_in_scope:
                return False

        return ip_in_scope

    @staticmethod
    def _resolve_target_context(
        target: Any,
        *,
        site: Optional[Site] = None,
        ip_addresses: Optional[Sequence[IPAddress]] = None,
        expected_hostname: Optional[str] = None,
        index: Optional[SiteRecordIndex] = None,
    ) -> tuple[list[str], list[str], str]:
        """Return (target_ips, expected_hostnames, target_label)."""
        ips: list[str] = []
        hosts: list[str] = []

        def _add_ip(raw_ip: Optional[str]) -> None:
            cleaned = _clean_optional_str(raw_ip)
            if cleaned and cleaned not in ips:
                ips.append(cleaned)

        def _add_host(raw_host: Optional[str]) -> None:
            cleaned = _clean_optional_str(raw_host)
            if cleaned and cleaned not in hosts:
                hosts.append(cleaned)

        if expected_hostname:
            _add_host(expected_hostname)

        # With an index, the IP records are looked up per target below instead
        all_ip_recs: list[IPAddress] = []
        if index is None:
            if ip_addresses:
                all_ip_recs.extend(ip_addresses)
            if site is not None:
                all_ip_recs.extend(site.ip_addresses)

        if isinstance(target, IPAddress):
            _add_ip(target.ip)
            for attr in ("hostname", "dns_name", "name"):
                val = getattr(target, attr, None)
                if isinstance(val, str):
                    _add_host(val)
            if index is not None:
                for name in index.hostnames_for_ip_record(target):
                    _add_host(name)
            elif site is not None:
                for eq in site.equipment:
                    if (
                        target.assigned_object_id == eq.equipment_id
                        or target.ip in eq.assigned_ips
                    ):
                        _add_host(eq.name)
                for dev in site.devices:
                    if (
                        target.assigned_object_id == dev.device_id
                        or dev.management_ip == target.ip
                    ):
                        _add_host(dev.hostname)
            return ips, hosts, f"IPAddress {target.ip}"

        if isinstance(target, Equipment):
            _add_host(target.name)
            for ip_str in target.assigned_ips:
                _add_ip(ip_str)
            if index is not None:
                all_ip_recs = index.ip_records_for_object(target.equipment_id)
            for ip_rec in all_ip_recs:
                if ip_rec.assigned_object_id == target.equipment_id:
                    _add_ip(ip_rec.ip)
            return ips, hosts, f"Equipment {target.name} ({target.equipment_id})"

        if isinstance(target, NetworkDevice):
            _add_host(target.hostname)
            _add_ip(target.management_ip)
            if index is not None:
                all_ip_recs = index.ip_records_for_object(target.device_id)
            for ip_rec in all_ip_recs:
                if ip_rec.assigned_object_id == target.device_id:
                    _add_ip(ip_rec.ip)
            return ips, hosts, f"NetworkDevice {target.hostname} ({target.device_id})"

        if isinstance(target, str):
            cleaned = target.strip()
            try:
                addr = _parse_ipv4_host(cleaned)
                _add_ip(str(addr))
                return ips, hosts, f"IP {addr}"
            except ScopeViolationError:
                _add_host(cleaned)
                return ips, hosts, f"hostname {cleaned!r}"

        if isinstance(target, Mapping):
            _add_ip(target.get("ip") or target.get("ip_address"))
            _add_host(
                target.get("hostname")
                or target.get("name")
                or target.get("fqdn")
            )
            return ips, hosts, "mapping"

        return ips, hosts, type(target).__name__

    def evaluate(
        self,
        target: Any,
        *,
        site: Optional[Site] = None,
        ip_addresses: Optional[Sequence[IPAddress]] = None,
        dns_records: Optional[Iterable[DnsRecord | Mapping[str, Any]]] = None,
        a_records: Optional[Any] = None,
        forward_records: Optional[Any] = None,
        ptr_records: Optional[Any] = None,
        reverse_records: Optional[Any] = None,
        dhcp_leases: Optional[Iterable[DhcpLeaseRecord | Mapping[str, Any]]] = None,
        leases: Optional[Iterable[DhcpLeaseRecord | Mapping[str, Any]]] = None,
        subnets: Optional[Iterable[Subnet | str]] = None,
        scope_guard: Optional[SubnetScopeGuard] = None,
        hostname: Optional[str] = None,
        expected_hostname: Optional[str] = None,
        evaluation_time: Optional[datetime | str] = None,
        **kwargs: Any,
    ) -> ValidationSignal:
        """Evaluate /24-scoped DHCP leases and forward/reverse DNS records for target."""
        _ = kwargs
        eval_dt = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else (
                self.evaluation_time
                if self.evaluation_time is not None
                else resolve_evaluation_time(None)
            )
        )

        guard = self._resolve_scope_guard(
            site=site, subnets=subnets, scope_guard=scope_guard
        )

        has_custom_dns = any(
            x is not None
            for x in (
                dns_records,
                a_records,
                forward_records,
                ptr_records,
                reverse_records,
            )
        )
        dns_pool = (
            self._coerce_dns_records(
                dns_records=dns_records,
                a_records=a_records if a_records is not None else forward_records,
                ptr_records=ptr_records if ptr_records is not None else reverse_records,
            )
            if has_custom_dns
            else self._dns_records
        )

        raw_leases = dhcp_leases if dhcp_leases is not None else leases
        lease_pool = (
            self._coerce_dhcp_leases(raw_leases)
            if raw_leases is not None
            else self._dhcp_leases
        )

        # classify_site passes a per-call index; it is only used for the exact inputs it indexes
        index: Optional[SiteRecordIndex] = kwargs.get("_site_index")
        if index is not None and not index.matches_ips(site, ip_addresses):
            index = None
        raw_target_ips, raw_expected_hosts, target_label = self._resolve_target_context(
            target,
            site=site,
            ip_addresses=ip_addresses,
            expected_hostname=expected_hostname or hostname,
            index=index,
        )

        scope_memo = self._scope_memo(guard)
        in_scope_target_ips: list[str] = []
        out_of_scope_target_ips: list[str] = []
        for raw_ip in raw_target_ips:
            _, parsed_ip, in_scope = scope_memo.host_scope(raw_ip, guard)
            if parsed_ip is None:
                out_of_scope_target_ips.append(raw_ip)
            elif not in_scope:
                out_of_scope_target_ips.append(parsed_ip)
            else:
                in_scope_target_ips.append(parsed_ip)

        sot_ip_set = set(in_scope_target_ips)
        sot_host_set = {
            norm
            for h in raw_expected_hosts
            if (norm := normalize_hostname(h)) is not None
        }

        if not sot_ip_set and not sot_host_set:
            detail_msg = (
                f"Target {target_label} IP(s) {out_of_scope_target_ips} outside allocated /24 subnet scope"
                if out_of_scope_target_ips
                else f"No in-scope IP or hostname available for {target_label}"
            )
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=None,
                age_seconds=None,
                details=detail_msg,
                source=self.source,
                metadata={
                    "dns_mismatch": False,
                    "dhcp_lease_active": False,
                    "out_of_scope_ips": out_of_scope_target_ips,
                },
            )

        # Filter DHCP leases to allocated /24 scope and match against target
        cached = self._scoped_lease_cache
        if lease_pool is self._dhcp_leases and (cached is None or cached[0] is not guard):
            # The collector's own lease pool only needs filtering and indexing once per guard
            scoped_leases = [
                (lease, lease.normalized_hostname)
                for lease in lease_pool
                if self._is_lease_in_slash24_scope(lease, guard, scope_memo)
            ]
            leases_by_ip: dict[str, list[int]] = {}
            leases_by_host: dict[str, list[int]] = {}
            for position, (lease, lease_host) in enumerate(scoped_leases):
                leases_by_ip.setdefault(lease.ip, []).append(position)
                if lease_host is not None:
                    leases_by_host.setdefault(lease_host, []).append(position)
            cached = (guard, scoped_leases, leases_by_ip, leases_by_host)
            self._scoped_lease_cache = cached

        matched_leases: list[DhcpLeaseRecord] = []
        if lease_pool is self._dhcp_leases and cached is not None:
            # Index hits are sorted by pool position to keep the linear scan's order
            scoped_leases, leases_by_ip, leases_by_host = cached[1:]
            positions: set[int] = set()
            for ip in sot_ip_set:
                positions.update(leases_by_ip.get(ip, ()))
            for host in sot_host_set:
                positions.update(leases_by_host.get(host, ()))
            matched_leases = [scoped_leases[pos][0] for pos in sorted(positions)]
        else:
            for lease in lease_pool:
                if not self._is_lease_in_slash24_scope(lease, guard, scope_memo):
                    continue
                lease_host = lease.normalized_hostname
                ip_match = bool(sot_ip_set and lease.ip in sot_ip_set)
                host_match = bool(
                    sot_host_set
                    and lease_host is not None
                    and lease_host in sot_host_set
                )
                if ip_match or host_match:
                    matched_leases.append(lease)

        active_leases = [
            lease for lease in matched_leases if lease.is_active(eval_dt)
        ]
        expired_leases = [
            lease for lease in matched_leases if not lease.is_active(eval_dt)
        ]

        # Match forward (A) and reverse (PTR) DNS records
        all_a = [rec for rec in dns_pool if rec.record_type == "A"]
        all_ptr = [rec for rec in dns_pool if rec.record_type == "PTR"]

        matched_a: list[DnsRecord] = []
        matched_ptr: list[DnsRecord] = []

        for rec in all_a:
            if (sot_ip_set and rec.ip in sot_ip_set) or (
                sot_host_set
                and rec.normalized_hostname is not None
                and rec.normalized_hostname in sot_host_set
            ):
                matched_a.append(rec)

        for rec in all_ptr:
            if (sot_ip_set and rec.ip in sot_ip_set) or (
                sot_host_set
                and rec.normalized_hostname is not None
                and rec.normalized_hostname in sot_host_set
            ):
                matched_ptr.append(rec)

        # Expand cross-references so A<->PTR disagreement is detected even when target is IP-only or host-only
        discovered_hosts = {
            rec.normalized_hostname
            for rec in (*matched_a, *matched_ptr)
            if rec.normalized_hostname is not None
        }
        discovered_ips = {rec.ip for rec in (*matched_a, *matched_ptr)}

        for rec in all_a:
            if rec not in matched_a and (
                rec.ip in discovered_ips
                or (
                    rec.normalized_hostname is not None
                    and rec.normalized_hostname in discovered_hosts
                )
            ):
                matched_a.append(rec)

        for rec in all_ptr:
            if rec not in matched_ptr and (
                rec.ip in discovered_ips
                or (
                    rec.normalized_hostname is not None
                    and rec.normalized_hostname in discovered_hosts
                )
            ):
                matched_ptr.append(rec)

        if not matched_leases and not matched_a and not matched_ptr:
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=None,
                age_seconds=None,
                details=f"No matching /24 DHCP lease or DNS A/PTR records found for {target_label}",
                source=self.source,
                metadata={
                    "dns_mismatch": False,
                    "dhcp_lease_active": False,
                    "out_of_scope_ips": out_of_scope_target_ips,
                },
            )

        # Evaluate DNS/SoT alignment and detect drift
        dns_mismatch = False
        mismatch_reasons: list[str] = []

        a_ips = {rec.ip for rec in matched_a}
        ptr_ips = {rec.ip for rec in matched_ptr}
        a_hosts = {
            rec.normalized_hostname
            for rec in matched_a
            if rec.normalized_hostname is not None
        }
        ptr_hosts = {
            rec.normalized_hostname
            for rec in matched_ptr
            if rec.normalized_hostname is not None
        }

        if sot_ip_set:
            bad_a_ips = sorted(a_ips - sot_ip_set)
            if bad_a_ips:
                dns_mismatch = True
                mismatch_reasons.append(
                    f"DNS A record IP(s) {bad_a_ips} disagree with SoT IP(s) {sorted(sot_ip_set)}"
                )
            bad_ptr_ips = sorted(ptr_ips - sot_ip_set)
            if bad_ptr_ips:
                dns_mismatch = True
                mismatch_reasons.append(
                    f"DNS PTR record IP(s) {bad_ptr_ips} disagree with SoT IP(s) {sorted(sot_ip_set)}"
                )

        if sot_host_set:
            bad_a_hosts = sorted(a_hosts - sot_host_set)
            if bad_a_hosts:
                dns_mismatch = True
                mismatch_reasons.append(
                    f"DNS A hostname(s) {bad_a_hosts} disagree with SoT hostname(s) {sorted(sot_host_set)}"
                )
            bad_ptr_hosts = sorted(ptr_hosts - sot_host_set)
            if bad_ptr_hosts:
                dns_mismatch = True
                mismatch_reasons.append(
                    f"DNS PTR hostname(s) {bad_ptr_hosts} disagree with SoT hostname(s) {sorted(sot_host_set)}"
                )

        if matched_a and matched_ptr:
            if a_ips != ptr_ips:
                dns_mismatch = True
                mismatch_reasons.append(
                    f"forward A IP(s) {sorted(a_ips)} and reverse PTR IP(s) {sorted(ptr_ips)} disagree"
                )
            if a_hosts != ptr_hosts:
                dns_mismatch = True
                mismatch_reasons.append(
                    f"forward A hostname(s) {sorted(a_hosts)} and reverse PTR hostname(s) {sorted(ptr_hosts)} disagree"
                )

        for lease in active_leases:
            if (
                sot_host_set
                and lease.normalized_hostname is not None
                and lease.normalized_hostname not in sot_host_set
            ):
                dns_mismatch = True
                mismatch_reasons.append(
                    f"active DHCP lease hostname {lease.normalized_hostname!r} disagrees with SoT {sorted(sot_host_set)}"
                )
            if sot_ip_set and lease.ip not in sot_ip_set:
                dns_mismatch = True
                mismatch_reasons.append(
                    f"active DHCP lease IP {lease.ip} disagrees with SoT IP(s) {sorted(sot_ip_set)}"
                )
            if (
                lease.normalized_hostname is not None
                and (a_hosts or ptr_hosts)
                and lease.normalized_hostname not in (a_hosts | ptr_hosts)
            ):
                dns_mismatch = True
                mismatch_reasons.append(
                    f"active DHCP lease hostname {lease.normalized_hostname!r} disagrees with DNS {sorted(a_hosts | ptr_hosts)}"
                )

        # Resolve observed_at and age_seconds from matching lease/DNS timestamps if available
        obs_candidates: list[datetime] = []
        for lease in active_leases or expired_leases:
            if lease.observed_at is not None:
                obs_candidates.append(lease.observed_at)
        for rec in (*matched_a, *matched_ptr):
            if rec.observed_at is not None:
                obs_candidates.append(rec.observed_at)

        observed_at = max(obs_candidates) if obs_candidates else eval_dt
        age_seconds = max(0.0, (eval_dt - observed_at).total_seconds())

        has_dns_records = bool(matched_a or matched_ptr)
        if active_leases:
            status = SignalStatus.ACTIVE
            lease_ips = [lease.ip for lease in active_leases]
            detail_parts = [
                f"Active /24 DHCP lease on {', '.join(lease_ips)} for {target_label}"
            ]
            if has_dns_records and not dns_mismatch:
                detail_parts.append("DNS A/PTR aligned (dns_mismatch=False)")
            elif dns_mismatch:
                detail_parts.append(
                    f"dns_mismatch=True ({'; '.join(mismatch_reasons)})"
                )
            details = "; ".join(detail_parts)
        elif has_dns_records and not dns_mismatch:
            status = SignalStatus.ACTIVE
            details = (
                f"DNS records aligned for {target_label} "
                f"(A={len(matched_a)}, PTR={len(matched_ptr)}, dns_mismatch=False)"
            )
        elif dns_mismatch:
            status = SignalStatus.INACTIVE
            details = (
                f"DNS/SoT mismatch for {target_label}: "
                f"dns_mismatch=True ({'; '.join(mismatch_reasons)})"
            )
        else:
            status = SignalStatus.INACTIVE
            exp_ips = [lease.ip for lease in expired_leases]
            details = (
                f"Expired/inactive /24 DHCP lease on {', '.join(exp_ips)} for {target_label} "
                "(dns_mismatch=False)"
            )

        metadata = {
            "dns_mismatch": dns_mismatch,
            "mismatch_reasons": mismatch_reasons,
            "dhcp_lease_active": bool(active_leases),
            "lease_active": bool(active_leases),
            "matched_ips": sorted(
                {
                    *(lease.ip for lease in matched_leases),
                    *a_ips,
                    *ptr_ips,
                }
            ),
            "a_records": [rec.to_dict() for rec in matched_a],
            "ptr_records": [rec.to_dict() for rec in matched_ptr],
            "dhcp_leases": [lease.to_dict() for lease in matched_leases],
            "out_of_scope_ips": out_of_scope_target_ips,
        }

        return ValidationSignal(
            signal_type=self.signal_type,
            status=status,
            observed_at=observed_at,
            age_seconds=age_seconds,
            details=details,
            source=self.source,
            metadata=metadata,
        )

    def collect(self, target: Any, **kwargs: Any) -> ValidationSignal:
        """Convenience alias for evaluate()."""
        return self.evaluate(target, **kwargs)

    def collect_for_ip(
        self, ip_address: IPAddress | str, **kwargs: Any
    ) -> ValidationSignal:
        """Evaluate DNS/DHCP signal for an IPAddress record or IP string."""
        return self.evaluate(ip_address, **kwargs)

    def collect_for_equipment(
        self, equipment: Equipment, **kwargs: Any
    ) -> ValidationSignal:
        """Evaluate DNS/DHCP signal for an Equipment record."""
        return self.evaluate(equipment, **kwargs)

    def collect_for_device(
        self, device: NetworkDevice, **kwargs: Any
    ) -> ValidationSignal:
        """Evaluate DNS/DHCP signal for a NetworkDevice record."""
        return self.evaluate(device, **kwargs)
