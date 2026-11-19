"""Service banner fingerprinting engine."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterable, Mapping, Sequence
import copy
import dataclasses
import functools
import inspect
from typing import Any, Optional

from sot_validator.discovery._fingerprint_common import (
    HTTP_BANNER_PORTS,
    SSH_BANNER_PORTS,
    TLS_BANNER_PORTS,
    _EXOS_MODEL_RE,
    _canonical_ipv4,
    _clean_text,
    _ip_or_none,
    _normalize_ports,
    _pair,
    _str_or_none,
)
from sot_validator.discovery._fingerprint_models import (
    DeviceFingerprint,
    RawServiceBanner,
    TlsCertificate,
)
from sot_validator.discovery._fingerprint_signatures import (
    _SIGNATURES,
    _extract_hostname,
    _matching_sources,
    _signature_confidence,
    _signature_sources,
)
from sot_validator.discovery._fingerprint_transport import (
    _default_async_http,
    _default_async_ssh_banner,
    _default_async_tls,
)
from sot_validator.discovery.router_tables import (
    _is_synthetic_device_hostname,
    _is_synthetic_equipment_name,
)
from sot_validator.discovery.scanner import _run_coro_sync
from sot_validator.models import Site


class ServiceBannerFingerprinter:
    """Collect banners from known open ports and fingerprint the device behind them."""

    def __init__(
        self,
        *,
        ssh_fn: Optional[Callable[..., Any]] = None,
        http_fn: Optional[Callable[..., Any]] = None,
        tls_fn: Optional[Callable[..., Any]] = None,
        snmp_fn: Optional[Callable[..., Any]] = None,
        timeout_sec: float = 2.0,
        max_concurrency: int = 16,
    ) -> None:
        if (
            isinstance(timeout_sec, bool)
            or not isinstance(timeout_sec, (int, float))
            or timeout_sec <= 0
        ):
            raise ValueError("timeout_sec must be a number > 0")
        if (
            isinstance(max_concurrency, bool)
            or not isinstance(max_concurrency, int)
            or max_concurrency < 1
        ):
            raise ValueError("max_concurrency must be an integer >= 1")
        self.timeout_sec: float = float(timeout_sec)
        self.max_concurrency: int = max_concurrency
        self._ssh_fn = ssh_fn
        self._http_fn = http_fn
        self._tls_fn = tls_fn
        self._snmp_fn = snmp_fn

    # Matching

    def fingerprint(self, banner: RawServiceBanner) -> DeviceFingerprint:
        """Identify vendor, OS, role and template from a banner without any I/O."""
        if not isinstance(banner, RawServiceBanner):
            raise ValueError("banner must be a RawServiceBanner instance")
        sources = _signature_sources(banner)
        matches = [
            (sig, hits)
            for sig in _SIGNATURES
            if (hits := _matching_sources(sig, sources))
        ]
        hostname = _extract_hostname(banner)
        if not matches:
            return DeviceFingerprint(ip=banner.ip, discovered_hostname=hostname)

        winner, winner_hits = matches[0]
        os_family = winner.os_family or next(
            (sig.os_family for sig, _ in matches if sig.generic and sig.os_family),
            None,
        )
        model: Optional[str] = None
        if winner.name == "extreme-exos" and banner.snmp_sys_descr:
            model_match = _EXOS_MODEL_RE.search(banner.snmp_sys_descr)
            if model_match is not None:
                model = model_match.group(1)
        return DeviceFingerprint(
            ip=banner.ip,
            vendor=winner.vendor,
            model=model,
            os_family=os_family,
            discovered_hostname=hostname,
            inferred_role=winner.role,
            recommended_template_id=winner.template_id,
            confidence=_signature_confidence(winner, len(winner_hits)),
            matched_signatures=[sig.name for sig, _ in matches],
        )

    # Collection

    async def _guarded_call(
        self,
        semaphore: asyncio.Semaphore,
        fn: Optional[Callable[..., Any]],
        default: Optional[Callable[..., Any]],
        *args: Any,
    ) -> Any:
        async with semaphore:
            try:
                if fn is None:
                    return await default(*args) if default is not None else None
                res = fn(*args)
                if inspect.isawaitable(res):
                    res = await res
                return res
            except Exception:
                return None

    async def _collect_with_semaphore(
        self, ip: str, open_ports: Iterable[int], semaphore: asyncio.Semaphore
    ) -> RawServiceBanner:
        ip = _canonical_ipv4(ip)
        ports = _normalize_ports(open_ports)
        timeout = self.timeout_sec
        call = functools.partial(self._guarded_call, semaphore)
        probes: list[tuple[str, Optional[int], Any]] = []
        for port in ports:
            if port in SSH_BANNER_PORTS:
                ssh = call(self._ssh_fn, _default_async_ssh_banner, ip, port, timeout)
                probes.append(("ssh", port, ssh))
            if port in HTTP_BANNER_PORTS:
                http = call(
                    self._http_fn, _default_async_http, ip, port, False, timeout
                )
                probes.append(("http", port, http))
            if port in TLS_BANNER_PORTS:
                tls = call(self._tls_fn, _default_async_tls, ip, port, timeout)
                https = call(
                    self._http_fn, _default_async_http, ip, port, True, timeout
                )
                probes.extend((("tls", port, tls), ("http", port, https)))
        if self._snmp_fn is not None:
            probes.append(("snmp", None, call(self._snmp_fn, None, ip, timeout)))

        results = await asyncio.gather(*(coro for _, _, coro in probes))

        ssh_banner: Optional[str] = None
        titles: list[str] = []
        headers: dict[str, str] = {}
        tls_cn: Optional[str] = None
        san_names: list[str] = []
        certificates: list[TlsCertificate] = []
        sys_descr: Optional[str] = None
        sys_name: Optional[str] = None
        for (kind, probe_port, _), res in zip(probes, results):
            if kind == "ssh":
                cleaned = _clean_text(_str_or_none(res), "ssh_banner")
                if ssh_banner is None and cleaned is not None:
                    ssh_banner = cleaned
            elif kind == "http":
                pair = _pair(res)
                if pair is None:
                    continue
                raw_headers, raw_title = pair
                title = _clean_text(_str_or_none(raw_title), "http_titles")
                if title is not None:
                    titles.append(title)
                if isinstance(raw_headers, Mapping):
                    for raw_key, raw_value in raw_headers.items():
                        key = _clean_text(_str_or_none(raw_key), "http_headers key")
                        value = _clean_text(
                            _str_or_none(raw_value), "http_headers value"
                        )
                        if key is not None and value is not None:
                            headers.setdefault(key.lower(), value)
            elif kind == "tls":
                if isinstance(res, TlsCertificate):
                    raw_cn, raw_sans = res.subject_cn, res.san_dns_names
                else:
                    pair = _pair(res)
                    if pair is None:
                        continue
                    raw_cn, raw_sans = pair
                cn = _clean_text(_str_or_none(raw_cn), "tls_subject_cn")
                if tls_cn is None and cn is not None:
                    tls_cn = cn
                port_sans: list[str] = []
                if isinstance(raw_sans, Sequence) and not isinstance(
                    raw_sans, (str, bytes)
                ):
                    for raw_san in raw_sans:
                        san = _clean_text(_str_or_none(raw_san), "tls_san_dns_names")
                        if san is not None and san not in san_names:
                            san_names.append(san)
                        if san is not None and san not in port_sans:
                            port_sans.append(san)
                try:
                    if isinstance(res, TlsCertificate):
                        if (res.ip, res.port) == (ip, probe_port):
                            certificates.append(res)
                        else:
                            certificates.append(
                                dataclasses.replace(res, ip=ip, port=probe_port)
                            )
                    elif cn is not None or port_sans:
                        certificates.append(
                            TlsCertificate(
                                ip=ip,
                                port=probe_port,
                                subject_cn=cn,
                                san_dns_names=port_sans,
                            )
                        )
                except ValueError:
                    # A malformed entry is skipped; the merged fields still count
                    pass
            elif kind == "snmp":
                pair = _pair(res)
                if pair is None:
                    continue
                sys_descr = _str_or_none(pair[0])
                sys_name = _str_or_none(pair[1])

        return RawServiceBanner(
            ip=ip,
            ssh_banner=ssh_banner,
            http_titles=titles,
            http_headers=headers,
            tls_subject_cn=tls_cn,
            tls_san_dns_names=san_names,
            snmp_sys_descr=sys_descr,
            snmp_sys_name=sys_name,
            tls_certificates=certificates,
        )

    async def collect_async(
        self, ip: str, open_ports: Iterable[int]
    ) -> RawServiceBanner:
        """Collect banners from the known-open banner ports of one IP."""
        semaphore = asyncio.Semaphore(self.max_concurrency)
        return await self._collect_with_semaphore(ip, open_ports, semaphore)

    def collect(self, ip: str, open_ports: Iterable[int]) -> RawServiceBanner:
        """Synchronous wrapper around :meth:`collect_async`."""
        return _run_coro_sync(self.collect_async(ip, open_ports))

    async def collect_many_async(
        self,
        targets: Mapping[str, Sequence[int]] | Iterable[tuple[str, Sequence[int]]],
    ) -> list[RawServiceBanner]:
        """Collect banners for many IPs; all probes share one concurrency bound."""
        if isinstance(targets, Mapping):
            pairs = list(targets.items())
        elif isinstance(targets, (str, bytes)) or not isinstance(targets, Iterable):
            raise ValueError(
                "targets must be a mapping or iterable of (ip, ports) pairs"
            )
        else:
            pairs = []
            for item in targets:
                pair = _pair(item)
                if pair is None:
                    raise ValueError("targets entries must be (ip, ports) pairs")
                pairs.append(pair)
        semaphore = asyncio.Semaphore(self.max_concurrency)
        collections = (
            self._collect_with_semaphore(ip, ports, semaphore) for ip, ports in pairs
        )
        return list(await asyncio.gather(*collections))

    def collect_many(
        self,
        targets: Mapping[str, Sequence[int]] | Iterable[tuple[str, Sequence[int]]],
    ) -> list[RawServiceBanner]:
        """Synchronous wrapper around :meth:`collect_many_async`."""
        return _run_coro_sync(self.collect_many_async(targets))

    # Enrichment

    def enrich_site(
        self, site: Site, banners: Iterable[RawServiceBanner]
    ) -> tuple[Site, list[DeviceFingerprint]]:
        """Return an enriched deep copy of ``site`` and one fingerprint per banner."""
        if not isinstance(site, Site):
            raise ValueError("site must be a Site instance")
        fingerprints = [self.fingerprint(banner) for banner in banners]
        enriched = copy.deepcopy(site)

        for fp in fingerprints:
            for device in enriched.devices:
                if _ip_or_none(device.management_ip) != fp.ip:
                    continue
                if fp.vendor and not (device.vendor or "").strip():
                    device.vendor = fp.vendor
                if fp.model and not (device.model or "").strip():
                    device.model = fp.model
                if fp.discovered_hostname and _is_synthetic_device_hostname(
                    device.hostname, device.management_ip or ""
                ):
                    device.hostname = fp.discovered_hostname
            for eq in enriched.equipment:
                if fp.ip not in {_ip_or_none(raw) for raw in eq.assigned_ips}:
                    continue
                if fp.discovered_hostname and _is_synthetic_equipment_name(
                    eq.name, fp.ip, eq.equipment_id
                ):
                    eq.name = fp.discovered_hostname
        return enriched, fingerprints
