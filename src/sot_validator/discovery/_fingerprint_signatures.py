"""Service signature table, hostname extraction and signature confidence scoring."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import ipaddress
import re
from typing import Optional

from sot_validator.discovery._fingerprint_common import _HOST_LABEL_RE
from sot_validator.discovery._fingerprint_models import RawServiceBanner


@dataclass(frozen=True)
class _ServiceSignature:
    name: str
    patterns: tuple[re.Pattern[str], ...]
    vendor: Optional[str]
    os_family: Optional[str]
    role: str
    template_id: Optional[str]
    generic: bool = False


def _sig(
    name: str,
    patterns: Sequence[str],
    vendor: Optional[str],
    os_family: Optional[str],
    role: str,
    template_id: Optional[str],
    *,
    generic: bool = False,
) -> _ServiceSignature:
    return _ServiceSignature(
        name=name,
        patterns=tuple(re.compile(p, re.IGNORECASE) for p in patterns),
        vendor=vendor,
        os_family=os_family,
        role=role,
        template_id=template_id,
        generic=generic,
    )


# Table order is precedence: appliances first, generic OS/SSH signatures last
_SIGNATURES: tuple[_ServiceSignature, ...] = (
    _sig(
        "extreme-exos",
        [r"extremexos"],
        "Extreme Networks",
        "ExtremeXOS",
        "switch",
        "extreme-exos-48p",
    ),
    _sig(
        "extreme-voss",
        [r"\bvoss\b", r"\bvsp-\d+"],
        "Extreme Networks",
        "VOSS",
        "switch",
        "extreme-voss-core",
    ),
    _sig(
        "apc",
        [r"powernet", r"\bapc\b", r"american power conversion"],
        "APC",
        None,
        "ups",
        "apc-smart-ups",
    ),
    _sig(
        "unifi-os",
        [r"\bunifi"],
        "Ubiquiti",
        "UniFi OS",
        "router",
        "unifi-multi-vlan-router",
    ),
    _sig(
        "edgeos",
        [r"edgeos", r"edgerouter"],
        "Ubiquiti",
        "EdgeOS",
        "router",
        "unifi-multi-vlan-router",
    ),
    _sig(
        "proxmox-ve",
        [r"pve-manager", r"proxmox virtual environment", r"pve-api-daemon"],
        "Proxmox",
        "Proxmox VE",
        "hypervisor",
        "proxmox-ve-host",
    ),
    _sig(
        "synology",
        [r"synology", r"diskstation", r"rackstation"],
        "Synology",
        "DSM",
        "nas_storage",
        "generic-smb-nas",
    ),
    _sig(
        "truenas",
        [r"truenas", r"freenas"],
        "iXsystems",
        "TrueNAS",
        "nas_storage",
        "generic-smb-nas",
    ),
    _sig(
        "home-assistant",
        [r"home assistant"],
        "Home Assistant",
        None,
        "automation_hub",
        None,
    ),
    _sig("portainer", [r"portainer"], "Portainer", None, "server", None),
    _sig("pihole", [r"pi-hole"], "Pi-hole", None, "dns_server", None),
    _sig("adguard", [r"adguard"], "AdGuard", None, "dns_server", None),
    _sig("bind", [r"\bbind\b"], "ISC", None, "dns_server", None),
    _sig("samba", [r"samba"], "Samba", None, "nas_storage", "generic-smb-nas"),
    _sig("cachyos", [r"cachyos"], None, "CachyOS", "server", None, generic=True),
    _sig("ubuntu", [r"ubuntu"], None, "Ubuntu", "server", None, generic=True),
    _sig(
        "debian",
        [r"debian", r"\bdeb1\d"],
        None,
        "Debian",
        "server",
        None,
        generic=True,
    ),
    _sig("dropbear", [r"dropbear"], None, "Embedded Linux", "host", None, generic=True),
)


def _valid_hostname(candidate: Optional[str]) -> Optional[str]:
    if not candidate:
        return None
    name = candidate.strip().lower()
    if name.endswith("."):
        name = name[:-1]
    if not name or len(name) > 253 or "*" in name:
        return None
    try:
        ipaddress.ip_address(name)
        return None
    except ValueError:
        pass
    labels = name.split(".")
    if not all(_HOST_LABEL_RE.match(label) for label in labels):
        return None
    if labels[0] == "localhost":
        return None
    return name


def _extract_hostname(banner: RawServiceBanner) -> Optional[str]:
    candidates = [
        *banner.tls_san_dns_names,
        banner.tls_subject_cn,
        banner.snmp_sys_name,
        banner.mdns_name,
    ]
    for candidate in candidates:
        hostname = _valid_hostname(candidate)
        if hostname is not None:
            return hostname
    return None


def _signature_sources(banner: RawServiceBanner) -> dict[str, list[str]]:
    return {
        "ssh": [banner.ssh_banner] if banner.ssh_banner else [],
        "http": [*banner.http_titles, *banner.http_headers.values()],
        "tls": [
            *([banner.tls_subject_cn] if banner.tls_subject_cn else []),
            *banner.tls_san_dns_names,
        ],
        "snmp": [banner.snmp_sys_descr] if banner.snmp_sys_descr else [],
    }


def _matching_sources(
    signature: _ServiceSignature, sources: Mapping[str, list[str]]
) -> set[str]:
    allowed = ("ssh", "snmp") if signature.generic else ("ssh", "http", "tls", "snmp")
    return {
        source
        for source in allowed
        if any(p.search(text) for text in sources[source] for p in signature.patterns)
    }


def _signature_confidence(signature: _ServiceSignature, source_count: int) -> float:
    # Appliance winners land in [0.6, 0.9], generic winners in [0.2, 0.3]
    extra = 0.1 * (min(source_count, 4) - 1)
    base = 0.2 if signature.generic else 0.6
    return round(base + extra, 2)
