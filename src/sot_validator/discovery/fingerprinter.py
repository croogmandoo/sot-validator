"""Read-only SSH/HTTP/TLS/SNMP service banner and certificate fingerprinting engine."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterable, Mapping, Sequence
import copy
import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
import functools
import html
import inspect
import ipaddress
import re
import ssl
from typing import Any, Optional
import unicodedata

from sot_validator.discovery.router_tables import (
    _is_synthetic_device_hostname,
    _is_synthetic_equipment_name,
)
from sot_validator.discovery.scanner import _run_coro_sync
from sot_validator.models import Site, _parse_optional_datetime
from sot_validator.topology.device_types import DeviceTypeCatalog

SSH_BANNER_PORTS: tuple[int, ...] = (22,)
HTTP_BANNER_PORTS: tuple[int, ...] = (80, 5000, 8000, 8080, 8123, 9000)
TLS_BANNER_PORTS: tuple[int, ...] = (443, 5001, 8006, 8443, 9443)

_MAX_TEXT_LEN = 256
_MAX_HEADERS = 32
_MAX_TITLES = 16
_MAX_SAN_NAMES = 32
_MAX_TLS_CERTIFICATES = 16
_SSH_READ_LIMIT = 256
_HTTP_HEADER_LIMIT = 64 * 1024
_HTTP_BODY_LIMIT = 64 * 1024
_DER_MAX_INPUT = 16 * 1024

_FINGERPRINT_ROLES: frozenset[str] = frozenset(
    {
        "switch",
        "router",
        "ups",
        "hypervisor",
        "nas_storage",
        "dns_server",
        "automation_hub",
        "iot_device",
        "server",
        "host",
    }
)
_TEMPLATE_CATALOG = DeviceTypeCatalog()

_WHITESPACE_RE = re.compile(r"\s+")
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_EXOS_MODEL_RE = re.compile(r"extremexos\s*\(\s*([^()]+?)\s*\)", re.IGNORECASE)
_HTML_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title\s*>", re.IGNORECASE | re.DOTALL)


def _clean_text(value: Any, field_name: str) -> Optional[str]:
    """Strip control characters, collapse whitespace and cap a text value."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string or None")
    chars: list[str] = []
    for ch in value:
        if ch in "\t\r\n":
            chars.append(" ")
        elif unicodedata.category(ch) != "Cc":
            chars.append(ch)
    cleaned = _WHITESPACE_RE.sub(" ", "".join(chars)).strip()[:_MAX_TEXT_LEN].rstrip()
    return cleaned or None


def _clean_text_list(values: Any, field_name: str, limit: int) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes)) or not isinstance(values, (list, tuple)):
        raise ValueError(f"{field_name} must be a list of strings")
    cleaned_list: list[str] = []
    for raw in values:
        if raw is None:
            continue
        cleaned = _clean_text(raw, field_name)
        if cleaned is not None and cleaned not in cleaned_list:
            cleaned_list.append(cleaned)
    return cleaned_list[:limit]


def _clean_headers(headers: Any) -> dict[str, str]:
    if headers is None:
        return {}
    if not isinstance(headers, Mapping):
        raise ValueError("http_headers must be a mapping of strings to strings")
    cleaned_headers: dict[str, str] = {}
    for raw_key, raw_value in headers.items():
        key = _clean_text(raw_key, "http_headers key")
        value = _clean_text(raw_value, "http_headers value")
        if key is None or value is None:
            continue
        key = key.lower()
        if key not in cleaned_headers:
            cleaned_headers[key] = value
    return dict(list(cleaned_headers.items())[:_MAX_HEADERS])


def _canonical_ipv4(ip: Any) -> str:
    if not isinstance(ip, str) or not ip.strip():
        raise ValueError("ip must be a non-empty IPv4 string")
    return str(ipaddress.IPv4Address(ip.strip()))


def _ip_or_none(value: Any) -> Optional[str]:
    try:
        return _canonical_ipv4(value)
    except ValueError:
        return None


def _utc_datetime(value: Any, field_name: str) -> Optional[datetime]:
    """Parse a datetime or ISO-8601 string into aware UTC, treating naive as UTC."""
    parsed = _parse_optional_datetime(value, field_name)
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass
class TlsCertificate:
    """Leaf certificate details read from one TLS port of one host."""

    ip: str
    port: int
    subject_cn: Optional[str] = None
    subject_dn: Optional[str] = None
    issuer_dn: Optional[str] = None
    san_dns_names: list[str] = field(default_factory=list)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    signature_algorithm: Optional[str] = None
    key_type: Optional[str] = None
    key_bits: Optional[int] = None

    def __post_init__(self) -> None:
        self.ip = _canonical_ipv4(self.ip)
        if (
            isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or not (1 <= self.port <= 65535)
        ):
            raise ValueError(f"port must be an integer in 1..65535, got {self.port!r}")
        self.subject_cn = _clean_text(self.subject_cn, "subject_cn")
        self.subject_dn = _clean_text(self.subject_dn, "subject_dn")
        self.issuer_dn = _clean_text(self.issuer_dn, "issuer_dn")
        self.san_dns_names = _clean_text_list(
            self.san_dns_names, "san_dns_names", _MAX_SAN_NAMES
        )
        self.not_before = _utc_datetime(self.not_before, "not_before")
        self.not_after = _utc_datetime(self.not_after, "not_after")
        self.signature_algorithm = _clean_text(
            self.signature_algorithm, "signature_algorithm"
        )
        self.key_type = _clean_text(self.key_type, "key_type")
        if self.key_bits is not None and (
            isinstance(self.key_bits, bool) or not isinstance(self.key_bits, int)
        ):
            raise ValueError(f"key_bits must be an integer or None, got {self.key_bits!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "port": self.port,
            "subject_cn": self.subject_cn,
            "subject_dn": self.subject_dn,
            "issuer_dn": self.issuer_dn,
            "san_dns_names": list(self.san_dns_names),
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "signature_algorithm": self.signature_algorithm,
            "key_type": self.key_type,
            "key_bits": self.key_bits,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TlsCertificate:
        return cls(
            ip=data.get("ip"),
            port=data.get("port"),
            subject_cn=data.get("subject_cn"),
            subject_dn=data.get("subject_dn"),
            issuer_dn=data.get("issuer_dn"),
            san_dns_names=data.get("san_dns_names"),
            not_before=data.get("not_before"),
            not_after=data.get("not_after"),
            signature_algorithm=data.get("signature_algorithm"),
            key_type=data.get("key_type"),
            key_bits=data.get("key_bits"),
        )


def _clean_tls_certificates(values: Any) -> list[TlsCertificate]:
    if isinstance(values, (str, bytes)) or not isinstance(values, (list, tuple)):
        raise ValueError("tls_certificates must be a list of TlsCertificate entries")
    certificates: list[TlsCertificate] = []
    for item in values:
        if isinstance(item, TlsCertificate):
            certificates.append(item)
        elif isinstance(item, Mapping):
            certificates.append(TlsCertificate.from_dict(item))
        else:
            raise ValueError(
                "tls_certificates entries must be TlsCertificate instances or mappings"
            )
    return certificates[:_MAX_TLS_CERTIFICATES]


@dataclass
class RawServiceBanner:
    """Sanitised service banners and certificate names collected from one host."""

    ip: str
    ssh_banner: Optional[str] = None
    http_titles: list[str] = field(default_factory=list)
    http_headers: dict[str, str] = field(default_factory=dict)
    tls_subject_cn: Optional[str] = None
    tls_san_dns_names: list[str] = field(default_factory=list)
    snmp_sys_descr: Optional[str] = None
    snmp_sys_name: Optional[str] = None
    mdns_name: Optional[str] = None
    tls_certificates: list[TlsCertificate] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.ip = _canonical_ipv4(self.ip)
        self.ssh_banner = _clean_text(self.ssh_banner, "ssh_banner")
        self.http_titles = _clean_text_list(
            self.http_titles, "http_titles", _MAX_TITLES
        )
        self.http_headers = _clean_headers(self.http_headers)
        self.tls_subject_cn = _clean_text(self.tls_subject_cn, "tls_subject_cn")
        self.tls_san_dns_names = _clean_text_list(
            self.tls_san_dns_names, "tls_san_dns_names", _MAX_SAN_NAMES
        )
        self.snmp_sys_descr = _clean_text(self.snmp_sys_descr, "snmp_sys_descr")
        self.snmp_sys_name = _clean_text(self.snmp_sys_name, "snmp_sys_name")
        self.mdns_name = _clean_text(self.mdns_name, "mdns_name")
        self.tls_certificates = _clean_tls_certificates(self.tls_certificates)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "ssh_banner": self.ssh_banner,
            "http_titles": list(self.http_titles),
            "http_headers": dict(self.http_headers),
            "tls_subject_cn": self.tls_subject_cn,
            "tls_san_dns_names": list(self.tls_san_dns_names),
            "snmp_sys_descr": self.snmp_sys_descr,
            "snmp_sys_name": self.snmp_sys_name,
            "mdns_name": self.mdns_name,
            "tls_certificates": [cert.to_dict() for cert in self.tls_certificates],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RawServiceBanner:
        return cls(
            ip=data["ip"],
            ssh_banner=data.get("ssh_banner"),
            http_titles=list(data.get("http_titles") or []),
            http_headers=dict(data.get("http_headers") or {}),
            tls_subject_cn=data.get("tls_subject_cn"),
            tls_san_dns_names=list(data.get("tls_san_dns_names") or []),
            snmp_sys_descr=data.get("snmp_sys_descr"),
            snmp_sys_name=data.get("snmp_sys_name"),
            mdns_name=data.get("mdns_name"),
            tls_certificates=data.get("tls_certificates") or [],
        )


@dataclass
class DeviceFingerprint:
    """Vendor, OS, role and device template identified from a host's service banners."""

    ip: str
    vendor: Optional[str] = None
    model: Optional[str] = None
    os_family: Optional[str] = None
    discovered_hostname: Optional[str] = None
    inferred_role: str = "host"
    recommended_template_id: Optional[str] = None
    confidence: float = 0.0
    matched_signatures: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.ip = _canonical_ipv4(self.ip)
        for name in ("vendor", "model", "os_family", "discovered_hostname"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{name} must be a string or None")

        if self.inferred_role not in _FINGERPRINT_ROLES:
            raise ValueError(f"Unknown inferred_role: {self.inferred_role!r}")

        if self.recommended_template_id is not None:
            try:
                _TEMPLATE_CATALOG.get(self.recommended_template_id)
            except KeyError as exc:
                raise ValueError(
                    f"Unknown recommended_template_id: {self.recommended_template_id!r}"
                ) from exc

        if isinstance(self.confidence, bool) or not isinstance(
            self.confidence, (int, float)
        ):
            raise ValueError("confidence must be a number in 0.0..1.0")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be a number in 0.0..1.0")
        self.confidence = float(self.confidence)

        if isinstance(self.matched_signatures, (str, bytes)) or not isinstance(
            self.matched_signatures, (list, tuple)
        ):
            raise ValueError("matched_signatures must be a list of strings")
        if not all(isinstance(name, str) for name in self.matched_signatures):
            raise ValueError("matched_signatures must be a list of strings")
        self.matched_signatures = list(self.matched_signatures)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "vendor": self.vendor,
            "model": self.model,
            "os_family": self.os_family,
            "discovered_hostname": self.discovered_hostname,
            "inferred_role": self.inferred_role,
            "recommended_template_id": self.recommended_template_id,
            "confidence": self.confidence,
            "matched_signatures": list(self.matched_signatures),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DeviceFingerprint:
        return cls(
            ip=data["ip"],
            vendor=data.get("vendor"),
            model=data.get("model"),
            os_family=data.get("os_family"),
            discovered_hostname=data.get("discovered_hostname"),
            inferred_role=data.get("inferred_role", "host"),
            recommended_template_id=data.get("recommended_template_id"),
            confidence=data.get("confidence", 0.0),
            matched_signatures=list(data.get("matched_signatures") or []),
        )


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


def _der_tlv(data: bytes, offset: int, end: int) -> tuple[int, int, int]:
    """Read one DER TLV header; return ``(tag, value_start, value_end)``."""
    if offset + 2 > end:
        raise ValueError("truncated DER element")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise ValueError("high-tag-number DER form is not supported")
    first_len = data[offset + 1]
    pos = offset + 2
    if first_len < 0x80:
        length = first_len
    else:
        num_bytes = first_len & 0x7F
        if num_bytes == 0 or num_bytes > 3 or pos + num_bytes > end:
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[pos : pos + num_bytes], "big")
        pos += num_bytes
    if pos + length > end:
        raise ValueError("DER length exceeds input")
    return tag, pos, pos + length


def _der_children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    children: list[tuple[int, int, int]] = []
    offset = start
    while offset < end:
        tlv = _der_tlv(data, offset, end)
        children.append(tlv)
        offset = tlv[2]
    return children


def _der_expect(tlv: tuple[int, int, int], tag: int) -> tuple[int, int, int]:
    if tlv[0] != tag:
        raise ValueError(f"unexpected DER tag 0x{tlv[0]:02x}")
    return tlv


_DER_SEQUENCE = 0x30
_DER_SET = 0x31
_DER_INTEGER = 0x02
_DER_BIT_STRING = 0x03
_DER_OID = 0x06
_DER_OCTET_STRING = 0x04
_DER_UTC_TIME = 0x17
_DER_GENERALIZED_TIME = 0x18
_DER_EXTENSIONS = 0xA3
_DER_SAN_DNS_NAME = 0x82
_OID_COMMON_NAME = b"\x55\x04\x03"
_OID_SUBJECT_ALT_NAME = b"\x55\x1d\x11"
_DER_STRING_CODECS: dict[int, str] = {
    0x0C: "utf-8",
    0x13: "latin-1",
    0x14: "latin-1",
    0x16: "latin-1",
    0x1C: "utf-32-be",
    0x1E: "utf-16-be",
}
_DN_SHORT_NAMES: dict[str, str] = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "STREET",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "0.9.2342.19200300.100.1.25": "DC",
    "0.9.2342.19200300.100.1.1": "UID",
}
_DN_SPECIAL_CHARS = frozenset(',+"\\<>;')
_SIGNATURE_ALGORITHM_NAMES: dict[str, str] = {
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
}
_OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
_OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
_EC_CURVE_BITS: dict[str, int] = {
    "1.2.840.10045.3.1.7": 256,
    "1.3.132.0.34": 384,
    "1.3.132.0.35": 521,
}
_KEY_TYPE_NAMES: dict[str, str] = {
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    "1.2.840.10040.4.1": "DSA",
}
_UTC_TIME_RE = re.compile(r"([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z")
_GENERALIZED_TIME_RE = re.compile(
    r"([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z"
)


def _decode_oid(body: bytes) -> str:
    """Decode a DER OBJECT IDENTIFIER body into its dotted string form."""
    if not body or body[-1] & 0x80:
        raise ValueError("truncated OID")
    arcs: list[int] = []
    value = 0
    for byte in body:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    first = arcs[0]
    if first < 40:
        head = [0, first]
    elif first < 80:
        head = [1, first - 40]
    else:
        head = [2, first - 80]
    return ".".join(str(arc) for arc in [*head, *arcs[1:]])


def _der_oid(data: bytes, tlv: tuple[int, int, int]) -> str:
    oid = _der_expect(tlv, _DER_OID)
    return _decode_oid(data[oid[1] : oid[2]])


def _escape_dn_value(value: str) -> str:
    """Escape one attribute value for an RFC 4514 DN string."""
    chars = ["\\" + ch if ch in _DN_SPECIAL_CHARS else ch for ch in value]
    if chars and chars[0] in ("#", " "):
        chars[0] = "\\" + chars[0]
    if len(chars) > 1 and chars[-1] == " ":
        chars[-1] = "\\ "
    return "".join(chars)


def _render_dn(data: bytes, name_tlv: tuple[int, int, int]) -> str:
    """Render an X.509 Name as an RFC 4514 string (RDNs in reverse DER order)."""
    name = _der_expect(name_tlv, _DER_SEQUENCE)
    rdns: list[str] = []
    for rdn in _der_children(data, name[1], name[2]):
        _der_expect(rdn, _DER_SET)
        attributes: list[str] = []
        for atv in _der_children(data, rdn[1], rdn[2]):
            _der_expect(atv, _DER_SEQUENCE)
            parts = _der_children(data, atv[1], atv[2])
            if len(parts) != 2:
                raise ValueError("malformed AttributeTypeAndValue")
            dotted = _der_oid(data, parts[0])
            label = _DN_SHORT_NAMES.get(dotted, dotted)
            codec = _DER_STRING_CODECS.get(parts[1][0])
            if codec is None:
                # The value TLV starts where the attribute type OID ends
                value = "#" + data[parts[0][2] : parts[1][2]].hex()
            else:
                value = _escape_dn_value(data[parts[1][1] : parts[1][2]].decode(codec))
            attributes.append(f"{label}={value}")
        rdns.append("+".join(attributes))
    return ",".join(reversed(rdns))


def _parse_der_time(data: bytes, tlv: tuple[int, int, int]) -> datetime:
    """Parse a UTCTime or GeneralizedTime ``...Z`` value into an aware UTC datetime."""
    text = data[tlv[1] : tlv[2]].decode("ascii")
    if tlv[0] == _DER_UTC_TIME:
        match = _UTC_TIME_RE.fullmatch(text)
        if match is None:
            raise ValueError("malformed UTCTime")
        year = int(match.group(1))
        year += 1900 if year >= 50 else 2000
    elif tlv[0] == _DER_GENERALIZED_TIME:
        match = _GENERALIZED_TIME_RE.fullmatch(text)
        if match is None:
            raise ValueError("malformed GeneralizedTime")
        year = int(match.group(1))
    else:
        raise ValueError("unsupported validity time type")
    month, day, hour, minute, second = (int(match.group(i)) for i in range(2, 7))
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


def _validity_time(
    data: bytes, validity_tlv: tuple[int, int, int], index: int
) -> datetime:
    validity = _der_expect(validity_tlv, _DER_SEQUENCE)
    times = _der_children(data, validity[1], validity[2])
    if len(times) != 2:
        raise ValueError("malformed Validity")
    return _parse_der_time(data, times[index])


def _signature_algorithm(data: bytes, algorithm_tlv: tuple[int, int, int]) -> str:
    algorithm = _der_expect(algorithm_tlv, _DER_SEQUENCE)
    parts = _der_children(data, algorithm[1], algorithm[2])
    dotted = _der_oid(data, parts[0])
    return _SIGNATURE_ALGORITHM_NAMES.get(dotted, dotted)


def _public_key(
    data: bytes, spki_tlv: tuple[int, int, int]
) -> tuple[str, Optional[int]]:
    """Return ``(key_type, key_bits)`` from a subjectPublicKeyInfo."""
    spki = _der_expect(spki_tlv, _DER_SEQUENCE)
    parts = _der_children(data, spki[1], spki[2])
    if len(parts) != 2:
        raise ValueError("malformed SubjectPublicKeyInfo")
    algorithm = _der_expect(parts[0], _DER_SEQUENCE)
    algorithm_parts = _der_children(data, algorithm[1], algorithm[2])
    dotted = _der_oid(data, algorithm_parts[0])
    bit_string = _der_expect(parts[1], _DER_BIT_STRING)
    if bit_string[1] >= bit_string[2] or data[bit_string[1]] != 0:
        raise ValueError("malformed public key BIT STRING")
    if dotted == _OID_RSA_ENCRYPTION:
        rsa_key = _der_expect(
            _der_tlv(data, bit_string[1] + 1, bit_string[2]), _DER_SEQUENCE
        )
        if rsa_key[2] != bit_string[2]:
            raise ValueError("trailing data after RSAPublicKey")
        rsa_parts = _der_children(data, rsa_key[1], rsa_key[2])
        if len(rsa_parts) != 2:
            raise ValueError("malformed RSAPublicKey")
        modulus = _der_expect(rsa_parts[0], _DER_INTEGER)
        # Unsigned read: a leading 0x00 sign byte adds no bits
        bits = int.from_bytes(data[modulus[1] : modulus[2]], "big").bit_length()
        if bits == 0:
            raise ValueError("empty RSA modulus")
        return "RSA", bits
    if dotted == _OID_EC_PUBLIC_KEY:
        curve_bits: Optional[int] = None
        if len(algorithm_parts) == 2 and algorithm_parts[1][0] == _DER_OID:
            curve_bits = _EC_CURVE_BITS.get(_der_oid(data, algorithm_parts[1]))
        return "EC", curve_bits
    return _KEY_TYPE_NAMES.get(dotted, dotted), None


def _guarded_read(reader: Callable[..., Any], *args: Any) -> Any:
    """Run one optional field reader; any malformed-DER error leaves the field unset."""
    try:
        return reader(*args)
    except (ValueError, IndexError):
        # UnicodeDecodeError is a ValueError subclass
        return None


def _read_certificate(data: bytes) -> dict[str, Any]:
    """Walk a DER X.509 certificate without recursion and return its fields.

    The CN/SAN walk is structural and raises on malformed input; every other
    field is read in its own guarded step and is ``None`` when it can't be read.
    """
    cert = _der_expect(_der_tlv(data, 0, len(data)), _DER_SEQUENCE)
    if cert[2] != len(data):
        raise ValueError("trailing data after certificate")
    cert_children = _der_children(data, cert[1], cert[2])
    if not cert_children:
        raise ValueError("empty certificate")
    tbs = _der_expect(cert_children[0], _DER_SEQUENCE)
    fields = _der_children(data, tbs[1], tbs[2])
    idx = 1 if fields and fields[0][0] == 0xA0 else 0
    # serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
    if len(fields) < idx + 6:
        raise ValueError("truncated tbsCertificate")
    subject = _der_expect(fields[idx + 4], _DER_SEQUENCE)

    common_name: Optional[str] = None
    for rdn in _der_children(data, subject[1], subject[2]):
        _der_expect(rdn, _DER_SET)
        for atv in _der_children(data, rdn[1], rdn[2]):
            _der_expect(atv, _DER_SEQUENCE)
            parts = _der_children(data, atv[1], atv[2])
            if len(parts) != 2:
                raise ValueError("malformed AttributeTypeAndValue")
            oid = _der_expect(parts[0], _DER_OID)
            if common_name is None and data[oid[1] : oid[2]] == _OID_COMMON_NAME:
                codec = _DER_STRING_CODECS.get(parts[1][0])
                if codec is None:
                    raise ValueError("unsupported CN string type")
                common_name = data[parts[1][1] : parts[1][2]].decode(codec)

    san_names: list[str] = []
    for extra in fields[idx + 6 :]:
        if extra[0] != _DER_EXTENSIONS:
            continue
        ext_children = _der_children(data, extra[1], extra[2])
        if len(ext_children) != 1:
            raise ValueError("malformed extensions")
        ext_seq = _der_expect(ext_children[0], _DER_SEQUENCE)
        for ext in _der_children(data, ext_seq[1], ext_seq[2]):
            _der_expect(ext, _DER_SEQUENCE)
            ext_parts = _der_children(data, ext[1], ext[2])
            if len(ext_parts) < 2:
                raise ValueError("malformed Extension")
            oid = _der_expect(ext_parts[0], _DER_OID)
            if data[oid[1] : oid[2]] != _OID_SUBJECT_ALT_NAME:
                continue
            value = _der_expect(ext_parts[-1], _DER_OCTET_STRING)
            general_names = _der_children(data, value[1], value[2])
            if len(general_names) != 1:
                raise ValueError("malformed GeneralNames")
            names_seq = _der_expect(general_names[0], _DER_SEQUENCE)
            for gn in _der_children(data, names_seq[1], names_seq[2]):
                if gn[0] == _DER_SAN_DNS_NAME:
                    dns_name = data[gn[1] : gn[2]].decode("ascii")
                    if dns_name not in san_names:
                        san_names.append(dns_name)

    key = _guarded_read(_public_key, data, fields[idx + 5]) or (None, None)
    return {
        "subject_cn": common_name,
        "san_dns_names": san_names,
        "subject_dn": _guarded_read(_render_dn, data, fields[idx + 4]),
        "issuer_dn": _guarded_read(_render_dn, data, fields[idx + 2]),
        "not_before": _guarded_read(_validity_time, data, fields[idx + 3], 0),
        "not_after": _guarded_read(_validity_time, data, fields[idx + 3], 1),
        "signature_algorithm": _guarded_read(
            _signature_algorithm, data, cert_children[1]
        ),
        "key_type": key[0],
        "key_bits": key[1],
    }


def _read_certificate_bytes(der: Any) -> Optional[dict[str, Any]]:
    if not isinstance(der, (bytes, bytearray)) or not der or len(der) > _DER_MAX_INPUT:
        return None
    try:
        return _read_certificate(bytes(der))
    except (ValueError, IndexError):
        # UnicodeDecodeError is a ValueError subclass
        return None


def parse_tls_certificate(der: Any, ip: str, port: int) -> Optional[TlsCertificate]:
    """Read the leaf certificate details from DER bytes seen on ``ip:port``.

    Returns ``None`` for oversized or structurally malformed input; fields that
    can't be read individually are left as ``None``.
    """
    fields = _read_certificate_bytes(der)
    if fields is None:
        return None
    return TlsCertificate(ip=ip, port=port, **fields)


def _parse_der_certificate(der: Any) -> tuple[Optional[str], list[str]]:
    """Extract the subject CN and SAN dNSNames from a DER X.509 certificate.

    The reader walks the fixed X.509 structure without recursion and returns
    ``(None, [])`` for oversized or malformed input.
    """
    fields = _read_certificate_bytes(der)
    if fields is None:
        return None, []
    return fields["subject_cn"], fields["san_dns_names"]


def _unverified_tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _read_capped(
    reader: asyncio.StreamReader,
    limit: int,
    timeout_sec: float,
    stop: Optional[bytes] = None,
) -> bytes:
    """Read at most ``limit`` bytes before the deadline, stopping early at ``stop``."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_sec
    buf = bytearray()
    while len(buf) < limit:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        try:
            chunk = await asyncio.wait_for(
                reader.read(limit - len(buf)), timeout=remaining
            )
        except asyncio.TimeoutError:
            break
        if not chunk:
            break
        buf += chunk
        if stop is not None and stop in chunk:
            break
    return bytes(buf[:limit])


async def _close_writer(
    writer: Optional[asyncio.StreamWriter], timeout_sec: float
) -> None:
    if writer is None:
        return
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=timeout_sec)
    except (OSError, asyncio.TimeoutError, EOFError):
        pass


async def _default_async_ssh_banner(
    ip: str, port: int, timeout_sec: float
) -> Optional[str]:
    """Default SSH identification reader: connect, send nothing, read one line."""
    writer: Optional[asyncio.StreamWriter] = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout_sec
        )
        data = await _read_capped(reader, _SSH_READ_LIMIT, timeout_sec, stop=b"\n")
    except (OSError, asyncio.TimeoutError, EOFError, ValueError):
        return None
    finally:
        await _close_writer(writer, timeout_sec)
    line = data.split(b"\n", 1)[0]
    return line.decode("utf-8", errors="replace") or None


def _parse_http_response(
    head: bytes, body: bytes
) -> Optional[tuple[dict[str, str], Optional[str]]]:
    lines = head.decode("iso-8859-1").split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        if key and key not in headers:
            headers[key] = value.strip()
    title: Optional[str] = None
    match = _HTML_TITLE_RE.search(body)
    if match is not None:
        title = html.unescape(match.group(1).decode("utf-8", errors="replace"))
    return headers, title


async def _default_async_http(
    ip: str, port: int, use_tls: bool, timeout_sec: float
) -> Optional[tuple[dict[str, str], Optional[str]]]:
    """Default HTTP(S) fetcher: one unauthenticated ``GET /``, no redirects."""
    writer: Optional[asyncio.StreamWriter] = None
    request = (
        f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: sot-validator\r\n"
        "Accept: text/html\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                ip,
                port,
                ssl=_unverified_tls_context() if use_tls else None,
                ssl_handshake_timeout=timeout_sec if use_tls else None,
                limit=_HTTP_HEADER_LIMIT,
            ),
            timeout=timeout_sec,
        )
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout=timeout_sec)
        head = await asyncio.wait_for(
            reader.readuntil(b"\r\n\r\n"), timeout=timeout_sec
        )
        body = await _read_capped(reader, _HTTP_BODY_LIMIT, timeout_sec)
    except (
        OSError,
        asyncio.TimeoutError,
        EOFError,
        ValueError,
        asyncio.LimitOverrunError,
    ):
        return None
    finally:
        await _close_writer(writer, timeout_sec)
    return _parse_http_response(head, body)


async def _default_async_tls(
    ip: str, port: int, timeout_sec: float
) -> Optional[TlsCertificate]:
    """Default TLS fetcher: handshake only, then parse the peer certificate."""
    writer: Optional[asyncio.StreamWriter] = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(
                ip,
                port,
                ssl=_unverified_tls_context(),
                ssl_handshake_timeout=timeout_sec,
            ),
            timeout=timeout_sec,
        )
        ssl_object = writer.get_extra_info("ssl_object")
        der = (
            ssl_object.getpeercert(binary_form=True)
            if ssl_object is not None
            else None
        )
    except (OSError, asyncio.TimeoutError, EOFError, ValueError):
        return None
    finally:
        await _close_writer(writer, timeout_sec)
    if not der:
        return None
    return parse_tls_certificate(der, ip, port)


def _str_or_none(value: Any) -> Optional[str]:
    return value if isinstance(value, str) else None


def _pair(value: Any) -> Optional[tuple[Any, Any]]:
    if isinstance(value, (tuple, list)) and len(value) == 2:
        return value[0], value[1]
    return None


def _normalize_ports(open_ports: Iterable[int]) -> list[int]:
    if isinstance(open_ports, (str, bytes)) or not isinstance(open_ports, Iterable):
        raise ValueError("open_ports must be a sequence of integers in 1..65535")
    ports: set[int] = set()
    for port in open_ports:
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not (1 <= port <= 65535)
        ):
            raise ValueError(f"Invalid TCP port: {port!r}")
        ports.add(port)
    return sorted(ports)


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
