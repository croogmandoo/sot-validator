"""TLS certificate, raw service banner and device fingerprint records."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from sot_validator.discovery._fingerprint_common import (
    _FINGERPRINT_ROLES,
    _MAX_SAN_NAMES,
    _MAX_TITLES,
    _MAX_TLS_CERTIFICATES,
    _TEMPLATE_CATALOG,
    _canonical_ipv4,
    _clean_headers,
    _clean_text,
    _clean_text_list,
    _utc_datetime,
)


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
