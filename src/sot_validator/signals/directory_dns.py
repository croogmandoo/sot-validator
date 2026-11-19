"""Active Directory computer account and /24-scoped DNS/DHCP lease correlation collectors."""

from __future__ import annotations

from sot_validator.signals._directory_ad import (
    ActiveDirectoryCollector,
    AdComputerRecord,
)
from sot_validator.signals._directory_common import (
    _clean_optional_str,
    _normalize_fqdn,
    _normalize_hostname_str,
    _parse_bool_flag,
    normalize_hostname,
)
from sot_validator.signals._directory_dns_collector import DnsDhcpLeaseCollector
from sot_validator.signals._directory_dns_records import DhcpLeaseRecord, DnsRecord

__all__ = [
    "ActiveDirectoryCollector",
    "AdComputerRecord",
    "DhcpLeaseRecord",
    "DnsDhcpLeaseCollector",
    "DnsRecord",
    "normalize_hostname",
]
