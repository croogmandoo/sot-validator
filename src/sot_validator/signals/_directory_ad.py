"""Active Directory computer account record and collector."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from sot_validator.models import (
    Equipment,
    IPAddress,
    NetworkDevice,
    SignalStatus,
    SignalType,
    Site,
    ValidationSignal,
)
from sot_validator.signals._directory_common import (
    _clean_optional_str,
    _normalize_fqdn,
    _parse_bool_flag,
    normalize_hostname,
)
from sot_validator.signals.base import (
    SECONDS_PER_DAY,
    SignalCollector,
    normalize_utc_datetime,
    resolve_evaluation_time,
    validate_recency_thresholds,
)


@dataclass(init=False)
class AdComputerRecord:
    """Active Directory computer account record."""

    sam_account_name: str
    dns_hostname: Optional[str] = None
    operating_system: Optional[str] = None
    enabled: bool = True
    last_logon_timestamp: Optional[datetime] = None
    pwd_last_set: Optional[datetime] = None
    distinguished_name: Optional[str] = None

    def __init__(
        self,
        sam_account_name: Optional[str] = None,
        dns_hostname: Optional[str] = None,
        operating_system: Optional[str] = None,
        enabled: Any = True,
        last_logon_timestamp: Optional[datetime | str] = None,
        pwd_last_set: Optional[datetime | str] = None,
        distinguished_name: Optional[str] = None,
        *,
        sAMAccountName: Optional[str] = None,
        dNSHostName: Optional[str] = None,
        operatingSystem: Optional[str] = None,
        lastLogonTimestamp: Optional[datetime | str] = None,
        pwdLastSet: Optional[datetime | str] = None,
        distinguishedName: Optional[str] = None,
        ou: Optional[str] = None,
        OU: Optional[str] = None,
        name: Optional[str] = None,
        cn: Optional[str] = None,
    ) -> None:
        resolved_dns = _clean_optional_str(
            dns_hostname if dns_hostname is not None else dNSHostName
        )
        resolved_sam = _clean_optional_str(
            sam_account_name
            if sam_account_name is not None
            else (sAMAccountName or name or cn)
        )
        if not resolved_sam and resolved_dns:
            short = normalize_hostname(resolved_dns)
            if short:
                resolved_sam = f"{short.upper()}$"
        if not resolved_sam:
            raise ValueError("sam_account_name (sAMAccountName) must be a non-empty string")

        self.sam_account_name = resolved_sam
        self.dns_hostname = resolved_dns
        self.operating_system = _clean_optional_str(
            operating_system if operating_system is not None else operatingSystem
        )
        self.enabled = _parse_bool_flag(enabled, default=True)

        raw_logon = (
            last_logon_timestamp
            if last_logon_timestamp is not None
            else lastLogonTimestamp
        )
        if raw_logon is not None and (
            not isinstance(raw_logon, str) or raw_logon.strip()
        ):
            self.last_logon_timestamp = normalize_utc_datetime(
                raw_logon, field_name="last_logon_timestamp"
            )
        else:
            self.last_logon_timestamp = None

        raw_pwd = pwd_last_set if pwd_last_set is not None else pwdLastSet
        if raw_pwd is not None and (not isinstance(raw_pwd, str) or raw_pwd.strip()):
            self.pwd_last_set = normalize_utc_datetime(
                raw_pwd, field_name="pwd_last_set"
            )
        else:
            self.pwd_last_set = None

        self.distinguished_name = _clean_optional_str(
            distinguished_name
            if distinguished_name is not None
            else (distinguishedName or ou or OU)
        )

    @property
    def sAMAccountName(self) -> str:
        return self.sam_account_name

    @property
    def dNSHostName(self) -> Optional[str]:
        return self.dns_hostname

    @property
    def operatingSystem(self) -> Optional[str]:
        return self.operating_system

    @property
    def lastLogonTimestamp(self) -> Optional[datetime]:
        return self.last_logon_timestamp

    @property
    def pwdLastSet(self) -> Optional[datetime]:
        return self.pwd_last_set

    @property
    def distinguishedName(self) -> Optional[str]:
        return self.distinguished_name

    @property
    def ou(self) -> Optional[str]:
        return self.distinguished_name

    @property
    def normalized_hostname(self) -> Optional[str]:
        return normalize_hostname(self.dns_hostname or self.sam_account_name)

    def to_dict(self) -> dict[str, Any]:
        logon_iso = (
            self.last_logon_timestamp.isoformat()
            if self.last_logon_timestamp is not None
            else None
        )
        pwd_iso = (
            self.pwd_last_set.isoformat() if self.pwd_last_set is not None else None
        )
        return {
            "sam_account_name": self.sam_account_name,
            "sAMAccountName": self.sam_account_name,
            "dns_hostname": self.dns_hostname,
            "dNSHostName": self.dns_hostname,
            "operating_system": self.operating_system,
            "operatingSystem": self.operating_system,
            "enabled": self.enabled,
            "last_logon_timestamp": logon_iso,
            "lastLogonTimestamp": logon_iso,
            "pwd_last_set": pwd_iso,
            "pwdLastSet": pwd_iso,
            "distinguished_name": self.distinguished_name,
            "distinguishedName": self.distinguished_name,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AdComputerRecord:
        enabled_val = data.get("enabled")
        if enabled_val is None:
            enabled_val = data.get("is_enabled", data.get("account_enabled", True))
        return cls(
            sam_account_name=(
                data.get("sam_account_name")
                or data.get("sAMAccountName")
                or data.get("account_name")
                or data.get("name")
                or data.get("cn")
            ),
            dns_hostname=(
                data.get("dns_hostname")
                or data.get("dNSHostName")
                or data.get("fqdn")
                or data.get("hostname")
            ),
            operating_system=(
                data.get("operating_system")
                or data.get("operatingSystem")
                or data.get("os")
            ),
            enabled=enabled_val,
            last_logon_timestamp=(
                data.get("last_logon_timestamp")
                if data.get("last_logon_timestamp") is not None
                else (data.get("lastLogonTimestamp") or data.get("last_logon"))
            ),
            pwd_last_set=(
                data.get("pwd_last_set")
                if data.get("pwd_last_set") is not None
                else (data.get("pwdLastSet") or data.get("password_last_set"))
            ),
            distinguished_name=(
                data.get("distinguished_name")
                or data.get("distinguishedName")
                or data.get("dn")
                or data.get("ou")
                or data.get("OU")
            ),
        )


class ActiveDirectoryCollector(SignalCollector):
    """Correlate SoT equipment and device hostnames against Active Directory computer accounts."""

    signal_type = SignalType.AD_COMPUTER_ACCOUNT

    def __init__(
        self,
        records: Optional[Iterable[AdComputerRecord | Mapping[str, Any]]] = None,
        *,
        accounts: Optional[Iterable[AdComputerRecord | Mapping[str, Any]]] = None,
        active_threshold_days: Optional[float] = None,
        active_within_days: Optional[float] = None,
        stale_threshold_days: Optional[float] = None,
        stale_after_days: Optional[float] = None,
        evaluation_time: Optional[datetime | str] = None,
        source: str = "active_directory",
    ) -> None:
        resolved_active = (
            active_threshold_days
            if active_threshold_days is not None
            else (active_within_days if active_within_days is not None else 30.0)
        )
        resolved_stale = (
            stale_threshold_days
            if stale_threshold_days is not None
            else (stale_after_days if stale_after_days is not None else 90.0)
        )
        self.active_threshold_days, self.stale_threshold_days = (
            validate_recency_thresholds(resolved_active, resolved_stale)
        )
        self.active_within_days = self.active_threshold_days
        self.stale_after_days = self.stale_threshold_days
        self.evaluation_time: Optional[datetime] = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else None
        )
        self.source = source

        raw_records = records if records is not None else accounts
        self._records: list[AdComputerRecord] = self._coerce_records(raw_records)

    @staticmethod
    def _coerce_records(
        records: Optional[Iterable[AdComputerRecord | Mapping[str, Any]]],
    ) -> list[AdComputerRecord]:
        if records is None:
            return []
        if isinstance(records, Mapping):
            # Support dict keyed by hostname or {"records": [...]} / {"accounts": [...]}
            if "records" in records and isinstance(records["records"], Iterable):
                records = records["records"]
            elif "accounts" in records and isinstance(records["accounts"], Iterable):
                records = records["accounts"]
            else:
                coerced_map: list[AdComputerRecord] = []
                for key, val in records.items():
                    if isinstance(val, AdComputerRecord):
                        coerced_map.append(val)
                    elif isinstance(val, Mapping):
                        item_dict = dict(val)
                        item_dict.setdefault("sam_account_name", str(key))
                        coerced_map.append(AdComputerRecord.from_dict(item_dict))
                return coerced_map

        out: list[AdComputerRecord] = []
        for item in records:
            if isinstance(item, AdComputerRecord):
                out.append(item)
            elif isinstance(item, Mapping):
                out.append(AdComputerRecord.from_dict(item))
            else:
                raise ValueError(f"Unsupported AD computer record: {item!r}")
        return out

    @property
    def records(self) -> tuple[AdComputerRecord, ...]:
        return tuple(self._records)

    @staticmethod
    def _extract_target_hostnames(
        target: Any, site: Optional[Site] = None
    ) -> tuple[list[str], str]:
        if isinstance(target, Equipment):
            return [target.name], f"Equipment {target.name} ({target.equipment_id})"
        if isinstance(target, NetworkDevice):
            return [target.hostname], f"NetworkDevice {target.hostname} ({target.device_id})"
        if isinstance(target, IPAddress):
            hosts: list[str] = []
            for attr in ("hostname", "dns_name", "name"):
                val = getattr(target, attr, None)
                if isinstance(val, str) and val.strip():
                    hosts.append(val.strip())
            if site is not None:
                for eq in site.equipment:
                    if (
                        target.assigned_object_id == eq.equipment_id
                        or target.ip in eq.assigned_ips
                    ):
                        if eq.name not in hosts:
                            hosts.append(eq.name)
                for dev in site.devices:
                    if (
                        target.assigned_object_id == dev.device_id
                        or dev.management_ip == target.ip
                    ):
                        if dev.hostname not in hosts:
                            hosts.append(dev.hostname)
            return hosts, f"IPAddress {target.ip}"
        if isinstance(target, str):
            cleaned = target.strip()
            return ([cleaned] if cleaned else []), f"hostname {cleaned!r}"
        if isinstance(target, Mapping):
            raw_host = (
                target.get("name")
                or target.get("hostname")
                or target.get("dns_hostname")
                or target.get("dNSHostName")
                or target.get("sam_account_name")
                or target.get("sAMAccountName")
            )
            cleaned = _clean_optional_str(raw_host)
            return ([cleaned] if cleaned else []), "mapping"
        return [], type(target).__name__

    @staticmethod
    def _match_record(
        candidate_hostnames: Sequence[str],
        records: Sequence[AdComputerRecord],
    ) -> Optional[AdComputerRecord]:
        target_fqdns = {
            fqdn
            for h in candidate_hostnames
            if (fqdn := _normalize_fqdn(h)) is not None and "." in fqdn
        }
        target_shorts = {
            short
            for h in candidate_hostnames
            if (short := normalize_hostname(h)) is not None
        }
        if not target_fqdns and not target_shorts:
            return None

        fqdn_matches: list[AdComputerRecord] = []
        short_matches: list[AdComputerRecord] = []

        for rec in records:
            rec_fqdn = _normalize_fqdn(rec.dns_hostname)
            rec_sam_short = normalize_hostname(rec.sam_account_name)
            rec_dns_short = normalize_hostname(rec.dns_hostname)

            if target_fqdns and rec_fqdn in target_fqdns:
                fqdn_matches.append(rec)
                continue

            if (rec_sam_short and rec_sam_short in target_shorts) or (
                rec_dns_short and rec_dns_short in target_shorts
            ):
                short_matches.append(rec)

        matches = fqdn_matches if fqdn_matches else short_matches
        if not matches:
            return None

        def _sort_key(rec: AdComputerRecord) -> tuple[int, float]:
            timestamps = [
                ts.timestamp()
                for ts in (rec.last_logon_timestamp, rec.pwd_last_set)
                if ts is not None
            ]
            freshest_ts = max(timestamps) if timestamps else float("-inf")
            return (1 if rec.enabled else 0, freshest_ts)

        return max(matches, key=_sort_key)

    def evaluate(
        self,
        target: Any,
        *,
        site: Optional[Site] = None,
        records: Optional[Iterable[AdComputerRecord | Mapping[str, Any]]] = None,
        accounts: Optional[Iterable[AdComputerRecord | Mapping[str, Any]]] = None,
        active_threshold_days: Optional[float] = None,
        active_within_days: Optional[float] = None,
        stale_threshold_days: Optional[float] = None,
        stale_after_days: Optional[float] = None,
        evaluation_time: Optional[datetime | str] = None,
        **kwargs: Any,
    ) -> ValidationSignal:
        """Evaluate Active Directory computer account status and timestamp recency for target."""
        _ = kwargs
        raw_active = (
            active_threshold_days
            if active_threshold_days is not None
            else (
                active_within_days
                if active_within_days is not None
                else self.active_threshold_days
            )
        )
        raw_stale = (
            stale_threshold_days
            if stale_threshold_days is not None
            else (
                stale_after_days
                if stale_after_days is not None
                else self.stale_threshold_days
            )
        )
        active_days, stale_days = validate_recency_thresholds(raw_active, raw_stale)

        eval_dt = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else (
                self.evaluation_time
                if self.evaluation_time is not None
                else resolve_evaluation_time(None)
            )
        )

        pool = (
            self._coerce_records(records if records is not None else accounts)
            if (records is not None or accounts is not None)
            else self._records
        )

        candidate_hosts, target_label = self._extract_target_hostnames(
            target, site=site
        )
        if not candidate_hosts:
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=None,
                age_seconds=None,
                details=f"No hostname available on {target_label} for AD correlation",
                source=self.source,
                metadata={"matched": False},
            )

        record = self._match_record(candidate_hosts, pool)
        if record is None:
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=None,
                age_seconds=None,
                details=(
                    f"No matching Active Directory computer account found for {target_label}"
                ),
                source=self.source,
                metadata={
                    "matched": False,
                    "normalized_hostname": normalize_hostname(candidate_hosts[0]),
                },
            )

        timestamp_candidates: list[tuple[str, datetime, float]] = []
        if record.last_logon_timestamp is not None:
            age_logon = max(
                0.0, (eval_dt - record.last_logon_timestamp).total_seconds()
            )
            timestamp_candidates.append(
                ("lastLogonTimestamp", record.last_logon_timestamp, age_logon)
            )
        if record.pwd_last_set is not None:
            age_pwd = max(0.0, (eval_dt - record.pwd_last_set).total_seconds())
            timestamp_candidates.append(("pwdLastSet", record.pwd_last_set, age_pwd))

        freshest_attr: Optional[str] = None
        freshest_dt: Optional[datetime] = None
        freshest_age_sec: Optional[float] = None
        if timestamp_candidates:
            freshest_attr, freshest_dt, freshest_age_sec = min(
                timestamp_candidates,
                key=lambda item: (item[2], -item[1].timestamp()),
            )

        os_label = record.operating_system or "Windows"
        active_sec = active_days * SECONDS_PER_DAY
        stale_sec = stale_days * SECONDS_PER_DAY

        if not record.enabled:
            status = SignalStatus.INACTIVE
            account_stale = True
            ts_note = (
                f", {freshest_attr}={freshest_dt.isoformat()} "
                f"(age {freshest_age_sec / SECONDS_PER_DAY:.2f}d)"
                if freshest_dt is not None and freshest_age_sec is not None
                else ""
            )
            details = (
                f"AD computer account {record.sam_account_name} is disabled "
                f"(enabled=False, os={os_label}{ts_note})"
            )
        elif freshest_dt is None or freshest_age_sec is None:
            status = SignalStatus.INACTIVE
            account_stale = True
            details = (
                f"AD computer account {record.sam_account_name} is enabled "
                f"(os={os_label}) but has no lastLogonTimestamp or pwdLastSet recorded"
            )
        elif freshest_age_sec <= active_sec:
            status = SignalStatus.ACTIVE
            account_stale = False
            age_days = freshest_age_sec / SECONDS_PER_DAY
            details = (
                f"AD computer account {record.sam_account_name} is active "
                f"(enabled=True, os={os_label}, {freshest_attr}={freshest_dt.isoformat()}, "
                f"age {age_days:.2f}d <= active threshold {active_days:g}d)"
            )
        elif freshest_age_sec <= stale_sec:
            status = SignalStatus.INACTIVE
            account_stale = False
            age_days = freshest_age_sec / SECONDS_PER_DAY
            details = (
                f"AD computer account {record.sam_account_name} is in intermediate aging window "
                f"(enabled=True, os={os_label}, {freshest_attr}={freshest_dt.isoformat()}, "
                f"age {age_days:.2f}d > active threshold {active_days:g}d, "
                f"<= stale threshold {stale_days:g}d)"
            )
        else:
            status = SignalStatus.INACTIVE
            account_stale = True
            age_days = freshest_age_sec / SECONDS_PER_DAY
            details = (
                f"AD computer account {record.sam_account_name} is stale "
                f"(enabled=True, os={os_label}, {freshest_attr}={freshest_dt.isoformat()}, "
                f"age {age_days:.2f}d > stale threshold {stale_days:g}d)"
            )

        metadata: dict[str, Any] = {
            "matched": True,
            "sAMAccountName": record.sam_account_name,
            "sam_account_name": record.sam_account_name,
            "dNSHostName": record.dns_hostname,
            "dns_hostname": record.dns_hostname,
            "operatingSystem": record.operating_system,
            "operating_system": record.operating_system,
            "enabled": record.enabled,
            "distinguishedName": record.distinguished_name,
            "distinguished_name": record.distinguished_name,
            "lastLogonTimestamp": (
                record.last_logon_timestamp.isoformat()
                if record.last_logon_timestamp is not None
                else None
            ),
            "pwdLastSet": (
                record.pwd_last_set.isoformat()
                if record.pwd_last_set is not None
                else None
            ),
            "account_stale": account_stale,
            "normalized_hostname": record.normalized_hostname,
        }

        return ValidationSignal(
            signal_type=self.signal_type,
            status=status,
            observed_at=freshest_dt,
            age_seconds=freshest_age_sec,
            details=details,
            source=self.source,
            metadata=metadata,
        )

    def collect(self, target: Any, **kwargs: Any) -> ValidationSignal:
        """Convenience alias for evaluate()."""
        return self.evaluate(target, **kwargs)

    def collect_for_equipment(
        self, equipment: Equipment, **kwargs: Any
    ) -> ValidationSignal:
        """Evaluate AD computer account signal for an Equipment record."""
        return self.evaluate(equipment, **kwargs)

    def collect_for_device(
        self, device: NetworkDevice, **kwargs: Any
    ) -> ValidationSignal:
        """Evaluate AD computer account signal for a NetworkDevice record."""
        return self.evaluate(device, **kwargs)
