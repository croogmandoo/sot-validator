"""Classification constants and policy: default signal weights, signal-type sets, ClassificationPolicy."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from sot_validator.models import SignalType
from sot_validator.signals.base import (
    SECONDS_PER_DAY,
    validate_recency_thresholds,
)

DEFAULT_SIGNAL_WEIGHTS: dict[SignalType, float] = {
    SignalType.VM_POWER_STATE: 0.45,
    SignalType.AD_COMPUTER_ACCOUNT: 0.40,
    SignalType.SNMP_API_REACHABILITY: 0.40,
    SignalType.ICMP_REACHABILITY: 0.35,
    SignalType.ARP_RECENCY: 0.35,
    SignalType.DNS_DHCP_LEASE: 0.35,
    SignalType.PORT_STATE: 0.25,
    SignalType.LAST_SEEN_TIMESTAMP: 0.15,
}

_SUBSTANTIVE_STALE_SIGNAL_TYPES: frozenset[SignalType] = frozenset(
    {
        SignalType.ARP_RECENCY,
        SignalType.PORT_STATE,
        SignalType.VM_POWER_STATE,
        SignalType.LAST_SEEN_TIMESTAMP,
        SignalType.AD_COMPUTER_ACCOUNT,
        SignalType.DNS_DHCP_LEASE,
    }
)

_HIGH_CONFIDENCE_ACTIVE_SIGNAL_TYPES: frozenset[SignalType] = frozenset(
    {
        SignalType.ICMP_REACHABILITY,
        SignalType.SNMP_API_REACHABILITY,
        SignalType.ARP_RECENCY,
        SignalType.VM_POWER_STATE,
        SignalType.AD_COMPUTER_ACCOUNT,
        SignalType.DNS_DHCP_LEASE,
    }
)

_ACTIVE_PROBE_SIGNAL_TYPES: frozenset[SignalType] = frozenset(
    {
        SignalType.ICMP_REACHABILITY,
        SignalType.SNMP_API_REACHABILITY,
    }
)


def _default_signal_weights() -> dict[SignalType, float]:
    return dict(DEFAULT_SIGNAL_WEIGHTS)


@dataclass
class ClassificationPolicy:
    """Configurable recency thresholds, rules, and signal weights for classification."""

    active_within_days: float = 7.0
    stale_after_days: float = 30.0
    windows_vm_ignore_icmp_unreachable: bool = True
    signal_weights: dict[SignalType, float] = field(
        default_factory=_default_signal_weights
    )

    def __post_init__(self) -> None:
        self.active_within_days, self.stale_after_days = validate_recency_thresholds(
            self.active_within_days,
            self.stale_after_days,
        )
        if not isinstance(self.windows_vm_ignore_icmp_unreachable, bool):
            raise ValueError("windows_vm_ignore_icmp_unreachable must be a boolean")
        if not isinstance(self.signal_weights, Mapping):
            raise ValueError("signal_weights must be a mapping of SignalType to float")

        normalized_weights: dict[SignalType, float] = dict(DEFAULT_SIGNAL_WEIGHTS)
        for raw_key, raw_val in self.signal_weights.items():
            key = (
                raw_key
                if isinstance(raw_key, SignalType)
                else SignalType(str(raw_key))
            )
            if isinstance(raw_val, bool) or not isinstance(raw_val, (int, float)):
                raise ValueError(
                    f"Signal weight for {key.value} must be a non-negative number"
                )
            weight = float(raw_val)
            if weight < 0.0:
                raise ValueError(
                    f"Signal weight for {key.value} must be non-negative"
                )
            normalized_weights[key] = weight

        self.signal_weights = normalized_weights

    @property
    def active_threshold_seconds(self) -> float:
        """Active recency window in seconds."""
        return self.active_within_days * SECONDS_PER_DAY

    @property
    def stale_threshold_seconds(self) -> float:
        """Stale inactivity threshold in seconds."""
        return self.stale_after_days * SECONDS_PER_DAY

    def weight_for(self, signal_type: SignalType) -> float:
        """Return the configured non-negative weight for a SignalType."""
        return self.signal_weights.get(
            signal_type, DEFAULT_SIGNAL_WEIGHTS.get(signal_type, 0.1)
        )

