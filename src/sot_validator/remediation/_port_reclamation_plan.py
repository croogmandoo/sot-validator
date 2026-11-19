"""Port reclamation candidate and staged plan records with CLI script rendering."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from typing import Any, Optional
import uuid

from sot_validator.models import _format_optional_datetime, _require_non_empty_str
from sot_validator.remediation._port_reclamation_common import (
    ExtremeCliDialect,
    _clean_optional_str,
    _coerce_cli_dialect,
    _preserve_str_tuple,
)
from sot_validator.remediation._port_reclamation_records import BlockedPortRecord
from sot_validator.remediation.sink import (
    _enforce_dry_run_only,
    _resolve_plan_timestamp,
)


@dataclass(frozen=True)
class PortReclamationCandidate:
    """Eligible stale Extreme Networks access port with staged CLI disable and rollback commands."""

    port_id: str
    device_id: str
    port_name: str
    site_id: Optional[str] = None
    device_hostname: Optional[str] = None
    admin_status: Optional[str] = "up"
    oper_status: Optional[str] = "down"
    poe_status: Optional[str] = None
    vlan_id: Optional[str] = None
    description: Optional[str] = None
    connected_device_id: Optional[str] = None
    inactive_runs: int = 0
    inactive_days: float = 0.0
    estimated_poe_watts_saved: float = 0.0
    poe_restore_limit_mw: int = 30000
    dialect: ExtremeCliDialect = ExtremeCliDialect.EXOS
    exos_disable_commands: tuple[str, ...] = ()
    exos_rollback_commands: tuple[str, ...] = ()
    exos_rollback_command: str = ""
    voss_disable_commands: tuple[str, ...] = ()
    voss_rollback_commands: tuple[str, ...] = ()
    voss_rollback_command: str = ""

    def __post_init__(self) -> None:
        _require_non_empty_str(self.port_id, "port_id")
        _require_non_empty_str(self.device_id, "device_id")
        _require_non_empty_str(self.port_name, "port_name")

        if isinstance(self.inactive_runs, bool) or not isinstance(
            self.inactive_runs, int
        ) or self.inactive_runs < 0:
            raise ValueError("inactive_runs must be a non-negative integer")
        if isinstance(self.inactive_days, bool) or not isinstance(
            self.inactive_days, (int, float)
        ) or float(self.inactive_days) < 0.0:
            raise ValueError("inactive_days must be a non-negative number")
        if isinstance(self.estimated_poe_watts_saved, bool) or not isinstance(
            self.estimated_poe_watts_saved, (int, float)
        ) or float(self.estimated_poe_watts_saved) < 0.0:
            raise ValueError(
                "estimated_poe_watts_saved must be a non-negative number"
            )
        if isinstance(self.poe_restore_limit_mw, bool) or not isinstance(
            self.poe_restore_limit_mw, int
        ) or self.poe_restore_limit_mw < 0:
            raise ValueError(
                "poe_restore_limit_mw must be a non-negative integer"
            )

        coerced_dialect = _coerce_cli_dialect(self.dialect, "dialect")
        object.__setattr__(self, "dialect", coerced_dialect)
        object.__setattr__(self, "inactive_days", float(self.inactive_days))
        object.__setattr__(
            self,
            "estimated_poe_watts_saved",
            round(float(self.estimated_poe_watts_saved), 2),
        )

        pname = self.port_name.strip()
        limit_mw = self.poe_restore_limit_mw

        exos_fwd = _preserve_str_tuple(self.exos_disable_commands) or (
            f"configure inline-power operator-limit 0 ports {pname}",
            f"disable ports {pname}",
        )
        exos_rb = _preserve_str_tuple(self.exos_rollback_commands) or (
            f"configure inline-power operator-limit {limit_mw} ports {pname}",
            f"enable ports {pname}",
        )
        exos_rb_one = _clean_optional_str(self.exos_rollback_command) or (
            f"enable ports {pname}; configure inline-power operator-limit {limit_mw} ports {pname}"
        )

        voss_fwd = _preserve_str_tuple(self.voss_disable_commands) or (
            f"interface GigabitEthernet {pname}",
            "poe-shutdown",
            "shutdown",
            "exit",
        )
        voss_rb = _preserve_str_tuple(self.voss_rollback_commands) or (
            f"interface GigabitEthernet {pname}",
            "no poe-shutdown",
            "no shutdown",
            "exit",
        )
        voss_rb_one = _clean_optional_str(self.voss_rollback_command) or (
            f"interface GigabitEthernet {pname}; no poe-shutdown; no shutdown; exit"
        )

        object.__setattr__(self, "exos_disable_commands", exos_fwd)
        object.__setattr__(self, "exos_rollback_commands", exos_rb)
        object.__setattr__(self, "exos_rollback_command", exos_rb_one)
        object.__setattr__(self, "voss_disable_commands", voss_fwd)
        object.__setattr__(self, "voss_rollback_commands", voss_rb)
        object.__setattr__(self, "voss_rollback_command", voss_rb_one)

    @property
    def name(self) -> str:
        """Alias for port_name."""
        return self.port_name

    @property
    def consecutive_stale_runs(self) -> int:
        """Alias for inactive_runs."""
        return self.inactive_runs

    @property
    def stale_duration_days(self) -> float:
        """Alias for inactive_days."""
        return self.inactive_days

    @property
    def forward_commands(self) -> tuple[str, ...]:
        """Return staged forward disable commands for the active CLI dialect."""
        if self.dialect is ExtremeCliDialect.VOSS:
            return self.voss_disable_commands
        return self.exos_disable_commands

    @property
    def disable_commands(self) -> tuple[str, ...]:
        """Alias for forward_commands."""
        return self.forward_commands

    @property
    def rollback_commands(self) -> tuple[str, ...]:
        """Return staged rollback commands for the active CLI dialect."""
        if self.dialect is ExtremeCliDialect.VOSS:
            return self.voss_rollback_commands
        return self.exos_rollback_commands

    @property
    def rollback_command(self) -> str:
        """Return 1-command rollback string for the active CLI dialect."""
        if self.dialect is ExtremeCliDialect.VOSS:
            return self.voss_rollback_command
        return self.exos_rollback_command

    def to_dict(self) -> dict[str, Any]:
        return {
            "port_id": self.port_id,
            "device_id": self.device_id,
            "port_name": self.port_name,
            "site_id": self.site_id,
            "device_hostname": self.device_hostname,
            "admin_status": self.admin_status,
            "oper_status": self.oper_status,
            "poe_status": self.poe_status,
            "vlan_id": self.vlan_id,
            "description": self.description,
            "connected_device_id": self.connected_device_id,
            "inactive_runs": self.inactive_runs,
            "inactive_days": self.inactive_days,
            "estimated_poe_watts_saved": self.estimated_poe_watts_saved,
            "poe_restore_limit_mw": self.poe_restore_limit_mw,
            "dialect": self.dialect.value,
            "exos_disable_commands": list(self.exos_disable_commands),
            "exos_rollback_commands": list(self.exos_rollback_commands),
            "exos_rollback_command": self.exos_rollback_command,
            "voss_disable_commands": list(self.voss_disable_commands),
            "voss_rollback_commands": list(self.voss_rollback_commands),
            "voss_rollback_command": self.voss_rollback_command,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PortReclamationCandidate:
        if isinstance(data, cls):
            return data
        return cls(
            port_id=data["port_id"],
            device_id=data["device_id"],
            port_name=data.get("port_name") or data.get("name", ""),
            site_id=data.get("site_id"),
            device_hostname=data.get("device_hostname"),
            admin_status=data.get("admin_status", "up"),
            oper_status=data.get("oper_status", "down"),
            poe_status=data.get("poe_status"),
            vlan_id=data.get("vlan_id"),
            description=data.get("description"),
            connected_device_id=data.get("connected_device_id"),
            inactive_runs=int(
                data.get(
                    "inactive_runs", data.get("consecutive_stale_runs", 0)
                )
            ),
            inactive_days=float(
                data.get("inactive_days", data.get("stale_duration_days", 0.0))
            ),
            estimated_poe_watts_saved=float(
                data.get("estimated_poe_watts_saved", 0.0)
            ),
            poe_restore_limit_mw=int(data.get("poe_restore_limit_mw", 30000)),
            dialect=_coerce_cli_dialect(
                data.get("dialect", ExtremeCliDialect.EXOS)
            ),
            exos_disable_commands=tuple(data.get("exos_disable_commands", ())),
            exos_rollback_commands=tuple(
                data.get("exos_rollback_commands", ())
            ),
            exos_rollback_command=data.get("exos_rollback_command", ""),
            voss_disable_commands=tuple(data.get("voss_disable_commands", ())),
            voss_rollback_commands=tuple(
                data.get("voss_rollback_commands", ())
            ),
            voss_rollback_command=data.get("voss_rollback_command", ""),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> PortReclamationCandidate:
        return cls.from_dict(json.loads(raw))


def _render_staged_cli_script(
    candidates: Sequence[PortReclamationCandidate],
    *,
    dialect: ExtremeCliDialect,
    rollback: bool,
    estimated_poe_watts_saved: float,
) -> str:
    mode_label = "ROLLBACK" if rollback else "STAGED PORT & POE RECLAMATION"
    lines: list[str] = [
        f"# Extreme Networks ({dialect.value.upper()}) {mode_label} SCRIPT (DRY-RUN)",
        f"# Eligible ports: {len(candidates)} | Estimated PoE savings: {estimated_poe_watts_saved:.2f}W",
    ]
    if not candidates:
        lines.append("# No eligible ports for reclamation.")
        return "\n".join(lines) + "\n"

    for candidate in candidates:
        host_Part = (
            f" ({candidate.device_hostname})"
            if candidate.device_hostname
            else ""
        )
        lines.append(
            f"# Device: {candidate.device_id}{host_Part} | Port: {candidate.port_name} ({candidate.port_id}) "
            f"| Inactive: {candidate.inactive_runs} runs ({candidate.inactive_days:.1f}d) "
            f"| PoE saved: {candidate.estimated_poe_watts_saved:.2f}W"
        )
        if dialect is ExtremeCliDialect.EXOS:
            if rollback:
                lines.append(
                    f"# 1-command rollback: {candidate.exos_rollback_command}"
                )
                lines.extend(candidate.exos_rollback_commands)
            else:
                lines.extend(candidate.exos_disable_commands)
        else:
            if rollback:
                lines.append(
                    f"# 1-command rollback: {candidate.voss_rollback_command}"
                )
                lines.extend(candidate.voss_rollback_commands)
            else:
                lines.extend(candidate.voss_disable_commands)

    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class PortReclamationPlan:
    """Staged dry-run Extreme switch port and PoE reclamation plan with rollback scripts."""

    candidates: tuple[PortReclamationCandidate, ...] = ()
    blocked_ports: tuple[BlockedPortRecord, ...] = ()
    estimated_poe_watts_saved: float = 0.0
    min_inactive_runs: int = 3
    min_inactive_days: float = 30.0
    dialect: ExtremeCliDialect = ExtremeCliDialect.EXOS
    exos_commands: tuple[str, ...] = ()
    exos_rollback_commands: tuple[str, ...] = ()
    voss_commands: tuple[str, ...] = ()
    voss_rollback_commands: tuple[str, ...] = ()
    exos_script: str = ""
    exos_rollback_script: str = ""
    voss_script: str = ""
    voss_rollback_script: str = ""
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    plan_id: str = field(
        default_factory=lambda: f"port-plan-{uuid.uuid4().hex[:12]}"
    )
    dry_run: bool = True

    def __post_init__(self) -> None:
        _enforce_dry_run_only(self.dry_run, "PortReclamationPlan")
        _require_non_empty_str(self.plan_id, "plan_id")

        if isinstance(self.min_inactive_runs, bool) or not isinstance(
            self.min_inactive_runs, int
        ) or self.min_inactive_runs < 1:
            raise ValueError("min_inactive_runs must be an integer >= 1")
        if isinstance(self.min_inactive_days, bool) or not isinstance(
            self.min_inactive_days, (int, float)
        ) or float(self.min_inactive_days) < 0.0:
            raise ValueError("min_inactive_days must be a non-negative number")

        coerced_dialect = _coerce_cli_dialect(self.dialect, "dialect")
        resolved_generated_at = _resolve_plan_timestamp(self.generated_at)

        normalized_candidates = tuple(
            c
            if isinstance(c, PortReclamationCandidate)
            else PortReclamationCandidate.from_dict(c)
            for c in (self.candidates or ())
        )
        normalized_blocked = tuple(
            b
            if isinstance(b, BlockedPortRecord)
            else BlockedPortRecord.from_dict(b)
            for b in (self.blocked_ports or ())
        )

        computed_poe = round(
            sum(c.estimated_poe_watts_saved for c in normalized_candidates), 2
        )
        if (
            self.estimated_poe_watts_saved == 0.0
            and computed_poe > 0.0
        ):
            resolved_poe = computed_poe
        else:
            resolved_poe = round(float(self.estimated_poe_watts_saved), 2)
        if resolved_poe < 0.0:
            raise ValueError(
                "estimated_poe_watts_saved must be a non-negative number"
            )

        exos_cmds = _preserve_str_tuple(self.exos_commands) or tuple(
            cmd
            for c in normalized_candidates
            for cmd in c.exos_disable_commands
        )
        exos_rb_cmds = _preserve_str_tuple(self.exos_rollback_commands) or tuple(
            cmd
            for c in normalized_candidates
            for cmd in c.exos_rollback_commands
        )
        voss_cmds = _preserve_str_tuple(self.voss_commands) or tuple(
            cmd
            for c in normalized_candidates
            for cmd in c.voss_disable_commands
        )
        voss_rb_cmds = _preserve_str_tuple(self.voss_rollback_commands) or tuple(
            cmd
            for c in normalized_candidates
            for cmd in c.voss_rollback_commands
        )

        exos_scr = self.exos_script or _render_staged_cli_script(
            normalized_candidates,
            dialect=ExtremeCliDialect.EXOS,
            rollback=False,
            estimated_poe_watts_saved=resolved_poe,
        )
        exos_rb_scr = self.exos_rollback_script or _render_staged_cli_script(
            normalized_candidates,
            dialect=ExtremeCliDialect.EXOS,
            rollback=True,
            estimated_poe_watts_saved=resolved_poe,
        )
        voss_scr = self.voss_script or _render_staged_cli_script(
            normalized_candidates,
            dialect=ExtremeCliDialect.VOSS,
            rollback=False,
            estimated_poe_watts_saved=resolved_poe,
        )
        voss_rb_scr = self.voss_rollback_script or _render_staged_cli_script(
            normalized_candidates,
            dialect=ExtremeCliDialect.VOSS,
            rollback=True,
            estimated_poe_watts_saved=resolved_poe,
        )

        object.__setattr__(self, "candidates", normalized_candidates)
        object.__setattr__(self, "blocked_ports", normalized_blocked)
        object.__setattr__(self, "estimated_poe_watts_saved", resolved_poe)
        object.__setattr__(
            self, "min_inactive_days", float(self.min_inactive_days)
        )
        object.__setattr__(self, "dialect", coerced_dialect)
        object.__setattr__(self, "exos_commands", exos_cmds)
        object.__setattr__(self, "exos_rollback_commands", exos_rb_cmds)
        object.__setattr__(self, "voss_commands", voss_cmds)
        object.__setattr__(self, "voss_rollback_commands", voss_rb_cmds)
        object.__setattr__(self, "exos_script", exos_scr)
        object.__setattr__(self, "exos_rollback_script", exos_rb_scr)
        object.__setattr__(self, "voss_script", voss_scr)
        object.__setattr__(self, "voss_rollback_script", voss_rb_scr)
        object.__setattr__(self, "generated_at", resolved_generated_at)

    @property
    def eligible_ports(self) -> tuple[PortReclamationCandidate, ...]:
        """Alias for candidates."""
        return self.candidates

    @property
    def forward_commands(self) -> tuple[str, ...]:
        """Return staged forward CLI commands for the plan's active dialect."""
        if self.dialect is ExtremeCliDialect.VOSS:
            return self.voss_commands
        return self.exos_commands

    @property
    def rollback_commands(self) -> tuple[str, ...]:
        """Return staged rollback CLI commands for the plan's active dialect."""
        if self.dialect is ExtremeCliDialect.VOSS:
            return self.voss_rollback_commands
        return self.exos_rollback_commands

    @property
    def forward_script(self) -> str:
        """Return staged forward CLI script for the plan's active dialect."""
        if self.dialect is ExtremeCliDialect.VOSS:
            return self.voss_script
        return self.exos_script

    @property
    def rollback_script(self) -> str:
        """Return staged rollback CLI script for the plan's active dialect."""
        if self.dialect is ExtremeCliDialect.VOSS:
            return self.voss_rollback_script
        return self.exos_rollback_script

    def format_cli_script(
        self, dialect: ExtremeCliDialect | str = ExtremeCliDialect.EXOS
    ) -> str:
        """Return the staged forward CLI script for the requested Extreme CLI dialect."""
        target = _coerce_cli_dialect(dialect, "dialect")
        return (
            self.voss_script
            if target is ExtremeCliDialect.VOSS
            else self.exos_script
        )

    def format_rollback_script(
        self, dialect: ExtremeCliDialect | str = ExtremeCliDialect.EXOS
    ) -> str:
        """Return the staged rollback CLI script for the requested Extreme CLI dialect."""
        target = _coerce_cli_dialect(dialect, "dialect")
        return (
            self.voss_rollback_script
            if target is ExtremeCliDialect.VOSS
            else self.exos_rollback_script
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "generated_at": _format_optional_datetime(self.generated_at),
            "dry_run": self.dry_run,
            "dialect": self.dialect.value,
            "min_inactive_runs": self.min_inactive_runs,
            "min_inactive_days": self.min_inactive_days,
            "estimated_poe_watts_saved": self.estimated_poe_watts_saved,
            "candidates": [c.to_dict() for c in self.candidates],
            "blocked_ports": [b.to_dict() for b in self.blocked_ports],
            "exos_commands": list(self.exos_commands),
            "exos_rollback_commands": list(self.exos_rollback_commands),
            "voss_commands": list(self.voss_commands),
            "voss_rollback_commands": list(self.voss_rollback_commands),
            "exos_script": self.exos_script,
            "exos_rollback_script": self.exos_rollback_script,
            "voss_script": self.voss_script,
            "voss_rollback_script": self.voss_rollback_script,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PortReclamationPlan:
        if isinstance(data, cls):
            return data
        raw_candidates = data.get(
            "candidates", data.get("eligible_ports", ())
        )
        return cls(
            plan_id=data.get(
                "plan_id", f"port-plan-{uuid.uuid4().hex[:12]}"
            ),
            generated_at=_resolve_plan_timestamp(data.get("generated_at")),
            dry_run=data.get("dry_run", True),
            dialect=_coerce_cli_dialect(
                data.get("dialect", ExtremeCliDialect.EXOS)
            ),
            min_inactive_runs=int(data.get("min_inactive_runs", 3)),
            min_inactive_days=float(data.get("min_inactive_days", 30.0)),
            estimated_poe_watts_saved=float(
                data.get("estimated_poe_watts_saved", 0.0)
            ),
            candidates=tuple(
                PortReclamationCandidate.from_dict(c) for c in raw_candidates
            ),
            blocked_ports=tuple(
                BlockedPortRecord.from_dict(b)
                for b in data.get("blocked_ports", ())
            ),
            exos_commands=tuple(data.get("exos_commands", ())),
            exos_rollback_commands=tuple(
                data.get("exos_rollback_commands", ())
            ),
            voss_commands=tuple(data.get("voss_commands", ())),
            voss_rollback_commands=tuple(
                data.get("voss_rollback_commands", ())
            ),
            exos_script=data.get("exos_script", ""),
            exos_rollback_script=data.get("exos_rollback_script", ""),
            voss_script=data.get("voss_script", ""),
            voss_rollback_script=data.get("voss_rollback_script", ""),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> PortReclamationPlan:
        return cls.from_dict(json.loads(raw))
