"""Unattended run lock, run manifest and exit-code contract (POSIX-only).

Used by the ``run`` and ``campaign`` commands through ``sot_validator.cli._ops_run``.
"""

from __future__ import annotations

from sot_validator.ops.runner import (
    MANIFEST_FILENAME,
    ExitCode,
    RunLock,
    RunLockHeld,
    RunManifest,
    SiteStatus,
    file_sha256,
    select_exit_code,
    tool_version,
)

__all__ = [
    "ExitCode",
    "MANIFEST_FILENAME",
    "RunLock",
    "RunLockHeld",
    "RunManifest",
    "SiteStatus",
    "file_sha256",
    "select_exit_code",
    "tool_version",
]
