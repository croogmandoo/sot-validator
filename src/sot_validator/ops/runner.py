"""Unattended run lock, run manifest and exit-code contract (POSIX-only: ``fcntl``).

``RunLock`` is a non-blocking ``fcntl.flock`` lock on a file that holds a JSON
holder record (``pid``, ``started_at``). The flock is the source of truth; the
record only names the holder for ``RunLockHeld`` messages and lets a new holder
log when it reclaims a lock left by a dead process. The lock file is truncated,
never deleted, on release.

``RunManifest`` records one run (ids, times, tool version, config hash, per-site
status and output files) and writes it atomically to ``run_manifest.json`` with
every value passed through ``observability.redact``.

``ExitCode`` and ``select_exit_code`` define the process exit-code contract.
None of this is wired into the CLI yet.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import enum
import errno
import fcntl
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Optional, Union

from sot_validator.observability import get_logger, redact

MANIFEST_FILENAME = "run_manifest.json"
SITE_STATUSES: tuple[str, ...] = ("ok", "skipped", "failed")

_log = get_logger(__name__)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class RunLockHeld(RuntimeError):
    """Raised when another process holds the run lock."""

    def __init__(
        self, lock_path: Union[str, os.PathLike[str]], pid: Optional[int], started_at: Optional[str]
    ) -> None:
        self.lock_path = Path(lock_path)
        self.pid = pid
        self.started_at = started_at
        if pid is None:
            holder = "unknown holder"
        else:
            holder = f"pid {pid} started at {started_at if started_at else 'unknown time'}"
        super().__init__(f"run lock {self.lock_path} is held by {holder}")


def _read_holder(fd: int) -> tuple[Optional[int], Optional[str]]:
    """Return ``(pid, started_at)`` from the holder record, or ``(None, None)``."""
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            chunks.append(chunk)
        record = json.loads(b"".join(chunks).decode("utf-8"))
    except (OSError, ValueError):
        return None, None
    if not isinstance(record, dict):
        return None, None
    pid = record.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return None, None
    started_at = record.get("started_at")
    return pid, started_at if isinstance(started_at, str) else None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, OverflowError):
        return False
    except PermissionError:
        return True
    return True


class RunLock:
    """Non-blocking exclusive ``fcntl.flock`` run lock with stale-record reclaim."""

    def __init__(self, path: Union[str, os.PathLike[str]]) -> None:
        self.path = Path(path)
        self._fd: Optional[int] = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def acquire(self) -> "RunLock":
        """Take the lock or raise ``RunLockHeld``; never blocks."""
        if self._fd is not None:
            return self
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if not isinstance(exc, BlockingIOError) and exc.errno not in (
                errno.EWOULDBLOCK,
                errno.EAGAIN,
            ):
                os.close(fd)
                raise
            pid, started_at = _read_holder(fd)
            os.close(fd)
            raise RunLockHeld(self.path, pid, started_at) from None
        try:
            old_pid, old_started = _read_holder(fd)
            if old_pid is not None and old_pid != os.getpid() and not _pid_alive(old_pid):
                if old_started:
                    _log.warning(
                        "reclaiming stale run lock %s from dead pid %d started at %s",
                        self.path,
                        old_pid,
                        old_started,
                    )
                else:
                    _log.warning(
                        "reclaiming stale run lock %s from dead pid %d", self.path, old_pid
                    )
            record = json.dumps({"pid": os.getpid(), "started_at": _utc_now_iso()})
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, record.encode("utf-8"))
            os.fsync(fd)
        except BaseException:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
            raise
        self._fd = fd
        return self

    def release(self) -> None:
        """Empty the lock file, unlock and close it; a no-op when not held."""
        fd = self._fd
        if fd is None:
            return
        self._fd = None
        try:
            os.ftruncate(fd, 0)
            os.fsync(fd)
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def __enter__(self) -> "RunLock":
        return self.acquire()

    def __exit__(self, *exc_info: Any) -> None:
        self.release()


@dataclass(frozen=True)
class SiteStatus:
    """Outcome of one site in a run: ``ok``, ``skipped`` or ``failed``."""

    site_id: str
    status: str
    reason: Any = None

    def __post_init__(self) -> None:
        if self.status not in SITE_STATUSES:
            raise ValueError(
                f"invalid site status {self.status!r}; expected one of {', '.join(SITE_STATUSES)}"
            )


def _iso_utc(value: datetime, field_name: str) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat()


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return str(value)


@dataclass
class RunManifest:
    """Record of one unattended run, written atomically as ``run_manifest.json``."""

    run_id: str
    started_at: datetime
    finished_at: Optional[datetime]
    tool_version: str
    config_sha256: Optional[str]
    sites: list[SiteStatus]
    output_files: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Return a redacted, JSON-safe dict of the manifest."""
        data: dict[str, Any] = {
            "run_id": self.run_id,
            "started_at": _iso_utc(self.started_at, "started_at"),
            "finished_at": (
                None if self.finished_at is None else _iso_utc(self.finished_at, "finished_at")
            ),
            "tool_version": self.tool_version,
            "config_sha256": self.config_sha256,
            "sites": [
                {"site_id": site.site_id, "status": site.status, "reason": site.reason}
                for site in self.sites
            ],
            "output_files": [str(item) for item in self.output_files],
        }
        return _json_safe(redact(data))

    def write(self, output_dir: Union[str, os.PathLike[str]]) -> Path:
        """Atomically write the manifest to ``output_dir / MANIFEST_FILENAME``.

        Uses a same-directory temp file that is flushed, fsynced and moved into
        place with ``os.replace``. On failure the temp file is removed, an
        existing manifest is left unchanged, and the exception propagates.
        """
        target = Path(output_dir) / MANIFEST_FILENAME
        content = json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"
        fd, tmp_name = tempfile.mkstemp(
            dir=target.parent, prefix=f".{target.name}.", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o644)
            os.replace(tmp_name, target)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
            raise
        return target


def file_sha256(path: Union[str, os.PathLike[str]]) -> str:
    """Return the hex SHA-256 of the file's bytes, read in chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tool_version() -> str:
    """Return the installed ``sot-validator`` version, or ``"unknown"``."""
    try:
        return importlib.metadata.version("sot-validator")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


class ExitCode(enum.IntEnum):
    """Process exit-code contract for unattended runs.

    - ``SUCCESS`` (0): every site ok or skipped and no actionable findings.
    - ``ACTIONABLE`` (1): the run completed and produced findings an operator should act on.
    - ``PARTIAL`` (2): at least one site failed while others succeeded or were skipped.
    - ``FAILED`` (3): the run failed as a whole, or every site failed.
    - ``LOCK_HELD`` (4): another run held the lock, so this run did nothing.
    """

    SUCCESS = 0
    ACTIONABLE = 1
    PARTIAL = 2
    FAILED = 3
    LOCK_HELD = 4


def select_exit_code(
    site_statuses: Iterable[Union[SiteStatus, str]],
    *,
    actionable_findings: bool = False,
    run_failed: bool = False,
    lock_held: bool = False,
) -> ExitCode:
    """Pick the run's ``ExitCode``; ``skipped`` sites never count as failures.

    The flags must be real ``bool`` values and every status one of
    ``SITE_STATUSES``, so a string such as ``"false"`` is rejected rather than
    treated as truthy.
    """
    for name, flag in (
        ("actionable_findings", actionable_findings),
        ("run_failed", run_failed),
        ("lock_held", lock_held),
    ):
        if not isinstance(flag, bool):
            raise TypeError(f"{name} must be a bool, got {type(flag).__name__}")
    statuses = [
        item.status if isinstance(item, SiteStatus) else item for item in site_statuses
    ]
    for status in statuses:
        if status not in SITE_STATUSES:
            raise ValueError(
                f"invalid site status {status!r}; expected one of {', '.join(SITE_STATUSES)}"
            )
    failed = sum(1 for status in statuses if status == "failed")
    if lock_held:
        return ExitCode.LOCK_HELD
    if run_failed or (statuses and failed == len(statuses)):
        return ExitCode.FAILED
    if failed:
        return ExitCode.PARTIAL
    if actionable_findings:
        return ExitCode.ACTIONABLE
    return ExitCode.SUCCESS
