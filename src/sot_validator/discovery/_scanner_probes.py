"""Discovery scanner sync runner, child environment and default probes."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import os
import socket
import subprocess
from typing import Any, Optional

from sot_validator.discovery._scanner_common import (
    _PING_RTT_PATTERN,
    parse_ip_neigh_output,
)


def _run_coro_sync(coro: Any) -> Any:
    """Execute a coroutine synchronously, handling existing running event loops safely."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()
    return asyncio.run(coro)


_DEFAULT_CHILD_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def _minimal_child_env() -> dict[str, str]:
    """Allowlisted environment for child processes: ``PATH`` plus ``LANG``/``LC_*`` only."""
    env = {
        key: value
        for key, value in os.environ.items()
        if key in ("PATH", "LANG") or key.startswith("LC_")
    }
    if not env.get("PATH"):
        env["PATH"] = _DEFAULT_CHILD_PATH
    return env


async def _default_async_ping(
    ip: str, timeout_sec: float
) -> tuple[bool, Optional[float]]:
    """Default async ICMP probe via system ``ping`` binary."""
    wait_arg = str(max(1, int(round(timeout_sec))))
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping",
            "-n",
            "-c",
            "1",
            "-W",
            wait_arg,
            ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_minimal_child_env(),
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_sec + 1.0
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return False, None
    except OSError:
        return False, None

    if proc.returncode != 0:
        return False, None

    output = stdout_bytes.decode("utf-8", errors="replace")
    match = _PING_RTT_PATTERN.search(output)
    rtt_ms = float(match.group(1)) if match is not None else None
    return True, rtt_ms


async def _default_async_tcp_probe(ip: str, port: int, timeout_sec: float) -> bool:
    """Default async TCP connect probe using ``asyncio.open_connection``."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout_sec
        )
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return True
    except (OSError, asyncio.TimeoutError):
        return False


def _default_arp_table_reader() -> dict[str, tuple[Optional[str], Optional[str]]]:
    """Default kernel ARP neighbor table reader using ``ip -4 neigh show``."""
    try:
        completed = subprocess.run(
            ["ip", "-4", "neigh", "show"],
            capture_output=True,
            text=True,
            timeout=3.0,
            check=False,
            env=_minimal_child_env(),
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    if completed.returncode != 0:
        return {}
    return parse_ip_neigh_output(completed.stdout)


async def _default_async_rdns(ip: str) -> Optional[str]:
    """Default reverse DNS lookup using ``socket.gethostbyaddr``."""
    try:
        host, _, _ = await asyncio.to_thread(socket.gethostbyaddr, ip)
        return host.strip() if host and host.strip() else None
    except (socket.herror, socket.gaierror, OSError):
        return None

