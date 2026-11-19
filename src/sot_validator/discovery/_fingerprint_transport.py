"""Default read-only SSH/HTTP/TLS banner network transports."""

from __future__ import annotations

import asyncio
import html
import ssl
from typing import Optional

from sot_validator.discovery._fingerprint_common import (
    _HTML_TITLE_RE,
    _HTTP_BODY_LIMIT,
    _HTTP_HEADER_LIMIT,
    _SSH_READ_LIMIT,
)
from sot_validator.discovery._fingerprint_der import parse_tls_certificate
from sot_validator.discovery._fingerprint_models import TlsCertificate


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
