"""Workbench payload helpers and the shared not-found error."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any, Optional

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(value: str, prefix: str = "dev") -> str:
    slug = _SLUG_RE.sub("-", value.strip().lower()).strip("-")
    if not slug:
        slug = "item"
    return f"{prefix}-{slug}" if not slug.startswith(f"{prefix}-") else slug


def _optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        return str(value).strip() or None
    stripped = value.strip()
    return stripped if stripped else None


def _bulk_csv_fields(body: Mapping[str, Any]) -> tuple[str, Optional[str]]:
    csv_text = body.get("csv")
    if not isinstance(csv_text, str):
        raise ValueError("csv must be a string")
    as_of = body.get("as_of")
    if as_of is not None and not isinstance(as_of, str):
        raise ValueError("as_of must be an ISO-8601 string")
    return csv_text, _optional_str(as_of)


class WorkbenchNotFoundError(KeyError):
    """Raised when a requested workbench resource (such as a device) does not exist."""
