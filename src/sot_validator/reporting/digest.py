"""Weekly change digest: new, resolved and persisting findings between two runs.

`DigestBuilder` compares a previous and a current `DigestRunInput` across five
categories (stale records, data-quality errors, certificates expiring within
30 days or expired, site health drops, and discovery drift) and returns a
`ChangeDigest`. The renderers produce plain text (capped at 4,000 characters),
Markdown and a self-contained HTML email body. Nothing here reads the clock or
the environment, so identical input always renders identical output.

Findings are read by attribute (duck typing) so this module never imports
`sot_validator.lifecycle`, `sot_validator.quality` or `sot_validator.discovery`
at runtime: `lifecycle.certificates` imports `reporting`, which would cycle.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
import html
from typing import TYPE_CHECKING, Any, Optional

from sot_validator.models import ValidationClassification
from sot_validator.reporting.fleet import TREND_DEGRADING
from sot_validator.reporting.generators import _escape_md_cell

if TYPE_CHECKING:
    from sot_validator.discovery.monitor import ScanDriftEvent
    from sot_validator.lifecycle.certificates import CertificateFinding
    from sot_validator.models import ValidationResult
    from sot_validator.quality.checks import QualityFinding
    from sot_validator.reporting.fleet import SiteScorecard

CATEGORY_STALE_RECORDS = "stale_records"
CATEGORY_QUALITY_ERRORS = "quality_errors"
CATEGORY_CERTIFICATES_30D = "certificates_30d"
CATEGORY_HEALTH_DROPS = "health_drops"
CATEGORY_DRIFT = "drift"
DIGEST_CATEGORIES: tuple[str, ...] = (
    CATEGORY_STALE_RECORDS,
    CATEGORY_QUALITY_ERRORS,
    CATEGORY_CERTIFICATES_30D,
    CATEGORY_HEALTH_DROPS,
    CATEGORY_DRIFT,
)
CATEGORY_TITLES: dict[str, str] = {
    CATEGORY_STALE_RECORDS: "Stale records",
    CATEGORY_QUALITY_ERRORS: "Data-quality errors",
    CATEGORY_CERTIFICATES_30D: "Certificates expired or expiring within 30 days",
    CATEGORY_HEALTH_DROPS: "Site health drops",
    CATEGORY_DRIFT: "Discovery drift",
}

POLICY_ON_CHANGE = "on_change"
POLICY_ALWAYS = "always"
SEND_POLICIES: tuple[str, ...] = (POLICY_ON_CHANGE, POLICY_ALWAYS)

DEFAULT_TOP_N = 10
DEFAULT_MAX_CHARS = 4000
MAX_ITEM_LINE_CHARS = 200

DIGEST_TITLE = "SoT weekly change digest"
NO_CHANGES_MESSAGE = "SoT weekly digest: no changes since the previous run."
NO_DATA = "no data"

# Equal sot_validator.lifecycle.certificates.ISSUE_EXPIRED and expiring_issue(30)
# (not imported: import cycle).
_CERT_EXPIRED = "expired"
_CERT_EXPIRING_30D = "expiring_30d"
_CERT_FLAG_ORDER: dict[str, int] = {_CERT_EXPIRED: 0, _CERT_EXPIRING_30D: 1}

# Equals sot_validator.discovery.monitor.SEVERITY_LEVELS (not imported: import cycle).
_DRIFT_SEVERITY_ORDER: dict[str, int] = {"critical": 0, "warning": 1, "info": 2}

_STALE = ValidationClassification.STALE_LIKELY_UNUSED.value


@dataclass
class DigestRunInput:
    """Findings from one run; `None` means the category has no data for this run."""

    results: Optional[Sequence[ValidationResult]] = None
    quality_findings: Optional[Sequence[QualityFinding]] = None
    certificate_findings: Optional[Sequence[CertificateFinding]] = None
    scorecards: Optional[Sequence[SiteScorecard]] = None
    drift_events: Optional[Sequence[ScanDriftEvent]] = None


@dataclass
class DigestItem:
    """One new finding shown in the digest."""

    key: str
    site_id: str
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key, "site_id": self.site_id, "summary": self.summary}


@dataclass
class DigestCategoryResult:
    """New/resolved/persisting counts and the top new items for one category."""

    category: str
    title: str
    has_data: bool
    new: Optional[int] = None
    resolved: Optional[int] = None
    persisting: Optional[int] = None
    top_new: list[DigestItem] = field(default_factory=list)

    @property
    def more_new(self) -> int:
        """New items not listed in `top_new`."""
        if not self.has_data or self.new is None:
            return 0
        return self.new - len(self.top_new)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "title": self.title,
            "has_data": self.has_data,
            "new": self.new,
            "resolved": self.resolved,
            "persisting": self.persisting,
            "top_new": [item.to_dict() for item in self.top_new],
        }


@dataclass
class ChangeDigest:
    """Per-category changes between two runs, in `DIGEST_CATEGORIES` order."""

    categories: list[DigestCategoryResult]
    top_n: int = DEFAULT_TOP_N

    @property
    def is_empty(self) -> bool:
        """True when no category with data has new items (resolved-only is empty)."""
        return not any(c.has_data and (c.new or 0) > 0 for c in self.categories)

    def category(self, category_id: str) -> DigestCategoryResult:
        for result in self.categories:
            if result.category == category_id:
                return result
        raise KeyError(category_id)

    def should_send(self, policy: str = POLICY_ON_CHANGE) -> bool:
        if not isinstance(policy, str) or policy not in SEND_POLICIES:
            raise ValueError(f"policy must be one of {SEND_POLICIES}, got {policy!r}")
        if policy == POLICY_ALWAYS:
            return True
        return not self.is_empty

    def to_dict(self) -> dict[str, Any]:
        return {
            "top_n": self.top_n,
            "is_empty": self.is_empty,
            "categories": [c.to_dict() for c in self.categories],
        }


# ---------------------------------------------------------------------------
# Finding extraction
# ---------------------------------------------------------------------------

# Each extractor yields (key, sort_key, item) for one finding of its category.
_Entry = tuple[Any, tuple[Any, ...], DigestItem]


def _text(value: Any) -> str:
    """Collapse a value to one line of text."""
    if value is None:
        return ""
    return " ".join(
        "".join(ch if ch.isprintable() else " " for ch in str(value)).split()
    )


def _key_str(key: Any) -> str:
    if isinstance(key, tuple):
        return "/".join(_text(part) for part in key)
    return _text(key)


def _stale_entries(results: Iterable[Any]) -> Iterable[_Entry]:
    for result in results:
        classification = getattr(result, "classification", None)
        if getattr(classification, "value", classification) != _STALE:
            continue
        site = _text(getattr(result, "site_id", None))
        item_type = _text(getattr(result, "item_type", None))
        item_id = _text(getattr(result, "item_id", None))
        key = (site, item_type, item_id)
        name = _text(getattr(result, "name", None))
        summary = f"{site} {item_type} {item_id} ({name})"
        yield key, (site, _key_str(key)), DigestItem(_key_str(key), site, summary)


def _quality_entries(findings: Iterable[Any]) -> Iterable[_Entry]:
    for finding in findings:
        if getattr(finding, "severity", None) != "error":
            continue
        site = _text(getattr(finding, "site_id", None))
        key = _text(getattr(finding, "finding_id", None))
        rule = _text(getattr(finding, "rule", None))
        message = _text(getattr(finding, "message", None))
        summary = f"{site} {rule}: {message}"
        yield key, (site, key), DigestItem(key, site, summary)


def _certificate_entries(findings: Iterable[Any]) -> Iterable[_Entry]:
    for finding in findings:
        site = _text(getattr(finding, "site_id", None))
        ip = _text(getattr(finding, "ip", None))
        port = _text(getattr(finding, "port", None))
        cn = _text(getattr(finding, "subject_cn", None)) or "-"
        days = getattr(finding, "days_remaining", None)
        if isinstance(days, bool) or not isinstance(days, int):
            days = None
        for flag in sorted(set(getattr(finding, "issues", None) or ())):
            if flag not in _CERT_FLAG_ORDER:
                continue
            key = (site, ip, port, flag)
            if flag == _CERT_EXPIRED:
                tail = "expired"
            elif days is None:
                tail = "expires within 30 days"
            else:
                tail = f"expires in {days} days"
            summary = f"{site} {ip}:{port} {cn} {tail}"
            sort_key = (
                _CERT_FLAG_ORDER[flag],
                days is None,
                days if days is not None else 0,
                _key_str(key),
            )
            yield key, sort_key, DigestItem(_key_str(key), site, summary)


def _score(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _health_entries(scorecards: Iterable[Any]) -> Iterable[_Entry]:
    for card in scorecards:
        if getattr(card, "trend", None) != TREND_DEGRADING:
            continue
        site = _text(getattr(card, "site_id", None))
        previous = _score(getattr(card, "previous_score", None))
        current = _score(getattr(card, "health_score", None))
        prev_text = f"{previous:.1f}" if previous is not None else "-"
        cur_text = f"{current:.1f}" if current is not None else "-"
        summary = f"{site} {prev_text} -> {cur_text}"
        if previous is not None and current is not None:
            sort_key: tuple[Any, ...] = (0, -(previous - current), site)
        else:
            sort_key = (1, 0.0, site)
        yield site, sort_key, DigestItem(site, site, summary)


def _drift_entries(events: Iterable[Any]) -> Iterable[_Entry]:
    for event in events:
        site = _text(getattr(event, "site_id", None))
        key = _text(getattr(event, "event_id", None))
        severity = _text(getattr(event, "severity", None))
        text = _text(getattr(event, "summary", None))
        summary = f"{site} [{severity}] {text}"
        rank = _DRIFT_SEVERITY_ORDER.get(severity, len(_DRIFT_SEVERITY_ORDER))
        yield key, (rank, key), DigestItem(key, site, summary)


_CATEGORY_SOURCES: dict[str, tuple[str, Callable[[Iterable[Any]], Iterable[_Entry]]]] = {
    CATEGORY_STALE_RECORDS: ("results", _stale_entries),
    CATEGORY_QUALITY_ERRORS: ("quality_findings", _quality_entries),
    CATEGORY_CERTIFICATES_30D: ("certificate_findings", _certificate_entries),
    CATEGORY_HEALTH_DROPS: ("scorecards", _health_entries),
    CATEGORY_DRIFT: ("drift_events", _drift_entries),
}


def _collect(
    findings: Iterable[Any], extractor: Callable[[Iterable[Any]], Iterable[_Entry]]
) -> dict[Any, tuple[tuple[Any, ...], DigestItem]]:
    """Map each key to its entry; duplicates keep the lowest (sort_key, summary)."""
    collected: dict[Any, tuple[tuple[Any, ...], DigestItem]] = {}
    for key, sort_key, item in extractor(findings):
        existing = collected.get(key)
        if existing is None or (sort_key, item.summary) < (
            existing[0],
            existing[1].summary,
        ):
            collected[key] = (sort_key, item)
    return collected


class DigestBuilder:
    """Compare two runs and build a `ChangeDigest`."""

    def __init__(
        self,
        previous: DigestRunInput,
        current: DigestRunInput,
        *,
        top_n: int = DEFAULT_TOP_N,
    ) -> None:
        if not isinstance(previous, DigestRunInput):
            raise ValueError("previous must be a DigestRunInput")
        if not isinstance(current, DigestRunInput):
            raise ValueError("current must be a DigestRunInput")
        if isinstance(top_n, bool) or not isinstance(top_n, int) or top_n < 1:
            raise ValueError(f"top_n must be an integer >= 1, got {top_n!r}")
        self.previous = previous
        self.current = current
        self.top_n = top_n

    def build(self) -> ChangeDigest:
        return ChangeDigest(
            categories=[self._category(cid) for cid in DIGEST_CATEGORIES],
            top_n=self.top_n,
        )

    def _category(self, category_id: str) -> DigestCategoryResult:
        attr, extractor = _CATEGORY_SOURCES[category_id]
        title = CATEGORY_TITLES[category_id]
        prev_findings = getattr(self.previous, attr)
        cur_findings = getattr(self.current, attr)
        if prev_findings is None or cur_findings is None:
            return DigestCategoryResult(category=category_id, title=title, has_data=False)
        prev = _collect(prev_findings, extractor)
        cur = _collect(cur_findings, extractor)
        new_keys = cur.keys() - prev.keys()
        ranked = sorted(
            (cur[key] for key in new_keys), key=lambda entry: (entry[0], entry[1].summary)
        )
        return DigestCategoryResult(
            category=category_id,
            title=title,
            has_data=True,
            new=len(new_keys),
            resolved=len(prev.keys() - cur.keys()),
            persisting=len(cur.keys() & prev.keys()),
            top_new=[item for _, item in ranked[: self.top_n]],
        )


# ---------------------------------------------------------------------------
# Text
# ---------------------------------------------------------------------------


def _require_digest(digest: Any) -> ChangeDigest:
    if not isinstance(digest, ChangeDigest):
        raise ValueError("digest must be a ChangeDigest")
    return digest


def _counts_text(result: DigestCategoryResult) -> str:
    if not result.has_data:
        return f"{result.title}: {NO_DATA}"
    return (
        f"{result.title}: {result.new} new / {result.resolved} resolved"
        f" / {result.persisting} persisting"
    )


def _clip(line: str, limit: int = MAX_ITEM_LINE_CHARS) -> str:
    return line if len(line) <= limit else line[: limit - 1] + "…"


def _truncation_notice(omitted: int, max_chars: int) -> str:
    return f"… {omitted} more item(s) omitted (truncated to {max_chars} characters)"


def render_digest_text(digest: ChangeDigest, *, max_chars: int = DEFAULT_MAX_CHARS) -> str:
    """Plain-text digest that never exceeds `max_chars` characters."""
    _require_digest(digest)
    if isinstance(max_chars, bool) or not isinstance(max_chars, int) or max_chars < 1:
        raise ValueError(f"max_chars must be an integer >= 1, got {max_chars!r}")
    if digest.is_empty:
        if len(NO_CHANGES_MESSAGE) > max_chars:
            raise ValueError(f"max_chars {max_chars} is too small for the digest")
        return NO_CHANGES_MESSAGE

    fixed = [DIGEST_TITLE, *(_counts_text(c) for c in digest.categories)]
    # (line, is_item) pairs; only item lines count towards the truncation notice.
    body: list[tuple[str, bool]] = []
    for result in digest.categories:
        if not result.top_new:
            continue
        body.append(("", False))
        body.append((_clip(f"New {result.title.lower()}:"), False))
        body.extend((_clip(f"  - {item.summary}"), True) for item in result.top_new)
        if result.more_new > 0:
            body.append((f"  … and {result.more_new} more", False))

    full = "\n".join(fixed + [line for line, _ in body])
    if len(full) <= max_chars:
        return full

    total_items = sum(1 for _, is_item in body if is_item)
    reserve = len(_truncation_notice(total_items, max_chars)) + 2
    kept: list[tuple[str, bool]] = []
    length = len("\n".join(fixed))
    for line, is_item in body:
        if length + 1 + len(line) + reserve > max_chars:
            break
        kept.append((line, is_item))
        length += 1 + len(line)
    # Do not leave a section heading (or blank separator) without any items.
    while kept and not kept[-1][1]:
        kept.pop()
    omitted = total_items - sum(1 for _, is_item in kept if is_item)
    lines = fixed + [line for line, _ in kept] + ["", _truncation_notice(omitted, max_chars)]
    text = "\n".join(lines)
    if len(text) > max_chars:
        raise ValueError(f"max_chars {max_chars} is too small for the digest")
    return text


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def _count_cell(value: Optional[int], has_data: bool) -> str:
    return str(value) if has_data and value is not None else NO_DATA


def render_digest_markdown(digest: ChangeDigest) -> str:
    """Markdown digest: a counts table, then one table of new items per category."""
    _require_digest(digest)
    if digest.is_empty:
        return NO_CHANGES_MESSAGE

    lines = [
        f"# {DIGEST_TITLE}",
        "",
        "| Category | New | Resolved | Persisting |",
        "| --- | ---: | ---: | ---: |",
    ]
    for result in digest.categories:
        cells = (
            _escape_md_cell(result.title),
            _escape_md_cell(_count_cell(result.new, result.has_data)),
            _escape_md_cell(_count_cell(result.resolved, result.has_data)),
            _escape_md_cell(_count_cell(result.persisting, result.has_data)),
        )
        lines.append("| " + " | ".join(cells) + " |")

    for result in digest.categories:
        if not result.top_new:
            continue
        lines.extend(
            [
                "",
                f"## New {_escape_md_cell(result.title.lower())}",
                "",
                "| Site | Item |",
                "| --- | --- |",
            ]
        )
        for item in result.top_new:
            lines.append(
                f"| {_escape_md_cell(item.site_id)} | {_escape_md_cell(item.summary)} |"
            )
        if result.more_new > 0:
            lines.extend(["", f"_… and {result.more_new} more_"])
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------


def _esc(value: Any) -> str:
    """Escape any value for safe inclusion in HTML text or quoted attributes."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


_DIGEST_STYLE = """
    body { font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
      color: #0f172a; background: #ffffff; margin: 16px; font-size: 15px; }
    h1 { font-size: 20px; margin: 0 0 12px; }
    h2 { font-size: 16px; margin: 20px 0 8px; }
    .table-wrap { overflow-x: auto; }
    table { border-collapse: collapse; min-width: 320px; }
    th, td { border: 1px solid #cbd5e1; padding: 6px 10px; text-align: left;
      vertical-align: top; }
    th { background: #f1f5f9; }
    td.num { text-align: right; font-variant-numeric: tabular-nums; }
    td.nodata { color: #475569; font-style: italic; }
    p.more { color: #334155; margin: 6px 0 0; }
"""


def _html_document(body: str) -> str:
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_esc(DIGEST_TITLE)}</title>\n"
        f"<style>{_DIGEST_STYLE}</style>\n"
        f"</head>\n<body>\n{body}\n</body>\n</html>\n"
    )


def _count_td(value: Optional[int], has_data: bool) -> str:
    if not has_data or value is None:
        return f'<td class="nodata">{_esc(NO_DATA)}</td>'
    return f'<td class="num">{_esc(value)}</td>'


def render_digest_html(digest: ChangeDigest) -> str:
    """Self-contained HTML email body (inline style only, every value escaped)."""
    _require_digest(digest)
    if digest.is_empty:
        return _html_document(f"<p>{_esc(NO_CHANGES_MESSAGE)}</p>")

    parts = [
        f"<h1>{_esc(DIGEST_TITLE)}</h1>",
        '<div class="table-wrap"><table>',
        "<thead><tr><th>Category</th><th>New</th><th>Resolved</th>"
        "<th>Persisting</th></tr></thead>",
        "<tbody>",
    ]
    for result in digest.categories:
        parts.append(
            f"<tr><td>{_esc(result.title)}</td>"
            f"{_count_td(result.new, result.has_data)}"
            f"{_count_td(result.resolved, result.has_data)}"
            f"{_count_td(result.persisting, result.has_data)}</tr>"
        )
    parts.append("</tbody></table></div>")

    for result in digest.categories:
        if not result.top_new:
            continue
        parts.append(f"<h2>New {_esc(result.title.lower())}</h2>")
        parts.append('<div class="table-wrap"><table>')
        parts.append("<thead><tr><th>Site</th><th>Item</th></tr></thead><tbody>")
        for item in result.top_new:
            parts.append(
                f"<tr><td>{_esc(item.site_id)}</td><td>{_esc(item.summary)}</td></tr>"
            )
        parts.append("</tbody></table></div>")
        if result.more_new > 0:
            parts.append(f'<p class="more">… and {_esc(result.more_new)} more</p>')
    return _html_document("\n".join(parts))


__all__ = [
    "CATEGORY_CERTIFICATES_30D",
    "CATEGORY_DRIFT",
    "CATEGORY_HEALTH_DROPS",
    "CATEGORY_QUALITY_ERRORS",
    "CATEGORY_STALE_RECORDS",
    "CATEGORY_TITLES",
    "ChangeDigest",
    "DIGEST_CATEGORIES",
    "DigestBuilder",
    "DigestCategoryResult",
    "DigestItem",
    "DigestRunInput",
    "POLICY_ALWAYS",
    "POLICY_ON_CHANGE",
    "SEND_POLICIES",
    "render_digest_html",
    "render_digest_markdown",
    "render_digest_text",
]
