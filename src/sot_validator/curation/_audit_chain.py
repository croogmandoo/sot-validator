"""Audit log hash chaining, anchor validation, and chain verification."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
import hashlib
import json
from typing import TYPE_CHECKING, Any, Optional

from sot_validator.curation._records import AuditLogEntry, GENESIS_HASH, _HASH_PATTERN

if TYPE_CHECKING:
    from sot_validator.curation.store import CurationStore


def _compute_entry_hash(entry: AuditLogEntry) -> str:
    """Return SHA-256 of `prev_hash` followed by the canonical JSON of `entry` without `entry_hash`."""
    if entry.prev_hash is None:
        raise ValueError("prev_hash must be set to compute entry_hash")
    payload = entry.to_dict()
    del payload["entry_hash"]
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(entry.prev_hash.encode("ascii") + canonical).hexdigest()


def _chain_entries(
    entries: Sequence[AuditLogEntry], prev_hash: str = GENESIS_HASH
) -> list[AuditLogEntry]:
    """Return copies of `entries` hash-chained in order, starting from `prev_hash`."""
    chained: list[AuditLogEntry] = []
    for entry in entries:
        linked = replace(entry, prev_hash=prev_hash, entry_hash=None)
        linked = replace(linked, entry_hash=_compute_entry_hash(linked))
        chained.append(linked)
        prev_hash = linked.entry_hash
    return chained


@dataclass(frozen=True)
class AuditChainReport:
    """Result of walking the curation audit log hash chain."""

    ok: bool
    entries_checked: int
    broken_index: Optional[int] = None
    reason: Optional[str] = None


def _validate_anchor(anchor: Any) -> tuple[int, str]:
    if not isinstance(anchor, (tuple, list)) or len(anchor) != 2:
        raise ValueError("anchor must be an (entry_count, head_hash) tuple")
    count, head_hash = anchor
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError("anchor entry_count must be a non-negative integer")
    if not isinstance(head_hash, str) or _HASH_PATTERN.fullmatch(head_hash) is None:
        raise ValueError("anchor head_hash must be 64 lowercase hex characters")
    if count == 0 and head_hash != GENESIS_HASH:
        raise ValueError("anchor with entry_count 0 must use GENESIS_HASH")
    return count, head_hash


def verify_audit_chain(
    store: CurationStore, anchor: Optional[tuple[int, str]] = None
) -> AuditChainReport:
    """Walk the audit log in `seq` order and report the first hash-chain break or anchor mismatch."""
    from sot_validator.curation.store import CurationStore

    if not isinstance(store, CurationStore):
        raise ValueError("store must be a CurationStore instance")
    anchor_pair = _validate_anchor(anchor) if anchor is not None else None

    rows = store._conn.execute("SELECT * FROM audit_log ORDER BY seq ASC").fetchall()
    entries = [store._row_to_audit_entry(r) for r in rows]
    known_hashes = {e.entry_hash for e in entries if e.entry_hash is not None}

    expected_prev = GENESIS_HASH
    for idx, entry in enumerate(entries):
        if entry.entry_hash is None or _compute_entry_hash(entry) != entry.entry_hash:
            return AuditChainReport(
                ok=False, entries_checked=idx, broken_index=idx, reason="hash_mismatch"
            )
        if entry.prev_hash != expected_prev:
            reason = (
                "prev_link_broken"
                if entry.prev_hash == GENESIS_HASH or entry.prev_hash in known_hashes
                else "gap"
            )
            return AuditChainReport(
                ok=False, entries_checked=idx, broken_index=idx, reason=reason
            )
        expected_prev = entry.entry_hash

    if anchor_pair is not None:
        count, head_hash = anchor_pair
        if count > 0 and (
            len(entries) < count or entries[count - 1].entry_hash != head_hash
        ):
            return AuditChainReport(
                ok=False,
                entries_checked=len(entries),
                broken_index=count - 1,
                reason="anchor_mismatch",
            )

    return AuditChainReport(ok=True, entries_checked=len(entries))
