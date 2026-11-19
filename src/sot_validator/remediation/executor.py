"""Phase 2 approval-gated SoT remediation executor, reversible SQL generator, and rollback journal.

Remediation write paths are deliberately outside ``ReadOnlyHttpGuard`` and the read-only
extraction rules; they stay gated by SHA-256 manifest verification, ``confirm_write`` and
the append-only rollback journal instead.
"""

from __future__ import annotations

from sot_validator.remediation._executor_common import (
    ManifestVerificationError,
    RemediationExecutionError,
    _TABLE_ORDER,
    _TABLE_SQL_COLUMNS,
    _UnknownExecutionIdError,
    _format_sql_datetime,
    _resolve_target_table,
    _sql_literal,
)
from sot_validator.remediation._executor_engine import (
    RemediationExecutionResult,
    RemediationExecutor,
    _apply_remediation_to_site,
    _restore_site_from_journal_entry,
)
from sot_validator.remediation._executor_journal import (
    RollbackJournal,
    RollbackJournalEntry,
    RollbackPlan,
    _build_rollback_transaction_sql,
)
from sot_validator.remediation._executor_snapshot import (
    _normalize_sites_lookup,
    _query_sqlite_snapshot,
    _resolve_fallback_snapshot,
    _resolve_site_snapshot,
    _table_has_column,
    _validate_and_filter_manifest_entries,
)
from sot_validator.remediation._executor_sql import (
    SqlRemediationScriptGenerator,
    SqlRemediationScripts,
    _build_remediate_and_rollback_row_sql,
)


__all__ = [
    "ManifestVerificationError",
    "RemediationExecutionError",
    "RemediationExecutionResult",
    "RemediationExecutor",
    "RollbackJournal",
    "RollbackJournalEntry",
    "RollbackPlan",
    "SqlRemediationScriptGenerator",
    "SqlRemediationScripts",
]
