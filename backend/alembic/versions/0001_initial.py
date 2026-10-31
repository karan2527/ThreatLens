"""Create the initial ThreatLens schema."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create all core tables and indexes."""
    op.create_table(
        "anonymous_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("session_token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_anonymous_sessions_token_hash",
        "anonymous_sessions",
        ["session_token_hash"],
    )
    op.create_table(
        "indicators",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("type", sa.String(20), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("normalized_value", sa.Text(), nullable=False),
        sa.Column("canonical_hash", sa.String(64), nullable=False),
        sa.Column("hash_algorithm", sa.String(10)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("type", "normalized_value", name="uq_indicator_type_value"),
    )
    op.create_index("ix_indicators_type", "indicators", ["type"])
    op.create_index(
        "ix_indicators_normalized_value", "indicators", ["normalized_value"]
    )
    op.create_index("ix_indicators_canonical_hash", "indicators", ["canonical_hash"])
    op.create_table(
        "scans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("indicator_id", sa.String(36), nullable=False),
        sa.Column("session_id", sa.String(36)),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("verdict", sa.String(20)),
        sa.Column("severity", sa.String(20)),
        sa.Column("risk_score", sa.Integer()),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("current_stage", sa.String(100), nullable=False),
        sa.Column("coverage", sa.JSON(), nullable=False),
        sa.Column("explanation", sa.JSON(), nullable=False),
        sa.Column("cache_hit", sa.Boolean(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["indicator_id"], ["indicators.id"]),
        sa.ForeignKeyConstraint(
            ["session_id"], ["anonymous_sessions.id"], ondelete="SET NULL"
        ),
        sa.CheckConstraint("risk_score IS NULL OR risk_score BETWEEN 0 AND 100"),
        sa.CheckConstraint("progress BETWEEN 0 AND 100"),
    )
    for name, column in (
        ("ix_scans_indicator_id", "indicator_id"),
        ("ix_scans_session_id", "session_id"),
        ("ix_scans_status", "status"),
        ("ix_scans_verdict", "verdict"),
        ("ix_scans_severity", "severity"),
    ):
        op.create_index(name, "scans", [column])
    op.create_index("ix_scans_session_created", "scans", ["session_id", "created_at"])
    op.create_table(
        "provider_results",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), nullable=False),
        sa.Column("provider_name", sa.String(80), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("verdict", sa.String(20)),
        sa.Column("malicious_count", sa.Integer(), nullable=False),
        sa.Column("suspicious_count", sa.Integer(), nullable=False),
        sa.Column("harmless_count", sa.Integer(), nullable=False),
        sa.Column("undetected_count", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.String(20)),
        sa.Column("raw_response", sa.JSON()),
        sa.Column("normalized_data", sa.JSON()),
        sa.Column("error_code", sa.String(80)),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("from_cache", sa.Boolean(), nullable=False),
        sa.Column("cache_age_seconds", sa.Integer()),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("scan_id", "provider_name", name="uq_provider_scan_name"),
    )
    op.create_index("ix_provider_results_scan_id", "provider_results", ["scan_id"])
    op.create_table(
        "reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), nullable=False),
        sa.Column("report_type", sa.String(10), nullable=False),
        sa.Column("storage_path", sa.String(500), nullable=False),
        sa.Column("checksum", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_reports_scan_id", "reports", ["scan_id"])
    op.create_table(
        "scan_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), nullable=False),
        sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_scan_events_scan_id", "scan_events", ["scan_id"])
    op.create_table(
        "provider_usage",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("provider_name", sa.String(80), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.UniqueConstraint(
            "provider_name", "window_start", name="uq_provider_usage_window"
        ),
    )


def downgrade() -> None:
    """Drop the schema in reverse dependency order."""
    for table in (
        "provider_usage",
        "scan_events",
        "reports",
        "provider_results",
        "scans",
        "indicators",
        "anonymous_sessions",
    ):
        op.drop_table(table)
