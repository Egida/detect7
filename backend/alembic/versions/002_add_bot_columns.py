"""Add bot columns to domain_logs and refresh domain_stats

Revision ID: 002
Revises: 001
Create Date: 2026-03-10
"""
from alembic import op
import sqlalchemy as sa

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("domain_logs", sa.Column("is_known_bot", sa.Boolean, server_default=sa.text("false"), nullable=False))
    op.add_column("domain_logs", sa.Column("bot_name", sa.String(50), nullable=True))

    # Recreate continuous aggregate with bot_requests column
    op.execute("SELECT remove_continuous_aggregate_policy('domain_stats', if_exists => true)")
    op.execute("DROP MATERIALIZED VIEW IF EXISTS domain_stats CASCADE")
    op.execute("""
        CREATE MATERIALIZED VIEW domain_stats
        WITH (timescaledb.continuous) AS
        SELECT
            time_bucket('5 minutes', timestamp) AS bucket,
            domain_id,
            COUNT(*)                              AS total_requests,
            COUNT(*) FILTER (WHERE is_known_bot)  AS bot_requests,
            SUM(bytes_sent)                       AS total_bytes,
            AVG(request_time)                     AS avg_request_time,
            COUNT(DISTINCT source_ip)             AS unique_ips,
            COUNT(*) FILTER (WHERE status_code >= 400) AS error_count
        FROM domain_logs
        GROUP BY bucket, domain_id
        WITH NO DATA
    """)
    op.execute("""
        SELECT add_continuous_aggregate_policy('domain_stats',
            start_offset    => INTERVAL '1 hour',
            end_offset      => INTERVAL '5 minutes',
            schedule_interval => INTERVAL '5 minutes',
            if_not_exists   => true
        )
    """)


def downgrade() -> None:
    op.execute("SELECT remove_continuous_aggregate_policy('domain_stats', if_exists => true)")
    op.execute("DROP MATERIALIZED VIEW IF EXISTS domain_stats CASCADE")
    op.execute("""
        CREATE MATERIALIZED VIEW domain_stats
        WITH (timescaledb.continuous) AS
        SELECT
            time_bucket('5 minutes', timestamp) AS bucket,
            domain_id,
            COUNT(*)                              AS total_requests,
            SUM(bytes_sent)                       AS total_bytes,
            AVG(request_time)                     AS avg_request_time,
            COUNT(DISTINCT source_ip)             AS unique_ips,
            COUNT(*) FILTER (WHERE status_code >= 400) AS error_count
        FROM domain_logs
        GROUP BY bucket, domain_id
        WITH NO DATA
    """)
    op.execute("""
        SELECT add_continuous_aggregate_policy('domain_stats',
            start_offset    => INTERVAL '1 hour',
            end_offset      => INTERVAL '5 minutes',
            schedule_interval => INTERVAL '5 minutes',
            if_not_exists   => true
        )
    """)
    op.drop_column("domain_logs", "bot_name")
    op.drop_column("domain_logs", "is_known_bot")
