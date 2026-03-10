"""Initial schema with TimescaleDB hypertables

Revision ID: 001
Revises:
Create Date: 2026-03-10
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE")

    # --- plans ---
    op.create_table(
        "plans",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("name", sa.String(50), unique=True, nullable=False),
        sa.Column("max_domains", sa.Integer, nullable=False),
        sa.Column("max_rps", sa.Integer, nullable=False),
        sa.Column("retention_days", sa.Integer, nullable=False),
        sa.Column("price_cents", sa.Integer, nullable=False, server_default="0"),
        sa.Column("stripe_price_id", sa.String(255), nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
    )

    # --- users (extend existing concept) ---
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("email", sa.String(255), unique=True, index=True, nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("plan_id", sa.Integer, sa.ForeignKey("plans.id"), nullable=True),
        sa.Column("email_verified", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("email_verify_token", sa.String(255), nullable=True),
    )

    # --- domains ---
    op.create_table(
        "domains",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("owner_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False, index=True),
        sa.Column("verify_filename", sa.String(255), nullable=False),
        sa.Column("verify_token", sa.String(255), nullable=False),
        sa.Column("is_verified", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("verified_at", sa.DateTime, nullable=True),
        sa.Column("cf_verified", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("verification_method", sa.String(20), nullable=True),
        sa.Column("setup_step", sa.Integer, nullable=True),
        sa.Column("strip_subdomains", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.UniqueConstraint("owner_id", "name", name="uq_owner_domain"),
    )

    # --- subscriptions ---
    op.create_table(
        "subscriptions",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("plan_id", sa.Integer, sa.ForeignKey("plans.id"), nullable=False),
        sa.Column("stripe_subscription_id", sa.String(255), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("current_period_start", sa.DateTime, nullable=False),
        sa.Column("current_period_end", sa.DateTime, nullable=False),
    )

    # --- api_keys ---
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("domain_id", sa.Integer, sa.ForeignKey("domains.id"), nullable=False),
        sa.Column("key_prefix", sa.String(20), nullable=False),
        sa.Column("key_enc", sa.Text, nullable=False),
        sa.Column("key_sha256", sa.String(64), nullable=False, index=True),
        sa.Column("name", sa.String(100), nullable=False, server_default="default"),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("last_used_at", sa.DateTime, nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("expires_at", sa.DateTime, nullable=True),
        sa.UniqueConstraint("domain_id", "key_sha256", name="uq_domain_key_hash"),
    )

    # --- domain_logs (will become hypertable) ---
    op.create_table(
        "domain_logs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("timestamp", sa.DateTime, nullable=False, index=True),
        sa.Column("domain_id", sa.Integer, nullable=False, index=True),
        sa.Column("source_ip", sa.String(45), nullable=False),
        sa.Column("method", sa.String(10), nullable=False),
        sa.Column("path", sa.String(2048), nullable=False),
        sa.Column("status_code", sa.Integer, nullable=False),
        sa.Column("bytes_sent", sa.Integer, nullable=False, server_default="0"),
        sa.Column("request_time", sa.Float, nullable=False, server_default="0"),
        sa.Column("country", sa.String(2), nullable=True),
        sa.Column("city", sa.String(100), nullable=True),
    )

    # --- detection_events (will become hypertable) ---
    op.create_table(
        "detection_events",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("started_at", sa.DateTime, nullable=False, index=True),
        sa.Column("domain_id", sa.Integer, nullable=False, index=True),
        sa.Column("detected_ip", sa.String(45), nullable=False, index=True),
        sa.Column("threat_score", sa.Float, nullable=False),
        sa.Column("country", sa.String(2), nullable=True),
        sa.Column("city", sa.String(100), nullable=True),
        sa.Column("ptr", sa.String(255), nullable=True),
        sa.Column("request_count", sa.Integer, nullable=False),
        sa.Column("peak_rps", sa.Float, nullable=False),
        sa.Column("request_rate", sa.Float, nullable=False, server_default="0"),
        sa.Column("error_rate", sa.Float, nullable=False, server_default="0"),
        sa.Column("ip_data_preview", JSONB, nullable=True),
        sa.Column("last_feature", JSONB, nullable=True),
        sa.Column("ended_at", sa.DateTime, nullable=True),
        sa.Column("cf_pushed_at", sa.DateTime, nullable=True),
        sa.Column("cf_expires_at", sa.DateTime, nullable=True),
    )

    # --- domain_origin_ips ---
    op.create_table(
        "domain_origin_ips",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("domain_id", sa.Integer, sa.ForeignKey("domains.id"), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("label", sa.String(50), nullable=True),
        sa.Column("verified", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("firewall_whitelisted", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("domain_id", "ip_address", name="uq_domain_origin_ip"),
    )

    # --- cloudflare_integrations ---
    op.create_table(
        "cloudflare_integrations",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("domain_id", sa.Integer, sa.ForeignKey("domains.id"), unique=True, nullable=False),
        sa.Column("cf_api_token_enc", sa.Text, nullable=False),
        sa.Column("cf_zone_id", sa.String(50), nullable=False),
        sa.Column("cf_blocklist_id", sa.String(50), nullable=True),
        sa.Column("cf_whitelist_id", sa.String(50), nullable=True),
        sa.Column("cf_waf_rule_id", sa.String(50), nullable=True),
        sa.Column("sync_interval_sec", sa.Integer, nullable=False, server_default="60"),
        sa.Column("block_duration_sec", sa.Integer, nullable=False, server_default="3600"),
        sa.Column("mitigation_enabled", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # --- whitelisted_ips ---
    op.create_table(
        "whitelisted_ips",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("domain_id", sa.Integer, sa.ForeignKey("domains.id"), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("description", sa.String(255), nullable=True),
        sa.Column("added_by", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("cf_synced", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("domain_id", "ip_address", name="uq_domain_whitelist_ip"),
    )

    # --- firewall_commands ---
    op.create_table(
        "firewall_commands",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("domain_id", sa.Integer, sa.ForeignKey("domains.id"), nullable=False),
        sa.Column("action", sa.String(10), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("description", sa.String(255), nullable=False, server_default=""),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("executed_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # -----------------------------------------------------------------------
    # TimescaleDB: convert to hypertables
    # -----------------------------------------------------------------------
    op.execute(
        "SELECT create_hypertable('domain_logs', by_range('timestamp'), "
        "migrate_data => true, if_not_exists => true)"
    )
    op.execute(
        "SELECT create_hypertable('detection_events', by_range('started_at'), "
        "migrate_data => true, if_not_exists => true)"
    )

    # 24-hour retention for raw nginx logs
    op.execute(
        "SELECT add_retention_policy('domain_logs', INTERVAL '24 hours', if_not_exists => true)"
    )

    # Default 90-day retention for detection events (per-plan enforcement done in app layer)
    op.execute(
        "SELECT add_retention_policy('detection_events', INTERVAL '90 days', if_not_exists => true)"
    )

    # -----------------------------------------------------------------------
    # TimescaleDB: continuous aggregate for dashboard stats
    # -----------------------------------------------------------------------
    op.execute("""
        CREATE MATERIALIZED VIEW IF NOT EXISTS domain_stats
        WITH (timescaledb.continuous) AS
        SELECT
            time_bucket('5 minutes', timestamp)  AS bucket,
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


def downgrade() -> None:
    op.execute("DROP MATERIALIZED VIEW IF EXISTS domain_stats CASCADE")
    op.execute("SELECT remove_retention_policy('detection_events', if_exists => true)")
    op.execute("SELECT remove_retention_policy('domain_logs', if_exists => true)")

    op.drop_table("firewall_commands")
    op.drop_table("whitelisted_ips")
    op.drop_table("cloudflare_integrations")
    op.drop_table("domain_origin_ips")
    op.drop_table("detection_events")
    op.drop_table("domain_logs")
    op.drop_table("api_keys")
    op.drop_table("subscriptions")
    op.drop_table("domains")
    op.drop_table("users")
    op.drop_table("plans")
