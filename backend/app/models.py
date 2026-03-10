from datetime import datetime

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Integer, String, Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    plan_id: Mapped[int | None] = mapped_column(ForeignKey("plans.id"), nullable=True)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    email_verify_token: Mapped[str | None] = mapped_column(String(255), nullable=True)

    domains: Mapped[list["Domain"]] = relationship(back_populates="owner")
    plan: Mapped["Plan | None"] = relationship()
    subscriptions: Mapped[list["Subscription"]] = relationship(back_populates="user")


# ---------------------------------------------------------------------------
# Domain
# ---------------------------------------------------------------------------

class Domain(Base):
    __tablename__ = "domains"
    __table_args__ = (
        UniqueConstraint("owner_id", "name", name="uq_owner_domain"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    verify_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    verify_token: Mapped[str] = mapped_column(String(255), nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    cf_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    verification_method: Mapped[str | None] = mapped_column(String(20), nullable=True)
    setup_step: Mapped[int | None] = mapped_column(Integer, nullable=True)
    strip_subdomains: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    owner: Mapped["User"] = relationship(back_populates="domains")
    origin_ips: Mapped[list["DomainOriginIP"]] = relationship(back_populates="domain", cascade="all, delete-orphan")
    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="domain", cascade="all, delete-orphan")
    cf_integration: Mapped["CloudflareIntegration | None"] = relationship(back_populates="domain", uselist=False, cascade="all, delete-orphan")


# ---------------------------------------------------------------------------
# Plan & Subscription
# ---------------------------------------------------------------------------

class Plan(Base):
    __tablename__ = "plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    max_domains: Mapped[int] = mapped_column(Integer, nullable=False)
    max_rps: Mapped[int] = mapped_column(Integer, nullable=False)
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False)
    price_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    stripe_price_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    plan_id: Mapped[int] = mapped_column(ForeignKey("plans.id"), nullable=False)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    current_period_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    current_period_end: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    user: Mapped["User"] = relationship(back_populates="subscriptions")
    plan: Mapped["Plan"] = relationship()


# ---------------------------------------------------------------------------
# API Key (syslog tag authentication)
# ---------------------------------------------------------------------------

class ApiKey(Base):
    __tablename__ = "api_keys"
    __table_args__ = (
        UniqueConstraint("domain_id", "key_sha256", name="uq_domain_key_hash"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(20), nullable=False)
    key_enc: Mapped[str] = mapped_column(Text, nullable=False)
    key_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False, default="default")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    user: Mapped["User"] = relationship()
    domain: Mapped["Domain"] = relationship(back_populates="api_keys")


# ---------------------------------------------------------------------------
# Domain Logs (TimescaleDB hypertable -- 24h retention)
# ---------------------------------------------------------------------------

class DomainLog(Base):
    __tablename__ = "domain_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    domain_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    bytes_sent: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    request_time: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    city: Mapped[str | None] = mapped_column(String(100), nullable=True)


# ---------------------------------------------------------------------------
# Detection Events (TimescaleDB hypertable -- retention per plan)
# ---------------------------------------------------------------------------

class DetectionEvent(Base):
    __tablename__ = "detection_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    domain_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    detected_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    threat_score: Mapped[float] = mapped_column(Float, nullable=False)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    city: Mapped[str | None] = mapped_column(String(100), nullable=True)
    ptr: Mapped[str | None] = mapped_column(String(255), nullable=True)
    request_count: Mapped[int] = mapped_column(Integer, nullable=False)
    peak_rps: Mapped[float] = mapped_column(Float, nullable=False)
    request_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    error_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    ip_data_preview: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    last_feature: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    cf_pushed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    cf_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


# ---------------------------------------------------------------------------
# Domain Origin IPs (multi-node support)
# ---------------------------------------------------------------------------

class DomainOriginIP(Base):
    __tablename__ = "domain_origin_ips"
    __table_args__ = (
        UniqueConstraint("domain_id", "ip_address", name="uq_domain_origin_ip"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    label: Mapped[str | None] = mapped_column(String(50), nullable=True)
    verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    firewall_whitelisted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    domain: Mapped["Domain"] = relationship(back_populates="origin_ips")


# ---------------------------------------------------------------------------
# Cloudflare Integration (per-domain)
# ---------------------------------------------------------------------------

class CloudflareIntegration(Base):
    __tablename__ = "cloudflare_integrations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"), unique=True, nullable=False)
    cf_api_token_enc: Mapped[str] = mapped_column(Text, nullable=False)
    cf_zone_id: Mapped[str] = mapped_column(String(50), nullable=False)
    cf_blocklist_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    cf_whitelist_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    cf_waf_rule_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    sync_interval_sec: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    block_duration_sec: Mapped[int] = mapped_column(Integer, default=3600, nullable=False)
    mitigation_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    user: Mapped["User"] = relationship()
    domain: Mapped["Domain"] = relationship(back_populates="cf_integration")


# ---------------------------------------------------------------------------
# Whitelisted IPs (user-managed, synced to CF whitelist)
# ---------------------------------------------------------------------------

class WhitelistedIP(Base):
    __tablename__ = "whitelisted_ips"
    __table_args__ = (
        UniqueConstraint("domain_id", "ip_address", name="uq_domain_whitelist_ip"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    added_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    cf_synced: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)


# ---------------------------------------------------------------------------
# Firewall Commands (CSF commands for ingestor server)
# ---------------------------------------------------------------------------

class FirewallCommand(Base):
    __tablename__ = "firewall_commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id"), nullable=False)
    action: Mapped[str] = mapped_column(String(10), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
