from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    created_at: datetime
    plan_id: int | None = None
    email_verified: bool = False


# ---------------------------------------------------------------------------
# Plans
# ---------------------------------------------------------------------------

class PlanPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    max_domains: int
    max_rps: int
    retention_days: int
    price_cents: int


# ---------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------

class DomainCreate(BaseModel):
    name: str = Field(min_length=3, max_length=253)


class DomainPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    verify_filename: str
    verify_token: str
    is_verified: bool
    created_at: datetime
    verified_at: datetime | None
    cf_verified: bool = False
    setup_step: int | None = None
    strip_subdomains: bool = False


class VerifyResponse(BaseModel):
    success: bool
    message: str


class ForwardingInstructions(BaseModel):
    nginx_log_format: str
    nginx_access_log_line: str
    notes: list[str]


# ---------------------------------------------------------------------------
# API Keys
# ---------------------------------------------------------------------------

class ApiKeyCreate(BaseModel):
    name: str = Field(default="default", max_length=100)


class ApiKeyPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    domain_id: int
    key_prefix: str
    name: str
    created_at: datetime
    last_used_at: datetime | None
    is_active: bool
    expires_at: datetime | None


class ApiKeyCreated(ApiKeyPublic):
    """Returned only on creation -- includes full plaintext key."""
    plaintext_key: str


# ---------------------------------------------------------------------------
# Origin IPs
# ---------------------------------------------------------------------------

class OriginIPCreate(BaseModel):
    ip_address: str = Field(max_length=45)
    label: str | None = None


class OriginIPPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    domain_id: int
    ip_address: str
    label: str | None
    verified: bool
    firewall_whitelisted: bool
    created_at: datetime


# ---------------------------------------------------------------------------
# Whitelisted IPs
# ---------------------------------------------------------------------------

class WhitelistedIPCreate(BaseModel):
    ip_address: str = Field(max_length=45)
    description: str | None = None


class WhitelistedIPPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    domain_id: int
    ip_address: str
    description: str | None
    cf_synced: bool
    created_at: datetime


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class TimeseriesPoint(BaseModel):
    t: str
    requests: int
    problems: int


class NamedCount(BaseModel):
    name: str
    count: int


class RecentDetection(BaseModel):
    detected_ip: str
    threat_score: float
    country: str | None
    request_count: int
    peak_rps: float
    started_at: str


class DashboardSummary(BaseModel):
    total_requests_5m: int
    suspicious_events_5m: int
    max_rps_5m: float
    current_rps: float
    blocked_ips: int
    top_countries: list[NamedCount]
    top_problem_paths: list[NamedCount]
    timeline: list[TimeseriesPoint]
    recent_detections: list[RecentDetection]
