from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field


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


class VerifyResponse(BaseModel):
    success: bool
    message: str


class ForwardingInstructions(BaseModel):
    nginx_log_format: str
    nginx_access_log_line: str
    notes: list[str]


class TimeseriesPoint(BaseModel):
    t: str
    requests: int
    problems: int


class NamedCount(BaseModel):
    name: str
    count: int


class DashboardSummary(BaseModel):
    total_requests_5m: int
    suspicious_events_5m: int
    max_rps_5m: float
    top_countries: list[NamedCount]
    top_problem_paths: list[NamedCount]
    timeline: list[TimeseriesPoint]
