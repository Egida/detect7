import os
import re
import secrets
from datetime import datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..crypto import encrypt_value, decrypt_value, hash_api_key, generate_api_key
from ..database import get_db
from ..deps import get_current_user
from ..models import ApiKey, Domain, DomainOriginIP, User
from ..redis_client import set_api_key_cache, delete_api_key_cache
from ..schemas import (
    ApiKeyCreated,
    DomainCreate,
    DomainPublic,
    ForwardingInstructions,
    VerifyResponse,
)

router = APIRouter(prefix="/domains", tags=["domains"])

DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
COLLECTOR_HOST = os.getenv("DETECT7_COLLECTOR_HOST", "detect7.example.com")
COLLECTOR_PORT = os.getenv("DETECT7_COLLECTOR_PORT", "514")


def _normalize_domain(domain: str) -> str:
    normalized = domain.strip().lower()
    if normalized.startswith("http://") or normalized.startswith("https://"):
        normalized = normalized.split("://", 1)[1]
    normalized = normalized.strip("/")
    return normalized


def _validate_domain(domain: str) -> None:
    if not DOMAIN_RE.fullmatch(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")


def _build_key_cache_meta(domain: Domain, user: User, db: Session) -> dict:
    origin_ips_rows = db.scalars(
        select(DomainOriginIP.ip_address).where(DomainOriginIP.domain_id == domain.id)
    ).all()
    plan = user.plan
    return {
        "user_id": user.id,
        "domain_id": domain.id,
        "host": domain.name,
        "strip_subdomains": domain.strip_subdomains,
        "origin_ips": list(origin_ips_rows),
        "max_rps": plan.max_rps if plan else 100,
    }


def _push_key_to_cache(plaintext_key: str, domain: Domain, user: User, db: Session) -> None:
    meta = _build_key_cache_meta(domain, user, db)
    set_api_key_cache(plaintext_key, meta)


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

@router.get("", response_model=list[DomainPublic])
def list_domains(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    stmt = select(Domain).where(Domain.owner_id == user.id).order_by(Domain.created_at.desc())
    return list(db.scalars(stmt))


@router.post("", response_model=DomainPublic, status_code=status.HTTP_201_CREATED)
def add_domain(
    payload: DomainCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    domain_name = _normalize_domain(payload.name)
    _validate_domain(domain_name)

    existing = db.scalar(
        select(Domain).where(Domain.owner_id == user.id, Domain.name == domain_name)
    )
    if existing:
        raise HTTPException(status_code=409, detail="Domain already added")

    verify_id = secrets.token_hex(8)
    verify_token = secrets.token_urlsafe(24)
    domain = Domain(
        owner_id=user.id,
        name=domain_name,
        verify_filename=f"detect7-verify-{verify_id}.txt",
        verify_token=verify_token,
    )
    db.add(domain)
    db.flush()

    plaintext_key = generate_api_key()
    api_key = ApiKey(
        user_id=user.id,
        domain_id=domain.id,
        key_prefix=plaintext_key[:12],
        key_enc=encrypt_value(plaintext_key),
        key_sha256=hash_api_key(plaintext_key),
        name="default",
    )
    db.add(api_key)
    db.commit()
    db.refresh(domain)

    _push_key_to_cache(plaintext_key, domain, user, db)

    return domain


@router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_domain(
    domain_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    domain = db.scalar(select(Domain).where(Domain.id == domain_id, Domain.owner_id == user.id))
    if domain is None:
        raise HTTPException(status_code=404, detail="Domain not found")

    for ak in domain.api_keys:
        try:
            pt = decrypt_value(ak.key_enc)
            delete_api_key_cache(pt)
        except Exception:
            pass

    db.delete(domain)
    db.commit()


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

@router.post("/{domain_id}/verify", response_model=VerifyResponse)
async def verify_domain(
    domain_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    domain = db.scalar(select(Domain).where(Domain.id == domain_id, Domain.owner_id == user.id))
    if domain is None:
        raise HTTPException(status_code=404, detail="Domain not found")

    expected = domain.verify_token.strip()
    urls = [
        f"https://{domain.name}/{domain.verify_filename}",
        f"http://{domain.name}/{domain.verify_filename}",
    ]

    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
        for url in urls:
            try:
                response = await client.get(url)
                if response.status_code == 200 and response.text.strip() == expected:
                    domain.is_verified = True
                    domain.verified_at = datetime.utcnow()
                    domain.verification_method = "txt"
                    db.add(domain)
                    db.commit()
                    return VerifyResponse(success=True, message=f"Verified using {url}")
            except httpx.HTTPError:
                continue

    return VerifyResponse(
        success=False,
        message="Verification file not found or token mismatch",
    )


# ---------------------------------------------------------------------------
# Log forwarding instructions (personalized per domain)
# ---------------------------------------------------------------------------

@router.get("/{domain_id}/instructions/log-forwarding", response_model=ForwardingInstructions)
def log_forwarding_instructions(
    domain_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    domain = db.scalar(select(Domain).where(Domain.id == domain_id, Domain.owner_id == user.id))
    if domain is None:
        raise HTTPException(status_code=404, detail="Domain not found")

    active_key = db.scalar(
        select(ApiKey)
        .where(ApiKey.domain_id == domain.id, ApiKey.is_active.is_(True))
        .order_by(ApiKey.created_at.desc())
    )

    if active_key:
        tag_value = decrypt_value(active_key.key_enc)
    else:
        tag_value = "YOUR_API_KEY"

    return ForwardingInstructions(
        nginx_log_format=(
            "log_format gelf_json escape=json '{' "
            "'\"domain\": \"$host\",' "
            "'\"timestamp\": \"$msec\",' "
            "'\"remote_addr\": \"$remote_addr\",' "
            "'\"request\": \"$request\",' "
            "'\"response_status\": \"$status\",' "
            "'\"body_bytes_sent\": \"$body_bytes_sent\",' "
            "'\"http_referer\": \"$http_referer\",' "
            "'\"http_user_agent\": \"$http_user_agent\",' "
            "'\"request_time\": \"$request_time\",' "
            "'\"request_length\": \"$request_length\",' "
            "'\"connection\": \"$connection\",' "
            "'\"connection_requests\": \"$connection_requests\"' "
            "'}';"
        ),
        nginx_access_log_line=(
            f"access_log syslog:server={COLLECTOR_HOST}:{COLLECTOR_PORT},"
            f"tag={tag_value},severity=info gelf_json;"
        ),
        notes=[
            "Apply this to every virtual host/server block you want to monitor.",
            "The API key in the tag authenticates this domain. Do not share it.",
            "Allow outbound UDP/{} from your Nginx host to the collector.".format(COLLECTOR_PORT),
        ],
    )


# Keep the old generic endpoint for backwards compatibility
@router.get("/instructions/log-forwarding", response_model=ForwardingInstructions)
def log_forwarding_instructions_generic():
    return ForwardingInstructions(
        nginx_log_format=(
            "log_format gelf_json escape=json '{' "
            "'\"domain\": \"$host\",' "
            "'\"timestamp\": \"$msec\",' "
            "'\"remote_addr\": \"$remote_addr\",' "
            "'\"request\": \"$request\",' "
            "'\"response_status\": \"$status\",' "
            "'\"body_bytes_sent\": \"$body_bytes_sent\",' "
            "'\"http_referer\": \"$http_referer\",' "
            "'\"http_user_agent\": \"$http_user_agent\",' "
            "'\"request_time\": \"$request_time\",' "
            "'\"request_length\": \"$request_length\",' "
            "'\"connection\": \"$connection\",' "
            "'\"connection_requests\": \"$connection_requests\"' "
            "'}';"
        ),
        nginx_access_log_line=(
            f"access_log syslog:server={COLLECTOR_HOST}:{COLLECTOR_PORT},"
            "tag=dk7_YOUR_API_KEY,severity=info gelf_json;"
        ),
        notes=[
            "Replace dk7_YOUR_API_KEY with your domain's actual API key.",
            "Apply this to every virtual host/domain you onboard.",
            "Allow outbound UDP/{} from your Nginx host to the collector.".format(COLLECTOR_PORT),
        ],
    )
