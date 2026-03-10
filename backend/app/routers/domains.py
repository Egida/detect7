import re
import secrets
from datetime import datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import Domain, User
from ..schemas import DomainCreate, DomainPublic, ForwardingInstructions, VerifyResponse


router = APIRouter(prefix="/domains", tags=["domains"])

DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def _normalize_domain(domain: str) -> str:
    normalized = domain.strip().lower()
    if normalized.startswith("http://") or normalized.startswith("https://"):
        normalized = normalized.split("://", 1)[1]
    normalized = normalized.strip("/")
    return normalized


def _validate_domain(domain: str) -> None:
    if not DOMAIN_RE.fullmatch(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")


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
    db.commit()
    db.refresh(domain)
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

    db.delete(domain)
    db.commit()


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
                    db.add(domain)
                    db.commit()
                    return VerifyResponse(success=True, message=f"Verified using {url}")
            except httpx.HTTPError:
                continue

    return VerifyResponse(
        success=False,
        message="Verification file not found or token mismatch",
    )


@router.get("/instructions/log-forwarding", response_model=ForwardingInstructions)
def log_forwarding_instructions():
    return ForwardingInstructions(
        nginx_log_format=(
            "log_format gelf_json escape=json '{' "
            "'\"domain\": \"$host\",' "
            "'\"timestamp\": \"$msec\",' "
            "'\"remote_addr\": \"$remote_addr\",' "
            "'\"request\": \"$request\",' "
            "'\"response_status\": \"$status\",' "
            "'\"request_time\": \"$request_time\"' "
            "'}';"
        ),
        nginx_access_log_line=(
            "access_log syslog:server=YOUR_COLLECTOR_IP:514,tag=ddos7,severity=info gelf_json;"
        ),
        notes=[
            "Apply this to every virtual host/domain you onboard.",
            "Keep the same JSON field names so parser normalization remains accurate.",
            "Allow outbound UDP/514 from your Nginx host to the collector.",
        ],
    )
