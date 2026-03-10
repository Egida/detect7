import hashlib
import random
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import Domain, User
from ..schemas import DashboardSummary, TimeseriesPoint


router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def _seed_for_domain(domain: str, user_id: int) -> int:
    digest = hashlib.sha256(f"{user_id}:{domain}".encode("utf-8")).hexdigest()
    return int(digest[:8], 16)


@router.get("/summary/{domain_id}", response_model=DashboardSummary)
def dashboard_summary(
    domain_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    domain = db.scalar(select(Domain).where(Domain.id == domain_id, Domain.owner_id == user.id))
    if domain is None:
        raise HTTPException(status_code=404, detail="Domain not found")
    if not domain.is_verified:
        raise HTTPException(status_code=403, detail="Domain is not verified")

    rng = random.Random(_seed_for_domain(domain.name, user.id))
    now = datetime.now(timezone.utc)

    timeline: list[TimeseriesPoint] = []
    requests_sum = 0
    problems_sum = 0
    peak_rps = 0.0

    for minute in range(59, -1, -1):
        ts = now - timedelta(minutes=minute)
        base = rng.randint(120, 420)
        spike = rng.randint(0, 250) if rng.random() > 0.85 else 0
        requests = base + spike
        problems = max(0, int(requests * rng.uniform(0.01, 0.11)))
        rps = requests / 60
        peak_rps = max(peak_rps, rps)
        requests_sum += requests
        problems_sum += problems
        timeline.append(
            TimeseriesPoint(
                t=ts.isoformat(),
                requests=requests,
                problems=problems,
            )
        )

    countries = ["US", "DE", "NL", "GB", "FR", "SG", "IN", "JP"]
    paths = ["/", "/wp-login.php", "/api/search", "/xmlrpc.php", "/login", "/feed"]
    top_countries = [{"name": c, "count": rng.randint(300, 3500)} for c in countries[:5]]
    top_problem_paths = [{"name": p, "count": rng.randint(40, 700)} for p in paths[:5]]

    return DashboardSummary(
        total_requests_5m=sum(p.requests for p in timeline[-5:]),
        suspicious_events_5m=sum(p.problems for p in timeline[-5:]),
        max_rps_5m=round(max((p.requests / 60) for p in timeline[-5:]), 2),
        top_countries=sorted(top_countries, key=lambda x: x["count"], reverse=True),
        top_problem_paths=sorted(top_problem_paths, key=lambda x: x["count"], reverse=True),
        timeline=timeline,
    )
