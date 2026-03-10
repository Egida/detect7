from datetime import datetime, timedelta, timezone
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import User
from ..queries import dashboard as q
from ..schemas import (
    DashboardSummary,
    NamedCount,
    RecentDetection,
    TimeseriesPoint,
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


class TimeRange(str, Enum):
    m5 = "5m"
    m30 = "30m"
    h1 = "1h"
    h6 = "6h"
    h24 = "24h"
    d7 = "7d"


_RANGE_DELTA = {
    TimeRange.m5: timedelta(minutes=5),
    TimeRange.m30: timedelta(minutes=30),
    TimeRange.h1: timedelta(hours=1),
    TimeRange.h6: timedelta(hours=6),
    TimeRange.h24: timedelta(hours=24),
    TimeRange.d7: timedelta(days=7),
}

_RANGE_BUCKET = {
    TimeRange.m5: "1 minute",
    TimeRange.m30: "1 minute",
    TimeRange.h1: "1 minute",
    TimeRange.h6: "5 minutes",
    TimeRange.h24: "5 minutes",
    TimeRange.d7: "1 hour",
}


@router.get("/summary/{domain_id}", response_model=DashboardSummary)
def dashboard_summary(
    domain_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    range: TimeRange = Query(TimeRange.h1, alias="range"),
):
    if q.domain_owned_by(db, domain_id, user.id) is None:
        raise HTTPException(status_code=404, detail="Domain not found")

    now = datetime.now(timezone.utc)
    since = now - _RANGE_DELTA[range]
    bucket = _RANGE_BUCKET[range]
    since_5m = now - timedelta(minutes=5)

    # Timeline (use continuous aggregate for 7d, raw logs otherwise)
    use_agg = range == TimeRange.d7
    tl_rows = (
        q.timeline_from_aggregate(db, domain_id, since)
        if use_agg
        else q.timeline_from_raw_logs(db, domain_id, since, bucket)
    )
    det_counts = q.detection_counts_by_bucket(db, domain_id, since, bucket)

    timeline = [
        TimeseriesPoint(
            t=row.t.isoformat() if hasattr(row.t, "isoformat") else str(row.t),
            requests=int(row.requests),
            problems=det_counts.get(row.t, 0),
        )
        for row in tl_rows
    ]

    # Headline numbers
    stats = q.log_stats_since(db, domain_id, since_5m)
    total_5m = int(stats.total) if stats else 0
    max_rps_5m = round(float(stats.peak_rps), 2) if stats else 0.0

    since_60s = now - timedelta(seconds=60)
    current_rps = round(q.request_count_since(db, domain_id, since_60s) / 60.0, 2)
    suspicious_5m = q.detection_count_since(db, domain_id, since_5m)

    # Leaderboards
    top_countries = [NamedCount(name=r.name, count=int(r.count)) for r in q.top_countries(db, domain_id, since)]
    top_paths = [NamedCount(name=r.name, count=int(r.count)) for r in q.top_paths(db, domain_id, since)]

    # Detections
    blocked_ips = q.active_blocked_ip_count(db, domain_id, now)
    recent_detections = [
        RecentDetection(
            detected_ip=r.detected_ip,
            threat_score=round(float(r.threat_score), 2),
            country=r.country,
            request_count=int(r.request_count),
            peak_rps=round(float(r.peak_rps), 2),
            started_at=r.started_at.isoformat() if hasattr(r.started_at, "isoformat") else str(r.started_at),
        )
        for r in q.recent_detections(db, domain_id, since)
    ]

    return DashboardSummary(
        total_requests_5m=total_5m,
        suspicious_events_5m=suspicious_5m,
        max_rps_5m=max_rps_5m,
        current_rps=current_rps,
        blocked_ips=blocked_ips,
        top_countries=top_countries,
        top_problem_paths=top_paths,
        timeline=timeline,
        recent_detections=recent_detections,
    )
