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
    DomainCount,
    NamedCount,
    OverviewDashboard,
    ProblemIP,
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


def _ts_iso(val) -> str:
    return val.isoformat() if hasattr(val, "isoformat") else str(val)


# ---------------------------------------------------------------------------
# Per-domain dashboard
# ---------------------------------------------------------------------------

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

    use_agg = range == TimeRange.d7
    tl_rows = (
        q.timeline_from_aggregate(db, domain_id, since)
        if use_agg
        else q.timeline_from_raw_logs(db, domain_id, since, bucket)
    )
    det_counts = q.detection_counts_by_bucket(db, domain_id, since, bucket)

    timeline = [
        TimeseriesPoint(
            t=_ts_iso(row.ts),
            requests=int(row.requests),
            bots=int(row.bots) if hasattr(row, "bots") else 0,
            problems=det_counts.get(row.ts, 0),
        )
        for row in tl_rows
    ]

    stats = q.log_stats_since(db, domain_id, since_5m)
    total_5m = int(stats.total) if stats else 0
    total_bots_5m = int(stats.total_bots) if stats and hasattr(stats, "total_bots") else 0
    max_rps_5m = round(float(stats.peak_rps), 2) if stats else 0.0

    since_60s = now - timedelta(seconds=60)
    current_rps = round(q.request_count_since(db, domain_id, since_60s) / 60.0, 2)
    suspicious_5m = q.detection_count_since(db, domain_id, since_5m)

    top_countries = [
        NamedCount(name=r.name, count=int(r.count), bot_count=int(r.bot_count))
        for r in q.top_countries(db, domain_id, since)
    ]
    top_paths = [
        NamedCount(name=r.name, count=int(r.count), bot_count=int(r.bot_count))
        for r in q.top_paths(db, domain_id, since)
    ]

    blocked_ips = q.active_blocked_ip_count(db, domain_id, now)
    recent_dets = [
        RecentDetection(
            detected_ip=r.detected_ip,
            threat_score=round(float(r.threat_score), 2),
            country=r.country,
            request_count=int(r.request_count),
            peak_rps=round(float(r.peak_rps), 2),
            started_at=_ts_iso(r.started_at),
        )
        for r in q.recent_detections(db, domain_id, since)
    ]

    prob_tl = [
        TimeseriesPoint(t=_ts_iso(r.ts), requests=int(r.requests))
        for r in q.problems_timeline(db, domain_id, since, bucket)
    ]
    prob_rps_tl = [
        TimeseriesPoint(t=_ts_iso(r.ts), requests=int(float(r.requests)))
        for r in q.problems_rps_timeline(db, domain_id, since, bucket)
    ]
    resp_statuses = [
        NamedCount(name=r.name, count=int(r.count), bot_count=int(r.bot_count))
        for r in q.response_status_breakdown(db, domain_id, since)
    ]
    prob_ip_rows = [
        ProblemIP(
            timestamp=_ts_iso(r.timestamp),
            domain_name=r.domain_name,
            detected_ip=r.detected_ip,
            country=r.country,
            ptr=r.ptr,
            peak_rps=round(float(r.peak_rps), 2),
            request_count=int(r.request_count),
        )
        for r in q.problem_ips(db, domain_id, since)
    ]

    return DashboardSummary(
        total_requests_5m=total_5m,
        total_bots_5m=total_bots_5m,
        suspicious_events_5m=suspicious_5m,
        max_rps_5m=max_rps_5m,
        current_rps=current_rps,
        blocked_ips=blocked_ips,
        top_countries=top_countries,
        top_problem_paths=top_paths,
        timeline=timeline,
        recent_detections=recent_dets,
        problems_timeline=prob_tl,
        problems_rps_timeline=prob_rps_tl,
        response_statuses=resp_statuses,
        problem_ips=prob_ip_rows,
    )


# ---------------------------------------------------------------------------
# All-domains overview
# ---------------------------------------------------------------------------

@router.get("/overview", response_model=OverviewDashboard)
def dashboard_overview(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    range: TimeRange = Query(TimeRange.m30, alias="range"),
):
    domain_ids = q.user_domain_ids(db, user.id)
    if not domain_ids:
        return OverviewDashboard(
            timeline=[], top_domains_by_requests=[], top_domains_by_problems=[],
            top_countries=[], unique_visitors_by_domain=[],
            problems_timeline=[], problems_rps_timeline=[],
            problem_ips=[], total_requests=0, total_bots=0,
            total_problems=0, current_rps=0.0,
        )

    now = datetime.now(timezone.utc)
    since = now - _RANGE_DELTA[range]
    bucket = _RANGE_BUCKET[range]

    tl_rows = q.overview_timeline(db, domain_ids, since, bucket)
    det_counts = q.overview_detection_counts_by_bucket(db, domain_ids, since, bucket)
    timeline = [
        TimeseriesPoint(
            t=_ts_iso(r.ts),
            requests=int(r.requests),
            bots=int(r.bots),
            problems=det_counts.get(r.ts, 0),
        )
        for r in tl_rows
    ]

    top_dom_req = [
        DomainCount(domain_id=r.domain_id, domain_name=r.domain_name,
                     count=int(r.count), bot_count=int(r.bot_count))
        for r in q.overview_top_domains_by_requests(db, domain_ids, since)
    ]
    top_dom_prob = [
        DomainCount(domain_id=r.domain_id, domain_name=r.domain_name, count=int(r.count))
        for r in q.overview_top_domains_by_problems(db, domain_ids, since)
    ]
    top_c = [
        NamedCount(name=r.name, count=int(r.count), bot_count=int(r.bot_count))
        for r in q.overview_top_countries(db, domain_ids, since)
    ]
    uv = [
        DomainCount(domain_id=r.domain_id, domain_name=r.domain_name, count=int(r.count))
        for r in q.overview_unique_visitors_by_domain(db, domain_ids, since)
    ]

    prob_tl = [
        TimeseriesPoint(t=_ts_iso(r.ts), requests=int(r.requests))
        for r in q.overview_problems_timeline(db, domain_ids, since, bucket)
    ]
    prob_rps = [
        TimeseriesPoint(t=_ts_iso(r.ts), requests=int(float(r.requests)))
        for r in q.overview_problems_rps_timeline(db, domain_ids, since, bucket)
    ]
    pips = [
        ProblemIP(
            timestamp=_ts_iso(r.timestamp), domain_name=r.domain_name,
            detected_ip=r.detected_ip, country=r.country, ptr=r.ptr,
            peak_rps=round(float(r.peak_rps), 2), request_count=int(r.request_count),
        )
        for r in q.overview_problem_ips(db, domain_ids, since)
    ]

    totals = q.overview_totals(db, domain_ids, since)
    since_60s = now - timedelta(seconds=60)
    crps = q.overview_current_rps(db, domain_ids, since_60s)
    tprob = q.overview_total_problems(db, domain_ids, since)

    return OverviewDashboard(
        timeline=timeline,
        top_domains_by_requests=top_dom_req,
        top_domains_by_problems=top_dom_prob,
        top_countries=top_c,
        unique_visitors_by_domain=uv,
        problems_timeline=prob_tl,
        problems_rps_timeline=prob_rps,
        problem_ips=pips,
        total_requests=int(totals.total_requests) if totals else 0,
        total_bots=int(totals.total_bots) if totals else 0,
        total_problems=tprob,
        current_rps=crps,
    )
