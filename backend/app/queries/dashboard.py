"""Isolated SQL queries for the dashboard.

Each function accepts a Session plus typed parameters and returns raw rows
or scalar values. No HTTP/FastAPI/Pydantic concerns leak in here.
"""

from datetime import datetime
from typing import Any, Sequence

from sqlalchemy import Row, text
from sqlalchemy.orm import Session


# ---------------------------------------------------------------------------
# Domain ownership check
# ---------------------------------------------------------------------------

def domain_owned_by(db: Session, domain_id: int, user_id: int) -> Row | None:
    return db.execute(
        text("SELECT id FROM domains WHERE id = :did AND owner_id = :uid"),
        {"did": domain_id, "uid": user_id},
    ).first()


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

def timeline_from_aggregate(
    db: Session, domain_id: int, since: datetime
) -> Sequence[Row]:
    return db.execute(
        text("""
            SELECT bucket AS t,
                   COALESCE(total_requests, 0) AS requests
            FROM domain_stats
            WHERE domain_id = :did AND bucket >= :since
            ORDER BY bucket
        """),
        {"did": domain_id, "since": since},
    ).fetchall()


def timeline_from_raw_logs(
    db: Session, domain_id: int, since: datetime, bucket_width: str
) -> Sequence[Row]:
    return db.execute(
        text("""
            SELECT time_bucket(:bw, timestamp) AS t,
                   COUNT(*) AS requests
            FROM domain_logs
            WHERE domain_id = :did AND timestamp >= :since
            GROUP BY t ORDER BY t
        """),
        {"bw": bucket_width, "did": domain_id, "since": since},
    ).fetchall()


def detection_counts_by_bucket(
    db: Session, domain_id: int, since: datetime, bucket_width: str
) -> dict[Any, int]:
    rows = db.execute(
        text("""
            SELECT time_bucket(:bw, started_at) AS t,
                   COUNT(*) AS cnt
            FROM detection_events
            WHERE domain_id = :did AND started_at >= :since
            GROUP BY t
        """),
        {"bw": bucket_width, "did": domain_id, "since": since},
    ).fetchall()
    return {row.t: int(row.cnt) for row in rows}


# ---------------------------------------------------------------------------
# Headline stats
# ---------------------------------------------------------------------------

def log_stats_since(db: Session, domain_id: int, since: datetime) -> Row | None:
    """Total requests and peak RPS within the window."""
    return db.execute(
        text("""
            SELECT COUNT(*) AS total,
                   COUNT(*) / GREATEST(
                       EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp))), 1
                   ) AS peak_rps
            FROM domain_logs
            WHERE domain_id = :did AND timestamp >= :since
        """),
        {"did": domain_id, "since": since},
    ).first()


def request_count_since(db: Session, domain_id: int, since: datetime) -> int:
    row = db.execute(
        text(
            "SELECT COUNT(*) AS cnt FROM domain_logs "
            "WHERE domain_id = :did AND timestamp >= :since"
        ),
        {"did": domain_id, "since": since},
    ).first()
    return int(row.cnt) if row else 0


def detection_count_since(db: Session, domain_id: int, since: datetime) -> int:
    row = db.execute(
        text(
            "SELECT COUNT(*) AS cnt FROM detection_events "
            "WHERE domain_id = :did AND started_at >= :since"
        ),
        {"did": domain_id, "since": since},
    ).first()
    return int(row.cnt) if row else 0


# ---------------------------------------------------------------------------
# Leaderboards
# ---------------------------------------------------------------------------

def top_countries(
    db: Session, domain_id: int, since: datetime, limit: int = 10
) -> Sequence[Row]:
    return db.execute(
        text("""
            SELECT country AS name, COUNT(*) AS count
            FROM domain_logs
            WHERE domain_id = :did AND timestamp >= :since AND country IS NOT NULL
            GROUP BY country ORDER BY count DESC LIMIT :lim
        """),
        {"did": domain_id, "since": since, "lim": limit},
    ).fetchall()


def top_paths(
    db: Session, domain_id: int, since: datetime, limit: int = 10
) -> Sequence[Row]:
    return db.execute(
        text("""
            SELECT path AS name, COUNT(*) AS count
            FROM domain_logs
            WHERE domain_id = :did AND timestamp >= :since
            GROUP BY path ORDER BY count DESC LIMIT :lim
        """),
        {"did": domain_id, "since": since, "lim": limit},
    ).fetchall()


# ---------------------------------------------------------------------------
# Blocked / detections
# ---------------------------------------------------------------------------

def active_blocked_ip_count(db: Session, domain_id: int, now: datetime) -> int:
    row = db.execute(
        text("""
            SELECT COUNT(DISTINCT detected_ip) AS cnt
            FROM detection_events
            WHERE domain_id = :did
              AND cf_pushed_at IS NOT NULL
              AND (cf_expires_at IS NULL OR cf_expires_at > :now)
        """),
        {"did": domain_id, "now": now},
    ).first()
    return int(row.cnt) if row else 0


def recent_detections(
    db: Session, domain_id: int, since: datetime, limit: int = 20
) -> Sequence[Row]:
    return db.execute(
        text("""
            SELECT detected_ip, threat_score, country,
                   request_count, peak_rps, started_at
            FROM detection_events
            WHERE domain_id = :did AND started_at >= :since
            ORDER BY started_at DESC LIMIT :lim
        """),
        {"did": domain_id, "since": since, "lim": limit},
    ).fetchall()
