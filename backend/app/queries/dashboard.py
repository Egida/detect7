"""Isolated SQL queries for the dashboard.

Each function accepts a Session plus typed parameters and returns raw rows
or scalar values. No HTTP/FastAPI/Pydantic concerns leak in here.
"""

from datetime import datetime
from typing import Any, Sequence

from sqlalchemy import Row, text
from sqlalchemy.orm import Session


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _domain_ids_clause(domain_ids: list[int]) -> str:
    return ",".join(str(int(d)) for d in domain_ids)


def domain_owned_by(db: Session, domain_id: int, user_id: int) -> Row | None:
    return db.execute(
        text("SELECT id FROM domains WHERE id = :did AND owner_id = :uid"),
        {"did": domain_id, "uid": user_id},
    ).first()


def user_domain_ids(db: Session, user_id: int) -> list[int]:
    rows = db.execute(
        text("SELECT id FROM domains WHERE owner_id = :uid"),
        {"uid": user_id},
    ).fetchall()
    return [r.id for r in rows]


# ---------------------------------------------------------------------------
# Per-domain timeline
# ---------------------------------------------------------------------------

def timeline_from_aggregate(
    db: Session, domain_id: int, since: datetime
) -> Sequence[Row]:
    return db.execute(
        text("""
            SELECT bucket AS ts,
                   COALESCE(total_requests, 0) AS requests,
                   COALESCE(bot_requests, 0) AS bots
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
            SELECT time_bucket(CAST(:bw AS interval), timestamp) AS ts,
                   COUNT(*) AS requests,
                   COUNT(*) FILTER (WHERE is_known_bot) AS bots
            FROM domain_logs
            WHERE domain_id = :did AND timestamp >= :since
            GROUP BY ts ORDER BY ts
        """),
        {"bw": bucket_width, "did": domain_id, "since": since},
    ).fetchall()


def detection_counts_by_bucket(
    db: Session, domain_id: int, since: datetime, bucket_width: str
) -> dict[Any, int]:
    rows = db.execute(
        text("""
            SELECT time_bucket(CAST(:bw AS interval), started_at) AS ts,
                   COUNT(*) AS cnt
            FROM detection_events
            WHERE domain_id = :did AND started_at >= :since
            GROUP BY ts
        """),
        {"bw": bucket_width, "did": domain_id, "since": since},
    ).fetchall()
    return {row.ts: int(row.cnt) for row in rows}


# ---------------------------------------------------------------------------
# Per-domain headline stats
# ---------------------------------------------------------------------------

def log_stats_since(db: Session, domain_id: int, since: datetime) -> Row | None:
    return db.execute(
        text("""
            SELECT COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE is_known_bot) AS total_bots,
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
# Per-domain leaderboards
# ---------------------------------------------------------------------------

def top_countries(
    db: Session, domain_id: int, since: datetime, limit: int = 10
) -> Sequence[Row]:
    return db.execute(
        text("""
            SELECT country AS name, COUNT(*) AS count,
                   COUNT(*) FILTER (WHERE is_known_bot) AS bot_count
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
            SELECT path AS name, COUNT(*) AS count,
                   COUNT(*) FILTER (WHERE is_known_bot) AS bot_count
            FROM domain_logs
            WHERE domain_id = :did AND timestamp >= :since
            GROUP BY path ORDER BY count DESC LIMIT :lim
        """),
        {"did": domain_id, "since": since, "lim": limit},
    ).fetchall()


def response_status_breakdown(
    db: Session, domain_id: int, since: datetime
) -> Sequence[Row]:
    return db.execute(
        text("""
            SELECT CAST(status_code AS text) AS name, COUNT(*) AS count,
                   COUNT(*) FILTER (WHERE is_known_bot) AS bot_count
            FROM domain_logs
            WHERE domain_id = :did AND timestamp >= :since
            GROUP BY status_code ORDER BY count DESC
        """),
        {"did": domain_id, "since": since},
    ).fetchall()


# ---------------------------------------------------------------------------
# Per-domain problems
# ---------------------------------------------------------------------------

def problems_timeline(
    db: Session, domain_id: int, since: datetime, bucket_width: str
) -> Sequence[Row]:
    return db.execute(
        text("""
            SELECT time_bucket(CAST(:bw AS interval), started_at) AS ts,
                   COUNT(*) AS requests
            FROM detection_events
            WHERE domain_id = :did AND started_at >= :since
            GROUP BY ts ORDER BY ts
        """),
        {"bw": bucket_width, "did": domain_id, "since": since},
    ).fetchall()


def problems_rps_timeline(
    db: Session, domain_id: int, since: datetime, bucket_width: str
) -> Sequence[Row]:
    return db.execute(
        text("""
            SELECT time_bucket(CAST(:bw AS interval), started_at) AS ts,
                   MAX(peak_rps) AS requests
            FROM detection_events
            WHERE domain_id = :did AND started_at >= :since
            GROUP BY ts ORDER BY ts
        """),
        {"bw": bucket_width, "did": domain_id, "since": since},
    ).fetchall()


def problem_ips(
    db: Session, domain_id: int, since: datetime, limit: int = 50
) -> Sequence[Row]:
    return db.execute(
        text("""
            SELECT de.started_at AS timestamp, d.name AS domain_name,
                   de.detected_ip, de.country, de.ptr,
                   de.peak_rps, de.request_count
            FROM detection_events de
            JOIN domains d ON d.id = de.domain_id
            WHERE de.domain_id = :did AND de.started_at >= :since
            ORDER BY de.started_at DESC LIMIT :lim
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


# ---------------------------------------------------------------------------
# Overview (all domains for a user)
# ---------------------------------------------------------------------------

def overview_timeline(
    db: Session, domain_ids: list[int], since: datetime, bucket_width: str
) -> Sequence[Row]:
    ids = _domain_ids_clause(domain_ids)
    return db.execute(
        text(f"""
            SELECT time_bucket(CAST(:bw AS interval), timestamp) AS ts,
                   COUNT(*) AS requests,
                   COUNT(*) FILTER (WHERE is_known_bot) AS bots
            FROM domain_logs
            WHERE domain_id IN ({ids}) AND timestamp >= :since
            GROUP BY ts ORDER BY ts
        """),
        {"bw": bucket_width, "since": since},
    ).fetchall()


def overview_detection_counts_by_bucket(
    db: Session, domain_ids: list[int], since: datetime, bucket_width: str
) -> dict[Any, int]:
    ids = _domain_ids_clause(domain_ids)
    rows = db.execute(
        text(f"""
            SELECT time_bucket(CAST(:bw AS interval), started_at) AS ts,
                   COUNT(*) AS cnt
            FROM detection_events
            WHERE domain_id IN ({ids}) AND started_at >= :since
            GROUP BY ts
        """),
        {"bw": bucket_width, "since": since},
    ).fetchall()
    return {row.ts: int(row.cnt) for row in rows}


def overview_top_domains_by_requests(
    db: Session, domain_ids: list[int], since: datetime, limit: int = 10
) -> Sequence[Row]:
    ids = _domain_ids_clause(domain_ids)
    return db.execute(
        text(f"""
            SELECT dl.domain_id, d.name AS domain_name,
                   COUNT(*) AS count,
                   COUNT(*) FILTER (WHERE dl.is_known_bot) AS bot_count
            FROM domain_logs dl
            JOIN domains d ON d.id = dl.domain_id
            WHERE dl.domain_id IN ({ids}) AND dl.timestamp >= :since
            GROUP BY dl.domain_id, d.name ORDER BY count DESC LIMIT :lim
        """),
        {"since": since, "lim": limit},
    ).fetchall()


def overview_top_domains_by_problems(
    db: Session, domain_ids: list[int], since: datetime, limit: int = 10
) -> Sequence[Row]:
    ids = _domain_ids_clause(domain_ids)
    return db.execute(
        text(f"""
            SELECT de.domain_id, d.name AS domain_name,
                   COUNT(*) AS count
            FROM detection_events de
            JOIN domains d ON d.id = de.domain_id
            WHERE de.domain_id IN ({ids}) AND de.started_at >= :since
            GROUP BY de.domain_id, d.name ORDER BY count DESC LIMIT :lim
        """),
        {"since": since, "lim": limit},
    ).fetchall()


def overview_top_countries(
    db: Session, domain_ids: list[int], since: datetime, limit: int = 10
) -> Sequence[Row]:
    ids = _domain_ids_clause(domain_ids)
    return db.execute(
        text(f"""
            SELECT country AS name, COUNT(*) AS count,
                   COUNT(*) FILTER (WHERE is_known_bot) AS bot_count
            FROM domain_logs
            WHERE domain_id IN ({ids}) AND timestamp >= :since AND country IS NOT NULL
            GROUP BY country ORDER BY count DESC LIMIT :lim
        """),
        {"since": since, "lim": limit},
    ).fetchall()


def overview_unique_visitors_by_domain(
    db: Session, domain_ids: list[int], since: datetime
) -> Sequence[Row]:
    ids = _domain_ids_clause(domain_ids)
    return db.execute(
        text(f"""
            SELECT dl.domain_id, d.name AS domain_name,
                   COUNT(DISTINCT dl.source_ip) AS count
            FROM domain_logs dl
            JOIN domains d ON d.id = dl.domain_id
            WHERE dl.domain_id IN ({ids}) AND dl.timestamp >= :since
            GROUP BY dl.domain_id, d.name ORDER BY count DESC
        """),
        {"since": since},
    ).fetchall()


def overview_problems_timeline(
    db: Session, domain_ids: list[int], since: datetime, bucket_width: str
) -> Sequence[Row]:
    ids = _domain_ids_clause(domain_ids)
    return db.execute(
        text(f"""
            SELECT time_bucket(CAST(:bw AS interval), started_at) AS ts,
                   COUNT(*) AS requests
            FROM detection_events
            WHERE domain_id IN ({ids}) AND started_at >= :since
            GROUP BY ts ORDER BY ts
        """),
        {"bw": bucket_width, "since": since},
    ).fetchall()


def overview_problems_rps_timeline(
    db: Session, domain_ids: list[int], since: datetime, bucket_width: str
) -> Sequence[Row]:
    ids = _domain_ids_clause(domain_ids)
    return db.execute(
        text(f"""
            SELECT time_bucket(CAST(:bw AS interval), started_at) AS ts,
                   MAX(peak_rps) AS requests
            FROM detection_events
            WHERE domain_id IN ({ids}) AND started_at >= :since
            GROUP BY ts ORDER BY ts
        """),
        {"bw": bucket_width, "since": since},
    ).fetchall()


def overview_problem_ips(
    db: Session, domain_ids: list[int], since: datetime, limit: int = 50
) -> Sequence[Row]:
    ids = _domain_ids_clause(domain_ids)
    return db.execute(
        text(f"""
            SELECT de.started_at AS timestamp, d.name AS domain_name,
                   de.detected_ip, de.country, de.ptr,
                   de.peak_rps, de.request_count
            FROM detection_events de
            JOIN domains d ON d.id = de.domain_id
            WHERE de.domain_id IN ({ids}) AND de.started_at >= :since
            ORDER BY de.started_at DESC LIMIT :lim
        """),
        {"since": since, "lim": limit},
    ).fetchall()


def overview_totals(
    db: Session, domain_ids: list[int], since: datetime
) -> Row | None:
    ids = _domain_ids_clause(domain_ids)
    return db.execute(
        text(f"""
            SELECT COUNT(*) AS total_requests,
                   COUNT(*) FILTER (WHERE is_known_bot) AS total_bots
            FROM domain_logs
            WHERE domain_id IN ({ids}) AND timestamp >= :since
        """),
        {"since": since},
    ).first()


def overview_current_rps(
    db: Session, domain_ids: list[int], since_60s: datetime
) -> float:
    ids = _domain_ids_clause(domain_ids)
    row = db.execute(
        text(f"""
            SELECT COUNT(*) AS cnt FROM domain_logs
            WHERE domain_id IN ({ids}) AND timestamp >= :since
        """),
        {"since": since_60s},
    ).first()
    return round(int(row.cnt) / 60.0, 2) if row else 0.0


def overview_total_problems(
    db: Session, domain_ids: list[int], since: datetime
) -> int:
    ids = _domain_ids_clause(domain_ids)
    row = db.execute(
        text(f"""
            SELECT COUNT(*) AS cnt FROM detection_events
            WHERE domain_id IN ({ids}) AND started_at >= :since
        """),
        {"since": since},
    ).first()
    return int(row.cnt) if row else 0
