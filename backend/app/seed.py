"""Seed default plans into the database on first run."""

import logging
from sqlalchemy.orm import Session
from .models import Plan

logger = logging.getLogger(__name__)

DEFAULT_PLANS = [
    {
        "name": "Free",
        "max_domains": 1,
        "max_rps": 100,
        "retention_days": 7,
        "price_cents": 0,
    },
    {
        "name": "Pro",
        "max_domains": 5,
        "max_rps": 1000,
        "retention_days": 30,
        "price_cents": 2900,
    },
    {
        "name": "Enterprise",
        "max_domains": 25,
        "max_rps": 10000,
        "retention_days": 90,
        "price_cents": 9900,
    },
]


def seed_plans(db: Session) -> None:
    existing = {p.name for p in db.query(Plan.name).all()}
    added = 0
    for plan_data in DEFAULT_PLANS:
        if plan_data["name"] not in existing:
            db.add(Plan(**plan_data))
            added += 1
    if added:
        db.commit()
        logger.info("Seeded %d default plan(s)", added)
