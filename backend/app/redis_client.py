"""Shared Redis client for the SaaS backend (API key cache management)."""

import json
import os
from typing import Any

import redis

REDIS_APIKEY_PREFIX = os.getenv("REDIS_APIKEY_PREFIX", "dk7:key")
REDIS_URL = os.getenv(
    "REDIS_URL",
    f"redis://{os.getenv('REDIS_APIKEY_SERVER', 'localhost')}:"
    f"{os.getenv('REDIS_APIKEY_PORT', '6379')}/{os.getenv('REDIS_APIKEY_DB', '2')}",
)

_pool: redis.ConnectionPool | None = None


def _get_pool() -> redis.ConnectionPool:
    global _pool
    if _pool is None:
        _pool = redis.ConnectionPool.from_url(REDIS_URL, decode_responses=True)
    return _pool


def get_redis() -> redis.Redis:
    return redis.Redis(connection_pool=_get_pool())


def set_api_key_cache(plaintext_key: str, meta: dict[str, Any]) -> None:
    r = get_redis()
    r.set(f"{REDIS_APIKEY_PREFIX}:{plaintext_key}", json.dumps(meta))


def delete_api_key_cache(plaintext_key: str) -> None:
    r = get_redis()
    r.delete(f"{REDIS_APIKEY_PREFIX}:{plaintext_key}")
