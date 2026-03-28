"""
db.py — thin async database abstraction for OmniAudit

Supports two backends selected by DB_BACKEND env var:
  sqlite   — aiosqlite on /app/data/omniaudit.db  (Fly.io free tier)
  postgres — asyncpg pool                          (Fly Postgres, OCI, etc.)

The public interface is intentionally minimal:
  await db.execute(sql, *args)
  row  = await db.fetchrow(sql, *args)
  rows = await db.fetchall(sql, *args)
  val  = await db.fetchval(sql, *args)
  await db.init()
  await db.close()

Parameter style:
  Both backends use positional parameters.
  asyncpg uses $1 $2 $3 ...
  aiosqlite uses ? ? ? ...
  Pass args as positional — this module converts the placeholders automatically.
"""

import asyncio
import logging
import os
import re
from typing import Any, Optional

logger = logging.getLogger("omniaudit.db")

DB_BACKEND  = os.environ.get("DB_BACKEND", "postgres").lower()
SQLITE_PATH = os.environ.get("SQLITE_PATH", "/app/data/omniaudit.db")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
DB_SSL      = os.environ.get("DB_SSL", "disable")

_pool = None          # asyncpg Pool  (postgres backend)
_sqlite_path = None   # str           (sqlite backend)
_sqlite_lock: Optional[asyncio.Lock] = None  # serialises writes for sqlite


def _pg_to_sqlite(sql: str) -> str:
    """Convert $1 $2 ... placeholders to ? for sqlite3/aiosqlite."""
    return re.sub(r"\$\d+", "?", sql)


# ── SQLite helpers ─────────────────────────────────────────────────────────────
async def _sqlite_execute(sql: str, args: tuple) -> None:
    import aiosqlite
    sql = _pg_to_sqlite(sql)
    async with _sqlite_lock:
        async with aiosqlite.connect(_sqlite_path) as conn:
            conn.row_factory = aiosqlite.Row
            await conn.execute(sql, args)
            await conn.commit()


async def _sqlite_fetchrow(sql: str, args: tuple) -> Optional[dict]:
    import aiosqlite
    sql = _pg_to_sqlite(sql)
    async with aiosqlite.connect(_sqlite_path) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(sql, args) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def _sqlite_fetchall(sql: str, args: tuple) -> list[dict]:
    import aiosqlite
    sql = _pg_to_sqlite(sql)
    async with aiosqlite.connect(_sqlite_path) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(sql, args) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]


async def _sqlite_fetchval(sql: str, args: tuple) -> Any:
    import aiosqlite
    sql = _pg_to_sqlite(sql)
    async with aiosqlite.connect(_sqlite_path) as conn:
        async with conn.execute(sql, args) as cur:
            row = await cur.fetchone()
            return row[0] if row else None


# ── SQLite advisory lock simulation (patrol de-dup) ───────────────────────────
# SQLite is single-process by design; the in-process _patrol_running flag in
# main.py is sufficient. These stubs let the same code path work for both
# backends without branching.
async def try_advisory_lock(lock_id: int) -> bool:
    if DB_BACKEND == "sqlite":
        return True   # always granted — single process
    async with _pool.acquire() as conn:
        return await conn.fetchval("SELECT pg_try_advisory_lock($1)", lock_id)


async def release_advisory_lock(lock_id: int) -> None:
    if DB_BACKEND == "sqlite":
        return
    async with _pool.acquire() as conn:
        await conn.execute("SELECT pg_advisory_unlock($1)", lock_id)


# ── Public interface ───────────────────────────────────────────────────────────
async def execute(sql: str, *args) -> None:
    if DB_BACKEND == "sqlite":
        await _sqlite_execute(sql, args)
    else:
        async with _pool.acquire() as conn:
            await conn.execute(sql, *args)


async def fetchrow(sql: str, *args) -> Optional[dict]:
    if DB_BACKEND == "sqlite":
        return await _sqlite_fetchrow(sql, args)
    else:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(sql, *args)
            return dict(row) if row else None


async def fetchall(sql: str, *args) -> list[dict]:
    if DB_BACKEND == "sqlite":
        return await _sqlite_fetchall(sql, args)
    else:
        async with _pool.acquire() as conn:
            rows = await conn.fetch(sql, *args)
            return [dict(r) for r in rows]


async def fetchval(sql: str, *args) -> Any:
    if DB_BACKEND == "sqlite":
        return await _sqlite_fetchval(sql, args)
    else:
        async with _pool.acquire() as conn:
            return await conn.fetchval(sql, *args)


# ── Init / teardown ────────────────────────────────────────────────────────────
async def init() -> None:
    global _pool, _sqlite_path, _sqlite_lock

    if DB_BACKEND == "sqlite":
        import aiosqlite
        from pathlib import Path
        _sqlite_path = SQLITE_PATH
        _sqlite_lock = asyncio.Lock()
        Path(_sqlite_path).parent.mkdir(parents=True, exist_ok=True)
        # SQLite pragma: WAL mode for concurrent reads during writes
        async with aiosqlite.connect(_sqlite_path) as conn:
            await conn.execute("PRAGMA journal_mode=WAL")
            await conn.execute("PRAGMA synchronous=NORMAL")
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS audits (
                    audit_id         TEXT PRIMARY KEY,
                    timestamp        TEXT NOT NULL,
                    scan_type        TEXT NOT NULL DEFAULT 'standard',
                    filename         TEXT,
                    zip_hash         TEXT,
                    code_hash        TEXT,
                    findings         TEXT,
                    finding_fps      TEXT,
                    summary          TEXT,
                    signature        TEXT,
                    sovereign_pubkey TEXT
                )
            """)
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audits_zip_hash  ON audits (zip_hash)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audits_code_hash ON audits (code_hash)"
            )
            await conn.commit()
        logger.info(f"SQLite database ready at {_sqlite_path}")

    else:
        import asyncpg
        ssl_arg = DB_SSL if DB_SSL in ("require", "verify-ca", "verify-full") else None
        _pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=1,
            max_size=5,
            ssl=ssl_arg,
            command_timeout=60,
        )
        async with _pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS audits (
                    audit_id         TEXT PRIMARY KEY,
                    timestamp        TIMESTAMPTZ NOT NULL,
                    scan_type        TEXT NOT NULL DEFAULT 'standard',
                    filename         TEXT,
                    zip_hash         TEXT,
                    code_hash        TEXT,
                    findings         JSONB,
                    finding_fps      JSONB,
                    summary          JSONB,
                    signature        TEXT,
                    sovereign_pubkey TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_audits_zip_hash  ON audits (zip_hash);
                CREATE INDEX IF NOT EXISTS idx_audits_code_hash ON audits (code_hash);
            """)
        logger.info("PostgreSQL database ready")


async def close() -> None:
    if DB_BACKEND != "sqlite" and _pool is not None:
        await _pool.close()
