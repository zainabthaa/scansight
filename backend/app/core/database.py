"""SQLite persistence: scan history plus caches for NVD data and AI explanations."""

from __future__ import annotations

import json
import time
from pathlib import Path

import aiosqlite

from app.models import ScanJob, ScanStatus, ScanSummary

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    status      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans (created_at DESC);

CREATE TABLE IF NOT EXISTS cve_cache (
    cve_id      TEXT PRIMARY KEY,
    data        TEXT NOT NULL,
    fetched_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_cache (
    cve_id      TEXT NOT NULL,
    provider    TEXT NOT NULL,
    model       TEXT NOT NULL,
    data        TEXT NOT NULL,
    created_at  REAL NOT NULL,
    PRIMARY KEY (cve_id, provider, model)
);
"""


class Database:
    def __init__(self, path: str):
        self.path = path

    async def init(self) -> None:
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.path) as db:
            await db.executescript(SCHEMA)
            await db.commit()

    # --- scans ---------------------------------------------------------------------------

    async def save_scan(self, job: ScanJob) -> None:
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                "INSERT INTO scans (id, target, status, created_at, data) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET status = excluded.status, data = excluded.data",
                (job.id, job.target, job.status.value, job.created_at.isoformat(),
                 job.model_dump_json()),
            )
            await db.commit()

    async def get_scan(self, scan_id: str) -> ScanJob | None:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute("SELECT data FROM scans WHERE id = ?", (scan_id,))
            row = await cursor.fetchone()
        return ScanJob.model_validate_json(row[0]) if row else None

    async def list_scans(self, limit: int = 50) -> list[ScanSummary]:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute(
                "SELECT data FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
            )
            rows = await cursor.fetchall()
        summaries = []
        for (data,) in rows:
            job = ScanJob.model_validate_json(data)
            ports = [p for h in job.result.hosts for p in h.ports] if job.result else []
            summaries.append(
                ScanSummary(
                    id=job.id,
                    target=job.target,
                    status=job.status,
                    created_at=job.created_at,
                    open_ports=sum(1 for p in ports if p.state == "open"),
                    cve_count=sum(len(p.cves) for p in ports),
                    severity_counts=job.severity_counts,
                )
            )
        return summaries

    async def fail_unfinished(self) -> int:
        """Mark scans left running by a previous process (crash/restart) as failed."""
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute(
                "SELECT data FROM scans WHERE status IN ('queued', 'running', 'enriching')"
            )
            rows = await cursor.fetchall()
        for (data,) in rows:
            job = ScanJob.model_validate_json(data)
            job.status = ScanStatus.failed
            job.error = "Interrupted by a server restart"
            await self.save_scan(job)
        return len(rows)

    async def delete_scan(self, scan_id: str) -> bool:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            await db.commit()
            return cursor.rowcount > 0

    # --- NVD cache -----------------------------------------------------------------------

    async def get_cve(self, cve_id: str, max_age_seconds: int) -> dict | None:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute(
                "SELECT data, fetched_at FROM cve_cache WHERE cve_id = ?", (cve_id,)
            )
            row = await cursor.fetchone()
        if row and time.time() - row[1] < max_age_seconds:
            return json.loads(row[0])
        return None

    async def put_cve(self, cve_id: str, data: dict) -> None:
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO cve_cache (cve_id, data, fetched_at) VALUES (?, ?, ?)",
                (cve_id, json.dumps(data), time.time()),
            )
            await db.commit()

    # --- AI cache ------------------------------------------------------------------------

    async def get_explanation(self, cve_id: str, provider: str, model: str) -> dict | None:
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute(
                "SELECT data FROM ai_cache WHERE cve_id = ? AND provider = ? AND model = ?",
                (cve_id, provider, model),
            )
            row = await cursor.fetchone()
        return json.loads(row[0]) if row else None

    async def put_explanation(self, cve_id: str, provider: str, model: str, data: dict) -> None:
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO ai_cache (cve_id, provider, model, data, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (cve_id, provider, model, json.dumps(data), time.time()),
            )
            await db.commit()
