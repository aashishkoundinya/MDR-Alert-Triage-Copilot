"""
Database layer — async PostgreSQL via asyncpg.
Handles schema init, alert CRUD, and metrics aggregation.
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Optional
import asyncpg

log = logging.getLogger(__name__)


class Database:
    def __init__(self):
        self.pool: Optional[asyncpg.Pool] = None

    async def init(self):
        dsn = os.environ["DATABASE_URL"]  # e.g. postgresql://user:pass@host:5432/socdb
        self.pool = await asyncpg.create_pool(dsn, min_size=2, max_size=10)
        await self._create_tables()
        log.info("Database ready.")

    async def _create_tables(self):
        async with self.pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id              TEXT PRIMARY KEY,
                    sentinel_id     TEXT UNIQUE NOT NULL,
                    title           TEXT NOT NULL,
                    source_host     TEXT,
                    source_ip       TEXT,
                    external_ip     TEXT,
                    raw_logs        JSONB,

                    -- AI triage fields
                    classification  TEXT,           -- True Positive | False Positive | Needs Review
                    confidence      INTEGER,         -- 0-100
                    severity        TEXT,            -- Critical | High | Medium | Low
                    triage_summary  TEXT,
                    attack_story    TEXT,
                    mitre_tactics   JSONB,           -- [{id, name, description, mapping}]
                    timeline        JSONB,           -- [{timestamp, event_type, description, ...}]
                    recommended_action TEXT,
                    pivotal_event   TEXT,

                    -- Workflow
                    status          TEXT DEFAULT 'New',   -- New | In Review | Escalated | Dismissed
                    analyst_note    TEXT,
                    created_at      TIMESTAMPTZ DEFAULT NOW(),
                    updated_at      TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_severity    ON alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_alerts_status      ON alerts(status);
                CREATE INDEX IF NOT EXISTS idx_alerts_created_at  ON alerts(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_sentinel_id ON alerts(sentinel_id);
            """)

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _row_to_dict(self, row) -> dict:
        if row is None:
            return None
        d = dict(row)
        # Parse JSONB fields back to Python objects
        for field in ("raw_logs", "mitre_tactics", "timeline"):
            if isinstance(d.get(field), str):
                d[field] = json.loads(d[field])
        # Serialise datetimes
        for field in ("created_at", "updated_at"):
            if isinstance(d.get(field), datetime):
                d[field] = d[field].isoformat()
        return d

    # ── Writes ────────────────────────────────────────────────────────────────
    async def alert_exists(self, sentinel_id: str) -> bool:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id FROM alerts WHERE sentinel_id = $1", sentinel_id
            )
            return row is not None

    async def save_alert(self, raw: dict, triage: dict) -> str:
        """Persist a new alert with its triage data. Returns the internal alert ID."""
        import uuid
        alert_id = f"ALT-{datetime.now().strftime('%Y-%m%d')}-{str(uuid.uuid4())[:6].upper()}"

        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO alerts (
                    id, sentinel_id, title, source_host, source_ip, external_ip, raw_logs,
                    classification, confidence, severity, triage_summary, attack_story,
                    mitre_tactics, timeline, recommended_action, pivotal_event, status
                ) VALUES (
                    $1,$2,$3,$4,$5,$6,$7,
                    $8,$9,$10,$11,$12,
                    $13,$14,$15,$16,$17
                )
            """,
                alert_id,
                raw["sentinel_id"],
                raw.get("title", "Unnamed Alert"),
                raw.get("source_host"),
                raw.get("source_ip"),
                raw.get("external_ip"),
                json.dumps(raw.get("raw_logs", [])),
                triage["classification"],
                triage["confidence"],
                triage["severity"],
                triage["triage_summary"],
                triage["attack_story"],
                json.dumps(triage["mitre_tactics"]),
                json.dumps(triage["timeline"]),
                triage["recommended_action"],
                triage.get("pivotal_event"),
                "New",
            )
        log.info(f"Saved alert {alert_id}")
        return alert_id

    async def update_status(self, alert_id: str, status: str):
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE alerts SET status=$1, updated_at=NOW() WHERE id=$2",
                status, alert_id
            )

    async def update_classification(self, alert_id: str, classification: str):
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE alerts SET classification=$1, updated_at=NOW() WHERE id=$2",
                classification, alert_id
            )

    # ── Reads ─────────────────────────────────────────────────────────────────
    async def get_alerts(
        self,
        severity: Optional[str] = None,
        classification: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> list:
        conditions = []
        params = []
        i = 1
        if severity:
            conditions.append(f"severity = ${i}"); params.append(severity); i+=1
        if classification:
            conditions.append(f"classification = ${i}"); params.append(classification); i+=1
        if status:
            conditions.append(f"status = ${i}"); params.append(status); i+=1

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)

        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                f"""SELECT id, sentinel_id, title, source_host, source_ip, external_ip,
                           classification, confidence, severity, triage_summary,
                           mitre_tactics, status, created_at, updated_at
                    FROM alerts {where}
                    ORDER BY created_at DESC
                    LIMIT ${i}""",
                *params
            )
        return [self._row_to_dict(r) for r in rows]

    async def get_alert(self, alert_id: str) -> Optional[dict]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM alerts WHERE id=$1", alert_id
            )
        return self._row_to_dict(row)

    async def get_metrics(self) -> dict:
        async with self.pool.acquire() as conn:
            total       = await conn.fetchval("SELECT COUNT(*) FROM alerts")
            tp          = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE classification='True Positive'")
            fp          = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE classification='False Positive'")
            nr          = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE classification='Needs Review'")
            critical    = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE severity='Critical'")
            high        = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE severity='High'")
            escalated   = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE status='Escalated'")
            avg_conf    = await conn.fetchval("SELECT ROUND(AVG(confidence)) FROM alerts")

            hourly_rows = await conn.fetch("""
                SELECT DATE_TRUNC('hour', created_at) AS hour, COUNT(*) AS count
                FROM alerts
                WHERE created_at >= NOW() - INTERVAL '24 hours'
                GROUP BY 1 ORDER BY 1
            """)

            mitre_rows = await conn.fetch("""
                SELECT tactic->>'name' AS tactic_name, COUNT(*) AS cnt
                FROM alerts, jsonb_array_elements(mitre_tactics) AS tactic
                GROUP BY 1 ORDER BY 2 DESC LIMIT 5
            """)

        return {
            "total": total,
            "true_positive": tp,
            "false_positive": fp,
            "needs_review": nr,
            "critical": critical,
            "high": high,
            "escalated": escalated,
            "avg_confidence": int(avg_conf or 0),
            "tp_rate": round((tp / total * 100) if total else 0, 1),
            "hourly_volume": [{"hour": str(r["hour"]), "count": r["count"]} for r in hourly_rows],
            "top_mitre_tactics": [{"name": r["tactic_name"], "count": r["cnt"]} for r in mitre_rows],
        }