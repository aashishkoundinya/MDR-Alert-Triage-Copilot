"""
KPMG MDR SOC Alert Triage Copilot — FastAPI Backend
Local mode: log generator POSTs alerts directly. No Azure/Sentinel needed.
"""

import os
import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# ── Lazy imports so startup doesn't crash if a dep is missing ─────────────────
from db import Database
from claude_triage import ClaudeTriageEngine
from slack_notifier import SlackNotifier

app = FastAPI(title="KPMG MDR SOC Copilot", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db     = Database()
claude = ClaudeTriageEngine()
slack  = SlackNotifier()


@app.on_event("startup")
async def startup():
    await db.init()
    log.info("✅ SOC Copilot backend started (local mode — no Sentinel required).")


# ─────────────────────────────────────────────────────────────────────────────
# CORE ENDPOINT: Log generator POSTs raw alert data here
# This replaces the Sentinel polling loop for local development
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/ingest")
async def ingest_alert(payload: dict, background_tasks: BackgroundTasks):
    """
    Receives a raw alert from the log generator.
    Runs Claude triage in background, saves to DB, posts Slack if Critical/High.
    """
    sentinel_id = payload.get("sentinel_id", "")
    if not sentinel_id:
        raise HTTPException(status_code=400, detail="sentinel_id is required")

    exists = await db.alert_exists(sentinel_id)
    if exists:
        return {"message": "duplicate — already ingested", "sentinel_id": sentinel_id}

    # Triage in background so the log generator gets an instant 200 response
    background_tasks.add_task(_triage_and_save, payload)
    return {"message": "accepted", "sentinel_id": sentinel_id}


async def _triage_and_save(raw: dict):
    try:
        log.info(f"Triaging: {raw.get('title')}")
        triage    = await claude.triage(raw)
        alert_id  = await db.save_alert(raw, triage)
        # if triage["severity"] in ("Critical", "High"):
        #     await slack.post_new_alert(alert_id, raw, triage)
        log.info(f"✅ Alert saved: {alert_id} | {triage['classification']} | {triage['severity']} | {triage['confidence']}%")
    except Exception as e:
        log.error(f"Triage/save failed: {e}", exc_info=True)


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/alerts")
async def list_alerts(
    severity:       Optional[str] = None,
    classification: Optional[str] = None,
    status:         Optional[str] = None,
    limit:          int = 100,
):
    alerts = await db.get_alerts(
        severity=severity, classification=classification,
        status=status, limit=limit
    )
    return {"alerts": alerts, "total": len(alerts)}


@app.get("/alerts/{alert_id}")
async def get_alert(alert_id: str):
    alert = await db.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.post("/alerts/{alert_id}/escalate")
async def escalate_alert(alert_id: str, background_tasks: BackgroundTasks, body: dict = {}):
    alert = await db.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert["status"] == "Escalated":
        return {"message": "Already escalated", "alert_id": alert_id}
    await db.update_status(alert_id, "Escalated")
    analyst_note = body.get("analyst_note")
    background_tasks.add_task(slack.post_escalation, alert_id, alert, analyst_note)
    log.info(f"🚨 Alert {alert_id} escalated to L2 — Slack notified.")
    return {"message": "Escalated to L2 and posted to Slack", "alert_id": alert_id}


@app.post("/alerts/{alert_id}/dismiss")
async def dismiss_alert(alert_id: str):
    alert = await db.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    await db.update_status(alert_id, "Dismissed")
    await db.update_classification(alert_id, "False Positive")
    return {"message": "Alert dismissed", "alert_id": alert_id}


@app.get("/metrics")
async def get_metrics():
    return await db.get_metrics()