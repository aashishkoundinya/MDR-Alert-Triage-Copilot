"""
Slack Notifier — Block Kit rich messages for new Critical/High alerts and L2 escalations.
"""

import os
import logging
from typing import Optional
import httpx

log = logging.getLogger(__name__)

SEV_EMOJI = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🔵",
}
CLS_EMOJI = {
    "True Positive":  "⚠️",
    "False Positive": "✅",
    "Needs Review":   "🔍",
}


class SlackNotifier:
    """
    Posts Block Kit messages to a Slack webhook.

    Required env vars:
        SLACK_WEBHOOK_URL          — Incoming Webhook URL
        DASHBOARD_BASE_URL         — e.g. https://soc.yourdomain.com  (no trailing slash)
    """

    def __init__(self):
        self.webhook_url   = os.environ.get("SLACK_WEBHOOK_URL", "")
        self.dashboard_url = os.environ.get("DASHBOARD_BASE_URL", "https://soc.kpmg.internal")

    async def _post(self, payload: dict):
        if not self.webhook_url:
            log.warning("SLACK_WEBHOOK_URL not set — skipping Slack notification.")
            return
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(self.webhook_url, json=payload)
            if resp.status_code != 200:
                log.error(f"Slack webhook failed: {resp.status_code} {resp.text}")
            else:
                log.info("Slack notification sent.")

    # ── New Critical/High Alert ───────────────────────────────────────────────
    async def post_new_alert(self, alert_id: str, raw: dict, triage: dict):
        sev = triage["severity"]
        cls = triage["classification"]
        emoji = SEV_EMOJI.get(sev, "⚪")
        cls_emoji = CLS_EMOJI.get(cls, "🔍")
        conf = triage["confidence"]
        conf_bar = self._conf_bar(conf)
        alert_url = f"{self.dashboard_url}/alerts/{alert_id}"

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {sev.upper()} ALERT — {raw.get('title', 'New Alert')}",
                    "emoji": True,
                }
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Alert ID*\n`{alert_id}`"},
                    {"type": "mrkdwn", "text": f"*Severity*\n{emoji} {sev}"},
                    {"type": "mrkdwn", "text": f"*AI Classification*\n{cls_emoji} {cls}"},
                    {"type": "mrkdwn", "text": f"*Confidence*\n{conf_bar} {conf}%"},
                    {"type": "mrkdwn", "text": f"*Source Host*\n`{raw.get('source_host', 'Unknown')}`"},
                    {"type": "mrkdwn", "text": f"*Source IP*\n`{raw.get('source_ip', 'Unknown')}`"},
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*AI Triage Summary*\n{triage['triage_summary']}",
                }
            },
        ]

        # MITRE tactics if present
        if triage.get("mitre_tactics"):
            tactic_labels = " ".join([
                f"`{t['id']} {t['name']}`" for t in triage["mitre_tactics"][:4]
            ])
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*MITRE ATT&CK*\n{tactic_labels}"}
            })

        blocks += [
            {"type": "divider"},
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🔍 View in Dashboard", "emoji": True},
                        "url": alert_url,
                        "style": "primary",
                    }
                ]
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"KPMG MDR SOC Copilot • Auto-triaged by Claude AI • <{alert_url}|{alert_id}>"}
                ]
            }
        ]

        await self._post({
            "text": f"{emoji} New {sev} Alert: {raw.get('title', 'Unknown')} — {cls} ({conf}% confidence)",
            "blocks": blocks,
        })

    # ── L2 Escalation ─────────────────────────────────────────────────────────
    async def post_escalation(self, alert_id: str, alert: dict, analyst_note: Optional[str] = None):
        sev = alert.get("severity", "Unknown")
        emoji = SEV_EMOJI.get(sev, "⚪")
        alert_url = f"{self.dashboard_url}/alerts/{alert_id}"

        note_block = []
        if analyst_note:
            note_block = [{
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Analyst Note*\n_{analyst_note}_"}
            }]

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 L2 ESCALATION — {alert.get('title', 'Alert')}",
                    "emoji": True,
                }
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Alert ID*\n`{alert_id}`"},
                    {"type": "mrkdwn", "text": f"*Severity*\n{emoji} {sev}"},
                    {"type": "mrkdwn", "text": f"*Source Host*\n`{alert.get('source_host', 'Unknown')}`"},
                    {"type": "mrkdwn", "text": f"*Classification*\n{alert.get('classification', 'Unknown')}"},
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Triage Summary*\n{alert.get('triage_summary', 'See dashboard for details.')}",
                }
            },
            *note_block,
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Recommended Actions*\n{alert.get('recommended_action', 'See dashboard.')}",
                }
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🔍 View Full Timeline", "emoji": True},
                        "url": alert_url,
                        "style": "danger",
                    }
                ]
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"⚠️ *Action required from L2 team* • Escalated via KPMG MDR SOC Copilot • <{alert_url}|{alert_id}>"}
                ]
            }
        ]

        await self._post({
            "text": f"🚨 L2 Escalation: {alert.get('title', 'Alert')} [{sev}] — {alert_id}",
            "blocks": blocks,
        })

    # ── Helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _conf_bar(confidence: int) -> str:
        filled = round(confidence / 10)
        return "█" * filled + "░" * (10 - filled)