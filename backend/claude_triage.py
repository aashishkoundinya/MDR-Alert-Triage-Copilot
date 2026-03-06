"""
Claude AI Triage Engine
Sends raw log chains to Claude claude-sonnet-4-20250514 and returns structured triage JSON.
"""

import os
import json
import logging
from datetime import datetime
import anthropic

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an expert Tier 2 SOC analyst and threat intelligence specialist working for KPMG's Managed Detection & Response team.

Your job is to analyse raw security log chains from Microsoft Sentinel and produce a structured triage report. You have deep knowledge of:
- MITRE ATT&CK framework (Enterprise)
- Windows Event Log forensics
- Network traffic analysis
- Malware behaviour patterns
- APT tactics and threat actor TTPs

You always respond with ONLY valid JSON — no preamble, no markdown fences, no explanation outside the JSON structure.
"""

TRIAGE_PROMPT_TEMPLATE = """Analyse the following security alert and raw log chain from Microsoft Sentinel.

Alert Title: {title}
Source Host: {source_host}
Source IP: {source_ip}
External IP: {external_ip}
Alert Generated: {timestamp}

Raw Log Chain:
{raw_logs}

Produce a complete triage report as a single JSON object with EXACTLY this structure:

{{
  "classification": "True Positive" | "False Positive" | "Needs Review",
  "confidence": <integer 0-100>,
  "severity": "Critical" | "High" | "Medium" | "Low",
  "triage_summary": "<3-4 sentences: what happened, why classified this way, key evidence>",
  "attack_story": "<1-2 paragraphs: tell the full attack chain as a narrative, written for a non-technical manager>",
  "mitre_tactics": [
    {{
      "id": "TA0006",
      "name": "Credential Access",
      "technique_id": "T1110.001",
      "technique_name": "Brute Force: Password Guessing",
      "description": "<how this tactic manifests in these specific logs>"
    }}
  ],
  "timeline": [
    {{
      "id": "EVT-001",
      "timestamp": "<ISO8601 from the log>",
      "event_type": "<short label e.g. Authentication Failure>",
      "description": "<plain English, 1 sentence, what happened and why it matters>",
      "raw_log": "<the relevant raw log line as a string>",
      "mitre_tactic": "<e.g. TA0006 - Credential Access>",
      "severity_level": <1-5 integer>,
      "is_pivot_point": <true | false>
    }}
  ],
  "recommended_action": "<numbered list of specific, actionable steps the L1 analyst should take right now>",
  "pivotal_event": "<id of the single most critical timeline event, e.g. EVT-003>"
}}

Rules:
- timeline must have one entry per distinct log event, ordered chronologically
- exactly ONE event must have is_pivot_point: true — this is the moment the attack became real
- pivotal_event must match the id of that event
- confidence above 85 only for clear, unambiguous attacks
- if classifying as False Positive, still complete all fields but set severity to Low
- triage_summary must reference specific IPs, usernames, process names from the logs
"""


class ClaudeTriageEngine:
    def __init__(self):
        self.client = anthropic.AsyncAnthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    async def triage(self, raw_alert: dict) -> dict:
        """
        raw_alert must contain:
          sentinel_id, title, source_host, source_ip, external_ip, raw_logs (list of dicts)
        Returns the structured triage dict.
        """
        raw_logs_str = json.dumps(raw_alert.get("raw_logs", []), indent=2)

        prompt = TRIAGE_PROMPT_TEMPLATE.format(
            title=raw_alert.get("title", "Unknown Alert"),
            source_host=raw_alert.get("source_host", "Unknown"),
            source_ip=raw_alert.get("source_ip", "Unknown"),
            external_ip=raw_alert.get("external_ip", "N/A"),
            timestamp=raw_alert.get("timestamp", datetime.utcnow().isoformat()),
            raw_logs=raw_logs_str,
        )

        log.info(f"Sending alert '{raw_alert.get('title')}' to Claude for triage...")

        message = await self.client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        response_text = message.content[0].text.strip()

        # Strip markdown fences if model accidentally adds them
        if response_text.startswith("```"):
            lines = response_text.split("\n")
            response_text = "\n".join(lines[1:-1])

        try:
            triage = json.loads(response_text)
        except json.JSONDecodeError as e:
            log.error(f"Claude returned invalid JSON: {e}\nRaw: {response_text[:500]}")
            # Fallback — return a safe default so the alert is still saved
            triage = _fallback_triage(raw_alert, response_text)

        log.info(f"Triage complete: {triage['classification']} | {triage['severity']} | {triage['confidence']}% confidence")
        return triage


def _fallback_triage(raw_alert: dict, raw_response: str) -> dict:
    """Return a minimal valid triage if JSON parsing fails."""
    return {
        "classification": "Needs Review",
        "confidence": 50,
        "severity": "Medium",
        "triage_summary": "Automated triage encountered a parsing error. Manual review required. Raw AI response has been preserved in analyst_note.",
        "attack_story": "Triage parsing failed — please review raw logs manually.",
        "mitre_tactics": [],
        "timeline": [],
        "recommended_action": "1. Review raw logs manually.\n2. Re-trigger triage via POST /dev/triage.\n3. Escalate to L2 if unsure.",
        "pivotal_event": None,
        "_raw_claude_response": raw_response[:1000],
    }