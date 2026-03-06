# """
# Claude AI Triage Engine
# Sends raw log chains to Claude claude-sonnet-4-20250514 and returns structured triage JSON.
# """

# import os
# import json
# import logging
# from datetime import datetime
# import anthropic

# log = logging.getLogger(__name__)

# SYSTEM_PROMPT = """You are an expert Tier 2 SOC analyst and threat intelligence specialist working for KPMG's Managed Detection & Response team.

# Your job is to analyse raw security log chains from Microsoft Sentinel and produce a structured triage report. You have deep knowledge of:
# - MITRE ATT&CK framework (Enterprise)
# - Windows Event Log forensics
# - Network traffic analysis
# - Malware behaviour patterns
# - APT tactics and threat actor TTPs

# You always respond with ONLY valid JSON — no preamble, no markdown fences, no explanation outside the JSON structure.
# """

# TRIAGE_PROMPT_TEMPLATE = """Analyse the following security alert and raw log chain from Microsoft Sentinel.

# Alert Title: {title}
# Source Host: {source_host}
# Source IP: {source_ip}
# External IP: {external_ip}
# Alert Generated: {timestamp}

# Raw Log Chain:
# {raw_logs}

# Produce a complete triage report as a single JSON object with EXACTLY this structure:

# {{
#   "classification": "True Positive" | "False Positive" | "Needs Review",
#   "confidence": <integer 0-100>,
#   "severity": "Critical" | "High" | "Medium" | "Low",
#   "triage_summary": "<3-4 sentences: what happened, why classified this way, key evidence>",
#   "attack_story": "<1-2 paragraphs: tell the full attack chain as a narrative, written for a non-technical manager>",
#   "mitre_tactics": [
#     {{
#       "id": "TA0006",
#       "name": "Credential Access",
#       "technique_id": "T1110.001",
#       "technique_name": "Brute Force: Password Guessing",
#       "description": "<how this tactic manifests in these specific logs>"
#     }}
#   ],
#   "timeline": [
#     {{
#       "id": "EVT-001",
#       "timestamp": "<ISO8601 from the log>",
#       "event_type": "<short label e.g. Authentication Failure>",
#       "description": "<plain English, 1 sentence, what happened and why it matters>",
#       "raw_log": "<the relevant raw log line as a string>",
#       "mitre_tactic": "<e.g. TA0006 - Credential Access>",
#       "severity_level": <1-5 integer>,
#       "is_pivot_point": <true | false>
#     }}
#   ],
#   "recommended_action": "<numbered list of specific, actionable steps the L1 analyst should take right now>",
#   "pivotal_event": "<id of the single most critical timeline event, e.g. EVT-003>"
# }}

# Rules:
# - timeline must have one entry per distinct log event, ordered chronologically
# - exactly ONE event must have is_pivot_point: true — this is the moment the attack became real
# - pivotal_event must match the id of that event
# - confidence above 85 only for clear, unambiguous attacks
# - if classifying as False Positive, still complete all fields but set severity to Low
# - triage_summary must reference specific IPs, usernames, process names from the logs
# """


# class ClaudeTriageEngine:
#     def __init__(self):
#         self.client = anthropic.AsyncAnthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

#     async def triage(self, raw_alert: dict) -> dict:
#         """
#         raw_alert must contain:
#           sentinel_id, title, source_host, source_ip, external_ip, raw_logs (list of dicts)
#         Returns the structured triage dict.
#         """
#         raw_logs_str = json.dumps(raw_alert.get("raw_logs", []), indent=2)

#         prompt = TRIAGE_PROMPT_TEMPLATE.format(
#             title=raw_alert.get("title", "Unknown Alert"),
#             source_host=raw_alert.get("source_host", "Unknown"),
#             source_ip=raw_alert.get("source_ip", "Unknown"),
#             external_ip=raw_alert.get("external_ip", "N/A"),
#             timestamp=raw_alert.get("timestamp", datetime.utcnow().isoformat()),
#             raw_logs=raw_logs_str,
#         )

#         log.info(f"Sending alert '{raw_alert.get('title')}' to Claude for triage...")

#         message = await self.client.messages.create(
#             model="claude-haiku-4-5-20251001",
#             max_tokens=4096,
#             system=SYSTEM_PROMPT,
#             messages=[{"role": "user", "content": prompt}],
#         )

#         response_text = message.content[0].text.strip()

#         # Strip markdown fences if model accidentally adds them
#         if response_text.startswith("```"):
#             lines = response_text.split("\n")
#             response_text = "\n".join(lines[1:-1])

#         try:
#             triage = json.loads(response_text)
#         except json.JSONDecodeError as e:
#             log.error(f"Claude returned invalid JSON: {e}\nRaw: {response_text[:500]}")
#             # Fallback — return a safe default so the alert is still saved
#             triage = _fallback_triage(raw_alert, response_text)

#         log.info(f"Triage complete: {triage['classification']} | {triage['severity']} | {triage['confidence']}% confidence")
#         return triage


# def _fallback_triage(raw_alert: dict, raw_response: str) -> dict:
#     """Return a minimal valid triage if JSON parsing fails."""
#     return {
#         "classification": "Needs Review",
#         "confidence": 50,
#         "severity": "Medium",
#         "triage_summary": "Automated triage encountered a parsing error. Manual review required. Raw AI response has been preserved in analyst_note.",
#         "attack_story": "Triage parsing failed — please review raw logs manually.",
#         "mitre_tactics": [],
#         "timeline": [],
#         "recommended_action": "1. Review raw logs manually.\n2. Re-trigger triage via POST /dev/triage.\n3. Escalate to L2 if unsure.",
#         "pivotal_event": None,
#         "_raw_claude_response": raw_response[:1000],
#     }

"""
Claude AI Triage Engine — with KQL query generation for pivotal events.
Uses Anthropic claude-sonnet-4-20250514.
"""

import os
import json
import logging
from datetime import datetime, timezone
import anthropic

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an expert Tier 2 SOC analyst and threat intelligence specialist working for KPMG's Managed Detection & Response team.

You have deep expertise in:
- MITRE ATT&CK framework (Enterprise)
- Windows Event Log forensics (Event IDs, Sysmon, Security logs)
- KQL (Kusto Query Language) for Microsoft Sentinel / Log Analytics
- Network traffic analysis and malware behaviour patterns
- APT tactics and threat actor TTPs

CRITICAL: Respond with ONLY a valid JSON object. No markdown fences, no explanation, no text before or after. Start with { and end with }."""

TRIAGE_PROMPT_TEMPLATE = """Analyse this security alert and raw log chain. Produce a complete triage report.

Alert Title: {title}
Source Host: {source_host}
Source IP: {source_ip}
External IP: {external_ip}
Alert Generated: {timestamp}

Raw Log Chain:
{raw_logs}

Respond with ONLY this exact JSON structure:

{{
  "classification": "True Positive",
  "confidence": 95,
  "severity": "Critical",
  "triage_summary": "3-4 sentences describing what happened, why classified this way, key evidence including specific IPs, usernames, process names from the logs.",
  "attack_story": "1-2 paragraphs narrating the full attack chain in plain English for a non-technical manager.",
  "mitre_tactics": [
    {{
      "id": "TA0006",
      "name": "Credential Access",
      "technique_id": "T1110.001",
      "technique_name": "Brute Force: Password Guessing",
      "description": "How this tactic appears in these specific logs."
    }}
  ],
  "timeline": [
    {{
      "id": "EVT-001",
      "timestamp": "2024-01-15T14:22:14Z",
      "event_type": "Authentication Failure",
      "description": "One plain English sentence: what happened and why it matters.",
      "raw_log": "the raw log entry as a string",
      "mitre_tactic": "TA0006 - Credential Access",
      "severity_level": 3,
      "is_pivot_point": false
    }}
  ],
  "recommended_action": "1. First action.\\n2. Second action.\\n3. Third action.",
  "pivotal_event": "EVT-001",
  "pivotal_kql": "SOCCopilotLogs_CL\\n| where TimeGenerated between (datetime(2024-01-15T14:29:00Z) .. datetime(2024-01-15T14:32:00Z))\\n| where WorkstationName_s == \\"WKSTN-JOHNSON-01\\"\\n| where AccountName_s == \\"mjohnson\\"\\n| where EventID_d == 4624\\n| project TimeGenerated, EventID_d, AccountName_s, IpAddress_s, WorkstationName_s, LogonType_d\\n| order by TimeGenerated asc"
}}

Rules:
- classification must be exactly: True Positive, False Positive, or Needs Review
- severity must be exactly: Critical, High, Medium, or Low
- confidence is integer 0-100
- timeline has one entry per distinct log event, in chronological order
- exactly ONE timeline event has is_pivot_point: true — the moment the attack became real/confirmed
- pivotal_event matches the id of the event where is_pivot_point is true
- pivotal_kql is a ready-to-run KQL query that will find EXACTLY the pivotal event log in Microsoft Sentinel
  - Use the table SOCCopilotLogs_CL (our custom log table)
  - Filter by the exact timestamp window (±2 minutes around the pivotal event)
  - Filter by specific field values from the pivotal log (host, account, EventID, IP, etc.)
  - Use _s suffix for string fields, _d suffix for numeric fields, _b for boolean
  - Always include: | project to select relevant columns, | order by TimeGenerated asc
  - The query must be a string with real newlines escaped as \\n
- triage_summary must reference specific values (IPs, usernames, process names) from the logs
- for False Positive: set severity to Low, confidence above 85"""


VALID_CLASSIFICATIONS = {"True Positive", "False Positive", "Needs Review"}
VALID_SEVERITIES      = {"Critical", "High", "Medium", "Low"}


class ClaudeTriageEngine:
    def __init__(self):
        self.client = anthropic.AsyncAnthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    async def triage(self, raw_alert: dict) -> dict:
        raw_logs_str = json.dumps(raw_alert.get("raw_logs", []), indent=2)

        prompt = TRIAGE_PROMPT_TEMPLATE.format(
            title=raw_alert.get("title", "Unknown Alert"),
            source_host=raw_alert.get("source_host", "Unknown"),
            source_ip=raw_alert.get("source_ip", "Unknown"),
            external_ip=raw_alert.get("external_ip", "N/A"),
            timestamp=raw_alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
            raw_logs=raw_logs_str,
        )

        log.info(f"Sending '{raw_alert.get('title')}' to Claude for triage...")

        message = await self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        response_text = message.content[0].text.strip()

        # Strip accidental markdown fences
        if response_text.startswith("```"):
            lines = response_text.split("\n")
            response_text = "\n".join(lines[1:-1])

        try:
            triage = json.loads(response_text)
        except json.JSONDecodeError as e:
            log.error(f"Claude returned invalid JSON: {e}")
            return _fallback_triage(raw_alert, response_text)

        triage = _validate(triage, raw_alert)
        log.info(f"Triage complete: {triage['classification']} | {triage['severity']} | {triage['confidence']}%")
        return triage


def _validate(data: dict, raw_alert: dict) -> dict:
    if data.get("classification") not in VALID_CLASSIFICATIONS:
        data["classification"] = "Needs Review"
    if data.get("severity") not in VALID_SEVERITIES:
        data["severity"] = "Medium"
    try:
        data["confidence"] = max(0, min(100, int(data.get("confidence", 50))))
    except (TypeError, ValueError):
        data["confidence"] = 50

    for field in ("triage_summary", "attack_story", "recommended_action"):
        if not isinstance(data.get(field), str) or not data[field].strip():
            data[field] = f"[{field} not generated — review raw logs manually]"

    if not isinstance(data.get("timeline"), list):
        data["timeline"] = []
    if not isinstance(data.get("mitre_tactics"), list):
        data["mitre_tactics"] = []

    # Ensure exactly one pivot point
    timeline = data["timeline"]
    pivots = [e for e in timeline if e.get("is_pivot_point")]
    if not pivots and timeline:
        timeline.sort(key=lambda e: e.get("severity_level", 0), reverse=True)
        timeline[0]["is_pivot_point"] = True

    pivot_ids = {e["id"] for e in timeline if e.get("is_pivot_point") and "id" in e}
    if pivot_ids:
        data["pivotal_event"] = next(iter(pivot_ids))
    elif not data.get("pivotal_event") and timeline:
        data["pivotal_event"] = timeline[0].get("id", "EVT-001")

    # Generate fallback KQL if Claude didn't produce one
    if not data.get("pivotal_kql"):
        data["pivotal_kql"] = _generate_fallback_kql(raw_alert, data)

    return data


def _generate_fallback_kql(raw_alert: dict, triage: dict) -> str:
    host = raw_alert.get("source_host", "UNKNOWN")
    ip   = raw_alert.get("source_ip", "")
    ts   = raw_alert.get("timestamp", datetime.now(timezone.utc).isoformat())
    return (
        f'SOCCopilotLogs_CL\n'
        f'| where TimeGenerated between (datetime({ts[:19]}Z) .. now())\n'
        f'| where WorkstationName_s == "{host}" or SourceHost_s == "{host}"\n'
        f'| order by TimeGenerated asc'
    )


def _fallback_triage(raw_alert: dict, raw_response: str) -> dict:
    return {
        "classification": "Needs Review",
        "confidence": 40,
        "severity": "Medium",
        "triage_summary": f"Automated triage could not complete for '{raw_alert.get('title', 'Unknown')}'. Manual analyst review required.",
        "attack_story": "Triage failed — review raw logs and re-trigger manually.",
        "mitre_tactics": [],
        "timeline": [],
        "recommended_action": "1. Review raw logs manually.\n2. Re-trigger triage.\n3. Escalate to L2 if suspicious.",
        "pivotal_event": None,
        "pivotal_kql": _generate_fallback_kql(raw_alert, {}),
    }