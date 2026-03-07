"""
KPMG MDR SOC Copilot — Log Generator v2
========================================
- Randomised scenario selection (not sequential)
- ~60% clean/normal logs, ~40% attack scenarios
- Dual output: POST to FastAPI /ingest AND ship to SIEM
- Supported SIEMs: Microsoft Sentinel, Splunk HEC, Wazuh REST API
  Set SIEM_TARGET in .env to: sentinel | splunk | wazuh | none
- Writes synthetic logs to file for Wazuh agent to monitor
  Set LOG_OUTPUT_FILE in .env to the path of the log file
"""

import os
import json
import time
import hmac
import random
import hashlib
import base64
import logging
import asyncio
from datetime import datetime, timezone, timedelta
from email.utils import formatdate
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
BACKEND_URL    = os.environ.get("BACKEND_URL",    "http://localhost:8000")
INGEST_URL     = f"{BACKEND_URL}/ingest"
CYCLE_INTERVAL = int(os.environ.get("CYCLE_INTERVAL", "30"))

# Which SIEM to ship logs to: sentinel | splunk | wazuh | none
SIEM_TARGET    = os.environ.get("SIEM_TARGET", "none").lower()

# ── Log file output (for Wazuh agent file monitoring) ─────────────────────────
# Set LOG_OUTPUT_FILE in .env to enable writing synthetic logs to a file
# Example: LOG_OUTPUT_FILE=C:\MDR-Alert-Triage-Copilot\logs\synthetic.log
LOG_OUTPUT_FILE = os.environ.get("LOG_OUTPUT_FILE", "")

def write_to_log_file(payload: dict):
    """Write each raw log event as a JSON line to the log file for Wazuh monitoring."""
    if not LOG_OUTPUT_FILE:
        return
    try:
        log_path = Path(LOG_OUTPUT_FILE)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            for event in payload.get("raw_logs", []):
                # Tag every event with alert metadata so it's searchable in Wazuh
                tagged_event = {
                    **event,
                    "SOCAlertTitle":  payload.get("title", ""),
                    "SOCSentinelID":  payload.get("sentinel_id", ""),
                    "SOCSourceHost":  payload.get("source_host", ""),
                    "SOCExternalIP":  payload.get("external_ip", ""),
                    "SOCAlertType":   payload.get("type", "unknown"),
                    "SOCTimestamp":   payload.get("timestamp", ""),
                }
                f.write(json.dumps(tagged_event) + "\n")
    except Exception as e:
        log.error(f"  ❌ Failed to write to log file: {e}")

# Microsoft Sentinel (Log Analytics HTTP Data Collector)
SENTINEL_WORKSPACE_ID  = os.environ.get("SENTINEL_WORKSPACE_ID", "")
SENTINEL_WORKSPACE_KEY = os.environ.get("SENTINEL_WORKSPACE_KEY", "")
SENTINEL_LOG_TYPE      = os.environ.get("SENTINEL_LOG_TYPE", "SOCCopilotLogs")

# Splunk HTTP Event Collector
SPLUNK_HEC_URL   = os.environ.get("SPLUNK_HEC_URL", "")
SPLUNK_HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "")
SPLUNK_INDEX     = os.environ.get("SPLUNK_INDEX", "main")
SPLUNK_SOURCE    = os.environ.get("SPLUNK_SOURCE", "soc-copilot")

# Wazuh REST API
WAZUH_API_URL      = os.environ.get("WAZUH_API_URL", "")
WAZUH_API_USER     = os.environ.get("WAZUH_API_USER", "wazuh")
WAZUH_API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "")
WAZUH_AGENT_ID     = os.environ.get("WAZUH_AGENT_ID", "001")

# ── Fixture data ──────────────────────────────────────────────────────────────
INTERNAL_HOSTS = [
    "WKSTN-JOHNSON-01", "WKSTN-MARTINEZ-03", "WKSTN-THOMPSON-08",
    "WKSTN-HARRIS-04",  "WKSTN-CHEN-02",     "SRV-APP-07",
    "SRV-FILE-01",      "DC-PROD-02",         "DC-PROD-01",
    "SRV-EMAIL-01",     "SRV-DB-03",          "WKSTN-PATEL-05",
]
INTERNAL_IPS = {
    "WKSTN-JOHNSON-01":  "192.168.10.45",
    "WKSTN-MARTINEZ-03": "192.168.10.78",
    "WKSTN-THOMPSON-08": "192.168.10.203",
    "WKSTN-HARRIS-04":   "192.168.10.91",
    "WKSTN-CHEN-02":     "192.168.10.34",
    "SRV-APP-07":        "192.168.20.112",
    "SRV-FILE-01":       "192.168.20.55",
    "DC-PROD-02":        "192.168.1.20",
    "DC-PROD-01":        "192.168.1.21",
    "SRV-EMAIL-01":      "192.168.20.30",
    "SRV-DB-03":         "192.168.20.88",
    "WKSTN-PATEL-05":    "192.168.10.112",
}
USERS = ["mjohnson", "lmartinez", "lthompson", "jharris", "jchen",
         "svc-apprunner", "svc-backup", "apatel", "dsmith", "kwilson"]
BENIGN_DOMAINS = [
    "microsoft.com", "office.com", "azure.com", "teams.microsoft.com",
    "google.com", "github.com", "stackoverflow.com", "npmjs.com",
    "pypi.org", "docs.python.org", "zoom.us", "slack.com",
]
PHISHING_DOMAINS = [
    "invoices-kpmg-portal.com", "secure-update-microsoft.net",
    "corp-hr-portal.io",        "office365-verify.com",
]
BENIGN_PROCESSES = [
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Program Files\\Microsoft Office\\Office16\\EXCEL.EXE",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Windows\\explorer.exe",
    "C:\\Program Files\\Microsoft VS Code\\Code.exe",
    "C:\\Windows\\System32\\taskhostw.exe",
    "C:\\Program Files\\Microsoft Office\\Office16\\OUTLOOK.EXE",
]

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def mins_ago(m):
    return (datetime.now(timezone.utc) - timedelta(minutes=m)).isoformat()

def uid():
    return str(int(time.time() * 1000))[-8:]

def rand_pid():
    return random.randint(1000, 65535)


# ══════════════════════════════════════════════════════════════════════════════
# CLEAN / NORMAL LOG GENERATORS (~60% of output)
# ══════════════════════════════════════════════════════════════════════════════

def clean_successful_logon():
    host = random.choice(list(INTERNAL_IPS.keys())[:8])
    user = random.choice(USERS[:7])
    return {
        "type": "clean",
        "sentinel_id": f"CLEAN-LOGON-{uid()}",
        "title": "Normal User Authentication",
        "source_host": host,
        "source_ip": INTERNAL_IPS[host],
        "external_ip": None,
        "timestamp": now_iso(),
        "raw_logs": [{
            "EventID": 4624,
            "TimeGenerated": now_iso(),
            "EventType": "AuthenticationSuccess",
            "AccountName": user,
            "IpAddress": INTERNAL_IPS[host],
            "WorkstationName": host,
            "LogonType": 2,
            "AuthPackage": "Kerberos",
            "LogonProcess": "User32",
            "SubjectUserName": "SYSTEM",
        }]
    }

def clean_dns_queries():
    host = random.choice(list(INTERNAL_IPS.keys())[:8])
    domains = random.sample(BENIGN_DOMAINS, random.randint(2, 5))
    return {
        "type": "clean",
        "sentinel_id": f"CLEAN-DNS-{uid()}",
        "title": "Normal DNS Resolution Activity",
        "source_host": host,
        "source_ip": INTERNAL_IPS[host],
        "external_ip": None,
        "timestamp": now_iso(),
        "raw_logs": [{
            "EventType": "DNSQuery",
            "TimeGenerated": mins_ago(random.randint(0, 3)),
            "SourceHost": host,
            "SourceIP": INTERNAL_IPS[host],
            "QueryName": domain,
            "QueryType": "A",
            "Result": "NoError",
            "ResponseIP": f"104.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
        } for domain in domains]
    }

def clean_process_creation():
    host = random.choice(list(INTERNAL_IPS.keys())[:6])
    user = random.choice(USERS[:6])
    proc = random.choice(BENIGN_PROCESSES)
    return {
        "type": "clean",
        "sentinel_id": f"CLEAN-PROC-{uid()}",
        "title": "Normal Process Execution",
        "source_host": host,
        "source_ip": INTERNAL_IPS[host],
        "external_ip": None,
        "timestamp": now_iso(),
        "raw_logs": [{
            "EventID": 4688,
            "TimeGenerated": now_iso(),
            "EventType": "ProcessCreated",
            "AccountName": user,
            "NewProcessName": proc,
            "ParentImage": "C:\\Windows\\explorer.exe",
            "CommandLine": f'"{proc}"',
            "WorkstationName": host,
            "ProcessId": rand_pid(),
            "IntegrityLevel": "Medium",
        }]
    }

def clean_file_share_access():
    host = random.choice(list(INTERNAL_IPS.keys())[:6])
    user = random.choice(USERS[:6])
    shares = [
        f"\\\\SRV-FILE-01\\Shared\\Projects\\Q{random.randint(1,4)}_Report.docx",
        "\\\\SRV-FILE-01\\Shared\\HR\\Policies\\Leave_Policy.pdf",
        "\\\\SRV-FILE-01\\Shared\\Finance\\Budget_2024.xlsx",
        "\\\\DC-PROD-01\\SYSVOL\\corp.local\\Policies",
    ]
    return {
        "type": "clean",
        "sentinel_id": f"CLEAN-FILE-{uid()}",
        "title": "Normal File Share Access",
        "source_host": host,
        "source_ip": INTERNAL_IPS[host],
        "external_ip": None,
        "timestamp": now_iso(),
        "raw_logs": [{
            "EventID": 4663,
            "TimeGenerated": now_iso(),
            "EventType": "FileAccess",
            "AccountName": user,
            "WorkstationName": host,
            "ObjectName": random.choice(shares),
            "AccessMask": "0x1",
            "ProcessName": random.choice(BENIGN_PROCESSES[:4]),
            "HandleId": hex(random.randint(0x100, 0xFFF)),
        }]
    }

def clean_scheduled_task():
    return {
        "type": "clean",
        "sentinel_id": f"CLEAN-TASK-{uid()}",
        "title": "Scheduled Maintenance Task Execution",
        "source_host": "SRV-APP-07",
        "source_ip": INTERNAL_IPS["SRV-APP-07"],
        "external_ip": None,
        "timestamp": now_iso(),
        "raw_logs": [{
            "EventID": 4698,
            "TimeGenerated": now_iso(),
            "EventType": "ScheduledTaskCreated",
            "AccountName": "svc-backup",
            "TaskName": f"\\Microsoft\\Windows\\{random.choice(['Defrag','WindowsUpdate','DiskCleanup','BackupTask'])}",
            "WorkstationName": "SRV-APP-07",
            "TaskContent": "<Task><Triggers><CalendarTrigger/></Triggers></Task>",
        }, {
            "EventID": 4688,
            "TimeGenerated": now_iso(),
            "EventType": "ProcessCreated",
            "AccountName": "SYSTEM",
            "NewProcessName": "C:\\Windows\\System32\\schtasks.exe",
            "CommandLine": "/run /tn BackupTask",
            "WorkstationName": "SRV-APP-07",
            "ProcessId": rand_pid(),
        }]
    }

def clean_patch_tuesday():
    host = random.choice(list(INTERNAL_IPS.keys())[:6])
    return {
        "type": "clean",
        "sentinel_id": f"CLEAN-PATCH-{uid()}",
        "title": "Windows Update Activity",
        "source_host": host,
        "source_ip": INTERNAL_IPS[host],
        "external_ip": "13.107.4.50",
        "timestamp": now_iso(),
        "raw_logs": [{
            "EventType": "WindowsUpdate",
            "TimeGenerated": now_iso(),
            "SourceHost": host,
            "UpdateTitle": random.choice([
                "2024-01 Cumulative Update for Windows 11",
                "Security Intelligence Update for Windows Defender",
                "Update for Microsoft 365 Apps",
            ]),
            "KBArticle": f"KB{random.randint(4000000,5999999)}",
            "Status": "Downloaded",
            "DownloadSizeMB": random.randint(50, 450),
        }]
    }

def clean_user_logoff():
    host = random.choice(list(INTERNAL_IPS.keys())[:6])
    user = random.choice(USERS[:6])
    return {
        "type": "clean",
        "sentinel_id": f"CLEAN-LOGOFF-{uid()}",
        "title": "Normal User Logoff",
        "source_host": host,
        "source_ip": INTERNAL_IPS[host],
        "external_ip": None,
        "timestamp": now_iso(),
        "raw_logs": [{
            "EventID": 4634,
            "TimeGenerated": now_iso(),
            "EventType": "UserLogoff",
            "AccountName": user,
            "WorkstationName": host,
            "LogonType": 2,
            "SessionDurationMinutes": random.randint(30, 480),
        }]
    }

def clean_service_account_activity():
    return {
        "type": "clean",
        "sentinel_id": f"CLEAN-SVC-{uid()}",
        "title": "Service Account Routine Operation",
        "source_host": "SRV-DB-03",
        "source_ip": INTERNAL_IPS["SRV-DB-03"],
        "external_ip": None,
        "timestamp": now_iso(),
        "raw_logs": [{
            "EventID": 4624,
            "TimeGenerated": now_iso(),
            "EventType": "AuthenticationSuccess",
            "AccountName": "svc-backup",
            "IpAddress": INTERNAL_IPS["SRV-APP-07"],
            "WorkstationName": "SRV-DB-03",
            "LogonType": 5,
            "AuthPackage": "Kerberos",
            "LogonProcess": "Advapi",
        }, {
            "EventID": 4663,
            "TimeGenerated": now_iso(),
            "EventType": "FileAccess",
            "AccountName": "svc-backup",
            "WorkstationName": "SRV-DB-03",
            "ObjectName": "E:\\Backups\\db_backup_latest.bak",
            "AccessMask": "0x2",
            "ProcessName": "C:\\Program Files\\BackupExec\\backup.exe",
        }]
    }

CLEAN_GENERATORS = [
    clean_successful_logon,
    clean_successful_logon,
    clean_dns_queries,
    clean_dns_queries,
    clean_process_creation,
    clean_file_share_access,
    clean_scheduled_task,
    clean_patch_tuesday,
    clean_user_logoff,
    clean_service_account_activity,
]


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK SCENARIO GENERATORS (~40% of output)
# ══════════════════════════════════════════════════════════════════════════════

def scenario_brute_force():
    host        = "WKSTN-JOHNSON-01"
    attacker_ip = "45.142.212.100"
    user        = "mjohnson"
    fail_count  = random.randint(28, 55)
    return {
        "type": "attack",
        "sentinel_id": f"BRUTE-{uid()}",
        "title": "Brute Force Attack → Lateral Movement Detected",
        "source_host": host,
        "source_ip": INTERNAL_IPS[host],
        "external_ip": attacker_ip,
        "timestamp": now_iso(),
        "raw_logs": [{
            "EventID": 4625,
            "TimeGenerated": mins_ago(random.randint(9, 15)),
            "EventType": "AuthenticationFailure",
            "AccountName": user,
            "IpAddress": attacker_ip,
            "WorkstationName": host,
            "FailureReason": "Unknown user name or bad password",
            "LogonType": 3,
            "SubStatus": "0xC000006A",
        } for _ in range(fail_count)] + [
            {
                "EventID": 4624,
                "TimeGenerated": mins_ago(6),
                "EventType": "AuthenticationSuccess",
                "AccountName": user,
                "IpAddress": attacker_ip,
                "WorkstationName": host,
                "LogonType": 3,
                "AuthPackage": "NTLM",
                "Note": f"SUCCESS after {fail_count} failures — attacker authenticated",
            },
            {
                "EventID": 5140,
                "TimeGenerated": mins_ago(4),
                "EventType": "SMBShareAccess",
                "AccountName": user,
                "SourceIP": INTERNAL_IPS[host],
                "TargetHosts": ["DC-PROD-02", "WKSTN-HARRIS-04", "SRV-FILE-01"],
                "ShareName": "\\\\DC-PROD-02\\IPC$",
                "AccessMask": "0x1",
            },
            {
                "EventID": 11,
                "TimeGenerated": mins_ago(2),
                "EventType": "FileCreated",
                "TargetFilename": "C:\\Windows\\Temp\\svchost32.exe",
                "TargetHost": "DC-PROD-02",
                "Hashes": "SHA256=" + "a1b2c3d4" * 8,
                "AccountName": user,
            },
        ],
    }

def scenario_phishing_c2():
    host  = "WKSTN-MARTINEZ-03"
    c2_ip = "185.220.101.47"
    user  = "lmartinez"
    phish = random.choice(PHISHING_DOMAINS)
    return {
        "type": "attack",
        "sentinel_id": f"PHISH-{uid()}",
        "title": "Phishing → PowerShell C2 Beacon Established",
        "source_host": host,
        "source_ip": INTERNAL_IPS[host],
        "external_ip": c2_ip,
        "timestamp": now_iso(),
        "raw_logs": [
            {"EventType": "EmailReceived", "TimeGenerated": mins_ago(22), "Recipient": f"{user}@corp.local", "SenderDomain": phish, "Subject": "Invoice #INV-2024-8821 - Action Required", "EmbeddedLinks": [f"http://{phish}/view/INV-2024-8821"], "SpamScore": 0.2},
            {"EventID": 4688, "TimeGenerated": mins_ago(20), "EventType": "ProcessCreated", "ParentImage": "C:\\Program Files\\Microsoft Office\\Office16\\OUTLOOK.EXE", "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0A...", "AccountName": f"CORP\\{user}", "WorkstationName": host},
            {"EventID": 3, "TimeGenerated": mins_ago(19), "EventType": "NetworkConnection", "Image": "powershell.exe", "DestinationIp": c2_ip, "DestinationPort": 443, "Protocol": "tcp", "ProcessId": rand_pid(), "WorkstationName": host},
            {"EventType": "NetworkBeacon", "TimeGenerated": mins_ago(18), "SourceIP": INTERNAL_IPS[host], "DestinationIP": c2_ip, "BeaconInterval": "60s", "ConnectionCount": random.randint(12, 22), "TotalBytesSent": random.randint(40000, 60000), "TotalBytesReceived": random.randint(100000, 150000)},
        ],
    }

def scenario_privesc_exfil():
    host  = "SRV-APP-07"
    exfil = "91.108.56.190"
    return {
        "type": "attack",
        "sentinel_id": f"EXFIL-{uid()}",
        "title": "Privilege Escalation → 2.3GB Sensitive Data Exfiltration",
        "source_host": host,
        "source_ip": INTERNAL_IPS[host],
        "external_ip": exfil,
        "timestamp": now_iso(),
        "raw_logs": [
            {"EventID": 4688, "TimeGenerated": mins_ago(16), "EventType": "ProcessCreated", "AccountName": "svc-apprunner", "NewProcessName": "C:\\Windows\\Temp\\upd_svc.exe", "CommandLine": "upd_svc.exe --bypass-token", "IntegrityLevel": "Medium", "WorkstationName": host},
            {"EventID": 4672, "TimeGenerated": mins_ago(15), "EventType": "SpecialPrivilegesAssigned", "AccountName": "SYSTEM", "PrivilegeList": ["SeDebugPrivilege", "SeTcbPrivilege", "SeBackupPrivilege"], "ProcessId": rand_pid(), "WorkstationName": host},
            {"EventID": 4663, "TimeGenerated": mins_ago(12), "EventType": "FileSystemAccess", "AccountName": "SYSTEM", "ObjectName": "E:\\HR\\Exports", "ObjectType": "Directory", "FileCount": random.randint(700, 900), "TotalSizeMB": random.randint(2100, 2500), "WorkstationName": host},
            {"EventType": "LargeDataTransfer", "TimeGenerated": mins_ago(9), "SourceHost": host, "SourceIP": INTERNAL_IPS[host], "DestinationIP": exfil, "DestinationPort": 443, "BytesTransferred": random.randint(2_000_000_000, 2_600_000_000), "DurationSeconds": random.randint(120, 200), "Protocol": "TLS1.3", "ProcessName": "curl.exe", "GeoIP": "RU - Saint Petersburg"},
        ],
    }

def scenario_ransomware():
    host = "WKSTN-THOMPSON-08"
    user = "lthompson"
    return {
        "type": "attack",
        "sentinel_id": f"RANSOM-{uid()}",
        "title": "Ransomware Precursor — Shadow Copy Deletion + Active File Encryption",
        "source_host": host,
        "source_ip": INTERNAL_IPS[host],
        "external_ip": None,
        "timestamp": now_iso(),
        "raw_logs": [
            {"EventID": 4688, "TimeGenerated": mins_ago(7), "EventType": "ProcessCreated", "AccountName": user, "NewProcessName": "C:\\Windows\\System32\\vssadmin.exe", "CommandLine": "vssadmin delete shadows /all /quiet", "WorkstationName": host},
            {"EventType": "MassFileRename", "TimeGenerated": mins_ago(6), "SourceHost": host, "FilesRenamed": random.randint(10000, 18000), "OriginalExtensions": [".docx", ".xlsx", ".pdf", ".jpg", ".pptx"], "NewExtension": ".crypted", "EncryptionRatePerSecond": random.randint(60, 90), "TargetDirectory": f"C:\\Users\\{user}"},
            {"EventID": 11, "TimeGenerated": mins_ago(5), "EventType": "FileCreated", "Image": "C:\\Windows\\Temp\\wuauclt.exe", "TargetFilename": f"C:\\Users\\{user}\\Documents\\HOW_TO_DECRYPT.txt", "Hash": "SHA256=f3a1b2c9d8e7f6a5b4c3d2e1f0a9b8c7", "WorkstationName": host},
        ],
    }

def scenario_insider():
    host = "WKSTN-CHEN-02"
    user = "jchen"
    return {
        "type": "attack",
        "sentinel_id": f"INSIDER-{uid()}",
        "title": "Insider Threat — Off-Hours HR & Finance Data Exfiltration",
        "source_host": host,
        "source_ip": INTERNAL_IPS[host],
        "external_ip": "drive.personal-storage.io",
        "timestamp": now_iso(),
        "raw_logs": [
            {"EventID": 4624, "TimeGenerated": mins_ago(90), "EventType": "UserLogon", "AccountName": user, "IpAddress": INTERNAL_IPS[host], "WorkstationName": host, "LogonType": 2, "AuthPackage": "Kerberos", "LocalTime": "03:17 AM", "OnCallSchedule": "None"},
            {"EventID": 5140, "TimeGenerated": mins_ago(85), "EventType": "NetworkShareAccess", "AccountName": user, "SourceHost": host, "ShareName": "\\\\HR-SRV\\Confidential", "FilesAccessed": random.randint(250, 350), "BytesRead": random.randint(600_000_000, 900_000_000), "DurationMinutes": random.randint(15, 25), "AdditionalShares": ["\\\\FINANCE-SRV\\Reports"]},
            {"EventType": "CloudUpload", "TimeGenerated": mins_ago(70), "SourceHost": host, "DestinationDomain": "drive.personal-storage.io", "BytesUploaded": random.randint(700_000_000, 950_000_000), "Protocol": "HTTPS", "ProcessName": "chrome.exe", "UserAccount": user, "ApprovedVendor": False},
        ],
    }

def scenario_credential_dumping():
    host = "DC-PROD-02"
    user = "administrator"
    return {
        "type": "attack",
        "sentinel_id": f"CRED-{uid()}",
        "title": "Credential Dumping — LSASS Memory Access Detected",
        "source_host": host,
        "source_ip": INTERNAL_IPS[host],
        "external_ip": None,
        "timestamp": now_iso(),
        "raw_logs": [
            {"EventID": 4688, "TimeGenerated": mins_ago(10), "EventType": "ProcessCreated", "AccountName": user, "NewProcessName": "C:\\Windows\\Temp\\procdump64.exe", "CommandLine": "procdump64.exe -ma lsass.exe lsass.dmp", "WorkstationName": host, "ProcessId": rand_pid()},
            {"EventID": 10, "TimeGenerated": mins_ago(9), "EventType": "ProcessAccess", "SourceImage": "C:\\Windows\\Temp\\procdump64.exe", "TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1fffff", "WorkstationName": host, "Note": "LSASS full memory dump — credential theft likely"},
            {"EventID": 11, "TimeGenerated": mins_ago(8), "EventType": "FileCreated", "TargetFilename": "C:\\Windows\\Temp\\lsass.dmp", "Image": "C:\\Windows\\Temp\\procdump64.exe", "WorkstationName": host, "FileSizeMB": random.randint(80, 160)},
            {"EventID": 4688, "TimeGenerated": mins_ago(6), "EventType": "ProcessCreated", "AccountName": user, "NewProcessName": "C:\\Windows\\System32\\cmd.exe", "CommandLine": f"cmd /c copy C:\\Windows\\Temp\\lsass.dmp \\\\{INTERNAL_IPS['SRV-APP-07']}\\C$\\Temp\\", "WorkstationName": host},
        ],
    }

def scenario_false_positive_vuln_scan():
    return {
        "type": "false_positive",
        "sentinel_id": f"FP-SCAN-{uid()}",
        "title": "Scheduled Vulnerability Scan — Approved Nessus Activity",
        "source_host": "SRV-VULN-SCAN-01",
        "source_ip": "192.168.1.10",
        "external_ip": None,
        "timestamp": now_iso(),
        "raw_logs": [{
            "EventType": "PortScan",
            "TimeGenerated": now_iso(),
            "SourceIP": "192.168.1.10",
            "TargetRange": "192.168.0.0/16",
            "PortsScanned": "1-65535",
            "Scanner": "Nessus 10.4.2",
            "ScanID": f"SCHED-{datetime.now().strftime('%Y-%m-%d')}-WEEKLY",
            "AuthorizedBy": "SecOps",
            "ChangeTicket": "CHG-2024-0892",
        }]
    }

def scenario_false_positive_admin_rdp():
    host = random.choice(["DC-PROD-01", "SRV-APP-07", "SRV-DB-03"])
    return {
        "type": "false_positive",
        "sentinel_id": f"FP-RDP-{uid()}",
        "title": "Admin RDP Session — IT Department Maintenance",
        "source_host": host,
        "source_ip": INTERNAL_IPS[host],
        "external_ip": None,
        "timestamp": now_iso(),
        "raw_logs": [{
            "EventID": 4624,
            "TimeGenerated": now_iso(),
            "EventType": "AuthenticationSuccess",
            "AccountName": "dsmith",
            "IpAddress": "192.168.1.50",
            "WorkstationName": host,
            "LogonType": 10,
            "AuthPackage": "Kerberos",
            "Note": "IT admin RDP — change ticket CHG-2024-1104",
        }, {
            "EventID": 4688,
            "TimeGenerated": now_iso(),
            "EventType": "ProcessCreated",
            "AccountName": "dsmith",
            "NewProcessName": "C:\\Windows\\System32\\mmc.exe",
            "CommandLine": "mmc.exe eventvwr.msc",
            "WorkstationName": host,
        }]
    }

ATTACK_SCENARIOS = [
    (scenario_brute_force,              3),
    (scenario_phishing_c2,              3),
    (scenario_privesc_exfil,            2),
    (scenario_ransomware,               2),
    (scenario_insider,                  2),
    (scenario_credential_dumping,       2),
    (scenario_false_positive_vuln_scan, 2),
    (scenario_false_positive_admin_rdp, 2),
]

ATTACK_FNS     = [fn for fn, _ in ATTACK_SCENARIOS]
ATTACK_WEIGHTS = [w  for _, w  in ATTACK_SCENARIOS]
ATTACK_PROBABILITY = 0.40


# ══════════════════════════════════════════════════════════════════════════════
# SIEM SHIPPERS
# ══════════════════════════════════════════════════════════════════════════════

def _sentinel_signature(workspace_id: str, key: str, date: str, content_length: int) -> str:
    string_to_hash = f"POST\n{content_length}\napplication/json\nx-ms-date:{date}\n/api/logs"
    decoded_key    = base64.b64decode(key)
    encoded_hash   = base64.b64encode(
        hmac.new(decoded_key, string_to_hash.encode("utf-8"), digestmod=hashlib.sha256).digest()
    ).decode("utf-8")
    return f"SharedKey {workspace_id}:{encoded_hash}"

async def ship_to_sentinel(logs: list[dict], log_type: str = SENTINEL_LOG_TYPE):
    if not SENTINEL_WORKSPACE_ID or not SENTINEL_WORKSPACE_KEY:
        log.warning("Sentinel credentials not set — skipping Sentinel ingest.")
        return
    body           = json.dumps(logs).encode("utf-8")
    rfc1123_date   = formatdate(usegmt=True)
    signature      = _sentinel_signature(SENTINEL_WORKSPACE_ID, SENTINEL_WORKSPACE_KEY, rfc1123_date, len(body))
    url = f"https://{SENTINEL_WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    headers = {
        "Content-Type":  "application/json",
        "Authorization": signature,
        "Log-Type":      log_type,
        "x-ms-date":     rfc1123_date,
        "time-generated-field": "TimeGenerated",
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, headers=headers, content=body)
    if resp.status_code == 200:
        log.info(f"  ✅ Sentinel: {len(logs)} event(s) ingested → table {log_type}_CL")
    else:
        log.error(f"  ❌ Sentinel ingest failed: {resp.status_code} {resp.text[:200]}")

async def ship_to_splunk(logs: list[dict], source_type: str = "json"):
    if not SPLUNK_HEC_URL or not SPLUNK_HEC_TOKEN:
        log.warning("Splunk HEC credentials not set — skipping Splunk ingest.")
        return
    events = ""
    for event in logs:
        events += json.dumps({
            "time":       datetime.now(timezone.utc).timestamp(),
            "host":       event.get("WorkstationName", event.get("SourceHost", "unknown")),
            "source":     SPLUNK_SOURCE,
            "sourcetype": source_type,
            "index":      SPLUNK_INDEX,
            "event":      event,
        }) + "\n"
    url = f"{SPLUNK_HEC_URL}/services/collector/event"
    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type":  "application/json",
    }
    async with httpx.AsyncClient(timeout=30, verify=False) as client:
        resp = await client.post(url, headers=headers, content=events.encode())
    if resp.status_code == 200:
        log.info(f"  ✅ Splunk: {len(logs)} event(s) → index={SPLUNK_INDEX}")
    else:
        log.error(f"  ❌ Splunk ingest failed: {resp.status_code} {resp.text[:200]}")

_wazuh_token: str = ""
_wazuh_token_expiry: float = 0

async def _get_wazuh_token() -> str:
    global _wazuh_token, _wazuh_token_expiry
    if _wazuh_token and time.time() < _wazuh_token_expiry:
        return _wazuh_token
    url = f"{WAZUH_API_URL}/security/user/authenticate"
    async with httpx.AsyncClient(timeout=15, verify=False) as client:
        resp = await client.post(url, auth=(WAZUH_API_USER, WAZUH_API_PASSWORD))
        resp.raise_for_status()
        data = resp.json()
    _wazuh_token        = data["data"]["token"]
    _wazuh_token_expiry = time.time() + 3500
    return _wazuh_token

async def ship_to_wazuh(logs: list[dict]):
    if not WAZUH_API_URL or not WAZUH_API_PASSWORD:
        log.warning("Wazuh credentials not set — skipping Wazuh ingest.")
        return
    try:
        token = await _get_wazuh_token()
    except Exception as e:
        log.error(f"  ❌ Wazuh auth failed: {e}")
        return
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }
    url = f"{WAZUH_API_URL}/active-response"
    for event in logs:
        payload = {
            "command":   "custom-soc-copilot",
            "arguments": [json.dumps(event)[:1000]],
            "agents_list": [WAZUH_AGENT_ID],
        }
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                resp = await client.put(url, headers=headers, json=payload)
            if resp.status_code not in (200, 201):
                log.error(f"  ❌ Wazuh event failed: {resp.status_code} {resp.text[:100]}")
        except Exception as e:
            log.error(f"  ❌ Wazuh event error: {e}")
    log.info(f"  ✅ Wazuh: {len(logs)} event(s) → agent {WAZUH_AGENT_ID}")


async def ship_to_siem(payload: dict):
    """Route all raw_logs in a payload to the configured SIEM."""
    raw_logs = payload.get("raw_logs", [])
    if not raw_logs:
        return
    tagged = []
    for ev in raw_logs:
        tagged.append({
            **ev,
            "SOCAlertTitle":    payload.get("title", ""),
            "SOCSentinelID":    payload.get("sentinel_id", ""),
            "SOCSourceHost":    payload.get("source_host", ""),
            "SOCExternalIP":    payload.get("external_ip", ""),
            "SOCAlertType":     payload.get("type", "unknown"),
        })
    if SIEM_TARGET == "sentinel":
        await ship_to_sentinel(tagged)
    elif SIEM_TARGET == "splunk":
        await ship_to_splunk(tagged)
    elif SIEM_TARGET == "wazuh":
        await ship_to_wazuh(tagged)
    elif SIEM_TARGET == "none":
        pass
    else:
        log.warning(f"Unknown SIEM_TARGET '{SIEM_TARGET}' — set to: sentinel | splunk | wazuh | none")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN CYCLE
# ══════════════════════════════════════════════════════════════════════════════

async def run_cycle():
    if random.random() < ATTACK_PROBABILITY:
        fn = random.choices(ATTACK_FNS, weights=ATTACK_WEIGHTS, k=1)[0]
        payload = fn()
        label = f"[ATTACK] {payload['title']}"
    else:
        fn = random.choice(CLEAN_GENERATORS)
        payload = fn()
        label = f"[CLEAN]  {payload['title']}"

    log.info(f"🔁 Generating: {label}")

    # 1. Write to log file for Wazuh agent monitoring
    if LOG_OUTPUT_FILE:
        write_to_log_file(payload)
        log.info(f"  📝 Written to log file: {LOG_OUTPUT_FILE}")

    # 2. Ship raw logs to SIEM
    siem_task = asyncio.create_task(ship_to_siem(payload))

    # 3. POST to FastAPI /ingest (attack + false_positive only)
    if payload.get("type") in ("attack", "false_positive"):
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(INGEST_URL, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    log.info(f"  ✅ FastAPI: {data.get('message')} — {payload['sentinel_id']}")
                else:
                    log.error(f"  ❌ FastAPI rejected: {resp.status_code} {resp.text[:100]}")
        except httpx.ConnectError:
            log.error(f"  ❌ Cannot reach FastAPI at {BACKEND_URL} — is it running?")
        except Exception as e:
            log.error(f"  ❌ FastAPI error: {e}")
    else:
        log.info(f"  ℹ️  Clean log — written to file/SIEM only, not to dashboard")

    await siem_task


async def main():
    log.info("=" * 60)
    log.info("KPMG MDR SOC Copilot — Log Generator v2")
    log.info(f"  Cycle interval : {CYCLE_INTERVAL}s")
    log.info(f"  Attack prob    : {int(ATTACK_PROBABILITY*100)}%  Clean prob: {int((1-ATTACK_PROBABILITY)*100)}%")
    log.info(f"  SIEM target    : {SIEM_TARGET.upper() if SIEM_TARGET != 'none' else 'None (local only)'}")
    log.info(f"  FastAPI URL    : {INGEST_URL}")
    log.info(f"  Log output     : {LOG_OUTPUT_FILE if LOG_OUTPUT_FILE else 'Disabled'}")
    log.info("=" * 60)

    await run_cycle()

    while True:
        await asyncio.sleep(CYCLE_INTERVAL)
        await run_cycle()


if __name__ == "__main__":
    asyncio.run(main())