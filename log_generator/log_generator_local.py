"""
Synthetic Log Generator — LOCAL MODE
Posts attack scenarios directly to FastAPI /ingest endpoint.
No Azure, no Sentinel required.

Run: python log_generator_local.py
"""

import os
import json
import time
import random
import logging
import asyncio
from datetime import datetime, timezone, timedelta

import httpx
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# Where to POST alerts — your local FastAPI backend
BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000")
INGEST_URL  = f"{BACKEND_URL}/ingest"

# How often to fire a new alert (seconds). 30s is good for local demos.
CYCLE_INTERVAL = int(os.environ.get("CYCLE_INTERVAL", "30"))

# ── Fixture data ──────────────────────────────────────────────────────────────
INTERNAL_HOSTS = [
    "WKSTN-JOHNSON-01", "WKSTN-MARTINEZ-03", "WKSTN-THOMPSON-08",
    "WKSTN-HARRIS-04",  "WKSTN-CHEN-02",     "SRV-APP-07",
    "SRV-FILE-01",      "DC-PROD-02",         "DC-PROD-01",
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
}
USERS = ["mjohnson", "lmartinez", "lthompson", "jharris", "jchen", "svc-apprunner"]
PHISHING_DOMAINS = [
    "invoices-kpmg-portal.com", "secure-update-microsoft.net",
    "corp-hr-portal.io",        "office365-verify.com",
]

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def mins_ago(m):
    return (datetime.now(timezone.utc) - timedelta(minutes=m)).isoformat()

def uid():
    """Short unique suffix for sentinel IDs so duplicate-check works."""
    return str(int(time.time() * 1000))[-8:]


# ── Attack scenario builders ──────────────────────────────────────────────────

def scenario_brute_force():
    host        = "WKSTN-JOHNSON-01"
    attacker_ip = "45.142.212.100"
    user        = "mjohnson"
    fail_count  = random.randint(35, 55)

    failures = [{
        "EventID": 4625,
        "TimeGenerated": mins_ago(random.randint(9, 15)),
        "EventType": "AuthenticationFailure",
        "AccountName": user,
        "IpAddress": attacker_ip,
        "WorkstationName": host,
        "FailureReason": "Unknown user name or bad password",
        "LogonType": 3,
    } for _ in range(fail_count)]

    return {
        "sentinel_id": f"BRUTE-{uid()}",
        "title": "Brute Force Attack → Lateral Movement Detected",
        "source_host": host,
        "source_ip": INTERNAL_IPS[host],
        "external_ip": attacker_ip,
        "timestamp": now_iso(),
        "raw_logs": failures + [
            {
                "EventID": 4624,
                "TimeGenerated": mins_ago(6),
                "EventType": "AuthenticationSuccess",
                "AccountName": user,
                "IpAddress": attacker_ip,
                "WorkstationName": host,
                "LogonType": 3,
                "AuthPackage": "NTLM",
                "Note": f"SUCCESS after {fail_count} failures",
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
    host    = "WKSTN-MARTINEZ-03"
    c2_ip   = "185.220.101.47"
    user    = "lmartinez"
    phish   = random.choice(PHISHING_DOMAINS)

    return {
        "sentinel_id": f"PHISH-{uid()}",
        "title": "Phishing → PowerShell C2 Beacon Established",
        "source_host": host,
        "source_ip": INTERNAL_IPS[host],
        "external_ip": c2_ip,
        "timestamp": now_iso(),
        "raw_logs": [
            {
                "EventType": "EmailReceived",
                "TimeGenerated": mins_ago(22),
                "Recipient": f"{user}@corp.local",
                "SenderDomain": phish,
                "Subject": "Invoice #INV-2024-8821 - Action Required",
                "EmbeddedLinks": [f"http://{phish}/view/INV-2024-8821"],
            },
            {
                "EventID": 4688,
                "TimeGenerated": mins_ago(20),
                "EventType": "ProcessCreated",
                "ParentImage": "C:\\Program Files\\Microsoft Office\\Office16\\OUTLOOK.EXE",
                "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0A...",
                "AccountName": f"CORP\\{user}",
                "WorkstationName": host,
            },
            {
                "EventID": 3,
                "TimeGenerated": mins_ago(19),
                "EventType": "NetworkConnection",
                "Image": "powershell.exe",
                "DestinationIp": c2_ip,
                "DestinationPort": 443,
                "Protocol": "tcp",
                "ProcessId": random.randint(5000, 9999),
                "WorkstationName": host,
            },
            {
                "EventType": "NetworkBeacon",
                "TimeGenerated": mins_ago(18),
                "SourceIP": INTERNAL_IPS[host],
                "DestinationIP": c2_ip,
                "BeaconInterval": "60s",
                "ConnectionCount": random.randint(12, 22),
                "TotalBytesSent": random.randint(40000, 60000),
                "TotalBytesReceived": random.randint(100000, 150000),
            },
        ],
    }


def scenario_privesc_exfil():
    host    = "SRV-APP-07"
    exfil   = "91.108.56.190"

    return {
        "sentinel_id": f"EXFIL-{uid()}",
        "title": "Privilege Escalation → 2.3GB Sensitive Data Exfiltration",
        "source_host": host,
        "source_ip": INTERNAL_IPS[host],
        "external_ip": exfil,
        "timestamp": now_iso(),
        "raw_logs": [
            {
                "EventID": 4688,
                "TimeGenerated": mins_ago(16),
                "EventType": "ProcessCreated",
                "AccountName": "svc-apprunner",
                "NewProcessName": "C:\\Windows\\Temp\\upd_svc.exe",
                "CommandLine": "upd_svc.exe --bypass-token",
                "IntegrityLevel": "Medium",
                "WorkstationName": host,
            },
            {
                "EventID": 4672,
                "TimeGenerated": mins_ago(15),
                "EventType": "SpecialPrivilegesAssigned",
                "AccountName": "SYSTEM",
                "PrivilegeList": ["SeDebugPrivilege", "SeTcbPrivilege", "SeBackupPrivilege"],
                "ProcessId": random.randint(8000, 12000),
                "WorkstationName": host,
            },
            {
                "EventID": 4663,
                "TimeGenerated": mins_ago(12),
                "EventType": "FileSystemAccess",
                "AccountName": "SYSTEM",
                "ObjectName": "E:\\HR\\Exports",
                "ObjectType": "Directory",
                "FileCount": random.randint(700, 900),
                "TotalSizeMB": random.randint(2100, 2500),
                "WorkstationName": host,
            },
            {
                "EventType": "LargeDataTransfer",
                "TimeGenerated": mins_ago(9),
                "SourceHost": host,
                "SourceIP": INTERNAL_IPS[host],
                "DestinationIP": exfil,
                "DestinationPort": 443,
                "BytesTransferred": random.randint(2_000_000_000, 2_600_000_000),
                "DurationSeconds": random.randint(120, 200),
                "Protocol": "TLS1.3",
                "ProcessName": "curl.exe",
                "GeoIP": "RU - Saint Petersburg",
            },
        ],
    }


def scenario_ransomware():
    host = "WKSTN-THOMPSON-08"
    user = "lthompson"

    return {
        "sentinel_id": f"RANSOM-{uid()}",
        "title": "Ransomware Precursor — Shadow Copy Deletion + Active File Encryption",
        "source_host": host,
        "source_ip": INTERNAL_IPS[host],
        "external_ip": None,
        "timestamp": now_iso(),
        "raw_logs": [
            {
                "EventID": 4688,
                "TimeGenerated": mins_ago(7),
                "EventType": "ProcessCreated",
                "AccountName": user,
                "NewProcessName": "C:\\Windows\\System32\\vssadmin.exe",
                "CommandLine": "vssadmin delete shadows /all /quiet",
                "WorkstationName": host,
            },
            {
                "EventType": "MassFileRename",
                "TimeGenerated": mins_ago(6),
                "SourceHost": host,
                "FilesRenamed": random.randint(10000, 18000),
                "OriginalExtensions": [".docx", ".xlsx", ".pdf", ".jpg", ".pptx"],
                "NewExtension": ".crypted",
                "EncryptionRatePerSecond": random.randint(60, 90),
                "TargetDirectory": f"C:\\Users\\{user}",
            },
            {
                "EventID": 11,
                "TimeGenerated": mins_ago(5),
                "EventType": "FileCreated",
                "Image": "C:\\Windows\\Temp\\wuauclt.exe",
                "TargetFilename": f"C:\\Users\\{user}\\Documents\\HOW_TO_DECRYPT.txt",
                "Hash": "SHA256=f3a1b2c9d8e7f6a5b4c3d2e1f0a9b8c7",
                "WorkstationName": host,
            },
        ],
    }


def scenario_insider():
    host = "WKSTN-CHEN-02"
    user = "jchen"

    return {
        "sentinel_id": f"INSIDER-{uid()}",
        "title": "Insider Threat — Off-Hours HR & Finance Data Exfiltration",
        "source_host": host,
        "source_ip": INTERNAL_IPS[host],
        "external_ip": "drive.personal-storage.io",
        "timestamp": now_iso(),
        "raw_logs": [
            {
                "EventID": 4624,
                "TimeGenerated": mins_ago(90),
                "EventType": "UserLogon",
                "AccountName": user,
                "IpAddress": INTERNAL_IPS[host],
                "WorkstationName": host,
                "LogonType": 2,
                "AuthPackage": "Kerberos",
                "LocalTime": "03:17 AM",
                "OnCallSchedule": "None",
            },
            {
                "EventID": 5140,
                "TimeGenerated": mins_ago(85),
                "EventType": "NetworkShareAccess",
                "AccountName": user,
                "SourceHost": host,
                "ShareName": "\\\\HR-SRV\\Confidential",
                "FilesAccessed": random.randint(250, 350),
                "BytesRead": random.randint(600_000_000, 900_000_000),
                "DurationMinutes": random.randint(15, 25),
                "AdditionalShares": ["\\\\FINANCE-SRV\\Reports"],
            },
            {
                "EventType": "CloudUpload",
                "TimeGenerated": mins_ago(70),
                "SourceHost": host,
                "DestinationDomain": "drive.personal-storage.io",
                "BytesUploaded": random.randint(700_000_000, 950_000_000),
                "Protocol": "HTTPS",
                "ProcessName": "chrome.exe",
                "UserAccount": user,
                "ApprovedVendor": False,
            },
        ],
    }


def scenario_false_positive():
    """Occasional benign activity that triggers a low-severity alert."""
    return {
        "sentinel_id": f"FP-{uid()}",
        "title": "Scheduled Vulnerability Scan — Approved Scanner Activity",
        "source_host": "SRV-VULN-SCAN-01",
        "source_ip": "192.168.1.10",
        "external_ip": None,
        "timestamp": now_iso(),
        "raw_logs": [
            {
                "EventType": "PortScan",
                "TimeGenerated": now_iso(),
                "SourceIP": "192.168.1.10",
                "TargetRange": "192.168.0.0/16",
                "PortsScanned": "1-65535",
                "Scanner": "Nessus 10.4.2",
                "ScanID": f"SCHED-{datetime.now().strftime('%Y-%m-%d')}-WEEKLY",
                "AuthorizedBy": "SecOps",
            }
        ],
    }


# ── Scenario rotation: 4 attacks then 1 FP ───────────────────────────────────
SCENARIOS = [
    scenario_brute_force,
    scenario_phishing_c2,
    scenario_privesc_exfil,
    scenario_ransomware,
    scenario_insider,
    scenario_false_positive,
]
scenario_index = 0


async def run_cycle():
    global scenario_index
    fn      = SCENARIOS[scenario_index % len(SCENARIOS)]
    payload = fn()
    scenario_index += 1

    title = payload["title"]
    log.info(f"🚀 Sending: [{title}]")

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(INGEST_URL, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                log.info(f"✅ Backend accepted: {data.get('message')} — {payload['sentinel_id']}")
            else:
                log.error(f"❌ Backend rejected: {resp.status_code} {resp.text}")
    except httpx.ConnectError:
        log.error(f"❌ Cannot connect to backend at {BACKEND_URL}. Is it running?")
    except Exception as e:
        log.error(f"❌ Error: {e}")


async def main():
    log.info(f"🔁 Log generator started — firing every {CYCLE_INTERVAL}s → {INGEST_URL}")
    log.info(f"   Scenarios: {len(SCENARIOS)} | Order: rotating")

    # Fire one immediately on start
    await run_cycle()

    while True:
        await asyncio.sleep(CYCLE_INTERVAL)
        await run_cycle()


if __name__ == "__main__":
    asyncio.run(main())