import { useState, useEffect, useRef } from "react";

// ─── MOCK DATA ────────────────────────────────────────────────────────────────
const MOCK_ALERTS = [
  {
    id: "ALT-2024-0891",
    title: "Brute Force Attack → Lateral Movement Detected",
    sourceHost: "WKSTN-JOHNSON-01",
    sourceIP: "192.168.10.45",
    externalIP: "45.142.212.100",
    timestamp: new Date(Date.now() - 1000 * 60 * 4),
    severity: "Critical",
    classification: "True Positive",
    confidence: 97,
    status: "New",
    scenario: 1,
    mitreTactics: [
      { id: "TA0006", name: "Credential Access", color: "#ef4444" },
      { id: "TA0008", name: "Lateral Movement", color: "#f97316" },
      { id: "TA0001", name: "Initial Access", color: "#eab308" },
    ],
    triageSummary:
      "A brute force attack originating from external IP 45.142.212.100 successfully compromised user account 'mjohnson' after 47 failed login attempts over 8 minutes. The attacker immediately pivoted to internal SMB connections across three workstations, indicating an automated lateral movement toolkit. The attack pattern matches known APT29 TTPs.",
    attackStory:
      "At 14:22 UTC, an external threat actor began systematically attempting to authenticate to the VPN portal using the account 'mjohnson'. After 47 failed attempts spanning 8 minutes, the correct credentials were discovered — likely obtained via a previous phishing campaign or credential dump. Within 90 seconds of successful authentication, the actor deployed an automated lateral movement script that established SMB connections to DC-PROD-02, WKSTN-HARRIS-04, and SRV-FILE-01, enumerating network shares and dropping a reconnaissance payload. The speed and precision of post-compromise activity strongly suggests an experienced, well-resourced threat actor.",
    recommendedAction:
      "1. Immediately disable mjohnson account and revoke all active sessions. 2. Isolate WKSTN-JOHNSON-01, WKSTN-HARRIS-04, and SRV-FILE-01 from the network. 3. Collect memory dumps from all affected hosts before remediation. 4. Escalate to L2/IR team — likely APT activity. 5. Review VPN logs for additional compromised accounts from same source IP.",
    pivotalEvent: "EVT-004",
    timeline: [
      {
        id: "EVT-001",
        timestamp: new Date(Date.now() - 1000 * 60 * 12),
        eventType: "Authentication Failure",
        description: "First of 47 failed login attempts for user 'mjohnson' from external IP",
        rawLog: '{"EventID":4625,"TimeGenerated":"2024-01-15T14:22:14Z","AccountName":"mjohnson","IpAddress":"45.142.212.100","FailureReason":"Unknown user name or bad password","WorkstationName":"WKSTN-JOHNSON-01","LogonType":3}',
        mitreTactic: "TA0006 - Credential Access",
        severityLevel: 2,
        isPivotPoint: false,
      },
      {
        id: "EVT-002",
        timestamp: new Date(Date.now() - 1000 * 60 * 10),
        eventType: "Authentication Failure Spike",
        description: "39 additional failed attempts in 6 minutes — automated brute force pattern confirmed",
        rawLog: '{"EventID":4625,"TimeGenerated":"2024-01-15T14:24:52Z","AccountName":"mjohnson","IpAddress":"45.142.212.100","FailureReason":"Unknown user name or bad password","AttemptCount":39,"TimeWindow":"360s","Pattern":"Sequential password spray"}',
        mitreTactic: "TA0006 - Credential Access",
        severityLevel: 3,
        isPivotPoint: false,
      },
      {
        id: "EVT-003",
        timestamp: new Date(Date.now() - 1000 * 60 * 8),
        eventType: "Account Lockout",
        description: "Account 'mjohnson' temporarily locked out — attacker paused for 90 seconds before continuing",
        rawLog: '{"EventID":4740,"TimeGenerated":"2024-01-15T14:27:01Z","AccountName":"mjohnson","CallerComputerName":"WKSTN-JOHNSON-01","SubjectUserSid":"S-1-5-18"}',
        mitreTactic: "TA0006 - Credential Access",
        severityLevel: 3,
        isPivotPoint: false,
      },
      {
        id: "EVT-004",
        timestamp: new Date(Date.now() - 1000 * 60 * 6),
        eventType: "Successful Authentication",
        description: "⚡ BREACH POINT — mjohnson successfully authenticated from attacker IP after account reset",
        rawLog: '{"EventID":4624,"TimeGenerated":"2024-01-15T14:30:14Z","AccountName":"mjohnson","IpAddress":"45.142.212.100","LogonType":3,"WorkstationName":"WKSTN-JOHNSON-01","AuthPackage":"NTLM","KeyLength":0}',
        mitreTactic: "TA0001 - Initial Access",
        severityLevel: 5,
        isPivotPoint: true,
      },
      {
        id: "EVT-005",
        timestamp: new Date(Date.now() - 1000 * 60 * 5),
        eventType: "SMB Lateral Movement",
        description: "Automated SMB connections initiated to 3 internal hosts within 90 seconds of breach",
        rawLog: '{"EventID":5140,"TimeGenerated":"2024-01-15T14:31:44Z","AccountName":"mjohnson","SourceIP":"192.168.10.45","TargetHosts":["DC-PROD-02","WKSTN-HARRIS-04","SRV-FILE-01"],"ShareName":"\\\\*\\\\IPC$","AccessMask":"0x1"}',
        mitreTactic: "TA0008 - Lateral Movement",
        severityLevel: 5,
        isPivotPoint: false,
      },
      {
        id: "EVT-006",
        timestamp: new Date(Date.now() - 1000 * 60 * 4),
        eventType: "Reconnaissance Payload Drop",
        description: "Unknown binary 'svchost32.exe' written to C:\\Windows\\Temp on DC-PROD-02",
        rawLog: '{"EventID":11,"TimeGenerated":"2024-01-15T14:32:28Z","Image":"C:\\\\Windows\\\\System32\\\\cmd.exe","TargetFilename":"C:\\\\Windows\\\\Temp\\\\svchost32.exe","ProcessId":4821,"User":"DOMAIN\\\\mjohnson","Hashes":"SHA256=a1b2c3d4e5f6..."}',
        mitreTactic: "TA0002 - Execution",
        severityLevel: 5,
        isPivotPoint: false,
      },
    ],
  },
  {
    id: "ALT-2024-0892",
    title: "Phishing → PowerShell C2 Beacon Established",
    sourceHost: "WKSTN-MARTINEZ-03",
    sourceIP: "192.168.10.78",
    externalIP: "185.220.101.47",
    timestamp: new Date(Date.now() - 1000 * 60 * 18),
    severity: "High",
    classification: "True Positive",
    confidence: 89,
    status: "In Review",
    scenario: 2,
    mitreTactics: [
      { id: "TA0001", name: "Initial Access", color: "#eab308" },
      { id: "TA0002", name: "Execution", color: "#f97316" },
      { id: "TA0011", name: "C2", color: "#ef4444" },
    ],
    triageSummary:
      "User lmartinez clicked a malicious link in a spoofed invoice email, which spawned PowerShell from Outlook. The PowerShell process established an outbound C2 beacon to 185.220.101.47 (known Tor exit node) with a 60-second check-in interval. Encoded commands were downloaded and executed in memory — fileless attack technique.",
    attackStory:
      "At 13:44 UTC, lmartinez received what appeared to be a routine invoice email. The embedded link redirected through two legitimate-looking domains before delivering a malicious HTA payload. Outlook spawned powershell.exe, which immediately contacted a C2 server over HTTPS on port 443. The beacon has been active for 18 minutes with consistent 60-second intervals, suggesting an operator is actively monitoring the connection.",
    recommendedAction:
      "1. Kill PowerShell process PID 7291 on WKSTN-MARTINEZ-03. 2. Block 185.220.101.47 at perimeter firewall immediately. 3. Isolate WKSTN-MARTINEZ-03 from network. 4. Pull email headers and report phishing domain to security team. 5. Check if other users received same email.",
    pivotalEvent: "EVT-102",
    timeline: [
      {
        id: "EVT-101",
        timestamp: new Date(Date.now() - 1000 * 60 * 20),
        eventType: "Phishing Email Received",
        description: "Malicious email from spoofed domain 'invoices-kpmg-portal.com' delivered to lmartinez inbox",
        rawLog: '{"EventType":"EmailReceived","TimeGenerated":"2024-01-15T13:44:01Z","Recipient":"lmartinez@corp.local","SenderDomain":"invoices-kpmg-portal.com","Subject":"Invoice #INV-2024-8821 - Action Required","AttachmentCount":0,"EmbeddedLinks":["http://invoices-kpmg-portal.com/view/INV-2024-8821"]}',
        mitreTactic: "TA0001 - Initial Access",
        severityLevel: 2,
        isPivotPoint: false,
      },
      {
        id: "EVT-102",
        timestamp: new Date(Date.now() - 1000 * 60 * 18),
        eventType: "Malicious Link Clicked",
        description: "⚡ User clicked phishing link — Outlook spawned PowerShell with encoded command string",
        rawLog: '{"EventID":4688,"TimeGenerated":"2024-01-15T13:46:14Z","ParentImage":"C:\\\\Program Files\\\\Microsoft Office\\\\Office16\\\\OUTLOOK.EXE","NewProcessName":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","CommandLine":"powershell -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0...","User":"CORP\\\\lmartinez"}',
        mitreTactic: "TA0002 - Execution",
        severityLevel: 5,
        isPivotPoint: true,
      },
      {
        id: "EVT-103",
        timestamp: new Date(Date.now() - 1000 * 60 * 17),
        eventType: "C2 Connection Established",
        description: "PowerShell opened outbound HTTPS connection to Tor exit node 185.220.101.47:443",
        rawLog: '{"EventID":3,"TimeGenerated":"2024-01-15T13:47:09Z","Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","DestinationIp":"185.220.101.47","DestinationPort":443,"Protocol":"tcp","ProcessId":7291,"User":"CORP\\\\lmartinez"}',
        mitreTactic: "TA0011 - Command and Control",
        severityLevel: 5,
        isPivotPoint: false,
      },
      {
        id: "EVT-104",
        timestamp: new Date(Date.now() - 1000 * 60 * 16),
        eventType: "Beacon Pattern Detected",
        description: "Consistent 60-second callback intervals to C2 — operator actively monitoring",
        rawLog: '{"EventType":"NetworkBeacon","TimeGenerated":"2024-01-15T13:48:14Z","SourceIP":"192.168.10.78","DestinationIP":"185.220.101.47","BeaconInterval":"60s","ConnectionCount":16,"TotalBytesSent":48291,"TotalBytesReceived":124882}',
        mitreTactic: "TA0011 - Command and Control",
        severityLevel: 4,
        isPivotPoint: false,
      },
    ],
  },
  {
    id: "ALT-2024-0893",
    title: "Privilege Escalation → Sensitive Data Exfiltration",
    sourceHost: "SRV-APP-07",
    sourceIP: "192.168.20.112",
    externalIP: "91.108.56.190",
    timestamp: new Date(Date.now() - 1000 * 60 * 35),
    severity: "Critical",
    classification: "True Positive",
    confidence: 94,
    status: "Escalated",
    scenario: 3,
    mitreTactics: [
      { id: "TA0004", name: "Privilege Escalation", color: "#ef4444" },
      { id: "TA0010", name: "Exfiltration", color: "#ef4444" },
      { id: "TA0007", name: "Discovery", color: "#f97316" },
    ],
    triageSummary:
      "Service account 'svc-apprunner' exploited a local privilege escalation vulnerability to gain SYSTEM privileges on SRV-APP-07. The attacker then accessed the HR data directory and initiated a bulk transfer of 2.3GB to an external IP registered in Russia. The data exfiltration appears complete.",
    attackStory:
      "Starting at 13:27 UTC, the compromised service account 'svc-apprunner' executed a known Windows privilege escalation exploit (CVE-2023-36802). After gaining SYSTEM-level access, the actor spent 4 minutes enumerating the file system before locating the HR database exports in E:\\HR\\Exports. A total of 2.3GB was transferred to 91.108.56.190 over an encrypted channel. This is a confirmed data breach requiring immediate incident response.",
    recommendedAction:
      "1. IMMEDIATE: Notify CISO and legal team — data breach protocols apply. 2. Disable svc-apprunner account immediately. 3. Block 91.108.56.190 at all egress points. 4. Forensic image of SRV-APP-07 before any changes. 5. Determine exact contents of exfiltrated data for breach notification assessment.",
    pivotalEvent: "EVT-203",
    timeline: [
      {
        id: "EVT-201",
        timestamp: new Date(Date.now() - 1000 * 60 * 42),
        eventType: "Exploit Execution",
        description: "svc-apprunner executed suspicious binary matching CVE-2023-36802 exploit signature",
        rawLog: '{"EventID":4688,"TimeGenerated":"2024-01-15T13:27:44Z","AccountName":"svc-apprunner","NewProcessName":"C:\\\\Windows\\\\Temp\\\\upd_svc.exe","ParentImage":"C:\\\\Windows\\\\System32\\\\services.exe","CommandLine":"upd_svc.exe --bypass-token","IntegrityLevel":"Medium"}',
        mitreTactic: "TA0004 - Privilege Escalation",
        severityLevel: 4,
        isPivotPoint: false,
      },
      {
        id: "EVT-202",
        timestamp: new Date(Date.now() - 1000 * 60 * 41),
        eventType: "SYSTEM Privileges Obtained",
        description: "Process token elevated to NT AUTHORITY\\SYSTEM — full system compromise",
        rawLog: '{"EventID":4672,"TimeGenerated":"2024-01-15T13:28:12Z","AccountName":"SYSTEM","PrivilegeList":["SeAssignPrimaryTokenPrivilege","SeTcbPrivilege","SeSecurityPrivilege","SeTakeOwnershipPrivilege","SeLoadDriverPrivilege","SeBackupPrivilege","SeRestorePrivilege","SeDebugPrivilege"],"ProcessId":9141}',
        mitreTactic: "TA0004 - Privilege Escalation",
        severityLevel: 5,
        isPivotPoint: false,
      },
      {
        id: "EVT-203",
        timestamp: new Date(Date.now() - 1000 * 60 * 38),
        eventType: "Sensitive Directory Access",
        description: "⚡ SYSTEM process accessed HR exports directory — 847 files enumerated",
        rawLog: '{"EventID":4663,"TimeGenerated":"2024-01-15T13:31:09Z","AccountName":"SYSTEM","ObjectName":"E:\\\\HR\\\\Exports","ObjectType":"Directory","AccessList":"%%4416 %%4417 %%4418","ProcessName":"C:\\\\Windows\\\\System32\\\\cmd.exe","HandleId":"0x358"}',
        mitreTactic: "TA0007 - Discovery",
        severityLevel: 5,
        isPivotPoint: true,
      },
      {
        id: "EVT-204",
        timestamp: new Date(Date.now() - 1000 * 60 * 36),
        eventType: "Data Exfiltration",
        description: "2.3GB transferred to Russian IP 91.108.56.190 over encrypted channel — exfil complete",
        rawLog: '{"EventType":"LargeDataTransfer","TimeGenerated":"2024-01-15T13:33:44Z","SourceHost":"SRV-APP-07","DestinationIP":"91.108.56.190","DestinationPort":443,"BytesTransferred":2469606195,"Duration":"187s","Protocol":"TLS1.3","ProcessName":"curl.exe"}',
        mitreTactic: "TA0010 - Exfiltration",
        severityLevel: 5,
        isPivotPoint: false,
      },
    ],
  },
  {
    id: "ALT-2024-0894",
    title: "Ransomware Precursor — Shadow Copy Deletion",
    sourceHost: "WKSTN-THOMPSON-08",
    sourceIP: "192.168.10.203",
    externalIP: null,
    timestamp: new Date(Date.now() - 1000 * 60 * 52),
    severity: "Critical",
    classification: "True Positive",
    confidence: 99,
    status: "New",
    scenario: 4,
    mitreTactics: [
      { id: "TA0040", name: "Impact", color: "#ef4444" },
      { id: "TA0005", name: "Defense Evasion", color: "#f97316" },
    ],
    triageSummary:
      "Classic ransomware deployment pattern detected on WKSTN-THOMPSON-08. vssadmin.exe deleted all volume shadow copies, followed by rapid file renaming with '.crypted' extension across the user profile. The encryption pattern suggests a known ransomware family. Immediate containment required.",
    attackStory:
      "At 13:10 UTC, an unknown process initiated the classic ransomware kill chain on WKSTN-THOMPSON-08. Volume shadow copies were deleted to prevent recovery, followed by systematic file encryption starting with the Documents folder. Over 14,000 files have been renamed with .crypted extension. The process is ongoing.",
    recommendedAction:
      "1. EMERGENCY: Immediately isolate WKSTN-THOMPSON-08 from all network connections. 2. Do NOT restart the machine. 3. Check if any network shares are mapped and isolate those servers immediately. 4. Identify patient zero — how did ransomware land on this host? 5. Engage IR team — check for lateral spread.",
    pivotalEvent: "EVT-302",
    timeline: [
      {
        id: "EVT-301",
        timestamp: new Date(Date.now() - 1000 * 60 * 55),
        eventType: "Shadow Copy Deletion",
        description: "vssadmin.exe deleted all volume shadow copies — backup destruction initiated",
        rawLog: '{"EventID":4688,"TimeGenerated":"2024-01-15T13:10:22Z","AccountName":"lthompson","NewProcessName":"C:\\\\Windows\\\\System32\\\\vssadmin.exe","CommandLine":"vssadmin delete shadows /all /quiet","ProcessId":12847}',
        mitreTactic: "TA0005 - Defense Evasion",
        severityLevel: 5,
        isPivotPoint: false,
      },
      {
        id: "EVT-302",
        timestamp: new Date(Date.now() - 1000 * 60 * 54),
        eventType: "Mass File Encryption",
        description: "⚡ 14,000+ files renamed to .crypted extension — active ransomware encryption in progress",
        rawLog: '{"EventType":"MassFileRename","TimeGenerated":"2024-01-15T13:11:08Z","SourceHost":"WKSTN-THOMPSON-08","FilesRenamed":14291,"OriginalExtensions":[".docx",".xlsx",".pdf",".jpg"],"NewExtension":".crypted","EncryptionRate":"76 files/second","TargetDirectory":"C:\\\\Users\\\\lthompson"}',
        mitreTactic: "TA0040 - Impact",
        severityLevel: 5,
        isPivotPoint: true,
      },
      {
        id: "EVT-303",
        timestamp: new Date(Date.now() - 1000 * 60 * 53),
        eventType: "Ransom Note Dropped",
        description: "HOW_TO_DECRYPT.txt created in every affected directory",
        rawLog: '{"EventID":11,"TimeGenerated":"2024-01-15T13:12:44Z","Image":"C:\\\\Windows\\\\Temp\\\\wuauclt.exe","TargetFilename":"C:\\\\Users\\\\lthompson\\\\Documents\\\\HOW_TO_DECRYPT.txt","Hash":"SHA256=f3a1b2c9d8e7...","NoteContent":"Your files have been encrypted..."}',
        mitreTactic: "TA0040 - Impact",
        severityLevel: 4,
        isPivotPoint: false,
      },
    ],
  },
  {
    id: "ALT-2024-0895",
    title: "Insider Threat — Off-Hours HR Data Access",
    sourceHost: "WKSTN-CHEN-02",
    sourceIP: "192.168.10.34",
    externalIP: "drive.personal-storage.io",
    timestamp: new Date(Date.now() - 1000 * 60 * 90),
    severity: "High",
    classification: "Needs Review",
    confidence: 72,
    status: "In Review",
    scenario: 5,
    mitreTactics: [
      { id: "TA0009", name: "Collection", color: "#f97316" },
      { id: "TA0010", name: "Exfiltration", color: "#ef4444" },
    ],
    triageSummary:
      "User account 'jchen' authenticated at 03:17 AM local time and accessed HR and Finance network shares outside business hours. 847MB of files were downloaded locally then uploaded to a personal cloud storage domain. The user has no documented on-call duties. Medium-high confidence insider threat — requires HR and legal consultation before action.",
    attackStory:
      "At 03:17 AM, jchen's credentials were used to log in from their registered workstation. Over 45 minutes, the account accessed the \\\\HR-SRV\\Confidential and \\\\FINANCE-SRV\\Reports shares, downloading 847MB of documents. The files were then uploaded to 'drive.personal-storage.io' — a personal cloud service not approved for corporate data. This could be a malicious insider or a compromised account being used off-hours.",
    recommendedAction:
      "1. Do NOT immediately alert the user — maintain covert monitoring. 2. Notify HR and Legal before taking any action. 3. Preserve all logs with legal hold. 4. Verify if jchen has legitimate business reason for this access. 5. Check if jchen badge data shows them physically in office at 03:17 AM.",
    pivotalEvent: "EVT-402",
    timeline: [
      {
        id: "EVT-401",
        timestamp: new Date(Date.now() - 1000 * 60 * 130),
        eventType: "Off-Hours Authentication",
        description: "jchen logged in at 03:17 AM — no scheduled on-call duties on record",
        rawLog: '{"EventID":4624,"TimeGenerated":"2024-01-15T03:17:44Z","AccountName":"jchen","IpAddress":"192.168.10.34","WorkstationName":"WKSTN-CHEN-02","LogonType":2,"AuthPackage":"Kerberos"}',
        mitreTactic: "TA0001 - Initial Access",
        severityLevel: 2,
        isPivotPoint: false,
      },
      {
        id: "EVT-402",
        timestamp: new Date(Date.now() - 1000 * 60 * 125),
        eventType: "Sensitive Share Access",
        description: "⚡ HR Confidential and Finance shares accessed and bulk downloaded — 847MB",
        rawLog: '{"EventID":5140,"TimeGenerated":"2024-01-15T03:22:18Z","AccountName":"jchen","ShareName":"\\\\\\\\HR-SRV\\\\Confidential","FilesAccessed":291,"BytesRead":634291048,"Duration":"18min","AdditionalShares":["\\\\\\\\FINANCE-SRV\\\\Reports"]}',
        mitreTactic: "TA0009 - Collection",
        severityLevel: 4,
        isPivotPoint: true,
      },
      {
        id: "EVT-403",
        timestamp: new Date(Date.now() - 1000 * 60 * 105),
        eventType: "Cloud Upload — Unapproved Service",
        description: "847MB uploaded to personal cloud storage domain not on approved vendor list",
        rawLog: '{"EventType":"CloudUpload","TimeGenerated":"2024-01-15T03:42:09Z","SourceHost":"WKSTN-CHEN-02","DestinationDomain":"drive.personal-storage.io","BytesUploaded":888143872,"Protocol":"HTTPS","ProcessName":"chrome.exe","UserAccount":"jchen"}',
        mitreTactic: "TA0010 - Exfiltration",
        severityLevel: 4,
        isPivotPoint: false,
      },
    ],
  },
  {
    id: "ALT-2024-0890",
    title: "Routine Port Scan — Internal Vulnerability Scanner",
    sourceHost: "SRV-VULN-SCAN-01",
    sourceIP: "192.168.1.10",
    externalIP: null,
    timestamp: new Date(Date.now() - 1000 * 60 * 110),
    severity: "Low",
    classification: "False Positive",
    confidence: 96,
    status: "Dismissed",
    scenario: 0,
    mitreTactics: [{ id: "TA0007", name: "Discovery", color: "#3b82f6" }],
    triageSummary:
      "This alert was triggered by the scheduled Nessus vulnerability scan from the approved scanner SRV-VULN-SCAN-01. The scan is on the approved scanning schedule and matches expected behavior. No action required.",
    attackStory:
      "The weekly Tuesday vulnerability scan executed on schedule from the approved scanner appliance. Port sweeps across the 192.168.0.0/16 subnet are expected and authorized. This alert is a known false positive from the SIEM rule and should be suppressed.",
    recommendedAction:
      "No action required. Consider adding SRV-VULN-SCAN-01 to the allowlist in Sentinel analytics rule to prevent future false positive alerts during scheduled scan windows.",
    pivotalEvent: "EVT-502",
    timeline: [
      {
        id: "EVT-501",
        timestamp: new Date(Date.now() - 1000 * 60 * 115),
        eventType: "Port Scan Initiated",
        description: "Scheduled Nessus scan started from approved scanner — authorized activity",
        rawLog: '{"EventType":"PortScan","TimeGenerated":"2024-01-15T12:55:00Z","SourceIP":"192.168.1.10","TargetRange":"192.168.0.0/16","PortsScanned":"1-65535","Scanner":"Nessus 10.4.2","ScanID":"SCHED-2024-01-15-WEEKLY"}',
        mitreTactic: "TA0007 - Discovery",
        severityLevel: 1,
        isPivotPoint: false,
      },
    ],
  },
];

// ─── UTILITY FUNCTIONS ────────────────────────────────────────────────────────
const severityConfig = {
  Critical: { color: "#ef4444", bg: "rgba(239,68,68,0.12)", border: "rgba(239,68,68,0.3)", dot: "bg-red-500" },
  High: { color: "#f97316", bg: "rgba(249,115,22,0.12)", border: "rgba(249,115,22,0.3)", dot: "bg-orange-500" },
  Medium: { color: "#eab308", bg: "rgba(234,179,8,0.12)", border: "rgba(234,179,8,0.3)", dot: "bg-yellow-500" },
  Low: { color: "#3b82f6", bg: "rgba(59,130,246,0.12)", border: "rgba(59,130,246,0.3)", dot: "bg-blue-500" },
};

const classificationConfig = {
  "True Positive": { color: "#ef4444", bg: "rgba(239,68,68,0.1)", label: "TP" },
  "False Positive": { color: "#22c55e", bg: "rgba(34,197,94,0.1)", label: "FP" },
  "Needs Review": { color: "#eab308", bg: "rgba(234,179,8,0.1)", label: "NR" },
};

const formatRelativeTime = (date) => {
  const diff = Date.now() - date.getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
};

const formatTimestamp = (date) =>
  date.toISOString().replace("T", " ").substring(0, 19) + " UTC";

const severityLevelColor = (level) => {
  if (level === 5) return "#ef4444";
  if (level === 4) return "#f97316";
  if (level === 3) return "#eab308";
  if (level === 2) return "#3b82f6";
  return "#6b7280";
};

// ─── ICONS ────────────────────────────────────────────────────────────────────
const Icon = ({ name, size = 16, color = "currentColor" }) => {
  const icons = {
    shield: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
    alert: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
    clock: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>,
    server: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>,
    chevronRight: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2"><polyline points="9 18 15 12 9 6"/></svg>,
    x: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>,
    arrowUp: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2"><line x1="12" y1="19" x2="12" y2="5"/><polyline points="5 12 12 5 19 12"/></svg>,
    check: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2"><polyline points="20 6 9 13 4 10"/></svg>,
    activity: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>,
    filter: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>,
    terminal: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>,
    slack: <svg width={size} height={size} viewBox="0 0 24 24" fill={color}><path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312zM15.165 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zM15.165 17.688a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z"/></svg>,
    barChart: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/><line x1="2" y1="20" x2="22" y2="20"/></svg>,
    eye: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>,
    code: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>,
  };
  return icons[name] || null;
};

// ─── CONFIDENCE GAUGE ─────────────────────────────────────────────────────────
const ConfidenceGauge = ({ value }) => {
  const [animated, setAnimated] = useState(0);
  useEffect(() => {
    const t = setTimeout(() => setAnimated(value), 300);
    return () => clearTimeout(t);
  }, [value]);
  const color = value >= 85 ? "#ef4444" : value >= 65 ? "#f97316" : "#eab308";
  const circumference = 2 * Math.PI * 36;
  const offset = circumference - (animated / 100) * circumference;
  return (
    <div className="relative flex items-center justify-center" style={{ width: 90, height: 90 }}>
      <svg width="90" height="90" style={{ transform: "rotate(-90deg)" }}>
        <circle cx="45" cy="45" r="36" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="6" />
        <circle cx="45" cy="45" r="36" fill="none" stroke={color} strokeWidth="6"
          strokeDasharray={circumference} strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 1.2s cubic-bezier(0.4,0,0.2,1)" }}
        />
      </svg>
      <div className="absolute text-center">
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 18, fontWeight: 700, color, lineHeight: 1 }}>{animated}%</div>
        <div style={{ fontSize: 9, color: "rgba(255,255,255,0.4)", marginTop: 2 }}>CONF</div>
      </div>
    </div>
  );
};

// ─── MITRE CHIP ───────────────────────────────────────────────────────────────
const MitreChip = ({ tactic }) => (
  <div style={{
    display: "inline-flex", alignItems: "center", gap: 6, padding: "4px 10px",
    background: "rgba(59,130,246,0.08)", border: "1px solid rgba(59,130,246,0.2)",
    borderRadius: 3, fontSize: 11, fontFamily: "'JetBrains Mono', monospace",
  }}>
    <span style={{ color: "#3b82f6" }}>{tactic.id}</span>
    <span style={{ color: "rgba(255,255,255,0.6)" }}>{tactic.name}</span>
  </div>
);

// ─── TIMELINE COMPONENT ───────────────────────────────────────────────────────
const AttackTimeline = ({ events, pivotalEventId }) => {
  const [expanded, setExpanded] = useState(null);
  return (
    <div style={{ position: "relative", paddingLeft: 32 }}>
      {/* Connecting line */}
      <div style={{
        position: "absolute", left: 11, top: 12, bottom: 12, width: 2,
        background: "linear-gradient(to bottom, rgba(59,130,246,0.6), rgba(59,130,246,0.1))",
      }} />
      {events.map((event, i) => {
        const isPivot = event.id === pivotalEventId;
        const dotColor = severityLevelColor(event.severityLevel);
        const isExpanded = expanded === event.id;
        return (
          <div key={event.id} style={{ position: "relative", marginBottom: isPivot ? 28 : 20 }}>
            {/* Node dot */}
            <div style={{
              position: "absolute", left: -32, top: 14,
              width: isPivot ? 24 : 14, height: isPivot ? 24 : 14,
              borderRadius: "50%", background: dotColor,
              border: `2px solid ${isPivot ? dotColor : "transparent"}`,
              boxShadow: isPivot ? `0 0 0 4px rgba(239,68,68,0.2), 0 0 16px ${dotColor}` : "none",
              transform: isPivot ? "translate(-5px, -5px)" : "translate(0, 0)",
              zIndex: 2, transition: "all 0.3s ease",
            }} />
            <div
              onClick={() => setExpanded(isExpanded ? null : event.id)}
              style={{
                background: isPivot ? "rgba(239,68,68,0.06)" : "rgba(255,255,255,0.02)",
                border: `1px solid ${isPivot ? "rgba(239,68,68,0.25)" : "rgba(255,255,255,0.06)"}`,
                borderRadius: 4, padding: "12px 14px", cursor: "pointer",
                transition: "all 0.2s ease",
              }}
              onMouseEnter={e => { e.currentTarget.style.background = isPivot ? "rgba(239,68,68,0.1)" : "rgba(255,255,255,0.04)"; }}
              onMouseLeave={e => { e.currentTarget.style.background = isPivot ? "rgba(239,68,68,0.06)" : "rgba(255,255,255,0.02)"; }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
                <div style={{ flex: 1 }}>
                  {isPivot && (
                    <div style={{
                      display: "inline-flex", alignItems: "center", gap: 4, marginBottom: 6,
                      padding: "2px 8px", background: "rgba(239,68,68,0.15)", border: "1px solid rgba(239,68,68,0.4)",
                      borderRadius: 2, fontSize: 9, fontWeight: 700, letterSpacing: "0.1em", color: "#ef4444",
                    }}>
                      ⚡ PIVOTAL EVENT
                    </div>
                  )}
                  <div style={{ fontSize: 12, fontWeight: 600, color: "rgba(255,255,255,0.9)", marginBottom: 4 }}>
                    {event.eventType}
                  </div>
                  <div style={{ fontSize: 12, color: "rgba(255,255,255,0.55)", lineHeight: 1.5 }}>
                    {event.description}
                  </div>
                </div>
                <div style={{ textAlign: "right", flexShrink: 0 }}>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "rgba(255,255,255,0.35)" }}>
                    {formatTimestamp(event.timestamp)}
                  </div>
                  <div style={{ fontSize: 10, color: "#3b82f6", marginTop: 4 }}>{event.mitreTactic}</div>
                </div>
              </div>
              {isExpanded && (
                <div style={{ marginTop: 12, borderTop: "1px solid rgba(255,255,255,0.06)", paddingTop: 12 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
                    <Icon name="terminal" size={12} color="#3b82f6" />
                    <span style={{ fontSize: 10, color: "#3b82f6", fontFamily: "'JetBrains Mono', monospace" }}>RAW LOG</span>
                  </div>
                  <pre style={{
                    fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "rgba(255,255,255,0.6)",
                    background: "rgba(0,0,0,0.4)", border: "1px solid rgba(255,255,255,0.08)",
                    borderRadius: 3, padding: 12, overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all",
                    margin: 0, lineHeight: 1.6,
                  }}>
                    {JSON.stringify(JSON.parse(event.rawLog), null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};

// ─── ALERT CARD ───────────────────────────────────────────────────────────────
const AlertCard = ({ alert, onClick, isNew }) => {
  const sev = severityConfig[alert.severity];
  const cls = classificationConfig[alert.classification];
  const [pulse, setPulse] = useState(isNew);

  useEffect(() => {
    if (isNew) {
      const t = setTimeout(() => setPulse(false), 8000);
      return () => clearTimeout(t);
    }
  }, [isNew]);

  return (
    <div
      onClick={onClick}
      style={{
        background: pulse ? "rgba(59,130,246,0.04)" : "rgba(255,255,255,0.02)",
        border: `1px solid ${pulse ? "rgba(59,130,246,0.25)" : "rgba(255,255,255,0.06)"}`,
        borderLeft: `3px solid ${sev.color}`,
        borderRadius: 4, padding: "14px 16px", cursor: "pointer", marginBottom: 6,
        transition: "all 0.2s ease",
        animation: isNew ? "slideIn 0.4s ease" : "none",
        position: "relative", overflow: "hidden",
      }}
      onMouseEnter={e => { e.currentTarget.style.background = "rgba(255,255,255,0.04)"; e.currentTarget.style.borderColor = "rgba(255,255,255,0.12)"; e.currentTarget.style.borderLeftColor = sev.color; }}
      onMouseLeave={e => { e.currentTarget.style.background = pulse ? "rgba(59,130,246,0.04)" : "rgba(255,255,255,0.02)"; e.currentTarget.style.borderColor = pulse ? "rgba(59,130,246,0.25)" : "rgba(255,255,255,0.06)"; e.currentTarget.style.borderLeftColor = sev.color; }}
    >
      {pulse && <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 1, background: "linear-gradient(90deg, transparent, rgba(59,130,246,0.6), transparent)", animation: "shimmer 2s infinite" }} />}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6, flexWrap: "wrap" }}>
            <span style={{
              padding: "2px 8px", borderRadius: 2, fontSize: 10, fontWeight: 700, letterSpacing: "0.05em",
              background: sev.bg, border: `1px solid ${sev.border}`, color: sev.color,
            }}>{alert.severity.toUpperCase()}</span>
            <span style={{
              padding: "2px 8px", borderRadius: 2, fontSize: 10, fontWeight: 700,
              background: cls.bg, color: cls.color,
            }}>{cls.label}</span>
            {alert.status === "New" && (
              <span style={{ padding: "2px 8px", borderRadius: 2, fontSize: 10, fontWeight: 600, background: "rgba(59,130,246,0.1)", color: "#3b82f6" }}>NEW</span>
            )}
            {alert.status === "Escalated" && (
              <span style={{ padding: "2px 8px", borderRadius: 2, fontSize: 10, fontWeight: 600, background: "rgba(239,68,68,0.1)", color: "#ef4444" }}>ESCALATED</span>
            )}
          </div>
          <div style={{ fontSize: 13, fontWeight: 600, color: "rgba(255,255,255,0.9)", marginBottom: 6, lineHeight: 1.3 }}>
            {alert.title}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <span style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11, color: "rgba(255,255,255,0.4)", fontFamily: "'JetBrains Mono', monospace" }}>
              <Icon name="server" size={11} color="rgba(255,255,255,0.3)" />
              {alert.sourceHost}
            </span>
            <span style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", fontFamily: "'JetBrains Mono', monospace" }}>{alert.sourceIP}</span>
          </div>
        </div>
        <div style={{ textAlign: "right", flexShrink: 0 }}>
          <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", fontFamily: "'JetBrains Mono', monospace", marginBottom: 8 }}
            title={formatTimestamp(alert.timestamp)}>
            {formatRelativeTime(alert.timestamp)}
          </div>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 3 }}>
            <div style={{ fontSize: 10, color: "rgba(255,255,255,0.35)" }}>{alert.confidence}% conf</div>
            <div style={{ width: 80, height: 3, background: "rgba(255,255,255,0.08)", borderRadius: 2 }}>
              <div style={{
                width: `${alert.confidence}%`, height: "100%", borderRadius: 2,
                background: `linear-gradient(90deg, ${cls.color}, ${cls.color}aa)`,
                transition: "width 0.8s ease",
              }} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// ─── ALERT DETAIL PANEL ───────────────────────────────────────────────────────
const AlertDetailPanel = ({ alert, onClose, onEscalate, onDismiss }) => {
  const [escalating, setEscalating] = useState(false);
  const [escalated, setEscalated] = useState(alert.status === "Escalated");
  const [dismissed, setDismissed] = useState(false);
  const sev = severityConfig[alert.severity];

  const handleEscalate = async () => {
    setEscalating(true);
    await new Promise(r => setTimeout(r, 1800));
    setEscalating(false);
    setEscalated(true);
    onEscalate(alert.id);
  };

  const handleDismiss = () => {
    setDismissed(true);
    setTimeout(() => onDismiss(alert.id), 500);
  };

  return (
    <div style={{
      position: "fixed", top: 0, right: 0, bottom: 0, width: "min(680px, 100vw)",
      background: "#0d0d14", borderLeft: "1px solid rgba(255,255,255,0.08)",
      display: "flex", flexDirection: "column", zIndex: 100,
      animation: "slideInRight 0.35s cubic-bezier(0.4,0,0.2,1)",
      overflowY: "auto",
    }}>
      {/* Header */}
      <div style={{ padding: "20px 24px", borderBottom: "1px solid rgba(255,255,255,0.06)", flexShrink: 0 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <div style={{ flex: 1, marginRight: 16 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
              <span style={{
                padding: "3px 10px", borderRadius: 2, fontSize: 11, fontWeight: 700,
                background: sev.bg, border: `1px solid ${sev.border}`, color: sev.color,
              }}>{alert.severity.toUpperCase()}</span>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "rgba(255,255,255,0.35)" }}>{alert.id}</span>
            </div>
            <div style={{ fontSize: 16, fontWeight: 700, color: "rgba(255,255,255,0.95)", lineHeight: 1.3, marginBottom: 8 }}>
              {alert.title}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
              <span style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 12, color: "rgba(255,255,255,0.4)", fontFamily: "'JetBrains Mono', monospace" }}>
                <Icon name="server" size={12} color="rgba(255,255,255,0.3)" />{alert.sourceHost}
              </span>
              <span style={{ fontSize: 12, color: "rgba(255,255,255,0.4)", fontFamily: "'JetBrains Mono', monospace" }}>{alert.sourceIP}</span>
              {alert.externalIP && <span style={{ fontSize: 12, color: "#ef4444", fontFamily: "'JetBrains Mono', monospace" }}>→ {alert.externalIP}</span>}
            </div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 12 }}>
            <button onClick={onClose} style={{ background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 3, padding: "6px 8px", cursor: "pointer", color: "rgba(255,255,255,0.6)", display: "flex", alignItems: "center" }}>
              <Icon name="x" size={14} />
            </button>
            <ConfidenceGauge value={alert.confidence} />
          </div>
        </div>
      </div>

      {/* Scrollable content */}
      <div style={{ flex: 1, overflowY: "auto", padding: "20px 24px" }}>
        {/* Classification + MITRE */}
        <div style={{ marginBottom: 20 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
            <div style={{
              padding: "6px 14px", borderRadius: 3, fontSize: 13, fontWeight: 700,
              background: classificationConfig[alert.classification].bg,
              color: classificationConfig[alert.classification].color,
              border: `1px solid ${classificationConfig[alert.classification].color}40`,
            }}>{alert.classification}</div>
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {alert.mitreTactics.map(t => <MitreChip key={t.id} tactic={t} />)}
          </div>
        </div>

        {/* Triage Summary */}
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: "rgba(255,255,255,0.35)", letterSpacing: "0.1em", marginBottom: 10 }}>AI TRIAGE SUMMARY</div>
          <div style={{ fontSize: 13, color: "rgba(255,255,255,0.7)", lineHeight: 1.7, padding: "14px 16px", background: "rgba(59,130,246,0.05)", border: "1px solid rgba(59,130,246,0.12)", borderRadius: 4 }}>
            {alert.triageSummary}
          </div>
        </div>

        {/* Attack Story */}
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: "rgba(255,255,255,0.35)", letterSpacing: "0.1em", marginBottom: 10 }}>ATTACK NARRATIVE</div>
          <div style={{ fontSize: 13, color: "rgba(255,255,255,0.6)", lineHeight: 1.8, fontStyle: "italic" }}>
            {alert.attackStory}
          </div>
        </div>

        {/* Attack Timeline */}
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: "rgba(255,255,255,0.35)", letterSpacing: "0.1em", marginBottom: 16 }}>ATTACK TIMELINE — {alert.timeline.length} EVENTS</div>
          <AttackTimeline events={alert.timeline} pivotalEventId={alert.pivotalEvent} />
        </div>

        {/* Recommended Action */}
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: "rgba(255,255,255,0.35)", letterSpacing: "0.1em", marginBottom: 10 }}>RECOMMENDED ACTIONS</div>
          <div style={{ fontSize: 13, color: "rgba(255,255,255,0.65)", lineHeight: 1.8, padding: "14px 16px", background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 4, whiteSpace: "pre-line" }}>
            {alert.recommendedAction}
          </div>
        </div>
      </div>

      {/* Action Bar */}
      <div style={{ padding: "16px 24px", borderTop: "1px solid rgba(255,255,255,0.06)", display: "flex", gap: 10, flexShrink: 0 }}>
        {!dismissed && alert.classification !== "False Positive" && (
          <button
            onClick={handleEscalate}
            disabled={escalating || escalated}
            style={{
              flex: 1, padding: "11px 0", borderRadius: 3, fontSize: 13, fontWeight: 700,
              border: escalated ? "1px solid rgba(34,197,94,0.4)" : "1px solid rgba(239,68,68,0.5)",
              background: escalated ? "rgba(34,197,94,0.1)" : escalating ? "rgba(239,68,68,0.05)" : "rgba(239,68,68,0.12)",
              color: escalated ? "#22c55e" : "#ef4444", cursor: escalated ? "default" : "pointer",
              display: "flex", alignItems: "center", justifyContent: "center", gap: 8, transition: "all 0.3s ease",
            }}
          >
            {escalating ? (
              <>
                <div style={{ width: 12, height: 12, border: "2px solid rgba(239,68,68,0.3)", borderTopColor: "#ef4444", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
                Sending to Slack...
              </>
            ) : escalated ? (
              <><Icon name="check" size={14} color="#22c55e" /> Escalated to L2</>
            ) : (
              <><Icon name="arrowUp" size={14} /> Escalate to L2</>
            )}
          </button>
        )}
        <button
          onClick={handleDismiss}
          style={{
            flex: 1, padding: "11px 0", borderRadius: 3, fontSize: 13, fontWeight: 600,
            border: "1px solid rgba(255,255,255,0.1)", background: "rgba(255,255,255,0.03)",
            color: "rgba(255,255,255,0.5)", cursor: "pointer", transition: "all 0.2s ease",
          }}
          onMouseEnter={e => { e.currentTarget.style.background = "rgba(255,255,255,0.07)"; e.currentTarget.style.color = "rgba(255,255,255,0.8)"; }}
          onMouseLeave={e => { e.currentTarget.style.background = "rgba(255,255,255,0.03)"; e.currentTarget.style.color = "rgba(255,255,255,0.5)"; }}
        >
          Mark False Positive
        </button>
        <button
          onClick={onClose}
          style={{ padding: "11px 16px", borderRadius: 3, fontSize: 13, border: "1px solid rgba(255,255,255,0.08)", background: "transparent", color: "rgba(255,255,255,0.4)", cursor: "pointer" }}
        >
          <Icon name="x" size={14} />
        </button>
      </div>
    </div>
  );
};

// ─── METRICS VIEW ─────────────────────────────────────────────────────────────
const MetricsView = ({ alerts }) => {
  const total = alerts.length;
  const tp = alerts.filter(a => a.classification === "True Positive").length;
  const fp = alerts.filter(a => a.classification === "False Positive").length;
  const nr = alerts.filter(a => a.classification === "Needs Review").length;
  const critical = alerts.filter(a => a.severity === "Critical").length;
  const high = alerts.filter(a => a.severity === "High").length;

  const mitreCount = {};
  alerts.forEach(a => a.mitreTactics.forEach(t => { mitreCount[t.name] = (mitreCount[t.name] || 0) + 1; }));
  const topMitre = Object.entries(mitreCount).sort((a, b) => b[1] - a[1]).slice(0, 5);

  const hourlyData = Array.from({ length: 12 }, (_, i) => ({
    hour: `${String(8 + i).padStart(2, "0")}:00`,
    count: Math.floor(Math.random() * 8) + 1,
  }));

  const maxCount = Math.max(...hourlyData.map(d => d.count));

  const StatCard = ({ label, value, sublabel, color }) => (
    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 4, padding: "20px 22px" }}>
      <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", letterSpacing: "0.1em", marginBottom: 8 }}>{label}</div>
      <div style={{ fontSize: 32, fontWeight: 700, color: color || "rgba(255,255,255,0.9)", fontFamily: "'JetBrains Mono', monospace", lineHeight: 1 }}>{value}</div>
      {sublabel && <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", marginTop: 6 }}>{sublabel}</div>}
    </div>
  );

  return (
    <div style={{ padding: "24px 28px", maxWidth: 900 }}>
      <div style={{ fontSize: 11, fontWeight: 600, color: "rgba(255,255,255,0.3)", letterSpacing: "0.12em", marginBottom: 20 }}>SHIFT METRICS — TODAY 08:00–20:00 UTC</div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 28 }}>
        <StatCard label="TOTAL ALERTS" value={total} sublabel="this shift" />
        <StatCard label="TRUE POSITIVE" value={tp} sublabel={`${Math.round(tp/total*100)}% TP rate`} color="#ef4444" />
        <StatCard label="FALSE POSITIVE" value={fp} sublabel={`${Math.round(fp/total*100)}% FP rate`} color="#22c55e" />
        <StatCard label="NEEDS REVIEW" value={nr} sublabel="pending triage" color="#eab308" />
      </div>

      {/* Classification breakdown */}
      <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 4, padding: "20px 22px", marginBottom: 20 }}>
        <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", letterSpacing: "0.1em", marginBottom: 16 }}>CLASSIFICATION BREAKDOWN</div>
        <div style={{ display: "flex", gap: 4, height: 28, borderRadius: 3, overflow: "hidden" }}>
          {[{ v: tp, c: "#ef4444", l: "TP" }, { v: nr, c: "#eab308", l: "NR" }, { v: fp, c: "#22c55e", l: "FP" }].map(({ v, c, l }) => (
            <div key={l} style={{ flex: v, background: c, opacity: 0.7, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, fontWeight: 700, color: "#000", minWidth: v > 0 ? 30 : 0 }}>
              {v > 0 ? `${l} ${v}` : ""}
            </div>
          ))}
        </div>
      </div>

      {/* Severity breakdown */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 20 }}>
        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 4, padding: "20px 22px" }}>
          <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", letterSpacing: "0.1em", marginBottom: 16 }}>SEVERITY DISTRIBUTION</div>
          {[
            { label: "Critical", count: critical, color: "#ef4444" },
            { label: "High", count: high, color: "#f97316" },
            { label: "Medium", count: alerts.filter(a => a.severity === "Medium").length, color: "#eab308" },
            { label: "Low", count: alerts.filter(a => a.severity === "Low").length, color: "#3b82f6" },
          ].map(({ label, count, color }) => (
            <div key={label} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
              <div style={{ width: 60, fontSize: 11, color: "rgba(255,255,255,0.5)" }}>{label}</div>
              <div style={{ flex: 1, height: 6, background: "rgba(255,255,255,0.06)", borderRadius: 3 }}>
                <div style={{ width: `${(count / total) * 100}%`, height: "100%", background: color, borderRadius: 3, opacity: 0.8 }} />
              </div>
              <div style={{ width: 24, fontSize: 12, fontWeight: 700, color, fontFamily: "'JetBrains Mono', monospace", textAlign: "right" }}>{count}</div>
            </div>
          ))}
        </div>

        <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 4, padding: "20px 22px" }}>
          <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", letterSpacing: "0.1em", marginBottom: 16 }}>TOP MITRE TACTICS</div>
          {topMitre.map(([name, count], i) => (
            <div key={name} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
              <div style={{ width: 18, height: 18, background: "rgba(59,130,246,0.1)", border: "1px solid rgba(59,130,246,0.2)", borderRadius: 2, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 9, color: "#3b82f6", fontWeight: 700 }}>
                {i + 1}
              </div>
              <div style={{ flex: 1, fontSize: 12, color: "rgba(255,255,255,0.6)" }}>{name}</div>
              <div style={{ fontSize: 12, fontWeight: 700, color: "#3b82f6", fontFamily: "'JetBrains Mono', monospace" }}>{count}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Alert volume sparkline */}
      <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 4, padding: "20px 22px" }}>
        <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", letterSpacing: "0.1em", marginBottom: 16 }}>ALERT VOLUME — HOURLY</div>
        <div style={{ display: "flex", alignItems: "flex-end", gap: 4, height: 60 }}>
          {hourlyData.map(({ hour, count }) => (
            <div key={hour} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
              <div style={{
                width: "100%", background: "rgba(59,130,246,0.5)", borderRadius: "2px 2px 0 0",
                height: `${(count / maxCount) * 50}px`, minHeight: 4, transition: "height 0.6s ease",
              }} />
              <div style={{ fontSize: 8, color: "rgba(255,255,255,0.25)", fontFamily: "'JetBrains Mono', monospace", whiteSpace: "nowrap" }}>
                {hour.split(":")[0]}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// ─── MAIN APP ─────────────────────────────────────────────────────────────────
export default function SOCDashboard() {
  const [alerts, setAlerts] = useState(MOCK_ALERTS);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [activeTab, setActiveTab] = useState("alerts");
  const [filterSeverity, setFilterSeverity] = useState("All");
  const [filterClass, setFilterClass] = useState("All");
  const [filterStatus, setFilterStatus] = useState("All");
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const filteredAlerts = alerts.filter(a => {
    if (filterSeverity !== "All" && a.severity !== filterSeverity) return false;
    if (filterClass !== "All" && a.classification !== filterClass) return false;
    if (filterStatus !== "All" && a.status !== filterStatus) return false;
    return true;
  });

  const criticalCount = alerts.filter(a => a.severity === "Critical").length;
  const tpCount = alerts.filter(a => a.classification === "True Positive").length;
  const newCount = alerts.filter(a => a.status === "New").length;
  const avgConf = Math.round(alerts.reduce((s, a) => s + a.confidence, 0) / alerts.length);

  const handleEscalate = (id) => {
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: "Escalated" } : a));
  };
  const handleDismiss = (id) => {
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: "Dismissed", classification: "False Positive" } : a));
    setSelectedAlert(null);
  };

  const navItems = [
    { id: "alerts", label: "Alert Queue", icon: "alert", badge: newCount },
    { id: "metrics", label: "Shift Metrics", icon: "barChart", badge: null },
  ];

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #0a0a0f; }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: rgba(255,255,255,0.02); }
        ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.12); border-radius: 2px; }
        @keyframes slideIn { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes slideInRight { from { opacity: 0; transform: translateX(32px); } to { opacity: 1; transform: translateX(0); } }
        @keyframes shimmer { 0% { transform: translateX(-100%); } 100% { transform: translateX(100%); } }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:0.5; } }
        @keyframes blink { 0%,100% { opacity:1; } 50% { opacity:0; } }
      `}</style>

      <div style={{ display: "flex", height: "100vh", background: "#0a0a0f", fontFamily: "'Inter', sans-serif", color: "#fff", overflow: "hidden" }}>

        {/* ── SIDEBAR ── */}
        <div style={{ width: 220, background: "#07070d", borderRight: "1px solid rgba(255,255,255,0.06)", display: "flex", flexDirection: "column", flexShrink: 0 }}>
          {/* Brand */}
          <div style={{ padding: "20px 18px 18px", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
              <div style={{ width: 28, height: 28, background: "linear-gradient(135deg, #3b82f6, #1d4ed8)", borderRadius: 4, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Icon name="shield" size={15} color="#fff" />
              </div>
              <div>
                <div style={{ fontSize: 13, fontWeight: 800, letterSpacing: "0.05em", color: "#fff" }}>KPMG MDR</div>
                <div style={{ fontSize: 9, color: "rgba(255,255,255,0.3)", letterSpacing: "0.12em" }}>SOC COPILOT</div>
              </div>
            </div>
          </div>

          {/* Analyst info */}
          <div style={{ padding: "14px 18px", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
              <div style={{ width: 28, height: 28, borderRadius: "50%", background: "linear-gradient(135deg, rgba(59,130,246,0.4), rgba(29,78,216,0.4))", border: "1px solid rgba(59,130,246,0.3)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 11, fontWeight: 700, color: "#3b82f6" }}>
                SR
              </div>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: "rgba(255,255,255,0.85)" }}>S. Reddy</div>
                <div style={{ fontSize: 10, color: "rgba(255,255,255,0.35)" }}>L1 Analyst</div>
              </div>
              <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 4 }}>
                <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#22c55e", animation: "pulse 2s infinite" }} />
                <span style={{ fontSize: 9, color: "#22c55e" }}>LIVE</span>
              </div>
            </div>
            <div style={{ fontSize: 10, color: "rgba(255,255,255,0.25)", fontFamily: "'JetBrains Mono', monospace" }}>
              Shift: 08:00–20:00 UTC
            </div>
          </div>

          {/* Nav */}
          <nav style={{ padding: "10px 10px", flex: 1 }}>
            {navItems.map(item => (
              <button key={item.id} onClick={() => setActiveTab(item.id)} style={{
                width: "100%", display: "flex", alignItems: "center", gap: 10, padding: "9px 10px",
                borderRadius: 4, border: "none", cursor: "pointer", marginBottom: 2,
                background: activeTab === item.id ? "rgba(59,130,246,0.12)" : "transparent",
                color: activeTab === item.id ? "#3b82f6" : "rgba(255,255,255,0.45)",
                fontSize: 12, fontWeight: 500, textAlign: "left", transition: "all 0.15s ease",
              }}
              onMouseEnter={e => { if (activeTab !== item.id) e.currentTarget.style.background = "rgba(255,255,255,0.04)"; }}
              onMouseLeave={e => { if (activeTab !== item.id) e.currentTarget.style.background = "transparent"; }}
              >
                <Icon name={item.icon} size={14} color={activeTab === item.id ? "#3b82f6" : "rgba(255,255,255,0.35)"} />
                <span style={{ flex: 1 }}>{item.label}</span>
                {item.badge > 0 && (
                  <span style={{ padding: "1px 7px", borderRadius: 10, fontSize: 10, fontWeight: 700, background: "#ef4444", color: "#fff" }}>
                    {item.badge}
                  </span>
                )}
              </button>
            ))}
          </nav>

          {/* Clock */}
          <div style={{ padding: "14px 18px", borderTop: "1px solid rgba(255,255,255,0.06)" }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 20, fontWeight: 700, color: "rgba(255,255,255,0.85)", letterSpacing: "0.05em" }}>
              {time.toISOString().substring(11, 19)}
            </div>
            <div style={{ fontSize: 10, color: "rgba(255,255,255,0.25)", marginTop: 2 }}>
              {time.toDateString()}
            </div>
          </div>
        </div>

        {/* ── MAIN CONTENT ── */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>

          {activeTab === "alerts" && (
            <>
              {/* Stats bar */}
              <div style={{ padding: "14px 24px", borderBottom: "1px solid rgba(255,255,255,0.06)", display: "flex", alignItems: "center", gap: 24, flexShrink: 0, background: "rgba(255,255,255,0.01)" }}>
                {[
                  { label: "TOTAL", value: alerts.length, color: "rgba(255,255,255,0.85)" },
                  { label: "CRITICAL", value: criticalCount, color: "#ef4444" },
                  { label: "TRUE POS", value: tpCount, color: "#f97316" },
                  { label: "AVG CONF", value: `${avgConf}%`, color: "#3b82f6" },
                  { label: "NEW", value: newCount, color: "#22c55e" },
                ].map(({ label, value, color }) => (
                  <div key={label} style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 18, fontWeight: 700, color }}>{value}</span>
                    <span style={{ fontSize: 10, color: "rgba(255,255,255,0.3)", letterSpacing: "0.08em" }}>{label}</span>
                  </div>
                ))}
                <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6 }}>
                  <div style={{ width: 7, height: 7, borderRadius: "50%", background: "#22c55e", animation: "pulse 2s infinite" }} />
                  <span style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", fontFamily: "'JetBrains Mono', monospace" }}>SENTINEL CONNECTED</span>
                </div>
              </div>

              {/* Filter bar */}
              <div style={{ padding: "10px 24px", borderBottom: "1px solid rgba(255,255,255,0.06)", display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
                <Icon name="filter" size={13} color="rgba(255,255,255,0.3)" />
                <span style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", marginRight: 4 }}>FILTER</span>
                {["All", "Critical", "High", "Medium", "Low"].map(s => (
                  <button key={s} onClick={() => setFilterSeverity(s)} style={{
                    padding: "4px 10px", borderRadius: 2, fontSize: 11, border: "1px solid",
                    borderColor: filterSeverity === s ? (s === "All" ? "rgba(255,255,255,0.3)" : severityConfig[s]?.border || "rgba(255,255,255,0.3)") : "rgba(255,255,255,0.06)",
                    background: filterSeverity === s ? (s === "All" ? "rgba(255,255,255,0.06)" : severityConfig[s]?.bg || "rgba(255,255,255,0.06)") : "transparent",
                    color: filterSeverity === s ? (s === "All" ? "rgba(255,255,255,0.8)" : severityConfig[s]?.color || "#fff") : "rgba(255,255,255,0.3)",
                    cursor: "pointer",
                  }}>{s}</button>
                ))}
                <div style={{ width: 1, height: 16, background: "rgba(255,255,255,0.08)", margin: "0 4px" }} />
                {["All", "True Positive", "False Positive", "Needs Review"].map(c => (
                  <button key={c} onClick={() => setFilterClass(c)} style={{
                    padding: "4px 10px", borderRadius: 2, fontSize: 11, border: "1px solid",
                    borderColor: filterClass === c ? "rgba(255,255,255,0.2)" : "rgba(255,255,255,0.06)",
                    background: filterClass === c ? "rgba(255,255,255,0.06)" : "transparent",
                    color: filterClass === c ? "rgba(255,255,255,0.8)" : "rgba(255,255,255,0.3)",
                    cursor: "pointer",
                  }}>{c === "All" ? "All Classes" : c}</button>
                ))}
              </div>

              {/* Alert list */}
              <div style={{ flex: 1, overflowY: "auto", padding: "16px 24px" }}>
                {filteredAlerts.length === 0 ? (
                  <div style={{ textAlign: "center", padding: "60px 0", color: "rgba(255,255,255,0.2)", fontSize: 13 }}>
                    No alerts match current filters
                  </div>
                ) : (
                  filteredAlerts.map(alert => (
                    <AlertCard
                      key={alert.id}
                      alert={alert}
                      onClick={() => setSelectedAlert(alert)}
                      isNew={alert.status === "New"}
                    />
                  ))
                )}
              </div>
            </>
          )}

          {activeTab === "metrics" && <MetricsView alerts={alerts} />}
        </div>

        {/* ── DETAIL PANEL ── */}
        {selectedAlert && (
          <>
            <div
              onClick={() => setSelectedAlert(null)}
              style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", zIndex: 99, backdropFilter: "blur(2px)" }}
            />
            <AlertDetailPanel
              alert={selectedAlert}
              onClose={() => setSelectedAlert(null)}
              onEscalate={handleEscalate}
              onDismiss={handleDismiss}
            />
          </>
        )}
      </div>
    </>
  );
}