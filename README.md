# 🛡️ MDR Alert Triage Copilot

> An AI-powered Security Operations Centre dashboard for Managed Detection & Response L1 analysts. Simulates realistic attack scenarios, ships logs to Wazuh SIEM, triages every alert with Claude AI, and enables one-click L2 escalation via Slack.

**Live Demo:** [mdrcopilot.ddns.net](http://mdrcopilot.ddns.net)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Features](#features)
- [How It Works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Project Structure](#project-structure)
- [Environment Variables](#environment-variables)
- [Local Setup](#local-setup)
- [Cloud Deployment (Azure)](#cloud-deployment-azure)
- [SIEM Integration](#siem-integration)

---

## Overview

The KPMG MDR SOC Alert Triage Copilot is a full-stack cybersecurity operations platform built to simulate, detect, and triage security incidents in real time. It is designed to demonstrate how AI can augment L1 SOC analyst workflows — reducing mean time to triage, surfacing MITRE ATT&CK context automatically, and routing confirmed threats to L2 teams instantly.

The system continuously generates synthetic attack telemetry (brute force, ransomware, phishing, credential dumping, insider threats, and more) alongside realistic clean/benign logs. All logs are shipped to **Wazuh** for SIEM correlation. The Python backend pulls those logs and sends them to the **Claude AI** API for deep triage. Triaged alerts appear on the live React dashboard where analysts can investigate, confirm, and escalate.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Azure Windows VM                          │
│                  (mdrcopilot.ddns.net)                       │
│                                                             │
│  ┌─────────────────┐    ┌──────────────────────────────┐   │
│  │  Log Generator  │───▶│     Wazuh Agent              │   │
│  │  (Python)       │    │  (ships logs to Wazuh Cloud) │   │
│  └─────────────────┘    └──────────────┬─────────────┘    │
│                                        │                    │
│  ┌─────────────────┐                   │                    │
│  │  FastAPI        │◀──────────────────┘                   │
│  │  Backend        │  (pulls logs back from Wazuh)         │
│  │                 │                                        │
│  │  ┌───────────┐  │  ┌──────────────────────────────┐    │
│  │  │ Claude AI │◀─┤  │       PostgreSQL              │    │
│  │  │  Triage   │  │  │   (stores triaged alerts)     │    │
│  │  └───────────┘  │  └──────────────────────────────┘    │
│  └────────┬────────┘                                        │
│           │                                                 │
│  ┌────────▼────────┐                                        │
│  │  Caddy          │  (reverse proxy + HTTPS)               │
│  │  (port 80/443)  │                                        │
│  └────────┬────────┘                                        │
└───────────┼─────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────┐        ┌─────────────────────────┐
│   React Dashboard        │        │    Wazuh Cloud          │
│   (L1 Analyst View)      │        │    Dashboard            │
│   mdrcopilot.ddns.net    │        │   (raw log visibility)  │
└──────────┬──────────────┘        └─────────────────────────┘
           │
           │  L1 clicks Escalate
           ▼
┌─────────────────────────┐
│   Slack — L2 Channel    │
│   (Block Kit alert card)│
└─────────────────────────┘
```

**Domain:** No-IP DDNS (`mdrcopilot.ddns.net`) points to the Azure VM's static public IP. Caddy handles TLS termination and proxies API calls to FastAPI.

---

> **Note:** Azure can be swapped out for any cloud provider (AWS, GCP, DigitalOcean, etc.) and Claude can be replaced with any LLM API you are comfortable with. The underlying architecture, flow, and functionality remain exactly the same regardless of which provider you use.

> **Note on Log Generation:** The synthetic log generator included in this project is purely for simulation and demo purposes. In a real-world SOC deployment, the log generator would be completely removed. Instead, actual endpoint telemetry, network logs, and SIEM alerts flowing in from your environment in real time would feed directly into the triage pipeline.

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | React 18, Vite, Tailwind CSS, Framer Motion |
| **Backend** | Python 3.11, FastAPI, Uvicorn |
| **AI Triage** | Anthropic Claude (`claude-sonnet-4-20250514`) |
| **Database** | PostgreSQL 16 via asyncpg |
| **SIEM** | Wazuh Cloud (agent on VM → cloud manager) |
| **Reverse Proxy** | Caddy 2 (automatic HTTPS via Let's Encrypt) |
| **Process Manager** | NSSM (Windows services for backend, generator, Caddy) |
| **Notifications** | Slack Incoming Webhooks (Block Kit) |
| **Infrastructure** | Microsoft Azure — Windows Server 2022 VM (Standard B2s) |
| **Domain** | No-IP DDNS (`mdrcopilot.ddns.net`) |
| **Font Stack** | JetBrains Mono (data/logs), Inter (UI) |

---

## Features

### Live Alert Dashboard
- Real-time alert queue polling every 10 seconds
- New alert shimmer animation with 8-second highlight
- Severity badges — Critical / High / Medium / Low
- Classification badges — True Positive / False Positive / Needs Review
- Confidence score with animated arc gauge
- Backend offline detection with error state

### AI-Powered Triage (Claude)
Every alert is automatically triaged by Claude AI and returns:
- **Classification** — True Positive, False Positive, or Needs Review
- **Confidence score** — 0–100%
- **Severity** — Critical / High / Medium / Low
- **Triage summary** — specific evidence citing IPs, usernames, process names
- **Attack narrative** — plain-English story for non-technical managers
- **MITRE ATT&CK mapping** — tactic IDs, technique IDs, and descriptions
- **Attack timeline** — chronological event-by-event breakdown with raw logs
- **Recommended containment actions** — numbered step-by-step response
- **Pivotal event** — shows the key point during the attack

### Alert Detail Modal
- Full-screen overlay with severity colour coding
- Expandable timeline events showing raw log JSON
- Confidence arc animation
- MITRE ATT&CK chip tags

### L1 → L2 Escalation
- Escalate button sends a rich Slack Block Kit message to the L2 channel
- Message includes: alert title, severity, host, IP, triage summary, and a direct dashboard link
- Button transitions to green "✓ Escalated to L2 via Slack" on success
- Status persists in PostgreSQL

### Alert Classification
- Mark alerts as False Positive directly from the dashboard
- Updates classification and status in the database
- Reflected instantly in the UI

### Shift Metrics Panel
- Total alerts, True Positives, False Positives, Needs Review counts
- Classification split bar chart
- Top MITRE ATT&CK tactics seen this shift
- Hourly alert volume bar chart
- Average confidence score

### Realistic Log Generation
- **40% attack scenarios** — randomised, weighted selection
- **60% clean/benign logs** — realistic background noise
- Attack types: Brute Force + Lateral Movement, Phishing + C2 Beacon, Privilege Escalation + Data Exfiltration, Ransomware Precursor, Insider Threat, Credential Dumping (LSASS)
- Clean log types: Normal logons, DNS queries, process creation, file share access, scheduled tasks, Windows Update, service account activity
- All logs tagged with alert metadata for SIEM correlation

### Analyst Login
- Session-based login page (username/password via `.env`)
- Protects the entire dashboard

---

## How It Works

### End-to-End Flow

**1. Log Generation**
The Python log generator fires every 30 seconds. Each cycle randomly picks either an attack scenario (40% probability) or a clean/benign log (60% probability). Attack scenarios include realistic Windows Event IDs, process names, network connections, and lateral movement chains.

**2. SIEM Ingestion — Wazuh**
Every log (clean and attack) is shipped to Wazuh Cloud via the Wazuh Agent running on the VM. This gives full SIEM visibility — Wazuh applies its own correlation rules, generates alerts, and stores the complete raw log history. Clean logs go to Wazuh only. Attack logs go to both Wazuh and the FastAPI backend.

**3. FastAPI Backend Ingest**
Attack and false positive logs are POSTed to `POST /ingest`. Then immediately queues the alert for AI triage.

**4. Claude AI Triage**
The raw log chain is sent to Claude (`claude-sonnet-4-20250514`) with a structured prompt. Claude returns a JSON object containing the full triage report including classification, MITRE mapping, timeline, attack narrative, containment steps, and a KQL query targeting the pivotal event. The triage result is stored in PostgreSQL.

**5. Dashboard Display**
The React frontend polls `GET /alerts` every 10 seconds. New alerts appear with a shimmer highlight. L1 analysts click any alert to open the full detail modal.

**6. L1 Actions**
- **Investigate** — view full triage, timeline, MITRE tags, raw logs, KQL query
- **Escalate** — posts a Slack message to the L2 channel, marks alert as Escalated
- **Dismiss** — marks alert as False Positive

**7. L2 Notification**
Escalations are delivered to Slack as rich Block Kit cards containing the alert title, severity, confidence, source host, triage summary, and a direct link to the dashboard. L2 analysts are notified instantly with enough context to begin response.

---

## Prerequisites

Here's the updated section:

---

### Accounts & Services Required

| Service | Purpose |
|---|---|
| [Anthropic Console](https://console.anthropic.com) | Claude API for AI triage |
| [Wazuh Cloud](https://cloud.wazuh.com) | SIEM log management |
| [Slack](https://slack.com) | L2 escalation notifications |
| [No-IP](https://noip.com) | DDNS domain pointing to VM |
| [Microsoft Azure](https://portal.azure.com) | Cloud VM hosting |

---

### Local Development Requirements

- **Python 3.11+**
- **Node.js 20+** and npm
- **PostgreSQL 16** running locally
- **Git**

### Azure VM Requirements (Cloud Deployment)

- Windows Server 2022 VM — Standard B2s (2 vCPU, 4GB RAM)
- Static public IP
- NSG inbound rules open on ports 80, 443, 3389
- Chocolatey, Python, Node.js, PostgreSQL, NSSM, Caddy installed

---

## Project Structure

```
SOC_ALERT_TRIAGE_COPILOT/
│
├── backend/
│   ├── main.py              # FastAPI app — all API endpoints
│   ├── db.py                # PostgreSQL schema + async queries
│   ├── claude_triage.py     # Claude AI triage engine
│   ├── slack_notifier.py    # Slack Block Kit escalation messages
│   ├── sentinel.py          # Azure Sentinel polling (optional)
│   ├── requirements.txt
│   └── .env                 # Backend secrets (not committed)
│
├── log-generator/
│   ├── log_generator_local.py   # Synthetic log generator v2
│   ├── requirements.txt
│   └── .env                     # Generator config (not committed)
│
├── my-app/                  # React + Vite frontend
│   ├── src/
│   │   ├── App.jsx          # Main dashboard component
│   │   ├── index.css        # Global reset styles
│   │   └── main.jsx
│   ├── .env.local           # Frontend env vars (not committed)
│   ├── vite.config.js       # Dev proxy config
│   └── package.json
```

---

## Environment Variables

### `backend/.env`

```env
ANTHROPIC_API_KEY=sk-ant-your-key-here
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/socdb
DASHBOARD_BASE_URL=https://mdrcopilot.ddns.net
```

### `log-generator/.env`

```env
BACKEND_URL=http://localhost:8000
CYCLE_INTERVAL=30
LOG_OUTPUT_FILE=C:\YourPath

```

### `my-app/.env.local`

```env
VITE_API_URL=/backend
VITE_DASHBOARD_USER=yourusername
VITE_DASHBOARD_PASS=password
```

---

## Local Setup

```bash
# 1. Clone the repo
git clone https://github.com/youruser/soc-copilot.git
cd soc-copilot

# 2. Create the database
psql -U postgres -c "CREATE DATABASE socdb;"

# 3. Backend
cd backend
python -m venv venv && venv\Scripts\activate   # Windows
pip install -r requirements.txt
# Create .env with your keys (see above)
uvicorn main:app --reload --port 8000

# 4. Log Generator (new terminal)
cd log-generator
python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt
# Create .env (see above)
python log_generator_local.py

# 5. Frontend (new terminal)
cd my-app
npm install
# Create .env.local (see above)
npm run dev

# Open http://localhost:5173
```

---

## Cloud Deployment (Azure)

**Summary:**
1. Create Azure Resource Group + Windows Server 2022 VM (Standard B2s)
2. Set static public IP, open ports 80/443/3389 in NSG
3. Point `mdrcopilot.ddns.net` A record to VM public IP via No-IP
4. RDP into VM — install Python, Node, PostgreSQL, Caddy, NSSM via Chocolatey
5. Copy project files, create `.env` files, build React frontend (`npm run build`)
6. Write Caddyfile pointing to your domain
7. Register FastAPI, log generator, and Caddy as Windows Services via NSSM
8. Start all three services — dashboard live at `https://mdrcopilot.ddns.net`

**Teardown:** Delete the `your_resource_group` resource group in Azure Portal. All resources are removed instantly and billing stops.

---

## SIEM Integration

### Wazuh (Active)

The Wazuh Agent runs on the Azure VM and ships all generated logs to Wazuh Cloud. The log generator uses the Wazuh REST API to inject events under a configured agent. Both clean and attack logs are visible in the Wazuh dashboard for full SIEM correlation.

---

<div align="center">
  <sub>Built for KPMG Managed Detection & Response · Confidential</sub>
</div>





## Run on Cloud (Only for developer reference)

```bash
nssm start MDRBackend
nssm start MDRCaddy
nssm start MDRLogGenerator
```

Stop services
```bash
nssm stop MDRBackend
nssm stop MDRCaddy
nssm stop MDRLogGenerator
```

```bash
psql -U postgres -d socdb -c "TRUNCATE TABLE alerts;"
```