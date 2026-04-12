```
╔╦══════════════════════════════════════════════════════════════════════╦╗
║║                                                                      ║║
╠╬══  H  E  I  M  D  A  L  L  ═════════════════════════════  v 0 . 9  ══╬╣
║║                                                                      ║║
║║   ██╗  ██╗███████╗██╗███╗   ███╗██████╗  █████╗ ██╗     ██╗          ║║
║║   ██║  ██║██╔════╝██║████╗ ████║██╔══██╗██╔══██╗██║     ██║          ║║
║║   ███████║█████╗  ██║██╔████╔██║██║  ██║███████║██║     ██║          ║║
║║   ██╔══██║██╔══╝  ██║██║╚██╔╝██║██║  ██║██╔══██║██║     ██║          ║║
║║   ██║  ██║███████╗██║██║ ╚═╝ ██║██████╔╝██║  ██║███████╗███████╗     ║║
║║   ╚═╝  ╚═╝╚══════╝╚═╝╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝     ║║
║║                                                                      ║║
╠╬══════════════════  DFIR & THREAT HUNTING WORKBENCH  ═════════════════╬╣
║║                                                                      ║║
╚╩══════════════════════════════════════════════════════════════════════╩╝
```

# Heimdall DFIR

> *Guardian of the Nine Worlds — See the unseen.*

[![EN](https://img.shields.io/badge/lang-EN-blue)](README.md)
[![FR](https://img.shields.io/badge/lang-FR-blueviolet)](README.fr.md)
![Version](https://img.shields.io/badge/version-0.9.0-blue)
![Docker](https://img.shields.io/badge/docker-compose-2496ED)
![Node](https://img.shields.io/badge/node-18+-339933)
![React](https://img.shields.io/badge/react-18-61DAFB)
![Elasticsearch](https://img.shields.io/badge/elasticsearch-8.13-005571)
![License](https://img.shields.io/badge/license-MIT-green)

Heimdall DFIR is a **unified investigation cockpit** built for CSIRT / SOC / DFIR teams.
It ingests, correlates and visualises any forensic source — Windows/Linux artifacts,
network captures, RAM dumps — in a single, collaborative, real-time interface.

> ⚠️ **BETA NOTICE:** Heimdall DFIR is currently in beta. Not all features are fully functional yet, and you may encounter bugs. Use in production environments at your own risk.

> 📍 **[Roadmap →](ROADMAP.md)**

---

## Features

### 🔬 Forensic Analysis
- **Super Timeline** — multi-source ingestion via Elasticsearch, histogram, advanced host/user/type filters, pagination, CSV export
- **Collection isolation** — each source (Hayabusa, MFT, PCAP…) has its own timeline view with zero data spillage
- **Hayabusa** — Sigma detections on EVTX, colour-coded severity levels, direct IOC pivot
- **Zimmerman Parsers** — PECmd (Prefetch), MFTECmd ($MFT), LECmd (LNK), SBECmd (Shellbags)
- **PCAP Parser** — DNS/HTTP/TLS/TCP extraction via tshark → Super Timeline
- **Memory Forensics** — chunked upload up to 256 GB, automatic resume, VolWeb + Volatility 3

### 🛡️ Threat Hunting
- **YARA Engine** — CRUD rules, per-file or per-case scan, results with offsets and matched strings
- **Sigma Engine** — hunt on the Super Timeline, `contains/startswith/re` modifiers, MITRE mapping
- **GitHub Import** — bulk import from Neo23x0/signature-base, Yara-Rules/rules, SigmaHQ/sigma
- **TAXII/STIX Threat Intel** — TAXII 2.1 connector, Elasticsearch `threat_intel` index, automatic post-ingestion correlation

### 🎯 Automatic Detections
- **Timestomping** — `$SIA` vs `$FN` comparison (NTFS timestamps) on MFT artifacts
- **Double extension** — detects `.pdf.exe`, `.docx.scr`, etc. on MFT / LNK / Prefetch
- **C2 Beaconing** — coefficient of variation of connection intervals (beacon score 0–100)
- **Persistence** — Registry Run Keys, LNK Startup, BITS Jobs, Sigma Hayabusa (T1547/T1053)

### 📊 Triage & Investigation
- **Machine triage score** — 0–100, 16 rules (EVTX + Sysmon), CRITICAL/HIGH/MEDIUM/LOW levels
- **Lateral movement graph** — D3.js force-directed, Event IDs 4624/4648/4768/4769/4776/Sysmon 3
- **Attack Chain** — MITRE ATT&CK bookmarks, 14-phase kill chain, compact/full view
- **IOC Enrichment** — VirusTotal API v3 + AbuseIPDB, Redis 24h cache, inline badges
- **Threat Intel Correlations** — automatic IOC matching vs Super Timeline per case

### ⚡ SOAR & Automation
- **SOAR Engine** — YARA + Sigma + Threat Intel + Triage in parallel post-ingestion
- **Automatic alerts** — critical/high/medium/low severity, acknowledgement, real-time badge
- **DFIR Playbooks** — Ransomware (11 steps), RDP Compromise (10), Phishing (9), MITRE mapping per step
- **Legal Hold** — evidence freeze, HMAC-SHA256 signed downloadable manifest
- **Sysmon Configs** — SwiftOnSecurity, Neo23x0, olafhartong_modular, ion-storm bundled

### 🔒 Security & Administration
- **ClamAV** — mandatory AV scan post-upload, quarantine, live status per evidence item
- **Hard Delete DoD 5220.22-M** — 7-pass shred + Node.js fallback, DB cascade + ES index deletion
- **JWT Rotation** — 15-min access token + refresh token, Redis blacklist, logout revocation
- **Automatic Backup** — pg_dump | gzip, list + download from the admin interface
- **Health Dashboard** — live status of PostgreSQL / Elasticsearch / Redis / ClamAV / BullMQ
- **Docker Infrastructure** — CPU/RAM monitoring of all containers (dockerode), 5s auto-refresh
- **Audit Log** — all actions tracked with HMAC, admin export

### 🤖 Local AI (Ollama) — *functional beta*

> Requires [Ollama](https://ollama.com) — enabled via `OLLAMA_URL` in `.env`. Silently disabled if absent.

- **Global AI Chat** — floating button accessible from all pages, real-time SSE streaming, pre-built DFIR prompts by category (Windows artifacts, MITRE ATT&CK, network, memory…)
- **Case Copilot** — AI panel docked in each case, context automatically injected (IOCs, SOAR alerts, timeline artifacts, evidence, notes) for precise answers about the ongoing investigation
- **Persistence** — conversation history stored in DB per case, reloaded each session
- **Supported models** — `qwen3:14b` (default), `qwen2.5:7b/14b`, `deepseek-r1:8b`, `llama3.2:3b`, `mistral:7b`
- **No-think mode** — strips `<think>…</think>` tags for clean output (configurable)

### 👥 Collaboration
- **Live case chat** — Socket.io, DB persistence, message bubbles, deletion, unread badge
- **Real-time presence** — list of analysts connected to a case
- **Investigation notes** — CRUD on every timeline artifact, XSS sanitisation
- **Enriched PDF report** — machine triage, YARA results, Threat Intel correlations, kill chain

---

## Architecture

```
 Browser
    │
    ▼
[bifrost / nginx :80/:443]       ← rate-limit, security headers, SSL
    │
    ├──▶ [asgard / frontend :3000]    React 18 · Vite · D3.js · TanStack Table
    │
    └──▶ [odin / backend :4000]       Node.js · Express · TypeScript (ts-node)
              │
              ├──▶ [yggdrasil / postgres :5432]    full DFIR schema (18 migrations)
              ├──▶ [hermod / redis :6379]           BullMQ queues · sessions · JWT blacklist
              ├──▶ [mimir / elasticsearch :9200]    Super Timeline (per-case index)
              ├──▶ [tyr / clamav :3310]             real-time AV analysis
              └──▶ [huginn / worker]                BullMQ consumer (concurrency=2)
                        │
                        ├── Zimmerman Tools  (PECmd · MFTECmd · LECmd · SBECmd)
                        ├── Hayabusa
                        └── tshark (PCAP)

RAM analysis branch:
    ├──▶ [njord / minio :9000]        S3 dump storage (console :9001)
    ├──▶ [hel-api / hel-worker]       VolWeb Django + Celery + Volatility 3
    └──▶ [hel-proxy :8888]            VolWeb Nginx (SSO Magic Link from Heimdall)
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Vite, D3.js, Recharts, TanStack Table, socket.io-client, react-resizable-panels |
| Backend | Node.js 18+, Express, TypeScript (ts-node transpileOnly), socket.io |
| Queue | BullMQ, ioredis |
| Database | PostgreSQL 16 |
| Cache / Sessions | Redis 7 |
| Full-text search | Elasticsearch 8.13 |
| Object storage | MinIO (S3 API) |
| Memory analysis | VolWeb + Volatility 3 |
| Antivirus | ClamAV 1.4.3 |
| Threat Hunting | YARA (libyara), Sigma (js-yaml), TAXII 2.1 / STIX 2.1 |
| Network | tshark (PCAP parsing) |
| Containerisation | Docker Compose v2 |
| Reverse proxy | Nginx (rate-limit, CSP, HSTS, SSL) |

---

## Getting Started

### Prerequisites

- Docker ≥ 24 + Docker Compose v2
- `openssl` (secret generation)
- 8 GB RAM minimum recommended (Elasticsearch + VolWeb)

### Installation

```bash
git clone https://github.com/RaiseiX/Heimdall-DFIR.git
cd Heimdall-DFIR
bash start.sh
```

The script handles everything automatically:
- Checks prerequisites (Docker, openssl)
- Generates all secrets (JWT, DB, Redis, MinIO…) via `openssl rand`
- Builds and starts all containers
- Waits for PostgreSQL to be ready
- Applies all SQL migrations (v2.7 → v2.22)

**Access after install:**

| Service | URL |
|---------|-----|
| Heimdall UI | http://localhost |
| API | http://localhost:4000 |
| VolWeb (RAM) | http://localhost:8888 |
| MinIO console | http://localhost:9001 |

### Post-startup configuration

```bash
# Create the VolWeb superuser (RAM forensics)
docker exec -it hel-api python manage.py createsuperuser
# Then create a bucket named "volweb" at http://localhost:9001

# Local AI (optional)
# Set OLLAMA_URL=http://ollama:11434 in .env, then:
docker exec ollama ollama pull qwen3:14b
```

### Environment variables

| Variable | Required | Description |
|----------|:--------:|-------------|
| `DB_PASSWORD` | ✅ | PostgreSQL password |
| `REDIS_PASSWORD` | ✅ | Redis password |
| `JWT_SECRET` | ✅ | `openssl rand -hex 64` |
| `ALLOWED_ORIGINS` | ✅ | Frontend URL (CORS), e.g. `http://localhost:3000` |
| `MINIO_ROOT_USER` | ✅ | MinIO / VolWeb access key |
| `MINIO_ROOT_PASSWORD` | ✅ | MinIO / VolWeb secret key |
| `VOLWEB_DJANGO_SECRET` | ✅ | `openssl rand -hex 50` |
| `DOCKER_GID` | ✅ | Docker socket GID — `stat -c %g /var/run/docker.sock` |
| `VIRUSTOTAL_API_KEY` | ⬜ | IOC enrichment VirusTotal (optional) |
| `ABUSEIPDB_API_KEY` | ⬜ | IOC enrichment AbuseIPDB (optional) |
| `GITHUB_TOKEN` | ⬜ | GitHub rules import — rate limit 60 → 5,000 req/h (optional) |
| `OLLAMA_URL` | ⬜ | Local AI Ollama, e.g. `http://ollama:11434` (optional) |

### Default credentials *(change in production)*

| Role | Login | Password |
|------|-------|----------|
| Admin | `admin` | `Admin2026!` |
| Analyst | `analyst` | `Analyst2026!` |

---

## Data Sources & Parsers

### Zimmerman Tools (Windows Artifacts)

| Parser | Artifact | Description |
|--------|----------|-------------|
| **Hayabusa** | EVTX (`.evtx`) | Sigma detections — critical/high/medium/low levels |
| **EvtxECmd** | EVTX (`.evtx`) | Raw Windows event logs |
| **MFTECmd** | `$MFT` | Master File Table — timestamps, paths, sizes |
| **PECmd** | Prefetch (`.pf`) | Execution history, DLL dependencies |
| **LECmd** | LNK (`.lnk`) | Recent files, volumes, target machines |
| **SBECmd** | Shellbags | Folder navigation history (NTUSER.DAT / UsrClass.dat) |
| **AmcacheParser** | `Amcache.hve` | Installed/executed programs |
| **AppCompatCacheParser** | ShimCache (SYSTEM) | Application execution (Shimcache) |
| **RECmd** | Registry hives (SAM, SYSTEM, NTUSER.DAT) | Forensic registry keys |
| **JLECmd** | Jump Lists (`.automaticDestinations-ms`) | Recent files per application |
| **SrumECmd** | SRUM (`SRUDB.dat`) | Network & CPU usage per process |
| **SQLECmd** | SQLite (`.sqlite`, `.db`) | Chrome / Firefox / Edge history (cookies, history) |
| **RBCmd** | Recycle Bin (`$I*`) | Deleted files — original path, size, date |
| **BitsParser** | BITS (`qmgr*.dat`) | BITS transfers (persistence, downloads) |

### Other sources

| Source | Parser | Output |
|--------|--------|--------|
| PCAP (`.pcap`, `.pcapng`) | tshark | DNS / HTTP / TLS ClientHello / TCP flows → Timeline |
| RAM dumps (`.raw`, `.vmem`, `.mem`, `.dmp`) | Volatility 3 via VolWeb | Processes, network connections, memory artifacts |
| Any file (< 5 GB) | ClamAV | AV scan, quarantine, live status |
| TAXII 2.1 feeds | Internal TAXII client | Elasticsearch `threat_intel` index |

---

## CyberChef Forensic

Native React implementation of a decoder/deobfuscator — **no external dependency**.

**Available operations:**

| Category | Operations |
|----------|-----------|
| Specialised | PowerShell `-EncodedCommand` (Base64 + UTF-16LE) |
| Encoding | Base64 (standard / URL-safe), Hex (↔), URL (↔), HTML Entities, Char codes (dec/hex/oct), UTF-16LE → Text |
| Cipher | ROT13 / Caesar (configurable shift), XOR (1-byte hex key) |
| Transform | Reverse (char / line / word), Remove Null Bytes |
| Extract | Strings (configurable min length), URLs, IP Addresses, Regex |
| Analyse | Statistics + Shannon entropy |

**Automatic obfuscation detection:** heuristic analysis that detects encoded PowerShell, Base64, `\xAB` hex, URL-encoding, decimal charcode, HTML entities, high entropy — and suggests the corresponding decoding operations with a confidence score.

---

## Memory Forensics — VolWeb

VolWeb is a collaborative platform built on Volatility 3. It is natively integrated into Heimdall via an **SSO Magic Link** (one click from the evidence tab → automatic login with no re-authentication).

**Volatility plugins available in VolWeb:**
- `windows.pslist` / `windows.pstree` — process list and tree
- `windows.cmdline` — command-line arguments
- `windows.netscan` / `windows.netstat` — active network connections
- `windows.dlllist` — DLLs loaded by process
- `windows.handles` — open handles
- `windows.malfind` — memory injection detection
- `windows.svcscan` — Windows services
- `windows.registry.hivelist` / `printkey` — in-memory registry artifacts
- And more depending on the installed VolWeb version

**RAM upload:**
- Chunked upload (50 MB/chunk, configurable) up to **256 GB**
- Automatic resume (localStorage + status endpoint)
- Zero corruption: positional writes on pre-allocated sparse file
- Async streaming to VolWeb (zero RAM buffering)

---

## Required third-party tools (not included)

The following tools must be placed in the Docker volumes:

| Tool | Volume | Path |
|------|--------|------|
| [Zimmerman Tools](https://ericzimmerman.github.io/) (.NET DLLs) | `zimmerman_tools` | `/app/zimmerman-tools/` |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) (Linux binary) | `uploads_data` | `/app/hayabusa/hayabusa` |

```bash
# Example — copy Hayabusa into the backend container
docker cp hayabusa odin:/app/hayabusa/hayabusa
docker exec odin chmod +x /app/hayabusa/hayabusa
```

---

## Credits

- [Zimmerman Tools](https://ericzimmerman.github.io/) — Windows forensic parsers
- [Hayabusa](https://github.com/Yamato-Security/hayabusa) — Sigma EVTX scanner (Yamato Security)
- [VolWeb](https://github.com/k1nd0ne/VolWeb) — collaborative Volatility 3 platform
- [Volatility Foundation](https://www.volatilityfoundation.org/) — memory analysis
- [ClamAV](https://www.clamav.net/) — open-source antivirus engine
- [Elastic](https://www.elastic.co/) — search & analytics engine
- [SigmaHQ](https://github.com/SigmaHQ/sigma) — official Sigma rules
- [Neo23x0 / signature-base](https://github.com/Neo23x0/signature-base) — reference YARA rules
- [Yara-Rules](https://github.com/Yara-Rules/rules) — community YARA collection
- [MITRE ATT&CK](https://attack.mitre.org/) — tactics and techniques framework

---

## License

MIT © Heimdall DFIR Contributors
