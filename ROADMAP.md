# Heimdall DFIR — Roadmap V2.0

> *Updated 2026-03-31*
> *Written from a Principal Staff Engineer / CPO Cybersecurity perspective.*
>
> Contributions are welcome — open an issue to discuss an idea.

[![EN](https://img.shields.io/badge/lang-EN-blue)](ROADMAP.md)
[![FR](https://img.shields.io/badge/lang-FR-blueviolet)](ROADMAP.fr.md)

---

## Strategic Positioning

### Why Heimdall Must Constantly Evolve

Adversaries continuously evolve their TTPs. A static DFIR tool becomes blind: new log sources appear (EDR, cloud, containers), event volumes explode, and teams expect tools that **think with them**, not just for them.

### Differentiation Axes

| Competitor | Strength | Our Answer |
|-----------|---------|------------|
| **Magnet AXIOM** | 1000+ parsers, mobile | Data sovereignty, real-time collab, local AI |
| **Elastic Security** | Scale, ML, SIEM | Self-hosted, air-gapped, simple deployment |
| **TheHive + Cortex** | Case management | Native timeline, unified threat hunting, Investigation Graph |
| **Timesketch** | Timeline Elasticsearch | Collaboration, SOAR, LLM Copilot, multi-case |
| **Velociraptor** | Live response | Offline forensics, accessible UI, auto-report |
| **Autopsy** | Carving, GUI | Web-native, multi-user, real-time |

### V2.0 Vision

> *"Heimdall is the only open-source DFIR workbench that combines offline forensics,
> real-time collaboration, unified threat hunting and sovereign local AI intelligence —
> designed for teams that cannot put their data in the cloud."*

The V2.0 ambition is to move from *"good DFIR timeline tool"* to *"collaborative, AI-augmented and sovereign threat intelligence platform"* — a tool that DFIR teams never want to leave, that MSSPs can offer their clients, and that universities use to train the next generation of analysts.

---

## ✅ v0.9.0 — Current foundation (completed)

### Foundation missions
- [x] **M1** — Super Timeline Elasticsearch (per-case index, bulkIndex, searchTimeline)
- [x] **M2** — Hard Delete DoD 5220.22-M (7-pass shred + Node.js fallback)
- [x] **M3** — Real-time collaboration (Socket.io rooms, presence, dashboard:update)
- [x] **M4** — BullMQ Workers architecture (parser-jobs queue, Redis pub/sub, isolated worker service)
- [x] **M5** — ClamAV + VolWeb (Volatility 3, MinIO, SSO Magic Link, 256 GB chunked upload)
- [x] **M6** — Workbench UI + Investigation Notes (TanStack Table, Split-Pane, XSS sanitisation)
- [x] **M7** — Full security review (SQL/command injection, secrets, CORS, Docker, Nginx headers)
- [x] **M8** — YARA / Sigma Threat Hunting + GitHub import (Neo23x0, Yara-Rules, SigmaHQ)
- [x] **M9** — TAXII / STIX Threat Intel (ES `threat_intel` index, automatic correlation)

### Feature missions
- [x] **C.1** — IOC Enrichment VirusTotal + AbuseIPDB (Redis 24h cache)
- [x] **B.1** — Machine triage score (0–100, 16 EVTX + Sysmon rules) + open-source Sysmon Configs
- [x] **B.2** — D3.js lateral movement graph (EIDs 4624/4648/4768/4769/4776)

### DFIR v2.7 plans (Blocs 1–6)
- [x] **Bloc 1** — ECS on collection_timeline, Hayabusa → Timeline, host/user filters, temporal gaps
- [x] **Bloc 2** — Multi-select artifacts, Hayabusa severity highlighting, Persistence detection
- [x] **Bloc 3** — Automatic detections: Timestomping, Double Extension, C2 Beaconing
- [x] **Bloc 4** — Live case chat, universal CSV export, STIX 2.1 export, enriched PDF report
- [x] **Bloc 5** — Health Dashboard, JWT Rotation + Redis blacklist, automatic DB Backup
- [x] **Bloc 6** — DFIR Playbooks (Ransomware/RDP/Phishing), HMAC Legal Hold, PCAP parser (tshark), Docker Infrastructure

### Critical missions
- [x] **Collection isolation** (v2.18) — `evidence_id` FK + 3-layer anti-IDOR, zero spillage
- [x] **SOAR Engine** — YARA + Sigma + TI + Triage in parallel post-ingestion, socket alerts
- [x] **RAM Stabilisation** (v2.22) — sparse positional writes, `INTEGER[]` idempotence, localStorage resume, async VolWeb streaming
- [x] **AI Copilot** (Ollama) — global SSE chat, per-case copilot with injected forensic context, DB persistence

### Features outside initial roadmap (bonus delivered)
- [x] Native CyberChef Forensic (Base64/Hex/XOR/ROT13, automatic obfuscation detection)
- [x] MITRE ATT&CK tab + APT Attribution
- [x] Attack Chain (14-phase kill chain, bookmarks)
- [x] Network Graph + PCAP analysis (tshark)
- [x] Collection Agent scripts (CatScale)
- [x] Cross-case IOCs (`/api/iocs/cross-case`)
- [x] Case Risk Score (`riskScoreService.ts`)
- [x] TAXII SSRF fix (`networkUtils.ts`)
- [x] Structured logging winston (`config/logger.ts`)
- [x] Per-user rate limiting (`rateLimiter.ts`)

---

## 📊 Global implementation status

```
Quick Wins    : ▓▓▓▓▓▓░░░░  6/9  implemented  (1 partial · 2 not started)
Core Features : ▓▓▓▓▓░░░░░  5/25 implemented  (5 partial · 15 not started)
Moonshots     : ░░░░░░░░░░  0/7  (long-term vision)
Off-roadmap   : ▓▓▓▓▓▓▓▓▓▓ 13 additional features delivered
```

### Quick Wins

| ID | Feature | Status | Notes |
|----|---------|:------:|-------|
| QW-1 | Cross-case IOCs | ✅ | `/api/iocs/cross-case`, SQL view, dashboard widget |
| QW-2 | Timeline Enrichment | 🔶 | ContextMenu button OK, missing inspector integration |
| QW-3 | Case Risk Score | ✅ | `riskScoreService.ts` — 0-100 score, Redis cache |
| QW-4 | TAXII SSRF Fix | ✅ | `networkUtils.ts` — private hostname/IP validation |
| QW-5 | Structured logging (winston) | ✅ | `config/logger.ts` — structured JSON + AsyncLocalStorage |
| QW-6 | Per-user rate limiting | ✅ | `rateLimiter.ts` — 5 jobs max/user, HTTP 429 |
| QW-7 | MFA TOTP / FIDO2 | ❌ | Not started |
| QW-8 | Case Templates | 🔶 | Report templates OK, missing case checklist/workflow |
| QW-9 | Mobile PWA | ❌ | Not started |

### Core Features

| ID | Feature | Status | Notes |
|----|---------|:------:|-------|
| CF-1 | Local LLM Copilot (Ollama) | ✅ | `aiService.ts`, SSE streaming, per-case context |
| CF-2 | Investigation Graph | 🔶 | NetworkGraphD3 network OK, missing full investigation graph |
| CF-3 | Case Team Management | ❌ | Not started |
| CF-4 | SIEM Export | 🔶 | STIX 2.1 + ES OK, missing native Splunk HEC format |
| CF-5 | Prometheus + Grafana | ❌ | Not started |
| CF-6 | Automated tests | 🔶 | Jest configured, 1 unit test — no systematic suite |
| CF-7 | Enriched PDF report | ✅ | `reports.js` — templates, parameterisable sections, optional AI |
| CF-8 | Cloud Forensics AWS/Azure/M365 | ❌ | Not started |
| CF-9 | Live Response Bridge (Velociraptor) | ❌ | Not started |
| CF-10 | Local Binary Triage | ❌ | Not started |
| CF-11 | OpenAPI + Webhooks | ❌ | Not started |
| CF-12 | YARA/Sigma Community Hub | ❌ | Not started |
| CF-13 | Email Forensics (.eml/.msg/.pst) | ❌ | Not started |
| CF-14 | SSO / SAML 2.0 / LDAP | ❌ | Not started |
| CF-15 | CTF / Training Mode | ❌ | Not started |
| CF-16 | NLP Search | ❌ | Depends CF-1 ✅ — can start |
| CF-17 | Session Recording & Audit Log | ✅ | `auditLog` middleware + `audit_logs` table |
| CF-18 | Container / Docker Forensics | ❌ | Not started |
| CF-19 | Native Linux Forensics (CatScale) | ✅ | `catscaleService.ts`, full parser, dedicated tab |
| CF-20 | NTDS.dit / AD Forensics | 🔶 | Credential dump detection OK, missing NTDS.dit parsing |
| CF-21 | Bidirectional MISP | ❌ | TAXII/STIX pull OK, missing push to MISP |
| CF-22 | EDR Integration | ❌ | Not started |
| CF-23 | Deduplication & Noise Reduction | 🔶 | STIX/IOC dedup OK, missing global Signal mode |
| CF-24 | NIS2/GDPR Breach Notification | ❌ | Not started |
| CF-25 | Similar Case Detection | ❌ | Not started |

### Moonshots

| ID | Feature | Status |
|----|---------|:------:|
| MS-1 | Cross-case Campaign Intelligence | ❌ |
| MS-2 | Big Data Architecture (500M events/case) | ❌ |
| MS-3 | Advanced proactive AI Copilot | ❌ |
| MS-4 | Air-gapped & Sovereign Certification | ❌ |
| MS-5 | MSSP Multi-tenancy | ❌ |
| MS-6 | Plugin System (extensible architecture) | ❌ |
| MS-7 | UEBA — User & Entity Behavior Analytics | ❌ |

---

## 🗓️ Planning

> **Guiding principle**: *Make it work correctly → Make it work reliably → Make it scale.*

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 FOUNDATION — Security & Reliability (non-negotiable)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

2026 Q1 — Sprint 0
  ├─ [SEC]   QW-7 : MFA TOTP / FIDO2
  ├─ [CODE]  CF-6 : Backend tests — critical services
  ├─ [INFRA] pgBouncer (PostgreSQL connection pooling)
  ├─ [INFRA] PG + ES backup → MinIO + restore testing
  └─ [CODE]  QW-8 : Case Templates

2026 Q1-Q2 — Sprint 1 : Observability & Quick Wins
  ├─ CF-5  : Prometheus + Grafana
  ├─ QW-9  : Mobile PWA
  ├─ CF-16 : NLP Search (depends CF-1 ✅)
  └─ CF-6  : Route + integration tests

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 FEATURES — New functionality
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

2026 Q2 (April → July)
  ├─ CF-14 : SSO / SAML / LDAP        ← enterprise unlock
  ├─ CF-13 : Email Forensics           ← attack vector #1
  ├─ CF-8  : Cloud Forensics AWS/Azure/M365
  ├─ CF-19 : Native Linux Forensics (✅ partial)
  └─ CF-11 : OpenAPI + Webhooks

2026 Q3 (July → October)
  ├─ CF-2  : Investigation Graph       ← differentiator #2
  ├─ CF-3  : Case Team Management
  ├─ CF-9  : Live Response (Velociraptor)
  ├─ CF-10 : Local Binary Triage
  ├─ CF-18 : Container / Docker Forensics
  ├─ CF-20 : NTDS.dit / Active Directory
  ├─ CF-22 : EDR Integration (Phase 1)
  ├─ CF-23 : Deduplication & Noise Reduction
  └─ CF-6  : e2e tests + full coverage

2026 Q4 (October → January 2027)
  ├─ CF-4  : SIEM Export (Splunk HEC)
  ├─ CF-12 : YARA/Sigma Community Hub
  ├─ CF-15 : CTF / Training Mode
  ├─ CF-21 : Bidirectional MISP
  ├─ CF-24 : NIS2/GDPR Breach Notification
  ├─ CF-25 : Similar Case Detection
  └─ MS-4  : Air-gapped certification

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SCALE — Multi-server (stack proven in production)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

2027 Q1 — Docker Swarm (>20 analysts / multi-incident)
  ├─ Compose → Swarm migration
  ├─ Horizontal BullMQ worker scaling (0–10)
  └─ MS-1 : Campaign Intelligence

2027 Q2-Q3 — Moonshots
  ├─ MS-2 : Big Data Architecture (ClickHouse)
  ├─ MS-5 : MSSP Multi-tenancy
  ├─ MS-3 : Advanced AI Copilot (proactive)
  └─ MS-7 : UEBA — Behavior Analytics

2027 Q4+ — Kubernetes (>50 analysts / MSSP)
  ├─ Heimdall Helm chart
  ├─ HPA on parser-worker (autoscaling queue depth)
  └─ MS-6 : Plugin System
```

---

## Synthesis table

| ID | Feature | Effort | Impact | Differentiator | Priority |
|----|---------|:------:|:------:|:--------------:|:--------:|
| QW-7 | MFA TOTP / FIDO2 | S | XL | — | 🔴 P0 |
| CF-16 | NLP Search | S | XL | ✅ | 🔴 P0 |
| CF-6 | Automated tests | M | L | — | 🟠 P1 |
| CF-5 | Prometheus + Grafana | M | L | — | 🟠 P1 |
| CF-8 | Cloud Forensics AWS/Azure/M365 | M | XL | ✅✅ | 🟠 P1 |
| CF-9 | Live Response Bridge (Velociraptor) | M | XL | ✅✅ | 🟠 P1 |
| CF-13 | Email Forensics | M | XL | ✅ | 🟠 P1 |
| CF-14 | SSO / SAML / LDAP | S | L | — | 🟠 P1 |
| CF-18 | Container / Docker Forensics | M | XL | ✅ | 🟠 P1 |
| CF-19 | Native Linux Forensics | M | XL | ✅ | 🟠 P1 |
| CF-20 | NTDS.dit / AD Forensics | M | XL | ✅ | 🟠 P1 |
| CF-22 | EDR Integration | M | XL | ✅✅ | 🟠 P1 |
| CF-23 | Deduplication & Noise Reduction | M | L | — | 🟠 P1 |
| QW-8 | Case Templates | S | L | — | 🟠 P1 |
| QW-9 | Mobile PWA | S | M | — | 🟡 P2 |
| CF-2 | Investigation Graph | M | XL | ✅✅ | 🟡 P2 |
| CF-3 | Case Team Management | M | L | — | 🟡 P2 |
| CF-4 | SIEM Export | M | L | — | 🟡 P2 |
| CF-10 | Local Binary Triage | M | XL | ✅ | 🟡 P2 |
| CF-11 | OpenAPI + Webhooks | M | L | — | 🟡 P2 |
| CF-12 | YARA/Sigma Community Hub | M | XL | ✅✅ | 🟡 P2 |
| CF-15 | CTF / Training Mode | M | L | ✅✅ | 🟡 P2 |
| CF-17 | Session Recording & Audit Log | M | L | — | 🟡 P2 |
| CF-21 | Bidirectional MISP | M | L | — | 🟡 P2 |
| CF-24 | NIS2/GDPR Breach Notification | M | M | ✅✅ | 🟡 P2 |
| CF-25 | Similar Case Detection | M | L | ✅ | 🟡 P2 |
| MS-4 | Air-gapped certification | XL | XL | ✅✅ | 🟡 P2 |
| MS-1 | Campaign Intelligence | XL | XL | ✅✅ | 🔵 P3 |
| MS-2 | Big Data Architecture | XL | XL | ✅ | 🔵 P3 |
| MS-3 | Advanced AI Copilot | XL | XL | ✅✅ | 🔵 P3 |
| MS-5 | MSSP Multi-tenancy | XL | XL | ✅✅ | 🔵 P3 |
| MS-6 | Plugin System | XL | XL | ✅✅ | 🔵 P3 |
| MS-7 | UEBA Behavior Analytics | XL | XL | ✅✅ | 🔵 P3 |

---

## Contributing

1. Fork the project
2. Create a `feature/my-feature` branch
3. Open a Pull Request with a clear description

All contributions are subject to the MIT license.
