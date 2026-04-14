# Changelog — Heimdall DFIR

All notable changes to this project are documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) — Semantic Versioning.

---

## [0.9.7] — 2026-04-14 — Security & Architecture Audit

### Security
- **XSS hardening** — `CaseDetailPage` print report and `BookmarkPanel` PDF export: added `esc()` helper escaping all 15+ adversary-controlled interpolations (`title`, `description`, `event_type`, `ioc_type`, `value`, `mitre_tactic`, CSS color attribute); eliminates MFT filename → stored XSS → analyst session hijack vector
- **Timestamp UTC enforcement** — all 30+ components previously calling `toLocaleString('fr-FR')` without timezone now route through `fmtLocal()` (UTC-forced, labelled); affected views: AdminPage, ThreatHuntPage, ThreatIntelPage, SuperTimelinePage, CaseDetailPage, ParserLogsPage, UsersPage, AttackChain, BookmarkPanel, CaseTimelineExplorer, SuperTimelineWorkbench, PlaybooksTab, LateralMovementGraph, SoarAlertsPanel, LateralMovementD3, AttackPathD3, NetworkGraphD3, AiCopilotModal
- **Print reports timezone** — case report and bookmark PDF timestamps now render as `YYYY-MM-DD HH:mm:ss UTC` instead of analyst browser local time

### Fixed
- **`normalizeTimestamp`** — offset-aware timestamps (e.g. `2023-01-15T14:30:00+02:00`) were silently discarded due to double-append of timezone suffix; now correctly converted to UTC ISO string
- **`useDateFormat` tzLabel** — default (non-UTC mode) was silent empty string; now shows `(local)` to prevent ambiguity between analysts in different timezones

### Performance / Memory
- **`parserWorker` backup** — replaced `spawnSync` with `spawn` pipeline (`pg_dump | gzip → file`); eliminates 512 MB heap ceiling that caused `ENOBUFS` on large forensic databases
- **CSV threshold** — `LARGE_CSV_THRESHOLD` lowered from 30 MB to 5 MB, reducing worst-case synchronous heap allocation from ~150 MB to ~25 MB

### Removed
- **`backend/src/routes/parsers.js`** — dead route never mounted in `server.js`; removed to eliminate accidental re-enable risk (full-file `readFileSync` OOM vector)

### Added
- **`fmtLocal(ts)`** utility in `utils/formatters.ts` — UTC-aware `toLocaleString` wrapper, shared across all non-super-timeline date displays
- **Admin → À propos** — new tab with collapsible credits table listing all integrated open-source DFIR tools (EZ Tools / MIT, Hayabusa / GPL 3.0, VolWeb / MIT, Volatility 3 / Volatility Software License)

---

## [0.9.6] — 2026-04-01 — Initial Public Release

### Added
- **VolWeb / RAM Analysis** — full stabilization of the upload pipeline (up to 256 GB)
  - Sparse pre-allocated file writes — no more corruption on network retry
  - Full async streaming to VolWeb via `createReadStream` + `FormData` (zero memory buffering)
  - Resume support: automatic detection of interrupted uploads, skips already-received chunks
  - Auto-provisioning: VolWeb superuser + MinIO bucket created on first start
  - Automatic VolWeb polling every 30s post-analysis with `volweb:completed` WebSocket notification
- **SOAR Engine** — automated parallel detection post-ingestion (YARA + Sigma + Threat Intel + Triage)
  - `automated_hunt_alerts` table with deduplication and per-alert acknowledgement
  - Auto-triggered after collection parse and BullMQ worker jobs
  - Real-time badge via WebSocket in case detail page
- **Collection Isolation** — each evidence collection fully isolated in Super Timeline
  - `evidence_id` column on `collection_timeline` (migration v2.18)
  - 3-layer IDOR protection: UUID validation → PostgreSQL ownership check → Elasticsearch term filter
- **Advanced Detections**
  - Timestomping: `$SIA` vs `$FN` comparison on MFT artifacts
  - Double extension: regex detection on MFT, LNK, Prefetch, Amcache
  - C2 Beaconing: coefficient of variation on connection intervals per destination IP
  - Persistence: 4 MITRE vectors (Registry Run Keys T1547.001, LNK Startup T1547.009, BITS Jobs T1197, Hayabusa Sigma)
- **Infrastructure & Admin**
  - Live Docker container dashboard: CPU%, RAM%, status (5s auto-refresh)
  - DoD 5220.22-M 7-pass hard delete (`shred -n 7 -z -u`) with Node.js fallback
  - DB backup trigger + direct download from admin UI
  - JWT rotation + Redis blacklist: 15min access token, revocable refresh token
- **Timeline UX**
  - Multi-select artifact type filter
  - Hayabusa row highlighting by severity (critical/high/medium/low)
  - Universal CSV export with configurable delimiter (`,` / `;` / Tab)
- **Enriched PDF Report** — Triage scores, YARA results, Threat Intel correlations, kill chain

### Fixed
- Frontend Dockerfile: replaced heredoc `<< 'SERVEREOF'` with `COPY server.js` for compatibility with non-BuildKit Docker builders

### Infrastructure
- Migrations: v2.18 (`evidence_id` on `collection_timeline`), v2.22 (`chunk_size`, `received_chunks_set` on `memory_uploads`)

---

## [0.9.5] — 2026-03-10

### Added
- **Conformité DoD** — Hard delete 7-pass with audit log (`wipe_standard: 'DoD 5220.22-M'`)
- **Docker Infrastructure Dashboard** — Dockerode integration, live container stats
- **JWT Rotation** — 15min access token + refresh token blacklist in Redis (migration v2.15)
- **DB Backup** — `pg_dump | gzip` via admin API, downloadable from UI
- **Audit Log** — extended to cover `logout`, `token_refresh`, `pcap_parse`, `backup_db`, `run_soar`

---

## [0.9.4] — 2026-03-07

### Added
- **SOAR Engine** (initial) — `automated_hunt_alerts` table, `soarService.ts`, fire-and-forget triggers
- **Phase 3 Threat Hunting** — persistence detector, multi-select type filter, Hayabusa severity highlighting
- **Bug Bash** — 5 fixes (file_size on import, React key prop, crypto require, socket catch, fmtSize TB)

---

## [0.9.3] — 2026-03-07

### Added
- **Playbooks DFIR** — 3 built-in playbooks (Ransomware 11 steps, RDP 10, Phishing 9), MITRE tags, per-step notes
- **Legal Hold** — HMAC-SHA256 signed manifest, admin-only toggle, UI banner
- **PCAP Parser** — tshark-based extraction (DNS, HTTP, TLS, TCP flows) into `collection_timeline`

---

## [0.9.2] — 2026-03-05

### Added
- **Chat live par cas** — Socket.io + DB persistence, floating panel, unread badge
- **Export CSV universel** — full-export from backend, configurable delimiter
- **Export STIX 2.1** — IOC bundle with STIX patterns, downloadable from case detail
- **Rapport PDF enrichi** — Triage scores §6, YARA §7, Threat Intel §8, Kill Chain §9

---

## [0.9.1] — 2026-03-01

### Added
- **Health Dashboard Admin** — PostgreSQL, Elasticsearch, Redis, ClamAV, BullMQ checks with LED indicators
- **Bookmarks + Attack Chain** — `timeline_bookmarks` table, BookmarkPanel, AttackChain kill chain (14 MITRE phases)
- **Lateral Movement Graph** — D3.js force-directed, Event IDs 4624/4648/4768/4769/4776/Sysmon 3
- **Triage Score** — 16 detection rules (EVTX + Sysmon), per-hostname risk score 0–100

---

## [0.9.0] — 2026-02-15

### Added
- Initial internal release
- Core DFIR platform: Cases, Evidence, Timeline, IOCs, Network, Reports
- Elasticsearch Super Timeline (index per case)
- BullMQ Worker architecture (parser isolation)
- ClamAV antivirus scan on upload
- VolWeb integration (Volatility 3 + MinIO)
- YARA + Sigma Threat Hunting
- TAXII/STIX Threat Intel connector with auto-correlation
- IOC enrichment (VirusTotal + AbuseIPDB)
- Sysmon open-source configs (SwiftOnSecurity, Neo23x0, olafhartong, ion-storm)
- Security audit: command injection fixes, secrets hardening, CORS, Docker USER, Nginx headers
