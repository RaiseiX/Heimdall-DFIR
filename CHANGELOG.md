# Changelog — Heimdall DFIR

All notable changes to this project are documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) — Semantic Versioning.

---

## [1.1.0] — 2026-05-05 — AI Engine Overhaul, Forensics Agents & Network Map Rebuild

### Added (AI Engine — Architecture)

- **`aiRouter.ts` — new Ollama orchestration layer** (`backend/src/services/aiRouter.ts`) — replaces the naive `isAvailable()` env-var check with a real HTTP probe against `/api/tags`; 60 s cached `OllamaStatus` with model tier detection (`fast` < 7 B / `standard` 7–13 B / `deep` ≥ 14 B); `selectModel(tier)` picks the best installed model for the requested tier with graceful fallback; `invalidateCache()` for admin-panel model pulls
- **`/api/chat` migration** — replaced `/api/generate` (single-turn completion) with Ollama's `/api/chat` (messages array); conversation history (last 10 turns) is now included in every request, enabling genuine multi-turn forensics dialogue; history is fetched **before** saving the new user message to avoid duplication
- **Qwen 3.5 thinking mode** — `/think` or `/no_think` prefix injected into the system message; the stream parser separates `<think>…</think>` tokens and emits them as `{ reasoningToken }` SSE events so the frontend can render the model's chain-of-thought in a collapsible panel
- **SSE keepalive during inference** — a `setInterval` ping every 5 s prevents Traefik's `responseHeaderTimeout` from closing the connection before the first token on slow 14 B models
- **`GET /llm/status`** — new endpoint returning `{ reachable, models[], tier, preferred: { fast, standard, deep } }`; admin panel now shows which model tier is active and which specific model will handle the next request
- **Model tier detection** (`aiRouter.ts`) — parameter count parsed from model name (`qwen3.5:14b` → 14 B); `probe()` returns `preferred` map with the best available model per tier; `selectModel()` falls back gracefully when a tier is not installed

### Added (AI Engine — Features)

- **3 Forensics Agents** (`backend/src/services/aiService.ts`) — inspired by My_AI's domain-specific temperature-tuned agents:
  - `triage` (temp 0.1) — verdict in 5 lines max: CRITICAL/HIGH/MEDIUM/LOW/BENIGN + MITRE ID + one action; zero creativity, maximum precision for rapid classification
  - `analysis` (temp 0.3) — 4-section deep dive: Observation → Hypothèse → ATT&CK Techniques → Recommandations
  - `narrative` (temp 0.5) — executive/legal-quality prose: résumé exécutif + chronological narrative + impact + recommendations; jargon explained inline
- **Analyst Feedback / RLHF-lite** — 👍 / 👎 buttons on each completed assistant message; stored in new `ai_feedback` table (`case_id UUID`, `user_id`, `rating SMALLINT CHECK IN (-1,1)`, `agent_type`, `model`, `msg_ref`, `created_at`); togglable (click again to un-record); fires `POST /cases/:caseId/ai/feedback` asynchronously without blocking the UI
- **Admin active-model selector** (`frontend/src/pages/AdminPage.jsx`) — new accent-bordered "Modèle actif" card above the test section; dropdown of all installed models + "Définir" button with 2.5 s "✓ Enregistré" confirmation; choice persisted to `localStorage` key `heimdall.ai.activeModel`; copilot modal initialises from this key (prefers stored value if model is still installed, falls back to first available model otherwise)
- **Agent selector chips in copilot** (`AiCopilotModal.jsx`) — ⚡ Triage / 🔍 Analyse / 📄 Rapport chip bar in the footer; active chip highlighted in accent colour; chips disabled while streaming; `agentType` forwarded in the stream request body
- **Default model changed to `qwen3.5:4b`** — optimised for analyst machines without a high-end GPU (3 GB VRAM, CPU-friendly); configurable via `AI_MODEL` env var; `.env.example` updated

### Changed (AI Engine)

- `aiService.ts` no longer imports `http` directly — all Ollama HTTP calls delegated to `aiRouter.ts`; file is now purely DFIR context-building + conversation orchestration
- `chat()` and `chatStream()` accept two new optional parameters: `thinkingMode: ThinkingMode` (default `'no_think'`) and `agentType: AgentType` (default `'analysis'`); both endpoints in `ai.ts` destructure these from the request body

### Added (MODEL_CATALOG)

- `qwen3.5:4b` — tagged `recommandé`, 2.6 Go, Heimdall default
- `qwen3.5:7b` — tagged `qualité`, 4.7 Go
- `qwen3.5:14b` — tagged `deep`, 9 Go, thinking mode recommended
- `qwen2.5:7b` retained as "génération précédente — stable et éprouvé"
- New tag colour `'deep': '#e879f9'` added to `TAG_COLOR`

### Added (Network Map — Bug Fixes)

- **Sysmon EID 3 source IP extraction fixed** (`backend/src/routes/network.js`) — the graph query was using `raw->>'Computer'` (machine hostname) as the source IP; Sysmon EID 3 stores the actual source IP in `raw->>'SourceIp'`; the new COALESCE priority: `SourceIp → src_ip column → SourceAddress → host_name → Computer → 'local'`; this fix unblocks network graph population for every EVTX-based case
- **`DestinationHostname` preferred over raw IP for destination nodes** — `DestinationHostname` (resolved domain name, e.g. `c2.evil.com`) is now the first option in the dst COALESCE chain; nodes show meaningful hostnames instead of raw IPs, making the graph immediately more readable for analysts
- **`DestinationIp` / `dst_ip` column added to filter condition** — the `WHERE` clause now also triggers on the structured `dst_ip INET` column, catching parsers that populate the column directly rather than raw JSON

### Added (Network Map — New Features)

- **Process name on edges** — `raw->>'Image'` (Sysmon EID 3 initiating process) extracted as `process_name` and stored in `edge.processes[]` (max 5 per edge to keep payload small); displayed as a purple `⚙ powershell.exe` chip in the event list when clicking a node
- **Time-range filter** — `from_ts` / `to_ts` ISO timestamp parameters accepted by `GET /network/:caseId/graph-data` and `GET /network/:caseId/beacons`; frontend: two `datetime-local` inputs in the graph toolbar with a clear button; changing the range re-fetches both the graph and beacons; params appended dynamically to avoid renumbering existing SQL `$N` placeholders
- **Beaconing detection endpoint** (`GET /network/:caseId/beacons`) — CTE with `LAG()` window function computes inter-connection intervals per `(src, dst, port)` group; pairs with CV (stddev/avg) < 0.35 and ≥ 5 events returned with `beacon_score = (1 − CV) × 100`; score 95+ = clock-regular C2 beacon; includes `processes[]`, `interval_avg_sec`, `first_seen`, `last_seen`
- **Beacon visualisation** (`NetworkGraphD3.jsx`) — beacon edges rendered in dashed orange (#f97316) instead of blue; dashed orange ring drawn around both endpoints of a beacon pair; beacon chip in node panel: `📡 beacon 91% · ∅300s`; beacon count chip in toolbar: `📡 3 beacons détectés`; beacons loaded in parallel with the graph on mount and re-fetched on time filter change
- **DGA score on domain nodes** — `computeDgaScore()` (Shannon entropy + consonant ratio + length + digit count + pattern) called inline when building `nodeMap`; score stored as `node.dga_score`; domains scoring ≥ 70 auto-flagged `is_suspicious = true`; red dashed outer ring on domains ≥ 60; `DGA 82%` chip in node side panel
- **Truncation warning** — `buildNetworkGraph()` returns `{ truncated: bool, limit: 500 }`; frontend shows an amber warning bar below the toolbar when the cap was hit; advises using the time filter or evidence filter to isolate a window; LIMIT raised from 300 → 500
- **`/graph-data/events` enriched** — side panel events now include `process_name` (from `raw->>'Image'`), `dst_port`, `protocol`; node lookup also searches `src_ip::text` and `dst_ip::text` columns so Sysmon-parsed rows with structured INET columns are found correctly
- **`networkAPI.beacons(caseId, params)`** added to `frontend/src/utils/api.js`

### Database Migrations

- `db/migrate_v2.27.sql` — `ALTER TABLE workbench_evidence_pins/audit ALTER COLUMN … TYPE UUID` hotfix for existing deployments (also in v1.0.0 — repeated here for completeness)
- `ai_feedback` table — inline migration in `server.js`: `id BIGSERIAL`, `case_id UUID`, `user_id UUID`, `rating SMALLINT CHECK IN (-1,1)`, `agent_type VARCHAR(32)`, `model VARCHAR(100)`, `msg_ref TEXT`, `created_at TIMESTAMPTZ`; GIN index `idx_ai_feedback_case` on `case_id`

---

## [1.0.0] — 2026-05-05 — Production Hardening: Codebase Audit, Docker Stack & Traefik TLS

### Fixed (Codebase Health Check — Critical)

- **[C-1] DB: UUID/INTEGER type mismatch on Workbench tables** — `migrate_v2.25.sql` declared `case_id` / `pinned_by` / `actor_id` as `INTEGER` while `cases.id` and `users.id` are `UUID`; every INSERT to `workbench_evidence_pins` and `workbench_evidence_audit` threw a PostgreSQL FK violation, silently breaking the entire Evidence Bridge and hash-chain ledger; fixed column types to `UUID` in the `CREATE TABLE` blocks; new `db/migrate_v2.27.sql` applies `ALTER TABLE … ALTER COLUMN … TYPE UUID` for existing deployments
- **[C-2] Frontend TypeScript: `react-window` undeclared + missing `@types`** — `react-window` was consumed by `ParserConsole.tsx:9` but absent from `package.json`; `@types/react-window` was not installed; `npm run typecheck` exited with code 2 (`TS7016`); added `react-window ^1.8.8` to dependencies and `@types/react-window ^1.8.8` to devDependencies; also added missing `width="100%"` prop to the `<FixedSizeList>` call (`ParserConsole.tsx:394`) which caused a second `TS2769` overload error once types were resolved; `npm run typecheck` now exits 0
- **[C-3] Frontend: `"Bearer null"` Authorization header** — `localStorage.getItem('heimdall_token')` returns `null` when the token is absent; `Authorization: \`Bearer ${token}\`` produced the literal string `"Bearer null"` instead of an omitted header, causing hard-to-diagnose 401s; fixed with a conditional spread at both call sites (`ParserConsole.tsx:137` and `:229`)

### Fixed (Codebase Health Check — High)

- **[H-2] Duplicate CSS object keys in three JSX files** — `border: 'none'` + `borderTop` declared twice on the same style object in `Layout.jsx:323`; `alignItems: 'center'` declared twice in `CaseDetailPage.jsx:762`; `border: 'none'` + `border: \`1px solid …\`` declared twice in `SuperTimelineWorkbench.jsx:3037`; JS engines silently use the last value, masking intent; duplicate keys removed from all three files; Vite build no longer emits duplicate-key warnings
- **[H-3] Stale `onSuccess` closure in `ParserConsole` socket callback** — `useCallback` for `parser:status` event closed over the `onSuccess` prop but only listed `[appendLog]` as a dependency; after a parent re-render changed `onSuccess`, the callback held a stale reference; added `onSuccess` to the dependency array (`ParserConsole.tsx:178`)
- **[H-4] Missing `AbortController` on fetch calls in `ParserConsole`** — two fetch chains (mount-time evidence/parser list, `handleRun` button) had no abort mechanism; on component unmount mid-request, React logged state-update-on-unmounted-component warnings; added `AbortController` with `return () => controller.abort()` cleanup to the mount `useEffect`; added `runControllerRef` (aborted on re-run and on component unmount via a dedicated cleanup `useEffect`) to the `handleRun` callback; abort errors are now silently swallowed and do not trigger the error branch

### Added (Docker Infrastructure Hardening)

- **Backend Dockerfile multi-stage build** — split the 162-line single stage into `tool-fetcher` (downloads .NET 9, 15 Zimmerman ZIPs, Hayabusa) + `runtime` (system deps, Python, copies tools from Stage 1, Node app); Stage 1 is Docker-layer-cached independently from source code; iterative rebuild time reduced from ~20 min to ~3 min on code changes; base image remains `node:20-bookworm-slim` (Alpine incompatible with .NET 9 + tshark + yara due to musl libc)
- **Resource limits on all 16 services** — `deploy.resources.limits` + `reservations` added to every service in `docker-compose.yml`; limits are tuned to DFIR workloads: `huginn` (BullMQ worker) 4 CPU / 8 GB, `hel-worker` (Volatility 3) 4 CPU / 12 GB, `hel-worker-yara` (YARA scan) 1 CPU / 6 GB, `odin` (backend) 2 CPU / 4 GB, `yggdrasil` (Postgres) 2 CPU / 4 GB; prevents a runaway Volatility job from OOM-killing the host
- **Healthchecks for 5 previously unmonitored services** — `odin` (backend): `curl -sf http://localhost:4000/api/health`; `huginn` (worker): process presence check via `ps`; `bifrost` (reverse proxy): `wget http://localhost:8080/ping`; `hel-api` (volweb-backend): `curl http://localhost:8000/`; `muninn` (PgBouncer): `pg_isready`; all services now have `service_healthy` conditions wired up the dependency chain
- **Dependency chain hardening** — `bifrost` (reverse proxy) now waits for `backend: service_healthy` and `frontend: service_healthy` before starting; `hel-worker` and `hel-worker-yarascan` now wait for `volweb-backend: service_healthy`; removes race-condition window where workers started before their upstreams were ready
- **3-network isolation** — replaced single flat `aesir-net` with `frontend-net` (Traefik ↔ frontend only), `heimdall-net` (all Heimdall internal services), `volweb-net` (isolated VolWeb stack); `frontend` (asgard) is on `frontend-net` only and cannot reach PostgreSQL or Redis directly; `db`, `redis`, `minio` are on both `heimdall-net` and `volweb-net` as shared infrastructure
- **PgBouncer `muninn`** — new `bitnami/pgbouncer:1.23.1` service in transaction pool mode; 200 virtual client connections multiplexed to 25 real PostgreSQL connections; `backend` and `worker` now use `DB_HOST=pgbouncer` instead of `DB_HOST=db`; prevents `max_connections` saturation under concurrent parsing + Volatility + AI analysis; VolWeb continues using `DB_HOST=db` directly (Django ORM compatibility)
- **BullMQ queue hardening** (`backend/src/config/queue.ts`) — `attempts` raised from 1 → 3 with exponential backoff (5 s → 10 s → 20 s); `timeout: 30 * 60 * 1000` hard-kills stuck jobs after 30 minutes; `removeOnComplete` / `removeOnFail` now include TTL (`age: 86400` / `age: 7 * 86400`) preventing unbounded queue growth
- **BullMQ job progress reporting** (`backend/src/workers/parserWorker.ts`) — `makeEmitterIO()` now intercepts `parser:status` socket events and mirrors `recordCount` into `job.updateProgress()`; BullMQ admin dashboard and future polling clients can track live ingestion progress with zero changes to `parserService.ts`
- **Infrastructure roadmap** — `tasks/docker_infrastructure_roadmap.md` documenting all changes, resource limit table, PgBouncer rationale, and architectural pitches (Traefik TLS, Prometheus + Grafana observability)

### Added (Traefik v3 — Automatic TLS)

- **Traefik v3.0 replaces nginx as reverse proxy** — `bifrost` container now runs `traefik:v3.0` instead of `nginx:alpine`; static config at `docker/traefik/traefik.yml`; hot-reloaded dynamic config at `docker/traefik/dynamic/config.yml`; Docker socket mounted read-only (`:ro`) — sufficient for label discovery, improves security posture
- **Automatic Let's Encrypt TLS** — TLS challenge resolver configured; on first start with a public domain + reachable ports 80/443, Traefik issues and renews certificates with zero manual steps; falls back silently to an internal self-signed cert for `localhost` or private networks; `letsencrypt_data` named volume persists `acme.json` across container restarts; HTTP → HTTPS permanent redirect on entrypoint `web` (:80)
- **4-router backend routing with priorities** — `heimdall-auth` (priority 30, `PathPrefix(/api/auth)`) uses `auth-ratelimit@file` (5 req/min, burst 3 — brute-force protection); `heimdall-socket` (priority 20, `PathPrefix(/socket.io)`) has no rate limit and passes WebSocket upgrades transparently; `heimdall-api` (priority 10, `PathPrefix(/api)`) uses `api-ratelimit@file` (30 req/s, burst 50); `heimdall-frontend` (priority 1, catch-all `Host()`) serves the React SPA
- **`heavy@file` serversTransport** — 7200 s `responseHeaderTimeout` + 3600 s `readIdleTimeout` for forensic upload operations (10 GB+ collection imports, 5 GB memory dumps, Volatility analysis triggers); all backend routes use this transport, matching the previous nginx `proxy_read_timeout 7200s` behaviour on heavy endpoints
- **`security-headers@file` middleware** — HSTS (1 year, includeSubDomains, preload), `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` (geolocation/mic/camera/payment/usb blocked), CSP, server identity header stripped; applied to all 4 routers
- **TLS hardening** — `docker/traefik/dynamic/config.yml` sets TLS 1.2 minimum and a modern cipher suite (ECDHE-ECDSA/RSA + AES-256-GCM / AES-128-GCM / ChaCha20-Poly1305); disables legacy RC4 / 3DES / CBC suites
- **Per-container network routing** — `traefik.docker.network=heimdall-net` on backend, `traefik.docker.network=frontend-net` on frontend; Traefik uses the correct IP for each container across the multi-network topology; no global network restriction needed in the Docker provider
- **`.env.example` updated** — `DOMAIN` (default `localhost`) and `ACME_EMAIL` (default `admin@heimdall.local`) documented; production deployment requires only updating these two variables

### Dependencies

- `react-window ^1.8.8` added to `frontend/package.json` dependencies (was transitive-only, now explicit)
- `@types/react-window ^1.8.8` added to `frontend/package.json` devDependencies

### Database Migrations

- `db/migrate_v2.27.sql` — hotfix: `ALTER TABLE workbench_evidence_pins ALTER COLUMN case_id TYPE UUID`, `ALTER COLUMN pinned_by TYPE UUID`; `ALTER TABLE workbench_evidence_audit ALTER COLUMN case_id TYPE UUID`, `ALTER COLUMN actor_id TYPE UUID`; repairs existing deployments that ran the original v2.25 migration with incorrect INTEGER FK types

---

## [0.9.9] — 2026-04-19 — Automated Threat Engine & Greyware Tagging

### Added
- **Threat Engine v2.26** (`backend/src/services/threatEngine.js`) — YAML-driven rule engine with `all/any/none` boolean AST, leaf ops `eq/neq/in/gte/lte/contains/icontains/regex/iregex`; artifact/event-id bucketed matcher runs in the ingest hot path (target ≤ 5 µs/record); mtime-cached hot-reload from `backend/config/threat_rules/*.yaml`
- **5 rule packs (61 rules)** — `rmm.yaml` (8: AnyDesk, TeamViewer, Atera, ScreenConnect, Splashtop, AeroAdmin, ConnectWise, RemotePC → Greyware/T1219), `anti_forensics.yaml` (8: log clear 1102/104, vssadmin/wbadmin delete, wevtutil cl, fsutil usn, cipher /w, bcdedit recovery, timestomp → Critical/High), `lolbin.yaml` (20: certutil/bitsadmin/regsvr32 Squiblydoo/mshta/rundll32 script/wmic/installutil/cmstp/msbuild/msiexec_remote/forfiles/pcalua/odbcconf/ieexec/hh/xwizard/presentationhost/pubprn_vbs/mavinject/powershell_encoded → T1218), `credential_access.yaml` (10: mimikatz/lsass access EID 10/dcsync/shadow creds/SAM dump/NTDS.dit/secretsdump/lazagne/kerberoasting burst/skeleton key → T1003), `persistence.yaml` (15: Run keys, Startup LNK, schtasks, service 7045, WMI event sub, BITS, logon scripts, IFEO accessibility, COM hijack, Winlogon tamper, Active Setup, DLL search order, Domain Admins add 4732/4728/4756, At legacy, service binpath shell → T1547/T1546/T1053/T1543/T1574/T1098)
- **DB migration `db/migrate_v2.26.sql`** — `collection_timeline.detections JSONB`, GIN `jsonb_path_ops` index, partial index for hits-only filter
- **Ingest wiring** (`backend/src/routes/collection.js:extractForensicFields`) — engine evaluates each record; matched rule tags auto-merged into `tags[]`; `detections[]` persisted to DB via extended COPY batch (29 columns)
- **Timeline query params** — `?detections=hits_only`, `?detection_severity=critical|high|medium|greyware`, `?detection_category=rmm|lolbin|...`; all force the Postgres path with safe `jsonb @>` containment filters
- **`GET /api/collection/:caseId/detections/summary`** — returns `{ total, by_severity, by_category, top_rules[10] }` via `jsonb_array_elements` + window functions; feeds the Workbench dashboard tile
- **Super Timeline UI** — new `🎯 Detections` column (severity-ranked pills: CRIT/HIGH/MED/GREY with per-rule tooltip showing name + MITRE); 3px left-border accent now honors the highest detection severity per row (no full-row neon — "No Christmas Tree rule"); filter drawer gains `🎯 Hits uniquement` toggle + sévérité-min dropdown
- **Workbench `DetectionsSummaryBanner`** — gradient banner on Timeline tab showing total hits + per-severity chips + top-3 rule names; auto-fetches `/detections/summary` on tab mount
- **Architecture doc** — `tasks/threat_engine_architecture.md` (Phase 2 deliverable) locking v1 scope at 5 packs / ~60 rules

## [0.9.8] — 2026-04-18 — Evidence Bridge & Workbench Foundation

### Added
- **Evidence Bridge** — persistent store (`frontend/src/state/evidenceBridge.js`, Zustand + `localStorage` key `heimdall.evidenceBridge.v1`) sharing pinned forensic rows between Super Timeline and Workbench; keyed by `caseId`, capped at 500 pins/case, dedup on `collection_timeline_id`
- **Super Timeline → Pin UX**
  - Cell right-click menu gains "📌 Épingler dans le Workbench" (purple accent, with already-pinned / max-pins guards + toast feedback)
  - New keyboard shortcut `P` on the focused row for one-key pinning
- **Pinned-row focus round-trip** — `/super-timeline?caseId=<id>&focus=<collection_timeline_id>` resolves the pinned row in `colFilteredRecords`, auto-expands its ancestor groups if grouping is active, scrolls via `rowVirtualizer.scrollToIndex(..., { align: 'center' })`, opens the details panel, and toasts "🎯 Ligne épinglée localisée"; Workbench's "↗ Timeline" button now uses this URL
- **Workbench tab** (`/cases/:id/workbench`) — new top-level tab in `CaseDetailPage` with Pin icon + pink count badge
  - `WorkbenchEvidenceTab` component: artifact-colored stripe per card, chips (artifact / tool / EID / MITRE), timestamp, host/user
  - Per-row analyst note textarea (auto-persisted), tri-state status (Triage / Confirmé / Rapporté), unpin, "↗ Timeline" jump-back
  - Toolbar: pin counter (N/500), status filter chips, fuzzy search across description/source/tool/host/user/note, 3 sort modes, Markdown clipboard export, JSON export, "vider le Workbench"
  - **Findings Board view** — new toggle (Liste / Board) beside the sort dropdown; kanban with 3 columns (Triage / Confirmé / Rapporté), native HTML5 drag-and-drop between columns updates status in-place, per-case view preference persisted via `heimdall.wb.view.<caseId>` localStorage key; compact cards show artifact chip, EID, MITRE, description (3-line clamp), host/user/timestamp, analyst note preview (2-line clamp), jump-back + unpin buttons
  - **Backend sync (multi-analyst)** — new `workbench_evidence_pins` table (v2.25 migration) with UUID pin_id, full forensic columns, `tags TEXT[]`, status, note, color; unique partial index `(case_id, collection_timeline_id)` prevents duplicate pinning server-side; new `/api/workbench-pins/:caseId` routes (GET list, POST create, PATCH update, DELETE single, DELETE clear); hybrid Zustand store — optimistic localStorage write then fire-and-forget REST sync; `hydrateFromServer(caseId)` called on Workbench tab mount (server wins on reconnect); WebSocket broadcasts `workbench:pin:{added,updated,removed,cleared}` to `case:<id>` room for multi-analyst collaboration
  - **Tamper-evident chain-of-custody ledger** — new `workbench_evidence_audit` append-only table; every mutation (pin / unpin / update / clear) appends one row whose `content_hash = sha256(prev_hash || action || canonical_payload_json)` via a deterministic JSON encoder (keys sorted recursively), forming a verifiable hash chain per case; `GET /api/workbench-pins/:caseId/audit` returns the full ledger plus `{ verified: bool, broken_at: seq|null, count }` for defensibility in legal proceedings
  - **Ledger UI** — new `Ledger` view in the Workbench (ShieldCheck icon); verification banner surfaces `Chaîne de preuve vérifiée` vs `CHAÎNE ALTÉRÉE` (with `broken_at` seq on rupture), operation count, distinct-analyst count, and SHA-256 chain-intact indicator; expandable per-entry rows show action-colored chip (pin/update/unpin/clear/import), actor name, UTC timestamp, truncated content hash, pin_id, prev_hash, content_hash, and a pretty-printed payload block; Refresh + Export JSON buttons for offline verification
  - **Live multi-analyst WebSocket sync** — `WorkbenchEvidenceTab` now subscribes to `workbench:pin:{added,updated,removed,cleared}` events on the shared `case:<id>` room (room membership already wired in `CaseDetailPage`); new `applyServer{Pin,Update,Remove,Clear}` store actions apply server-pushed changes **without** re-emitting REST sync, so concurrent analysts see each other's pins, status transitions, and unpins in real time with no echo loop
  - **Persistence Sweep analyzer** — new `Persistance` view (shield icon) runs 11 MITRE detection rules against pinned rows' description/source/tool/host blob: T1547.001 Registry Run Keys, T1547.009 LNK Startup, T1543.003 Windows Services, T1053.005 Scheduled Tasks, T1546.003 WMI Event Subscription, T1197 BITS Jobs, T1037.001 Logon Scripts, T1546.008 Accessibility Features (sethc/utilman/osk IFEO debuggers), T1546.015 COM Hijacking, T1574.011 Service Registry Perms, T1547.004 Winlogon Helper DLL; aggregates a weighted Persistence Score (low/medium/high/critical color bands), shows hits per MITRE technique with click-to-jump-back to Super Timeline
  - **Logon Session Reconstruction analyzer** — new `Sessions` view (logon icon) groups pinned `evtx/hayabusa` events with EID 4624/4625/4634/4647/4648 by extracted `TargetLogonId / LogonId` (regex against description), reconstructs sessions with start/end/duration, decodes LogonType (2=Interactive, 3=Network, 5=Service, 10=RDP…), extracts `Source Network Address` IP, classifies status (open / closed / failed / partial), renders one row per session with colored status stripe, inline event-chip strip (4624 green, 4625 red), jump-back to Super Timeline on chip click
  - **Pin → Rapport** — new "Rapport" toolbar button generates a printable forensic findings document (Blob URL, auto-invokes `window.print()`); respects current filters (status / search), fetches case metadata via `casesAPI.get()`, renders cover page (case number, title, investigator, description, generated-at UTC), summary counters, findings grouped by status (Rapporté → Confirmé → Triage) with accent-colored section headers; each finding includes artifact chip, tool, EID, MITRE, UTC timestamp, description, source, host/user context, analyst note (highlighted block), and a **chain-of-custody table** exposing `pin_id`, `pinned_at` UTC, `pinned_by`, `collection_timeline_id`, `dedupe_hash` for defensibility
- **EVTX per-EventID MITRE map** (`EVTX_MITRE_BY_EID` in `backend/src/routes/collection.js`) — 4624→T1078, 4625→T1110, 4688→T1059, 1102→T1070.001, 7045→T1543.003, 4698→T1053.005 applied for both `evtx` and `hayabusa` artifacts
- **Hayabusa forensic enrichment** — description regex extraction of ext/path/src_ip/dst_ip/details; INSERT extended from 20 to 25 columns so v2.23 unified fields populate at parse time
- **`hydrateTimelineRow`** — backend-side derivation of missing v2.23 columns (tool, event_id, ext, host_name, user_name, process_name, path, timestamp_kind) from `raw` JSON at GET time; applied to both Elasticsearch and Postgres response paths so legacy docs predating v2.23 no longer render blank TOOL/EID/EXT
- **`db/migrate_v2.24.sql`** — idempotent backfill for legacy rows (1679 tool/event_id rows + per-EventID MITRE for 6 event IDs)
- **Universal toolbar collapse** — `tl.toolbarCollapsed` localStorage flag now honored in all Super Timeline modes (not just workbench), freeing ~110-140 px of vertical table space
- **Architecture proposal** — `tasks/workbench_vs_timeline_architecture.md` documenting the Workbench vs Timeline split (shell, Evidence Bridge, typography enforcement, build sequence)

### Changed
- **Super Timeline Workbench tabs pruned** — reduced from 13 to 6 tabs (Timeline, MITRE, Persistance, IoA, Kill Chain, Export) to match real DFIR workflows; removed low-signal/overlapping views: Gantt, Heatmap, Dissimulation, Processus, Cluster, Multi-hôte, IA (IA remains accessible via the global Copilot modal `Ctrl+I`); command palette entries and tab-navigation hotkeys updated accordingly

### Fixed
- **EVTX / Hayabusa blank TOOL / EVENT ID / EXT** — Elasticsearch docs from v2.22 and earlier displayed empty unified columns despite the data being present in `raw`; resolved via the new `hydrateTimelineRow` path (no ES reindex required)
- **AppCompatCache path in Process column** — `ECS_COLUMNS.process` arrays cleared for `appcompat`, `mft`, `shellbags`, `registry`, `recycle`, `sqle` (no valid process concept for those artifacts)

### Dependencies
- **zustand ^4.5.0** added to `frontend/package.json` (Evidence Bridge store + persist middleware)

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
