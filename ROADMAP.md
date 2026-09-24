# Heimdall DFIR roadmap

Last reviewed: 10 August 2026

[Français](ROADMAP.fr.md) · [README](README.md) · [Changelog](CHANGELOG.md)

This roadmap describes direction, not release promises. Priorities may move when an investigation exposes a data-integrity, security or workflow problem. Work already shipped belongs in the [changelog](CHANGELOG.md); this document keeps only enough recent context to explain what comes next.

## Current state

Heimdall can already support a complete lab workflow: open a case, import a Windows or Linux collection, review the timeline, run detections, organise findings and draft a report. The main task now is to make that path predictable and supportable before adding another large set of screens.

| Area | State in the repository |
| --- | --- |
| Case workflow | Cases, assignees, investigation phases, Kanban, findings, DFIQ questions and collaborative report drafts are present |
| Ingestion | Windows collections, CatScale, CSV, PCAP and memory workflows are present; recent work added per-file state, deduplication and clearer parser outcomes |
| Timeline | Search, grouping, column preferences, saved searches, context and comparison views are present |
| Hunting | YARA, Sigma, Hayabusa, IOC correlation and YAML detection packs are present; some older review and alert panels still need to be reconnected or retired |
| Network analysis | Case and global graphs, lateral-movement analysis, annotations and PCAP-derived connections are present |
| Collaboration | Assignments, case chat, notebooks, real-time rooms and shared report editing are present |
| Administration | Accounts, sessions, password policy, retention, audit verification, backups and service health are present |
| Tests | Backend and frontend unit/integration suites exist, but critical browser journeys and deployment tests are still missing |

The application version is not described here on purpose: package files, health output and the changelog currently disagree. Establishing one release version is part of the work below.

## Recent work

Since the previous roadmap was written, the repository has gained or substantially revised:

- the investigation workspace, DFIQ question sets, Kanban and collaborative report editing;
- saved timeline searches, context and comparison views;
- a more explicit ingestion pipeline with per-file status, deduplication, CSV-aware imports and automatic hunting;
- CatScale parsing and Linux-specific detection rules;
- case-scoped real-time rooms and tighter route-level access controls;
- audit-log chaining, security and retention settings;
- the network investigation workflow and lateral-movement views;
- a common visual language across the main application and threat-hunting screens;
- a much larger backend and frontend test suite.

## Now: reliability and trust

These items take priority over new forensic domains.

### One release identity

Use one application version in the backend, frontend, health endpoint, installer and changelog. Release notes should distinguish the application version from database migration numbers.

Done means a tagged build reports the same version everywhere and both language READMEs can link to the same release notes.

### A safe first installation

Remove weak initial-password behaviour, make optional services genuinely optional, and clean up stale Compose and installer comments. Document the trust boundary created by the Docker socket, exposed MinIO ports and an Elasticsearch service without internal authentication.

Done means a fresh installation can be completed without a known default password and the operator can choose whether to start Ollama and host-management features.

### A tested analyst journey

Reconnect or remove dormant review, playbook, SOAR and triage panels. Fix role-dependent navigation so an action never leads to a route the user cannot open. Add browser tests for the path from case creation to import, timeline, finding and report.

Done means the supported journey has no dead navigation and runs in CI against a fresh database.

### Predictable ingestion

Keep expanding fixture-based tests for real collection layouts, interrupted jobs, parser failures and re-imports. Align documented upload limits with the limits actually enforced by each route. Make recovery steps visible to the operator.

Done means every imported file reaches a clear terminal state and a retry cannot silently duplicate timeline records.

### Restore and audit drills

Test PostgreSQL, Elasticsearch, MinIO and evidence-volume restoration together. Keep audit-key separation explicit and verify both row integrity and chain continuity. Describe secure deletion as storage-dependent rather than promising a named erasure standard on every volume.

Done means a documented drill can restore a representative case and explain which integrity properties are, and are not, verified.

## Next: useful gaps

The order inside each group is deliberately open. An issue should define scope and acceptance criteria before implementation starts.

### Analyst workflow

- reusable case templates with checklists, required fields and report defaults;
- team and group assignment beyond individual assignees;
- a responsive baseline for triage and review, without pretending the full desktop timeline fits on a phone;
- complete English coverage for the built-in forensic documentation;
- end-to-end tests for destructive confirmations, legal hold and concurrent report edits.

### Detection quality

- an analyst feedback loop for false positives and rule exceptions;
- known-good and prevalence signals to reduce noise;
- signed-driver and vulnerable-driver context;
- measurable rule-pack quality using versioned fixtures;
- better beaconing analysis for jittered or low-volume traffic.

### Interoperability

- OpenAPI documentation and outbound webhooks;
- audit forwarding and a documented SIEM export format, including Splunk HEC;
- bidirectional MISP workflows; current integration pulls indicators only;
- a Velociraptor bridge for live-response handoff rather than rebuilding endpoint collection in Heimdall;
- import and export contracts that can be tested independently of the UI.

### Additional evidence sources

- email containers and messages (`.eml`, `.msg`, `.pst`);
- cloud audit sources for Microsoft 365, Azure and AWS;
- NTDS.dit and deeper Active Directory artefacts;
- container and Docker artefacts;
- local binary triage with explicit sandbox and licensing boundaries.

### Operations and identity

- MFA using TOTP or WebAuthn/FIDO2;
- periodic review of the security policy, supported versions and private reporting workflow;
- SSO through SAML or OIDC, followed by LDAP only if there is a clear deployment need;
- Prometheus metrics and a small, maintained Grafana dashboard;
- tested backup scheduling, capacity alerts and queue saturation warnings;
- a deployment guide for disconnected networks.

## Later: scale after measurement

Multi-server work should start only after representative load tests show where the current Compose deployment fails.

- horizontal parser and hunting workers;
- cross-case campaign analysis with explicit access rules;
- larger timeline storage, with ClickHouse considered only after measurement;
- MSSP multi-tenancy with hard tenant isolation;
- a versioned plugin API;
- Kubernetes packaging once the service and storage contracts are stable.

## Project boundaries

Heimdall is not trying to become a general-purpose SIEM, a hosted evidence service or a replacement for endpoint live response. Local model features may assist with search and drafting, but they must not turn an unverified model response into a forensic conclusion or hide the supporting evidence.

## How work is chosen

When two items compete, preference goes to the one that:

1. protects case isolation or evidence integrity;
2. removes a failure from the normal analyst journey;
3. improves repeatability through tests, logs or documented recovery;
4. supports an evidence source users can provide and maintain fixtures for;
5. keeps the self-hosted deployment understandable.

To propose an item, open an issue describing the analyst problem, a representative input and the expected result. Small, testable changes are easier to review than a feature pitch with no evidence sample.
