# Heimdall DFIR

Self-hosted DFIR and threat-hunting workbench for case-driven investigations, forensic artifact ingestion, collaborative analysis, and report generation.

[![FR](https://img.shields.io/badge/lang-FR-blueviolet)](README.fr.md)
[![Docker Compose](https://img.shields.io/badge/runtime-Docker%20Compose-2496ED)](docker-compose.yml)
[![Node.js](https://img.shields.io/badge/backend-Node.js%2020-339933)](backend/package.json)
[![React](https://img.shields.io/badge/frontend-React%2018-61DAFB)](frontend/package.json)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Heimdall DFIR is a **unified investigation cockpit** built for CSIRT / SOC / DFIR teams.
It ingests, correlates and visualises any forensic source — Windows/Linux artifacts,
network captures, RAM dumps — in a single, collaborative, real-time interface.
Discord link : https://discord.gg/sx7DnNYMNF

> Heimdall is in active development. Validate the full workflow in a controlled environment before using it for production investigations.

## Table of Contents

- [What Heimdall Does](#what-heimdall-does)
- [Core Capabilities](#core-capabilities)
- [Architecture](#architecture)
- [Repository Layout](#repository-layout)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Operations](#operations)
- [Developer Workflow](#developer-workflow)
- [Forensic Tooling](#forensic-tooling)
- [Documentation](#documentation)
- [Security Notes](#security-notes)
- [Credits](#credits)
- [License](#license)

## What Heimdall Does

Heimdall gives CSIRT, SOC, and DFIR teams a single cockpit to:

- manage investigations and evidence by case;
- upload and parse forensic artifacts;
- build searchable timelines;
- run YARA, Sigma, threat-intelligence, and rule-based detections;
- collaborate through notes, pins, chat, and analyst workbench views;
- analyze memory dumps through VolWeb and Volatility 3;
- generate investigation reports and preserve evidence context.

The project is designed for self-hosted and sovereignty-sensitive environments where evidence should remain under operator control.

## Core Capabilities

| Area | Capabilities |
| --- | --- |
| Case management | Case records, evidence inventory, comments, notes, pins, reports |
| Timeline analysis | Super Timeline, artifact filters, column preferences, grouping, search, CSV export |
| Evidence ingestion | Standard uploads, chunked memory uploads, collection imports, parser streaming |
| Windows forensics | EVTX, Hayabusa, MFT, Prefetch, LNK, Shellbags, registry-oriented workflows |
| Network analysis | PCAP-derived flows, network map, beaconing indicators, global graph views |
| Memory forensics | VolWeb integration, MinIO storage, Volatility 3 worker stack |
| Threat hunting | YARA, Sigma, TAXII/STIX, IOC enrichment, detection summaries |
| Automation | BullMQ workers, SOAR alerts, triage scoring, playbooks |
| Collaboration | Socket.io presence, case chat, workbench pins, audit ledger |
| Local AI | Optional Ollama-backed copilot and case-aware assistant workflows |
| Administration | Users, backups, service health, Docker container visibility, access logs |

## Architecture

```text
Browser
  |
  v
bifrost / Traefik :80/:443
  |
  +--> asgard / frontend :3000
  |      React 18, Vite, Tailwind, D3, TanStack Table
  |
  +--> odin / backend :4000
         Node.js, Express, TypeScript, Socket.io
         |
         +--> yggdrasil / PostgreSQL 16
         +--> hermod / Redis 7
         +--> mimir / Elasticsearch 8.13
         +--> tyr / ClamAV
         +--> huginn / BullMQ worker
         +--> njord / MinIO
         +--> hel-api, hel-worker, hel-ui / VolWeb + Volatility 3
         +--> ollama / optional local LLM
```

The runtime topology is defined in [docker-compose.yml](docker-compose.yml). Traefik handles external routing and TLS. Internal services are split across frontend, Heimdall, and VolWeb networks.

## Repository Layout

```text
.
├── backend/              Node.js API, services, middleware, workers, parsers
├── frontend/             React/Vite application and UI modules
├── db/                   Initial schema, migrations, migration runners
├── docker/               Traefik and VolWeb support configuration
├── docs/                 Architecture, backend, UI, infra, workflow notes
├── nginx/                VolWeb proxy configuration and legacy nginx files
├── prompts/              Agent prompts for scoped audits and implementation
├── tasks/                Engineering decisions, backlog, lessons, active notes
├── templates/            Delivery templates for audits, bugs, features, redesigns
├── docker-compose.yml    Main runtime stack
├── start.sh              Linux/macOS bootstrap script
└── start.ps1             Windows bootstrap script
```

## Quick Start

### Prerequisites

- Docker 24+ with Docker Compose v2
- `openssl` for secret generation on Linux/macOS
- 16 GB RAM recommended for a full local stack, especially with Elasticsearch, VolWeb, ClamAV, and Ollama
- 50 GB free disk recommended for test evidence and Docker volumes

### Linux / macOS

```bash
git clone https://github.com/RaiseiX/Heimdall-DFIR.git
cd Heimdall-DFIR
bash start.sh
```

### Windows PowerShell

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\start.ps1
```

The bootstrap scripts create `.env` from [.env.example](.env.example), generate secrets, build images, start services, wait for PostgreSQL, and apply database migrations.

### Access

| Service | URL |
| --- | --- |
| Heimdall UI | `https://localhost` or `http://localhost` depending on local browser/TLS handling |
| API health | `https://localhost/api/health` |
| MinIO console | `http://localhost:9001` |
| VolWeb proxy | `http://localhost:8888` |

Default accounts are initialized from `.env` on first database creation:

| Role | Username | Default password source |
| --- | --- | --- |
| Admin | `admin` | `ADMIN_DEFAULT_PASSWORD` |
| Analyst | `analyst` | `ANALYST_DEFAULT_PASSWORD` |

Change these values before exposing the platform outside a local lab.

## Configuration

The main configuration file is `.env`, created from [.env.example](.env.example).

| Variable | Purpose |
| --- | --- |
| `DOMAIN` | Hostname routed by Traefik |
| `ACME_EMAIL` | Let's Encrypt registration email for public deployments |
| `DB_PASSWORD` | PostgreSQL application password |
| `REDIS_PASSWORD` | Redis password |
| `JWT_SECRET` | JWT signing secret |
| `ALLOWED_ORIGINS` | CORS allow-list |
| `MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD` | MinIO and VolWeb object-storage credentials |
| `VOLWEB_*` | VolWeb integration and public URL settings |
| `DOCKER_GID` | Host Docker socket group for the admin infrastructure panel |
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` | Optional IOC enrichment providers |
| `GITHUB_TOKEN` | Optional GitHub API token for rule imports |
| `OLLAMA_URL`, `AI_*` | Optional local AI configuration |

For public deployments, update `DOMAIN`, `ACME_EMAIL`, `ALLOWED_ORIGINS`, and all secrets before first start.

## Operations

Common commands:

```bash
docker compose ps
docker compose logs -f backend
docker compose logs -f worker
docker compose logs -f traefik
docker compose restart backend worker
bash db/migrate.sh
```

Resetting the stack with `docker compose down -v` deletes persistent case data, evidence metadata, queues, Elasticsearch indexes, MinIO objects, and application state. Use it only for disposable labs.

Persistent Docker volumes include PostgreSQL, Redis, Elasticsearch, uploaded evidence, collections, MinIO data, ClamAV signatures, backups, Ollama models, and Let's Encrypt certificates.

## Developer Workflow

Backend:

```bash
cd backend
npm install
npm run dev
npm run typecheck
npm test
```

Frontend:

```bash
cd frontend
npm install
npm run dev
npm run typecheck
npm run i18n:check
npm run build
```

The production stack is container-first. When changing runtime behavior, validate against Docker Compose because service names, mounted volumes, networks, proxy timeouts, and healthchecks are part of the application contract.

## Forensic Tooling

Some third-party tools are downloaded into the backend image during Docker build when network access is available. Check their upstream licenses before packaging or redistributing images.

| Tool | Use |
| --- | --- |
| Zimmerman Tools | Windows artifacts such as MFT, Prefetch, LNK, Shellbags, registry-oriented data |
| Hayabusa | Sigma-driven EVTX detection |
| tshark | PCAP parsing |
| VolWeb / Volatility 3 | Memory analysis |
| ClamAV | Antivirus scanning of uploaded evidence |
| SigmaHQ / YARA rule sources | Threat-hunting rules |

Manual Hayabusa repair, if the build-time download failed:

```bash
docker cp hayabusa odin:/app/hayabusa/hayabusa
docker exec odin chmod +x /app/hayabusa/hayabusa
```

## Documentation

- [French README](README.fr.md)
- [Documentation index](docs/README.md)
- [Architecture](docs/architecture.md)
- [Backend architecture](docs/backend.md)
- [Infrastructure](docs/infra.md)
- [UI architecture](docs/ui.md)
- [Design system](docs/design-system.md)
- [Delivery workflows](docs/workflows.md)
- [Roadmap](ROADMAP.md)
- [Changelog](CHANGELOG.md)
- [User tutorial](TUTORIAL.md)

## Security Notes

- Do not commit `.env` or real investigation data.
- Rotate generated secrets for any shared or production deployment.
- Keep Heimdall behind trusted network controls when handling sensitive evidence.
- Review Traefik, CORS, TLS, upload limits, and Docker socket access before exposing the service.
- Treat evidence deletion, reset commands, and Docker volume removal as destructive operations.
- Validate third-party parser binaries and rule packs before use in a sensitive environment.

## Credits

Heimdall builds on open-source DFIR and infrastructure projects including Zimmerman Tools, Hayabusa, VolWeb, Volatility 3, ClamAV, Elasticsearch, SigmaHQ, YARA rule communities, Redis, PostgreSQL, React, Node.js, and MITRE ATT&CK.

## License

[MIT](LICENSE) © Heimdall DFIR Contributors
