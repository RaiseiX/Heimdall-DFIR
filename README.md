# Heimdall DFIR

Self-hosted case management, evidence review and threat-hunting for DFIR teams.

[Français](README.fr.md) · [Roadmap](ROADMAP.md) · [Documentation](docs/README.md) · [Discord](https://discord.gg/sx7DnNYMNF)

![Heimdall DFIR dashboard](shots/dashboard.webp)

Heimdall brings imported evidence, timelines, detections, investigation notes and reports into one web interface. It is intended for labs, internal SOCs and incident-response teams that want to keep case data on infrastructure they control.

The project is under active development. Use test evidence first and review the deployment and evidence-handling model before relying on it for a live investigation.

## What is available today

| Area | What Heimdall provides |
| --- | --- |
| Investigations | Cases, assignees, structured notes, findings, DFIQ question sets, Kanban workflow and reports |
| Evidence ingestion | KAPE, Magnet RESPONSE, Velociraptor and CyLR collections; CatScale data; CSV imports; regular and chunked uploads |
| Timeline work | Case-scoped timeline, full-text search, field filters, grouping, saved searches, context view, comparison and CSV export |
| Detection | YARA and Sigma hunting, YAML threat rules, Hayabusa results, IOC correlation, triage scores and automated post-ingestion hunts |
| Network and memory | PCAP-derived connections, network and lateral-movement views, beaconing indicators, VolWeb and Volatility 3 |
| Analyst workflow | Timeline bookmarks, shared case chat, real-time updates, investigation status, collaborative report drafts and audit trails |
| Threat intelligence | TAXII/STIX feeds, MISP pull, cross-case IOCs and optional VirusTotal, AbuseIPDB and HIBP enrichment |
| Operations | User and session management, security and retention settings, health views, backups and access logs |
| Local model support | Ollama-backed chat and report assistance. Prompts stay on the configured Ollama service; results still require analyst review |

Heimdall analyses evidence that has already been collected. It is not an endpoint collection platform, a SIEM, or a substitute for validated forensic procedure. The [roadmap](ROADMAP.md) describes the project boundary and the work still ahead.

## Architecture

```text
Browser
  |
  v
Traefik :80/:443
  |
  +-- React frontend :3000
  |
  +-- Node.js API :4000
        |
        +-- PostgreSQL        cases, users, evidence metadata, audit data
        +-- Elasticsearch     timeline search
        +-- Redis / BullMQ    queues, cache and real-time coordination
        +-- ClamAV            upload scanning
        +-- MinIO / VolWeb    memory evidence and Volatility 3
        +-- Ollama            local model inference
```

The complete service definition lives in [docker-compose.yml](docker-compose.yml). Uploaded evidence and application state are stored in Docker volumes; PostgreSQL remains the source of truth for case and workflow data.

## Quick start

### Requirements

- Docker Engine 24 or later with Docker Compose v2
- `openssl` on Linux and macOS
- at least 16 GB of RAM for the complete stack; memory analysis and larger Ollama models need more
- enough free storage for Docker images, indexes and evidence; 50 GB is a practical starting point for a lab

### Linux and macOS

```bash
git clone https://github.com/RaiseiX/Heimdall-DFIR.git
cd Heimdall-DFIR
bash start.sh
```

### Windows PowerShell

```powershell
git clone https://github.com/RaiseiX/Heimdall-DFIR.git
cd Heimdall-DFIR
Set-ExecutionPolicy -Scope Process Bypass
.\start.ps1
```

The bootstrap script creates `.env` from [.env.example](.env.example), generates infrastructure secrets, builds the images, starts the services and applies the database migrations.

After the first start:

1. Open `https://localhost`. A local installation uses a self-signed certificate, so the browser will display a warning.
2. Sign in as `admin` or `analyst`. Their initial passwords come from `ADMIN_DEFAULT_PASSWORD` and `ANALYST_DEFAULT_PASSWORD`.
3. Change both application passwords before making Heimdall reachable from another machine.

The account variables are only read when the database is created. Editing them later does not rotate an existing account password; use the user settings in Heimdall instead.

### Local endpoints

| Service | Address |
| --- | --- |
| Heimdall | `https://localhost` |
| API health | `https://localhost/api/health` |
| VolWeb | `http://localhost:8888` |
| MinIO console | `http://localhost:9001` |

For a public hostname, set `DOMAIN`, `ACME_EMAIL` and `ALLOWED_ORIGINS` before starting the stack, then review the Traefik router and certificate-resolver settings for that domain. Do not rely on the local self-signed configuration for a public deployment.

## Configuration

The main settings live in `.env`.

| Variable | Purpose |
| --- | --- |
| `DOMAIN`, `ACME_EMAIL` | External hostname and Let's Encrypt registration address |
| `DB_PASSWORD`, `REDIS_PASSWORD` | PostgreSQL and Redis credentials |
| `JWT_SECRET` | Session signing; the audit key currently derives from it in the default Compose stack |
| `ADMIN_DEFAULT_PASSWORD`, `ANALYST_DEFAULT_PASSWORD` | Initial accounts on a fresh database |
| `ALLOWED_ORIGINS` | CORS allow-list |
| `MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD` | MinIO credentials used by VolWeb |
| `VOLWEB_*` | VolWeb connection and public URL |
| `GITHUB_TOKEN` | Optional token for public rule imports |
| `OLLAMA_URL` | Ollama service used by the assistant |
| `DOCKER_GID` | Host Docker group used by the operations view on Linux |

Do not commit `.env`. Keep a protected copy if you need to restore the deployment: it contains the credentials required to read or operate several services.

## Routine operations

```bash
docker compose ps
docker compose logs -f backend
docker compose logs -f worker
docker compose logs -f traefik
docker compose restart backend worker
bash db/migrate.sh
```

`docker compose down -v` deletes the persistent volumes for the stack. On a non-disposable installation, take a tested backup before removing volumes or changing the storage layout.

## Security and evidence handling

- Keep the platform on a trusted network until the deployment has been reviewed for its environment.
- Replace the initial account passwords and every placeholder in `.env`.
- The code supports a separate `AUDIT_HMAC_KEY`, but the default Compose service does not pass it to the backend yet. Wire a distinct key into the backend before relying on key separation.
- Review TLS, CORS, upload limits, MinIO exposure and host firewall rules before remote access.
- The backend mounts the Docker socket for the operations panel. Treat backend administrator access as host-sensitive and remove that capability if it is not needed.
- ClamAV scanning does not make an uploaded file safe to open outside the analysis workflow.
- Audit hash chains can reveal some forms of modification or deletion; they are not, by themselves, a legal chain-of-custody guarantee.
- Test backup and restore procedures with representative evidence before using the platform for real cases.

## Development

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
npm test
npm run build
```

Node.js 24 is used by the Docker images. Runtime changes should also be tested through Docker Compose because networks, health checks, volumes and proxy timeouts are part of the application.

## Repository guide

```text
backend/      API, services, workers and parsers
frontend/     React application
db/           schema, migrations and migration tooling
docker/       Traefik and VolWeb support files
docs/         maintained architecture and contributor documentation
tasks/        implementation notes and engineering backlog
```

Useful starting points:

- [Architecture](docs/architecture.md)
- [Backend](docs/backend.md)
- [Infrastructure](docs/infra.md)
- [Frontend](docs/ui.md)
- [Design system](docs/design-system.md)
- [Changelog](CHANGELOG.md)
- [User tutorial](TUTORIAL.md)

## Project and community

Questions and feedback are welcome on [Discord](https://discord.gg/sx7DnNYMNF). For a bug or a proposed change, open a GitHub issue with the affected version, reproduction steps and relevant logs with sensitive case data removed. Report suspected vulnerabilities privately by following the [security policy](SECURITY.md), not through a public issue or Discord.

Heimdall relies on open-source work from the wider DFIR ecosystem, including Zimmerman Tools, Hayabusa, VolWeb, Volatility 3, ClamAV, SigmaHQ, YARA communities and MITRE ATT&CK. Check the upstream licences of bundled or downloaded tools before redistributing images.

## License

[MIT](LICENSE) © Heimdall DFIR contributors
