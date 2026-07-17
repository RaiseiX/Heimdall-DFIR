# Backend

Node.js API and worker layer for Heimdall DFIR.

## Stack

- Node.js 20 in Docker, Express, Socket.io
- TypeScript through `ts-node` for selected routes/services
- PostgreSQL, Redis, Elasticsearch
- BullMQ for asynchronous parser and automation jobs
- ClamAV, MinIO, VolWeb, Ollama, YARA/Sigma integrations

## Commands

```bash
npm install
npm run dev
npm run start
npm run worker
npm run typecheck
npm test
```

## Structure

```text
backend/
├── config/              Runtime rule and timeline mapping files
├── parsers/             Python parser helpers
├── src/
│   ├── config/          Database, Redis, queue, logging configuration
│   ├── middleware/      Auth, rate limiting, request and access logging
│   ├── routes/          HTTP API route modules
│   ├── services/        Domain logic and external integrations
│   ├── types/           Shared TypeScript types
│   ├── utils/           Shared helpers
│   └── workers/         BullMQ worker entrypoints
├── tests/               Jest unit tests
├── Dockerfile
└── package.json
```

## Runtime Boundaries

- `routes/` maps requests, validates edge inputs, and delegates business logic.
- `services/` owns ingestion, parsing, detections, reports, AI, VolWeb, and external integrations.
- `workers/` owns long-running and asynchronous processing.
- PostgreSQL is the source of truth for cases, evidence metadata, users, audit data, pins, reports, and workflow state.
- Elasticsearch supports high-volume timeline search.
- Redis supports queues, sessions, cache, and token revocation.

## API Surface

The main API is mounted from `src/server.js` under `/api`.

Key route groups:

| Route | Responsibility |
| --- | --- |
| `/api/auth` | Authentication and JWT lifecycle |
| `/api/cases` | Case records and case-scoped views |
| `/api/evidence` | Evidence upload, metadata, comments, integrity, deletion |
| `/api/upload` | Chunked uploads |
| `/api/parsers` | Streaming parser execution and parser results |
| `/api/collection` | Collection ingestion and timeline data |
| `/api/timeline` | Timeline events |
| `/api/threat-hunting` | YARA and Sigma workflows |
| `/api/threat-intel` | TAXII/STIX and threat intelligence |
| `/api/iocs` | Indicators and enrichment |
| `/api/network` | Network graph and beaconing views |
| `/api/admin` | Health, backups, Docker, logs, Ollama administration |
| `/api/volweb` | VolWeb integration and SSO workflows |
| `/api/llm`, `/api/ai`, `/api/cases/:caseId/ai/*` | Local AI workflows |

Socket.io is used for case presence, chat, parser streaming, evidence pin sync, and real-time status events.

## Forensic Invariants

- `case_id` is the main isolation boundary. Cross-case reads must be explicit.
- Evidence metadata should preserve hashes, custody context, upload source, scan state, and parser state.
- Long-running parsing and automation should go through BullMQ workers where possible.
- Auditability matters: destructive or evidence-changing actions should remain observable.
- Memory-forensics data can live in MinIO/VolWeb paths and may not behave like local disk evidence.

## Related Docs

- [Root README](../README.md)
- [Backend architecture](../docs/backend.md)
- [Architecture](../docs/architecture.md)
- [Infrastructure](../docs/infra.md)
- [Workflows](../docs/workflows.md)
