# Heimdall DFIR

Plateforme DFIR et threat hunting auto-hébergée pour gérer des dossiers, importer des preuves, reconstruire des timelines et sortir des rapports.

[![EN](https://img.shields.io/badge/lang-EN-blue)](README.md)
[![Docker Compose](https://img.shields.io/badge/runtime-Docker%20Compose-2496ED)](docker-compose.yml)
[![Node.js](https://img.shields.io/badge/backend-Node.js%2020-339933)](backend/package.json)
[![React](https://img.shields.io/badge/frontend-React%2018-61DAFB)](frontend/package.json)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> Heimdall est en développement actif. Validez le workflow complet dans un environnement contrôlé avant toute utilisation en investigation de production.

## Sommaire

- [Objectif](#objectif)
- [Fonctionnalités principales](#fonctionnalités-principales)
- [Architecture](#architecture)
- [Organisation du dépôt](#organisation-du-dépôt)
- [Démarrage rapide](#démarrage-rapide)
- [Configuration](#configuration)
- [Exploitation](#exploitation)
- [Workflow développeur](#workflow-développeur)
- [Outils forensiques](#outils-forensiques)
- [Documentation](#documentation)
- [Notes de sécurité](#notes-de-sécurité)
- [Crédits](#crédits)
- [Licence](#licence)

## Objectif

Heimdall donne aux équipes CSIRT, SOC et DFIR un endroit central pour:

- gérer les dossiers d'investigation et les pièces à conviction;
- importer et parser des artefacts forensiques;
- construire des timelines recherchables;
- exécuter des détections YARA, Sigma, threat-intelligence et règles internes;
- collaborer avec notes, pins, chat et vues de revue analyste;
- analyser des dumps mémoire avec VolWeb et Volatility 3;
- générer des rapports d'investigation avec contexte de preuve.

Le projet vise les labs auto-hébergés, les SOC internes et les missions sensibles où les preuves doivent rester sous contrôle de l'opérateur.

## Fonctionnalités principales

| Domaine | Capacités |
| --- | --- |
| Gestion de cas | Dossiers, inventaire des preuves, commentaires, notes, pins, rapports |
| Timeline | Super Timeline, filtres artefact, préférences colonnes, groupement, recherche, export CSV |
| Ingestion | Upload standard, upload mémoire par chunks, imports de collections, streaming parser |
| Forensic Windows | EVTX, Hayabusa, MFT, Prefetch, LNK, Shellbags, workflows registre |
| Analyse réseau | Flux PCAP, network map, indicateurs de beaconing, graphes globaux |
| Analyse mémoire | Intégration VolWeb, stockage MinIO, workers Volatility 3 |
| Threat hunting | YARA, Sigma, TAXII/STIX, enrichissement IOC, résumés de détections |
| Automatisation | Workers BullMQ, alertes SOAR, score de triage, playbooks |
| Collaboration | Présence Socket.io, chat par cas, pins de preuves, ledger d'audit |
| IA locale | Copilot optionnel basé sur Ollama et contexte de cas |
| Administration | Utilisateurs, backups, santé services, conteneurs Docker, journaux d'accès |

## Architecture

```text
Navigateur
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
         +--> huginn / worker BullMQ
         +--> njord / MinIO
         +--> hel-api, hel-worker, hel-ui / VolWeb + Volatility 3
         +--> ollama / LLM local optionnel
```

La topologie runtime est définie dans [docker-compose.yml](docker-compose.yml). Traefik gère le routage externe et TLS. Les services internes sont séparés en réseaux frontend, Heimdall et VolWeb.

## Organisation du dépôt

```text
.
├── backend/              API Node.js, services, middleware, workers, parsers
├── frontend/             Application React/Vite et modules UI
├── db/                   Schéma initial, migrations, scripts de migration
├── docker/               Configuration Traefik et support VolWeb
├── docs/                 Notes architecture, backend, UI, infra, workflows
├── nginx/                Proxy VolWeb et anciens fichiers nginx
├── prompts/              Prompts d'agents pour audits et implémentation
├── tasks/                Décisions, backlog, leçons, notes de session
├── templates/            Modèles de livraison audit, bugfix, feature, redesign
├── docker-compose.yml    Stack runtime principale
├── start.sh              Bootstrap Linux/macOS
└── start.ps1             Bootstrap Windows
```

## Démarrage rapide

### Prérequis

- Docker 24+ avec Docker Compose v2
- `openssl` pour générer les secrets sous Linux/macOS
- 16 GB de RAM recommandés pour la stack complète, surtout avec Elasticsearch, VolWeb, ClamAV et Ollama
- 50 GB d'espace disque recommandés pour les preuves de test et volumes Docker

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

Les scripts créent `.env` depuis [.env.example](.env.example), génèrent les secrets, construisent les images, démarrent les services, attendent PostgreSQL et appliquent les migrations.

### Accès

| Service | URL |
| --- | --- |
| Interface Heimdall | `https://localhost` ou `http://localhost` selon le comportement TLS local |
| Santé API | `https://localhost/api/health` |
| Console MinIO | `http://localhost:9001` |
| Proxy VolWeb | `http://localhost:8888` |

Les comptes par défaut sont initialisés depuis `.env` à la première création de la base:

| Role | Identifiant | Source du mot de passe initial |
| --- | --- | --- |
| Admin | `admin` | `ADMIN_DEFAULT_PASSWORD` |
| Analyste | `analyst` | `ANALYST_DEFAULT_PASSWORD` |

Changez ces valeurs avant toute exposition hors laboratoire local.

## Configuration

La configuration principale est `.env`, créée depuis [.env.example](.env.example).

| Variable | Usage |
| --- | --- |
| `DOMAIN` | Nom d'hôte routé par Traefik |
| `ACME_EMAIL` | Email Let's Encrypt pour les déploiements publics |
| `DB_PASSWORD` | Mot de passe applicatif PostgreSQL |
| `REDIS_PASSWORD` | Mot de passe Redis |
| `JWT_SECRET` | Secret de signature JWT |
| `ALLOWED_ORIGINS` | Liste CORS autorisée |
| `MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD` | Identifiants MinIO et stockage VolWeb |
| `VOLWEB_*` | Intégration VolWeb et URL publique |
| `DOCKER_GID` | Groupe du socket Docker hôte pour le panneau infra admin |
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` | Fournisseurs optionnels d'enrichissement IOC |
| `GITHUB_TOKEN` | Token GitHub optionnel pour importer des règles |
| `OLLAMA_URL`, `AI_*` | Configuration optionnelle IA locale |

Pour un déploiement public, mettez à jour `DOMAIN`, `ACME_EMAIL`, `ALLOWED_ORIGINS` et tous les secrets avant le premier démarrage.

## Exploitation

Commandes utiles:

```bash
docker compose ps
docker compose logs -f backend
docker compose logs -f worker
docker compose logs -f traefik
docker compose restart backend worker
bash db/migrate.sh
```

`docker compose down -v` supprime les données persistantes: métadonnées de cas, index Elasticsearch, objets MinIO, files Redis, volumes d'uploads, backups et état applicatif. À réserver aux laboratoires jetables.

Les volumes persistants couvrent PostgreSQL, Redis, Elasticsearch, les preuves uploadées, les collections, MinIO, les signatures ClamAV, les backups, les modèles Ollama et les certificats Let's Encrypt.

## Workflow développeur

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

La stack de production est orientée conteneurs. Pour tout changement runtime, validez avec Docker Compose: noms de services, volumes, réseaux, timeouts proxy et healthchecks font partie du contrat applicatif.

## Outils forensiques

Certains outils tiers sont téléchargés dans l'image backend pendant le build Docker lorsque le réseau est disponible. Vérifiez leurs licences upstream avant packaging ou redistribution d'images.

| Outil | Usage |
| --- | --- |
| Zimmerman Tools | Artefacts Windows: MFT, Prefetch, LNK, Shellbags, données registre |
| Hayabusa | Détection Sigma sur EVTX |
| tshark | Parsing PCAP |
| VolWeb / Volatility 3 | Analyse mémoire |
| ClamAV | Scan antivirus des preuves uploadées |
| SigmaHQ / sources YARA | Règles de threat hunting |

Réparation manuelle Hayabusa si le téléchargement au build a échoué:

```bash
docker cp hayabusa odin:/app/hayabusa/hayabusa
docker exec odin chmod +x /app/hayabusa/hayabusa
```

## Documentation

- [README anglais](README.md)
- [Index documentation](docs/README.md)
- [Architecture](docs/architecture.md)
- [Backend](docs/backend.md)
- [Infrastructure](docs/infra.md)
- [Architecture UI](docs/ui.md)
- [Design system](docs/design-system.md)
- [Workflows de livraison](docs/workflows.md)
- [Roadmap](ROADMAP.fr.md)
- [Changelog](CHANGELOG.md)
- [Guide utilisateur](TUTORIAL.md)

## Notes de sécurité

- Ne commitez jamais `.env` ni de données d'investigation réelles.
- Régénérer les secrets pour tout environnement partagé ou de production.
- Garder Heimdall derrière des contrôles réseau de confiance pour manipuler des preuves sensibles.
- Revoir Traefik, CORS, TLS, limites d'upload et accès au socket Docker avant exposition.
- Considérer la suppression de preuves, les resets et la suppression de volumes Docker comme destructifs.
- Valider les binaires de parsing tiers et packs de règles avant usage sensible.

## Crédits

Heimdall s'appuie sur des projets open source DFIR et infrastructure: Zimmerman Tools, Hayabusa, VolWeb, Volatility 3, ClamAV, Elasticsearch, SigmaHQ, communautés YARA, Redis, PostgreSQL, React, Node.js et MITRE ATT&CK.

## Licence

[MIT](LICENSE) © Heimdall DFIR Contributors
