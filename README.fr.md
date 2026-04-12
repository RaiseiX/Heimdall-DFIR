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

Heimdall DFIR est un **cockpit d'investigation unifié** conçu pour les équipes CSIRT / SOC / DFIR.
Il ingère, corrèle et visualise n'importe quelle source forensique — artefacts Windows/Linux,
captures réseau, dumps RAM — dans une interface unique, collaborative et temps réel.

> ⚠️ **NOTE DE BÊTA :** Heimdall DFIR est actuellement en version bêta. Toutes les fonctionnalités ne sont pas encore opérationnelles et vous pourriez rencontrer des bugs. L'utilisation en environnement de production est à vos risques et périls.

> 📍 **[Roadmap →](ROADMAP.fr.md)**

---

## Fonctionnalités

### 🔬 Analyse forensique
- **Super Timeline** — ingestion multi-source via Elasticsearch, histogramme, filtres avancés host/user/type, pagination, export CSV
- **Isolation par collecte** — chaque source (Hayabusa, MFT, PCAP…) dispose de sa propre vue timeline sans mélange de données
- **Hayabusa** — détections Sigma sur EVTX, niveaux de sévérité colorés, pivot IOC direct
- **Parsers Zimmerman** — PECmd (Prefetch), MFTECmd ($MFT), LECmd (LNK), SBECmd (Shellbags)
- **PCAP Parser** — extraction DNS/HTTP/TLS/TCP via tshark → Super Timeline
- **Memory Forensics** — upload chunked jusqu'à 256 GB, resume automatique, VolWeb + Volatility 3

### 🛡️ Threat Hunting
- **Moteur YARA** — règles CRUD, scan par fichier ou par cas, résultats avec offsets et chaînes matchées
- **Moteur Sigma** — chasse sur la Super Timeline, modificateurs `contains/startswith/re`, mapping MITRE
- **Import GitHub** — importer en masse depuis Neo23x0/signature-base, Yara-Rules/rules, SigmaHQ/sigma
- **Threat Intel TAXII/STIX** — connecteur TAXII 2.1, index Elasticsearch `threat_intel`, corrélation automatique post-ingestion

### 🎯 Détections automatiques
- **Timestomping** — comparaison `$SIA` vs `$FN` (NTFS timestamps) sur artefacts MFT
- **Double extension** — détection `.pdf.exe`, `.docx.scr`, etc. sur MFT / LNK / Prefetch
- **Beaconing C2** — coefficient de variation des intervalles de connexion (beacon score 0–100)
- **Persistence** — Registry Run Keys, LNK Startup, BITS Jobs, Sigma Hayabusa (T1547/T1053)

### 📊 Triage & Investigation
- **Score de triage par machine** — 0–100, 16 règles (EVTX + Sysmon), niveaux CRITIQUE/ÉLEVÉ/MOYEN/FAIBLE
- **Graphe de mouvement latéral** — D3.js force-directed, Event IDs 4624/4648/4768/4769/4776/Sysmon 3
- **Attack Chain** — bookmarks MITRE ATT&CK, kill chain 14 phases, vue compacte/complète
- **IOC Enrichissement** — VirusTotal API v3 + AbuseIPDB, cache Redis 24h, badges inline
- **Corrélations Threat Intel** — matching automatique IOC vs Super Timeline par cas

### ⚡ SOAR & Automatisation
- **SOAR Engine** — YARA + Sigma + Threat Intel + Triage en parallèle post-ingestion
- **Alertes automatiques** — sévérité critique/haute/moyenne/faible, acquittement, badge temps réel
- **Playbooks DFIR** — Ransomware (11 étapes), RDP Compromise (10), Phishing (9), mapping MITRE par étape
- **Legal Hold** — gel des preuves, manifeste signé HMAC-SHA256 téléchargeable
- **Sysmon Configs** — SwiftOnSecurity, Neo23x0, olafhartong_modular, ion-storm bundlés

### 🔒 Sécurité & Administration
- **ClamAV** — scan AV obligatoire post-upload, quarantaine, statut live par pièce à conviction
- **Hard Delete DoD 5220.22-M** — shred 7 passes + fallback Node.js, cascade DB + index ES
- **JWT Rotation** — access token 15 min + refresh token, blacklist Redis, révocation logout
- **Backup automatique** — pg_dump | gzip, liste + téléchargement depuis l'interface admin
- **Health Dashboard** — statut live PostgreSQL / Elasticsearch / Redis / ClamAV / BullMQ
- **Infrastructure Docker** — monitoring CPU/RAM de tous les conteneurs (dockerode), auto-refresh 5s
- **Audit Log** — toutes les actions tracées avec HMAC, export admin

### 🤖 IA locale (Ollama) — *bêta fonctionnelle*

> Nécessite [Ollama](https://ollama.com) — s'active via `OLLAMA_URL` dans `.env`. Se désactive silencieusement si absent.

- **Chat IA global** — bouton flottant accessible depuis toutes les pages, streaming SSE en temps réel, prompts DFIR pré-construits par catégorie (artefacts Windows, MITRE ATT&CK, réseau, mémoire…)
- **Copilot par cas** — panel IA ancré dans chaque dossier, contexte automatiquement injecté (IOCs, alertes SOAR, artefacts timeline, preuves, notes) pour des réponses précises sur l'investigation en cours
- **Persistance** — historique de conversation stocké en base par cas, rechargé à chaque session
- **Modèles supportés** — `qwen3:14b` (défaut), `qwen2.5:7b/14b`, `deepseek-r1:8b`, `llama3.2:3b`, `mistral:7b`
- **Mode no-think** — suppression des balises `<think>…</think>` pour un affichage propre (configurable)

### 👥 Collaboration
- **Chat live par cas** — Socket.io, persistance DB, bulles, suppression, badge non-lus
- **Présence temps réel** — liste des analystes connectés sur un cas
- **Notes d'investigation** — CRUD sur chaque artefact de la timeline, sanitisation XSS
- **Rapport PDF enrichi** — triage machines, résultats YARA, corrélations Threat Intel, kill chain

---

## Architecture

```
 Browser
    │
    ▼
[bifrost / nginx :80/:443]       ← rate-limit, headers sécurité, SSL
    │
    ├──▶ [asgard / frontend :3000]    React 18 · Vite · D3.js · TanStack Table
    │
    └──▶ [odin / backend :4000]       Node.js · Express · TypeScript (ts-node)
              │
              ├──▶ [yggdrasil / postgres :5432]    schéma DFIR complet (18 migrations)
              ├──▶ [hermod / redis :6379]           BullMQ queues · sessions · blacklist JWT
              ├──▶ [mimir / elasticsearch :9200]    Super Timeline (index par cas)
              ├──▶ [tyr / clamav :3310]             analyse AV temps réel
              └──▶ [huginn / worker]                BullMQ consumer (concurrency=2)
                        │
                        ├── Zimmerman Tools  (PECmd · MFTECmd · LECmd · SBECmd)
                        ├── Hayabusa
                        └── tshark (PCAP)

Branche analyse RAM :
    ├──▶ [njord / minio :9000]        stockage S3 des dumps (console :9001)
    ├──▶ [hel-api / hel-worker]       VolWeb Django + Celery + Volatility 3
    └──▶ [hel-proxy :8888]            Nginx VolWeb (SSO Magic Link depuis Heimdall)
```

---

## Stack technique

| Couche | Technologie |
|--------|-------------|
| Frontend | React 18, Vite, D3.js, Recharts, TanStack Table, socket.io-client, react-resizable-panels |
| Backend | Node.js 18+, Express, TypeScript (ts-node transpileOnly), socket.io |
| Queue | BullMQ, ioredis |
| Base de données | PostgreSQL 16 |
| Cache / Sessions | Redis 7 |
| Recherche full-text | Elasticsearch 8.13 |
| Stockage objets | MinIO (API S3) |
| Analyse mémoire | VolWeb + Volatility 3 |
| Antivirus | ClamAV 1.4.3 |
| Threat Hunting | YARA (libyara), Sigma (js-yaml), TAXII 2.1 / STIX 2.1 |
| Réseau | tshark (PCAP parsing) |
| Conteneurisation | Docker Compose v2 |
| Reverse proxy | Nginx (rate-limit, CSP, HSTS, SSL) |

---

## Démarrage

### Prérequis

- Docker ≥ 24 + Docker Compose v2
- `openssl` (génération des secrets)
- 8 GB RAM minimum recommandés (Elasticsearch + VolWeb)

### Installation

```bash
git clone https://github.com/RaiseiX/Heimdall-DFIR.git
cd Heimdall-DFIR
bash start.sh
```

Le script prend en charge tout automatiquement :
- Vérifie les prérequis (Docker, openssl)
- Génère tous les secrets (JWT, DB, Redis, MinIO…) via `openssl rand`
- Build et démarre tous les conteneurs
- Attend que PostgreSQL soit prêt
- Applique toutes les migrations SQL (v2.7 → v2.22)

**Accès après installation :**

| Service | URL |
|---------|-----|
| Interface Heimdall | http://localhost |
| API | http://localhost:4000 |
| VolWeb (RAM) | http://localhost:8888 |
| Console MinIO | http://localhost:9001 |

### Configuration post-démarrage

```bash
# Créer le superuser VolWeb (analyse RAM)
docker exec -it hel-api python manage.py createsuperuser
# Puis créer un bucket "volweb" sur http://localhost:9001

# IA locale (optionnel)
# Définir OLLAMA_URL=http://ollama:11434 dans .env, puis :
docker exec ollama ollama pull qwen3:14b
```

### Variables d'environnement

| Variable | Requis | Description |
|----------|:------:|-------------|
| `DB_PASSWORD` | ✅ | Mot de passe PostgreSQL |
| `REDIS_PASSWORD` | ✅ | Mot de passe Redis |
| `JWT_SECRET` | ✅ | `openssl rand -hex 64` |
| `ALLOWED_ORIGINS` | ✅ | URL du frontend (CORS), ex: `http://localhost:3000` |
| `MINIO_ROOT_USER` | ✅ | Access key MinIO / VolWeb |
| `MINIO_ROOT_PASSWORD` | ✅ | Secret key MinIO / VolWeb |
| `VOLWEB_DJANGO_SECRET` | ✅ | `openssl rand -hex 50` |
| `DOCKER_GID` | ✅ | GID du socket Docker — `stat -c %g /var/run/docker.sock` |
| `VIRUSTOTAL_API_KEY` | ⬜ | Enrichissement IOC VirusTotal (optionnel) |
| `ABUSEIPDB_API_KEY` | ⬜ | Enrichissement IOC AbuseIPDB (optionnel) |
| `GITHUB_TOKEN` | ⬜ | Import règles GitHub — rate limit 60 → 5 000 req/h (optionnel) |
| `OLLAMA_URL` | ⬜ | IA locale Ollama, ex: `http://ollama:11434` (optionnel) |

### Credentials par défaut *(changer en production)*

| Rôle | Login | Mot de passe |
|------|-------|--------------|
| Admin | `admin` | `Admin2026!` |
| Analyst | `analyst` | `Analyst2026!` |

---

## Sources de données & Parsers

### Zimmerman Tools (Artefacts Windows)

| Parser | Artefact | Description |
|--------|----------|-------------|
| **Hayabusa** | EVTX (`.evtx`) | Détections Sigma — niveaux critical/high/medium/low |
| **EvtxECmd** | EVTX (`.evtx`) | Logs Windows événements bruts |
| **MFTECmd** | `$MFT` | Master File Table — timestamps, chemins, tailles |
| **PECmd** | Prefetch (`.pf`) | Historique d'exécutions, dépendances DLL |
| **LECmd** | LNK (`.lnk`) | Fichiers récents, volumes, machines cibles |
| **SBECmd** | Shellbags | Navigation dans les dossiers (NTUSER.DAT / UsrClass.dat) |
| **AmcacheParser** | `Amcache.hve` | Programmes installés/exécutés |
| **AppCompatCacheParser** | ShimCache (SYSTEM) | Exécutions applicatives (Shimcache) |
| **RECmd** | Registry hives (SAM, SYSTEM, NTUSER.DAT) | Clés de registre forensiques |
| **JLECmd** | Jump Lists (`.automaticDestinations-ms`) | Fichiers récents par application |
| **SrumECmd** | SRUM (`SRUDB.dat`) | Utilisation réseau & CPU par processus |
| **SQLECmd** | SQLite (`.sqlite`, `.db`) | Historique Chrome / Firefox / Edge (cookies, history) |
| **RBCmd** | Recycle Bin (`$I*`) | Fichiers supprimés — chemin original, taille, date |
| **BitsParser** | BITS (`qmgr*.dat`) | Transferts BITS (persistance, téléchargements) |

### Autres sources

| Source | Parser | Sortie |
|--------|--------|--------|
| PCAP (`.pcap`, `.pcapng`) | tshark | DNS / HTTP / TLS ClientHello / TCP flows → Timeline |
| Dumps RAM (`.raw`, `.vmem`, `.mem`, `.dmp`) | Volatility 3 via VolWeb | Processus, connexions réseau, artefacts mémoire |
| Tout fichier (< 5 GB) | ClamAV | Scan AV, quarantaine, statut live |
| Flux TAXII 2.1 | Client TAXII interne | Index Elasticsearch `threat_intel` |

---

## CyberChef Forensic

Implémentation native en React d'un décodeur/désobfuscateur — **aucune dépendance externe**.

**Opérations disponibles :**

| Catégorie | Opérations |
|-----------|-----------|
| Spécialisé | PowerShell `-EncodedCommand` (Base64 + UTF-16LE) |
| Encodage | Base64 (standard / URL-safe), Hex (↔), URL (↔), Entités HTML, Codes char (dec/hex/oct), UTF-16LE → Texte |
| Chiffrement | ROT13 / César (décalage configurable), XOR (clé hex sur 1 octet) |
| Formatage | Inverser (caractère / ligne / mot), Supprimer Null Bytes |
| Extraction | Chaînes (longueur min configurable), URLs, Adresses IP, Regex |
| Analyse | Statistiques + entropie de Shannon |

**Détection automatique d'obfuscation :** analyse heuristique qui détecte PowerShell encodé, Base64, `\xAB` hex, URL-encoding, charcode décimal, entités HTML, entropie élevée — et propose les opérations de décodage correspondantes avec un score de confiance.

---

## Memory Forensics — VolWeb

VolWeb est une plateforme collaborative basée sur Volatility 3. Il est intégré nativement dans Heimdall via un **SSO Magic Link** (un clic depuis l'onglet preuves → connexion automatique sans re-login).

**Plugins Volatility disponibles dans VolWeb :**
- `windows.pslist` / `windows.pstree` — liste et arborescence des processus
- `windows.cmdline` — arguments de ligne de commande
- `windows.netscan` / `windows.netstat` — connexions réseau actives
- `windows.dlllist` — DLLs chargées par processus
- `windows.handles` — handles ouverts
- `windows.malfind` — détection d'injections mémoire
- `windows.svcscan` — services Windows
- `windows.registry.hivelist` / `printkey` — artefacts registre en mémoire
- Et plus selon la version de VolWeb installée

**Upload RAM :**
- Upload chunked (50 MB/chunk, configurable) jusqu'à **256 GB**
- Resume automatique (localStorage + endpoint status)
- Zéro corruption : écriture positionnelle sur fichier sparse pré-alloué
- Streaming async vers VolWeb (zéro buffering RAM)

---

## Outils tiers requis (non inclus)

Les outils suivants doivent être placés dans les volumes Docker :

| Outil | Volume | Chemin |
|-------|--------|--------|
| [Zimmerman Tools](https://ericzimmerman.github.io/) (DLLs .NET) | `zimmerman_tools` | `/app/zimmerman-tools/` |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) (binaire Linux) | `uploads_data` | `/app/hayabusa/hayabusa` |

```bash
# Exemple — copier Hayabusa dans le conteneur backend
docker cp hayabusa odin:/app/hayabusa/hayabusa
docker exec odin chmod +x /app/hayabusa/hayabusa
```

---

## Crédits

- [Zimmerman Tools](https://ericzimmerman.github.io/) — parsers forensiques Windows
- [Hayabusa](https://github.com/Yamato-Security/hayabusa) — Sigma EVTX scanner (Yamato Security)
- [VolWeb](https://github.com/k1nd0ne/VolWeb) — plateforme Volatility 3 collaborative
- [Volatility Foundation](https://www.volatilityfoundation.org/) — analyse mémoire
- [ClamAV](https://www.clamav.net/) — moteur antivirus open source
- [Elastic](https://www.elastic.co/) — moteur de recherche & analytics
- [SigmaHQ](https://github.com/SigmaHQ/sigma) — règles Sigma officielles
- [Neo23x0 / signature-base](https://github.com/Neo23x0/signature-base) — règles YARA de référence
- [Yara-Rules](https://github.com/Yara-Rules/rules) — collection communautaire YARA
- [MITRE ATT&CK](https://attack.mitre.org/) — framework de tactiques et techniques

---

## License

MIT © Heimdall DFIR Contributors
