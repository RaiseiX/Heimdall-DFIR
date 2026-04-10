# Heimdall DFIR — Roadmap V2.0

> *Mis à jour le 2026-03-31*
> *Rédigé dans la perspective d'un Principal Staff Engineer / CPO Cybersécurité.*
>
> Les contributions sont les bienvenues — ouvre une issue pour discuter d'une idée.

[![EN](https://img.shields.io/badge/lang-EN-blue)](ROADMAP.md)
[![FR](https://img.shields.io/badge/lang-FR-blueviolet)](ROADMAP.fr.md)

---

## Positionnement stratégique

### Pourquoi Heimdall doit constamment évoluer

Les adversaires font évoluer leurs TTPs en permanence. Un outil DFIR figé devient aveugle : de nouvelles sources de logs apparaissent (EDR, cloud, containers), les volumes d'événements explosent, et les équipes s'attendent à des outils qui **pensent avec elles**, pas juste pour elles.

### Axes de différenciation

| Concurrent | Force | Notre réponse |
|-----------|-------|---------------|
| **Magnet AXIOM** | 1000+ parsers, mobile | Souveraineté des données, collab temps réel, IA locale |
| **Elastic Security** | Scale, ML, SIEM | Self-hosted, air-gapped, simplicité déploiement |
| **TheHive + Cortex** | Case management | Timeline native, threat hunting unifié, Investigation Graph |
| **Timesketch** | Timeline Elasticsearch | Collaboration, SOAR, LLM Copilot, multi-cas |
| **Velociraptor** | Live response | Forensique offline, interface accessible, rapport auto |
| **Autopsy** | Carving, GUI | Web-native, multi-utilisateur, temps réel |

### Vision V2.0

> *"Heimdall est le seul workbench DFIR open-source qui combine forensique offline,
> collaboration temps réel, threat hunting unifié et intelligence IA locale souveraine —
> conçu pour les équipes qui ne peuvent pas se permettre de mettre leurs données dans le cloud."*

L'ambition V2.0 est de passer de *"bon outil de timeline DFIR"* à *"plateforme d'intelligence sur les menaces collaborative, IA-augmentée et souveraine"* — un outil que les équipes DFIR ne veulent plus quitter, que les MSSPs peuvent proposer à leurs clients, et que les universités utilisent pour former la prochaine génération d'analystes.

---

## ✅ v0.9.0 — Socle actuel (complété)

### Missions fondations
- [x] **M1** — Super Timeline Elasticsearch (index par cas, bulkIndex, searchTimeline)
- [x] **M2** — Hard Delete DoD 5220.22-M (shred 7 passes + fallback Node.js)
- [x] **M3** — Collaboration temps réel (Socket.io rooms, présence, dashboard:update)
- [x] **M4** — Architecture Workers BullMQ (file parser-jobs, Redis pub/sub, service worker isolé)
- [x] **M5** — ClamAV + VolWeb (Volatility 3, MinIO, SSO Magic Link, upload chunked 256 GB)
- [x] **M6** — Workbench UI + Notes d'investigation (TanStack Table, Split-Pane, sanitisation XSS)
- [x] **M7** — Revue sécurité complète (injection SQL/cmd, secrets, CORS, Docker, Nginx headers)
- [x] **M8** — YARA / Sigma Threat Hunting + import depuis GitHub (Neo23x0, Yara-Rules, SigmaHQ)
- [x] **M9** — TAXII / STIX Threat Intel (index ES `threat_intel`, corrélation automatique)

### Missions fonctionnalités
- [x] **C.1** — IOC Enrichissement VirusTotal + AbuseIPDB (cache Redis 24h)
- [x] **B.1** — Score de triage par machine (0–100, 16 règles EVTX + Sysmon) + Sysmon Configs open-source
- [x] **B.2** — Graphe de mouvement latéral D3.js (EIDs 4624/4648/4768/4769/4776)

### Plans DFIR v2.7 (Blocs 1–6)
- [x] **Bloc 1** — ECS sur collection_timeline, Hayabusa → Timeline, filtres host/user, gaps temporels
- [x] **Bloc 2** — Multi-select artefacts, surlignage sévérité Hayabusa, détection Persistence
- [x] **Bloc 3** — Détections automatiques : Timestomping, Double Extension, Beaconing C2
- [x] **Bloc 4** — Chat live par cas, export CSV universel, export STIX 2.1, rapport PDF enrichi
- [x] **Bloc 5** — Health Dashboard, JWT Rotation + blacklist Redis, Backup DB automatique
- [x] **Bloc 6** — Playbooks DFIR (Ransomware/RDP/Phishing), Legal Hold HMAC, PCAP parser (tshark), Infrastructure Docker

### Missions critiques
- [x] **Isolation collectes** (v2.18) — `evidence_id` FK + anti-IDOR 3 couches, zéro spillage
- [x] **SOAR Engine** — YARA + Sigma + TI + Triage en parallèle post-ingestion, alertes socket
- [x] **RAM Stabilisation** (v2.22) — écriture positionnelle sparse, idempotence `INTEGER[]`, resume localStorage, streaming async VolWeb
- [x] **IA Copilot** (Ollama) — chat global SSE, copilot par cas avec contexte forensique injecté, persistance DB

### Features hors roadmap initiale (bonus livrés)
- [x] CyberChef Forensic natif (Base64/Hex/XOR/ROT13, détection obfuscation automatique)
- [x] MITRE ATT&CK tab + APT Attribution
- [x] Attack Chain (kill chain 14 phases, bookmarks)
- [x] Network Graph + PCAP analysis (tshark)
- [x] Collection Agent scripts (CatScale)
- [x] IOC multi-cas (`/api/iocs/cross-case`)
- [x] Case Risk Score (`riskScoreService.ts`)
- [x] Fix SSRF TAXII (`networkUtils.ts`)
- [x] Logging structuré winston (`config/logger.ts`)
- [x] Rate limiting par utilisateur (`rateLimiter.ts`)

---

## 📊 Statut d'implémentation global

```
Quick Wins    : ▓▓▓▓▓▓░░░░  6/9  implémentés  (1 partiel · 2 non démarrés)
Core Features : ▓▓▓▓▓░░░░░  5/25 implémentés  (5 partiels · 15 non démarrés)
Moonshots     : ░░░░░░░░░░  0/7  (vision long terme)
Hors roadmap  : ▓▓▓▓▓▓▓▓▓▓ 13 features supplémentaires livrées
```

### Quick Wins

| ID | Feature | Statut | Notes |
|----|---------|:------:|-------|
| QW-1 | IOC multi-cas | ✅ | `/api/iocs/cross-case`, vue SQL, widget dashboard |
| QW-2 | Enrichissement Timeline | 🔶 | Bouton ContextMenu OK, manque intégration dans l'inspector |
| QW-3 | Case Risk Score | ✅ | `riskScoreService.ts` — score 0-100, cache Redis |
| QW-4 | Fix SSRF TAXII | ✅ | `networkUtils.ts` — validation hostname/IP privées |
| QW-5 | Logging structuré (winston) | ✅ | `config/logger.ts` — JSON structuré + AsyncLocalStorage |
| QW-6 | Rate limiting par user | ✅ | `rateLimiter.ts` — 5 jobs max/user, HTTP 429 |
| QW-7 | MFA TOTP / FIDO2 | ❌ | Non commencé |
| QW-8 | Case Templates | 🔶 | Report templates OK, manque checklist/workflow de cas |
| QW-9 | PWA mobile | ❌ | Non commencé |

### Core Features

| ID | Feature | Statut | Notes |
|----|---------|:------:|-------|
| CF-1 | LLM Copilot local (Ollama) | ✅ | `aiService.ts`, streaming SSE, contexte par cas |
| CF-2 | Investigation Graph | 🔶 | NetworkGraphD3 réseau OK, manque graphe d'investigation complet |
| CF-3 | Case Team Management | ❌ | Non commencé |
| CF-4 | Export SIEM | 🔶 | STIX 2.1 + ES OK, manque format Splunk HEC natif |
| CF-5 | Prometheus + Grafana | ❌ | Non commencé |
| CF-6 | Tests automatisés | 🔶 | Jest configuré, 1 test unitaire — pas de suite systématique |
| CF-7 | Rapport PDF enrichi | ✅ | `reports.js` — templates, sections paramétrables, AI optionnel |
| CF-8 | Cloud Forensics AWS/Azure/M365 | ❌ | Non commencé |
| CF-9 | Live Response Bridge (Velociraptor) | ❌ | Non commencé |
| CF-10 | Binary Triage local | ❌ | Non commencé |
| CF-11 | OpenAPI + Webhooks | ❌ | Non commencé |
| CF-12 | Community Hub YARA/Sigma | ❌ | Non commencé |
| CF-13 | Email Forensics (.eml/.msg/.pst) | ❌ | Non commencé |
| CF-14 | SSO / SAML 2.0 / LDAP | ❌ | Non commencé |
| CF-15 | CTF / Mode Formation | ❌ | Non commencé |
| CF-16 | NLP Search | ❌ | Dépend CF-1 ✅ — peut démarrer |
| CF-17 | Session Recording & Audit Log | ✅ | `auditLog` middleware + `audit_logs` table |
| CF-18 | Container / Docker Forensics | ❌ | Non commencé |
| CF-19 | Linux Forensics natif (CatScale) | ✅ | `catscaleService.ts`, parser complet, tab dédié |
| CF-20 | NTDS.dit / AD Forensics | 🔶 | Détection credential dump OK, manque parsing NTDS.dit |
| CF-21 | MISP bidirectionnel | ❌ | TAXII/STIX pull OK, manque push vers MISP |
| CF-22 | EDR Integration | ❌ | Non commencé |
| CF-23 | Déduplication & Noise Reduction | 🔶 | Dédup STIX/IOC OK, manque mode Signal global |
| CF-24 | NIS2/RGPD Breach Notification | ❌ | Non commencé |
| CF-25 | Similar Case Detection | ❌ | Non commencé |

### Moonshots

| ID | Feature | Statut |
|----|---------|:------:|
| MS-1 | Campaign Intelligence cross-cas | ❌ |
| MS-2 | Architecture Big Data (500M événements/cas) | ❌ |
| MS-3 | AI Copilot avancé proactif | ❌ |
| MS-4 | Certification Air-gapped & Sovereign | ❌ |
| MS-5 | Multi-tenancy MSSP | ❌ |
| MS-6 | Plugin System (architecture extensible) | ❌ |
| MS-7 | UEBA — User & Entity Behavior Analytics | ❌ |

---

## 🗓️ Planning

> **Principe directeur** : *Faire fonctionner correctement → Faire fonctionner de façon fiable → Faire scaler.*

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SOCLE — Sécurité & Fiabilité (non négociable)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

2026 Q1 — Sprint 0
  ├─ [SÉCU]   QW-7 : MFA TOTP / FIDO2
  ├─ [CODE]   CF-6 : Tests backend — services critiques
  ├─ [INFRA]  pgBouncer (connection pooling PostgreSQL)
  ├─ [INFRA]  Backup PG + ES → MinIO + test restauration
  └─ [CODE]   QW-8 : Case Templates

2026 Q1-Q2 — Sprint 1 : Observabilité & Quick Wins
  ├─ CF-5  : Prometheus + Grafana
  ├─ QW-9  : PWA mobile
  ├─ CF-16 : NLP Search (dépend CF-1 ✅)
  └─ CF-6  : Tests routes + intégration

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 FEATURES — Nouvelles fonctionnalités
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

2026 Q2 (Avril → Juillet)
  ├─ CF-14 : SSO / SAML / LDAP        ← déblocage enterprise
  ├─ CF-13 : Email Forensics           ← vecteur #1
  ├─ CF-8  : Cloud Forensics AWS/Azure/M365
  ├─ CF-19 : Linux Forensics natif (✅ partiel)
  └─ CF-11 : OpenAPI + Webhooks

2026 Q3 (Juillet → Octobre)
  ├─ CF-2  : Investigation Graph       ← différenciateur #2
  ├─ CF-3  : Case Team Management
  ├─ CF-9  : Live Response (Velociraptor)
  ├─ CF-10 : Binary Triage local
  ├─ CF-18 : Container / Docker Forensics
  ├─ CF-20 : NTDS.dit / Active Directory
  ├─ CF-22 : EDR Integration (Phase 1)
  ├─ CF-23 : Déduplication & Noise Reduction
  └─ CF-6  : Tests e2e + coverage complet

2026 Q4 (Octobre → Janvier 2027)
  ├─ CF-4  : Export SIEM (Splunk HEC)
  ├─ CF-12 : Community Hub YARA/Sigma
  ├─ CF-15 : CTF / Mode Formation
  ├─ CF-21 : MISP bidirectionnel
  ├─ CF-24 : NIS2/RGPD Breach Notification
  ├─ CF-25 : Similar Case Detection
  └─ MS-4  : Air-gapped certification

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SCALE — Multi-serveur (stack prouvée en prod)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

2027 Q1 — Docker Swarm (>20 analystes / multi-incidents)
  ├─ Migration Compose → Swarm
  ├─ Scaling horizontal BullMQ workers (0–10)
  └─ MS-1 : Campaign Intelligence

2027 Q2-Q3 — Moonshots
  ├─ MS-2 : Architecture Big Data (ClickHouse)
  ├─ MS-5 : Multi-tenancy MSSP
  ├─ MS-3 : AI Copilot avancé (proactif)
  └─ MS-7 : UEBA — Behavior Analytics

2027 Q4+ — Kubernetes (>50 analystes / MSSP)
  ├─ Helm chart Heimdall
  ├─ HPA sur parser-worker (autoscaling queue depth)
  └─ MS-6 : Plugin System
```

---

## Tableau de synthèse

| ID | Feature | Effort | Impact | Différenciant | Priorité |
|----|---------|:------:|:------:|:-------------:|:--------:|
| QW-7 | MFA TOTP / FIDO2 | S | XL | — | 🔴 P0 |
| CF-16 | NLP Search | S | XL | ✅ | 🔴 P0 |
| CF-6 | Tests automatisés | M | L | — | 🟠 P1 |
| CF-5 | Prometheus + Grafana | M | L | — | 🟠 P1 |
| CF-8 | Cloud Forensics AWS/Azure/M365 | M | XL | ✅✅ | 🟠 P1 |
| CF-9 | Live Response Bridge (Velociraptor) | M | XL | ✅✅ | 🟠 P1 |
| CF-13 | Email Forensics | M | XL | ✅ | 🟠 P1 |
| CF-14 | SSO / SAML / LDAP | S | L | — | 🟠 P1 |
| CF-18 | Container / Docker Forensics | M | XL | ✅ | 🟠 P1 |
| CF-19 | Linux Forensics natif | M | XL | ✅ | 🟠 P1 |
| CF-20 | NTDS.dit / AD Forensics | M | XL | ✅ | 🟠 P1 |
| CF-22 | EDR Integration | M | XL | ✅✅ | 🟠 P1 |
| CF-23 | Déduplication & Noise Reduction | M | L | — | 🟠 P1 |
| QW-8 | Case Templates | S | L | — | 🟠 P1 |
| QW-9 | PWA mobile | S | M | — | 🟡 P2 |
| CF-2 | Investigation Graph | M | XL | ✅✅ | 🟡 P2 |
| CF-3 | Case Team Management | M | L | — | 🟡 P2 |
| CF-4 | Export SIEM | M | L | — | 🟡 P2 |
| CF-10 | Binary Triage local | M | XL | ✅ | 🟡 P2 |
| CF-11 | OpenAPI + Webhooks | M | L | — | 🟡 P2 |
| CF-12 | Community Hub YARA/Sigma | M | XL | ✅✅ | 🟡 P2 |
| CF-15 | CTF / Mode Formation | M | L | ✅✅ | 🟡 P2 |
| CF-17 | Session Recording & Audit Log | M | L | — | 🟡 P2 |
| CF-21 | MISP bidirectionnel | M | L | — | 🟡 P2 |
| CF-24 | NIS2/RGPD Breach Notification | M | M | ✅✅ | 🟡 P2 |
| CF-25 | Similar Case Detection | M | L | ✅ | 🟡 P2 |
| MS-4 | Air-gapped certification | XL | XL | ✅✅ | 🟡 P2 |
| MS-1 | Campaign Intelligence | XL | XL | ✅✅ | 🔵 P3 |
| MS-2 | Architecture Big Data | XL | XL | ✅ | 🔵 P3 |
| MS-3 | AI Copilot avancé | XL | XL | ✅✅ | 🔵 P3 |
| MS-5 | Multi-tenancy MSSP | XL | XL | ✅✅ | 🔵 P3 |
| MS-6 | Plugin System | XL | XL | ✅✅ | 🔵 P3 |
| MS-7 | UEBA Behavior Analytics | XL | XL | ✅✅ | 🔵 P3 |

---

## Contribuer

1. Fork le projet
2. Crée une branche `feature/ma-fonctionnalite`
3. Ouvre une Pull Request avec description claire

Toutes les contributions sont soumises à la licence MIT.
