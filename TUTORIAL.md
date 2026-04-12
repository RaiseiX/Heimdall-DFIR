# Heimdall DFIR — Complete User Guide

> Version 0.9.6 · English

---

## Table of Contents

1. [Overview](#1-overview)
2. [Installation & First Start](#2-installation--first-start)
3. [Interface Overview](#3-interface-overview)
4. [Cases — Creating & Managing Investigations](#4-cases--creating--managing-investigations)
5. [Evidence — Uploading Files](#5-evidence--uploading-files)
6. [Parsers — Extracting Artifacts](#6-parsers--extracting-artifacts)
7. [Super Timeline & Investigation Workbench](#7-super-timeline--investigation-workbench)
8. [Hayabusa — Sigma Detections on EVTX](#8-hayabusa--sigma-detections-on-evtx)
9. [Memory Forensics — RAM Analysis with VolWeb](#9-memory-forensics--ram-analysis-with-volweb)
10. [IOCs — Indicators of Compromise](#10-iocs--indicators-of-compromise)
11. [Threat Hunting — YARA & Sigma](#11-threat-hunting--yara--sigma)
12. [Threat Intelligence — TAXII / STIX](#12-threat-intelligence--taxii--stix)
13. [Triage — Machine Score](#13-triage--machine-score)
14. [Automatic Detections (SOAR)](#14-automatic-detections-soar)
15. [MITRE ATT&CK](#15-mitre-attck)
16. [Network Analysis](#16-network-analysis)
17. [Playbooks](#17-playbooks)
18. [Reports](#18-reports)
19. [Collaboration — Chat, Notes, Pins](#19-collaboration--chat-notes-pins)
20. [Administration](#20-administration)
21. [Keyboard Shortcuts & Tips](#21-keyboard-shortcuts--tips)

---

## 1. Overview

Heimdall DFIR is a **unified investigation cockpit** for CSIRT / SOC / DFIR teams. It ingests
forensic artefacts from Windows and Linux systems, network captures and RAM dumps, then
correlates and visualises them in a single real-time collaborative interface.

**Core philosophy:**  
Upload raw evidence → parse it automatically → investigate in the Super Timeline → hunt threats →
generate a signed report. Everything happens inside the same platform, with full audit logging.

**Key services (Docker containers):**

| Container | Role |
|---|---|
| `asgard` | React frontend (production build served by Express) |
| `odin` | Node.js backend API (port 4000) |
| `yggdrasil` | PostgreSQL database |
| `mimir` | Elasticsearch 8 (timeline index) |
| `hermod` | Redis (sessions, cache, job queue) |
| `bifrost` | Nginx reverse proxy (port 80) |
| `hel-api` | VolWeb — Volatility 3 REST API |
| `hel-worker` | Celery worker for Volatility analysis tasks |
| `njord` | MinIO S3-compatible object store |
| `tyr` | ClamAV antivirus daemon |
| `huginn` | BullMQ worker (YARA, parsers, SOAR) |
| `ollama` | Local LLM (optional, for the AI analyst) |

---

## 2. Installation & First Start

### Prerequisites

- **Docker** 24+ with the **Compose v2 plugin** (`docker compose version`)
- **openssl** (Linux/macOS) — for secret generation
- At least **16 GB RAM** and **50 GB disk** recommended for production use
- Linux / macOS / Windows (PowerShell 5.1+)

### Linux / macOS

```bash
git clone https://github.com/RaiseiX/Heimdall-DFIR.git
cd Heimdall-DFIR
bash start.sh
```

The script:
1. Checks prerequisites (Docker, Compose, openssl, DNS)
2. Generates a `.env` with random secrets (JWT, DB password, MinIO credentials…)
3. Builds all Docker images (~5–10 min first run)
4. Starts all containers
5. Waits for PostgreSQL, then applies all database migrations
6. Creates the MinIO `volweb` bucket and provisions the VolWeb superuser

### Windows

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\start.ps1
```

### After installation

Open **http://localhost** in your browser.

**Default credentials:**

| Account | Username | Password |
|---|---|---|
| Admin | `admin` | `Admin2026!` |
| Analyst | `analyst` | `Analyst2026!` |

> **Change these passwords immediately** before any production use.

### Optional: Zimmerman Tools

Zimmerman tools (PECmd, MFTECmd, LECmd, SBECmd, RECmd…) are not bundled due to licensing.

```bash
# Download from https://ericzimmerman.github.io/
# Then copy into the container:
docker cp ./PECmd.exe odin:/app/zimmerman-tools/PECmd.exe
docker cp ./MFTECmd.exe odin:/app/zimmerman-tools/MFTECmd.exe
# ... etc.
```

### Optional: Hayabusa

```bash
# Download the binary from https://github.com/Yamato-Security/hayabusa/releases
docker cp hayabusa odin:/app/hayabusa/hayabusa
docker exec odin chmod +x /app/hayabusa/hayabusa
```

### Optional: Local AI (Ollama)

```bash
# In .env, set:
# OLLAMA_URL=http://ollama:11434
docker compose up -d ollama
docker exec ollama ollama pull qwen3:14b
```

---

## 3. Interface Overview

The left sidebar contains:

| Icon | Section | Description |
|---|---|---|
| Grid | **Dashboard** | Global summary across all cases |
| Folder | **Cases** | List of all investigations |
| Target | **Threat Hunting** | YARA & Sigma rule management |
| Shield | **Threat Intel** | TAXII/STIX feeds & IOC database |
| Map | **Network Map** | Global lateral movement graph |
| Calendar | **Calendar** | Case timeline & events calendar |
| Terminal | **Sysmon Configs** | Sysmon XML configurations |
| Book | **Documentation** | Built-in reference (Windows/Linux artifacts, DFIR methodology…) |
| Gear | **Admin** | Users, backups, infrastructure (admin only) |

---

## 4. Cases — Creating & Managing Investigations

### Creating a case

1. Go to **Cases** in the sidebar
2. Click **+ New Case**
3. Fill in:
   - **Name** — e.g. `INC-2026-042`
   - **Description** — context of the incident
   - **Priority** — Critical / High / Medium / Low
   - **Status** — Active / Pending / Closed
   - **Tags** — free-form labels
4. Click **Create**

### Case detail page

Each case has the following tabs:

| Tab | Content |
|---|---|
| **Evidence** | Uploaded files, parser results, memory uploads |
| **Super Timeline** | All parsed artifacts merged in chronological order |
| **IOCs** | Indicators of Compromise for this case |
| **Detections** | SOAR alerts, YARA & Sigma hits, timestomping, C2 beaconing |
| **Network** | Lateral movement graph, PCAP-derived connections |
| **MITRE ATT&CK** | Live matrix populated from timeline data |
| **Playbooks** | DFIR runbooks with step-by-step checklists |
| **Hayabusa** | Sigma detections on uploaded EVTX files |
| **CyberChef** | Embedded CyberChef (decode, transform, analyse) |
| **Audit** | Full event log for every action performed on the case |

### Legal Hold

To freeze evidence and prevent any deletion:

1. Open the case
2. Click the lock icon **⛓ Legal Hold** (top bar)
3. An HMAC-SHA256 signed manifest is generated and can be downloaded as proof

Evidence under legal hold **cannot be deleted** until the hold is lifted (admin only).

---

## 5. Evidence — Uploading Files

### Supported file types

| Category | Examples |
|---|---|
| Windows artifacts | `.evtx`, `.mft`, `SYSTEM`, `SOFTWARE`, `NTUSER.DAT`, `AppCompatCache`, `.pf`, `.lnk`, `.db` |
| Linux artifacts | `auth.log`, `syslog`, `/etc/passwd`, bash history |
| Memory dumps | `.raw`, `.mem`, `.dmp`, `.vmem`, `.bin` (any size up to 256 GB) |
| Network captures | `.pcap`, `.pcapng` |
| Disk images | `.e01`, `.dd`, `.img` |
| Archives | `.zip`, `.tar.gz` (auto-extracted) |

### Uploading a file

1. Open a case → **Evidence** tab
2. Click **+ Upload Evidence**
3. Drag & drop or browse for your file
4. Fill in the optional metadata (description, source machine, acquisition date)
5. Click **Upload**

The file is:
- Scanned by **ClamAV** upon arrival (result shown inline)
- Hashed (MD5, SHA1, SHA256) — displayed in the evidence card
- Stored securely in the backend volume

> **Large files (>1 GB):** Upload uses a chunked protocol (50 MB chunks) with automatic resume.
> If the browser tab closes mid-upload, reopen it — Heimdall detects the interrupted upload
> and resumes from the last received chunk.

### Evidence card

Each uploaded file shows:
- File name, size, MIME type
- SHA256 / MD5 / SHA1 hashes (click to copy)
- ClamAV status (Clean / Infected / Pending)
- **Hex viewer** — first 256 bytes in hex
- **Strings viewer** — printable strings (min 4 chars)
- Parser run buttons (see section 6)

### Deleting evidence

- **Soft delete** — moves the file to trash, removes from ES index
- **Hard delete (DoD 5220.22-M)** — 7-pass shred, database cascade deletion, ES index purge
  → Available via the ⚠ **Hard Delete** button on the evidence card (admin only)

---

## 6. Parsers — Extracting Artifacts

### Running a parser

On an evidence card, click the parser button that matches the file type:

| Parser | Input | Output artifacts |
|---|---|---|
| **PECmd** | `.pf` Prefetch files | Executable name, run count, timestamps, loaded DLLs |
| **MFTECmd** | `$MFT` | All filesystem entries, MAC timestamps, folder paths |
| **LECmd** | `.lnk` LNK files | Target path, creation/access times, volume serial |
| **SBECmd** | `NTUSER.DAT`, `UsrClass.dat` | Shellbag paths, folder access history |
| **RECmd** | Registry hives (`SYSTEM`, `SOFTWARE`, `NTUSER.DAT`) | Key values, timestamps |
| **AppCompatCache** | `SYSTEM` hive | ShimCache entries — executed binaries |
| **AmCache** | `Amcache.hve` | SHA1 of executables, install paths |
| **Hayabusa** | `.evtx` folder or zip | Sigma-rule alerts with MITRE mapping |
| **EVTX** | Individual `.evtx` | Raw Windows Event Log entries |
| **PCAP** | `.pcap` / `.pcapng` | DNS, HTTP, TLS, TCP flow records |
| **SRUM** | `SRUDB.dat` | Application resource usage (CPU, network, bytes) |
| **WxTCmd** | Windows.10.0.db | Jump list / pinned apps |
| **Recycle Bin** | `$I` files | Deleted file records |
| **BITS** | `qmgr.db` | Background Intelligent Transfer jobs |

### Parser console

After launching a parser:
1. A real-time log console opens at the bottom of the page
2. Progress and stdout/stderr from the Zimmerman tool are streamed live
3. When complete, the artifact count is shown
4. Artifacts are immediately available in the **Super Timeline**

### Collections

A **Collection** groups artifacts by evidence source (e.g., all artifacts from `SERVER01`).
Each collection has its own isolated Super Timeline — records from one collection never
appear in another.

To view a collection's timeline:
- Evidence tab → click **View Collection** on any evidence card
- Or use the sidebar collection switcher inside the case

---

## 7. Super Timeline & Investigation Workbench

The Super Timeline is the heart of Heimdall — it merges all parsed artifacts from all
parsers into a single chronological view.

### Accessing the Super Timeline

1. Open a case → **Super Timeline** tab
2. Or navigate directly to `/cases/:id/timeline`

### Filtering & navigation

| Control | Description |
|---|---|
| **Search bar** | Full-text search across description, source, host, user |
| **Artifact type pills** | Filter by evtx, mft, prefetch, lnk, registry, etc. |
| **Date range** | From / To timestamps |
| **Host / User** | Filter by source machine or account |
| **Hayabusa severity** | Filter to critical/high/medium/low Sigma hits only |
| **Pagination** | 2 000 records per page; use ‹ › to navigate |
| **CSV Export** | Downloads up to 50 000 rows; choose delimiter (`,` `;` Tab) |

### Entering Investigation Workbench

Click **🔬 Workbench** (top-right of the timeline) to enter the full investigation interface.

#### Layout

The Workbench splits the screen into two panels:
- **Left (65%)** — the artifact grid
- **Right (35%)** — the inspector (details for the selected row)

Drag the divider to resize.

#### Artifact Grid

Each row represents one forensic event:

| Column | Description |
|---|---|
| ☐ | Select row (multi-select for bulk actions) |
| ★ | Bookmark this event |
| 📌 | Pin (shared with the team) |
| ○ / ⚡ / △ | Anomaly score — ⚡ = high (≥7/10), △ = medium (≥4/10) |
| Timestamp | UTC datetime |
| Type | Artifact type badge (color-coded) |
| Description | Parsed description with inline IOC chips |
| Source | Source file / hive / channel |
| Field | Timestamp column name |

**Right-click** any row for context menu: Follow process · Filter by host/user · Tag event

**Tags:** Click the ○ column on any row to assign a forensic level (Malicious / Suspicious /
Ambiguous / Benign) and free-form tags (Execution, Persistence, Lateral movement…).

#### Gap markers

When "Gaps" is enabled (toolbar), a red dashed separator appears between events with a time
gap larger than the selected threshold (5 min / 30 min / 1h / 4h). Useful for spotting
dormant periods in attacker activity.

#### Playback mode

Click **▶ Playback** (top toolbar) to replay events chronologically with a highlighted cursor.
Useful for walkthrough presentations or understanding the attack timeline step by step.

### Inspector — right panel

Click any row to populate the inspector. Five tabs are available:

#### Details tab

Shows the most important fields at a glance:
- Timestamp + timestamp column name
- Host, User, Process
- MITRE technique badge (if mapped)
- Description chips (colored by category: process, path, user, hash, IP, registry, port)
- Source file path
- **Raw CSV fields** — all original columns from the parser output, sorted by forensic priority
  (process > user > file > registry > network > hash > PID > channel)

Clickable fields: IPs, hashes, URLs have a **▶ VirusTotal** / **▶ AbuseIPDB** link.

For memory artifacts: a **↗ VolWeb (PID N)** button opens VolWeb directly at that process.

#### ±ctx tab (Context)

Shows all events within ±N minutes of the selected event.
Select the time window: 1 / 5 / 15 / 30 / 60 minutes.

Each nearby event shows its delta (e.g. `+2.4m`) and artifact type — ideal for
understanding what happened just before/after a suspicious event.

#### Pivot tab

Lists all **IOC fields** present in the selected event (IP, hash, username, image path, etc.)
with a count of how many other events in the current dataset share the same value.

Click **Pivot** on any field to instantly filter the timeline to all events matching that field/value.
This is the fastest way to pivot from "suspicious process" to "all events involving that process".

#### Verdict tab

- **Anomaly score bar** (0–10) with breakdown:
  - Unusual hours (before 06:00 or after 22:00)
  - Unique executable in dataset
  - Sensitive Event IDs (4698, 4768, 4769…)
  - IoA pattern matches
- **IoA patterns detected** — lists which attack patterns are triggered (Pass-the-Hash, DCSync, Kerberoasting, LOLBins, etc.)
- **Manual verdict** — tag the event as Malicious / Suspect / Ambiguous / Benign

#### Notes tab

Add investigator notes to any event. Notes are:
- Persisted in the database (linked to the event fingerprint)
- Visible to all team members on the case
- Editable / deletable by the author
- Indicated by a badge in the grid (📝 marker on the row)

Use `Ctrl+Enter` to submit a note quickly.

### Workbench tabs

The tab bar at the top of the Workbench gives access to all investigation views:

#### Timeline (default)
The main artifact grid + inspector described above.

#### Gantt
Horizontal bar chart showing artifact type activity over time. Useful for identifying
which artifact types are most dense in a given time range.

#### Heatmap
Calendar heatmap — event density per hour per day. Spots anomalous activity hours
(e.g., middle-of-night events on a business machine).

#### MITRE Live
ATT&CK matrix populated in real time from the loaded records. Techniques are highlighted
according to how many events map to them. Click a technique to filter the timeline.

#### Persistence
Dedicated view for persistence-related events: Registry Run Keys (T1547.001), LNK startup
(T1547.009), BITS Jobs (T1197), scheduled tasks. Auto-populated from the timeline.

#### Defense Evasion
Timestomping analysis ($SIA vs $FN comparison), double-extension detection, hollowing
indicators extracted from the timeline.

#### Process Tree
Builds a parent-child process tree from Event ID 4688 (Windows Security) or Sysmon
Event ID 1 records. Displays PID, process name, and creation timestamp.
Useful for tracing execution chains: `cmd.exe → powershell.exe → mshta.exe`.

#### IoA (Pattern Matcher)
Automatically scans all loaded records against the **8 built-in IoA patterns**:

| Pattern | What it detects |
|---|---|
| Pass-the-Hash | EID 4624 LogonType 3 with NTLM |
| DCSync | EID 4662 with replication GUIDs |
| Kerberoasting | EID 4769 with RC4 ticket (0x17/0x18) |
| LOLBins | certutil, mshta, wscript, regsvr32, rundll32, msiexec… |
| Credential Dumping | lsass access, sekurlsa, mimikatz, wce, pwdump |
| Lateral Transfer | psexec, psexesvc in image or service name |
| Scheduled Task Persist. | EID 4698/4702 or task artifact type |
| PowerShell Encoded | `-EncodedCommand`, `IEX`, `Invoke-Expression` |

Each hit is expandable to show the matching events.

#### Cluster
Groups all events by a selected field (artifact type / host / user / process / source).
A proportional bar shows the relative density. Useful for quickly identifying dominant
artifact types or the most active user account.

#### Multi-host
Left panel lists all source hosts in the dataset.
Click a host to filter the timeline to that machine only.
Useful in multi-host investigations where you need to correlate activity across machines.

#### Kill Chain (Attack Chain Builder)
Left panel shows all events that triggered IoA patterns (suggested notable events).
Click **+** to add any event to your attack chain.
Right panel displays the chain as a visual timeline with connector lines.

When complete:
- Name the chain
- Click **Copy Report** to copy a Markdown-formatted chain report to the clipboard

#### Export
Generate and download the dataset in three formats:

| Format | Content |
|---|---|
| **CSV** | All columns + optional IoA pattern column |
| **JSON** | Full records including raw parsed fields |
| **Markdown** | Investigation report: IoA summary + event table |

Scope options: **All events** or **IoA-only** (filtered to events matching attack patterns).

#### IA (AI Analyst)
Send the loaded timeline data to the configured LLM (Ollama or OpenAI-compatible endpoint).
The AI analyst can summarize the attack, suggest next investigation steps, and answer
questions about specific events.

---

## 8. Hayabusa — Sigma Detections on EVTX

Hayabusa runs Sigma rules against Windows Event Log files (`.evtx`) and produces
detection alerts with MITRE ATT&CK mapping and severity levels.

### Running a Hayabusa analysis

**From the Evidence tab:**
1. Upload a `.evtx` file or a ZIP containing multiple `.evtx` files
2. Click **Run Hayabusa** on the evidence card
3. Results appear in the **Hayabusa** tab of the case

**From the Hayabusa tab directly:**
1. Open a case → **Hayabusa** tab
2. Select the collection to analyse
3. Click **▶ Run Analysis**
4. A progress indicator shows the detection count

### Reading Hayabusa results

The Hayabusa view shows a dense virtualized table:

| Column | Description |
|---|---|
| ★ | Star/bookmark this detection |
| Severity dot | Color: 🔴 Critical · 🟠 High · 🟡 Medium · 🔵 Low |
| Timestamp | Event timestamp |
| Level | Text level label |
| EID | Windows Event ID |
| Channel | Log channel (Security, System, Sysmon…) |
| Sigma Rule | Name of the triggered Sigma rule |
| MITRE | Technique ID (e.g. T1055) |
| Tactic | ATT&CK tactic phase |

**Detail panel (right side):** click any row to see the full event fields, mapped MITRE
technique description, and rule details.

**Filtering:** use the search bar, level pills, and tactic selector to narrow results.

**Stats bar:** shows counts per severity level — click a pill to filter to that level only.

### Standalone Hayabusa page

Navigate to **Cases → [case] → Collections → [collection] → Hayabusa** for the full
standalone view. This page has the same layout as the embedded tab but with a collection
selector allowing you to switch between different evidence sources.

---

## 9. Memory Forensics — RAM Analysis with VolWeb

Heimdall integrates **VolWeb** (Volatility 3 web interface) for RAM dump analysis.

### Uploading a RAM dump

1. Open a case → **Evidence** tab
2. Click **+ Upload Memory Dump**
3. Select your `.raw`, `.mem`, `.vmem`, or `.dmp` file
4. The upload uses **50 MB chunks** with:
   - Real-time progress bar
   - Automatic resume on network interruption
   - 4-attempt exponential backoff per chunk (1s → 2s → 4s)

> Large dumps (16 GB+) typically upload in 5–20 minutes depending on disk I/O.

### Analysis pipeline

After upload completes, Heimdall automatically:
1. Transfers the dump to VolWeb via its chunk API
2. Triggers Volatility analysis via Celery tasks
3. Polls VolWeb every 30 seconds for completion
4. Emits a `volweb:completed` WebSocket event when done → a notification appears in the UI

**Status indicators on the evidence card:**

| Status | Meaning |
|---|---|
| `uploading` | Chunks being received |
| `processing` | Forwarded to VolWeb, Volatility running |
| `ready` | Analysis complete — open VolWeb |
| `error` | Analysis failed — check VolWeb logs |

### Opening VolWeb

When status is `ready`, click **↗ Open VolWeb** on the evidence card.
VolWeb opens at **http://localhost:8888** with the dump pre-loaded.

From VolWeb you can browse:
- Process list (pslist, pstree)
- Network connections (netstat)
- Loaded modules (dlllist)
- Memory strings (strings)
- Injected code (malfind)
- And all other Volatility 3 plugins

### Memory events in the Super Timeline

Memory analysis results that include timestamps (process creation, network connection times)
are automatically ingested into the Super Timeline as `memory` artifact type.

From any memory event in the inspector, the **↗ VolWeb (PID N)** button jumps directly
to that process in the VolWeb interface.

---

## 10. IOCs — Indicators of Compromise

### Adding IOCs manually

1. Open a case → **IOCs** tab
2. Click **+ Add IOC**
3. Fill in:
   - **Type**: IP, Domain, Hash (MD5/SHA1/SHA256), URL, Email, Filename
   - **Value**: the indicator value
   - **Severity**: 1–10 slider
   - **Is Malicious**: toggle
   - **Source**: origin of the IOC (e.g. "VirusTotal", "Threat Intel feed")
   - **Tags**: comma-separated labels
4. Click **Save**

### Importing IOCs from STIX

1. IOCs tab → **Import STIX**
2. Paste STIX 2.1 JSON or upload a `.json` file
3. Heimdall parses all `indicator` and `malware` objects and imports them as IOCs

### IOC enrichment

For each IOC, click the **🔍 Enrich** button to query:
- **VirusTotal** — detection ratio, file type, first/last seen
- **AbuseIPDB** — IP abuse score, country, ISP

Results are cached in Redis for 24 hours to avoid re-querying.

### IOC correlation

Heimdall automatically correlates IOCs against the Super Timeline on each ingestion.
Matching events are flagged in the **Detections** tab with a `threat_intel` label.

To manually trigger correlation:
- Detections tab → **Run Threat Intel Correlation**

### Cross-case IOC view

The global **Threat Intel** page (sidebar) shows all IOCs across all cases with a
cross-case correlation view: if the same IP or hash appears in multiple cases, they
are linked automatically.

---

## 11. Threat Hunting — YARA & Sigma

### YARA Rules

#### Managing rules

Navigate to **Threat Hunting** (sidebar) → **YARA** tab.

- **Create rule**: click **+ New Rule**, paste your YARA syntax, click Save
- **Import from GitHub**: click **Import from GitHub** to bulk-import from:
  - `Neo23x0/signature-base`
  - `Yara-Rules/rules`
  - Any public GitHub repository containing `.yar` / `.yara` files
- **Edit / Delete**: click any rule to open the editor

#### Running a scan

**Per file:**
1. Evidence tab → evidence card → **Run YARA**
2. Select which rules to apply (all or specific ruleset)
3. Results show matched rules, offsets, and matched strings

**Per case (bulk):**
1. Threat Hunting → **Run Case Scan**
2. Select the case
3. All evidence files in the case are scanned

Results are available in the case **Detections** tab under the `yara` category.

### Sigma Rules

#### Managing rules

Threat Hunting → **Sigma** tab.

- **Create rule**: click **+ New Rule**, write your Sigma YAML
- **Import from GitHub**: bulk import from `SigmaHQ/sigma` or any public Sigma repo
- Field mappings: Heimdall maps Sigma field names to Elasticsearch field names automatically
  for `evtx`, `hayabusa`, `sysmon`, `mft`, `network` log categories

#### Running a hunt

1. Threat Hunting → select a Sigma rule → **Hunt**
2. Select the target case and time range
3. Supported modifiers: `contains`, `startswith`, `endswith`, `re` (regex), `all`
4. Results are displayed inline and saved to the Detections tab

---

## 12. Threat Intelligence — TAXII / STIX

### Connecting a TAXII feed

1. **Threat Intel** (sidebar) → **TAXII Feeds** tab
2. Click **+ Add Feed**
3. Enter:
   - Feed URL (TAXII 2.1 discovery URL)
   - Username / Password (if required)
   - Collection ID
4. Click **Test Connection** to verify
5. Enable **Auto-sync** to pull new indicators automatically

### Viewing threat intel

- **Threat Intel** → **Indicators** tab: all imported STIX indicators
- Filter by type (IP, Domain, Hash, URL), TLP level, confidence
- Each indicator shows its source feed, first/last seen, and STIX object type

### Correlation with cases

Threat intel is automatically correlated with the Super Timeline post-ingestion.
Manual trigger: case → Detections tab → **Run Threat Intel Correlation**.

Matched events appear in Detections with the label `threat_intel` and show:
- Which indicator matched
- The STIX object it came from
- Confidence score

---

## 13. Triage — Machine Score

The Machine Score automatically evaluates the risk level of a source machine based on
its event logs. Score range: **0–100**.

### How it works

16 detection rules are evaluated against EVTX and Sysmon artifacts:

- Privilege escalation (EID 4672, 4673)
- Lateral movement (EID 4624 type 3, 4648, 4768, 4769, 4776)
- Process injection indicators (Sysmon EID 8, 10)
- Suspicious PowerShell (EID 4104 with encoded/obfuscated content)
- Service creation (EID 7045)
- Account creation / group modification (EID 4720, 4728, 4732)
- Scheduled task creation (EID 4698)
- Firewall rule modification (EID 4946, 4947)

### Viewing the score

1. Case → **Detections** tab → **Machine Triage** section
2. Or: Threat Hunting → **Triage** → select a case

The panel shows:
- Overall score with a color-coded gauge (green / yellow / orange / red)
- Severity breakdown: Critical / High / Medium / Low
- Rule-by-rule breakdown with event counts
- Recommended next steps based on triggered rules

### Running a triage

Triage runs automatically after EVTX parsing.
To re-run manually: Detections tab → **Re-run Triage**.

---

## 14. Automatic Detections (SOAR)

The SOAR engine runs automatically after every parser execution. It triggers four
detection modules in parallel:

| Module | What it detects |
|---|---|
| **YARA** | File content matches against all enabled YARA rules |
| **Sigma** | Event matches against all enabled Sigma rules |
| **Threat Intel** | IOC correlation against the threat intel database |
| **Triage** | Machine score recalculation |

### Viewing alerts

Case → **Detections** tab.

Each alert shows:
- Severity badge (Critical / High / Medium / Low)
- Category (yara / sigma / threat_intel / timestomping / double_extension / beaconing / persistence)
- Description and affected evidence
- **Acknowledge** button — marks the alert as reviewed

Real-time alerts appear as a badge on the case sidebar entry (updated via WebSocket).

### Built-in detection rules

Beyond YARA/Sigma, Heimdall includes hardcoded detectors:

**Timestomping:**
Compares `$STANDARD_INFORMATION` vs `$FILE_NAME` NTFS timestamps from MFT artifacts.
A delta > 1 second is flagged as potential timestomping.

**Double extension:**
Detects filenames like `invoice.pdf.exe`, `document.docx.scr` in MFT, LNK, Prefetch,
and Amcache artifacts.

**C2 Beaconing:**
For PCAP-derived network records, calculates the **coefficient of variation** (σ/μ)
of connection intervals per destination IP. CV < 0.3 indicates regular beaconing.
Score 0–100 is displayed per destination.

**Persistence:**
Detects four MITRE vectors:
- T1547.001 — Registry Run Keys (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`)
- T1547.009 — LNK files in `\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
- T1197 — BITS jobs from `qmgr.db`
- Hayabusa Sigma alerts tagged with `persistence` tactic

---

## 15. MITRE ATT&CK

### Live matrix

Case → **MITRE ATT&CK** tab.

The matrix is populated in real time from:
- Hayabusa detections (technique IDs from Sigma rule metadata)
- Super Timeline records with `mitre_technique_id` populated
- SOAR Sigma hits with MITRE mapping

Techniques are color-coded by hit count (lighter = fewer hits, darker = more).
Click any technique cell to:
- See the list of matching events
- Filter the Super Timeline to that technique

### Attack Chain

Case → **Evidence** tab → **Attack Chain** button (top right).

The Attack Chain view shows:
- A 14-phase MITRE kill chain (Reconnaissance → Impact)
- Events bookmarked to each phase
- Toggle between **compact** and **full** view
- PDF export of the chain

To bookmark an event to a phase:
1. Select the event in the Super Timeline
2. Click **Bookmark** in the inspector
3. Choose the kill chain phase

### APT Attribution

Case → **MITRE ATT&CK** → **APT Attribution** sub-tab.

Cross-references your detected techniques against known APT group profiles from the
MITRE ATT&CK knowledge base. Shows percentage match with each group.

---

## 16. Network Analysis

### Lateral movement graph

Case → **Network** tab.

A force-directed D3.js graph shows host-to-host connections derived from:
- EID 4624 (logon), 4648 (explicit creds), 4768/4769 (Kerberos)
- EID 4776 (NTLM), Sysmon EID 3 (network connection)
- PCAP-derived TCP flows

**Interactions:**
- Drag nodes to rearrange
- Click a node to highlight its connections
- Click an edge to see the events that created it
- Use the search box to find a specific host
- Filter by protocol or Event ID

### PCAP analysis

Evidence tab → upload a `.pcap` or `.pcapng` → click **Parse PCAP**.

Extracted records ingested into the Super Timeline:
- **DNS** — query/response pairs with resolved IPs
- **HTTP** — method, URL, User-Agent, status code
- **TLS** — SNI (server name), certificate fingerprint, JA3 hash
- **TCP flows** — src/dst IP:port, byte counts, duration

---

## 17. Playbooks

Playbooks are step-by-step DFIR runbooks to guide analysts through common incident types.

### Built-in playbooks

| Playbook | Steps | MITRE coverage |
|---|---|---|
| **Ransomware Response** | 11 steps | T1486, T1490, T1027, T1562 |
| **RDP Compromise** | 10 steps | T1078, T1021.001, T1547 |
| **Phishing Investigation** | 9 steps | T1566, T1204, T1059 |

### Using a playbook

1. Case → **Playbooks** tab
2. Select a playbook
3. For each step:
   - Read the description and recommended actions
   - Check the box when complete
   - Add a note (optional) with your findings for that step
4. Progress is saved automatically and visible to all team members

### Creating a custom playbook

Threat Hunting → **Playbooks** → **+ New Playbook**
- Add any number of steps
- Tag each step with a MITRE technique
- Assign a severity level per step

---

## 18. Reports

### Generating a PDF report

Case → top bar → **Generate Report**.

Two options:

**Quick report**: auto-generated with:
- Case summary (name, dates, priority, status)
- Evidence inventory (files, hashes, sizes)
- Machine triage score with gauge
- YARA results (hit count, matched rules)
- Sigma detections (by severity)
- Threat Intel correlations
- Attack Chain phases
- IOC list

**Template report**: click **Use Template** to select a custom report template.
Templates allow you to define which sections to include and customize the layout.

### Report templates

Admin panel → **Report Templates** (or via the modal in report generation).
Create templates with drag-and-drop section ordering and custom text blocks.

### Export from Workbench

The **Export** tab in the Workbench generates:
- CSV with all filtered events + IoA column
- JSON with full raw fields
- Markdown report with IoA summary + event table

---

## 19. Collaboration — Chat, Notes, Pins

### Case Chat

A real-time chat panel is available for each case (Socket.io powered):
- Click the 💬 chat icon (bottom-right of the case page)
- Messages are persisted in the database
- An unread badge appears on the icon when new messages arrive while the panel is closed
- All team members assigned to the case can participate

### Event Notes

In the Workbench inspector → **Notes** tab:
- Add free-text notes attached to any specific event
- Notes are linked to the event's fingerprint (timestamp + type + source hash)
- Visible to all case members
- Edit or delete your own notes

Events with notes show a 📝 indicator in the artifact grid.

### Pins

A **Pin** marks an event as notable and shares it with the whole team:
1. In the artifact grid, click the 📌 column on any row
2. The pin appears in the **Pins** panel at the top of the Timeline tab
3. Click **⬆ Promote** to make a pin global (visible to everyone, not just you)
4. Team pins are synchronized in real time via WebSocket

### Calendar

**Calendar** (sidebar) shows all cases and their key dates on a monthly calendar.
Useful for tracking deadlines, legal hold expiry dates, and investigation milestones.

---

## 20. Administration

Access: top-right menu → **Admin** (admin role required).

### User management

Admin → **Users** tab:
- Create / edit / delete users
- Set role: `admin` or `analyst`
- Enable / disable 2FA (TOTP)
- View last login and active sessions

### Infrastructure dashboard

Admin → **Infrastructure** tab:
- Live status of all Docker containers (CPU%, RAM%, uptime)
- Auto-refreshes every 5 seconds
- Click a container to see its last 100 log lines

### Database backup

Admin → **Backups** tab:
- Click **Create Backup** → triggers a `pg_dump | gzip`
- Download the backup directly from the browser
- Backups are listed with date, size, and SHA256

### Audit log

Admin → **Audit Log** tab:
- Full event log for all user actions across all cases
- Filter by action type, user, date range
- Exportable as CSV

Actions logged include: login, logout, file upload, parser run, YARA scan, evidence delete, legal hold toggle, backup creation, token refresh, and more.

### Sysmon configurations

**Sysmon Configs** (sidebar):
Four production-ready Sysmon configurations are bundled:
- `SwiftOnSecurity` — balanced, widely used
- `Neo23x0` — threat hunting focused
- `olafhartong_modular` — modular, highly granular
- `ion-storm` — comprehensive with DNS logging

Download any config and deploy it to your Windows endpoints with:
```powershell
.\Sysmon64.exe -accepteula -i sysmon-config.xml
```

---

## 21. Keyboard Shortcuts & Tips

### Workbench shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+K` | Open Command Palette (search all actions) |
| `Click row` | Select event → populate inspector |
| `Click again` | Deselect |
| Right-click | Context menu (filter, follow process) |

### Command Palette (Ctrl+K)

The command palette gives keyboard access to all Workbench actions:
- Switch views (Timeline, Gantt, Heatmap, MITRE…)
- Apply quick filters (critical only, malware keyword, lsass, powershell)
- Toggle playback mode
- Copy all filtered events as CSV

### Elapsed timer

The **mm:ss** counter in the Workbench header tracks how long you have been in
investigation mode for the current session.

### Performance tips

- Use the **artifact type filter** to narrow records before entering the Workbench (fewer
  records = faster rendering)
- The **Cluster tab** is the fastest way to identify which artifact type or host dominates
  your dataset
- Use **Pivot** in the inspector to jump between related events without re-typing searches
- The **±ctx** tab replaces manual timestamp arithmetic — just open it to see what happened
  around a suspicious event

### API access

The backend REST API is fully documented and accessible at `http://localhost:4000`.
All routes require a JWT token obtained from `POST /api/auth/login`.

```bash
curl -s -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin2026!"}' \
  | jq .token
```

Use the token as `Authorization: Bearer <token>` on all subsequent requests.

---

## Appendix — Common Workflows

### Workflow 1: Windows Incident Response

```
1. Create case (INC-2026-XXX, Critical)
2. Upload: $MFT → Parse MFTECmd
3. Upload: EVTX folder (zip) → Parse EVTX + Run Hayabusa
4. Upload: SYSTEM, SOFTWARE, NTUSER.DAT hives → Parse RECmd
5. Upload: Prefetch files → Parse PECmd
6. Upload: SRUM database → Parse SRUMECmd
7. Super Timeline → Workbench
8. Check IoA tab for instant pattern matches
9. Use ±ctx on suspicious events to build the attack sequence
10. Add notable events to Kill Chain
11. Assign MITRE techniques via bookmark
12. Generate PDF report
```

### Workflow 2: RAM Analysis

```
1. Create case or use existing
2. Evidence tab → Upload Memory Dump
3. Wait for upload + VolWeb forwarding (status: processing)
4. Receive volweb:completed notification
5. Click "Open VolWeb" → explore pslist, netstat, malfind
6. Memory timeline events auto-appear in Super Timeline
7. Pivot from VolWeb PID to Timeline using "↗ VolWeb" button in inspector
```

### Workflow 3: Threat Hunting Campaign

```
1. Threat Hunting → import Sigma rules from SigmaHQ/sigma
2. Import YARA rules from Neo23x0/signature-base
3. Run YARA case scan on all evidence
4. Run Sigma hunt with specific rules
5. Review hits in Detections tab
6. Pivot to Super Timeline for context on each hit
7. Export findings via Workbench Export tab
```

### Workflow 4: Multi-Host Investigation

```
1. Create one case
2. Upload artifacts from each host (use host name in evidence description)
3. After parsing, all artifacts land in the same Super Timeline with host_name populated
4. Workbench → Multi-host tab: click each host to isolate its activity
5. Workbench → Cluster tab → group by host_name to see relative activity
6. Use Pivot on user/IP fields to trace lateral movement across hosts
7. Network tab for the lateral movement graph
```

---

*Heimdall DFIR — Guardian of the Nine Worlds — See the unseen.*  
*Documentation generated for version 0.9.6*
