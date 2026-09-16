-- ╔══════════════════════════════════════════════════════════════╗
-- ║  Migration v2.16 — Playbooks DFIR + Legal Hold             ║
-- ╚══════════════════════════════════════════════════════════════╝
-- Run: docker exec -i forensiclab-db psql -U forensiclab forensiclab < db/migrate_v2.16.sql

-- ── Playbook library ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS playbooks (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  title         VARCHAR(200) NOT NULL,
  incident_type VARCHAR(50)  NOT NULL DEFAULT 'generic',
  description   TEXT,
  is_active     BOOLEAN      NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS playbook_steps (
  id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  playbook_id    UUID        NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
  step_order     INTEGER     NOT NULL,
  title          VARCHAR(300) NOT NULL,
  description    TEXT,
  note_required  BOOLEAN     NOT NULL DEFAULT FALSE,
  mitre_technique VARCHAR(20),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(playbook_id, step_order)
);

-- ── Playbook instances (one per case) ─────────────────────────
CREATE TABLE IF NOT EXISTS case_playbooks (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id      UUID        NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  playbook_id  UUID        NOT NULL REFERENCES playbooks(id),
  started_by   UUID        REFERENCES users(id),
  started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  UNIQUE(case_id, playbook_id)
);

CREATE TABLE IF NOT EXISTS case_playbook_steps (
  id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  case_playbook_id UUID        NOT NULL REFERENCES case_playbooks(id) ON DELETE CASCADE,
  step_id          UUID        NOT NULL REFERENCES playbook_steps(id),
  completed        BOOLEAN     NOT NULL DEFAULT FALSE,
  note             TEXT,
  completed_by     UUID        REFERENCES users(id),
  completed_at     TIMESTAMPTZ,
  UNIQUE(case_playbook_id, step_id)
);

CREATE INDEX IF NOT EXISTS idx_cp_case   ON case_playbooks(case_id);
CREATE INDEX IF NOT EXISTS idx_cps_cp    ON case_playbook_steps(case_playbook_id);

-- ── Legal Hold columns on cases ───────────────────────────────
ALTER TABLE cases
  ADD COLUMN IF NOT EXISTS legal_hold    BOOLEAN    NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS legal_hold_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS legal_hold_by UUID       REFERENCES users(id);

-- ═══════════════════════════════════════════════════════════════
-- Seed: 3 reference playbooks
-- ═══════════════════════════════════════════════════════════════

-- Ransomware
WITH pb AS (
  INSERT INTO playbooks (title, incident_type, description)
  VALUES ('Réponse Incident Ransomware', 'ransomware',
    'Procédure d''investigation forensique pour un incident ransomware : de l''isolation à la documentation.')
  ON CONFLICT DO NOTHING RETURNING id
)
INSERT INTO playbook_steps (playbook_id, step_order, title, description, note_required, mitre_technique)
SELECT pb.id, s.step_order, s.title, s.description, s.note_required, s.mitre_technique
FROM pb, (VALUES
  (1, 'Isolation réseau immédiate', 'Déconnecter le système du réseau (VLAN dédié ou débranchement physique). Documenter l''heure exacte.', TRUE, 'T1562.001'),
  (2, 'Identification du patient zéro', 'Identifier la première machine compromise. Collecter les logs de connexion réseaux des dernières 72h.', TRUE, NULL),
  (3, 'Analyse du vecteur d''infection initial', 'Rechercher l''email de phishing, l''exploit web ou le vecteur USB. Analyser les logs proxy, email et EDR.', TRUE, 'T1566'),
  (4, 'Collecte mémoire vive', 'Capturer la RAM de la machine infectée (Volatility/WinPmem). Lancer l''analyse VolWeb.', TRUE, NULL),
  (5, 'Analyse EventLog (Windows)', 'Importer les EVTX via Hayabusa. Cibler EID 4624/4648 (logon réseau), 4698 (tâche planifiée), 7045 (service créé).', FALSE, 'T1547'),
  (6, 'Recherche de persistances', 'Analyser les Run Keys (RECmd), services (sc query), tâches planifiées, WMI subscriptions.', TRUE, 'T1547.001'),
  (7, 'Analyse des connexions C2', 'Extraire les connexions réseau depuis Sysmon EID 3 et les logs firewall. Chercher des patterns de beaconing.', FALSE, 'T1071'),
  (8, 'Identification des données chiffrées', 'Lister les fichiers avec extension inconnue. Rechercher la note de rançon. Vérifier les copies shadow (vssadmin).', TRUE, 'T1486'),
  (9, 'Reconstruction de la timeline d''attaque', 'Consolider tous les artefacts dans la Super Timeline. Identifier le dwell time.', TRUE, NULL),
  (10, 'Analyse des outils de l''attaquant', 'Rechercher mimikatz, cobalt strike, PsExec, AnyDesk dans Prefetch/Amcache/MFT.', FALSE, 'T1588'),
  (11, 'Documentation et rapport final', 'Rédiger le rapport forensique. Inclure la chaîne d''attaque MITRE, les IOCs et les recommandations.', TRUE, NULL)
) AS s(step_order, title, description, note_required, mitre_technique);

-- Compromission RDP
WITH pb AS (
  INSERT INTO playbooks (title, incident_type, description)
  VALUES ('Compromission via RDP', 'rdp',
    'Procédure d''investigation pour une compromission par accès RDP non autorisé (brute-force ou credentials volés).')
  ON CONFLICT DO NOTHING RETURNING id
)
INSERT INTO playbook_steps (playbook_id, step_order, title, description, note_required, mitre_technique)
SELECT pb.id, s.step_order, s.title, s.description, s.note_required, s.mitre_technique
FROM pb, (VALUES
  (1, 'Identification des connexions RDP suspectes', 'Analyser EID 4624 (type 10=RemoteInteractive), 4625 (échecs), 4634/4647 (déconnexion). Identifier les IPs sources.', TRUE, 'T1078'),
  (2, 'Vérification des comptes compromis', 'Lister les comptes ayant accédé via RDP. Vérifier la création de comptes (EID 4720) et ajouts aux groupes (EID 4728).', TRUE, NULL),
  (3, 'Collecte des artefacts de session RDP', 'Analyser prefetch (mstsc.exe), jump lists, recent files. Vérifier UserAssist et ShellBags.', FALSE, 'T1021.001'),
  (4, 'Analyse du mouvement latéral', 'Construire le graphe de mouvement latéral. Identifier les machines atteintes via EID 4648.', TRUE, 'T1021'),
  (5, 'Recherche de persistances', 'Vérifier tâches planifiées (EID 4698), services (EID 7045), Run Keys, comptes backdoor.', TRUE, 'T1547'),
  (6, 'Analyse des outils déposés', 'Chercher dans Prefetch/Amcache les outils d''attaquant (netcat, mimikatz, tools de tunnel).', FALSE, 'T1588'),
  (7, 'Reconstruction timeline d''accès', 'Reconstituer la chronologie des accès. Identifier le premier accès et la durée de présence.', TRUE, NULL),
  (8, 'Identification des données accédées', 'Analyser les logs de fichiers partagés (EID 5140/5145), accès DB, exfiltration potentielle.', TRUE, 'T1005'),
  (9, 'Analyse réseau (C2/exfiltration)', 'Analyser les connexions sortantes. Chercher tunnels SSH/RDP, transferts FTP/HTTPS suspects.', FALSE, 'T1041'),
  (10, 'Documentation et remédiation', 'Rapport final + recommandations (MFA, NLA, accès conditionnel, rotation des credentials).', TRUE, NULL)
) AS s(step_order, title, description, note_required, mitre_technique);

-- Phishing
WITH pb AS (
  INSERT INTO playbooks (title, incident_type, description)
  VALUES ('Réponse Incident Phishing', 'phishing',
    'Procédure d''investigation pour un incident de phishing avec exécution de payload ou vol de credentials.')
  ON CONFLICT DO NOTHING RETURNING id
)
INSERT INTO playbook_steps (playbook_id, step_order, title, description, note_required, mitre_technique)
SELECT pb.id, s.step_order, s.title, s.description, s.note_required, s.mitre_technique
FROM pb, (VALUES
  (1, 'Récupération de l''email suspect', 'Obtenir l''email au format .eml. Extraire les headers SMTP (Return-Path, X-Originating-IP, DKIM).', TRUE, 'T1566.001'),
  (2, 'Analyse des pièces jointes', 'Extraire et analyser les pièces jointes en sandbox. Scanner avec YARA. Noter les hashes.', TRUE, 'T1566.001'),
  (3, 'Extraction et analyse des URLs', 'Dénombrer les URLs dans l''email. Vérifier les redirections. Enrichir avec VirusTotal.', TRUE, 'T1566.002'),
  (4, 'Vérification des clics utilisateurs', 'Analyser les logs proxy pour identifier qui a cliqué sur le lien. Vérifier les logs email gateway.', TRUE, NULL),
  (5, 'Recherche d''exécution de payload', 'Analyser Prefetch, Amcache, AppCompat pour des exécutables inconnus. Vérifier les téléchargements récents.', TRUE, 'T1204'),
  (6, 'Analyse post-exploitation', 'Si payload exécuté : chercher de la persistance, du mouvement latéral, des connexions C2.', FALSE, 'T1059'),
  (7, 'Inventaire des comptes compromis', 'Vérifier si des credentials ont été soumis à une page de phishing (proxy logs, formulaires). Forcer la rotation des MDP.', TRUE, 'T1078'),
  (8, 'Recherche de propagation interne', 'Vérifier si l''attaquant a relancé des campagnes de phishing depuis l''infrastructure interne.', FALSE, 'T1534'),
  (9, 'Documentation et mesures préventives', 'Rapport + IOCs (domaines, IPs, hashes). Recommandations : filtrage email, formation utilisateurs, MFA.', TRUE, NULL)
) AS s(step_order, title, description, note_required, mitre_technique);
