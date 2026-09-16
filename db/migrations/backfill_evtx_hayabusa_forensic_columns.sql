-- v2.24 — backfill legacy EVTX / Hayabusa rows whose v2.23 forensic columns are NULL.
-- Safe to re-run: only touches rows where tool IS NULL or event_id IS NULL.

BEGIN;

-- EVTX: tool + event_id from raw JSON payload
UPDATE collection_timeline
SET tool     = COALESCE(tool, 'EvtxECmd'),
    event_id = COALESCE(
      event_id,
      NULLIF(regexp_replace(COALESCE(raw->>'EventId', raw->>'EventID', raw->>'event_id', ''), '\D', '', 'g'), '')::int
    )
WHERE artifact_type = 'evtx'
  AND (tool IS NULL OR event_id IS NULL);

-- Hayabusa: tool + event_id
UPDATE collection_timeline
SET tool     = COALESCE(tool, 'Hayabusa'),
    event_id = COALESCE(
      event_id,
      NULLIF(regexp_replace(COALESCE(raw->>'event_id', raw->>'EventID', raw->>'EventId', ''), '\D', '', 'g'), '')::int
    )
WHERE artifact_type = 'hayabusa'
  AND (tool IS NULL OR event_id IS NULL);

-- EVTX per-EventID MITRE override (only overwrites when current value is NULL)
UPDATE collection_timeline SET
  mitre_technique_id   = 'T1078',
  mitre_technique_name = 'Valid Accounts',
  mitre_tactic         = 'defense-evasion'
WHERE artifact_type IN ('evtx', 'hayabusa') AND event_id = 4624 AND mitre_technique_id IS NULL;

UPDATE collection_timeline SET
  mitre_technique_id   = 'T1110',
  mitre_technique_name = 'Brute Force',
  mitre_tactic         = 'credential-access'
WHERE artifact_type IN ('evtx', 'hayabusa') AND event_id = 4625 AND mitre_technique_id IS NULL;

UPDATE collection_timeline SET
  mitre_technique_id   = 'T1059',
  mitre_technique_name = 'Command and Scripting Interpreter',
  mitre_tactic         = 'execution'
WHERE artifact_type IN ('evtx', 'hayabusa') AND event_id = 4688 AND mitre_technique_id IS NULL;

UPDATE collection_timeline SET
  mitre_technique_id   = 'T1070.001',
  mitre_technique_name = 'Indicator Removal: Clear Windows Event Logs',
  mitre_tactic         = 'defense-evasion'
WHERE artifact_type IN ('evtx', 'hayabusa') AND event_id = 1102 AND mitre_technique_id IS NULL;

UPDATE collection_timeline SET
  mitre_technique_id   = 'T1543.003',
  mitre_technique_name = 'Create or Modify System Process: Windows Service',
  mitre_tactic         = 'persistence'
WHERE artifact_type IN ('evtx', 'hayabusa') AND event_id = 7045 AND mitre_technique_id IS NULL;

UPDATE collection_timeline SET
  mitre_technique_id   = 'T1053.005',
  mitre_technique_name = 'Scheduled Task/Job: Scheduled Task',
  mitre_tactic         = 'persistence'
WHERE artifact_type IN ('evtx', 'hayabusa') AND event_id = 4698 AND mitre_technique_id IS NULL;

COMMIT;
