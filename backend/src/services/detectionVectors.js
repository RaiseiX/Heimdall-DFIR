// Detection SQL vectors extracted from cases.js so detection LOGIC can be tested
// against a real ephemeral Postgres. Definitions here MUST match the pre-extraction
// inline SQL until a hardening task changes them.
const SYSMON_BEHAVIOR_VECTORS = [
      {
        id: 'lsass_access',
        label: 'Accès LSASS (credential dumping) — EventID 10',
        mitre: 'T1003.001',
        severity: 'CRITIQUE',
        query: `
          SELECT id, timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type IN ('evtx', 'sysmon', 'hayabusa')
            AND (
              (COALESCE(raw->>'EventId', raw->>'EventID') = '10'
                AND raw->>'TargetImage' ILIKE '%lsass.exe%'
                AND raw->>'GrantedAccess' IN ('0x1410','0x1438','0x143a','0x1fffff')
                AND COALESCE(raw->>'SourceImage','') NOT ILIKE ALL (ARRAY[
                  '%\\wininit.exe','%\\csrss.exe','%\\services.exe','%\\lsm.exe','%\\MsMpEng.exe',
                  '%\\wmiprvse.exe','%\\taskmgr.exe','%\\procexp%.exe','%\\MsSense.exe','%\\SenseIR.exe'
                ]))
              OR description ILIKE '%mimikatz%'
              OR description ILIKE '%sekurlsa%'
              OR description ILIKE '%lsass%credential%'
            )
          ORDER BY timestamp LIMIT 200`,
      },
      {
        id: 'remote_thread',
        label: 'CreateRemoteThread (injection de processus) — EventID 8',
        mitre: 'T1055',
        severity: 'CRITIQUE',
        query: `
          SELECT id, timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type IN ('evtx', 'sysmon', 'hayabusa')
            AND (
              (COALESCE(raw->>'EventId', raw->>'EventID') = '8'
                AND raw->>'TargetImage' ILIKE ANY (ARRAY[
                  '%\\\\winlogon.exe','%\\\\csrss.exe','%\\\\wininit.exe','%\\\\services.exe',
                  '%\\\\svchost.exe','%\\\\smss.exe','%\\\\lsaiso.exe','%\\\\spoolsv.exe','%\\\\lsass.exe'
                ]))
              OR description ILIKE '%CreateRemoteThread%'
              OR description ILIKE '%remote thread%'
            )
          ORDER BY timestamp LIMIT 200`,
      },
      {
        id: 'exec_from_temp',
        label: 'Exécution depuis %TEMP% / %AppData% — EventID 1',
        mitre: 'T1059',
        severity: 'ÉLEVÉ',
        query: `
          SELECT id, timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type IN ('evtx', 'sysmon', 'prefetch', 'hayabusa')
            AND (
              (COALESCE(raw->>'EventId', raw->>'EventID') = '1'
                AND raw->>'Image' ILIKE '%\\\\Temp\\\\%'
                AND raw->>'Image' NOT ILIKE ALL (ARRAY[
                  '%setup%.exe','%update%.exe','%install%.exe','%updater%.exe','%unins%.exe',
                  '%msiexec%','%svchost%','%trustedinstaller%','%.tmp','%chrome%','%firefox%',
                  '%edge%','%brave%','%opera%','%wget%','%curl%'
                ]))
              OR (description ILIKE '%\\\\Temp\\\\%.exe%' AND description NOT ILIKE ALL (ARRAY[
                  '%setup%.exe','%update%.exe','%install%.exe','%updater%.exe','%unins%.exe',
                  '%msiexec%','%svchost%','%.tmp','%chrome%','%firefox%','%edge%','%wget%','%curl%'
                ]))
            )
          ORDER BY timestamp LIMIT 200`,
      },
      {
        id: 'unsigned_dll',
        label: 'Chargement DLL non signée — EventID 7',
        mitre: 'T1574.002',
        severity: 'ÉLEVÉ',
        query: `
          SELECT id, timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type IN ('evtx', 'sysmon')
            AND COALESCE(raw->>'EventId', raw->>'EventID') = '7'
            AND (
              raw->>'Signed' = 'false'
              OR raw->>'SignatureStatus' ILIKE '%error%'
              OR raw->>'SignatureStatus' ILIKE '%invalid%'
            )
            AND (
              raw->>'Image' ILIKE ANY (ARRAY[
                '%\\\\lsass.exe','%\\\\winlogon.exe','%\\\\csrss.exe','%\\\\wininit.exe',
                '%\\\\services.exe','%\\\\svchost.exe','%\\\\smss.exe','%\\\\spoolsv.exe',
                '%\\\\lsaiso.exe','%\\\\explorer.exe','%\\\\MsMpEng.exe','%\\\\audiodg.exe'
              ])
              OR raw->>'ImageLoaded' ILIKE '%\\\\Temp\\\\%'
              OR raw->>'ImageLoaded' ILIKE '%\\\\AppData\\\\%'
              OR raw->>'ImageLoaded' ILIKE '%\\\\ProgramData\\\\%'
            )
          ORDER BY timestamp LIMIT 200`,
      },
      {
        id: 'suspicious_network',
        label: 'Connexions réseau suspectes — EventID 3',
        mitre: 'T1071',
        severity: 'MOYEN',
        query: `
          SELECT id, timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type IN ('evtx', 'sysmon')
            AND COALESCE(raw->>'EventId', raw->>'EventID') = '3'
            AND (
              raw->>'DestinationPort' IN ('4444','1234','31337','1337','9001','5555','6666','9999')
              OR (raw->>'Image' ILIKE '%wscript%' AND raw->>'DestinationPort' NOT IN ('80','443'))
              OR (raw->>'Image' ILIKE '%mshta%')
            )
          ORDER BY timestamp LIMIT 200`,
      },
      {
        id: 'process_tampering',
        label: 'Altération de processus (Process Herpaderping/Hollowing) — EventID 25',
        mitre: 'T1055.012',
        severity: 'CRITIQUE',
        query: `
          SELECT id, timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type IN ('evtx', 'sysmon')
            AND (
              COALESCE(raw->>'EventId', raw->>'EventID') = '25'
              OR description ILIKE '%process hollowing%'
              OR description ILIKE '%process herpaderping%'
              OR description ILIKE '%process doppelgänging%'
            )
          ORDER BY timestamp LIMIT 200`,
      },
      {
        id: 'suspicious_file_create',
        label: 'Fichiers créés dans emplacements suspects — EventID 11',
        mitre: 'T1074',
        severity: 'MOYEN',
        query: `
          SELECT id, timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type IN ('evtx', 'sysmon')
            AND COALESCE(raw->>'EventId', raw->>'EventID') = '11'
            AND (
              (raw->>'TargetFilename' ILIKE '%\\\\Temp\\\\%' AND raw->>'TargetFilename' ~* '\\.(exe|dll|bat|ps1|vbs|hta|scr|com)$')
              OR (raw->>'TargetFilename' ILIKE '%\\\\AppData\\\\%' AND raw->>'TargetFilename' ~* '\\.(exe|bat|ps1|vbs|hta|scr|com)$')
              OR (raw->>'TargetFilename' ILIKE '%\\\\System32\\\\%' AND raw->>'TargetFilename' ~* '\\.(exe|scr|ps1|bat|hta)$')
              OR (raw->>'TargetFilename' ILIKE '%\\\\SysWOW64\\\\%' AND raw->>'TargetFilename' ~* '\\.(exe|scr|ps1|bat|hta)$')
            )
            AND raw->>'TargetFilename' NOT ILIKE ALL (ARRAY['%setup%.exe','%update%.exe','%install%.exe','%msiexec%.exe','%.tmp'])
          ORDER BY timestamp LIMIT 200`,
      },
      { id: 'c2_named_pipe', label: 'Pipe nommé C2 (PsExec/Cobalt Strike) — EventID 17/18',
        mitre: 'T1572', severity: 'CRITIQUE', query: `
          SELECT id, timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1 AND artifact_type IN ('evtx', 'sysmon')
            AND COALESCE(raw->>'EventId', raw->>'EventID') IN ('17', '18')
            AND (
              raw->>'PipeName' ~* '\\\\(PSEXESVC|paexec|remcom|csexec)' OR
              raw->>'PipeName' ~* '\\\\(msagent_|status_|postex_|MSSE-)' OR
              raw->>'PipeName' ~* '\\\\(demoagent|isapi_http)'
            )
          ORDER BY timestamp LIMIT 200`,
      },
      { id: 'ads_motw', label: 'Alternate Data Stream / Mark-of-the-Web — EventID 15',
        mitre: 'T1564.004', severity: 'MOYEN', query: `
          SELECT id, timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1 AND artifact_type IN ('evtx','sysmon')
            AND COALESCE(raw->>'EventId', raw->>'EventID') = '15'
            AND (
              -- MOTW on downloaded SCRIPT/CONTAINER formats (plain .exe/.msi/.iso
              -- downloads with Zone.Identifier are ubiquitous — not flagged)
              raw->>'TargetFilename' ~* '\\.(ps1|bat|vbs|hta|scr|js|jar):Zone\\.Identifier$'
              OR (raw->>'TargetFilename' ~* '\\.(exe|dll|msi):Zone\\.Identifier$'
                  AND raw->>'TargetFilename' ILIKE '%\\\\Temp\\\\%')
              -- executable content hidden in an alternate data stream
              OR raw->>'TargetFilename' ~* ':[^\\\\]+\\.(exe|dll|ps1|bat|vbs|scr)$'
            )
          ORDER BY timestamp LIMIT 200`,
      },
];

const EXEC_ANOMALY_VECTORS = [
    { id: 'lolbins', label: 'LOLBins — abus d\'exécution', mitre: 'T1218', severity: 'ÉLEVÉ', query: `
      SELECT timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND artifact_type IN ('evtx','sysmon','hayabusa','prefetch') AND (
        raw->>'CommandLine' ILIKE '%regsvr32%/i:http%' OR raw->>'CommandLine' ILIKE '%mshta%http%'
        OR raw->>'CommandLine' ILIKE '%mshta%javascript%' OR raw->>'CommandLine' ILIKE '%mshta%vbscript%'
        OR raw->>'CommandLine' ILIKE '%certutil%-urlcache%' OR raw->>'CommandLine' ILIKE '%certutil%-decode%'
        OR raw->>'CommandLine' ILIKE '%bitsadmin%/transfer%' OR raw->>'CommandLine' ILIKE '%rundll32%javascript:%'
        OR raw->>'CommandLine' ILIKE '%wmic%process%call%create%' OR raw->>'CommandLine' ILIKE '%msiexec%http%'
      ) ORDER BY timestamp LIMIT 200` },
    { id: 'masquerading', label: 'Masquerading — process système hors System32', mitre: 'T1036.005', severity: 'CRITIQUE', query: `
      SELECT timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND raw->>'Image' IS NOT NULL AND (
        (lower(raw->>'Image') LIKE '%svchost.exe'  AND lower(raw->>'Image') NOT LIKE '%system32%' AND lower(raw->>'Image') NOT LIKE '%syswow64%')
        OR (lower(raw->>'Image') LIKE '%lsass.exe'    AND lower(raw->>'Image') NOT LIKE '%system32%')
        OR (lower(raw->>'Image') LIKE '%services.exe' AND lower(raw->>'Image') NOT LIKE '%system32%')
        OR (lower(raw->>'Image') LIKE '%csrss.exe'    AND lower(raw->>'Image') NOT LIKE '%system32%')
        OR (lower(raw->>'Image') LIKE '%winlogon.exe' AND lower(raw->>'Image') NOT LIKE '%system32%')
        OR (lower(raw->>'Image') LIKE '%wininit.exe'  AND lower(raw->>'Image') NOT LIKE '%system32%')
        OR (lower(raw->>'Image') LIKE '%smss.exe'     AND lower(raw->>'Image') NOT LIKE '%system32%')
        OR (lower(raw->>'Image') LIKE '%spoolsv.exe'  AND lower(raw->>'Image') NOT LIKE '%system32%')
        OR (COALESCE(raw->>'EventId', raw->>'EventID') = '1' AND raw->>'OriginalFileName' IS NOT NULL AND raw->>'OriginalFileName' <> '' AND raw->>'Image' NOT ILIKE '%\\' || (raw->>'OriginalFileName'))
      ) ORDER BY timestamp LIMIT 200` },
    { id: 'powershell_abuse', label: 'PowerShell — encodé / cradle / caché', mitre: 'T1059.001', severity: 'ÉLEVÉ', query: `
      SELECT timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND artifact_type IN ('evtx','sysmon','hayabusa') AND (
        (lower(raw->>'Image') LIKE '%powershell%' OR description ILIKE '%powershell%') AND (
          raw->>'CommandLine' ILIKE '%-enc %' OR raw->>'CommandLine' ILIKE '%-encodedcommand%'
          OR raw->>'CommandLine' ILIKE '%frombase64string%' OR raw->>'CommandLine' ILIKE '%-w hidden%'
          OR raw->>'CommandLine' ILIKE '%-windowstyle hidden%' OR raw->>'CommandLine' ILIKE '%downloadstring%'
          OR raw->>'CommandLine' ILIKE '%downloadfile%' OR raw->>'CommandLine' ILIKE '%net.webclient%'
          OR raw->>'CommandLine' ILIKE '%invoke-expression%' OR raw->>'CommandLine' ILIKE '%iex(%'
          OR description ILIKE '%frombase64string%' OR description ILIKE '%downloadstring%'
        )
      ) ORDER BY timestamp LIMIT 200` },
    { id: 'buildtool_abuse', label: 'Compilation à la volée (MSBuild / csc / InstallUtil)', mitre: 'T1127.001', severity: 'ÉLEVÉ', query: `
      SELECT timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND artifact_type IN ('evtx','sysmon','hayabusa','prefetch') AND (
        raw->>'CommandLine' ILIKE '%msbuild.exe%'
        OR raw->>'CommandLine' ILIKE '%csc.exe%'
        OR raw->>'CommandLine' ILIKE '%installutil.exe%'
        OR raw->>'Image' ILIKE '%msbuild.exe%'
        OR raw->>'Image' ILIKE '%installutil.exe%'
      ) ORDER BY timestamp LIMIT 200` },
    { id: 'office_spawn_shell', label: 'Office/Outlook → interpréteur de commandes', mitre: 'T1204.002 / T1106', severity: 'CRITIQUE', query: `
      SELECT timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND artifact_type IN ('evtx','sysmon') AND (
        COALESCE(raw->>'ParentImage','') ~* '(winword|excel|powerpnt|outlook)\\.exe$'
        AND COALESCE(raw->>'Image','') ~* '(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)\\.exe$'
      ) ORDER BY timestamp LIMIT 200` },
    { id: 'signed_proxy_exec', label: 'Proxy signé détourné (pcalua / wsreset / computerdefaults / cmstp)', mitre: 'T1218', severity: 'ÉLEVÉ', query: `
      SELECT timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND artifact_type IN ('evtx','sysmon','hayabusa') AND (
        raw->>'CommandLine' ILIKE '%pcalua.exe%'
        OR raw->>'CommandLine' ILIKE '%wsreset.exe%'
        OR raw->>'CommandLine' ILIKE '%computerdefaults.exe%'
        OR raw->>'CommandLine' ILIKE '%cmstp.exe%inf%'
      ) ORDER BY timestamp LIMIT 200` },
];

// H4: WMI persistence — Sysmon EID 19/20/21, WMIActivity EID 5861 (permanent subscription),
// and the parsed CIM-repository rows (artifact_type 'wmi', friendly Type values
// CmdConsumer/ScriptConsumer/EventFilter/Binding from parse_wmi.py).
// Flags execution-capable consumers only: CommandLineEventConsumer / ActiveScriptEventConsumer,
// a Destination that launches a script/command interpreter, or a repository consumer with a
// CommandLineTemplate/ScriptText — a plain NTEventLogEventConsumer stays silent.
const WMI_PERSISTENCE_VECTORS = [
    { id: 'wmi_binding', label: 'Persistance WMI (Event Consumer/Filter/Binding) — EID 19/20/21/5861', mitre: 'T1546.003', severity: 'CRITIQUE', query: `
      SELECT id, timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND artifact_type IN ('evtx','sysmon','hayabusa','wmi') AND (
        (
          COALESCE(raw->>'EventId', raw->>'EventID') IN ('19','20','21','5861')
          -- EID 19/20/21 sont reutilises par d'autres canaux (RDP LocalSessionManager 20/21, etc.)
          -- -> exiger un contexte WMI (canal WMI-Activity ou description WMI)
          AND (source ILIKE '%WMI-Activity%' OR description ILIKE '%WMI%'
               OR description ILIKE '%EventConsumer%' OR description ILIKE '%EventFilter%')
        )
        OR (artifact_type = 'wmi' AND description ~* '(CmdConsumer|ScriptConsumer|CommandLineTemplate|ScriptText|ScriptingEngine)')
        OR description ~* '(CommandLineEventConsumer|ActiveScriptEventConsumer|FilterToConsumerBinding)'
        OR raw->>'Consumer' ~* '(CommandLineEventConsumer|ActiveScriptEventConsumer)'
        OR (raw->>'Consumer' IS NOT NULL AND raw->>'Destination' ~* '(powershell|cscript|wscript|cmd|\\.vbs|\\.ps1)')
      ) ORDER BY timestamp LIMIT 200` },
];

const TIMESTOMP_QUERY = `SELECT
         id,
         raw->>'FileName'            AS filename,
         raw->>'ParentPath'          AS parent_path,
         raw->>'Extension'           AS extension,
         raw->>'Created0x10'         AS sia_created,
         raw->>'Created0x30'         AS fn_created,
         raw->>'LastModified0x10'    AS sia_modified,
         raw->>'LastModified0x30'    AS fn_modified,
         raw->>'InUse'               AS in_use,
         raw->>'IsDirectory'         AS is_dir,
         timestamp                   AS indexed_at
       FROM collection_timeline
       WHERE case_id = $1
         AND artifact_type = 'mft'
         AND (
           -- $SIA Created before $FN Created (impossible without timestomping).
           -- CASE-guarded: PG only guarantees short-circuit in CASE, so the ::timestamptz
           -- cast never runs on a malformed (non-null but unparseable) value → no 500.
           CASE WHEN raw->>'Created0x10' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
                 AND raw->>'Created0x30' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
                THEN (raw->>'Created0x10')::timestamptz < (raw->>'Created0x30')::timestamptz
                ELSE false END
           OR
           -- $SIA Modified before $FN Modified
           CASE WHEN raw->>'LastModified0x10' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
                 AND raw->>'LastModified0x30' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
                THEN (raw->>'LastModified0x10')::timestamptz < (raw->>'LastModified0x30')::timestamptz
                ELSE false END
           OR
           -- MFTECmd's own SI<FN boolean flag (fires even when timestamps are equal)
           (raw->>'SI<FN') = 'True'
           OR
           -- Sub-second-zeroed $SI while $FN retains sub-second precision (classic timestomp artifact)
           (raw->>'Created0x10' LIKE '%.0000000'
            AND raw->>'Created0x30' IS NOT NULL
            AND raw->>'Created0x30' NOT LIKE '%.0000000')
         )
       -- Rows admitted only by the SI<FN / sub-second branches may carry a malformed
       -- $SI/$FN value; guard the timestamptz cast so ORDER BY can't 500 the endpoint.
       ORDER BY CASE
         WHEN raw->>'Created0x10' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
          AND raw->>'Created0x30' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
         THEN ABS(EXTRACT(EPOCH FROM (
           (raw->>'Created0x10')::timestamptz - (raw->>'Created0x30')::timestamptz
         )))
         ELSE 0
       END DESC
       LIMIT 500`;

module.exports = { SYSMON_BEHAVIOR_VECTORS, TIMESTOMP_QUERY, EXEC_ANOMALY_VECTORS, WMI_PERSISTENCE_VECTORS };
