import { Pool } from 'pg';

export interface MachineScore {
  hostname: string;
  score: number;
  risk_level: 'CRITIQUE' | 'ÉLEVÉ' | 'MOYEN' | 'FAIBLE';
  event_count: number;
  breakdown: Record<string, number>;
}

export interface CaseLevelIndicators {
  yara_matches: number;
  sigma_matches: number;
  threat_intel_matches: number;
  malicious_iocs: number;
}

export interface TriageResult {
  case_id: string;
  computed_at: string;
  machines: MachineScore[];
  case_indicators: CaseLevelIndicators;
}

const RISK_LEVEL = (s: number): MachineScore['risk_level'] => {
  if (s >= 80) return 'CRITIQUE';
  if (s >= 60) return 'ÉLEVÉ';
  if (s >= 40) return 'MOYEN';
  return 'FAIBLE';
};

const RULES: Record<string, number> = {

  suspicious_exec_path:      15,
  powershell_encoded:        15,
  lateral_movement:          10,
  privilege_escalation:      10,
  double_extension:          10,
  night_activity:             5,

  sysmon_proc_injection:     20,
  sysmon_lsass_access:       20,
  sysmon_suspicious_netconn: 10,
  sysmon_ads:                10,

  credential_dump_tool:      20,
  lolbas_exec:               15,
  uac_bypass:                15,
  wmi_persistence:           10,
  browser_exploitation:      20,
  ransomware_indicator:      25,
};

export async function computeTriageScores(pool: Pool, caseId: string): Promise<TriageResult> {
  const computed_at = new Date().toISOString();

  const tlRes = await pool.query<{
    hostname: string;
    event_count: string;
    has_suspicious_exec: boolean;
    has_ps_encoded: boolean;
    has_lateral_movement: boolean;
    has_priv_esc: boolean;
    has_double_ext: boolean;
    has_night_activity: boolean;
    has_sysmon_proc_injection: boolean;
    has_sysmon_lsass_access: boolean;
    has_sysmon_suspicious_netconn: boolean;
    has_sysmon_ads: boolean;
    has_credential_dump: boolean;
    has_lolbas: boolean;
    has_uac_bypass: boolean;
    has_wmi_persistence: boolean;
    has_browser_exploit: boolean;
    has_ransomware: boolean;
  }>(`
    SELECT
      COALESCE(
        NULLIF(TRIM(raw->>'ComputerName'), ''),
        NULLIF(TRIM(raw->>'Computer'), ''),
        NULLIF(TRIM(raw->>'Hostname'), ''),
        NULLIF(TRIM(raw->>'host'), ''),
        'inconnu'
      ) AS hostname,
      COUNT(*) AS event_count,

      BOOL_OR(
        raw::text ~* E'\\\\\\\\(temp|appdata|downloads|public)\\\\\\\\'
        AND raw::text ~* E'\\.(exe|ps1|bat|cmd|vbs|scr)'
      ) AS has_suspicious_exec,

      BOOL_OR(
        raw::text ~* 'powershell' AND raw::text ~* E'(-enc[a-z]*|-e\\s+[A-Za-z0-9+/]{16})'
      ) AS has_ps_encoded,

      BOOL_OR(
        (raw->>'EventID' = '4624' OR raw->>'EventId' = '4624')
        AND (raw->>'LogonType' IN ('3','10') OR raw->>'Logon Type' IN ('3','10'))
      ) AS has_lateral_movement,

      BOOL_OR(
        raw->>'EventID' = '4672' OR raw->>'EventId' = '4672'
      ) AS has_priv_esc,

      BOOL_OR(
        raw::text ~* E'\\.(pdf|doc|docx|xls|xlsx|zip|jpg|png)\\.(exe|ps1|bat|cmd|vbs|js|scr)'
      ) AS has_double_ext,

      BOOL_OR(
        EXTRACT(HOUR FROM COALESCE(timestamp, NOW())::timestamptz) >= 22
        OR EXTRACT(HOUR FROM COALESCE(timestamp, NOW())::timestamptz) <= 6
      ) AS has_night_activity,

      -- Process injection: Sysmon EID 8 (CreateRemoteThread) ou patterns natifs
      BOOL_OR(
        (raw->>'EventID' = '8' OR raw->>'EventId' = '8')
        OR raw::text ~* 'CreateRemoteThread'
        OR (raw::text ~* E'(mavinject|process.*inject|shellcode.*inject)'
            AND (raw->>'EventID' IN ('4688','4656') OR raw->>'EventId' IN ('4688','4656')))
      ) AS has_sysmon_proc_injection,

      -- Accès LSASS: Sysmon EID 10 ou EID 4688/4656 avec lsass
      BOOL_OR(
        ((raw->>'EventID' = '10' OR raw->>'EventId' = '10') AND raw::text ~* 'lsass')
        OR ((raw->>'EventID' IN ('4688','4656','4663') OR raw->>'EventId' IN ('4688','4656','4663'))
            AND raw::text ~* 'lsass\.exe'
            AND raw::text ~* E'(procdump|mimikatz|sekurlsa|safetykatz|nanodump|wce\.exe|fgdump)')
      ) AS has_sysmon_lsass_access,

      -- Connexion réseau depuis chemin suspect: Sysmon EID 3 ou WFP EID 5156
      BOOL_OR(
        ((raw->>'EventID' = '3' OR raw->>'EventId' = '3')
          AND raw::text ~* E'\\\\\\\\(temp|appdata|downloads|public)\\\\\\\\')
        OR ((raw->>'EventID' = '5156' OR raw->>'EventId' = '5156')
            AND raw::text ~* E'\\\\\\\\(temp|appdata|downloads|public)\\\\\\\\')
      ) AS has_sysmon_suspicious_netconn,

      -- ADS (Alternate Data Stream): Sysmon EID 15 ou Zone.Identifier
      BOOL_OR(
        raw->>'EventID' = '15' OR raw->>'EventId' = '15'
        OR raw::text ~* ':Zone\.Identifier'
        OR raw::text ~* E'\\$DATA'
      ) AS has_sysmon_ads,

      -- Credential dump tools (ion-storm T1003 / T1490) — ntdsutil ifm, procdump, wce
      BOOL_OR(
        raw::text ~* 'ntdsutil.*ifm'
        OR raw::text ~* 'procdump.*lsass'
        OR raw::text ~* 'mimikatz'
        OR raw::text ~* 'sekurlsa'
      ) AS has_credential_dump,

      -- LOLBAS — certutil, regsvr32/mshta/wscript loading remote (T1218)
      BOOL_OR(
        (raw::text ~* 'certutil' AND raw::text ~* E'(-decode|-urlcache|-f http)')
        OR (raw::text ~* 'regsvr32' AND raw::text ~* E'/i:http')
        OR (raw::text ~* 'mshta' AND raw::text ~* 'http')
      ) AS has_lolbas,

      -- UAC bypass — fodhelper / eventvwr parent (olafhartong T1548.002)
      BOOL_OR(
        raw::text ~* 'fodhelper\.exe'
        OR (raw::text ~* 'eventvwr\.exe' AND raw::text ~* 'ParentImage')
      ) AS has_uac_bypass,

      -- WMI persistence — wmiprvse spawning children (T1546.003)
      BOOL_OR(
        raw::text ~* 'wmiprvse\.exe' AND raw::text ~* 'ParentImage'
      ) AS has_wmi_persistence,

      -- Browser exploitation — browser spawning shell (ion-storm T1189)
      BOOL_OR(
        raw::text ~* E'(chrome|firefox|iexplore|msedge)\.exe'
        AND raw::text ~* E'(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe)'
      ) AS has_browser_exploit,

      -- Ransomware indicators — vssadmin/wbadmin delete shadows (T1490)
      BOOL_OR(
        (raw::text ~* 'vssadmin' AND raw::text ~* 'delete')
        OR (raw::text ~* 'wbadmin' AND raw::text ~* 'delete')
        OR raw::text ~* 'delete shadow'
      ) AS has_ransomware

    FROM collection_timeline
    WHERE case_id = $1
    GROUP BY 1
    ORDER BY COUNT(*) DESC
    LIMIT 200
  `, [caseId]);

  const [yaraR, sigmaR, intelR, iocR] = await Promise.all([
    pool.query<{ cnt: string }>('SELECT COUNT(*) as cnt FROM yara_scan_results WHERE case_id = $1', [caseId]),
    pool.query<{ total: string }>('SELECT COALESCE(SUM(match_count),0) as total FROM sigma_hunt_results WHERE case_id = $1', [caseId]),
    pool.query<{ cnt: string }>('SELECT COUNT(*) as cnt FROM threat_correlations WHERE case_id = $1', [caseId]),
    pool.query<{ cnt: string }>('SELECT COUNT(*) as cnt FROM iocs WHERE case_id = $1 AND is_malicious = true', [caseId]),
  ]);

  const case_indicators: CaseLevelIndicators = {
    yara_matches:        parseInt(yaraR.rows[0]?.cnt || '0'),
    sigma_matches:       parseInt(sigmaR.rows[0]?.total || '0'),
    threat_intel_matches: parseInt(intelR.rows[0]?.cnt || '0'),
    malicious_iocs:      parseInt(iocR.rows[0]?.cnt || '0'),
  };

  const machines: MachineScore[] = tlRes.rows.map(row => {
    const breakdown: Record<string, number> = {};

    if (row.has_suspicious_exec)         breakdown.suspicious_exec_path      = RULES.suspicious_exec_path;
    if (row.has_ps_encoded)              breakdown.powershell_encoded         = RULES.powershell_encoded;
    if (row.has_lateral_movement)        breakdown.lateral_movement           = RULES.lateral_movement;
    if (row.has_priv_esc)                breakdown.privilege_escalation       = RULES.privilege_escalation;
    if (row.has_double_ext)              breakdown.double_extension           = RULES.double_extension;
    if (row.has_night_activity)          breakdown.night_activity             = RULES.night_activity;
    if (row.has_sysmon_proc_injection)   breakdown.sysmon_proc_injection       = RULES.sysmon_proc_injection;
    if (row.has_sysmon_lsass_access)     breakdown.sysmon_lsass_access         = RULES.sysmon_lsass_access;
    if (row.has_sysmon_suspicious_netconn) breakdown.sysmon_suspicious_netconn = RULES.sysmon_suspicious_netconn;
    if (row.has_sysmon_ads)              breakdown.sysmon_ads                  = RULES.sysmon_ads;
    if (row.has_credential_dump)         breakdown.credential_dump_tool        = RULES.credential_dump_tool;
    if (row.has_lolbas)                  breakdown.lolbas_exec                 = RULES.lolbas_exec;
    if (row.has_uac_bypass)              breakdown.uac_bypass                  = RULES.uac_bypass;
    if (row.has_wmi_persistence)         breakdown.wmi_persistence             = RULES.wmi_persistence;
    if (row.has_browser_exploit)         breakdown.browser_exploitation        = RULES.browser_exploitation;
    if (row.has_ransomware)              breakdown.ransomware_indicator         = RULES.ransomware_indicator;

    const raw_score = Object.values(breakdown).reduce((a, b) => a + b, 0);
    const score = Math.min(100, raw_score);

    return {
      hostname: row.hostname,
      score,
      risk_level: RISK_LEVEL(score),
      event_count: parseInt(row.event_count),
      breakdown,
    };
  }).sort((a, b) => b.score - a.score);

  return { case_id: caseId, computed_at, machines, case_indicators };
}

export async function saveTriageScores(pool: Pool, caseId: string, result: TriageResult): Promise<void> {

  await pool.query('DELETE FROM triage_scores WHERE case_id = $1', [caseId]);

  for (const m of result.machines) {
    await pool.query(
      `INSERT INTO triage_scores (case_id, hostname, score, risk_level, event_count, breakdown, computed_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [caseId, m.hostname, m.score, m.risk_level, m.event_count, JSON.stringify(m.breakdown), result.computed_at]
    );
  }
}

export async function getTriageScores(pool: Pool, caseId: string): Promise<{ scores: MachineScore[]; computed_at: string | null }> {
  const res = await pool.query<MachineScore & { computed_at: string }>(
    'SELECT hostname, score, risk_level, event_count, breakdown, computed_at FROM triage_scores WHERE case_id = $1 ORDER BY score DESC',
    [caseId]
  );
  return {
    scores: res.rows,
    computed_at: res.rows[0]?.computed_at || null,
  };
}
