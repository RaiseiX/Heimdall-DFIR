const PREFIXE = /^([A-Za-z]:\\|\\Device\\HarddiskVolume[0-9]+\\|\.\\)/;

const PREFIXE_SQL = '^([A-Za-z]:\\\\|\\\\Device\\\\HarddiskVolume[0-9]+\\\\|\\.\\\\)';

const RELATIF = (expr: string) =>
  `lower(regexp_replace(${expr}, '${PREFIXE_SQL}', ''))`;

export function cheminRelatif(chemin?: string | null): string {
  if (typeof chemin !== 'string') return '';
  return chemin.trim().replace(PREFIXE, '').toLowerCase();
}

export function binaireAmcacheSql(): string {
  return `
    SELECT raw->>'FullPath'       AS chemin,
           raw->>'SHA1'           AS sha1,
           raw->>'Size'           AS taille,
           raw->>'ProductVersion' AS version,
           raw->>'ProductName'    AS produit,
           raw->>'LinkDate'       AS lien
      FROM collection_timeline
     WHERE case_id = $1 AND evidence_id = $2
       AND artifact_type = 'amcache_files'
       AND ${RELATIF(`coalesce(raw->>'FullPath','')`)} = $3
     LIMIT 5`;
}

export function binaireMftSql(): string {
  return `
    SELECT raw->>'FileSize'             AS taille,
           raw->>'Created0x10'          AS cree,
           raw->>'LastModified0x10'     AS modifie,
           raw->>'LastRecordChange0x10' AS change_enr,
           raw->>'LastAccess0x10'       AS accede,
           raw->>'ParentPath'           AS parent
      FROM collection_timeline
     WHERE case_id = $1 AND evidence_id = $2
       AND artifact_type = 'mft'
       AND raw @> jsonb_build_object('FileName', $4::text)
       AND ${RELATIF(`coalesce(raw->>'ParentPath','') || '\\' || coalesce(raw->>'FileName','')`)} = $3
     LIMIT 5`;
}

export function executionPrefetchSql(): string {
  return `
    SELECT raw->>'ExecutableName' AS nom,
           raw->>'RunCount'       AS executions,
           raw->>'LastRun'        AS derniere,
           raw->>'FilesLoadedCount' AS fichiers
      FROM collection_timeline
     WHERE case_id = $1 AND evidence_id = $2
       AND artifact_type = 'prefetch'
       AND lower(coalesce(raw->>'ExecutableName','')) = $3
     ORDER BY timestamp DESC
     LIMIT 5`;
}

export function executionSrumSql(): string {
  return `
    SELECT raw->>'Timestamp'              AS quand,
           raw->>'ForegroundBytesRead'    AS lus,
           raw->>'ForegroundBytesWritten' AS ecrits,
           raw->>'ForegroundCycleTime'    AS cycles
      FROM collection_timeline
     WHERE case_id = $1 AND evidence_id = $2
       AND artifact_type = 'srum'
       AND ${RELATIF(`coalesce(raw->>'ExeInfo','')`)} = $3
     ORDER BY timestamp DESC
     LIMIT 5`;
}

export function homonymesSql(): string {
  return `
    SELECT raw->>'FullPath' AS chemin,
           raw->>'SHA1'     AS sha1,
           raw->>'Size'     AS taille
      FROM collection_timeline
     WHERE case_id = $1 AND evidence_id = $2
       AND artifact_type = 'amcache_files'
       AND lower(coalesce(raw->>'Name','')) = $3
       AND ${RELATIF(`coalesce(raw->>'FullPath','')`)} <> $4
     ORDER BY 1
     LIMIT 20`;
}

export function repartitionEvenementsSql(): string {
  return `
    SELECT event_id,
           count(*)::text AS n,
           min(description) AS libelle
      FROM collection_timeline
     WHERE case_id = $1 AND evidence_id = $2
       AND artifact_type = 'evtx'
       AND raw->>'ProcessId' = $3
       AND timestamp >= $4::timestamptz
       AND ($5::timestamptz IS NULL OR timestamp < $5::timestamptz)
     GROUP BY event_id
     ORDER BY count(*) DESC, event_id
     LIMIT $6`;
}
