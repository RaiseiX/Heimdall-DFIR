export function windowsProcessEventsSql(): string {
  return `
    SELECT id, timestamp, artifact_type, description, source, event_id,
           raw->>'Provider' AS provider,
           raw->>'Channel'  AS channel
      FROM collection_timeline
     WHERE case_id = $1 AND evidence_id = $2
       AND artifact_type = 'evtx'
       AND raw->>'ProcessId' = $3
       AND timestamp >= $4::timestamptz
       AND ($5::timestamptz IS NULL OR timestamp < $5::timestamptz)
     ORDER BY timestamp DESC
     LIMIT $6`;
}
