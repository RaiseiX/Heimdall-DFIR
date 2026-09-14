// The columns GET /:caseId/timeline/groups will group by.
//
// This is a security boundary, not a convenience list: the column name is
// interpolated straight into the GROUP BY, so anything outside this set would be
// SQL the caller wrote. It lived inline in the route; it is here so a test can
// hold it to that contract rather than trusting a reading of the route.
//
// `artifact_name` joined the set on 2026-09-14. The re-parse put 1,820,858
// systemd-journal rows into the timeline, and that column is where the syslog
// identifier lands — 153 distinct values on journal rows against one or two fixed
// labels on every other artifact type. Two applications produce 66% of those
// rows, so without grouping by identifier the interesting ones (sshd, sudo, unit
// starts) are buried under discord and tailscaled.
export const GROUPABLE_COLUMNS: ReadonlySet<string> = new Set([
  'tool', 'event_id', 'artifact_type', 'artifact_name', 'host_name', 'user_name',
  'ext', 'mitre_technique_id', 'source', 'process_name',
  'timestamp_kind', 'sha1', 'src_ip', 'dst_ip',
]);
