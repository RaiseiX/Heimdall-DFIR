export function resumeArtefactsSql(): string {
  return `
    SELECT artifact_type,
           MAX(artifact_name) AS artifact_name,
           COUNT(*)::bigint AS lignes,
           COUNT(*) FILTER (WHERE timestamp IS NULL)::bigint AS sans_date,
           MIN(timestamp) AS premier,
           MAX(timestamp) AS dernier
      FROM collection_timeline
     WHERE case_id = $1 AND evidence_id = $2
     GROUP BY artifact_type
     ORDER BY lignes DESC, artifact_type`;
}

export interface LigneResume {
  artifact_type: string;
  artifact_name: string | null;
  lignes: string | number;
  sans_date: string | number;
  premier: string | Date | null;
  dernier: string | Date | null;
}

function iso(v: string | Date | null): string | null {
  if (!v) return null;
  const d = v instanceof Date ? v : new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

export function resumeArtefacts(lignes: LigneResume[]) {
  const types = lignes.map((l) => ({
    type: l.artifact_type,
    nom: l.artifact_name || l.artifact_type,
    lignes: Number(l.lignes) || 0,
    sansDate: Number(l.sans_date) || 0,
    premier: iso(l.premier),
    dernier: iso(l.dernier),
  }));
  return {
    types,
    total: types.reduce((s, t) => s + t.lignes, 0),
    sansDate: types.reduce((s, t) => s + t.sansDate, 0),
  };
}
