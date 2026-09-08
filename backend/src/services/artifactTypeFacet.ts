export const ARTIFACT_TYPE_AGG_SIZE = 200;

export interface ArtifactTypeFacet {
  types: string[];
  total: number;
  truncated: boolean;
}

interface Bucket { key?: unknown }

export function artifactTypeFacet(
  buckets: readonly Bucket[] | undefined | null,
  cardinality: number | undefined | null,
): ArtifactTypeFacet {
  const types = Array.isArray(buckets)
    ? buckets.map(b => String(b?.key ?? '')).filter(Boolean)
    : [];
  const mesure = typeof cardinality === 'number' && Number.isFinite(cardinality)
    ? cardinality
    : types.length;
  const total = Math.max(mesure, types.length);
  return { types, total, truncated: total > types.length };
}
