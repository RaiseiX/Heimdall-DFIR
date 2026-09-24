export function includeRawFor(artifactTypes: unknown): boolean {
  if (typeof artifactTypes !== 'string') return false;
  return artifactTypes.split(',').map(t => t.trim()).filter(Boolean).length === 1;
}

export function rawProjection(artifactTypes: unknown): string {
  return includeRawFor(artifactTypes) ? ', raw' : '';
}
