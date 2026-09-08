import { subtypesOf } from './artifactSubtype';

export interface ReparseScope {
  full: boolean;
  types: string[];
}

export function reparseScope(requestedTypes: unknown): ReparseScope {
  if (requestedTypes === 'all') return { full: true, types: [] };

  const asked = (Array.isArray(requestedTypes) ? requestedTypes : [requestedTypes])
    .filter((t): t is string => typeof t === 'string' && t.length > 0);

  const types = new Set<string>();
  for (const t of asked) {
    types.add(t);
    for (const sub of subtypesOf(t)) types.add(sub);
  }

  return { full: false, types: [...types].sort() };
}
