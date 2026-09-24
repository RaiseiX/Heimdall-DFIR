const COLLECTION_RE = /\/cases\/[^/]+\/collections\/([^/]+)/;

export function breadcrumbTargets(pathname, caseId) {
  const path = typeof pathname === 'string' ? pathname : '';
  const cas = caseId ? String(caseId) : null;
  const m = COLLECTION_RE.exec(path);
  return {
    cases: '/cases',
    caseRoot: cas ? `/cases/${cas}` : null,
    collection: cas && m ? `/cases/${cas}/collections/${m[1]}` : null,
  };
}
