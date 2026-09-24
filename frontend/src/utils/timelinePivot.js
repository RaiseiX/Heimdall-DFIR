import { QUERY_KEY_SET } from '../components/supertimeline/utils/timelineFilterKeys';

export function timelinePivotUrl({ caseId, collectionId, search, filters } = {}) {
  if (!caseId) return null;

  const sp = new URLSearchParams();
  if (search) sp.set('search', search);
  for (const [cle, valeur] of Object.entries(filters || {})) {
    if (!QUERY_KEY_SET.has(cle)) continue;
    if (valeur == null || valeur === '') continue;
    sp.set(cle, String(valeur));
  }

  const query = sp.toString().replace(/\+/g, '%20');

  if (collectionId) {
    return `/cases/${caseId}/collections/${collectionId}/timeline${query ? `?${query}` : ''}`;
  }
  return `/super-timeline?caseId=${caseId}${query ? `&${query}` : ''}`;
}
