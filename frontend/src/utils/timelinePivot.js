export function timelinePivotUrl({ caseId, collectionId, search } = {}) {
  if (!caseId) return null;

  const query = search ? `search=${encodeURIComponent(search)}` : '';

  if (collectionId) {
    return `/cases/${caseId}/collections/${collectionId}/timeline${query ? `?${query}` : ''}`;
  }
  return `/super-timeline?caseId=${caseId}${query ? `&${query}` : ''}`;
}
