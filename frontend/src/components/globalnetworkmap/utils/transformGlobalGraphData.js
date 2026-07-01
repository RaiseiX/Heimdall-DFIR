// frontend/src/components/globalnetworkmap/utils/transformGlobalGraphData.js
import { transformGraphData } from '../../networkmap/utils/graphDataTransform';

// Thin wrapper: calls existing transformGraphData then annotates each node element
// with evidence_ids and correlationCount derived from the merged API response.
export function transformGlobalGraphData(apiData, subnetRules = []) {
  const { elements } = transformGraphData(apiData, {}, subnetRules);

  return elements.map(el => {
    // Edges have el.data.source — skip annotation
    if (!el.data?.id || el.data?.source != null) return el;

    const raw = el.data?._raw;
    if (!raw) return el;

    const evidenceIds      = raw.evidence_ids || [];
    const correlationCount = evidenceIds.length;

    const newEl = {
      ...el,
      data: {
        ...el.data,
        evidence_ids:    evidenceIds,
        correlationCount,
      },
    };

    if (correlationCount >= 2) {
      const existing = newEl.classes || '';
      newEl.classes = existing
        ? `${existing} correlated`
        : 'correlated';
    }

    return newEl;
  });
}
