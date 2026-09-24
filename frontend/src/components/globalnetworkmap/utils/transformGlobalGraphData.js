import { transformGraphData } from '../../networkmap/utils/graphDataTransform';

export function transformGlobalGraphData(apiData, subnetRules = []) {
  const { elements } = transformGraphData(apiData, {}, subnetRules);

  return elements.map(el => {
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
