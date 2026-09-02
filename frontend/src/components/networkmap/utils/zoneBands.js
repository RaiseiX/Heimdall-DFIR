
import { zoneOf } from './zoneDeclaration';

export const BAND_ORDER = Object.freeze(['internal', 'external', 'unzoned']);

export function zoneBands(elements, declarations) {
  const groups = new Map();

  for (const el of elements || []) {
    if (el?.data?.source != null) continue;
    if (el?.data?.nodeType === 'cluster') continue;
    if (el?.data?.id == null) continue;

    const { inferred } = zoneOf({ id: el.data.id, type: el.data?._raw?.type }, declarations);
    const key = inferred || 'unzoned';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(el);
  }

  return BAND_ORDER
    .filter(zone => groups.has(zone))
    .map(zone => ({ zone, nodes: groups.get(zone) }));
}
