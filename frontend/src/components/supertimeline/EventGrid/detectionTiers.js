export const GRID_SEVERITIES = new Set(['critical', 'high']);

export function gridDetections(detections) {
  if (!Array.isArray(detections)) return [];
  return detections.filter(d => d && typeof d === 'object' && GRID_SEVERITIES.has(d.severity));
}

export function hasGridDetection(detections) {
  return gridDetections(detections).length > 0;
}

const CHIP_ORDER = ['critical', 'high'];

export function gridSeverity(detections) {
  const visible = gridDetections(detections);
  if (visible.length === 0) return null;
  return CHIP_ORDER.find(s => visible.some(d => d.severity === s)) ?? null;
}

export function detectionLabel(detections) {
  const severity = gridSeverity(detections);
  if (!severity) return null;
  const sources = [...new Set(gridDetections(detections).map(d => d.source).filter(Boolean))].sort();
  return sources.length ? `${severity} · ${sources.join('+')}` : severity;
}

export function detectionSummary(detections) {
  const all = Array.isArray(detections)
    ? detections.filter(d => d && typeof d === 'object')
    : [];
  const visible = gridDetections(all);

  const bySev = {};
  for (const d of visible) bySev[d.severity] = (bySev[d.severity] || 0) + 1;

  const chips = CHIP_ORDER
    .filter(s => bySev[s])
    .map(s => ({ severity: s, count: bySev[s] }));

  const sources = [...new Set(visible.map(d => d.source).filter(Boolean))].sort();

  const tooltip = all
    .map(d => `${String(d.severity || '?').toUpperCase()} — ${d.name}${d.source ? ` (${d.source})` : ''}${Array.isArray(d.mitre) && d.mitre.length ? ` [${d.mitre.join(',')}]` : ''}`)
    .join('\n');

  return { chips, sources, tooltip, hiddenCount: all.length - visible.length };
}
