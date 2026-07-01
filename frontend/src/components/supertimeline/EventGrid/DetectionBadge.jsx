import { memo } from 'react';
import { DETECTION_SEV_COLOR } from '../utils/timelineUtils';

const SEV_ORDER = ['critical', 'high', 'medium', 'greyware', 'low'];
const SEV_SHORT = { critical: 'CRIT', high: 'HIGH', medium: 'MED', greyware: 'GREY', low: 'LOW' };

export const DetectionBadge = memo(function DetectionBadge({ detections }) {
  if (!Array.isArray(detections) || !detections.length) {
    return <span style={{ color: 'var(--fl-border)' }}>—</span>;
  }
  const bySev = {};
  for (const d of detections) {
    const s = d?.severity || 'low';
    bySev[s] = (bySev[s] || 0) + 1;
  }
  const tooltip = detections
    .map(d => `${(d.severity || '?').toUpperCase()} — ${d.name}${d.mitre?.length ? ` [${d.mitre.join(',')}]` : ''}`)
    .join('\n');
  return (
    <span title={tooltip} style={{ display: 'inline-flex', gap: 3 }}>
      {SEV_ORDER.filter(s => bySev[s]).map(s => {
        const c = DETECTION_SEV_COLOR[s];
        return (
          <span key={s} style={{
            padding: '1px 5px', borderRadius: 3, fontSize: 9, fontWeight: 700,
            background: `color-mix(in srgb, ${c} 13%, transparent)`, color: c, border: `1px solid color-mix(in srgb, ${c} 31%, transparent)`,
          }}>
            {SEV_SHORT[s]}·{bySev[s]}
          </span>
        );
      })}
    </span>
  );
});
