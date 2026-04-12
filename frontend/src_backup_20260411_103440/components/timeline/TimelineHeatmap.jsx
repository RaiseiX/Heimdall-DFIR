
import { useState, useEffect } from 'react';
import { collectionAPI } from '../../utils/api';

const DAYS = ['Dim', 'Lun', 'Mar', 'Mer', 'Jeu', 'Ven', 'Sam'];
const HOURS = Array.from({ length: 24 }, (_, i) => i);

function lerp(t) {

  const r = Math.round(77  + (0   - 77)  * (1 - t));
  const g = Math.round(130 + (180 - 130) * t);
  const b = Math.round(192 + (255 - 192) * t);
  const a = Math.max(0.05, t);
  return `rgba(${r},${g},${b},${a})`;
}

export default function TimelineHeatmap({ caseId, availTypes, startTime, endTime }) {
  const [matrix, setMatrix]   = useState(null);
  const [maxCount, setMaxCount] = useState(1);
  const [loading, setLoading] = useState(false);
  const [hoveredCell, setHoveredCell] = useState(null);

  useEffect(() => {
    if (!caseId) return;
    setLoading(true);
    const params = {};
    if (availTypes?.length) params.artifact_types = availTypes.join(',');
    if (startTime) params.start_time = startTime;
    if (endTime)   params.end_time   = endTime;
    collectionAPI.heatmap(caseId, params)
      .then(r => {
        setMatrix(r.data.matrix);
        setMaxCount(r.data.max_count || 1);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [caseId, availTypes?.join(','), startTime, endTime]);

  if (loading) return (
    <div style={{ padding: '20px', textAlign: 'center', fontFamily: 'monospace', fontSize: 11, color: '#3a6a9a' }}>
      Chargement heatmap…
    </div>
  );
  if (!matrix) return null;

  const CELL_W = 22;
  const CELL_H = 18;
  const LABEL_W = 36;

  return (
    <div style={{ padding: '12px 16px', userSelect: 'none' }}>
      <div style={{ fontFamily: 'monospace', fontSize: 9, color: '#3a6a9a', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8 }}>
        Heatmap activité — heure UTC × jour de semaine
      </div>

      <div style={{ display: 'flex', marginLeft: LABEL_W, marginBottom: 2 }}>
        {HOURS.filter(h => h % 3 === 0).map(h => (
          <div key={h} style={{
            width: CELL_W * 3, fontSize: 8, fontFamily: 'monospace',
            color: '#2a5a8a', textAlign: 'center',
          }}>{String(h).padStart(2, '0')}h</div>
        ))}
      </div>

      {DAYS.map((day, wd) => (
        <div key={wd} style={{ display: 'flex', alignItems: 'center', marginBottom: 2 }}>
          
          <div style={{ width: LABEL_W, fontSize: 9, fontFamily: 'monospace', color: '#3a6a9a', flexShrink: 0 }}>
            {day}
          </div>
          
          {HOURS.map(h => {
            const count = matrix[wd][h];
            const t = count > 0 ? Math.max(0.08, count / maxCount) : 0;
            const isHovered = hoveredCell?.weekday === wd && hoveredCell?.hour === h;
            return (
              <div
                key={h}
                onMouseEnter={() => setHoveredCell({ weekday: wd, hour: h, count })}
                onMouseLeave={() => setHoveredCell(null)}
                style={{
                  width: CELL_W,
                  height: CELL_H,
                  background: count > 0 ? lerp(t) : 'rgba(77,130,192,0.03)',
                  border: isHovered ? '1px solid #4d82c080' : '1px solid rgba(77,130,192,0.08)',
                  borderRadius: 2,
                  cursor: count > 0 ? 'default' : 'default',
                  transition: 'border-color 0.1s',
                  position: 'relative',
                  flexShrink: 0,
                }}
                title={count > 0 ? `${day} ${String(h).padStart(2,'0')}h — ${count} événement${count > 1 ? 's' : ''}` : ''}
              />
            );
          })}
        </div>
      ))}

      {hoveredCell && hoveredCell.count > 0 && (
        <div style={{ marginTop: 6, fontFamily: 'monospace', fontSize: 10, color: '#7abfff' }}>
          {DAYS[hoveredCell.weekday]} {String(hoveredCell.hour).padStart(2, '0')}h00 UTC —{' '}
          <strong>{hoveredCell.count}</strong> événement{hoveredCell.count > 1 ? 's' : ''}
          {' '}({Math.round(hoveredCell.count / maxCount * 100)}% du pic)
        </div>
      )}

      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 8 }}>
        <span style={{ fontSize: 8, fontFamily: 'monospace', color: '#2a5a8a' }}>0</span>
        {[0.1, 0.25, 0.5, 0.75, 1.0].map(v => (
          <div key={v} style={{ width: 18, height: 10, borderRadius: 2, background: lerp(v) }} />
        ))}
        <span style={{ fontSize: 8, fontFamily: 'monospace', color: '#2a5a8a' }}>max ({maxCount})</span>
      </div>
    </div>
  );
}
