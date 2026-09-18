import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { collectionAPI } from '../../utils/api';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
const HOURS = Array.from({ length: 24 }, (_, i) => i);
const CELL_W = 22;
const CELL_H = 18;
const LABEL_W = 40;

const ETIQ = { fontFamily: MONO, fontSize: 9, color: 'var(--fl-dim)' };
const NOTE = { fontFamily: MONO, fontSize: 10, color: 'var(--fl-muted)', marginTop: 6 };
const TITRE = { ...ETIQ, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 };
const REF = { ...ETIQ, marginBottom: 8 };
const CADRE = { padding: '12px 16px', userSelect: 'none' };
const RANG = { display: 'flex', alignItems: 'center', marginBottom: 2 };
const BANDE = { display: 'flex', alignItems: 'center', gap: 6, marginTop: 8 };
const ECHELLE = { width: 18, height: 10, borderRadius: 2 };

function densite(t) {
  const a = Math.max(0.06, t);
  return `color-mix(in srgb, var(--fl-accent) ${Math.round(a * 100)}%, transparent)`;
}

export default function TimelineHeatmap({ caseId, availTypes, startTime, endTime }) {
  const { t, i18n } = useTranslation();
  const [matrix, setMatrix] = useState(null);
  const [maxCount, setMaxCount] = useState(1);
  const [meta, setMeta] = useState(null);
  const [loading, setLoading] = useState(false);
  const [survol, setSurvol] = useState(null);

  const jours = Array.from({ length: 7 }, (_, i) =>
    new Intl.DateTimeFormat(i18n.language, { weekday: 'short', timeZone: 'UTC' })
      .format(new Date(Date.UTC(2026, 2, 1 + i))));

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
        setMeta({ reference: r.data.reference || 'UTC', sansFuseau: r.data.hosts_without_offset || 0 });
      })
      .catch(() => { setMatrix(null); setMeta(null); })
      .finally(() => setLoading(false));
  }, [caseId, availTypes?.join(','), startTime, endTime]);

  if (loading) return <div style={{ ...ETIQ, padding: 20, textAlign: 'center' }}>{t('timeline.heatmap_title')}…</div>;
  if (!matrix) return null;
  if (maxCount === 0) return <div style={{ ...ETIQ, padding: 20 }}>{t('timeline.heatmap_empty')}</div>;

  return (
    <div style={CADRE}>
      <div style={TITRE}>
        {t('timeline.heatmap_title')}
      </div>
      <div style={REF}>
        {t('timeline.heatmap_reference', { ref: meta?.reference || 'UTC' })}
      </div>
      {meta?.sansFuseau > 0 && (
        <div role="alert" style={{ ...ETIQ, color: 'var(--fl-warn)', marginBottom: 8, whiteSpace: 'normal', maxWidth: CELL_W * 24 }}>
          {t('timeline.heatmap_warning', { n: meta.sansFuseau })}
        </div>
      )}

      <div style={{ display: 'flex', marginLeft: LABEL_W, marginBottom: 2 }}>
        {HOURS.filter(h => h % 3 === 0).map(h => (
          <div key={h} style={{ ...ETIQ, width: CELL_W * 3, fontSize: 8, textAlign: 'center' }}>
            {String(h).padStart(2, '0')}h
          </div>
        ))}
      </div>

      {jours.map((jour, wd) => (
        <div key={wd} style={RANG}>
          <div style={{ ...ETIQ, width: LABEL_W, flexShrink: 0 }}>{jour}</div>
          {HOURS.map(h => {
            const n = matrix[wd][h];
            const intensite = n > 0 ? Math.max(0.08, n / maxCount) : 0;
            const vise = survol?.weekday === wd && survol?.hour === h;
            return (
              <div
                key={h}
                onMouseEnter={() => setSurvol({ weekday: wd, hour: h, count: n })}
                onMouseLeave={() => setSurvol(null)}
                style={{
                  width: CELL_W, height: CELL_H, flexShrink: 0, borderRadius: 2,
                  background: n > 0 ? densite(intensite) : 'transparent',
                  border: `1px solid ${vise
                    ? 'color-mix(in srgb, var(--fl-accent) 50%, transparent)'
                    : 'var(--fl-border-soft, var(--fl-border))'}`,
                  transition: 'border-color 0.1s',
                }}
                title={n > 0 ? `${jour} ${String(h).padStart(2, '0')}h — ${n}` : ''}
              />
            );
          })}
        </div>
      ))}

      {survol && survol.count > 0 && (
        <div style={NOTE}>
          {jours[survol.weekday]} {String(survol.hour).padStart(2, '0')}h00 {meta?.reference || 'UTC'} —{' '}
          <strong>{survol.count}</strong> ({Math.round(survol.count / maxCount * 100)}%)
        </div>
      )}

      <div style={BANDE}>
        <span style={{ ...ETIQ, fontSize: 8 }}>0</span>
        {[0.1, 0.25, 0.5, 0.75, 1.0].map(v => (
          <div key={v} style={{ ...ECHELLE, background: densite(v) }} />
        ))}
        <span style={{ ...ETIQ, fontSize: 8 }}>{maxCount}</span>
      </div>
    </div>
  );
}
