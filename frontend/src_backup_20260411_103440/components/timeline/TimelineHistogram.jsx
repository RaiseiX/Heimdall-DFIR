
import { useState, useMemo } from 'react';
import {
  BarChart, Bar, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer,
} from 'recharts';

const ARTIFACT_COLORS = {
  evtx:      '#4d82c0', prefetch:  '#22c55e', mft:       '#8b72d6',
  lnk:       '#d97c20', registry:  '#c96898', amcache:   '#c89d1d',
  appcompat: '#f59e0b', shellbags: '#06b6d4', jumplist:  '#8b5cf6',
  srum:      '#f43f5e', recycle:   '#84cc16', wxtcmd:    '#d946ef',
  bits:      '#64748b', sum:       '#0ea5e9', hayabusa:  '#da3633',

};
function ac(t) { return ARTIFACT_COLORS[t] || '#7d8590'; }

function bucketKey(ts, monthly) {
  const d = new Date(ts);
  if (monthly) return `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,'0')}`;
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,'0')}-${String(d.getUTCDate()).padStart(2,'0')}`;
}

function shortLabel(k) {

  const parts = k.split('-');
  const MONTHS = ['Jan','Fév','Mar','Avr','Mai','Jui','Jul','Aoû','Sep','Oct','Nov','Déc'];
  if (parts.length === 2) return `${MONTHS[+parts[1]-1]} ${parts[0]}`;
  return `${+parts[2]} ${MONTHS[+parts[1]-1]}`;
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  const total = payload.reduce((s, p) => s + (p.value || 0), 0);
  const zScore = payload[0]?.payload?._zscore;
  const isAnomaly = payload[0]?.payload?._anomaly;
  return (
    <div style={{
      background: '#07101f', border: `1px solid ${isAnomaly ? '#da363360' : '#2a3a50'}`, borderRadius: 6,
      padding: '8px 12px', fontFamily: 'monospace', fontSize: 11,
      boxShadow: '0 8px 24px rgba(0,0,0,0.6)',
    }}>
      <div style={{ color: '#8aa0bc', marginBottom: 6, fontWeight: 700 }}>{label}</div>
      {isAnomaly && (
        <div style={{ marginBottom: 6, color: '#da3633', fontSize: 10, fontWeight: 700 }}>
          ⚠ Activité anormale · Z-score: {zScore?.toFixed(1)}σ
        </div>
      )}
      {payload.map(p => (
        <div key={p.dataKey} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
          <span style={{ width: 8, height: 8, borderRadius: 2, background: p.fill, display: 'inline-block', flexShrink: 0 }} />
          <span style={{ color: '#5a7090' }}>{p.dataKey}</span>
          <span style={{ color: '#c0cce0', marginLeft: 'auto', paddingLeft: 12 }}>{p.value}</span>
        </div>
      ))}
      <div style={{ borderTop: '1px solid #1a2a3a', marginTop: 6, paddingTop: 4, color: '#4d82c0', display: 'flex', justifyContent: 'space-between' }}>
        <span>Total</span><span>{total}</span>
      </div>
    </div>
  );
};

export default function TimelineHistogram({ records, availTypes, compact = false, onBucketClick }) {
  const [collapsed, setCollapsed] = useState(false);

  const { data, types } = useMemo(() => {
    if (!records?.length) return { data: [], types: [] };
    const timestamps = records.map(r => r.timestamp ? new Date(r.timestamp).getTime() : null).filter(Boolean);
    if (!timestamps.length) return { data: [], types: [] };

    const minT = Math.min(...timestamps);
    const maxT = Math.max(...timestamps);
    const rangeMs = maxT - minT;
    const monthly = rangeMs > 25 * 24 * 3600 * 1000;

    const bucketMap = {};
    records.forEach(r => {
      if (!r.timestamp) return;
      const t = new Date(r.timestamp).getTime();
      if (isNaN(t)) return;
      const k = bucketKey(t, monthly);
      if (!bucketMap[k]) bucketMap[k] = { _key: k, label: shortLabel(k) };
      const at = r.artifact_type || 'unknown';
      bucketMap[k][at] = (bucketMap[k][at] || 0) + 1;
    });

    const data = Object.values(bucketMap).sort((a, b) => a._key.localeCompare(b._key));
    const types = availTypes?.length
      ? availTypes
      : [...new Set(records.map(r => r.artifact_type).filter(Boolean))];

    const totals = data.map(d => {
      const total = types.reduce((s, t) => s + (d[t] || 0), 0);
      return total;
    });
    const mean = totals.reduce((s, v) => s + v, 0) / (totals.length || 1);
    const variance = totals.reduce((s, v) => s + (v - mean) ** 2, 0) / (totals.length || 1);
    const stdDev = Math.sqrt(variance);
    const dataWithAnomaly = data.map((d, i) => ({
      ...d,
      _total: totals[i],
      _zscore: stdDev > 0 ? (totals[i] - mean) / stdDev : 0,
      _anomaly: stdDev > 0 && (totals[i] - mean) / stdDev > 2,
    }));

    return { data: dataWithAnomaly, types };
  }, [records, availTypes]);

  if (compact) {
    if (!data.length) return null;
    const handleClick = onBucketClick ? (barData) => {
      if (!barData?.activePayload?.[0]?.payload?._key) return;
      const key = barData.activePayload[0].payload._key;
      const parts = key.split('-');
      let start, end;
      if (parts.length === 2) {
        start = new Date(Date.UTC(+parts[0], +parts[1] - 1, 1)).toISOString();
        end   = new Date(Date.UTC(+parts[0], +parts[1], 0, 23, 59, 59)).toISOString();
      } else {
        start = new Date(Date.UTC(+parts[0], +parts[1] - 1, +parts[2])).toISOString();
        end   = new Date(Date.UTC(+parts[0], +parts[1] - 1, +parts[2], 23, 59, 59)).toISOString();
      }
      onBucketClick(start, end);
    } : undefined;

    return (
      <div style={{ marginBottom: 6, borderRadius: 6, overflow: 'hidden', border: '1px solid #1a2035', flexShrink: 0 }}
           title="Mini-map : distribution des événements dans le temps. Cliquez sur une barre pour filtrer.">
        <ResponsiveContainer width="100%" height={52}>
          <BarChart data={data} margin={{ top: 2, right: 0, left: 0, bottom: 0 }} barCategoryGap="8%"
                    onClick={handleClick} style={{ cursor: onBucketClick ? 'pointer' : 'default' }}>
            <XAxis dataKey="label" hide />
            <YAxis hide />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(77,130,192,0.06)' }} />
            {types.map((t, idx) => (
              <Bar key={t} dataKey={t} stackId="a" fill={ac(t)} maxBarSize={20}
                   radius={idx === types.length - 1 ? [1, 1, 0, 0] : [0, 0, 0, 0]}>
                {idx === types.length - 1 && data.map((entry, i) => (
                  <Cell key={`cell-${i}`}
                    fill={entry._anomaly ? '#da363390' : ac(t)}
                    stroke={entry._anomaly ? '#da3633' : 'none'}
                    strokeWidth={entry._anomaly ? 1 : 0}
                  />
                ))}
              </Bar>
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    );
  }

  return (
    <div style={{ marginBottom: 8, border: '1px solid #1a2035', borderRadius: 8, overflow: 'hidden' }}>
      
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '7px 14px', background: '#07101f',
        borderBottom: collapsed ? 'none' : '1px solid #1a2035',
      }}>
        <span style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 600, color: '#8aa0bc', letterSpacing: '0.03em' }}>
          Histogramme Chronologique Pliable
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          
          {!collapsed && types.length > 0 && (
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', maxHeight: 36, overflowY: 'auto', overflowX: 'hidden' }}>
              {types.map(t => (
                <span key={t} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, fontFamily: 'monospace', color: '#484f58', flexShrink: 0 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: ac(t), display: 'inline-block', flexShrink: 0 }} />
                  {t}
                </span>
              ))}
            </div>
          )}
          <button
            onClick={() => setCollapsed(v => !v)}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#3d5070', fontSize: 14, lineHeight: 1, padding: '2px 4px' }}
          >
            {collapsed ? '∨' : '∧'}
          </button>
        </div>
      </div>

      {!collapsed && (
        <div style={{ background: '#05080f', padding: '6px 0 4px' }}>
          {data.length > 0 ? (
            <div style={{ width: '100%', height: 'clamp(40px, 8vh, 120px)' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data} margin={{ top: 4, right: 14, left: -10, bottom: 0 }} barCategoryGap="12%">
                <XAxis
                  dataKey="label"
                  tick={{ fontSize: 9, fontFamily: 'monospace', fill: '#3d5070' }}
                  axisLine={{ stroke: '#1a2035' }}
                  tickLine={false}
                  interval="preserveStartEnd"
                />
                <YAxis
                  tick={{ fontSize: 9, fontFamily: 'monospace', fill: '#3d5070' }}
                  axisLine={false}
                  tickLine={false}
                  width={28}
                />
                <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(77,130,192,0.06)' }} />
                {types.map((t, idx) => (
                  <Bar
                    key={t}
                    dataKey={t}
                    stackId="a"
                    fill={ac(t)}
                    maxBarSize={30}
                    radius={idx === types.length - 1 ? [2, 2, 0, 0] : [0, 0, 0, 0]}
                  >
                    {idx === types.length - 1 && data.map((entry, i) => (
                      <Cell
                        key={`cell-${i}`}
                        fill={entry._anomaly ? '#da363390' : ac(t)}
                        stroke={entry._anomaly ? '#da3633' : 'none'}
                        strokeWidth={entry._anomaly ? 1 : 0}
                      />
                    ))}
                  </Bar>
                ))}
              </BarChart>
            </ResponsiveContainer>
            </div>
          ) : (
            <div style={{ padding: '22px 0', textAlign: 'center', fontFamily: 'monospace', fontSize: 11, color: '#2a3a50' }}>
              Chargez des données pour afficher l'histogramme
            </div>
          )}
        </div>
      )}
    </div>
  );
}
