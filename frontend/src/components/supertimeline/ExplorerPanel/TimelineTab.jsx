import { useRef, useEffect, useMemo } from 'react';
import { useTimelineStore } from '../store/useTimelineStore';

const BUCKET_COLORS = {
  critical: 'var(--fl-danger)',
  high:     'var(--fl-warn)',
  medium:   'var(--fl-warn)',
  low:      'var(--fl-ok)',
  none:     '#2E5090',
};

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };

export default function TimelineTab() {
  const { records, pageSize, setFilter, applyFilters } = useTimelineStore();
  const canvasRef = useRef(null);

  const { buckets, minTs, maxTs } = useMemo(() => {
    if (!records.length) return { buckets: [], minTs: 0, maxTs: 0 };
    const timestamps = records
      .map(r => new Date(r.timestamp).getTime())
      .filter(t => !isNaN(t));
    if (!timestamps.length) return { buckets: [], minTs: 0, maxTs: 0 };
    const minTs  = Math.min(...timestamps);
    const maxTs  = Math.max(...timestamps);
    const spanMs = maxTs - minTs || 1;
    const N      = Math.max(1, Math.min(48, Math.ceil(spanMs / (60 * 60 * 1000))));
    const bucketMs = spanMs / N;
    const buckets = Array.from({ length: N }, () => ({ count: 0, maxSev: 'none' }));
    records.forEach(r => {
      const t = new Date(r.timestamp).getTime();
      if (isNaN(t)) return;
      const idx = Math.min(N - 1, Math.floor((t - minTs) / bucketMs));
      buckets[idx].count++;
      const sev = r.detections?.[0]?.severity;
      if (sev && (SEV_RANK[sev] || 0) > (SEV_RANK[buckets[idx].maxSev] || 0)) {
        buckets[idx].maxSev = sev;
      }
    });
    return { buckets, minTs, maxTs };
  }, [records]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !buckets.length) return;
    const ctx = canvas.getContext('2d');
    const W   = canvas.width;
    const H   = canvas.height;
    ctx.clearRect(0, 0, W, H);
    const maxCount = Math.max(...buckets.map(b => b.count), 1);
    const logMax   = Math.log(maxCount + 1);
    const bw       = W / buckets.length;
    buckets.forEach((b, i) => {
      if (!b.count) return;
      const h     = Math.round((Math.log(b.count + 1) / logMax) * (H - 4));
      const color = BUCKET_COLORS[b.maxSev] || BUCKET_COLORS.none;
      ctx.fillStyle = color + 'cc';
      ctx.fillRect(Math.floor(i * bw) + 1, H - h, Math.max(1, Math.floor(bw) - 1), h);
    });
  }, [buckets]);

  // Set canvas resolution to match rendered width for crisp rendering
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const w = canvas.parentElement?.clientWidth || 190;
    if (canvas.width !== w) {
      canvas.width = w;
    }
  }, []);

  function handleCanvasClick(e) {
    if (!buckets.length || !minTs || !maxTs) return;
    const canvas  = canvasRef.current;
    const rect    = canvas.getBoundingClientRect();
    const x       = e.clientX - rect.left;
    const idx     = Math.floor((x / rect.width) * buckets.length);
    const b       = buckets[Math.min(idx, buckets.length - 1)];
    if (!b?.count) return;
    const spanMs   = maxTs - minTs || 1;
    const bucketMs = spanMs / buckets.length;
    const start    = new Date(minTs + idx * bucketMs);
    const end      = new Date(minTs + (idx + 1) * bucketMs);
    const pad      = d => d.toISOString().slice(0, 16);
    setFilter('startTime', pad(start));
    setFilter('endTime',   pad(end));
    applyFilters();
  }

  if (!records.length) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
        color: 'var(--fl-subtle)', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: 16, textAlign: 'center' }}>
        No events loaded
      </div>
    );
  }

  const startLabel = minTs ? new Date(minTs).toISOString().slice(0, 10) : '';
  const endLabel   = maxTs ? new Date(maxTs).toISOString().slice(0, 10) : '';

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: '8px 10px', gap: 6 }}>
      <div style={{ fontSize: 8, color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 700 }}>
        Event density
      </div>
      <canvas
        ref={canvasRef}
        height={60}
        onClick={handleCanvasClick}
        style={{ width: '100%', height: 60, cursor: 'crosshair', borderRadius: 4,
          background: 'var(--fl-bg)', border: '1px solid var(--fl-raised)', display: 'block' }}
      />
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 8, color: 'var(--fl-subtle)' }}>
        <span>{startLabel}</span><span>{endLabel}</span>
      </div>
      <div style={{ fontSize: 8, color: 'var(--fl-raised)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', lineHeight: 1.4 }}>
        Showing distribution of loaded page ({pageSize} events).
        Click a bar to jump to that hour.
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 2 }}>
        {Object.entries(BUCKET_COLORS).map(([sev, col]) => (
          <span key={sev} style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: 8, color: 'var(--fl-muted)' }}>
            <span style={{ width: 6, height: 6, borderRadius: 1, background: col, display: 'inline-block' }} />
            {sev}
          </span>
        ))}
      </div>
    </div>
  );
}
