import { useRef, useEffect, useMemo, useState, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useTimelineStore } from '../store/useTimelineStore';

const SEV_TOKENS = {
  critical: '--fl-danger',
  high:     '--fl-warn',
  medium:   '--fl-warn',
  low:      '--fl-ok',
  none:     '--fl-purple',
};

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };
const BAR_ALPHA = 0.8;
const DIM_ALPHA = 0.28;

const MICRO = { fontSize: 8, color: 'var(--fl-muted)' };

function resolveTokens() {
  const cs = getComputedStyle(document.documentElement);
  const out = {};
  for (const [sev, token] of Object.entries(SEV_TOKENS)) {
    out[sev] = (cs.getPropertyValue(token) || '').trim() || '#6b8ccf';
  }
  return out;
}

export default function TimelineTab() {
  const { t, i18n } = useTranslation();
  const { records, pageSize, setFilter, applyFilters } = useTimelineStore();
  const canvasRef = useRef(null);

  const [brush, setBrush] = useState(null);
  const dragRef = useRef(null);

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

  const bucketMs = buckets.length ? ((maxTs - minTs) || 1) / buckets.length : 0;
  const range = brush
    ? { lo: Math.min(brush.a, brush.b), hi: Math.max(brush.a, brush.b) }
    : null;

  const selectedRows = useMemo(() => {
    if (!range) return 0;
    let n = 0;
    for (let i = range.lo; i <= range.hi; i++) n += buckets[i]?.count || 0;
    return n;
  }, [range, buckets]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !buckets.length) return;
    const ctx = canvas.getContext('2d');
    const W = canvas.width;
    const H = canvas.height;
    ctx.clearRect(0, 0, W, H);
    const colors   = resolveTokens();
    const maxCount = Math.max(...buckets.map(b => b.count), 1);
    const logMax   = Math.log(maxCount + 1);
    const bw       = W / buckets.length;

    buckets.forEach((b, i) => {
      if (!b.count) return;
      const h = Math.round((Math.log(b.count + 1) / logMax) * (H - 4));
      ctx.globalAlpha = !range || (i >= range.lo && i <= range.hi) ? BAR_ALPHA : DIM_ALPHA;
      ctx.fillStyle = colors[b.maxSev] || colors.none;
      ctx.fillRect(Math.floor(i * bw) + 1, H - h, Math.max(1, Math.floor(bw) - 1), h);
    });
    ctx.globalAlpha = 1;

    if (range) {
      const x0 = Math.floor(range.lo * bw);
      const x1 = Math.ceil((range.hi + 1) * bw);
      const accent = (getComputedStyle(document.documentElement)
        .getPropertyValue('--fl-accent') || '#8b7fff').trim();
      ctx.fillStyle = accent;
      ctx.globalAlpha = 0.09;
      ctx.fillRect(x0, 0, x1 - x0, H);
      ctx.globalAlpha = 1;
      ctx.fillRect(x0, 0, 1, H);
      ctx.fillRect(x1 - 1, 0, 1, H);
    }
  }, [buckets, range]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const w = canvas.parentElement?.clientWidth || 190;
    if (canvas.width !== w) canvas.width = w;
  }, []);

  const idxAt = useCallback(e => {
    const canvas = canvasRef.current;
    if (!canvas || !buckets.length) return null;
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    return Math.max(0, Math.min(buckets.length - 1, Math.floor((x / rect.width) * buckets.length)));
  }, [buckets.length]);

  function applyRange(lo, hi) {
    if (!buckets.length || !minTs) return;
    const start = new Date(minTs + lo * bucketMs);
    const end   = new Date(minTs + (hi + 1) * bucketMs);
    const pad   = d => d.toISOString().slice(0, 16);
    setFilter('startTime', pad(start));
    setFilter('endTime',   pad(end));
    applyFilters();
  }

  function release() {
    setBrush(null);
    setFilter('startTime', '');
    setFilter('endTime',   '');
    applyFilters();
  }

  function onMouseDown(e) {
    const i = idxAt(e);
    if (i == null) return;
    dragRef.current = { from: i, moved: false };
    setBrush({ a: i, b: i });
  }
  function onMouseMove(e) {
    if (!dragRef.current) return;
    const i = idxAt(e);
    if (i == null) return;
    if (i !== dragRef.current.from) dragRef.current.moved = true;
    setBrush({ a: dragRef.current.from, b: i });
  }
  function onMouseUp(e) {
    const d = dragRef.current;
    dragRef.current = null;
    if (!d) return;
    const i = idxAt(e) ?? d.from;
    const lo = Math.min(d.from, i), hi = Math.max(d.from, i);
    if (!buckets.slice(lo, hi + 1).some(b => b.count)) { setBrush(null); return; }
    applyRange(lo, hi);
  }

  function onKeyDown(e) {
    if (!buckets.length) return;
    const last = buckets.length - 1;
    const cur = brush || { a: 0, b: 0 };
    const step = e.key === 'ArrowLeft' ? -1 : e.key === 'ArrowRight' ? 1 : 0;
    if (step !== 0) {
      e.preventDefault();
      if (e.shiftKey) setBrush({ a: cur.a, b: Math.max(0, Math.min(last, cur.b + step)) });
      else {
        const a = Math.max(0, Math.min(last, cur.a + step));
        setBrush({ a, b: a });
      }
      return;
    }
    if (e.key === 'Enter' && range) { e.preventDefault(); applyRange(range.lo, range.hi); }
    if (e.key === 'Escape' && brush) { e.preventDefault(); release(); }
  }

  if (!records.length) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
        color: 'var(--fl-subtle)', ...MICRO, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: 16, textAlign: 'center' }}>
        {t('timeline.hist_empty')}
      </div>
    );
  }

  const fmtBound = ms => new Date(ms).toISOString().slice(0, 16).replace('T', ' ');
  const startLabel = minTs ? new Date(minTs).toISOString().slice(0, 10) : '';
  const endLabel   = maxTs ? new Date(maxTs).toISOString().slice(0, 10) : '';

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: '8px 10px', gap: 6 }}>
      <div style={{ ...MICRO, textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 700 }}>
        {t('timeline.hist_title')}
      </div>
      <canvas
        ref={canvasRef}
        height={60}
        tabIndex={0}
        role="slider"
        aria-label={t('timeline.hist_title')}
        aria-valuetext={range ? `${fmtBound(minTs + range.lo * bucketMs)} — ${fmtBound(minTs + (range.hi + 1) * bucketMs)}` : ''}
        onMouseDown={onMouseDown}
        onMouseMove={onMouseMove}
        onMouseUp={onMouseUp}
        onMouseLeave={() => { dragRef.current = null; }}
        onKeyDown={onKeyDown}
        style={{ width: '100%', height: 60, cursor: 'crosshair', borderRadius: 4,
          background: 'var(--fl-bg)', border: '1px solid var(--fl-raised)', display: 'block' }}
      />
      <div style={{ display: 'flex', justifyContent: 'space-between', ...MICRO }}>
        <span>{startLabel}</span><span>{endLabel}</span>
      </div>

      {range ? (
        <div style={{ ...MICRO, color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', lineHeight: 1.5 }}>
          <span style={{ color: 'var(--fl-accent)', fontWeight: 700 }}>
            {fmtBound(minTs + range.lo * bucketMs)} &rarr; {fmtBound(minTs + (range.hi + 1) * bucketMs)}
          </span>
          {' · '}
          {t('timeline.hist_rows', { count: selectedRows, formatted: selectedRows.toLocaleString(i18n.language) })}
          {' · '}
          <button onClick={release} style={{ background: 'none', border: 'none', padding: 0,
            color: 'var(--fl-muted)', cursor: 'pointer', font: 'inherit', textDecoration: 'underline' }}>
            {t('timeline.hist_release')}
          </button>
        </div>
      ) : (
        <div style={{ ...MICRO, color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', lineHeight: 1.4 }}>
          {t('timeline.hist_help', { count: pageSize, formatted: pageSize.toLocaleString(i18n.language) })}
        </div>
      )}

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 2 }}>
        {Object.keys(SEV_TOKENS).map(sev => (
          <span key={sev} style={{ display: 'flex', alignItems: 'center', gap: 3, ...MICRO }}>
            <span style={{ width: 6, height: 6, borderRadius: 1, background: `var(${SEV_TOKENS[sev]})`, display: 'inline-block' }} />
            {sev === 'none' ? t('timeline.sev_none') : t(`detections.severity.${sev}`)}
          </span>
        ))}
      </div>
    </div>
  );
}
