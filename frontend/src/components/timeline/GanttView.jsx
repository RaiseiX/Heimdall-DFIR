
import { useRef, useState, useEffect, useMemo, useCallback } from 'react';
import { artifactColor } from '../../constants/artifactColors';

const LANE_H  = 32;
const LABEL_W = 92;
const TICK_H  = 24;
const MIN_ZOOM = 0.4;
const MAX_ZOOM = 200;

function parseTs(ts) {
  if (!ts) return NaN;
  const s = String(ts).trim().replace(' ', 'T');

  if (s.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(s)) return new Date(s).getTime();

  return new Date(s + 'Z').getTime();
}

function fmtLabel(ts, zoom) {
  const d = new Date(ts);
  if (zoom > 20) {
    const hh = String(d.getUTCHours()).padStart(2, '0');
    const mm = String(d.getUTCMinutes()).padStart(2, '0');
    const ss = String(d.getUTCSeconds()).padStart(2, '0');
    return `${hh}:${mm}:${ss}`;
  }
  return `${d.getUTCMonth()+1}/${d.getUTCDate()} ${String(d.getUTCHours()).padStart(2,'0')}h`;
}

export default function GanttView({ records, onSelectRecord }) {
  const wrapRef    = useRef(null);
  const axisRef    = useRef(null);
  const lanesRef   = useRef(null);
  const [dim, setDim]     = useState({ w: 800, h: 400 });
  const [zoom, setZoom]   = useState(1);
  const [pan, setPan]     = useState(0);
  const [dragging, setDragging] = useState(false);
  const dragStartX   = useRef(0);
  const dragStartPan = useRef(0);
  const [hovered, setHovered] = useState(null);

  const groups = useMemo(() => {
    const map = new Map();
    for (const r of (records || [])) {
      const t = r.artifact_type || 'unknown';
      if (!map.has(t)) map.set(t, []);
      map.get(t).push(r);
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [records]);

  const lanes = groups.length;

  const { minTs, maxTs } = useMemo(() => {
    let min = Infinity, max = -Infinity;
    for (const r of (records || [])) {
      const t = parseTs(r.timestamp);
      if (isNaN(t)) continue;
      if (t < min) min = t;
      if (t > max) max = t;
    }
    if (min === Infinity) return { minTs: 0, maxTs: 1 };
    const pad = Math.max((max - min) * 0.02, 60000);
    return { minTs: min - pad, maxTs: max + pad };
  }, [records]);

  const range = maxTs - minTs;

  useEffect(() => {
    if (!wrapRef.current) return;
    const ob = new ResizeObserver(([e]) => {
      setDim({ w: e.contentRect.width || 800, h: e.contentRect.height || 400 });
    });
    ob.observe(wrapRef.current);
    return () => ob.disconnect();
  }, []);

  const availW = Math.max(1, dim.w - LABEL_W);

  const clampPan = useCallback((p, z) => {
    const plotW = availW * z;
    const minP = -(plotW - 40);
    const maxP = availW - 40;
    return Math.min(maxP, Math.max(minP, p));
  }, [availW]);

  const tsToX = useCallback((ts) => {
    const frac = (ts - minTs) / range;
    return LABEL_W + (frac * availW * zoom) + pan;
  }, [minTs, range, availW, zoom, pan]);

  const ticks = useMemo(() => {
    const pixelRange = availW * zoom;
    const secRange   = range / 1000;
    const candidates = [1, 5, 15, 30, 60, 300, 900, 1800, 3600, 7200, 21600, 86400];
    const idealPx  = pixelRange / 8;
    const secPerPx = secRange / Math.max(1, pixelRange);
    const idealSec = idealPx * secPerPx;
    const interval = candidates.find(c => c >= idealSec) || candidates[candidates.length - 1];
    const intervalMs = interval * 1000;
    const first = Math.ceil(minTs / intervalMs) * intervalMs;
    const result = [];
    for (let t = first; t <= maxTs; t += intervalMs) result.push(t);
    return result;
  }, [minTs, maxTs, range, availW, zoom]);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    function handleWheel(e) {
      e.preventDefault();
      const factor = e.deltaY < 0 ? 1.2 : 1 / 1.2;
      setZoom(z => {
        const newZ = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, z * factor));
        const rect  = el.getBoundingClientRect();
        const mouseX = e.clientX - rect.left - LABEL_W;
        setPan(p => clampPan(mouseX - (mouseX - p) * (newZ / z), newZ));
        return newZ;
      });
    }
    el.addEventListener('wheel', handleWheel, { passive: false });
    return () => el.removeEventListener('wheel', handleWheel);
  }, [availW, clampPan]);

  const handleMouseDown = (e) => {
    if (e.button !== 0) return;
    setDragging(true);
    dragStartX.current   = e.clientX;
    dragStartPan.current = pan;
  };
  const handleMouseMove = (e) => {
    if (!dragging) return;
    setPan(clampPan(dragStartPan.current + (e.clientX - dragStartX.current), zoom));
  };
  const handleMouseUp = () => setDragging(false);

  const handleReset = () => { setZoom(1); setPan(0); };

  if (!records?.length) return (
    <div style={{ padding: 20, textAlign: 'center', fontFamily: 'monospace', fontSize: 11, color: '#2a5a8a' }}>
      Aucune donnée — chargez des événements pour afficher le Gantt
    </div>
  );

  const lanesH = lanes * LANE_H + 8;

  return (
    <div ref={wrapRef} style={{ width: '100%', height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#060b14' }}>

      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '3px 10px 3px 10px', flexShrink: 0,
        fontFamily: 'monospace', fontSize: 9, color: '#2a5a8a',
        textTransform: 'uppercase', letterSpacing: '0.1em',
        borderBottom: '1px solid #0d1f30',
      }}>
        <span>Vue Gantt · {lanes} pistes · {records.length} événements · molette : zoom · glisser : défilement</span>
        <button
          onClick={handleReset}
          style={{
            background: 'none', border: '1px solid #1a3a5c', borderRadius: 3,
            color: '#2a5a8a', cursor: 'pointer', fontSize: 9, padding: '1px 8px',
            fontFamily: 'monospace', textTransform: 'uppercase',
          }}
        >Reset</button>
      </div>

      <svg
        ref={axisRef}
        width={dim.w}
        height={TICK_H + 4}
        style={{ flexShrink: 0, display: 'block' }}
      >
        <rect x={0} y={0} width={dim.w} height={TICK_H + 4} fill="#060b14" />
        {ticks.map((t, i) => {
          const x = tsToX(t);
          if (x < LABEL_W || x > dim.w) return null;
          return (
            <g key={i}>
              <line x1={x} y1={TICK_H - 6} x2={x} y2={TICK_H + 4} stroke="#0d1f30" strokeWidth={1} />
              <text x={x} y={TICK_H - 8} textAnchor="middle" fontSize={8} fill="#2a5a8a" fontFamily="monospace">
                {fmtLabel(t, zoom)}
              </text>
            </g>
          );
        })}
        
        <line x1={LABEL_W} y1={TICK_H} x2={dim.w} y2={TICK_H} stroke="#1a3a5c" strokeWidth={1} />
        
        {zoom !== 1 && (
          <text x={dim.w - 6} y={TICK_H - 8} textAnchor="end" fontSize={8} fill="#1a4a70" fontFamily="monospace">
            ×{zoom.toFixed(1)}
          </text>
        )}
      </svg>

      <div
        ref={lanesRef}
        style={{
          flex: 1,
          overflowY: 'auto',
          overflowX: 'hidden',
          cursor: dragging ? 'grabbing' : 'grab',
          scrollbarWidth: 'thin',
          scrollbarColor: '#1a3a5c #060b14',
        }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        <svg
          width={dim.w}
          height={lanesH}
          style={{ display: 'block' }}
        >
          <defs>
            <clipPath id="gantt-lane-clip">
              <rect x={LABEL_W} y={0} width={Math.max(0, dim.w - LABEL_W)} height={lanesH} />
            </clipPath>
          </defs>

          <g clipPath="url(#gantt-lane-clip)">
            {ticks.map((t, i) => {
              const x = tsToX(t);
              if (x < LABEL_W || x > dim.w) return null;
              return <line key={i} x1={x} y1={0} x2={x} y2={lanesH} stroke="#0d1f30" strokeWidth={1} />;
            })}
          </g>

          {groups.map(([type, evts], laneIdx) => {
            const y0  = laneIdx * LANE_H;
            const cy  = y0 + LANE_H / 2;
            const col = artifactColor(type);

            return (
              <g key={type}>
                
                <rect x={0} y={y0} width={dim.w} height={LANE_H}
                  fill={laneIdx % 2 === 0 ? '#070d1a' : '#060b14'} />
                
                <line x1={0} y1={y0 + LANE_H} x2={dim.w} y2={y0 + LANE_H} stroke="#0d1f30" strokeWidth={1} />
                
                <text x={LABEL_W - 6} y={cy + 3} textAnchor="end" fontSize={9}
                  fontFamily="monospace" fontWeight="700" style={{ fill: col, pointerEvents: 'none' }}>
                  {type}
                </text>
                <text x={LABEL_W - 6} y={cy + 13} textAnchor="end" fontSize={7} fill="#2a5a8a"
                  fontFamily="monospace" style={{ pointerEvents: 'none' }}>
                  {evts.length}
                </text>

                <g clipPath="url(#gantt-lane-clip)">
                  {evts.map((r, i) => {
                    const x = tsToX(parseTs(r.timestamp));
                    if (x < LABEL_W - 2 || x > dim.w + 2) return null;
                    const isHov = hovered === r;
                    return (
                      <g key={i}
                        style={{ cursor: 'pointer' }}
                        onClick={() => onSelectRecord?.(r)}
                        onMouseEnter={() => setHovered(r)}
                        onMouseLeave={() => setHovered(null)}
                      >
                        <rect
                          x={x - (isHov ? 3 : 1)}
                          y={cy - LANE_H * 0.35}
                          width={isHov ? 5 : 2}
                          height={LANE_H * 0.7}
                          rx={1}
                          opacity={isHov ? 1 : 0.65}
                          style={{ fill: col }}
                        />
                        
                        <rect x={x - 5} y={y0} width={10} height={LANE_H} fill="transparent" />
                      </g>
                    );
                  })}
                </g>
              </g>
            );
          })}

          {hovered && (() => {
            const x   = tsToX(parseTs(hovered.timestamp));
            const laneIdx = groups.findIndex(([type]) => type === hovered.artifact_type);
            const laneY   = laneIdx * LANE_H;
            const ty  = laneY <= 42 ? laneY + LANE_H + 4 : laneY - 42;
            const xc  = Math.min(Math.max(x, LABEL_W + 5), dim.w - 205);
            const col = artifactColor(hovered.artifact_type);
            const desc = (hovered.description || '').substring(0, 60);
            return (
              <g style={{ pointerEvents: 'none' }}>
                <rect x={xc} y={ty} width={200} height={38} rx={4} fill="#0d1525" stroke="#1a3a5c" strokeWidth={1} />
                <text x={xc + 6} y={ty + 13} fontSize={9} fontFamily="monospace" fontWeight="700" style={{ fill: col }}>
                  [{hovered.artifact_type}]
                </text>
                <text x={xc + 6} y={ty + 23} fontSize={8} fill="#7abfff" fontFamily="monospace">
                  {new Date(parseTs(hovered.timestamp)).toISOString().slice(0, 19).replace('T', ' ')} UTC
                </text>
                <text x={xc + 6} y={ty + 33} fontSize={8} fill="#6a8090" fontFamily="monospace">
                  {desc}{desc.length < (hovered.description || '').length ? '…' : ''}
                </text>
              </g>
            );
          })()}
        </svg>
      </div>
    </div>
  );
}
