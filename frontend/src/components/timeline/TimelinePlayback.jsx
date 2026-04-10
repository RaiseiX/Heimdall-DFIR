
import { useState, useEffect, useRef, useCallback } from 'react';

const SPEEDS = [
  { label: '0.5×', evtPerSec: 0.5 },
  { label: '1×',   evtPerSec: 1   },
  { label: '2×',   evtPerSec: 2   },
  { label: '5×',   evtPerSec: 5   },
  { label: '10×',  evtPerSec: 10  },
];

export default function TimelinePlayback({ records, onHighlight, onStop }) {
  const [playing, setPlaying]   = useState(false);
  const [cursor, setCursor]     = useState(0);
  const [speedIdx, setSpeedIdx] = useState(1);
  const intervalRef = useRef(null);

  const sorted = records ?? [];
  const total  = sorted.length;

  const stop = useCallback(() => {
    setPlaying(false);
    clearInterval(intervalRef.current);
    onStop?.();
  }, [onStop]);

  useEffect(() => {
    if (cursor >= total - 1 && playing) stop();
  }, [cursor, total, playing, stop]);

  useEffect(() => {
    if (!playing) return;
    clearInterval(intervalRef.current);
    const ms = 1000 / SPEEDS[speedIdx].evtPerSec;
    intervalRef.current = setInterval(() => {
      setCursor(c => {
        const next = c + 1;
        if (next >= total) return c;
        onHighlight?.(sorted[next], next);
        return next;
      });
    }, ms);
    return () => clearInterval(intervalRef.current);
  }, [playing, speedIdx, total]);

  function play() {
    if (cursor >= total - 1) setCursor(0);
    setPlaying(true);
    onHighlight?.(sorted[cursor], cursor);
  }

  function seek(pct) {
    const idx = Math.min(total - 1, Math.max(0, Math.floor(pct * total)));
    setCursor(idx);
    onHighlight?.(sorted[idx], idx);
  }

  const pct = total > 1 ? cursor / (total - 1) : 0;
  const current = sorted[cursor];

  return (
    <div style={{
      flexShrink: 0,
      padding: '6px 14px',
      borderTop: '1px solid #0d1f30',
      background: '#04080f',
      display: 'flex', alignItems: 'center', gap: 10,
    }}>
      
      <button
        onClick={() => playing ? stop() : play()}
        style={{
          padding: '3px 10px', borderRadius: 4, fontSize: 10, fontFamily: 'monospace',
          background: playing ? 'rgba(239,68,68,0.15)' : 'rgba(77,130,192,0.15)',
          color: playing ? '#ef4444' : '#4d82c0',
          border: `1px solid ${playing ? 'rgba(239,68,68,0.3)' : 'rgba(77,130,192,0.3)'}`,
          cursor: 'pointer', fontWeight: 700,
        }}
      >
        {playing ? '⏹ Stop' : '▶ Lecture'}
      </button>

      <div style={{ display: 'flex', gap: 2 }}>
        {SPEEDS.map((s, i) => (
          <button key={i} onClick={() => setSpeedIdx(i)}
            style={{
              padding: '2px 6px', borderRadius: 3, fontSize: 9, fontFamily: 'monospace',
              background: speedIdx === i ? 'rgba(77,130,192,0.2)' : 'transparent',
              color: speedIdx === i ? '#4d82c0' : '#2a5a8a',
              border: `1px solid ${speedIdx === i ? '#2a5a8a' : '#0d1f30'}`,
              cursor: 'pointer',
            }}
          >{s.label}</button>
        ))}
      </div>

      <div style={{ flex: 1, position: 'relative', height: 14, cursor: 'pointer' }}
        onClick={e => {
          const rect = e.currentTarget.getBoundingClientRect();
          seek((e.clientX - rect.left) / rect.width);
        }}
      >
        <div style={{ position: 'absolute', top: 5, left: 0, right: 0, height: 4, background: '#0d1f30', borderRadius: 2 }} />
        <div style={{ position: 'absolute', top: 5, left: 0, width: `${pct * 100}%`, height: 4, background: '#4d82c0', borderRadius: 2 }} />
        <div style={{
          position: 'absolute', top: 1, left: `calc(${pct * 100}% - 6px)`,
          width: 12, height: 12, borderRadius: '50%', background: '#4d82c0',
          border: '2px solid #060b14',
        }} />
      </div>

      <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#2a5a8a', flexShrink: 0 }}>
        {cursor + 1} / {total}
      </span>

      {current && (
        <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#7abfff', flexShrink: 0, maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {new Date(current.timestamp).toISOString().slice(0, 19).replace('T', ' ')} UTC
        </span>
      )}
    </div>
  );
}
