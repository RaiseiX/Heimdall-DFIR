
import { useState, useRef, useEffect, useCallback } from 'react';
import { collectionAPI } from '../../utils/api';

export const VERDICTS = [
  { id: 'malicious',  label: 'Malicious',  color: '#ef4444', bg: 'rgba(239,68,68,0.12)',  border: 'rgba(239,68,68,0.3)'  },
  { id: 'suspicious', label: 'Suspicious', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.3)' },
  { id: 'benign',     label: 'Benign',     color: '#22c55e', bg: 'rgba(34,197,94,0.12)',  border: 'rgba(34,197,94,0.3)'  },
  { id: 'unknown',    label: 'Unknown',    color: '#6b7280', bg: 'rgba(107,114,128,0.1)', border: 'rgba(107,114,128,0.25)' },
];

function getVerdictStyle(id) {
  return VERDICTS.find(v => v.id === id) || VERDICTS[3];
}

export function eventRef(r) {
  return `${r.timestamp || ''}|${r.artifact_type || ''}|${r.source || ''}`.substring(0, 200);
}

export default function VerdictBadge({ record, caseId, verdictMap, onVerdictChange }) {
  const ref = eventRef(record);
  const current = verdictMap?.get(ref) ?? null;
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const popRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    function h(e) { if (popRef.current && !popRef.current.contains(e.target)) setOpen(false); }
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [open]);

  const setVerdict = useCallback(async (verdictId) => {
    if (!caseId) return;
    setSaving(true);
    try {
      if (verdictId === null) {
        await collectionAPI.deleteVerdict(caseId, ref);
        onVerdictChange?.(ref, null);
      } else {
        await collectionAPI.setVerdict(caseId, { event_ref: ref, verdict: verdictId });
        onVerdictChange?.(ref, verdictId);
      }
    } catch  } finally {
      setSaving(false);
      setOpen(false);
    }
  }, [caseId, ref, onVerdictChange]);

  const style = current ? getVerdictStyle(current) : null;

  return (
    <div style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}>
      <button
        onClick={e => { e.stopPropagation(); setOpen(v => !v); }}
        title={current ? `Verdict: ${current}` : 'Définir un verdict'}
        style={{
          display: 'inline-flex', alignItems: 'center',
          padding: current ? '1px 6px' : '1px 4px',
          borderRadius: 3, fontSize: 9, fontFamily: 'monospace',
          cursor: 'pointer', border: 'none', transition: 'all 0.1s',
          fontWeight: current ? 700 : 400,
          background: current ? style.bg : 'transparent',
          color: current ? style.color : '#2a5a8a',
          borderColor: current ? style.border : 'transparent',
          borderStyle: 'solid', borderWidth: '1px',
          opacity: saving ? 0.5 : 1,
        }}
      >
        {current ? (
          <span style={{ whiteSpace: 'nowrap' }}>
            {current === 'malicious'  ? '🔴' :
             current === 'suspicious' ? '🟠' :
             current === 'benign'     ? '🟢' : '⚪'} {style.label}
          </span>
        ) : (
          <span style={{ fontSize: 8 }}>▷</span>
        )}
      </button>

      {open && (
        <div
          ref={popRef}
          onClick={e => e.stopPropagation()}
          style={{
            position: 'absolute', bottom: '100%', left: 0, zIndex: 9000, marginBottom: 4,
            background: '#0d1525', border: '1px solid #1a3a5c', borderRadius: 6,
            padding: '6px 8px', boxShadow: '0 4px 16px rgba(0,0,0,0.5)',
            minWidth: 140,
          }}
        >
          <div style={{ fontFamily: 'monospace', fontSize: 8, color: '#2a5a8a', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>
            Verdict
          </div>
          {VERDICTS.map(v => (
            <button key={v.id} onClick={() => setVerdict(v.id)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6, width: '100%',
                padding: '4px 6px', borderRadius: 4, marginBottom: 2,
                background: current === v.id ? v.bg : 'transparent',
                color: v.color, border: `1px solid ${current === v.id ? v.border : 'transparent'}`,
                fontSize: 10, fontFamily: 'monospace', cursor: 'pointer',
                fontWeight: current === v.id ? 700 : 400,
              }}
            >
              {v.id === 'malicious'  ? '🔴' :
               v.id === 'suspicious' ? '🟠' :
               v.id === 'benign'     ? '🟢' : '⚪'} {v.label}
            </button>
          ))}
          {current && (
            <button onClick={() => setVerdict(null)}
              style={{
                display: 'flex', alignItems: 'center', gap: 4, width: '100%',
                padding: '3px 6px', borderRadius: 4, marginTop: 2,
                background: 'transparent', color: '#3a6a9a', border: 'none',
                fontSize: 9, fontFamily: 'monospace', cursor: 'pointer',
              }}>
              ✕ Effacer
            </button>
          )}
        </div>
      )}
    </div>
  );
}
