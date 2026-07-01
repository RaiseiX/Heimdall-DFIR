import { useState, useEffect } from 'react';
import { collectionAPI } from '../../../../utils/api';
import { useTimelineStore } from '../../store/useTimelineStore';

export default function RawTab({ record: r }) {
  const { caseId } = useTimelineStore();
  const [raw, setRaw]       = useState(r?.raw || null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied]  = useState(false);

  useEffect(() => {
    if (!r) return;
    if (r.raw) { setRaw(r.raw); return; }
    setLoading(true);
    collectionAPI.timelineRowRaw(caseId, r.id)
      .then(res => { setRaw(res.data.raw); r.raw = res.data.raw; })
      .catch(() => setRaw(null))
      .finally(() => setLoading(false));
  }, [r?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!r) return null;

  const json = JSON.stringify(raw || {}, null, 2);

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'flex-end', padding: '6px 10px', borderBottom: '1px solid var(--fl-card)', flexShrink: 0 }}>
        <button onClick={() => { navigator.clipboard.writeText(json); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
          style={{ background: 'rgba(77,130,192,0.12)', border: '1px solid rgba(77,130,192,0.3)', color: copied ? 'var(--fl-ok)' : 'var(--fl-accent)',
            padding: '3px 10px', fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', borderRadius: 4, cursor: 'pointer' }}>
          {copied ? 'Copied!' : 'Copy JSON'}
        </button>
      </div>
      <pre style={{ flex: 1, overflow: 'auto', margin: 0, padding: '10px 12px',
        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, lineHeight: 1.55,
        color: loading ? 'var(--fl-muted)' : '#c0cfe0', background: 'var(--fl-bg)', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
        {loading ? 'Loading raw data…' : json}
      </pre>
    </div>
  );
}
