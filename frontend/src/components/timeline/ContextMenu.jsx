
import { useState, useEffect, useRef } from 'react';
import { iocsAPI } from '../../utils/api';

export default function ContextMenu({ record, pos, onClose, onFollowProcess, onFilter }) {
  const ref = useRef(null);
  const [enrichResult, setEnrichResult] = useState(null);
  const [enrichLoading, setEnrichLoading] = useState(false);

  useEffect(() => {
    function h(e) { if (ref.current && !ref.current.contains(e.target)) onClose(); }
    document.addEventListener('mousedown', h);
    document.addEventListener('contextmenu', h);
    return () => { document.removeEventListener('mousedown', h); document.removeEventListener('contextmenu', h); };
  }, [onClose]);

  const text = `${record?.description || ''} ${record?.source || ''}`;
  const ipMatch  = text.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
  const ip = ipMatch?.[1];

  function quickEnrich() {
    if (!ip) return;
    setEnrichLoading(true);
    iocsAPI.quickEnrich(ip, 'ip')
      .then(r => setEnrichResult(r.data?.enrichment || null))
      .catch(() => setEnrichResult(null))
      .finally(() => setEnrichLoading(false));
  }

  const hasProcess = record?.process_name || record?.raw?.ProcessName || record?.raw?.process_name;
  const processName = hasProcess;

  return (
    <div
      ref={ref}
      style={{
        position: 'fixed',
        top: pos.y, left: pos.x,
        zIndex: 9999,
        background: '#0a1520',
        border: '1px solid #1a3a5c',
        borderRadius: 7,
        boxShadow: '0 8px 32px rgba(0,0,0,0.6)',
        minWidth: 200,
        overflow: 'hidden',
        userSelect: 'none',
      }}
      onContextMenu={e => e.preventDefault()}
    >
      
      <div style={{ padding: '7px 12px', borderBottom: '1px solid #0d1f30', background: '#06111f' }}>
        <div style={{ fontFamily: 'monospace', fontSize: 9, color: '#3a6a9a', textTransform: 'uppercase', letterSpacing: '0.07em' }}>
          {record?.artifact_type || '?'}
        </div>
        <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#7abfff', marginTop: 1,
          maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {record?.description?.substring(0, 60) || '—'}
        </div>
      </div>

      <div style={{ padding: '4px 0' }}>
        
        {processName && (
          <Item
            icon="🔗"
            label={`Suivre le processus: ${String(processName).substring(0, 25)}`}
            onClick={() => { onFollowProcess?.(processName); onClose(); }}
          />
        )}

        <Item
          icon="🏷"
          label={`Filtrer par type: ${record?.artifact_type}`}
          onClick={() => { onFilter?.('type', record?.artifact_type); onClose(); }}
        />

        {record?.host_name && (
          <Item
            icon="🖥"
            label={`Filtrer par hôte: ${record.host_name}`}
            onClick={() => { onFilter?.('host', record.host_name); onClose(); }}
          />
        )}

        {record?.user_name && (
          <Item
            icon="👤"
            label={`Filtrer par utilisateur: ${record.user_name}`}
            onClick={() => { onFilter?.('user', record.user_name); onClose(); }}
          />
        )}

        {ip && (
          <>
            <div style={{ height: 1, background: '#0d1f30', margin: '4px 0' }} />
            <Item
              icon="🔍"
              label={enrichLoading ? 'Enrichissement…' : `Enrichir IP: ${ip}`}
              onClick={quickEnrich}
            />
            {enrichResult && (
              <div style={{ padding: '6px 12px', background: '#06111f', borderTop: '1px solid #0d1f30' }}>
                <div style={{ fontFamily: 'monospace', fontSize: 9, color: '#2a5a8a', marginBottom: 4 }}>
                  VirusTotal · AbuseIPDB
                </div>
                {enrichResult.virustotal?.verdict && (
                  <div style={{ fontFamily: 'monospace', fontSize: 10, color:
                    enrichResult.virustotal.verdict === 'malicious' ? '#ef4444' :
                    enrichResult.virustotal.verdict === 'suspicious' ? '#f59e0b' : '#22c55e'
                  }}>
                    VT: {enrichResult.virustotal.verdict}
                    {enrichResult.virustotal.positives != null && ` (${enrichResult.virustotal.positives}/${enrichResult.virustotal.total})`}
                  </div>
                )}
                {enrichResult.abuseipdb?.score != null && (
                  <div style={{ fontFamily: 'monospace', fontSize: 10, color: enrichResult.abuseipdb.score > 50 ? '#ef4444' : '#7abfff' }}>
                    AbuseIPDB score: {enrichResult.abuseipdb.score}%
                  </div>
                )}
              </div>
            )}
          </>
        )}

        <div style={{ height: 1, background: '#0d1f30', margin: '4px 0' }} />
        <Item
          icon="📋"
          label="Copier la description"
          onClick={() => { navigator.clipboard.writeText(record?.description || ''); onClose(); }}
        />
        <Item
          icon="📋"
          label="Copier la source"
          onClick={() => { navigator.clipboard.writeText(record?.source || ''); onClose(); }}
        />
      </div>
    </div>
  );
}

function Item({ icon, label, onClick }) {
  const [hov, setHov] = useState(false);
  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '6px 12px', cursor: 'pointer',
        background: hov ? '#0d1f35' : 'transparent',
        fontFamily: 'monospace', fontSize: 10,
        color: hov ? '#c0cce0' : '#7abfff',
      }}
    >
      <span>{icon}</span>
      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</span>
    </div>
  );
}
