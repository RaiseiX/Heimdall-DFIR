// frontend/src/components/globalnetworkmap/GlobalMapDetailPanel.jsx
import { EVIDENCE_COLORS } from './GlobalMapToolbar';
import { useTranslation } from 'react-i18next';

export default function GlobalMapDetailPanel({ node, evidenceSources, onClose }) {
  const { t } = useTranslation();
  if (!node) return null;

  // node is the Cytoscape data object from onNodeSelect(node.data())
  // Fields available: id, label, nodeType, is_suspicious, connection_count,
  // total_bytes, evidence_ids, correlationCount, dga_score, _raw (original API node)
  const raw         = node._raw || {};
  const evidenceIds = node.evidence_ids || [];
  const dgaScore    = node.dga_score || raw.dga_score || 0;
  const processes   = raw.processes || [];
  const totalBytes  = node.total_bytes || 0;
  const suspicious  = node.is_suspicious || false;

  const colorMap = Object.fromEntries(
    (evidenceSources || []).map((ev, i) => [ev.id, EVIDENCE_COLORS[i % EVIDENCE_COLORS.length]])
  );
  const nameMap = Object.fromEntries(
    (evidenceSources || []).map(ev => [ev.id, ev.name])
  );

  const borderColor = suspicious
    ? 'rgba(218,54,51,0.4)'
    : evidenceIds.length >= 2
      ? 'rgba(139,114,214,0.4)'
      : '#1e293b';

  return (
    <div style={{
      position: 'absolute',
      bottom: 12,
      right: 12,
      width: 240,
      background: 'rgba(10,15,26,0.97)',
      border: `1px solid ${borderColor}`,
      borderRadius: 6,
      padding: 12,
      fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
      fontSize: 11,
      zIndex: 10,
      maxHeight: 'calc(100% - 80px)',
      overflowY: 'auto',
    }}>
      {/* Header row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
        <div style={{
          color: 'var(--fl-purple)', fontWeight: 700,
          wordBreak: 'break-all', flex: 1, lineHeight: 1.3,
        }}>
          {node.label || node.id}
        </div>
        <button
          onClick={onClose}
          style={{ background: 'none', border: 'none', color: '#555', cursor: 'pointer', padding: '0 0 0 6px', fontSize: 13, lineHeight: 1 }}
        >
          ✕
        </button>
      </div>

      {/* Type + suspicious badges */}
      <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 8 }}>
        <span style={{
          background: '#1a1f2c', borderRadius: 3,
          padding: '1px 7px', color: 'var(--fl-accent)',
        }}>
          {node.nodeType || raw.type}
        </span>
        {suspicious && (
          <span style={{
            background: 'rgba(218,54,51,0.15)', borderRadius: 3,
            padding: '1px 7px', color: 'var(--fl-danger)',
          }}>
            {t('networkMap.suspicious')}
          </span>
        )}
        {evidenceIds.length >= 2 && (
          <span style={{
            background: 'rgba(139,114,214,0.15)', borderRadius: 3,
            padding: '1px 7px', color: 'var(--fl-purple)',
          }}>
            {t('networkMap.correlated_badge', { count: evidenceIds.length })}
          </span>
        )}
      </div>

      {/* Connection stats */}
      <div style={{ color: '#555', marginBottom: 10 }}>
        {t('networkMap.connections_label', { count: node.connection_count || 0 })}
        {totalBytes > 0 && ` · ${(totalBytes / 1024).toFixed(1)} KB`}
      </div>

      {/* Evidence attribution */}
      {evidenceIds.length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div style={{ color: 'var(--fl-purple)', fontSize: 9, fontWeight: 700, letterSpacing: 1, marginBottom: 5 }}>
            {t('networkMap.seen_in')}
          </div>
          {evidenceIds.map(eid => (
            <div key={eid} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
              <span style={{
                width: 7, height: 7, borderRadius: '50%',
                background: colorMap[eid] || '#8899aa',
                display: 'inline-block', flexShrink: 0,
              }} />
              <span style={{ color: '#8899aa', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {nameMap[eid] || eid}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* DGA score bar */}
      {dgaScore > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div style={{ color: 'var(--fl-purple)', fontSize: 9, fontWeight: 700, letterSpacing: 1, marginBottom: 5 }}>
            {t('networkMap.dga_score')}
          </div>
          <div style={{ height: 4, background: '#1a1f2c', borderRadius: 2, overflow: 'hidden', marginBottom: 3 }}>
            <div style={{
              height: '100%',
              width: `${dgaScore}%`,
              background: dgaScore >= 70 ? 'var(--fl-danger)' : 'var(--fl-gold)',
              borderRadius: 2,
            }} />
          </div>
          <div style={{ color: '#555' }}>{dgaScore}/100</div>
        </div>
      )}

      {/* Processes */}
      {processes.length > 0 && (
        <div>
          <div style={{ color: 'var(--fl-purple)', fontSize: 9, fontWeight: 700, letterSpacing: 1, marginBottom: 5 }}>
            {t('networkMap.processes')}
          </div>
          {processes.map(p => (
            <div key={p} style={{ color: '#555', fontSize: 10, marginBottom: 2 }}>
              {String(p).split('\\').pop()}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
