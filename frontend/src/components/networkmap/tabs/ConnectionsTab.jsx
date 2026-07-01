// frontend/src/components/networkmap/tabs/ConnectionsTab.jsx
import { useState } from 'react';
import { NODE_TYPES } from '../../../constants/nodeTypes';
import { detectNodeType } from '../utils/nodeTypeRegistry';
import { useTranslation } from 'react-i18next';

function fmtBytes(b) {
  if (!b) return '—';
  const k = 1024, s = ['B','KB','MB','GB'];
  const i = Math.min(Math.floor(Math.log(Math.max(b,1)) / Math.log(k)), s.length - 1);
  return `${(b / Math.pow(k,i)).toFixed(1)} ${s[i]}`;
}

function fmtTs(ts, locale) {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString(locale, { dateStyle: 'short', timeStyle: 'short' });
  } catch { return String(ts).slice(0, 16); }
}

export default function ConnectionsTab({ nodeData, allEdges, onSelectPeer }) {
  const { t, i18n } = useTranslation();
  const [expanded, setExpanded] = useState(null); // peerId whose edge is expanded

  if (!nodeData) return null;
  const nodeId = nodeData.id;

  const peers = [];
  (allEdges || []).forEach(e => {
    const src = e.data?.source;
    const tgt = e.data?.target;
    if (!src || !tgt) return;
    if (src === nodeId) peers.push({ peerId: tgt, direction: 'out', edge: e.data });
    else if (tgt === nodeId) peers.push({ peerId: src, direction: 'in',  edge: e.data });
  });

  peers.sort((a, b) => (b.edge.connection_count || 0) - (a.edge.connection_count || 0));

  if (!peers.length) return (
    <div style={{ padding: 12, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10 }}>{t('networkMap.no_connections')}</div>
  );

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '6px 10px' }}>
      <div style={{ fontSize: 7, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>
        {t(peers.length !== 1 ? 'networkMap.connections_count_pl' : 'networkMap.connections_count', { count: peers.length })}
      </div>

      {peers.map(({ peerId, direction, edge }, i) => {
        const typeId = detectNodeType({ id: peerId, type: '' });
        const color  = (NODE_TYPES[typeId] || NODE_TYPES.server).color;
        const isOpen = expanded === peerId;

        return (
          <div key={i} style={{ marginBottom: 2 }}>
            {/* Connection row */}
            <div
              onClick={() => setExpanded(isOpen ? null : peerId)}
              style={{
                padding: '5px 6px', borderRadius: isOpen ? '3px 3px 0 0' : 3,
                background: isOpen ? '#131722' : '#0a0f18',
                cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6,
                borderLeft: isOpen ? `2px solid ${color}` : '2px solid transparent',
              }}
              onMouseEnter={e => { e.currentTarget.style.background = '#0e1118'; }}
              onMouseLeave={e => { e.currentTarget.style.background = isOpen ? '#131722' : '#0a0f18'; }}
            >
              <span style={{ fontSize: 9, color: direction === 'out' ? 'var(--fl-warn)' : 'var(--fl-purple)', flexShrink: 0 }}>
                {direction === 'out' ? '→' : '←'}
              </span>
              <span style={{ fontSize: 9, color, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {peerId}
              </span>
              {/* Protocol / port badge */}
              {(edge.label || (edge.protocols && edge.protocols[0])) && (
                <span style={{ fontSize: 7, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 4px',
                  borderRadius: 2, background: '#0c1828', border: '1px solid #1a1f2c',
                  color: 'var(--fl-purple)', flexShrink: 0 }}>
                  {edge.label || edge.protocols[0]}
                </span>
              )}
              <span style={{ fontSize: 8, color: '#4a6080', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', flexShrink: 0 }}>
                {edge.connection_count || 1}x
              </span>
              <span style={{ fontSize: 8, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', flexShrink: 0 }}>
                {fmtBytes(edge.total_bytes)}
              </span>
              <span style={{ fontSize: 8, color: 'var(--fl-subtle)', flexShrink: 0 }}>{isOpen ? '▲' : '▼'}</span>
            </div>

            {/* Inline detail panel */}
            {isOpen && (
              <div style={{ background: '#0a0c11', border: '1px solid #131722', borderTop: 'none', borderRadius: '0 0 3px 3px', padding: '8px 10px' }}>
                {/* Stats row */}
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, marginBottom: 8 }}>
                  {[
                    [t('networkMap.fields.connections'), edge.connection_count || 1],
                    [t('networkMap.fields.total_bytes'), fmtBytes(edge.total_bytes)],
                    [t('networkMap.fields.direction'), direction === 'out' ? t('networkMap.outbound') : t('networkMap.inbound')],
                    ...(edge.first_seen ? [[t('networkMap.fields.first_seen'), fmtTs(edge.first_seen, i18n.language)]] : []),
                    ...(edge.last_seen  ? [[t('networkMap.fields.last_seen'),  fmtTs(edge.last_seen, i18n.language)]]  : []),
                  ].map(([label, val]) => (
                    <div key={label}>
                      <div style={{ fontSize: 7, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</div>
                      <div style={{ fontSize: 10, color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700 }}>{val}</div>
                    </div>
                  ))}
                </div>

                {/* Ports */}
                {edge.ports?.length > 0 && (
                  <div style={{ marginBottom: 6 }}>
                    <div style={{ fontSize: 7, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>{t('networkMap.fields.ports')}</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                      {edge.ports.slice(0, 12).map(p => (
                        <span key={p} style={{ fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 5px', borderRadius: 2, background: '#0c1828', border: '1px solid #1a1f2c', color: 'var(--fl-muted)' }}>{p}</span>
                      ))}
                      {edge.ports.length > 12 && <span style={{ fontSize: 8, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>+{edge.ports.length - 12}</span>}
                    </div>
                  </div>
                )}

                {/* Protocols */}
                {edge.protocols?.length > 0 && (
                  <div style={{ marginBottom: 6 }}>
                    <div style={{ fontSize: 7, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>{t('networkMap.fields.protocols')}</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                      {edge.protocols.map(p => (
                        <span key={p} style={{ fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 5px', borderRadius: 2, background: '#0a1820', border: '1px solid #1a1f2c', color: 'var(--fl-purple)' }}>{p}</span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Navigate to peer button */}
                <button
                  onClick={() => onSelectPeer?.(peerId)}
                  style={{ width: '100%', marginTop: 4, padding: '4px', borderRadius: 3, background: `color-mix(in srgb, ${color} 6%, transparent)`, border: `1px solid color-mix(in srgb, ${color} 19%, transparent)`, color, fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer' }}
                  onMouseEnter={e => { e.currentTarget.style.background = `color-mix(in srgb, ${color} 13%, transparent)`; }}
                  onMouseLeave={e => { e.currentTarget.style.background = `color-mix(in srgb, ${color} 6%, transparent)`; }}
                >
                  → {t('networkMap.inspect_peer', { peer: peerId })}
                </button>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
