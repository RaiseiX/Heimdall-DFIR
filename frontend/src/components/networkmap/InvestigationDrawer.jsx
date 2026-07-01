// frontend/src/components/networkmap/InvestigationDrawer.jsx
import { useState } from 'react';
import { NODE_TYPES } from '../../constants/nodeTypes';
import { detectNodeType } from './utils/nodeTypeRegistry';
import EventsTab      from './tabs/EventsTab';
import ConnectionsTab from './tabs/ConnectionsTab';
import IocTab         from './tabs/IocTab';
import LateralTab     from './tabs/LateralTab';

const TABS = [
  { key: 'events',  label: 'EVENTS' },
  { key: 'conns',   label: 'CONNS' },
  { key: 'ioc',     label: 'IOC' },
  { key: 'lateral', label: 'LATERAL' },
];

export default function InvestigationDrawer({ nodeData, caseId, allEdges, onClose, onSelectPeer, nodeOverrides, onOverrideType, onResetType, onDeleteManualNode }) {
  const [tab, setTab] = useState('events');
  if (!nodeData) return null;

  const ALL_TYPES  = Object.values(NODE_TYPES).sort((a, b) => a.label.localeCompare(b.label));
  // nodeData is Cytoscape element data — use pre-computed nodeType, fall back to detectNodeType with _raw
  const autoTypeId = nodeData.nodeType || detectNodeType({ id: nodeData.id, type: nodeData._raw?.type || '', is_suspicious: nodeData.is_suspicious });
  const overrideId = nodeOverrides?.[nodeData.id] ?? null;
  const activeTypeId = overrideId ?? autoTypeId;
  const type   = NODE_TYPES[activeTypeId] || NODE_TYPES.server;
  const acol   = type.color;

  function fmtBytes(b) {
    if (!b) return '—';
    const k = 1024, s = ['B','KB','MB','GB'];
    const i = Math.min(Math.floor(Math.log(Math.max(b,1)) / Math.log(k)), s.length - 1);
    return `${(b / Math.pow(k,i)).toFixed(1)} ${s[i]}`;
  }

  return (
    <div style={{ width: 'clamp(380px, 30vw, 540px)', flexShrink: 0, background: '#0a0c11', borderLeft: '1px solid #1a1f2c', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Color accent top border */}
      <div style={{ height: 3, background: acol, flexShrink: 0 }} />

      {/* Header */}
      <div style={{ padding: '8px 10px 6px', borderBottom: '1px solid #131722', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
          <span style={{ padding: '1px 6px', borderRadius: 3, fontSize: 7, fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: `color-mix(in srgb, ${acol} 9%, transparent)`, color: acol, border: `1px solid color-mix(in srgb, ${acol} 19%, transparent)` }}>
            {type.label.toUpperCase()}
          </span>
          <span style={{ fontSize: 10, color: acol, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {nodeData.label || nodeData.id}
          </span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--fl-muted)', cursor: 'pointer', fontSize: 14, lineHeight: 1, padding: '0 2px' }}>✕</button>
        </div>
        {/* Stats row */}
        <div style={{ fontSize: 8, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <span>{nodeData.connection_count || 0} conns · {fmtBytes(nodeData.total_bytes)}</span>
          {nodeData.serverScore != null && (
            <span title={`Comportement : ${nodeData.serverScore >= 0.65 ? 'SERVEUR' : nodeData.serverScore <= 0.25 ? 'CLIENT' : 'MIXTE'} (score ${nodeData.serverScore})`}
              style={{ fontSize: 7, color: nodeData.serverScore >= 0.65 ? 'var(--fl-ok)' : nodeData.serverScore <= 0.25 ? 'var(--fl-warn)' : 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'default' }}>
              {nodeData.serverScore >= 0.65 ? '▲SRV' : nodeData.serverScore <= 0.25 ? '▼CLT' : '≈MIX'}
            </span>
          )}
          {nodeData.confidence && nodeData.confidence !== 'OVERRIDE' && (
            <span title={`Signaux: ${(nodeData.signals||[]).join(', ')}`}
              style={{ fontSize: 7, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'help',
                color: nodeData.confidence === 'HIGH' ? 'var(--fl-ok)' : nodeData.confidence === 'MEDIUM' ? 'var(--fl-gold)' : 'var(--fl-muted)' }}>
              ● {nodeData.confidence}
            </span>
          )}
        </div>

        {/* GeoIP for external nodes */}
        {nodeData.geo && (
          <div style={{ fontSize: 7, color: 'var(--fl-purple)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', marginTop: 2, display: 'flex', alignItems: 'center', gap: 4 }}>
            <span>🌍</span>
            <span>{nodeData.geo.country}{nodeData.geo.city ? ` · ${nodeData.geo.city}` : ''}{nodeData.geo.region ? ` (${nodeData.geo.region})` : ''}</span>
          </div>
        )}

        {/* Risk + classification badges */}
        <div style={{ display: 'flex', gap: 3, marginTop: 4, flexWrap: 'wrap' }}>
          {nodeData.is_suspicious && <span style={{ padding: '1px 5px', borderRadius: 2, fontSize: 7, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'color-mix(in srgb, var(--fl-danger) 7%, transparent)', color: 'var(--fl-danger)', border: '1px solid color-mix(in srgb, var(--fl-danger) 15%, transparent)' }}>⚠ IOC</span>}
          {(nodeData.beacon_score || 0) > 70 && <span style={{ padding: '1px 5px', borderRadius: 2, fontSize: 7, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'color-mix(in srgb, var(--fl-warn) 7%, transparent)', color: 'var(--fl-warn)', border: '1px solid color-mix(in srgb, var(--fl-warn) 15%, transparent)' }}>◎ BEACON {nodeData.beacon_score}%</span>}
          {(nodeData.dga_score || 0) > 60 && <span style={{ padding: '1px 5px', borderRadius: 2, fontSize: 7, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'color-mix(in srgb, var(--fl-accent) 7%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 15%, transparent)' }}>⁉ DGA {nodeData.dga_score}</span>}
          {nodeData.osHint === 'windows'        && <span style={{ padding: '1px 5px', borderRadius: 2, fontSize: 7, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'color-mix(in srgb, var(--fl-purple) 7%, transparent)', color: 'var(--fl-purple)', border: '1px solid color-mix(in srgb, var(--fl-purple) 15%, transparent)' }}>⊞ WINDOWS</span>}
          {nodeData.osHint === 'linux'          && <span style={{ padding: '1px 5px', borderRadius: 2, fontSize: 7, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'color-mix(in srgb, var(--fl-warn) 7%, transparent)', color: 'var(--fl-warn)', border: '1px solid color-mix(in srgb, var(--fl-warn) 15%, transparent)' }}>🐧 LINUX</span>}
          {nodeData.osHint === 'network_device' && <span style={{ padding: '1px 5px', borderRadius: 2, fontSize: 7, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'color-mix(in srgb, var(--fl-ok) 7%, transparent)', color: 'var(--fl-ok)', border: '1px solid color-mix(in srgb, var(--fl-ok) 15%, transparent)' }}>⊟ NET-DEV</span>}
          {nodeData.ipCategory && <span style={{ padding: '1px 5px', borderRadius: 2, fontSize: 7, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'color-mix(in srgb, var(--fl-purple) 7%, transparent)', color: 'var(--fl-purple)', border: '1px solid color-mix(in srgb, var(--fl-purple) 15%, transparent)' }}>◈ {nodeData.ipCategory}</span>}
          {nodeData.segment && <span style={{ padding: '1px 5px', borderRadius: 2, fontSize: 7, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: `color-mix(in srgb, ${nodeData.segment.color} 9%, transparent)`, color: nodeData.segment.color, border: `1px solid color-mix(in srgb, ${nodeData.segment.color} 21%, transparent)` }}>⊕ {nodeData.segment.label}</span>}
          {(nodeData.portBadges || []).map(pb => (
            <span key={pb.badge} style={{ padding: '1px 5px', borderRadius: 2, fontSize: 7, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: `color-mix(in srgb, ${pb.color} 7%, transparent)`, color: pb.color, border: `1px solid color-mix(in srgb, ${pb.color} 15%, transparent)` }}>{pb.badge}</span>
          ))}
        </div>

        {/* Type override */}
        <div style={{ marginTop: 6, paddingTop: 6, borderTop: '1px solid #131722' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontSize: 7, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.08em', flexShrink: 0 }}>Type</span>
            <select
              value={activeTypeId}
              onChange={e => onOverrideType?.(nodeData.id, e.target.value)}
              style={{ flex: 1, background: '#131722', border: '1px solid #1a1f2c', borderRadius: 3, color: acol, fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '2px 4px', cursor: 'pointer', outline: 'none' }}
            >
              {ALL_TYPES.map(t => (
                <option key={t.id} value={t.id} style={{ background: '#0a0c11', color: t.color }}>
                  {t.label}
                </option>
              ))}
            </select>
            {overrideId && (
              <button
                onClick={() => onResetType?.(nodeData.id)}
                title="Restore auto-detected type"
                style={{ background: 'none', border: 'none', color: 'var(--fl-muted)', fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer', flexShrink: 0, padding: '1px 3px' }}
                onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-danger)'; }}
                onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; }}
              >↺</button>
            )}
          </div>
          {overrideId && (
            <div style={{ fontSize: 7, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', marginTop: 2 }}>
              Auto: {NODE_TYPES[autoTypeId]?.label ?? autoTypeId}
            </div>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid #131722', flexShrink: 0 }}>
        {TABS.map(t => (
          <button key={t.key} onClick={() => setTab(t.key)} style={{
            flex: 1, padding: '5px 4px', background: 'none', border: 'none',
            borderBottom: tab === t.key ? `2px solid ${acol}` : '2px solid transparent',
            color: tab === t.key ? acol : 'var(--fl-muted)',
            fontSize: 7.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer',
            letterSpacing: '0.06em',
          }}>{t.label}</button>
        ))}
      </div>

      {/* Tab content */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {tab === 'events'  && <EventsTab      caseId={caseId} nodeId={nodeData.id} />}
        {tab === 'conns'   && <ConnectionsTab nodeData={nodeData} allEdges={allEdges} onSelectPeer={onSelectPeer} />}
        {tab === 'ioc'     && <IocTab         nodeData={nodeData} />}
        {tab === 'lateral' && <LateralTab     nodeData={nodeData} allEdges={allEdges} />}
      </div>

      {/* Action bar */}
      <div style={{ padding: '6px 10px', borderTop: '1px solid #131722', display: 'flex', gap: 5, flexShrink: 0 }}>
        {nodeData._manual ? (
          <button
            onClick={() => onDeleteManualNode?.(nodeData.id)}
            style={{ flex: 1, padding: '5px', borderRadius: 3, background: 'color-mix(in srgb, var(--fl-danger) 6%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 19%, transparent)', color: 'var(--fl-danger)', fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer' }}
            onMouseEnter={e => { e.currentTarget.style.background = 'color-mix(in srgb, var(--fl-danger) 13%, transparent)'; }}
            onMouseLeave={e => { e.currentTarget.style.background = 'color-mix(in srgb, var(--fl-danger) 6%, transparent)'; }}
          >
            x Delete
          </button>
        ) : (
          <>
            <button style={{ flex: 1, padding: '5px', borderRadius: 3, background: `color-mix(in srgb, ${acol} 7%, transparent)`, border: `1px solid color-mix(in srgb, ${acol} 19%, transparent)`, color: acol, fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer' }}>
              ⇄ Timeline
            </button>
            {(nodeData.is_suspicious || (nodeData.beacon_score || 0) > 50) && (
              <button style={{ flex: 1, padding: '5px', borderRadius: 3, background: 'color-mix(in srgb, var(--fl-danger) 6%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 19%, transparent)', color: 'var(--fl-danger)', fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer' }}>
                Flag IOC
              </button>
            )}
          </>
        )}
      </div>
    </div>
  );
}
