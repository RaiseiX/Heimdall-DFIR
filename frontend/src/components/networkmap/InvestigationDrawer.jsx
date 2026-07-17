// frontend/src/components/networkmap/InvestigationDrawer.jsx
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { NODE_TYPES } from '../../constants/nodeTypes';
import { detectNodeType } from './utils/nodeTypeRegistry';
import { iocsAPI, bookmarksAPI } from '../../utils/api';
import { buildNodeArtifacts } from './utils/nodeArtifacts';
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
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [flagged, setFlagged] = useState(false);
  const [pinned, setPinned]   = useState(false);
  const [busy, setBusy]       = useState(false);
  // Reset per-node action state when a different node is selected.
  useEffect(() => { setFlagged(false); setPinned(false); setBusy(false); }, [nodeData?.id]);
  if (!nodeData) return null;

  const ALL_TYPES  = Object.values(NODE_TYPES).sort((a, b) => a.label.localeCompare(b.label));
  // nodeData is Cytoscape element data — use pre-computed nodeType, fall back to detectNodeType with _raw
  const autoTypeId = nodeData.nodeType || detectNodeType({ id: nodeData.id, type: nodeData._raw?.type || '', is_suspicious: nodeData.is_suspicious });
  const overrideId = nodeOverrides?.[nodeData.id] ?? null;
  const activeTypeId = overrideId ?? autoTypeId;
  const type   = NODE_TYPES[activeTypeId] || NODE_TYPES.server;
  const acol   = type.color;

  const art = buildNodeArtifacts(nodeData);

  function goTimeline() {
    if (!art.valid) return;
    navigate(`/super-timeline?caseId=${caseId}&search=${encodeURIComponent(art.timelineQuery)}`);
  }
  async function flagIoc() {
    if (!art.valid || busy || flagged) return;
    setBusy(true); setFlagged(true);
    try {
      await iocsAPI.create(caseId, {
        ioc_type: art.iocType, value: art.indicator, is_malicious: true,
        severity: art.severity, source: 'network-map', description: art.context, tags: ['network-map'],
      });
    } catch { setFlagged(false); alert(t('networkMap.flag_error')); }
    finally { setBusy(false); }
  }
  async function pinFinding() {
    if (!art.valid || busy || pinned) return;
    setBusy(true); setPinned(true);
    try {
      await bookmarksAPI.create(caseId, {
        title: art.indicator, description: art.context, confidence: 'medium', significance: '', color: acol,
      });
    } catch { setPinned(false); alert(t('networkMap.pin_error')); }
    finally { setBusy(false); }
  }

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
      <div style={{ padding: '11px 12px 9px', borderBottom: '1px solid #131722', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 4 }}>
          <span style={{ padding: '3px 8px', borderRadius: 3, fontSize: 11, fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: `color-mix(in srgb, ${acol} 9%, transparent)`, color: acol, border: `1px solid color-mix(in srgb, ${acol} 19%, transparent)` }}>
            {type.label.toUpperCase()}
          </span>
          <span style={{ fontSize: 15, color: acol, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {nodeData.label || nodeData.id}
          </span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--fl-muted)', cursor: 'pointer', fontSize: 15, lineHeight: 1, padding: '0 2px' }}>✕</button>
        </div>
        {/* Stats row */}
        <div style={{ fontSize: 12, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', display: 'flex', alignItems: 'center', gap: 9 }}>
          <span>{nodeData.connection_count || 0} conns · {fmtBytes(nodeData.total_bytes)}</span>
          {nodeData.serverScore != null && (
            <span title={`Comportement : ${nodeData.serverScore >= 0.65 ? 'SERVEUR' : nodeData.serverScore <= 0.25 ? 'CLIENT' : 'MIXTE'} (score ${nodeData.serverScore})`}
              style={{ fontSize: 11, color: nodeData.serverScore >= 0.65 ? 'var(--fl-ok)' : nodeData.serverScore <= 0.25 ? 'var(--fl-warn)' : 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'default' }}>
              {nodeData.serverScore >= 0.65 ? '▲SRV' : nodeData.serverScore <= 0.25 ? '▼CLT' : '≈MIX'}
            </span>
          )}
          {nodeData.confidence && nodeData.confidence !== 'OVERRIDE' && (
            <span title={`Signaux: ${(nodeData.signals||[]).join(', ')}`}
              style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'help',
                color: nodeData.confidence === 'HIGH' ? 'var(--fl-ok)' : nodeData.confidence === 'MEDIUM' ? 'var(--fl-gold)' : 'var(--fl-muted)' }}>
              ● {nodeData.confidence}
            </span>
          )}
        </div>

        {/* GeoIP for external nodes */}
        {nodeData.geo && (
          <div style={{ fontSize: 11, color: 'var(--fl-purple)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', marginTop: 3, display: 'flex', alignItems: 'center', gap: 5 }}>
            <span>🌍</span>
            <span>{nodeData.geo.country}{nodeData.geo.city ? ` · ${nodeData.geo.city}` : ''}{nodeData.geo.region ? ` (${nodeData.geo.region})` : ''}</span>
          </div>
        )}

        {/* Risk + classification badges */}
        <div style={{ display: 'flex', gap: 4, marginTop: 5, flexWrap: 'wrap' }}>
          {nodeData.is_suspicious && <span style={{ padding: '3px 8px', borderRadius: 2, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'color-mix(in srgb, var(--fl-danger) 7%, transparent)', color: 'var(--fl-danger)', border: '1px solid color-mix(in srgb, var(--fl-danger) 15%, transparent)' }}>⚠ IOC</span>}
          {(nodeData.beacon_score || 0) > 70 && <span style={{ padding: '3px 8px', borderRadius: 2, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'color-mix(in srgb, var(--fl-warn) 7%, transparent)', color: 'var(--fl-warn)', border: '1px solid color-mix(in srgb, var(--fl-warn) 15%, transparent)' }}>◎ BEACON {nodeData.beacon_score}%</span>}
          {(nodeData.dga_score || 0) > 60 && <span style={{ padding: '3px 8px', borderRadius: 2, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'color-mix(in srgb, var(--fl-accent) 7%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 15%, transparent)' }}>⁉ DGA {nodeData.dga_score}</span>}
          {nodeData.osHint === 'windows'        && <span style={{ padding: '3px 8px', borderRadius: 2, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'color-mix(in srgb, var(--fl-purple) 7%, transparent)', color: 'var(--fl-purple)', border: '1px solid color-mix(in srgb, var(--fl-purple) 15%, transparent)' }}>⊞ WINDOWS</span>}
          {nodeData.osHint === 'linux'          && <span style={{ padding: '3px 8px', borderRadius: 2, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'color-mix(in srgb, var(--fl-warn) 7%, transparent)', color: 'var(--fl-warn)', border: '1px solid color-mix(in srgb, var(--fl-warn) 15%, transparent)' }}>🐧 LINUX</span>}
          {nodeData.osHint === 'network_device' && <span style={{ padding: '3px 8px', borderRadius: 2, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'color-mix(in srgb, var(--fl-ok) 7%, transparent)', color: 'var(--fl-ok)', border: '1px solid color-mix(in srgb, var(--fl-ok) 15%, transparent)' }}>⊟ NET-DEV</span>}
          {nodeData.ipCategory && <span style={{ padding: '3px 8px', borderRadius: 2, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'color-mix(in srgb, var(--fl-purple) 7%, transparent)', color: 'var(--fl-purple)', border: '1px solid color-mix(in srgb, var(--fl-purple) 15%, transparent)' }}>◈ {nodeData.ipCategory}</span>}
          {nodeData.segment && <span style={{ padding: '3px 8px', borderRadius: 2, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: `color-mix(in srgb, ${nodeData.segment.color} 9%, transparent)`, color: nodeData.segment.color, border: `1px solid color-mix(in srgb, ${nodeData.segment.color} 21%, transparent)` }}>⊕ {nodeData.segment.label}</span>}
          {(nodeData.portBadges || []).map(pb => (
            <span key={pb.badge} style={{ padding: '3px 8px', borderRadius: 2, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: `color-mix(in srgb, ${pb.color} 7%, transparent)`, color: pb.color, border: `1px solid color-mix(in srgb, ${pb.color} 15%, transparent)` }}>{pb.badge}</span>
          ))}
        </div>

        {/* Type override */}
        <div style={{ marginTop: 7, paddingTop: 7, borderTop: '1px solid #131722' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <span style={{ fontSize: 11, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.08em', flexShrink: 0 }}>Type</span>
            <select
              value={activeTypeId}
              onChange={e => onOverrideType?.(nodeData.id, e.target.value)}
              style={{ flex: 1, background: '#131722', border: '1px solid #1a1f2c', borderRadius: 3, color: acol, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '3px 5px', cursor: 'pointer', outline: 'none' }}
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
                style={{ background: 'none', border: 'none', color: 'var(--fl-muted)', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer', flexShrink: 0, padding: '2px 4px' }}
                onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-danger)'; }}
                onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; }}
              >↺</button>
            )}
          </div>
          {overrideId && (
            <div style={{ fontSize: 11, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', marginTop: 3 }}>
              Auto: {NODE_TYPES[autoTypeId]?.label ?? autoTypeId}
            </div>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid #131722', flexShrink: 0 }}>
        {TABS.map(t => (
          <button key={t.key} onClick={() => setTab(t.key)} style={{
            flex: 1, padding: '6px 5px', background: 'none', border: 'none',
            borderBottom: tab === t.key ? `2px solid ${acol}` : '2px solid transparent',
            color: tab === t.key ? acol : 'var(--fl-muted)',
            fontSize: 12, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer',
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
            style={{ flex: 1, padding: '7px', borderRadius: 5, background: 'color-mix(in srgb, var(--fl-danger) 6%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 19%, transparent)', color: 'var(--fl-danger)', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer' }}
            onMouseEnter={e => { e.currentTarget.style.background = 'color-mix(in srgb, var(--fl-danger) 13%, transparent)'; }}
            onMouseLeave={e => { e.currentTarget.style.background = 'color-mix(in srgb, var(--fl-danger) 6%, transparent)'; }}
          >
            x Delete
          </button>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, width: '100%' }}>
            <div style={{ display: 'flex', gap: 6 }}>
              <button onClick={goTimeline} disabled={!art.valid} title={art.valid ? '' : '—'}
                style={{ flex: 1, padding: '7px', borderRadius: 5, background: 'color-mix(in srgb, var(--fl-accent) 10%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 32%, transparent)', color: 'var(--fl-accent)', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: art.valid ? 'pointer' : 'not-allowed', opacity: art.valid ? 1 : 0.5 }}>
                ⇄ {t('networkMap.action_timeline')}
              </button>
              <button onClick={flagIoc} disabled={!art.valid || flagged || busy}
                style={{ flex: 1, padding: '7px', borderRadius: 5, background: 'color-mix(in srgb, var(--fl-danger) 10%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 32%, transparent)', color: 'var(--fl-danger)', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: (art.valid && !flagged) ? 'pointer' : 'default', opacity: art.valid ? 1 : 0.5 }}>
                {flagged ? `✓ ${t('networkMap.flagged')}` : `⚑ ${t('networkMap.action_flag_ioc')}`}
              </button>
            </div>
            <button onClick={pinFinding} disabled={!art.valid || pinned || busy}
              style={{ width: '100%', padding: '7px', borderRadius: 5, background: 'color-mix(in srgb, var(--fl-ok) 10%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-ok) 32%, transparent)', color: 'var(--fl-ok)', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: (art.valid && !pinned) ? 'pointer' : 'default', opacity: art.valid ? 1 : 0.5 }}>
              {pinned ? `✓ ${t('networkMap.pinned')}` : `★ ${t('networkMap.action_pin_finding')}`}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
