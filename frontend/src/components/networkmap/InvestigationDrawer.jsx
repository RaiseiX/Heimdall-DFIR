import { useState, useEffect } from 'react';
import { X } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { controlStyle, controlHover } from '../ui/controlIdiom';
import { NODE_TYPES } from '../../constants/nodeTypes';
import { detectNodeType } from './utils/nodeTypeRegistry';
import { iocsAPI, bookmarksAPI } from '../../utils/api';
import { buildNodeArtifacts } from './utils/nodeArtifacts';
import { ZONES, zoneOf } from './utils/zoneDeclaration';
import { Action } from './MapControls';
import { peerSummary } from './utils/peerSummary';
import { portService, isCleartextPort } from './utils/registerGroups';
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

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

const rowLabel = {
  width: 92, flexShrink: 0,
  fontSize: 9, letterSpacing: '0.1em', textTransform: 'uppercase', fontWeight: 700,
  color: 'var(--fl-muted)', fontFamily: MONO,
};
const rowValue = { flex: 1, minWidth: 0, fontSize: 11, fontFamily: MONO, color: 'var(--fl-dim)' };
const rowNote  = { display: 'block', fontSize: 10, color: 'var(--fl-subtle)', fontFamily: MONO, marginTop: 1 };

const Dash = () => <span style={{ color: 'var(--fl-border)' }}>—</span>;

function Row({ label, children, notes = [] }) {
  return (
    <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, padding: '3px 0' }}>
      <span style={rowLabel}>{label}</span>
      <span style={rowValue}>
        {children}
        {notes.filter(Boolean).map((n, i) => <span key={i} style={rowNote}>{n}</span>)}
      </span>
    </div>
  );
}

export default function InvestigationDrawer({ nodeData, caseId, allEdges, onClose, onSelectPeer, nodeOverrides, onOverrideType, onResetType, onDeleteManualNode, zoneDeclarations, onDeclareZone, onWithdrawZone, onHideNode }) {
  const [tab, setTab] = useState('events');
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [flagged, setFlagged] = useState(false);
  const [pinned, setPinned]   = useState(false);
  const [busy, setBusy]       = useState(false);
  useEffect(() => { setFlagged(false); setPinned(false); setBusy(false); }, [nodeData?.id]);
  if (!nodeData) return null;

  const ALL_TYPES  = Object.values(NODE_TYPES).sort((a, b) => a.label.localeCompare(b.label));
  const autoTypeId = nodeData.nodeType || detectNodeType({ id: nodeData.id, type: nodeData._raw?.type || '', is_suspicious: nodeData.is_suspicious });
  const overrideId = nodeOverrides?.[nodeData.id] ?? null;
  const activeTypeId = overrideId ?? autoTypeId;
  const type   = NODE_TYPES[activeTypeId] || NODE_TYPES.server;
  const acol   = type.color;

  const art = buildNodeArtifacts(nodeData);

  const zone = zoneOf({ id: nodeData.id, type: nodeData._raw?.type }, zoneDeclarations);
  const declarable = zone.inferred !== null && !!onDeclareZone;
  const declaredAt = zone.at ? String(zone.at).slice(0, 19).replace('T', ' ') : '';

  const summary = peerSummary(nodeData.id, allEdges, { maxProcesses: 4 });
  const seenAt = (allEdges || [])
    .filter(e => e?.data?.source === nodeData.id || e?.data?.target === nodeData.id)
    .map(e => e?.data?.last_seen || e?.data?.first_seen)
    .filter(Boolean)
    .sort()
    .pop();

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
      <div style={{ padding: '11px 13px 10px', borderBottom: '1px solid #131722', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 9 }}>
          <span style={{ fontSize: 13, color: 'var(--fl-text)', fontFamily: MONO, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
            title={nodeData.id}>
            {nodeData.label || nodeData.id}
          </span>
          {onHideNode && (
            <Action onClick={() => onHideNode(nodeData.id)} title={t('networkMap.hidden.hide_hint')}>
              {t('networkMap.hidden.hide')}
            </Action>
          )}
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--fl-muted)', cursor: 'pointer', fontSize: 13, lineHeight: 1, padding: '0 2px' }}><X size={12} /></button>
        </div>

        <Row
          label={t('networkMap.zone.title')}
          notes={[
            zone.source === 'declared'
              ? t('networkMap.zone.declared_by', { by: zone.by, at: declaredAt })
              : zone.zone ? t('networkMap.zone.inferred_from') : null,
            zone.source === 'declared' && zone.inferred
              ? `${t(`networkMap.zone.${zone.inferred}`)} — ${t('networkMap.zone.inferred_from')}`
              : null,
          ]}
        >
          {zone.zone
            ? <span style={{ color: zone.source === 'declared' ? 'var(--fl-warn)' : 'var(--fl-dim)' }}>{t(`networkMap.zone.${zone.zone}`)}</span>
            : <Dash />}
        </Row>

        <Row
          label={t('networkMap.drawer.type')}
          notes={[
            overrideId ? `${t('networkMap.drawer.auto')} ${NODE_TYPES[autoTypeId]?.label ?? autoTypeId}` : null,
            !overrideId && nodeData.confidence && nodeData.confidence !== 'OVERRIDE'
              ? `${nodeData.confidence} · ${(nodeData.signals || []).join(', ')}` : null,
          ]}
        >
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <select
              value={activeTypeId}
              onChange={e => onOverrideType?.(nodeData.id, e.target.value)}
              style={{ flex: 1, minWidth: 0, background: 'none', border: 0, borderBottom: '1px solid var(--fl-border3)', color: acol, fontSize: 11, fontFamily: MONO, padding: '1px 0 2px', cursor: 'pointer', outline: 'none' }}
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
                title={t('networkMap.drawer.reset_type')}
                style={{ background: 'none', border: 'none', color: 'var(--fl-muted)', fontSize: 11, fontFamily: MONO, cursor: 'pointer', flexShrink: 0, padding: '0 2px' }}
                onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-danger)'; }}
                onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; }}
              >↺</button>
            )}
          </span>
        </Row>

        <Row label={t('networkMap.register.port')}>
          {summary.ports.length
            ? summary.ports.map((p, i) => (
              <span key={p}>
                {i > 0 ? <span style={{ color: 'var(--fl-border)' }}> · </span> : null}
                <span style={{ color: isCleartextPort(p) ? 'var(--fl-danger)' : 'var(--fl-dim)' }}>{`:${p}`}</span>
                {portService(p) ? <span style={{ fontSize: 10, color: isCleartextPort(p) ? 'var(--fl-danger)' : 'var(--fl-muted)', marginLeft: 5 }}>{portService(p)}</span> : null}
              </span>
            ))
            : <Dash />}
        </Row>

        <Row label={t('networkMap.register.process')}>
          {summary.processes.length
            ? <span>{summary.processes.join(', ')}{summary.truncated ? <span style={{ color: 'var(--fl-muted)' }}>{` +${summary.truncated}`}</span> : null}</span>
            : <span style={{ color: 'var(--fl-muted)', fontStyle: 'italic' }}>{t('networkMap.register.unattributed')}</span>}
        </Row>

        <Row label={t('networkMap.register.conn')}>
          <span style={{ color: 'var(--fl-text)' }}>{summary.connections || nodeData.connection_count || 0}</span>
        </Row>

        {nodeData.total_bytes > 0 && (
          <Row label={t('networkMap.drawer.volume')}>{fmtBytes(nodeData.total_bytes)}</Row>
        )}

        <Row label={t('networkMap.drawer.seen_at')}>
          {seenAt ? <span>{String(seenAt).slice(0, 19).replace('T', ' ')}</span> : <Dash />}
        </Row>

        {(nodeData.is_suspicious || (nodeData.beacon_score || 0) > 70 || (nodeData.dga_score || 0) > 60) && (
          <Row label={t('networkMap.drawer.verdict')}>
            {nodeData.is_suspicious && <span style={{ color: 'var(--fl-danger)' }}>{t('networkMap.drawer.ioc')}</span>}
            {(nodeData.beacon_score || 0) > 70 && (
              <span style={{ color: 'var(--fl-warn)', marginLeft: nodeData.is_suspicious ? 10 : 0 }}>
                {t('networkMap.drawer.beacon')} {nodeData.beacon_score}%
              </span>
            )}
            {(nodeData.dga_score || 0) > 60 && (
              <span style={{ color: 'var(--fl-accent)', marginLeft: 10 }}>{t('networkMap.drawer.dga')} {nodeData.dga_score}</span>
            )}
          </Row>
        )}

        {nodeData.osHint && (
          <Row label={t('networkMap.drawer.system')}>{t(`networkMap.drawer.os_${nodeData.osHint}`, nodeData.osHint)}</Row>
        )}

        {nodeData.serverScore != null && (
          <Row label={t('networkMap.drawer.behavior')} notes={[`score ${nodeData.serverScore}`]}>
            <span style={{ color: nodeData.serverScore >= 0.65 ? 'var(--fl-ok)' : nodeData.serverScore <= 0.25 ? 'var(--fl-warn)' : 'var(--fl-dim)' }}>
              {t(`networkMap.drawer.behavior_${nodeData.serverScore >= 0.65 ? 'server' : nodeData.serverScore <= 0.25 ? 'client' : 'mixed'}`)}
            </span>
          </Row>
        )}

        {nodeData.ipCategory && <Row label={t('networkMap.drawer.category')}>{nodeData.ipCategory}</Row>}

        {nodeData.segment && (
          <Row label={t('networkMap.subnet.title')}>
            <span style={{ color: nodeData.segment.color }}>{nodeData.segment.label}</span>
          </Row>
        )}

        {nodeData.geo && (
          <Row label={t('networkMap.drawer.country')}>
            {nodeData.geo.country}{nodeData.geo.city ? ` · ${nodeData.geo.city}` : ''}{nodeData.geo.region ? ` (${nodeData.geo.region})` : ''}
          </Row>
        )}

        {declarable && (
          <div style={{ marginTop: 9, paddingTop: 9, borderTop: '1px solid #131722' }}>
            <div style={{ ...rowLabel, width: 'auto', marginBottom: 5 }}>{t('networkMap.zone.declare')}</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 14, flexWrap: 'wrap' }}>
              {ZONES.map(z => {
                const on = zone.source === 'declared' && zone.zone === z;
                return (
                  <button
                    key={z}
                    type="button"
                    onClick={() => onDeclareZone(nodeData.id, z)}
                    aria-pressed={on}
                    style={{
                      background: 'none', border: 0, padding: '0 0 2px', cursor: 'pointer',
                      fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11,
                      color: on ? 'var(--fl-warn)' : 'var(--fl-muted)',
                      borderBottom: `1px solid ${on ? 'var(--fl-warn)' : 'var(--fl-border3)'}`,
                    }}
                  >{t(`networkMap.zone.${z}`)}</button>
                );
              })}
            </div>

            {zone.source === 'declared' && onWithdrawZone && (
              <button
                type="button"
                onClick={() => onWithdrawZone(nodeData.id)}
                style={{
                  display: 'block', marginTop: 7, background: 'none', border: 0, padding: '0 0 2px',
                  cursor: 'pointer', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11,
                  color: 'var(--fl-muted)', borderBottom: '1px solid var(--fl-border3)',
                }}
              >{t('networkMap.zone.withdraw')}</button>
            )}

            <div style={{ fontSize: 11, color: 'var(--fl-subtle)', marginTop: 7, lineHeight: 1.5 }}>
              {t('networkMap.zone.hint')}
            </div>
          </div>
        )}
      </div>

      <div style={{ display: 'flex', borderBottom: '1px solid var(--fl-card)', flexShrink: 0 }}>
        {TABS.map(t => (
          <button key={t.key} onClick={() => setTab(t.key)} aria-pressed={tab === t.key}
            style={{ ...controlStyle(tab === t.key), flex: 1, justifyContent: 'center', padding: '7px 0 5px' }}
            {...controlHover(tab === t.key)}>{t.label}</button>
        ))}
      </div>

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {tab === 'events'  && <EventsTab      caseId={caseId} nodeId={nodeData.id} />}
        {tab === 'conns'   && <ConnectionsTab nodeData={nodeData} allEdges={allEdges} onSelectPeer={onSelectPeer} />}
        {tab === 'ioc'     && <IocTab         nodeData={nodeData} />}
        {tab === 'lateral' && <LateralTab     nodeData={nodeData} allEdges={allEdges} />}
      </div>

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
