
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { byProcess, byPeer, byPort, portService, isCleartextPort, splitAddressTail } from './utils/registerGroups';
import { zoneOf } from './utils/zoneDeclaration';
import { formatCount } from '../../utils/formatCount';

const VIEWS = ['process', 'peer', 'port'];

const S = {
  band: {
    display: 'flex', alignItems: 'center', flexWrap: 'wrap',
    borderBottom: '1px solid var(--fl-border)', background: 'var(--fl-panel)',
  },
  bandL: {
    display: 'flex', alignItems: 'baseline', gap: 14,
    padding: '8px 14px', flex: '1 1 auto', flexWrap: 'wrap',
  },
  bandR: { display: 'flex', alignItems: 'center', gap: 12, padding: '8px 14px', flex: '0 0 auto', flexWrap: 'wrap' },
  stat: { fontFamily: 'var(--f-mono)', fontSize: 11, color: 'var(--fl-muted)', whiteSpace: 'nowrap' },
  strong: { color: 'var(--fl-text)', fontWeight: 600 },
  sep: { width: 1, alignSelf: 'stretch', background: 'var(--fl-border2)', margin: '6px 0' },
  seg: { display: 'flex', fontFamily: 'var(--f-mono)', fontSize: 11 },
  th: {
    fontFamily: 'var(--f-mono)', fontSize: 9, letterSpacing: '0.1em', textTransform: 'uppercase',
    color: 'var(--fl-muted)', fontWeight: 700, textAlign: 'left',
    padding: '7px 12px', borderBottom: '1px solid var(--fl-border)',
  },
  td: {
    padding: '0 12px', height: 28, borderBottom: '1px solid var(--fl-border2)',
    fontFamily: 'var(--f-mono)', fontSize: 10, color: 'var(--fl-dim)',
  },
  qual: { fontSize: 9, color: 'var(--fl-muted)', marginLeft: 5 },
  foot: {
    padding: '9px 14px', borderTop: '1px solid var(--fl-border)',
    fontFamily: 'var(--f-mono)', fontSize: 11, color: 'var(--fl-muted)',
  },
  empty: { padding: '28px 16px', textAlign: 'center', color: 'var(--fl-muted)', fontSize: 13 },
};

const thOrder = { ...S.th, color: 'var(--fl-accent)' };
const num     = { ...S.td, textAlign: 'right', color: 'var(--fl-text)' };

const Dash = () => <span style={{ color: 'var(--fl-border)' }}>—</span>;

function Port({ port, protocol }) {
  if (port === null || port === undefined) return <Dash />;
  const alert = isCleartextPort(port);
  return (
    <>
      <span style={{ color: alert ? 'var(--fl-danger)' : 'var(--fl-dim)' }}>{`:${port}`}</span>
      {protocol ? <span style={S.qual}>{protocol}</span> : null}
    </>
  );
}

function Peer({ value, onSelect }) {
  const { head, tail } = splitAddressTail(value);
  const inner = (
    <>
      {head ? <span style={{ color: 'var(--fl-muted)' }}>{head}</span> : null}
      <span style={{ color: 'var(--fl-dim)' }}>{tail}</span>
    </>
  );
  if (!onSelect) return inner;
  return (
    <button
      type="button"
      title={value}
      onClick={() => onSelect(value)}
      style={{ background: 'none', border: 0, padding: 0, font: 'inherit', cursor: 'pointer', textAlign: 'left' }}
    >{inner}</button>
  );
}

export default function LinkRegister({ data, loading = false, error = null, onSelectPeer, declarations, controls, trailing }) {
  const { t } = useTranslation();
  const [view, setView] = useState('process');

  const rows = data?.rows || [];
  const totals = data?.totals || null;
  const groups = useMemo(() => ({
    process: byProcess(rows),
    peer: byPeer(rows),
    port: byPort(rows),
  }), [rows]);

  const proc = (p) => (p === null
    ? <span style={{ color: 'var(--fl-muted)', fontStyle: 'italic' }}>{t('networkMap.register.unattributed')}</span>
    : <span style={{ color: 'var(--fl-text)' }}>{p}</span>);

  const zoneCell = (peer, z) => {
    const zone = zoneOf({ id: peer, type: z }, declarations);
    if (!zone.zone) return <Dash />;
    if (zone.source === 'declared') {
      return (
        <>
          <span style={{ color: 'var(--fl-warn)' }}>{t(`networkMap.zone.${zone.zone}`)}</span>
          <span style={S.qual}>{t('networkMap.register.declared')}</span>
        </>
      );
    }
    return <span style={{ color: 'var(--fl-muted)' }}>{t(`networkMap.zone.${zone.zone}`)}</span>;
  };

  const stateCell = (state, process) => {
    if (!state) return <Dash />;
    return <span style={{ fontSize: 9, color: process === null ? 'var(--fl-gold)' : 'var(--fl-muted)' }}>{state}</span>;
  };

  const body = () => {
    if (loading) return <div style={S.empty}>{t('networkMap.loading_graph')}</div>;
    if (error)   return <div style={S.empty}>{String(error)}</div>;
    if (!rows.length) {
      return (
        <div style={S.empty}>
          <div style={{ color: 'var(--fl-dim)' }}>{t('networkMap.register.empty')}</div>
          <div style={{ marginTop: 6, fontSize: 12, maxWidth: '60ch', margin: '6px auto 0' }}>
            {t('networkMap.register.empty_hint')}
          </div>
        </div>
      );
    }

    return (
      <table style={{ borderCollapse: 'collapse', width: '100%' }}>
        {view === 'process' && (
          <>
            <thead><tr>
              <th style={{ ...thOrder, width: '16%' }}>{t('networkMap.register.process')}</th>
              <th style={{ ...S.th, width: '26%' }}>{t('networkMap.register.peer')}</th>
              <th style={{ ...S.th, width: '11%' }}>{t('networkMap.register.port')}</th>
              <th style={{ ...S.th, width: '11%' }}>{t('networkMap.register.state')}</th>
              <th style={{ ...S.th, width: '13%' }}>{t('networkMap.register.zone')}</th>
              <th style={{ ...thOrder, textAlign: 'right', width: '9%' }}>{t('networkMap.register.conn')}</th>
            </tr></thead>
            <tbody>
              {groups.process.map(g => g.links.map((l, i) => (
                <tr key={`${g.process}|${l.peer}|${l.port}|${l.protocol}`}>
                  <td style={{ ...S.td, borderTop: i === 0 ? '1px solid var(--fl-border2)' : undefined }}>
                    {i === 0 ? proc(g.process) : <Dash />}
                  </td>
                  <td style={S.td}><Peer value={l.peer} onSelect={onSelectPeer} /></td>
                  <td style={S.td}><Port port={l.port} protocol={l.protocol} /></td>
                  <td style={S.td}>{stateCell(l.socket_state, g.process)}</td>
                  <td style={S.td}>{zoneCell(l.peer, l.zone)}</td>
                  <td style={num}>{formatCount(l.connections)}</td>
                </tr>
              )))}
            </tbody>
          </>
        )}

        {view === 'peer' && (
          <>
            <thead><tr>
              <th style={{ ...thOrder, width: '30%' }}>{t('networkMap.register.peer')}</th>
              <th style={{ ...S.th, width: '11%' }}>{t('networkMap.register.port')}</th>
              <th style={{ ...S.th, width: '13%' }}>{t('networkMap.register.zone')}</th>
              <th style={S.th}>{t('networkMap.register.process')}</th>
              <th style={{ ...thOrder, textAlign: 'right', width: '9%' }}>{t('networkMap.register.total')}</th>
            </tr></thead>
            <tbody>
              {groups.peer.map(g => (
                <tr key={`${g.peer}|${g.port}|${g.protocol}`}>
                  <td style={S.td}><Peer value={g.peer} onSelect={onSelectPeer} /></td>
                  <td style={S.td}><Port port={g.port} protocol={g.protocol} /></td>
                  <td style={S.td}>{zoneCell(g.peer, g.zone)}</td>
                  <td style={S.td}>
                    {g.processes.map((p, i) => (
                      <span key={`${p.process}`}>
                        {i > 0 ? <span style={{ color: 'var(--fl-border)' }}> · </span> : null}
                        {proc(p.process)}<span style={S.qual}>{formatCount(p.connections)}</span>
                      </span>
                    ))}
                  </td>
                  <td style={num}>{formatCount(g.connections)}</td>
                </tr>
              ))}
            </tbody>
          </>
        )}

        {view === 'port' && (
          <>
            <thead><tr>
              <th style={{ ...thOrder, width: '11%' }}>{t('networkMap.register.port')}</th>
              <th style={{ ...S.th, width: '20%' }}>{t('networkMap.register.service')}</th>
              <th style={{ ...S.th, textAlign: 'right', width: '10%' }}>{t('networkMap.register.peers')}</th>
              <th style={S.th}>{t('networkMap.register.process')}</th>
              <th style={{ ...thOrder, textAlign: 'right', width: '9%' }}>{t('networkMap.register.conn')}</th>
            </tr></thead>
            <tbody>
              {groups.port.map(g => (
                <tr key={String(g.port)}>
                  <td style={S.td}><Port port={g.port} /></td>
                  <td style={{ ...S.td, fontFamily: 'var(--f-ui)', fontSize: 11 }}>
                    {portService(g.port) || <Dash />}
                  </td>
                  <td style={num}>{formatCount(g.peers)}</td>
                  <td style={S.td}>
                    {g.processes.map((p, i) => (
                      <span key={String(p)}>
                        {i > 0 ? <span style={{ color: 'var(--fl-border)' }}>, </span> : null}
                        {proc(p)}
                      </span>
                    ))}
                  </td>
                  <td style={num}>{formatCount(g.connections)}</td>
                </tr>
              ))}
            </tbody>
          </>
        )}
      </table>
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <div style={S.band}>
        <div style={S.bandL}>
          {(data?.machines || []).map(m => (
            <span key={m} style={S.stat}><b style={S.strong}>{m}</b></span>
          ))}
          <span style={S.stat}>{t('networkMap.register.links', { count: totals?.links || 0 })}</span>
          <span style={S.stat}>{t('networkMap.connections_count', { count: totals?.connections || 0 })}</span>
          <span style={S.stat}>{t('networkMap.register.peers_count', { count: totals?.peers || 0 })}</span>
        </div>
        <div style={S.sep} />
        <div style={S.bandR}>
          {controls}
          <span style={S.seg} role="tablist">
            {VIEWS.map(v => (
              <button
                key={v}
                type="button"
                role="tab"
                aria-selected={view === v}
                onClick={() => setView(v)}
                style={{
                  padding: '3px 10px', background: 'none', border: 0,
                  borderBottom: `1px solid ${view === v ? 'var(--fl-accent)' : 'transparent'}`,
                  color: view === v ? 'var(--fl-text)' : 'var(--fl-muted)',
                  font: 'inherit', cursor: 'pointer',
                }}
              >{t(`networkMap.register.by_${v}`)}</button>
            ))}
          </span>
          {trailing}
        </div>
      </div>

      <div style={{ flex: '1 1 auto', overflow: 'auto' }}>{body()}</div>

      {rows.length > 0 && (
        <div style={S.foot}>
          <span>{t('networkMap.register.attribution', {
            attributed: formatCount(totals?.attributed || 0),
            total: formatCount(totals?.connections || 0),
          })}</span>
          {(totals?.unattributed_states || []).map(s => (
            <span key={s.state}>
              <span style={{ color: 'var(--fl-border)' }}> · </span>
              <span style={{ color: 'var(--fl-gold)' }}>
                {t('networkMap.register.lost', { count: s.count, state: s.state })}
              </span>
            </span>
          ))}
          <div style={{ marginTop: 4 }}>
            {totals?.observed_distinct === 1
              ? t('networkMap.register.one_instant', { at: totals.observed_from })
              : totals?.observed_distinct > 1
                ? t('networkMap.register.instants', {
                  count: totals.observed_distinct,
                  from: totals.observed_from,
                  to: totals.observed_to,
                })
                : t('networkMap.register.no_instant')}
          </div>
        </div>
      )}
    </div>
  );
}
