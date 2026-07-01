import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Crosshair, AlertTriangle, Clock, RefreshCw, ShieldCheck, ChevronRight } from 'lucide-react';
import { triageAPI } from '../utils/api';
import AlertInbox from '../components/triage/AlertInbox';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
const UI   = 'var(--f-ui, "Inter", sans-serif)';

const SEV = {
  critical: { key: 'triage.severity.critical', color: 'var(--fl-danger)' },
  high:     { key: 'triage.severity.high',     color: 'var(--fl-warn)' },
  medium:   { key: 'triage.severity.medium',   color: 'var(--fl-gold)' },
};
const SEV_ORDER = ['critical', 'high', 'medium'];

const TYPE_ICON = { detection: Crosshair, quarantine: AlertTriangle, deadline: Clock };

function itemLabel(it, t) {
  if (it.type === 'detection') return t('triage.item_detection', { count: it.count, severity: t(SEV[it.severity]?.key || SEV.high.key) });
  if (it.type === 'quarantine') return `${t('triage.item_quarantine')}${it.evidence ? ` · ${it.evidence}` : ''}`;
  if (it.type === 'deadline') return t('triage.item_deadline', { hours: it.hours_remaining });
  return it.type;
}
const itemAction = (it, t) => it.type === 'detection' ? t('triage.action_detections') : it.type === 'quarantine' ? t('triage.action_inspect') : t('triage.action_open_case');

export default function TriagePage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [tab, setTab]         = useState('inbox');   // 'inbox' = persistent alerts, 'queue' = live attention
  const [items, setItems]     = useState([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    triageAPI.queue()
      .then(r => setItems(r.data?.items || []))
      .catch(() => setItems([]))
      .finally(() => setLoading(false));
  }, []);
  useEffect(() => { load(); }, [load]);

  const grouped = SEV_ORDER.map(sev => ({ sev, list: items.filter(i => i.severity === sev) })).filter(g => g.list.length);

  return (
    <div style={{ padding: '18px 22px', background: 'var(--fl-bg)', minHeight: '100%' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, marginBottom: 4 }}>
        <h1 style={{ fontSize: 22, fontWeight: 600, margin: 0, color: 'var(--fl-text)', fontFamily: 'var(--f-display, var(--f-ui))', letterSpacing: '-0.02em' }}>
          {t('triage.title')}
        </h1>
        {tab === 'queue' && <span style={{ fontSize: 12, fontFamily: MONO, color: 'var(--fl-muted)' }}>{t('triage.count', { count: items.length })}</span>}
        <span style={{ flex: 1 }} />
        {tab === 'queue' && (
          <button onClick={load} title={t('common.refresh')}
            style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '4px 10px', borderRadius: 6, cursor: 'pointer', background: 'transparent', color: 'var(--fl-muted)', border: '1px solid var(--fl-border)', fontFamily: MONO, fontSize: 11 }}>
            <RefreshCw size={12} strokeWidth={1.6} style={{ animation: loading ? 'fl-spin 0.8s linear infinite' : 'none' }} /> {t('common.refresh')}
          </button>
        )}
      </div>

      {/* Inbox (persistent alerts) ⇆ Live queue (computed attention) */}
      <div style={{ display: 'flex', gap: 6, margin: '4px 0 18px' }}>
        {[['inbox', 'triage.inbox.tab'], ['queue', 'triage.queue_tab']].map(([k, lbl]) => (
          <button key={k} onClick={() => setTab(k)}
            style={{ padding: '6px 14px', borderRadius: 7, cursor: 'pointer', fontFamily: MONO, fontSize: 12,
              background: tab === k ? 'color-mix(in srgb, var(--fl-accent) 13%, transparent)' : 'transparent',
              color: tab === k ? 'var(--fl-text)' : 'var(--fl-muted)',
              border: `1px solid ${tab === k ? 'color-mix(in srgb, var(--fl-accent) 45%, transparent)' : 'var(--fl-border)'}` }}>
            {t(lbl)}
          </button>
        ))}
      </div>

      {tab === 'inbox' ? <AlertInbox /> : (
      <>
      <p style={{ fontSize: 13, color: 'var(--fl-dim)', fontFamily: UI, margin: '0 0 20px' }}>
        {t('triage.subtitle')}
      </p>

      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {[0,1,2,3,4].map(i => <div key={i} className="fl-skeleton" style={{ height: 48, borderRadius: 8, background: 'var(--fl-card)' }} />)}
        </div>
      ) : items.length === 0 ? (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '64px 16px', gap: 10 }}>
          <ShieldCheck size={28} strokeWidth={1.6} style={{ color: 'var(--fl-ok)' }} />
          <span style={{ fontSize: 13, fontFamily: MONO, color: 'var(--fl-muted)' }}>{t('triage.empty')}</span>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          {grouped.map(({ sev, list }) => (
            <div key={sev}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <span style={{ width: 8, height: 8, borderRadius: 2, background: SEV[sev].color }} />
                <span style={{ fontSize: 10.5, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.12em', color: SEV[sev].color, fontWeight: 700 }}>{t(SEV[sev].key)}</span>
                <span style={{ fontSize: 10, fontFamily: MONO, color: 'var(--fl-muted)' }}>{list.length}</span>
              </div>
              <div style={{ border: '1px solid var(--fl-border)', borderRadius: 8, overflow: 'hidden' }}>
                {list.map((it, i) => {
                  const TIcon = TYPE_ICON[it.type] || Crosshair;
                  return (
                    <div key={i}
                      onClick={() => navigate(`/cases/${it.case_id}/${it.tab || 'evidence'}`)}
                      style={{ display: 'grid', gridTemplateColumns: 'auto 1fr auto', alignItems: 'center', gap: 12, padding: '10px 14px', cursor: 'pointer', borderLeft: `3px solid ${SEV[sev].color}`, borderBottom: i < list.length - 1 ? '1px solid var(--fl-border2)' : 'none' }}
                      onMouseEnter={e => { e.currentTarget.style.background = 'var(--fl-surface-hover)'; }}
                      onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}>
                      <TIcon size={15} strokeWidth={1.6} style={{ color: SEV[sev].color }} />
                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontSize: 12.5, color: 'var(--fl-text)', fontFamily: UI, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{itemLabel(it, t)}</div>
                        <div style={{ fontSize: 10.5, color: 'var(--fl-muted)', fontFamily: MONO, marginTop: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {it.case_number}{it.title ? ` · ${it.title}` : ''}
                        </div>
                      </div>
                      <span style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: 11, fontFamily: MONO, color: 'var(--fl-accent)', flexShrink: 0 }}>
                        {itemAction(it, t)} <ChevronRight size={12} strokeWidth={1.6} />
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}
      </>
      )}
    </div>
  );
}
