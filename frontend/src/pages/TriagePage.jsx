import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Crosshair, AlertTriangle, Clock, RefreshCw, ShieldCheck, ChevronRight } from 'lucide-react';
import { triageAPI } from '../utils/api';
import AlertInbox from '../components/triage/AlertInbox';
import { markStyle } from '../components/ui/tableIdiom';
import { controlStyle, controlHover } from '../components/ui/controlIdiom';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
const UI   = 'var(--f-ui, "Inter", sans-serif)';

const SEG_ROW  = { display: 'flex', gap: 14, alignItems: 'baseline', margin: '4px 0 18px' };
const SEV_HEAD = { display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 8 };

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
  const [tab, setTab]         = useState('inbox');
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
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, marginBottom: 4 }}>
        <h1 style={{ fontSize: 22, fontWeight: 600, margin: 0, color: 'var(--fl-text)', fontFamily: 'var(--f-display, var(--f-ui))', letterSpacing: '-0.02em' }}>
          {t('triage.title')}
        </h1>
        {tab === 'queue' && <span style={{ fontSize: 12, fontFamily: MONO, color: 'var(--fl-muted)' }}>{t('triage.count', { count: items.length })}</span>}
        <span style={{ flex: 1 }} />
        {tab === 'queue' && (
          <button onClick={load} title={t('common.refresh')}
            style={controlStyle(false)} {...controlHover(false)}>
            <RefreshCw size={12} strokeWidth={1.6} style={{ animation: loading ? 'fl-spin 0.8s linear infinite' : 'none' }} /> {t('common.refresh')}
          </button>
        )}
      </div>

      <div style={SEG_ROW}>
        {[['inbox', 'triage.inbox.tab'], ['queue', 'triage.queue_tab']].map(([k, lbl]) => (
          <button key={k} onClick={() => setTab(k)}
            style={controlStyle(tab === k)} {...controlHover(tab === k)}>
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
              <div style={SEV_HEAD}>
                <span style={markStyle(SEV[sev].color)}>{t(SEV[sev].key)}</span>
                <span style={markStyle('var(--fl-muted)')}>{list.length}</span>
              </div>
              <div style={{ borderTop: '1px solid var(--fl-border)' }}>
                {list.map((it, i) => {
                  const TIcon = TYPE_ICON[it.type] || Crosshair;
                  return (
                    <div key={i}
                      onClick={() => navigate(`/cases/${it.case_id}/${it.tab || 'evidence'}`)}
                      style={{ display: 'grid', gridTemplateColumns: 'auto 1fr auto', alignItems: 'center', gap: 12, padding: '10px 14px', cursor: 'pointer', borderLeft: `3px solid ${SEV[sev].color}`, borderBottom: '1px solid var(--fl-border2)' }}
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
