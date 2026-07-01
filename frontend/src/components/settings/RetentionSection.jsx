import { useState, useEffect } from 'react';
import { Search, Trash2, ShieldAlert, Eye, Play, ShieldCheck } from 'lucide-react';
import { casesAPI, settingsAPI } from '../../utils/api';
import { MONO, UI, SectionHead, Row, Toggle, Btn, Input, Skeletons, Empty, Msg } from './shared';
import { useTranslation } from 'react-i18next';

export default function RetentionSection() {
  const { t } = useTranslation();
  // ── Auto-retention config ──────────────────────────────────────────────────
  const [cfg, setCfg]         = useState(null);   // { enabled, days }
  const [savingCfg, setSavingCfg] = useState(false);
  const [cfgMsg, setCfgMsg]   = useState('');
  const [preview, setPreview] = useState(null);   // { count, eligible }
  const [previewing, setPreviewing] = useState(false);
  const [running, setRunning] = useState(false);
  const [confirmRun, setConfirmRun] = useState(false);

  // ── Manual purge list ──────────────────────────────────────────────────────
  const [cases, setCases]     = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch]   = useState('');
  const [target, setTarget]   = useState(null);
  const [confirmTxt, setConfirmTxt] = useState('');
  const [purging, setPurging] = useState(false);
  const [msg, setMsg]         = useState('');

  const loadCfg = () => settingsAPI.getRetention().then(r => setCfg(r.data)).catch(() => setCfg({ enabled: false, days: 365 }));
  const loadCases = () => {
    setLoading(true);
    casesAPI.list().then(r => setCases(r.data?.cases || r.data || [])).catch(() => setCases([])).finally(() => setLoading(false));
  };
  useEffect(() => { loadCfg(); loadCases(); }, []);

  const saveCfg = async () => {
    setSavingCfg(true); setCfgMsg('');
    try { const r = await settingsAPI.setRetention(cfg); setCfg(r.data); setCfgMsg(t('settings.retention.policy_saved')); }
    catch { setCfgMsg(t('settings.messages.failed')); } finally { setSavingCfg(false); }
  };
  const doPreview = async () => {
    setPreviewing(true); setPreview(null);
    try { const r = await settingsAPI.previewRetention(cfg?.days); setPreview(r.data); }
    catch { setCfgMsg(t('settings.retention.preview_failed')); } finally { setPreviewing(false); }
  };
  const runNow = async () => {
    setRunning(true); setCfgMsg('');
    try { const r = await settingsAPI.runRetention(); setCfgMsg(t('settings.retention.purged_count', { count: r.data?.purged ?? 0 })); setConfirmRun(false); setPreview(null); loadCases(); }
    catch { setCfgMsg(t('settings.retention.purge_failed')); } finally { setRunning(false); }
  };

  const toggleExempt = async (c) => {
    const next = !c.retention_exempt;
    setCases(cs => cs.map(x => x.id === c.id ? { ...x, retention_exempt: next } : x));  // optimistic
    try { await settingsAPI.setCaseExempt(c.id, next); }
    catch { setCases(cs => cs.map(x => x.id === c.id ? { ...x, retention_exempt: !next } : x)); }
  };

  const purge = async () => {
    if (!target || confirmTxt !== target.case_number) return;
    setPurging(true); setMsg('');
    try { await casesAPI.hardDelete(target.id); setMsg(t('settings.retention.case_purged', { caseNumber: target.case_number })); setTarget(null); setConfirmTxt(''); loadCases(); }
    catch (e) { setMsg(`✗ ${e.response?.data?.error || t('settings.retention.purge_failed_plain')}`); }
    finally { setPurging(false); }
  };

  const filtered = cases.filter(c => !search || `${c.case_number} ${c.title}`.toLowerCase().includes(search.toLowerCase()));

  return (
    <>
      <SectionHead title={t('settings.retention.title')} desc={t('settings.retention.desc')} />

      {/* ── Auto-retention policy ── */}
      <div style={{ marginTop: 16, padding: 16, borderRadius: 10, border: '1px solid var(--fl-border)', background: 'var(--fl-panel)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <ShieldCheck size={14} style={{ color: 'var(--fl-accent)' }} />
          <span style={{ fontSize: 13, fontWeight: 600, fontFamily: UI, color: 'var(--fl-text)' }}>{t('settings.retention.auto_purge')}</span>
        </div>
        {!cfg ? <Skeletons n={2} h={36} /> : (
          <>
            <Row label={t('settings.retention.enable_auto')} desc={t('settings.retention.enable_auto_desc')}>
              <Toggle on={cfg.enabled} onClick={() => setCfg(c => ({ ...c, enabled: !c.enabled }))} />
            </Row>
            <Row label={t('settings.retention.delay_after_close')} desc={t('settings.retention.delay_after_close_desc')} last>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <Input type="number" min="1" value={cfg.days} onChange={e => setCfg(c => ({ ...c, days: parseInt(e.target.value, 10) || '' }))} width={90} style={{ textAlign: 'right', fontSize: 13 }} />
                <span style={{ fontSize: 12, color: 'var(--fl-muted)', fontFamily: MONO }}>{t('settings.retention.days')}</span>
              </div>
            </Row>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 14, flexWrap: 'wrap' }}>
              <Btn variant="primary" onClick={saveCfg} disabled={savingCfg}>{savingCfg ? t('settings.messages.saving') : t('common.save')}</Btn>
              <Btn onClick={doPreview} disabled={previewing}><Eye size={12} /> {previewing ? t('settings.retention.analyzing') : t('settings.retention.preview')}</Btn>
              {preview && preview.count > 0 && (
                confirmRun
                  ? <Btn variant="danger" onClick={runNow} disabled={running}>{running ? t('settings.retention.purging') : t('settings.retention.confirm_purge_count', { count: preview.count })}</Btn>
                  : <Btn variant="danger" onClick={() => setConfirmRun(true)}><Play size={12} /> {t('settings.retention.run_now')}</Btn>
              )}
              <Msg msg={cfgMsg} />
            </div>

            {preview && (
              <div style={{ marginTop: 12, padding: 12, borderRadius: 8, border: '1px solid var(--fl-border2)', background: 'var(--fl-bg)' }}>
                <div style={{ fontSize: 11.5, fontFamily: MONO, color: preview.count > 0 ? 'var(--fl-warn)' : 'var(--fl-ok)', marginBottom: preview.count > 0 ? 8 : 0 }}>
                  {preview.count === 0 ? t('settings.retention.no_eligible') : t('settings.retention.preview_count', { count: preview.count, days: preview.days })}
                </div>
                {preview.eligible?.slice(0, 50).map(c => (
                  <div key={c.id} style={{ display: 'flex', gap: 10, padding: '3px 0', fontSize: 11, fontFamily: MONO }}>
                    <span style={{ color: 'var(--fl-danger)', minWidth: 120 }}>{c.case_number}</span>
                    <span style={{ flex: 1, color: 'var(--fl-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.title}</span>
                    <span style={{ color: 'var(--fl-muted)' }}>{t('settings.retention.closed_days_ago', { days: c.days_closed })}</span>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>

      {/* ── Manual purge + per-case exemption ── */}
      <div style={{ marginTop: 24 }}>
        <div style={{ fontSize: 13, fontWeight: 600, fontFamily: UI, color: 'var(--fl-text)', marginBottom: 4 }}>{t('settings.retention.manual_title')}</div>
        <p style={{ fontSize: 11.5, color: 'var(--fl-muted)', fontFamily: UI, margin: '0 0 12px' }}>{t('settings.retention.manual_desc')}</p>
        <div style={{ position: 'relative' }}>
          <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--fl-muted)', pointerEvents: 'none' }} />
          <Input placeholder={t('settings.retention.search_case')} value={search} onChange={e => setSearch(e.target.value)} width="100%" style={{ paddingLeft: 30 }} />
        </div>

        {loading ? <Skeletons n={3} h={38} /> : filtered.length === 0 ? <Empty text={cases.length === 0 ? t('settings.retention.no_cases') : t('settings.retention.no_results')} /> : (
          <div style={{ marginTop: 12, maxHeight: 320, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 5 }}>
            {filtered.map(c => (
              <div key={c.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', borderRadius: 6, background: 'var(--fl-bg)', border: '1px solid var(--fl-border2)' }}>
                <span style={{ fontFamily: MONO, fontSize: 11, color: 'var(--fl-danger)', flexShrink: 0, minWidth: 120 }}>{c.case_number}</span>
                <span style={{ flex: 1, fontSize: 12, color: 'var(--fl-dim)', fontFamily: UI, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.title}</span>
                {c.legal_hold && <span style={{ fontSize: 9.5, fontFamily: MONO, padding: '1px 6px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-purple) 12%, transparent)', color: 'var(--fl-purple)', border: '1px solid color-mix(in srgb, var(--fl-purple) 21%, transparent)' }}>LEGAL HOLD</span>}
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, flexShrink: 0 }} title={t('settings.retention.exempt_title')}>
                  <span style={{ fontSize: 10, fontFamily: MONO, color: c.retention_exempt ? 'var(--fl-ok)' : 'var(--fl-subtle)' }}>{t('settings.retention.exempt')}</span>
                  <Toggle on={!!c.retention_exempt} onClick={() => toggleExempt(c)} />
                </span>
                <Btn variant="danger" onClick={() => { setTarget(c); setConfirmTxt(''); setMsg(''); }}><Trash2 size={12} /> {t('settings.retention.purge')}</Btn>
              </div>
            ))}
          </div>
        )}

        {target && (
          <div style={{ marginTop: 16, padding: 16, borderRadius: 8, border: '1px solid color-mix(in srgb, var(--fl-danger) 30%, transparent)', background: 'color-mix(in srgb, var(--fl-danger) 4%, transparent)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <ShieldAlert size={15} style={{ color: 'var(--fl-danger)' }} />
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--fl-danger)', fontFamily: UI }}>{t('settings.retention.irreversible_title', { caseNumber: target.case_number })}</span>
            </div>
            <p style={{ fontSize: 11.5, color: 'var(--fl-dim)', fontFamily: UI, margin: '0 0 10px', lineHeight: 1.5 }}>
              {t('settings.retention.type_to_confirm_prefix')} <code style={{ color: 'var(--fl-danger)', fontFamily: MONO }}>{target.case_number}</code> {t('settings.retention.type_to_confirm_suffix')}
            </p>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <Input placeholder={target.case_number} value={confirmTxt} onChange={e => setConfirmTxt(e.target.value)} width={200} />
              <Btn variant="danger" onClick={purge} disabled={confirmTxt !== target.case_number || purging}>{purging ? t('settings.retention.purging') : t('settings.retention.purge_forever')}</Btn>
              <Btn onClick={() => setTarget(null)}>{t('common.cancel')}</Btn>
            </div>
          </div>
        )}
        <div style={{ marginTop: 12 }}><Msg msg={msg} /></div>
      </div>
    </>
  );
}
