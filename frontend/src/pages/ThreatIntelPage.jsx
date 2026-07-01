import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Globe, Plus, Trash2, RefreshCw, Search, AlertTriangle, CheckCircle, Loader, ChevronLeft, ChevronRight, ShieldAlert, Rss, List, GitMerge } from 'lucide-react';
import { useTheme } from '../utils/theme';
import { threatIntelAPI, casesAPI } from '../utils/api';
import TabGroup from '../components/ui/TabGroup';
import { fmtLocal } from '../utils/formatters';

const IOC_COLORS = {
  ipv4:   'var(--fl-danger)',
  ipv6:   'var(--fl-warn)',
  domain: 'var(--fl-gold)',
  url:    'var(--fl-accent)',
  email:  'var(--fl-pink)',
  md5:    'var(--fl-ok)',
  sha1:   'var(--fl-artifact-shellbags)',
  sha256: 'var(--fl-purple)',
};

const STIX_COLORS = {
  indicator:       'var(--fl-accent)',
  malware:         'var(--fl-danger)',
  'attack-pattern':'var(--fl-gold)',
};

function IocBadge({ type }) {
  const T = useTheme();
  const color = IOC_COLORS[type] || T.muted;
  return (
    <span style={{
      background: `color-mix(in srgb, ${color} 13%, transparent)`,
      color,
      border: `1px solid color-mix(in srgb, ${color} 25%, transparent)`,
      borderRadius: 4,
      padding: '1px 6px',
      fontSize: 11,
      fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
      fontWeight: 600,
      textTransform: 'uppercase',
    }}>{type || '—'}</span>
  );
}

function StixBadge({ type }) {
  const T = useTheme();
  const color = STIX_COLORS[type] || T.muted;
  return (
    <span style={{
      background: `color-mix(in srgb, ${color} 13%, transparent)`,
      color,
      border: `1px solid color-mix(in srgb, ${color} 25%, transparent)`,
      borderRadius: 4,
      padding: '1px 6px',
      fontSize: 11,
      fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
    }}>{type}</span>
  );
}

function Toast({ msg, type, onClose }) {
  const T = useTheme();
  useEffect(() => { const t = setTimeout(onClose, 4000); return () => clearTimeout(t); }, [onClose]);
  const color = type === 'error' ? 'var(--fl-danger)' : type === 'warn' ? 'var(--fl-warn)' : 'var(--fl-ok)';
  return (
    <div style={{
      position: 'fixed', bottom: 24, right: 24, zIndex: 9999,
      background: T.panel, border: `1px solid ${color}`,
      borderRadius: 8, padding: '12px 18px', maxWidth: 400,
      color: T.text, boxShadow: '0 4px 20px rgba(0,0,0,0.4)',
      display: 'flex', alignItems: 'flex-start', gap: 10,
    }}>
      {type === 'error' ? <AlertTriangle size={16} style={{ color, marginTop: 2, flexShrink: 0 }} />
        : <CheckCircle size={16} style={{ color, marginTop: 2, flexShrink: 0 }} />}
      <span style={{ fontSize: 13 }}>{msg}</span>
    </div>
  );
}

function FeedsTab({ toast }) {
  const { t } = useTranslation();
  const T = useTheme();
  const [feeds, setFeeds]       = useState([]);
  const [loading, setLoading]   = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [fetching, setFetching] = useState({});
  const [form, setForm]         = useState({
    name: '', url: '', api_root: '', collection_id: '',
    auth_type: 'none', auth_value: '',
  });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await threatIntelAPI.feeds();
      setFeeds(Array.isArray(res.data) ? res.data : []);
    } catch { toast(t('threat_intel.feeds.load_error'), 'error'); }
    finally { setLoading(false); }
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  async function handleAdd(e) {
    e.preventDefault();
    try {
      await threatIntelAPI.addFeed(form);
      setShowModal(false);
      setForm({ name: '', url: '', api_root: '', collection_id: '', auth_type: 'none', auth_value: '' });
      toast(t('threat_intel.feeds.added'), 'ok');
      load();
    } catch (err) {
      toast(err.response?.data?.error || t('threat_intel.feeds.add_error'), 'error');
    }
  }

  async function handleDelete(id) {
    if (!confirm(t('threat_intel.feeds.delete_confirm'))) return;
    try {
      await threatIntelAPI.deleteFeed(id);
      toast(t('threat_intel.feeds.deleted'), 'ok');
      load();
    } catch { toast(t('threat_intel.feeds.delete_error'), 'error'); }
  }

  async function handleFetch(id) {
    setFetching(f => ({ ...f, [id]: true }));
    try {
      const res = await threatIntelAPI.fetchFeed(id);
      toast(res.data.message, 'ok');
      load();
    } catch (err) {
      toast(err.response?.data?.error || t('threat_intel.feeds.fetch_error'), 'error');
    } finally {
      setFetching(f => ({ ...f, [id]: false }));
    }
  }

  const inputStyle = {
    background: T.inputBg, border: `1px solid ${T.border}`,
    borderRadius: 6, padding: '7px 10px', color: T.text,
    fontSize: 13, width: '100%', outline: 'none',
  };
  const labelStyle = { fontSize: 12, color: T.muted, marginBottom: 4, display: 'block' };

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <span style={{ color: T.muted, fontSize: 13 }}>
          {t('threat_intel.feeds.count', { count: feeds.length })}
        </span>
        <button onClick={() => setShowModal(true)} style={{
          background: T.accent, color: '#fff', border: 'none',
          borderRadius: 6, padding: '7px 14px', cursor: 'pointer',
          display: 'flex', alignItems: 'center', gap: 6, fontSize: 13,
        }}>
          <Plus size={14} /> {t('threat_intel.feeds.add')}
        </button>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: 40, color: T.muted }}>
          <Loader size={20} style={{ animation: 'spin 1s linear infinite' }} />
        </div>
      ) : feeds.length === 0 ? (
        <div style={{
          border: `1px dashed ${T.border}`, borderRadius: 8,
          padding: 40, textAlign: 'center', color: T.muted,
        }}>
          <Globe size={32} style={{ marginBottom: 12, opacity: 0.4 }} />
          <div style={{ fontSize: 14 }}>{t('threat_intel.feeds.empty_title')}</div>
          <div style={{ fontSize: 12, marginTop: 6 }}>{t('threat_intel.feeds.empty_sub')}</div>
        </div>
      ) : (
        <div style={{ border: `1px solid ${T.border}`, borderRadius: 8, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ background: `color-mix(in srgb, ${T.accent} 6%, transparent)`, borderBottom: `1px solid ${T.border}` }}>
                {[t('threat_intel.feeds.col_name'), t('threat_intel.feeds.col_url'), t('threat_intel.feeds.col_auth'), t('threat_intel.feeds.col_indicators'), t('threat_intel.feeds.col_sync'), t('threat_intel.feeds.col_actions')].map(h => (
                  <th key={h} style={{ padding: '9px 12px', textAlign: 'left', color: T.muted, fontWeight: 600, fontSize: 11, textTransform: 'uppercase' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {feeds.map((f, i) => (
                <tr key={f.id} style={{ borderBottom: i < feeds.length - 1 ? `1px solid ${T.border}` : 'none' }}>
                  <td style={{ padding: '10px 12px', color: T.text, fontWeight: 500 }}>{f.name}</td>
                  <td style={{ padding: '10px 12px', color: T.dim, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {f.url}
                  </td>
                  <td style={{ padding: '10px 12px', color: T.muted, fontSize: 12 }}>{f.auth_type}</td>
                  <td style={{ padding: '10px 12px', color: T.text, fontWeight: 600 }}>
                    {f.indicator_count || 0}
                  </td>
                  <td style={{ padding: '10px 12px', color: T.muted, fontSize: 12 }}>
                    {f.last_fetched ? fmtLocal(f.last_fetched) : t('common.never')}
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button
                        onClick={() => handleFetch(f.id)}
                        disabled={fetching[f.id]}
                        title={t('threat_intel.feeds.sync')}
                        style={{
                          background: `color-mix(in srgb, ${T.accent} 13%, transparent)`, color: T.accent,
                          border: `1px solid color-mix(in srgb, ${T.accent} 25%, transparent)`, borderRadius: 5,
                          padding: '4px 8px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
                        }}
                      >
                        {fetching[f.id]
                          ? <Loader size={12} style={{ animation: 'spin 1s linear infinite' }} />
                          : <RefreshCw size={12} />}
                        <span style={{ fontSize: 11 }}>{t('threat_intel.feeds.sync_short')}</span>
                      </button>
                      <button
                        onClick={() => handleDelete(f.id)}
                        title={t('common.delete')}
                        style={{
                          background: `color-mix(in srgb, ${T.danger} 8%, transparent)`, color: T.danger,
                          border: `1px solid color-mix(in srgb, ${T.danger} 25%, transparent)`, borderRadius: 5,
                          padding: '4px 7px', cursor: 'pointer',
                        }}
                      >
                        <Trash2 size={12} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showModal && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 1000,
          background: 'rgba(0,0,0,0.6)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <div style={{
            background: T.panel, borderRadius: 8,
            border: `1px solid ${T.border}`,
            padding: 28, width: 500, maxWidth: '95vw',
          }}>
              <h3 style={{ color: T.text, margin: '0 0 20px', fontSize: 15, fontWeight: 600 }}>
              {t('threat_intel.feeds.modal_title')}
            </h3>
            <form onSubmit={handleAdd} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <label style={labelStyle}>{t('threat_intel.feeds.name')} *</label>
                <input style={inputStyle} value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} required placeholder={t('threat_intel.feeds.name_ph')} />
              </div>
              <div>
                <label style={labelStyle}>{t('threat_intel.feeds.url')} *</label>
                <input style={inputStyle} value={form.url} onChange={e => setForm(f => ({ ...f, url: e.target.value }))} required placeholder={t('threat_intel.feeds.url_ph')} />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <label style={labelStyle}>{t('threat_intel.feeds.api_root')}</label>
                  <input style={inputStyle} value={form.api_root} onChange={e => setForm(f => ({ ...f, api_root: e.target.value }))} placeholder={t('common.optional')} />
                </div>
                <div>
                  <label style={labelStyle}>Collection ID</label>
                  <input style={inputStyle} value={form.collection_id} onChange={e => setForm(f => ({ ...f, collection_id: e.target.value }))} placeholder={t('common.optional')} />
                </div>
              </div>
              <div>
                <label style={labelStyle}>{t('threat_intel.feeds.auth')}</label>
                <select style={{ ...inputStyle }} value={form.auth_type} onChange={e => setForm(f => ({ ...f, auth_type: e.target.value }))}>
                  <option value="none">{t('common.none')}</option>
                  <option value="bearer">Bearer Token</option>
                  <option value="basic">Basic (user:password)</option>
                </select>
              </div>
              {form.auth_type !== 'none' && (
                <div>
                  <label style={labelStyle}>
                    {form.auth_type === 'bearer' ? 'Token' : 'user:password'}
                  </label>
                  <input
                    type="password" style={inputStyle}
                    value={form.auth_value}
                    onChange={e => setForm(f => ({ ...f, auth_value: e.target.value }))}
                    placeholder={form.auth_type === 'bearer' ? 'Bearer token...' : 'user:password'}
                  />
                </div>
              )}
              <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', marginTop: 8 }}>
                <button type="button" onClick={() => setShowModal(false)} style={{
                  background: T.inputBg, color: T.dim, border: `1px solid ${T.border}`,
                  borderRadius: 6, padding: '8px 16px', cursor: 'pointer', fontSize: 13,
                }}>{t('common.cancel')}</button>
                <button type="submit" style={{
                  background: T.accent, color: '#fff', border: 'none',
                  borderRadius: 6, padding: '8px 18px', cursor: 'pointer', fontSize: 13, fontWeight: 600,
                }}>{t('common.add')}</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

const IOC_TYPES = ['', 'ipv4', 'ipv6', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256'];

function IndicatorsTab() {
  const { t } = useTranslation();
  const T = useTheme();
  const [data, setData]             = useState({ records: [], total: 0, page: 1, limit: 50, total_pages: 1 });
  const [loading, setLoading]       = useState(false);
  const [stats, setStats]           = useState(null);
  const [q, setQ]                   = useState('');
  const [iocType, setIocType]       = useState('');
  const [stixType, setStixType]     = useState('');
  const [page, setPage]             = useState(1);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [res, sRes] = await Promise.all([
        threatIntelAPI.indicators({ q: q || undefined, ioc_type: iocType || undefined, stix_type: stixType || undefined, page, limit: 50 }),
        !stats ? threatIntelAPI.stats() : Promise.resolve(null),
      ]);
      setData(res.data);
      if (sRes) setStats(sRes.data);
    } catch (_e) {}
    finally { setLoading(false); }
  }, [q, iocType, stixType, page, stats]);

  useEffect(() => { load(); }, [load]);

  const handleSearch = (e) => { e.preventDefault(); setPage(1); load(); };

  return (
    <div>
      
      {stats && (
        <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>
          <div style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 8, padding: '10px 16px', fontSize: 13 }}>
            <span style={{ color: T.muted, fontSize: 11 }}>{t('common.all')}</span>
            <div style={{ color: T.text, fontWeight: 700, fontSize: 20 }}>{stats.total.toLocaleString()}</div>
          </div>
          {stats.by_type.slice(0, 4).map(b => (
            <div key={b.key} style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 8, padding: '10px 16px', fontSize: 13 }}>
              <span style={{ color: T.muted, fontSize: 11 }}><StixBadge type={b.key} /></span>
              <div style={{ color: T.text, fontWeight: 700, fontSize: 18, marginTop: 4 }}>{b.doc_count.toLocaleString()}</div>
            </div>
          ))}
        </div>
      )}

      <form onSubmit={handleSearch} style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', flex: 1, minWidth: 200, background: T.inputBg, border: `1px solid ${T.border}`, borderRadius: 6 }}>
          <Search size={14} style={{ margin: '0 8px', color: T.muted, alignSelf: 'center' }} />
          <input
            style={{ flex: 1, background: 'none', border: 'none', color: T.text, fontSize: 13, padding: '7px 0', outline: 'none' }}
            placeholder={t('threat_intel.indicators.search_ph')}
            value={q} onChange={e => setQ(e.target.value)}
          />
        </div>
        <select value={iocType} onChange={e => { setIocType(e.target.value); setPage(1); }}
          style={{ background: T.inputBg, border: `1px solid ${T.border}`, borderRadius: 6, color: T.text, padding: '7px 10px', fontSize: 13 }}>
          <option value="">{t('threat_intel.indicators.all_ioc_types')}</option>
          {IOC_TYPES.filter(Boolean).map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
        </select>
        <select value={stixType} onChange={e => { setStixType(e.target.value); setPage(1); }}
          style={{ background: T.inputBg, border: `1px solid ${T.border}`, borderRadius: 6, color: T.text, padding: '7px 10px', fontSize: 13 }}>
          <option value="">{t('threat_intel.indicators.all_stix_types')}</option>
          <option value="indicator">{t('threat_intel.indicators.stix_indicator')}</option>
          <option value="malware">{t('threat_intel.indicators.stix_malware')}</option>
          <option value="attack-pattern">{t('threat_intel.indicators.stix_attack_pattern')}</option>
        </select>
        <button type="submit" style={{
          background: T.accent, color: '#fff', border: 'none',
          borderRadius: 6, padding: '7px 16px', cursor: 'pointer', fontSize: 13,
        }}>{t('common.search')}</button>
      </form>

      {loading ? (
        <div style={{ textAlign: 'center', padding: 40, color: T.muted }}>
          <Loader size={20} style={{ animation: 'spin 1s linear infinite' }} />
        </div>
      ) : data.records.length === 0 ? (
        <div style={{ border: `1px dashed ${T.border}`, borderRadius: 8, padding: 40, textAlign: 'center', color: T.muted }}>
          <ShieldAlert size={32} style={{ marginBottom: 12, opacity: 0.4 }} />
          <div style={{ fontSize: 14 }}>{t('threat_intel.indicators.empty_title')}</div>
          <div style={{ fontSize: 12, marginTop: 6 }}>{t('threat_intel.indicators.empty_sub')}</div>
        </div>
      ) : (
        <>
          <div style={{ border: `1px solid ${T.border}`, borderRadius: 8, overflow: 'hidden', marginBottom: 12 }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ background: `color-mix(in srgb, ${T.accent} 6%, transparent)`, borderBottom: `1px solid ${T.border}` }}>
                  {[t('threat_intel.indicators.col_stix'), t('threat_intel.indicators.col_ioc_type'), t('threat_intel.indicators.col_value'), t('common.name'), t('threat_intel.indicators.col_labels'), t('threat_intel.indicators.col_confidence'), t('threat_intel.indicators.col_source'), t('threat_intel.indicators.col_modified')].map(h => (
                    <th key={h} style={{ padding: '8px 10px', textAlign: 'left', color: T.muted, fontWeight: 600, fontSize: 10, textTransform: 'uppercase', whiteSpace: 'nowrap' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.records.map((r, i) => (
                  <tr key={r.stix_id || i} style={{ borderBottom: i < data.records.length - 1 ? `1px solid ${T.border}` : 'none' }}>
                    <td style={{ padding: '8px 10px' }}><StixBadge type={r.stix_type} /></td>
                    <td style={{ padding: '8px 10px' }}>{r.ioc_type ? <IocBadge type={r.ioc_type} /> : <span style={{ color: T.muted }}>—</span>}</td>
                    <td style={{ padding: '8px 10px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: T.text, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {r.ioc_value || '—'}
                    </td>
                    <td style={{ padding: '8px 10px', color: T.text, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {r.name}
                    </td>
                    <td style={{ padding: '8px 10px', maxWidth: 140 }}>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                        {(r.labels || []).slice(0, 2).map(l => (
                          <span key={l} style={{ background: `color-mix(in srgb, ${T.accent} 8%, transparent)`, color: T.accent, borderRadius: 3, padding: '0 5px', fontSize: 10 }}>{l}</span>
                        ))}
                      </div>
                    </td>
                    <td style={{ padding: '8px 10px', color: r.confidence !== null ? T.text : T.muted, textAlign: 'center' }}>
                      {r.confidence !== null ? r.confidence : '—'}
                    </td>
                    <td style={{ padding: '8px 10px', color: T.muted, whiteSpace: 'nowrap' }}>{r.source_name}</td>
                    <td style={{ padding: '8px 10px', color: T.muted, whiteSpace: 'nowrap' }}>
                      {r.modified ? new Date(r.modified).toLocaleDateString('fr-FR') : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ color: T.muted, fontSize: 12 }}>
              {t('threat_intel.indicators.range', { from: ((page - 1) * 50 + 1), to: Math.min(page * 50, data.total), total: data.total.toLocaleString() })}
            </span>
            <div style={{ display: 'flex', gap: 6 }}>
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                style={{ background: T.inputBg, border: `1px solid ${T.border}`, borderRadius: 5, padding: '5px 10px', color: page === 1 ? T.muted : T.text, cursor: page === 1 ? 'default' : 'pointer' }}>
                <ChevronLeft size={13} />
              </button>
              <span style={{ color: T.dim, fontSize: 12, alignSelf: 'center', padding: '0 6px' }}>
                {t('threat_intel.indicators.page', { page, total_pages: data.total_pages })}
              </span>
              <button
                onClick={() => setPage(p => Math.min(data.total_pages, p + 1))} disabled={page >= data.total_pages}
                style={{ background: T.inputBg, border: `1px solid ${T.border}`, borderRadius: 5, padding: '5px 10px', color: page >= data.total_pages ? T.muted : T.text, cursor: page >= data.total_pages ? 'default' : 'pointer' }}>
                <ChevronRight size={13} />
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function CorrelationsTab({ toast }) {
  const { t } = useTranslation();
  const T = useTheme();
  const [cases, setCases]               = useState([]);
  const [selectedCase, setSelectedCase] = useState('');
  const [correlations, setCorrelations] = useState([]);
  const [running, setRunning]           = useState(false);
  const [loading, setLoading]           = useState(false);

  useEffect(() => {
    casesAPI.list().then(r => setCases(r.data?.cases || r.data || [])).catch(() => {});
  }, []);

  async function loadCorrelations(caseId) {
    setLoading(true);
    try {
      const res = await threatIntelAPI.correlations(caseId);
      setCorrelations(Array.isArray(res.data) ? res.data : []);
    } catch { setCorrelations([]); }
    finally { setLoading(false); }
  }

  function handleCaseChange(id) {
    setSelectedCase(id);
    if (id) loadCorrelations(id);
    else setCorrelations([]);
  }

  async function handleCorrelate() {
    if (!selectedCase) return;
    setRunning(true);
    try {
      const res = await threatIntelAPI.correlate(selectedCase);
      toast(res.data.message, 'ok');
      loadCorrelations(selectedCase);
    } catch (err) {
      toast(err.response?.data?.error || t('threat_intel.correlations.correlate_error'), 'error');
    } finally { setRunning(false); }
  }

  return (
    <div>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 18, flexWrap: 'wrap' }}>
        <select
          value={selectedCase}
          onChange={e => handleCaseChange(e.target.value)}
          style={{ background: T.inputBg, border: `1px solid ${T.border}`, borderRadius: 6, color: T.text, padding: '8px 12px', fontSize: 13, minWidth: 250 }}
        >
          <option value="">{t('threat_intel.correlations.select_case')}</option>
          {cases.map(c => <option key={c.id} value={c.id}>{c.case_number} — {c.title}</option>)}
        </select>
        <button
          onClick={handleCorrelate}
          disabled={!selectedCase || running}
          style={{
            background: selectedCase ? T.accent : T.border,
            color: selectedCase ? '#fff' : T.muted,
            border: 'none', borderRadius: 6, padding: '8px 18px',
            cursor: selectedCase ? 'pointer' : 'default', fontSize: 13,
            display: 'flex', alignItems: 'center', gap: 7,
          }}
        >
          {running
            ? <><Loader size={14} style={{ animation: 'spin 1s linear infinite' }} /> Running analysis...</>
            : <><ShieldAlert size={14} /> {t('threat_intel.correlations.run')}</>}
        </button>

        {correlations.length > 0 && (
          <div style={{
            marginLeft: 'auto',
            background: `color-mix(in srgb, ${IOC_COLORS.ipv4} 8%, transparent)`,
            border: `1px solid color-mix(in srgb, ${IOC_COLORS.ipv4} 25%, transparent)`,
            borderRadius: 6, padding: '6px 14px',
            color: IOC_COLORS.ipv4, fontWeight: 700, fontSize: 14,
          }}>
            {t('threat_intel.correlations.matches', { count: correlations.length })}
          </div>
        )}
      </div>

      {!selectedCase ? (
        <div style={{ border: `1px dashed ${T.border}`, borderRadius: 8, padding: 40, textAlign: 'center', color: T.muted }}>
          <ShieldAlert size={32} style={{ marginBottom: 12, opacity: 0.4 }} />
          <div style={{ fontSize: 14 }}>{t('threat_intel.correlations.empty_title')}</div>
          <div style={{ fontSize: 12, marginTop: 6 }}>
            {t('threat_intel.correlations.empty_sub')}
          </div>
        </div>
      ) : loading ? (
        <div style={{ textAlign: 'center', padding: 40, color: T.muted }}>
          <Loader size={20} style={{ animation: 'spin 1s linear infinite' }} />
        </div>
      ) : correlations.length === 0 ? (
        <div style={{ border: `1px dashed ${T.border}`, borderRadius: 8, padding: 40, textAlign: 'center', color: T.muted }}>
          <CheckCircle size={32} style={{ marginBottom: 12, opacity: 0.4 }} />
          <div style={{ fontSize: 14 }}>{t('threat_intel.correlations.none_title')}</div>
          <div style={{ fontSize: 12, marginTop: 6 }}>{t('threat_intel.correlations.none_sub')}</div>
        </div>
      ) : (
        <div style={{ border: `1px solid ${T.border}`, borderRadius: 8, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ background: `color-mix(in srgb, ${IOC_COLORS.ipv4} 6%, transparent)`, borderBottom: `1px solid ${T.border}` }}>
                {[t('threat_intel.correlations.col_type'), t('threat_intel.correlations.col_value'), t('threat_intel.correlations.col_indicator'), t('threat_intel.correlations.col_source'), t('threat_intel.correlations.col_detected')].map(h => (
                  <th key={h} style={{ padding: '9px 12px', textAlign: 'left', color: T.muted, fontWeight: 600, fontSize: 10, textTransform: 'uppercase' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {correlations.map((c, i) => (
                <tr key={c.id} style={{ borderBottom: i < correlations.length - 1 ? `1px solid ${T.border}` : 'none' }}>
                  <td style={{ padding: '9px 12px' }}><IocBadge type={c.ioc_type} /></td>
                  <td style={{ padding: '9px 12px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: IOC_COLORS[c.ioc_type] || T.text, fontWeight: 600 }}>
                    {c.ioc_value}
                  </td>
                  <td style={{ padding: '9px 12px', color: T.text, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {c.indicator_name || c.stix_id || '—'}
                  </td>
                  <td style={{ padding: '9px 12px', color: T.muted }}>{c.source_name || '—'}</td>
                  <td style={{ padding: '9px 12px', color: T.muted, whiteSpace: 'nowrap' }}>
                    {fmtLocal(c.matched_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

const TABS = [
  { id: 'feeds',        labelKey: 'threat_intel.tabs.feeds',        icon: Rss,      to: '/threat-intel/feeds' },
  { id: 'indicators',   labelKey: 'threat_intel.tabs.indicators',   icon: List,     to: '/threat-intel/indicators' },
  { id: 'correlations', labelKey: 'threat_intel.tabs.correlations', icon: GitMerge, to: '/threat-intel/correlations' },
];

export default function ThreatIntelPage() {
  const { t } = useTranslation();
  const T = useTheme();
  const navigate = useNavigate();
  const { tab = 'feeds' } = useParams();
  const [toast, setToast] = useState(null);

  const showToast = useCallback((msg, type = 'ok') => {
    setToast({ msg, type });
  }, []);

  return (
    <div style={{ padding: 24, maxWidth: 1400, margin: '0 auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
        <Globe size={20} style={{ color: 'var(--fl-accent)' }} strokeWidth={1.6} />
        <div>
          <h1 style={{ margin: 0, color: 'var(--fl-text)', fontSize: 20, fontWeight: 600, fontFamily: 'var(--f-display, var(--f-ui))', letterSpacing: '-0.01em' }}>{t('threat_intel.title')}</h1>
          <p style={{ margin: 0, color: 'var(--fl-muted)', fontSize: 12, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
            {t('threat_intel.subtitle')}
          </p>
        </div>
      </div>

      {/* Segmented control nav */}
      <div style={{ display: 'inline-flex', gap: 2, padding: 3, marginBottom: 22, borderRadius: 9, background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', maxWidth: '100%', overflowX: 'auto' }}>
        {TABS.map(it => {
          const on = tab === it.id; const Ico = it.icon;
          return (
            <button key={it.id} onClick={() => navigate(it.to)}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 7, padding: '6px 13px', borderRadius: 7, border: 'none', cursor: 'pointer', whiteSpace: 'nowrap', flexShrink: 0,
                fontFamily: 'var(--f-ui, "Inter", sans-serif)', fontSize: 12.5, fontWeight: on ? 600 : 500,
                background: on ? 'var(--fl-card)' : 'transparent', color: on ? 'var(--fl-accent)' : 'var(--fl-muted)',
                boxShadow: on ? 'var(--fl-shadow-sm)' : 'none', transition: 'color 0.12s, background 0.12s' }}
              onMouseEnter={e => { if (!on) e.currentTarget.style.color = 'var(--fl-dim)'; }}
              onMouseLeave={e => { if (!on) e.currentTarget.style.color = 'var(--fl-muted)'; }}>
              <Ico size={13} strokeWidth={1.6} style={{ flexShrink: 0 }} />{t(it.labelKey)}
            </button>
          );
        })}
      </div>

      <div>
        {tab === 'feeds'        && <FeedsTab toast={showToast} />}
        {tab === 'indicators'   && <IndicatorsTab />}
        {tab === 'correlations' && <CorrelationsTab toast={showToast} />}
      </div>

      {toast && <Toast msg={toast.msg} type={toast.type} onClose={() => setToast(null)} />}

      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
