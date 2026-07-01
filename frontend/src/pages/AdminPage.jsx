import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { useParams, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useTheme } from '../utils/theme';
import { Settings, Plus, Shield, UserCheck, UserX, ScrollText, Trash2, Search, CheckCircle2, XCircle, RefreshCw, ShieldAlert, Activity, Database, Download, Cpu, MessageSquare, Bot, FileText } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { usersAPI, authAPI, casesAPI, adminAPI, feedbackAPI, settingsAPI } from '../utils/api';
import { Button, Modal, TabGroup, Spinner, EmptyState, Pagination } from '../components/ui';
import { fmtLocal } from '../utils/formatters';

const ACTION_COLORS = {
  login: 'var(--fl-ok)', login_failed: 'var(--fl-danger)', login_blocked: 'var(--fl-gold)',
  logout: 'var(--fl-dim)', token_refresh: 'var(--fl-accent)',
  import_collection: 'var(--fl-accent)', parse_collection: 'var(--fl-purple)', delete_collection_data: 'var(--fl-danger)', pcap_parse: 'var(--fl-purple)',
  create_case: 'var(--fl-warn)', update_case: 'var(--fl-warn)', hard_delete_case: 'var(--fl-danger)',
  upload_evidence: 'var(--fl-ok)', delete_evidence: 'var(--fl-danger)',
  add_mitre_technique: 'var(--fl-purple)', update_mitre_technique: 'var(--fl-purple)', delete_mitre_technique: 'var(--fl-danger)',
  create_user: 'var(--fl-purple)', update_user: 'var(--fl-warn)', delete_user: 'var(--fl-danger)', change_password: 'var(--fl-gold)',
  generate_report: 'var(--fl-purple)', create_ioc: 'var(--fl-gold)', delete_ioc: 'var(--fl-danger)',
  run_yara_scan: 'var(--fl-pink)', run_sigma_hunt: 'var(--fl-accent)', fetch_taxii: 'var(--fl-purple)', correlate_case: 'var(--fl-warn)',
  run_hayabusa: 'var(--fl-danger)', upload_evidence_chunked: 'var(--fl-ok)', download_report: 'var(--fl-purple)',
  backup_db: 'var(--fl-accent)', download_backup: 'var(--fl-accent)', run_soar: 'var(--fl-accent)',
};

const PRIORITY_COLOR = { critical: 'var(--fl-danger)', high: 'var(--fl-warn)', medium: 'var(--fl-gold)', low: 'var(--fl-ok)' };
const AUDIT_PAGE_SIZE = 50;

export default function AdminPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { tab = 'health' } = useParams();
  const [users, setUsers] = useState([]);   // for the Logs tab user filter

  // Operations-focused tabs (monitoring & maintenance). Account / Audit / RGPD / SLA
  // moved to Settings — legacy /admin URLs are redirected at the router level (App.jsx).
  const ADMIN_TABS = useMemo(() => [
    { id: 'health',   label: t('admin.tabs_health'),   icon: Activity,      to: '/admin/health' },
    { id: 'jobs',     label: t('admin.tabs_jobs'),     icon: Cpu,           to: '/admin/jobs' },
    { id: 'backups',  label: t('admin.tabs_backups'),  icon: Database,      to: '/admin/backups' },
    { id: 'docker',   label: t('admin.tabs_infra'),    icon: Cpu,           to: '/admin/docker' },
    { id: 'ai',       label: t('admin.tabs_ai'),       icon: Bot,           to: '/admin/ai' },
    { id: 'logs',     label: t('admin.tabs_logs'),     icon: FileText,      to: '/admin/logs' },
    { id: 'feedback', label: t('admin.tabs_feedback'), icon: MessageSquare, to: '/admin/feedback' },
    { id: 'about',    label: t('admin.tabs_about'),    icon: Shield,        to: '/admin/about' },
  ], [t]);

  useEffect(() => {
    usersAPI.list().then(({ data }) => setUsers(data)).catch(() => {});
  }, []);

  return (
    <div className="p-6">
      <div className="fl-header">
        <div>
          <h1 className="fl-header-title">{t('admin.admin_title')}</h1>
          <p className="fl-header-sub">{t('admin.operations_subtitle')}</p>
        </div>
      </div>

      {/* Segmented control nav (Operations-specific) */}
      <div style={{ display: 'inline-flex', gap: 2, padding: 3, marginBottom: 22, borderRadius: 9,
        background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', maxWidth: '100%', overflowX: 'auto' }}>
        {ADMIN_TABS.map(it => {
          const on = tab === it.id;
          const Ico = it.icon;
          return (
            <button key={it.id} onClick={() => navigate(it.to)}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 7, padding: '6px 13px', borderRadius: 7, border: 'none', cursor: 'pointer', whiteSpace: 'nowrap', flexShrink: 0,
                fontFamily: 'var(--f-ui, "Inter", sans-serif)', fontSize: 12.5, fontWeight: on ? 600 : 500,
                background: on ? 'var(--fl-card)' : 'transparent',
                color: on ? 'var(--fl-accent)' : 'var(--fl-muted)',
                boxShadow: on ? 'var(--fl-shadow-sm)' : 'none', transition: 'color 0.12s, background 0.12s' }}
              onMouseEnter={e => { if (!on) e.currentTarget.style.color = 'var(--fl-dim)'; }}
              onMouseLeave={e => { if (!on) e.currentTarget.style.color = 'var(--fl-muted)'; }}>
              <Ico size={13} style={{ flexShrink: 0 }} />
              {it.label}
            </button>
          );
        })}
      </div>

      {tab === 'health'   && <HealthTab />}
      {tab === 'backups'  && <BackupsTab />}
      {tab === 'jobs'     && <JobsTab />}
      {tab === 'feedback' && <FeedbackTab />}
      {tab === 'docker'   && <DockerTab />}
      {tab === 'ai'       && <AiSettingsTab />}
      {tab === 'logs'     && <LogsTab users={users} />}
      {tab === 'about'    && <AboutTab />}
    </div>
  );
}

function HealthTab() {
  const { t, i18n } = useTranslation();
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(false);
  const [lastAt, setLastAt]   = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try { const r = await adminAPI.health(); setData(r.data); setLastAt(new Date()); }
    catch { setData(null); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); const iv = setInterval(load, 30_000); return () => clearInterval(iv); }, [load]);

  const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
  const UI   = 'var(--f-ui, "Inter", sans-serif)';

  const services = data?.services ? Object.entries(data.services) : [];
  const okCount  = services.filter(([, s]) => s?.ok).length;
  const total    = services.length;
  const allOk    = total > 0 && okCount === total;
  const overall  = total === 0 ? 'var(--fl-muted)' : allOk ? 'var(--fl-ok)' : 'var(--fl-danger)';

  function metrics(svc) {
    if (svc.waiting !== undefined) {
      return [[t('admin.health.metric_waiting'), svc.waiting], [t('admin.health.metric_active'), svc.active], [t('admin.health.metric_completed'), svc.completed],
              [t('admin.health.metric_failed'), svc.failed, svc.failed > 0 ? 'var(--fl-danger)' : null]];
    }
    if (svc.status) return [[t('admin.health.metric_cluster'), svc.status, svc.status === 'green' ? 'var(--fl-ok)' : svc.status === 'yellow' ? 'var(--fl-warn)' : 'var(--fl-danger)'], [t('admin.health.metric_shards'), svc.shards ?? '—']];
    return null;
  }

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, marginBottom: 14 }}>
        <h3 style={{ fontSize: 18, fontWeight: 600, margin: 0, color: 'var(--fl-text)', fontFamily: 'var(--f-display, var(--f-ui))', letterSpacing: '-0.01em' }}>{t('admin.health.title')}</h3>
        <span style={{ flex: 1 }} />
        {lastAt && (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 10.5, fontFamily: MONO, color: 'var(--fl-muted)' }}>
            <span className="fl-pulse" style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--fl-ok)' }} />
            {lastAt.toLocaleTimeString(i18n.language)} · 30s
          </span>
        )}
        <button onClick={load} title={t('common.refresh')}
          style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '5px 11px', borderRadius: 6, cursor: 'pointer', background: 'transparent', color: 'var(--fl-muted)', border: '1px solid var(--fl-border)', fontFamily: MONO, fontSize: 11 }}>
          <RefreshCw size={12} style={{ animation: loading ? 'fl-spin 0.8s linear infinite' : 'none' }} /> {t('common.refresh')}
        </button>
      </div>

      {/* Editorial status line + segmented strip (status-page style) */}
      {total > 0 && (
        <div style={{ marginBottom: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 8 }}>
            <span style={{ width: 9, height: 9, borderRadius: 2, background: overall }} />
            <span style={{ fontSize: 13, fontWeight: 600, fontFamily: UI, color: 'var(--fl-text)' }}>{allOk ? t('admin.health.operational') : t('admin.status_degraded')}</span>
            <span style={{ fontSize: 12, fontFamily: MONO, color: 'var(--fl-muted)' }}>· {t('admin.health.online_count', { ok: okCount, total })}</span>
          </div>
          <div style={{ display: 'flex', gap: 3 }}>
            {services.map(([k, s]) => (
              <div key={k} title={`${s.name || k} — ${s.ok ? t('admin.status_ok') : t('admin.status_error').toLowerCase()}`}
                style={{ flex: 1, height: 4, borderRadius: 2, background: s.ok ? 'var(--fl-ok)' : 'var(--fl-danger)', opacity: s.ok ? 0.55 : 1 }} />
            ))}
          </div>
        </div>
      )}

      {loading && !data && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
          {[0,1,2,3,4,5].map(i => <div key={i} className="fl-skeleton" style={{ height: 92, borderRadius: 10, background: 'var(--fl-card)' }} />)}
        </div>
      )}

      {/* Service cards — uniform hairline, no colored side bar */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
        {services.map(([key, svc]) => {
          const ok = !!svc?.ok;
          const color = ok ? 'var(--fl-ok)' : 'var(--fl-danger)';
          const m = metrics(svc);
          return (
            <div key={key}
              style={{ background: 'var(--fl-card)', border: '1px solid var(--fl-border)', borderRadius: 10, padding: '15px 17px', transition: 'border-color 0.15s' }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--fl-border3)'; }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--fl-border)'; }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: m ? 13 : 0 }}>
                <span style={{ width: 8, height: 8, borderRadius: 2, background: color, flexShrink: 0,
                  boxShadow: ok ? 'none' : `0 0 0 3px color-mix(in srgb, ${color} 20%, transparent)` }} />
                <span style={{ fontWeight: 600, fontSize: 13.5, fontFamily: UI, color: 'var(--fl-text)' }}>{svc.name || key}</span>
                <span style={{ marginLeft: 'auto', fontSize: 9.5, fontWeight: 600, fontFamily: MONO, letterSpacing: '0.06em', color: ok ? 'var(--fl-muted)' : 'var(--fl-danger)' }}>
                  {ok ? t('admin.health.online_badge') : t('admin.status_error').toUpperCase()}
                </span>
              </div>
              {svc.reason && <p style={{ fontSize: 11, fontFamily: MONO, color: 'var(--fl-danger)', margin: '6px 0 0' }}>{svc.reason}</p>}
              {m && (
                <div style={{ display: 'grid', gridTemplateColumns: m.length === 4 ? '1fr 1fr 1fr 1fr' : `repeat(${m.length}, auto)`, gap: '10px 18px', justifyContent: 'start' }}>
                  {m.map(([label, value, c]) => (
                    <div key={label} style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                      <span style={{ fontSize: 16, fontWeight: 600, fontFamily: MONO, color: c || 'var(--fl-text)', fontFeatureSettings: '"tnum"', lineHeight: 1 }}>{value}</span>
                      <span style={{ fontSize: 9, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-subtle)' }}>{label}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {!loading && total === 0 && (
        <div style={{ textAlign: 'center', padding: '48px 16px', fontFamily: MONO, fontSize: 12, color: 'var(--fl-muted)' }}>
          {t('admin.health.fetch_failed')}
        </div>
      )}
    </div>
  );
}

function BackupsTab() {
  const { t } = useTranslation();
  const [backups, setBackups] = useState([]);
  const [loading, setLoading] = useState(false);
  const [triggering, setTrig] = useState(false);
  const [msg, setMsg]         = useState('');

  async function load() {
    setLoading(true);
    try { const r = await adminAPI.listBackups(); setBackups(r.data); }
    catch { setBackups([]); }
    finally { setLoading(false); }
  }
  useEffect(() => { load(); }, []);

  async function trigger() {
    setTrig(true); setMsg('');
    try { const r = await adminAPI.triggerBackup(); setMsg(t('admin.backups.created_msg', { filename: r.data.filename, size: (r.data.size/1024/1024).toFixed(1) })); await load(); }
    catch (e) { setMsg(t('admin.backups.error_msg', { error: e.response?.data?.error || t('common.unknown').toLowerCase() })); }
    finally { setTrig(false); }
  }

  const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
  function fmtSize(b) { if (b > 1048576) return t('admin.units.mb', { value: (b/1048576).toFixed(1) }); if (b > 1024) return t('admin.units.kb', { value: (b/1024).toFixed(0) }); return t('admin.units.bytes', { value: b }); }
  const totalSize = backups.reduce((s, b) => s + (b.size || 0), 0);
  const msgOk = msg.startsWith('✓');

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, marginBottom: 14 }}>
        <h3 style={{ fontSize: 18, fontWeight: 600, margin: 0, color: 'var(--fl-text)', fontFamily: 'var(--f-display, var(--f-ui))', letterSpacing: '-0.01em' }}>{t('admin.backups.title')}</h3>
        {backups.length > 0 && <span style={{ fontSize: 12, fontFamily: MONO, color: 'var(--fl-muted)' }}>{backups.length} · {fmtSize(totalSize)}</span>}
        <span style={{ flex: 1 }} />
        <Button variant="primary" size="sm" icon={Database} loading={triggering} onClick={trigger}>{t('admin.backups.trigger')}</Button>
        <button onClick={load} title={t('common.refresh')} style={{ display: 'flex', alignItems: 'center', padding: '5px 9px', borderRadius: 6, cursor: 'pointer', background: 'transparent', color: 'var(--fl-muted)', border: '1px solid var(--fl-border)' }}>
          <RefreshCw size={12} style={{ animation: loading ? 'fl-spin 0.8s linear infinite' : 'none' }} />
        </button>
      </div>

      {msg && (
        <div style={{ padding: '8px 14px', borderRadius: 6, marginBottom: 12, fontFamily: MONO, fontSize: 12,
          background: `color-mix(in srgb, ${msgOk ? 'var(--fl-ok)' : 'var(--fl-danger)'} 7%, transparent)`,
          border: `1px solid color-mix(in srgb, ${msgOk ? 'var(--fl-ok)' : 'var(--fl-danger)'} 22%, transparent)`,
          color: msgOk ? 'var(--fl-ok)' : 'var(--fl-danger)' }}>{msg}</div>
      )}

      <p style={{ fontSize: 11.5, color: 'var(--fl-muted)', marginBottom: 14, fontFamily: 'var(--f-ui, sans-serif)' }}>
        {t('admin.backups.storage_before')} <code style={{ fontFamily: MONO, color: 'var(--fl-dim)' }}>backups_data</code>. {t('admin.backups.storage_after')}
      </p>

      {loading && backups.length === 0 && <Spinner full text={t('admin.loading_backups')} />}
      {!loading && backups.length === 0 && <EmptyState icon={Database} title={t('admin.no_backups')} subtitle={t('admin.no_backups_sub')} />}

      {backups.length > 0 && (
        <div style={{ border: '1px solid var(--fl-border)', borderRadius: 10, overflow: 'hidden' }}>
          <table className="fl-table">
            <thead><tr>{[t('admin.backups.col_file'), t('admin.backups.col_size'), t('admin.col_date'), ''].map(h => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>
              {backups.map(b => (
                <tr key={b.name}>
                  <td className="font-mono text-xs" style={{ color: 'var(--fl-text)' }}>{b.name}</td>
                  <td className="font-mono text-xs" style={{ color: 'var(--fl-dim)', fontFeatureSettings: '"tnum"' }}>{fmtSize(b.size)}</td>
                  <td className="whitespace-nowrap font-mono text-xs" style={{ color: 'var(--fl-dim)' }}>{fmtLocal(b.created_at)}</td>
                  <td>
                    <a href={adminAPI.downloadBackup(b.name)} download style={{ display: 'inline-flex', alignItems: 'center', gap: 5, color: 'var(--fl-accent)', fontSize: 11.5, fontFamily: MONO, textDecoration: 'none' }}>
                      <Download size={12} /> {t('admin.backups.download')}
                    </a>
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

function JobsTab() {
  const { t } = useTranslation();
  const [jobs, setJobs]       = useState([]);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter]   = useState('all');
  const [expanded, setExpanded] = useState(new Set());

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = {};
      if (filter === 'error') params.filter = 'error';
      if (filter === '24h')   params.since  = '24h';
      const { data } = await adminAPI.jobs(params);
      setJobs(data || []);
    } catch { setJobs([]); }
    setLoading(false);
  }, [filter]);
  useEffect(() => { load(); }, [load]);

  function toggleExpand(id) {
    setExpanded(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  }

  const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
  const STATUS = { ok: ['var(--fl-ok)', t('admin.status_ok')], degraded: ['var(--fl-warn)', t('admin.status_degraded')], error: ['var(--fl-danger)', t('admin.status_error')] };
  const errCount = jobs.filter(j => j.status === 'error').length;

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, marginBottom: 14 }}>
        <h3 style={{ fontSize: 18, fontWeight: 600, margin: 0, color: 'var(--fl-text)', fontFamily: 'var(--f-display, var(--f-ui))', letterSpacing: '-0.01em' }}>{t('admin.jobs.title')}</h3>
        {jobs.length > 0 && (
          <span style={{ fontSize: 12, fontFamily: MONO, color: 'var(--fl-muted)' }}>
            {t(jobs.length > 1 ? 'admin.jobs.count_many' : 'admin.jobs.count_one', { count: jobs.length })}{errCount > 0 && <> · <span style={{ color: 'var(--fl-danger)' }}>{t(errCount > 1 ? 'admin.jobs.error_count_many' : 'admin.jobs.error_count_one', { count: errCount })}</span></>}
          </span>
        )}
        <span style={{ flex: 1 }} />
        <div style={{ display: 'flex', gap: 4 }}>
          {[['all', t('admin.filter_all')], ['error', t('admin.filter_errors_short')], ['24h', '24h']].map(([v, l]) => (
            <button key={v} onClick={() => setFilter(v)}
              style={{ padding: '4px 11px', borderRadius: 6, fontSize: 11, fontFamily: MONO, cursor: 'pointer',
                border: `1px solid ${filter === v ? 'color-mix(in srgb, var(--fl-accent) 25%, transparent)' : 'var(--fl-border)'}`,
                background: filter === v ? 'color-mix(in srgb, var(--fl-accent) 10%, transparent)' : 'transparent',
                color: filter === v ? 'var(--fl-accent)' : 'var(--fl-muted)' }}>{l}</button>
          ))}
        </div>
        <button onClick={load} title={t('common.refresh')} style={{ display: 'flex', alignItems: 'center', padding: '5px 9px', borderRadius: 6, cursor: 'pointer', background: 'transparent', color: 'var(--fl-muted)', border: '1px solid var(--fl-border)' }}>
          <RefreshCw size={12} style={{ animation: loading ? 'fl-spin 0.8s linear infinite' : 'none' }} />
        </button>
      </div>

      {loading && jobs.length === 0 && <Spinner full text={t('admin.loading_jobs')} />}
      {!loading && jobs.length === 0 && <EmptyState icon={Cpu} title={t('admin.no_jobs')} subtitle={t('admin.no_jobs_sub')} />}

      {jobs.length > 0 && (
        <div style={{ border: '1px solid var(--fl-border)', borderRadius: 10, overflow: 'hidden' }}>
          <table className="fl-table">
            <thead><tr>{[t('admin.col_case'), t('admin.col_status'), t('admin.col_records'), t('admin.col_analyst'), t('admin.col_date')].map(h => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>
              {jobs.map(job => {
                const [color, label] = STATUS[job.status] || ['var(--fl-muted)', job.status];
                const isExp = expanded.has(job.id);
                return (
                  <React.Fragment key={job.id}>
                    <tr onClick={() => toggleExpand(job.id)} style={{ cursor: 'pointer' }}>
                      <td>
                        <a href={`/cases/${job.case_id}`} onClick={e => { e.stopPropagation(); e.preventDefault(); window.location.href = `/cases/${job.case_id}`; }}
                          style={{ color: 'var(--fl-accent)', textDecoration: 'none', fontFamily: MONO, fontSize: 11 }}>{job.case_number}</a>
                        {job.case_title && <span style={{ marginLeft: 8, fontSize: 11, color: 'var(--fl-dim)' }}>{job.case_title}</span>}
                      </td>
                      <td>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7, fontFamily: MONO, fontSize: 11, color }}>
                          <span style={{ width: 7, height: 7, borderRadius: 2, background: color, boxShadow: job.status === 'error' ? `0 0 0 3px color-mix(in srgb, ${color} 20%, transparent)` : 'none' }} />{label}
                        </span>
                      </td>
                      <td className="font-mono text-xs" style={{ color: 'var(--fl-dim)', fontFeatureSettings: '"tnum"' }}>{(job.record_count || 0).toLocaleString()}</td>
                      <td className="text-xs" style={{ color: 'var(--fl-dim)' }}>{job.analyst || '—'}</td>
                      <td className="text-xs font-mono" style={{ color: 'var(--fl-dim)' }}>{job.updated_at ? fmtLocal(job.updated_at) : '—'}</td>
                    </tr>
                    {isExp && (
                      <tr><td colSpan={5} style={{ padding: '8px 14px', background: 'var(--fl-bg)' }}>
                        <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: 'var(--fl-dim)', fontSize: 10, fontFamily: MONO, maxHeight: 200, overflow: 'auto' }}>{JSON.stringify(job.output_data, null, 2)}</pre>
                      </td></tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function FeedbackTab() {
  const { t } = useTranslation();
  const [rows, setRows]       = useState([]);
  const [loading, setLoading] = useState(false);
  const [statusFilter, setStatusFilter] = useState('');
  const [saving, setSaving]   = useState({});
  const [replies, setReplies] = useState({});

  const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
  const STATUS_CONFIG = {
    open:        { label: t('admin.feedback.status_open'),        color: 'var(--fl-accent)' },
    in_progress: { label: t('admin.feedback.status_in_progress'), color: 'var(--fl-warn)' },
    resolved:    { label: t('admin.feedback.status_resolved'),    color: 'var(--fl-ok)' },
    closed:      { label: t('admin.feedback.status_closed'),      color: 'var(--fl-muted)' },
  };
  const TYPE_LABELS = { bug: t('admin.feedback.type_bug'), suggestion: t('admin.feedback.type_suggestion'), autre: t('admin.feedback.type_other') };

  const load = useCallback(async () => {
    setLoading(true);
    try { const { data } = await feedbackAPI.list(statusFilter ? { status: statusFilter } : {}); setRows(data || []); }
    catch { setRows([]); }
    setLoading(false);
  }, [statusFilter]);
  useEffect(() => { load(); }, [load]);

  async function saveReply(id) {
    setSaving(p => ({ ...p, [id]: true }));
    try { const row = rows.find(r => r.id === id); await feedbackAPI.update(id, { status: row?.status, admin_reply: replies[id] ?? row?.admin_reply ?? '' }); await load(); } catch {}
    setSaving(p => ({ ...p, [id]: false }));
  }
  async function updateStatus(id, status) {
    const row = rows.find(r => r.id === id);
    try { await feedbackAPI.update(id, { status, admin_reply: row?.admin_reply || null }); setRows(prev => prev.map(r => r.id === id ? { ...r, status } : r)); } catch {}
  }
  const openCount = rows.filter(r => r.status === 'open').length;

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, marginBottom: 14 }}>
        <h3 style={{ fontSize: 18, fontWeight: 600, margin: 0, color: 'var(--fl-text)', fontFamily: 'var(--f-display, var(--f-ui))', letterSpacing: '-0.01em' }}>{t('admin.feedback.title')}</h3>
        {openCount > 0 && <span style={{ fontSize: 12, fontFamily: MONO, color: 'var(--fl-accent)' }}>{t(openCount > 1 ? 'admin.feedback.open_count_many' : 'admin.feedback.open_count_one', { count: openCount })}</span>}
        <span style={{ flex: 1 }} />
        <div style={{ display: 'flex', gap: 4 }}>
          {[['', t('admin.filter_all')], ['open', t('admin.feedback.filter_open')], ['in_progress', t('admin.feedback.status_in_progress')], ['resolved', t('admin.feedback.filter_resolved')]].map(([v, l]) => (
            <button key={v} onClick={() => setStatusFilter(v)}
              style={{ padding: '4px 11px', borderRadius: 6, fontSize: 11, fontFamily: MONO, cursor: 'pointer',
                border: `1px solid ${statusFilter === v ? 'color-mix(in srgb, var(--fl-accent) 25%, transparent)' : 'var(--fl-border)'}`,
                background: statusFilter === v ? 'color-mix(in srgb, var(--fl-accent) 10%, transparent)' : 'transparent',
                color: statusFilter === v ? 'var(--fl-accent)' : 'var(--fl-muted)' }}>{l}</button>
          ))}
        </div>
        <button onClick={load} title={t('common.refresh')} style={{ display: 'flex', alignItems: 'center', padding: '5px 9px', borderRadius: 6, cursor: 'pointer', background: 'transparent', color: 'var(--fl-muted)', border: '1px solid var(--fl-border)' }}>
          <RefreshCw size={12} style={{ animation: loading ? 'fl-spin 0.8s linear infinite' : 'none' }} />
        </button>
      </div>

      {loading && <Spinner full text={t('admin.loading_tickets')} />}
      {!loading && rows.length === 0 && <EmptyState icon={MessageSquare} title={t('admin.no_tickets')} subtitle={t('admin.no_tickets_sub')} />}

      {!loading && rows.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {rows.map(row => {
            const sc = STATUS_CONFIG[row.status] || STATUS_CONFIG.open;
            return (
              <div key={row.id} style={{ borderRadius: 10, border: '1px solid var(--fl-border)', background: 'var(--fl-panel)', overflow: 'hidden' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px' }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: sc.color, flexShrink: 0 }} />
                  <span style={{ fontFamily: MONO, fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-muted)', minWidth: 72 }}>{TYPE_LABELS[row.type] || row.type}</span>
                  <span style={{ flex: 1, fontSize: 12.5, color: 'var(--fl-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.title || row.description?.slice(0, 80)}</span>
                  <span style={{ fontSize: 10, fontFamily: MONO, color: 'var(--fl-muted)', flexShrink: 0 }}>{row.username || '?'}</span>
                  <span style={{ fontSize: 10, fontFamily: MONO, color: 'var(--fl-subtle)', flexShrink: 0 }}>{new Date(row.created_at).toLocaleDateString('fr-FR')}</span>
                  <select value={row.status} onChange={e => updateStatus(row.id, e.target.value)}
                    style={{ padding: '3px 7px', borderRadius: 5, fontSize: 10.5, fontFamily: MONO, background: 'var(--fl-input-bg)', color: sc.color, border: '1px solid var(--fl-border)', cursor: 'pointer', flexShrink: 0 }}>
                    {Object.entries(STATUS_CONFIG).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
                  </select>
                </div>
                <div style={{ padding: '10px 14px', background: 'var(--fl-bg)', borderTop: '1px solid var(--fl-border2)' }}>
                  <p style={{ margin: '0 0 8px', fontSize: 11.5, color: 'var(--fl-dim)', lineHeight: 1.55, fontFamily: 'var(--f-ui, sans-serif)' }}>{row.description}</p>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
                    <textarea placeholder={t('admin.feedback.reply_placeholder')} value={replies[row.id] ?? (row.admin_reply || '')} onChange={e => setReplies(p => ({ ...p, [row.id]: e.target.value }))} rows={2}
                      style={{ flex: 1, padding: '6px 9px', borderRadius: 6, fontSize: 11.5, fontFamily: MONO, background: 'var(--fl-card)', color: 'var(--fl-text)', border: '1px solid var(--fl-border)', resize: 'vertical', outline: 'none' }} />
                    <Button variant="primary" size="xs" loading={saving[row.id]} onClick={() => saveReply(row.id)}>{t('common.save')}</Button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function DockerTab() {
  const { t, i18n } = useTranslation();
  const [data,    setData]    = useState(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState('');

  const load = useCallback(async () => {
    setLoading(true); setError('');
    try { const r = await adminAPI.dockerContainers(); setData(r.data); }
    catch (e) { setError(e.response?.data?.error || e.message || t('admin.errors.unknown')); setData(null); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); const iv = setInterval(load, 15000); return () => clearInterval(iv); }, [load]);

  const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
  function fmtMem(b) { if (!b) return t('admin.units.mb', { value: 0 }); if (b >= 1073741824) return t('admin.units.gb', { value: (b/1073741824).toFixed(1) }); return t('admin.units.mb', { value: (b/1048576).toFixed(0) }); }
  // Usage colour = signal only: calm steel under load, warn/danger when elevated.
  const usageColor = (pct, warnAt) => pct > 80 ? 'var(--fl-danger)' : pct > warnAt ? 'var(--fl-warn)' : 'var(--fl-purple)';
  const STATE = { running: ['var(--fl-ok)', t('admin.docker.state_running')], exited: ['var(--fl-danger)', t('admin.docker.state_exited')], paused: ['var(--fl-warn)', t('admin.docker.state_paused')], restarting: ['var(--fl-warn)', t('admin.docker.state_restarting')] };
  const TOOLTIP_STYLE = { background: 'var(--fl-card)', border: '1px solid var(--fl-border)', borderRadius: 6, fontSize: 12, color: 'var(--fl-text)' };

  const containers = data?.containers || [];
  const running    = containers.filter(c => c.state === 'running');
  const cpuChartData = [...running].sort((a, b) => b.cpu_percent - a.cpu_percent).slice(0, 10).map(c => ({ name: c.name.length > 18 ? c.name.slice(0, 17) + '…' : c.name, cpu: c.cpu_percent }));
  const ramChartData = [...running].sort((a, b) => b.mem_percent - a.mem_percent).slice(0, 10).map(c => ({ name: c.name.length > 18 ? c.name.slice(0, 17) + '…' : c.name, ram: c.mem_percent }));

  const Panel = ({ title, chartData, dataKey, warnAt }) => (
    <div style={{ background: 'var(--fl-card)', border: '1px solid var(--fl-border)', borderRadius: 10, padding: '14px 16px' }}>
      <p style={{ fontSize: 10.5, fontWeight: 600, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-muted)', marginBottom: 12 }}>{title}</p>
      <ResponsiveContainer width="100%" height={running.length > 6 ? 200 : 160}>
        <BarChart data={chartData} layout="vertical" margin={{ left: 0, right: 20, top: 0, bottom: 0 }}>
          <XAxis type="number" domain={[0, 100]} tick={{ fontSize: 10, fill: 'var(--fl-muted)' }} tickFormatter={v => v + '%'} axisLine={{ stroke: 'var(--fl-border)' }} tickLine={false} />
          <YAxis type="category" dataKey="name" tick={{ fontSize: 10.5, fill: 'var(--fl-dim)' }} width={130} axisLine={false} tickLine={false} />
          <Tooltip formatter={(v) => [`${v.toFixed(2)} %`, title]} contentStyle={TOOLTIP_STYLE} labelStyle={{ color: 'var(--fl-dim)', marginBottom: 2 }} cursor={{ fill: '#ffffff08' }} />
          <Bar dataKey={dataKey} radius={[0, 3, 3, 0]} barSize={11}>
            {chartData.map((e, i) => <Cell key={i} fill={usageColor(e[dataKey], warnAt)} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, marginBottom: 16 }}>
        <h3 style={{ fontSize: 18, fontWeight: 600, margin: 0, color: 'var(--fl-text)', fontFamily: 'var(--f-display, var(--f-ui))', letterSpacing: '-0.01em' }}>{t('admin.docker.title')}</h3>
        {data && (
          <span style={{ fontSize: 12, fontFamily: MONO, color: 'var(--fl-muted)' }}>
            <span style={{ color: running.length === containers.length ? 'var(--fl-ok)' : 'var(--fl-warn)' }}>{running.length}</span>/{containers.length} {t('admin.docker.online_suffix')}
          </span>
        )}
        <span style={{ flex: 1 }} />
        {data && <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 10.5, fontFamily: MONO, color: 'var(--fl-muted)' }}><span className="fl-pulse" style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--fl-ok)' }} />{new Date(data.timestamp).toLocaleTimeString(i18n.language)} · 15s</span>}
        <button onClick={load} title={t('common.refresh')} style={{ display: 'flex', alignItems: 'center', padding: '5px 9px', borderRadius: 6, cursor: 'pointer', background: 'transparent', color: 'var(--fl-muted)', border: '1px solid var(--fl-border)' }}>
          <RefreshCw size={12} style={{ animation: loading ? 'fl-spin 0.8s linear infinite' : 'none' }} />
        </button>
      </div>

      {error && <div style={{ padding: '10px 14px', borderRadius: 6, marginBottom: 14, background: 'color-mix(in srgb, var(--fl-danger) 7%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 22%, transparent)', fontSize: 12, fontFamily: MONO, color: 'var(--fl-danger)' }}>✗ {error}</div>}
      {loading && !data && <Spinner full text={t('admin.docker.loading_containers')} />}

      {running.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 18 }}>
          <Panel title={t('admin.docker.cpu_active')} chartData={cpuChartData} dataKey="cpu" warnAt={50} />
          <Panel title={t('admin.docker.ram_active')} chartData={ramChartData} dataKey="ram" warnAt={60} />
        </div>
      )}

      {containers.length > 0 && (
        <div style={{ border: '1px solid var(--fl-border)', borderRadius: 10, overflow: 'hidden' }}>
          <table className="fl-table">
            <thead><tr>{[t('admin.docker.col_container'), 'Image', t('admin.docker.col_state'), 'CPU', 'RAM', t('admin.docker.col_ram_used')].map(h => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>
              {containers.map(c => {
                const [color, label] = STATE[c.state] || ['var(--fl-muted)', c.state];
                return (
                  <tr key={c.id}>
                    <td className="font-mono text-xs" style={{ color: 'var(--fl-text)', fontWeight: 600 }}>{c.name}</td>
                    <td className="font-mono text-xs" style={{ color: 'var(--fl-muted)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.image}</td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7, fontFamily: MONO, fontSize: 11, color }}>
                        <span style={{ width: 7, height: 7, borderRadius: 2, background: color, boxShadow: c.state !== 'running' ? `0 0 0 3px color-mix(in srgb, ${color} 20%, transparent)` : 'none' }} />{label}
                      </span>
                    </td>
                    {['cpu_percent', 'mem_percent'].map((k, idx) => (
                      <td key={k}>
                        {c.state === 'running' ? (
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <div style={{ width: 60, height: 6, background: 'var(--fl-border)', borderRadius: 3, overflow: 'hidden' }}>
                              <div style={{ height: '100%', width: `${Math.min(c[k], 100)}%`, background: usageColor(c[k], idx === 0 ? 50 : 60), borderRadius: 3, transition: 'width 0.3s' }} />
                            </div>
                            <span style={{ fontSize: 11.5, fontFamily: MONO, color: 'var(--fl-dim)', minWidth: 40, fontFeatureSettings: '"tnum"' }}>{c[k].toFixed(1)}%</span>
                          </div>
                        ) : <span style={{ color: 'var(--fl-subtle)', fontSize: 12 }}>—</span>}
                      </td>
                    ))}
                    <td style={{ fontSize: 11.5, fontFamily: MONO, color: 'var(--fl-dim)', fontFeatureSettings: '"tnum"' }}>
                      {c.state === 'running' ? `${fmtMem(c.mem_used)} / ${fmtMem(c.mem_limit)}` : <span style={{ color: 'var(--fl-subtle)' }}>—</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

const COMPOSE_NETWORK = 'forensic-lab_aesir-net';

const MODEL_CATALOG = [
  { id: 'qwen2.5:3b',    label: 'Qwen 2.5 3B',       size: '1.9 GB',  descKey: 'qwen25_3b',    tag: 'recommended' },
  { id: 'qwen3.5:4b',    label: 'Qwen 3.5 4B',       size: '~2.8 GB', descKey: 'qwen35_4b',    tag: 'recent' },
  { id: 'qwen3.5:2b',    label: 'Qwen 3.5 2B',       size: '~1.6 GB', descKey: 'qwen35_2b',    tag: 'light' },
  { id: 'lfm2.5',        label: 'LFM2.5 8B-A1B',     size: '~4.7 GB', descKey: 'lfm25',        tag: 'agent' },
  { id: 'gemma4:e4b',    label: 'Gemma 4 (e4b)',     size: '~3 GB',   descKey: 'gemma4_e4b',   tag: 'recent' },
  { id: 'granite4.1:3b', label: 'Granite 4.1 3B',    size: '~2 GB',   descKey: 'granite41_3b', tag: 'light' },
  { id: 'llama3.2:3b',   label: 'Llama 3.2 3B',      size: '2 GB',    descKey: 'llama32_3b',   tag: 'light' },
  { id: 'qwen2.5:7b',    label: 'Qwen 2.5 7B',       size: '4.7 GB',  descKey: 'qwen25_7b',    tag: 'quality' },
  { id: 'qwen3.5:9b',    label: 'Qwen 3.5 9B',       size: '~6 GB',   descKey: 'qwen35_9b',    tag: 'quality' },
  { id: 'granite4.1:8b', label: 'Granite 4.1 8B',    size: '~5 GB',   descKey: 'granite41_8b', tag: 'recent' },
  { id: 'gpt-oss:20b',   label: 'GPT-OSS 20B',       size: '~13 GB',  descKey: 'gpt_oss_20b',  tag: 'powerful' },
];

const TAG_COLOR = {
  recommended:    'var(--fl-ok)',
  quality:        'var(--fl-accent)',
  'deep':         'var(--fl-pink)',
  reasoning:      'var(--fl-accent)',
  light:          'var(--fl-warn)',
  recent:         'var(--fl-purple)',
  agent:          'var(--fl-accent)',
  powerful:       'var(--fl-danger)',
};

const ACTIVE_MODEL_KEY = 'heimdall.ai.activeModel';

function AiSettingsTab() {
  const { t } = useTranslation();
  const [status, setStatus]           = useState(null);
  const [loading, setLoading]         = useState(false);
  const [testModel, setTestModel]     = useState('');
  const [testResult, setTestResult]   = useState('');
  const [testing, setTesting]         = useState(false);
  const [pullState, setPullState]     = useState({});
  const [deleting, setDeleting]       = useState({});
  const [activeModel, setActiveModel] = useState(() => localStorage.getItem(ACTIVE_MODEL_KEY) || '');
  const [activeSaved, setActiveSaved] = useState(false);
  const [ollamaStatus, setOllamaStatus] = useState(null);
  const [ollamaInstall, setOllamaInstall] = useState(null);
  const [ollamaStopping, setOllamaStopping] = useState(false);
  const abortRefs = useRef({});

  const token = localStorage.getItem('heimdall_token');

  const loadOllamaStatus = useCallback(async () => {
    try {
      const r = await fetch('/api/admin/ollama/status', { headers: { Authorization: `Bearer ${token}` } });
      if (r.ok) setOllamaStatus(await r.json());
    } catch {}
  }, [token]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch('/api/llm/models', { headers: { Authorization: `Bearer ${token}` } });
      const d = await r.json();
      setStatus(d);
      if (d.models?.length && !testModel) setTestModel(d.models[0]);
    } catch {
      setStatus({ available: false, models: [] });
    } finally { setLoading(false); }
  }, [token, testModel]);

  useEffect(() => {
    load();
    loadOllamaStatus();
    // Server-side active model is the source of truth (shared across analysts).
    fetch('/api/settings/ai', { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.json())
      .then(d => { if (d?.active_model) { setActiveModel(d.active_model); localStorage.setItem(ACTIVE_MODEL_KEY, d.active_model); } })
      .catch(() => {});
  }, [load, loadOllamaStatus]);

  async function installOllama() {
    if (ollamaInstall?.phase === 'pull' || ollamaInstall?.phase === 'create' || ollamaInstall?.phase === 'starting') return;
    setOllamaInstall({ phase: 'connecting', message: t('admin.ai.connecting_docker'), pct: 0, error: null });
    try {
      const res = await fetch('/api/admin/ollama/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split('\n'); buf = lines.pop() ?? '';
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const d = line.slice(6);
          if (d === '[DONE]') { await loadOllamaStatus(); await load(); break; }
          try {
            const j = JSON.parse(d);
            setOllamaInstall({ phase: j.phase, message: j.message, pct: j.pct ?? 0, error: j.phase === 'error' ? j.message : null });
          } catch {}
        }
      }
    } catch (e) {
      setOllamaInstall({ phase: 'error', message: e.message, pct: 0, error: e.message });
    }
  }

  async function stopOllama() {
    setOllamaStopping(true);
    try {
      await fetch('/api/admin/ollama/stop', { method: 'POST', headers: { Authorization: `Bearer ${token}` } });
      await loadOllamaStatus();
    } catch {}
    setOllamaStopping(false);
  }

  async function runTest() {
    if (!testModel || testing) return;
    setTesting(true); setTestResult('');
    try {
      const res = await fetch('/api/llm/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ model: testModel, prompt: t('admin.ai.test_prompt'), stream: true }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split('\n'); buf = lines.pop() ?? '';
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const d = line.slice(6);
          if (d === '[DONE]') break;
          try { const j = JSON.parse(d); if (j.response) setTestResult(p => p + j.response); } catch {}
        }
      }
    } catch (e) { setTestResult(t('admin.ai.error_result', { message: e.message })); }
    finally { setTesting(false); }
  }

  async function pullModel(modelId) {
    if (pullState[modelId]?.pulling) return;
    const ctrl = new AbortController();
    abortRefs.current[modelId] = ctrl;
    setPullState(p => ({ ...p, [modelId]: { pulling: true, phase: t('admin.ai.connecting'), pct: 0, done: false, error: null } }));
    try {
      const res = await fetch('/api/llm/pull', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ model: modelId }),
        signal: ctrl.signal,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split('\n'); buf = lines.pop() ?? '';
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const d = line.slice(6);
          if (d === '[DONE]') { setPullState(p => ({ ...p, [modelId]: { ...p[modelId], pulling: false, done: true, pct: 100 } })); break; }
          try {
            const j = JSON.parse(d);
            const pct = j.total > 0 ? Math.round((j.completed / j.total) * 100) : 0;
            setPullState(p => ({ ...p, [modelId]: { pulling: true, phase: j.status || t('admin.ai.downloading'), pct: pct || p[modelId]?.pct || 0, done: false, error: null } }));
          } catch {}
        }
      }
      await load();
    } catch (e) {
      if (e.name !== 'AbortError') {
        setPullState(p => ({ ...p, [modelId]: { pulling: false, done: false, pct: 0, error: e.message } }));
      } else {
        setPullState(p => ({ ...p, [modelId]: null }));
      }
    }
  }

  async function removeModel(modelId) {
    setDeleting(p => ({ ...p, [modelId]: true }));
    try {
      await fetch(`/api/llm/models/${encodeURIComponent(modelId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      await load();
    } catch {}
    setDeleting(p => ({ ...p, [modelId]: false }));
  }

  const ok = status?.available;
  const installed = new Set(status?.models || []);

  const ollamaRunning = ollamaStatus?.running;
  const ollamaExists  = ollamaStatus?.exists;
  const installBusy   = ollamaInstall && ['pull','create','starting','connecting'].includes(ollamaInstall.phase);

  return (
    <div>
      <style>{`@keyframes indeterminate { 0%{transform:translateX(-100%)} 100%{transform:translateX(200%)} }`}</style>
      
      <div style={{
        marginBottom: 24,
        background: 'var(--fl-panel)', border: `1px solid ${ollamaRunning ? 'color-mix(in srgb, var(--fl-ok) 30%, var(--fl-border))' : 'var(--fl-border)'}`,
        borderRadius: 8, padding: '16px 20px',
      }}>
        <div className="flex items-center gap-3 mb-3">
          <div style={{ width: 10, height: 10, borderRadius: '50%', background: ollamaRunning ? 'var(--fl-ok)' : ollamaExists ? 'var(--fl-warn)' : 'var(--fl-danger)', boxShadow: ollamaRunning ? '0 0 6px var(--fl-ok)' : 'none', flexShrink: 0 }} />
          <h4 style={{ fontWeight: 600, fontSize: 14, color: 'var(--fl-text)', margin: 0 }}>{t('admin.ai.ollama_service')}</h4>
          <span style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: ollamaRunning ? 'var(--fl-ok)' : ollamaExists ? 'var(--fl-warn)' : 'var(--fl-muted)' }}>
            {ollamaStatus === null ? '…' : ollamaRunning ? t('admin.ai.running') : ollamaExists ? t('admin.ai.stopped_state', { state: ollamaStatus.state }) : t('admin.ai.not_installed')}
          </span>
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
            <Button variant="ghost" size="sm" icon={RefreshCw} onClick={loadOllamaStatus} />
            {ollamaRunning ? (
              <Button variant="danger" size="sm" loading={ollamaStopping} onClick={stopOllama}>{t('admin.ai.stop_ollama')}</Button>
            ) : (
              <Button variant="primary" size="sm" icon={Bot} loading={installBusy} onClick={installOllama}>
                {ollamaExists ? t('admin.ai.start_ollama') : t('admin.ai.install_ollama')}
              </Button>
            )}
          </div>
        </div>

        {ollamaInstall && (
          <div style={{ marginTop: 8 }}>
            {ollamaInstall.phase !== 'error' && ollamaInstall.phase !== 'done' && (
              <div style={{ marginBottom: 6 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                  <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-warn)' }}>{ollamaInstall.message}</span>
                  {ollamaInstall.pct > 0 && <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-warn)' }}>{ollamaInstall.pct}%</span>}
                </div>
                <div style={{ height: 5, background: 'var(--fl-border)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: ollamaInstall.pct > 0 ? `${ollamaInstall.pct}%` : '100%', background: 'linear-gradient(90deg, var(--fl-warn), var(--fl-warn))', borderRadius: 3, transition: 'width 0.3s', animation: ollamaInstall.pct === 0 ? 'indeterminate 1.5s ease-in-out infinite' : 'none' }} />
                </div>
              </div>
            )}
            {ollamaInstall.phase === 'done' && <div style={{ fontSize: 11, color: 'var(--fl-ok)' }}>✓ {ollamaInstall.message}</div>}
            {ollamaInstall.phase === 'error' && <div style={{ fontSize: 11, color: 'var(--fl-danger)' }}>⚠ {ollamaInstall.error}</div>}
          </div>
        )}

        {!ollamaRunning && ollamaInstall?.phase !== 'done' && (
          <p style={{ fontSize: 11, color: 'var(--fl-muted)', margin: '8px 0 0' }}>
            {t('admin.ai.ollama_hint_before')} <code style={{ color: 'var(--fl-accent)' }}>ollama/ollama:latest</code> {t('admin.ai.ollama_hint_middle')} <code style={{ color: 'var(--fl-accent)' }}>aesir-net</code>. {t('admin.ai.ollama_hint_after')} <code style={{ color: 'var(--fl-accent)' }}>OLLAMA_URL=http://ollama:11434</code> {t('admin.ai.ollama_hint_end')}
          </p>
        )}
      </div>

      <div className="flex items-center gap-3 mb-5">
        <h3 className="font-semibold" style={{ color: 'var(--fl-text)' }}>{t('admin.ai.installed_models')}</h3>
        <Button variant="ghost" size="sm" icon={RefreshCw} loading={loading} onClick={load}>{t('common.refresh')}</Button>
        <span style={{
          marginLeft: 'auto', fontSize: 11, fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
          padding: '2px 10px', borderRadius: 10,
          background: ok ? 'color-mix(in srgb, var(--fl-ok) 12%, transparent)' : 'color-mix(in srgb, var(--fl-danger) 12%, transparent)',
          color: ok ? 'var(--fl-ok)' : 'var(--fl-danger)',
          border: `1px solid ${ok ? 'color-mix(in srgb, var(--fl-ok) 30%, transparent)' : 'color-mix(in srgb, var(--fl-danger) 30%, transparent)'}`,
        }}>
          {loading ? '…' : ok ? t('admin.ai.connected_badge') : t('admin.ai.unavailable_badge')}
        </span>
      </div>

      {!ok && !loading && (
        <div style={{ background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 8, padding: '18px 22px', marginBottom: 24 }}>
          <h4 style={{ fontSize: 13, fontWeight: 600, color: 'var(--fl-text)', marginBottom: 10 }}>{t('admin.ai.enable_title')}</h4>
          <p style={{ fontSize: 12, color: 'var(--fl-muted)', marginBottom: 8 }}>{t('admin.ai.enable_step_start')}</p>
          <pre style={{ background: 'var(--fl-bg)', borderRadius: 6, padding: '7px 12px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-accent)', border: '1px solid var(--fl-border)', margin: '0 0 12px' }}>docker compose --profile ai up -d ollama</pre>
          <p style={{ fontSize: 12, color: 'var(--fl-muted)', marginBottom: 8 }}>{t('admin.ai.enable_step_env_before')} <code style={{ color: 'var(--fl-accent)' }}>.env</code> {t('admin.ai.enable_step_env_after')}</p>
          <pre style={{ background: 'var(--fl-bg)', borderRadius: 6, padding: '7px 12px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-accent)', border: '1px solid var(--fl-border)', margin: 0 }}>OLLAMA_URL=http://ollama:11434</pre>
          <p style={{ fontSize: 11, color: 'var(--fl-muted)', marginTop: 10 }}>{t('admin.ai.enable_done_hint')}</p>
        </div>
      )}

      {ok && installed.size > 0 && (
        <div style={{ background: 'var(--fl-panel)', border: '1px solid color-mix(in srgb, var(--fl-accent) 35%, var(--fl-border))', borderRadius: 8, padding: '14px 18px', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Bot size={14} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} />
            <span style={{ fontSize: 12, color: 'var(--fl-text)', fontWeight: 700 }}>{t('admin.ai.active_model')}</span>
            <select
              value={activeModel || [...installed][0] || ''}
              onChange={e => { setActiveModel(e.target.value); setActiveSaved(false); }}
              className="fl-select"
              style={{ flex: 1, maxWidth: 280 }}
            >
              {[...installed].map(m => <option key={m} value={m}>{m}</option>)}
            </select>
            <Button
              variant="primary"
              size="sm"
              onClick={async () => {
                const chosen = activeModel || [...installed][0] || '';
                localStorage.setItem(ACTIVE_MODEL_KEY, chosen);
                setActiveModel(chosen);
                // Persist server-side so the whole AI stack (chat de case, rapport, agentique) uses it.
                try {
                  await fetch('/api/settings/ai', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
                    body: JSON.stringify({ active_model: chosen }),
                  });
                } catch (_e) { /* localStorage still set */ }
                setActiveSaved(true);
                setTimeout(() => setActiveSaved(false), 2500);
              }}
            >
              {activeSaved ? t('settings.messages.saved') : t('admin.ai.set_active')}
            </Button>
          </div>
          <p style={{ fontSize: 11, color: 'var(--fl-muted)', margin: '8px 0 0' }}>
            {t('admin.ai.active_model_hint')}
          </p>
        </div>
      )}

      {ok && installed.size > 0 && (
        <div style={{ background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 8, padding: '14px 18px', marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 12, color: 'var(--fl-text)', fontWeight: 600 }}>{t('admin.ai.test')}</span>
            <select value={testModel} onChange={e => setTestModel(e.target.value)} className="fl-select" style={{ flex: 1, maxWidth: 260 }}>
              {[...installed].map(m => <option key={m} value={m}>{m}</option>)}
            </select>
            <Button variant="primary" size="sm" loading={testing} onClick={runTest} icon={Bot}>{t('admin.ai.run_test')}</Button>
          </div>
          {(testing || testResult) && (
            <div style={{ marginTop: 10, background: 'var(--fl-bg)', borderRadius: 6, padding: '10px 14px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-text)', minHeight: 36, whiteSpace: 'pre-wrap', border: '1px solid var(--fl-border)' }}>
              {testing && !testResult ? <span style={{ color: 'var(--fl-muted)' }}>{t('admin.ai.generating')}</span> : testResult}
            </div>
          )}
        </div>
      )}

      <h4 style={{ fontSize: 13, fontWeight: 600, color: 'var(--fl-text)', marginBottom: 12 }}>
        {t('admin.ai.model_catalog')}
        <span style={{ fontSize: 11, fontWeight: 400, color: 'var(--fl-muted)', marginLeft: 8 }}>{t('admin.ai.install_hint')}</span>
      </h4>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {MODEL_CATALOG.map(m => {
          const isInstalled = installed.has(m.id);
          const ps = pullState[m.id];
          const isDel = deleting[m.id];
          return (
            <div key={m.id} style={{
              display: 'flex', alignItems: 'center', gap: 14,
              background: 'var(--fl-panel)', border: `1px solid ${isInstalled ? 'color-mix(in srgb, var(--fl-ok) 20%, var(--fl-border))' : 'var(--fl-border)'}`,
              borderRadius: 8, padding: '12px 16px',
            }}>
              
              <div style={{ width: 9, height: 9, borderRadius: '50%', flexShrink: 0, background: isInstalled ? 'var(--fl-ok)' : ps?.pulling ? 'var(--fl-warn)' : ps?.done ? 'var(--fl-ok)' : 'var(--fl-border)', boxShadow: isInstalled ? '0 0 5px var(--fl-ok)' : 'none' }} />

              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
                  <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--fl-text)' }}>{m.label}</span>
                  <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)' }}>{m.id}</span>
                  {m.tag && <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 6px', borderRadius: 3, background: `color-mix(in srgb, ${TAG_COLOR[m.tag]} 9%, transparent)`, color: TAG_COLOR[m.tag], border: `1px solid color-mix(in srgb, ${TAG_COLOR[m.tag]} 19%, transparent)` }}>{t(`admin.ai.tags.${m.tag}`)}</span>}
                  <span style={{ fontSize: 10, color: 'var(--fl-muted)', marginLeft: 'auto' }}>{m.size}</span>
                </div>
                <div style={{ fontSize: 11, color: 'var(--fl-muted)' }}>{t(`admin.ai.models.${m.descKey}`)}</div>

                {ps?.pulling && (
                  <div style={{ marginTop: 6 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                      <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-warn)' }}>{ps.phase}</span>
                      <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-warn)' }}>{ps.pct}%</span>
                    </div>
                    <div style={{ height: 4, background: 'var(--fl-border)', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${ps.pct}%`, background: 'linear-gradient(90deg, var(--fl-warn), var(--fl-warn))', borderRadius: 2, transition: 'width 0.3s' }} />
                    </div>
                  </div>
                )}
                {ps?.error && <div style={{ fontSize: 10, color: 'var(--fl-danger)', marginTop: 4 }}>⚠ {ps.error}</div>}
                {ps?.done && !isInstalled && <div style={{ fontSize: 10, color: 'var(--fl-ok)', marginTop: 4 }}>{t('admin.ai.install_done_refresh')}</div>}
              </div>

              <div style={{ flexShrink: 0, display: 'flex', gap: 6 }}>
                {isInstalled ? (
                  <>
                    <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-ok)', padding: '3px 8px', border: '1px solid color-mix(in srgb, var(--fl-ok) 30%, transparent)', borderRadius: 4 }}>{t('admin.ai.installed_badge')}</span>
                    <Button variant="danger" size="sm" loading={isDel} onClick={() => removeModel(m.id)}>{t('common.delete')}</Button>
                  </>
                ) : ps?.pulling ? (
                  <Button variant="secondary" size="sm" onClick={() => { abortRefs.current[m.id]?.abort(); }}>{t('common.cancel')}</Button>
                ) : (
                  <Button variant="primary" size="sm" icon={Bot} disabled={!ok} onClick={() => pullModel(m.id)}>
                    {ok ? t('admin.ai.install') : t('admin.ai.ollama_required')}
                  </Button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

const OPEN_SOURCE_CREDITS = [
  {
    name: "Eric Zimmerman's Tools (MFTECmd, PECmd, LECmd, EvtxECmd…)",
    author: 'Eric Zimmerman',
    license: 'MIT',
    descriptionKey: 'zimmerman',
  },
  {
    name: 'Hayabusa',
    author: 'Yamato Security',
    license: 'GNU GPL 3.0',
    descriptionKey: 'hayabusa',
  },
  {
    name: 'VolWeb',
    author: 'k1nd0ne',
    license: 'MIT',
    descriptionKey: 'volweb',
  },
  {
    name: 'Volatility 3',
    author: 'Volatility Foundation',
    license: 'Volatility Software License',
    descriptionKey: 'volatility3',
  },
];

const ACCESS_FETCH_SIZE = 10000; // rows per cursor-page
const ACCESS_ROW_H      = 34;
const LOG_ROW_H         = 28;
const VIRT_OVERSCAN     = 15;
const TABLE_HEIGHT      = 620; // px — virtualizer container height

function LogsTab({ users }) {
  const { t, i18n } = useTranslation();
  const [subTab, setSubTab] = useState('access');

  // ── Access log state ──
  const [accessRows,     setAccessRows]     = useState([]);
  const [accessTotal,    setAccessTotal]    = useState(0);
  const [accessLoading,  setAccessLoading]  = useState(false);
  const [loadingAll,     setLoadingAll]     = useState(false);
  const [loadProgress,   setLoadProgress]   = useState(0);   // loaded so far during "Tout charger"
  const [nextCursor,     setNextCursor]     = useState(null);
  const [accessMethod,   setAccessMethod]   = useState('');
  const [accessUser,     setAccessUser]     = useState('');
  const [accessFrom,     setAccessFrom]     = useState('');
  const [accessTo,       setAccessTo]       = useState('');
  const [accessPath,     setAccessPath]     = useState('');
  const abortRef = useRef(false);

  // ── Server log state ──
  const [logLines,  setLogLines]  = useState([]);
  const [logTotal,  setLogTotal]  = useState(0);
  const [logLoading, setLogLoading] = useState(false);
  const [logSearch, setLogSearch] = useState('');
  const [logLevel,  setLogLevel]  = useState('');
  const [logNote,   setLogNote]   = useState('');

  // ── Scroll containers for virtualizers ──
  const accessScrollRef = useRef(null);
  const logScrollRef    = useRef(null);

  // ── Virtualizers ──
  const accessVirt = useVirtualizer({
    count:            accessRows.length,
    getScrollElement: () => accessScrollRef.current,
    estimateSize:     () => ACCESS_ROW_H,
    overscan:         VIRT_OVERSCAN,
  });
  const logVirt = useVirtualizer({
    count:            logLines.length,
    getScrollElement: () => logScrollRef.current,
    estimateSize:     () => LOG_ROW_H,
    overscan:         VIRT_OVERSCAN,
  });

  const buildAccessParams = useCallback(() => {
    const p = { limit: ACCESS_FETCH_SIZE };
    if (accessMethod) p.method    = accessMethod;
    if (accessUser)   p.user_id   = accessUser;
    if (accessFrom)   p.date_from = accessFrom;
    if (accessTo)     p.date_to   = accessTo;
    if (accessPath)   p.path      = accessPath;
    return p;
  }, [accessMethod, accessUser, accessFrom, accessTo, accessPath]);

  // Initial load: first page only
  const loadAccess = useCallback(async () => {
    setAccessLoading(true);
    setAccessRows([]);
    setNextCursor(null);
    try {
      const { data } = await adminAPI.accessLogs(buildAccessParams());
      setAccessRows(data.rows || []);
      setAccessTotal(data.total ?? 0);
      setNextCursor(data.next_cursor ?? null);
    } catch {
      setAccessRows([]);
      setAccessTotal(0);
    }
    setAccessLoading(false);
  }, [buildAccessParams]);

  // Load ALL rows in cursor-batches of ACCESS_FETCH_SIZE
  const loadAll = useCallback(async () => {
    setLoadingAll(true);
    abortRef.current = false;
    let cursor = null;
    let accumulated = [...accessRows];
    setLoadProgress(accumulated.length);

    try {
      do {
        if (abortRef.current) break;
        const params = { ...buildAccessParams(), cursor: cursor || undefined };
        const { data } = await adminAPI.accessLogs(params);
        const newRows = data.rows || [];
        accumulated = [...accumulated, ...newRows];
        cursor = data.next_cursor ?? null;
        setAccessRows([...accumulated]);
        setLoadProgress(accumulated.length);
      } while (cursor && !abortRef.current);
    } catch {
      // keep what we have
    }
    setLoadingAll(false);
    setLoadProgress(0);
  }, [accessRows, buildAccessParams]);

  // Load more (one page, append)
  const loadMore = useCallback(async () => {
    if (!nextCursor || accessLoading) return;
    setAccessLoading(true);
    try {
      const params = { ...buildAccessParams(), cursor: nextCursor };
      const { data } = await adminAPI.accessLogs(params);
      setAccessRows(prev => [...prev, ...(data.rows || [])]);
      setNextCursor(data.next_cursor ?? null);
    } catch {}
    setAccessLoading(false);
  }, [nextCursor, accessLoading, buildAccessParams]);

  const loadLogs = useCallback(async () => {
    setLogLoading(true);
    try {
      const params = { limit: logSearch || logLevel ? 10000 : 2000 };
      if (logSearch) params.search = logSearch;
      if (logLevel)  params.level  = logLevel;
      const { data } = await adminAPI.serverLogs(params);
      setLogLines(data.lines || []);
      setLogTotal(data.total || 0);
      setLogNote(data.note  || '');
    } catch {
      setLogLines([]);
      setLogTotal(0);
    }
    setLogLoading(false);
  }, [logSearch, logLevel]);

  useEffect(() => {
    if (subTab === 'access') loadAccess();
    else loadLogs();
  }, [subTab]); // eslint-disable-line react-hooks/exhaustive-deps

  const METHOD_COLOR = {
    GET: 'var(--fl-ok)', POST: 'var(--fl-accent)',
    PUT: 'var(--fl-warn)', DELETE: 'var(--fl-danger)',
    PATCH: 'var(--fl-accent)',
  };
  const LEVEL_COLOR = {
    error: 'var(--fl-danger)', warn: 'var(--fl-warn)',
    info: 'var(--fl-accent)', debug: 'var(--fl-muted)',
    http: 'var(--fl-dim)', raw: 'var(--fl-dim)',
  };

  // ── Column widths (px) ──
  const A_COLS = [148, 100, 68, null, 56, 72, 100]; // last null = flex

  return (
    <div>
      {/* Sub-tab switcher */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
        {[
          { id: 'access', label: t('admin.logs.access_tab') },
          { id: 'server', label: t('admin.logs.server_tab') },
        ].map(s => (
          <button
            key={s.id}
            onClick={() => setSubTab(s.id)}
            style={{
              padding: '6px 16px', borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: 'pointer',
              background: subTab === s.id ? 'color-mix(in srgb, var(--fl-accent) 12%, transparent)' : 'var(--fl-panel)',
              color: subTab === s.id ? 'var(--fl-accent)' : 'var(--fl-muted)',
              border: subTab === s.id ? '1px solid color-mix(in srgb, var(--fl-accent) 30%, transparent)' : '1px solid var(--fl-border)',
            }}
          >
            {s.label}
          </button>
        ))}
      </div>

      {/* ══ ACCESS LOG ══ */}
      {subTab === 'access' && (
        <div>
          {/* Filters */}
          <div className="rounded-xl p-4 mb-4 border" style={{ background: 'var(--fl-panel)', borderColor: 'var(--fl-border)' }}>
            <div className="grid gap-3 mb-3" style={{ gridTemplateColumns: '1fr 1fr 1fr 1fr 1fr' }}>
              <div>
                <label className="fl-label">{t('admin.logs.method')}</label>
                <select value={accessMethod} onChange={e => setAccessMethod(e.target.value)} className="fl-select w-full">
                  <option value="">{t('admin.logs.all_feminine')}</option>
                  {['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].map(m => <option key={m} value={m}>{m}</option>)}
                </select>
              </div>
              <div>
                <label className="fl-label">{t('admin.col_user')}</label>
                <select value={accessUser} onChange={e => setAccessUser(e.target.value)} className="fl-select w-full">
                  <option value="">{t('admin.filter_all')}</option>
                  {users.map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
                </select>
              </div>
              <div>
                <label className="fl-label">{t('admin.logs.path_contains')}</label>
                <input value={accessPath} onChange={e => setAccessPath(e.target.value)} className="fl-input w-full" placeholder="/api/cases" />
              </div>
              <div>
                <label className="fl-label">{t('admin.filter_label_from')}</label>
                <input type="date" value={accessFrom} onChange={e => setAccessFrom(e.target.value)} className="fl-input w-full" />
              </div>
              <div>
                <label className="fl-label">{t('admin.filter_label_to')}</label>
                <input type="date" value={accessTo} onChange={e => setAccessTo(e.target.value)} className="fl-input w-full" />
              </div>
            </div>

            <div className="flex items-center justify-between gap-3">
              <span className="text-xs font-mono" style={{ color: 'var(--fl-muted)' }}>
                {t(accessRows.length !== 1 ? 'admin.logs.loaded_count_many' : 'admin.logs.loaded_count_one', { count: accessRows.length.toLocaleString(i18n.language) })}
                {accessTotal > 0 && ` / ${t('admin.logs.total_count', { count: accessTotal.toLocaleString(i18n.language) })}`}
                {loadingAll && loadProgress > 0 && (
                  <span style={{ color: 'var(--fl-accent)', marginLeft: 8 }}>
                    · {t('admin.logs.loading_progress', { count: loadProgress.toLocaleString(i18n.language) })}
                  </span>
                )}
              </span>
              <div style={{ display: 'flex', gap: 6 }}>
                <Button variant="ghost" size="sm" icon={RefreshCw} loading={accessLoading && !loadingAll} onClick={loadAccess}>
                  {t('admin.logs.apply')}
                </Button>
                {nextCursor && !loadingAll && (
                  <Button variant="ghost" size="sm" loading={accessLoading} onClick={loadMore}>
                    +{ACCESS_FETCH_SIZE.toLocaleString(i18n.language)}
                  </Button>
                )}
                {(nextCursor || accessRows.length < (accessTotal || 0)) && !loadingAll && (
                  <Button variant="primary" size="sm" onClick={loadAll}>
                    {t('admin.logs.load_all')}
                  </Button>
                )}
                {loadingAll && (
                  <Button variant="danger" size="sm" onClick={() => { abortRef.current = true; }}>
                    {t('common.cancel')}
                  </Button>
                )}
              </div>
            </div>
          </div>

          {accessLoading && accessRows.length === 0 ? (
            <Spinner full text={t('common.loading')} />
          ) : accessRows.length === 0 ? (
            <EmptyState icon={FileText} title={t('admin.logs.no_requests')} subtitle={t('admin.logs.no_requests_sub')} />
          ) : (
            <div style={{ borderRadius: 8, border: '1px solid var(--fl-border)', overflow: 'hidden', background: 'var(--fl-panel)' }}>
              {/* Sticky header */}
              <table style={{ tableLayout: 'fixed', width: '100%', borderCollapse: 'collapse' }}>
                <colgroup>
                  <col style={{ width: A_COLS[0] }} />
                  <col style={{ width: A_COLS[1] }} />
                  <col style={{ width: A_COLS[2] }} />
                  <col />
                  <col style={{ width: A_COLS[4] }} />
                  <col style={{ width: A_COLS[5] }} />
                  <col style={{ width: A_COLS[6] }} />
                </colgroup>
                <thead>
                  <tr style={{ background: 'var(--fl-panel)', borderBottom: '1px solid var(--fl-border)' }}>
                    {[t('admin.col_timestamp'), t('admin.col_user'), t('admin.logs.method'), 'Path', t('admin.col_status'), 'ms', 'IP'].map(h => (
                      <th key={h} style={{ padding: '7px 10px', textAlign: 'left', fontSize: 10, fontWeight: 700, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
              </table>

              {/* Virtualized body */}
              <div
                ref={accessScrollRef}
                style={{ height: TABLE_HEIGHT, overflow: 'auto' }}
              >
                <div style={{ height: accessVirt.getTotalSize(), position: 'relative' }}>
                  <table style={{ tableLayout: 'fixed', width: '100%', borderCollapse: 'collapse', position: 'absolute', top: 0, left: 0 }}>
                    <colgroup>
                      <col style={{ width: A_COLS[0] }} />
                      <col style={{ width: A_COLS[1] }} />
                      <col style={{ width: A_COLS[2] }} />
                      <col />
                      <col style={{ width: A_COLS[4] }} />
                      <col style={{ width: A_COLS[5] }} />
                      <col style={{ width: A_COLS[6] }} />
                    </colgroup>
                    <tbody>
                      {accessVirt.getVirtualItems().map(vi => {
                        const row = accessRows[vi.index];
                        const mc  = METHOD_COLOR[row.method] || 'var(--fl-dim)';
                        const sc  = row.status_code >= 500 ? 'var(--fl-danger)' : row.status_code >= 400 ? 'var(--fl-warn)' : 'var(--fl-ok)';
                        return (
                          <tr
                            key={vi.key}
                            style={{
                              height: ACCESS_ROW_H,
                              transform: `translateY(${vi.start}px)`,
                              borderBottom: '1px solid color-mix(in srgb, var(--fl-border) 50%, transparent)',
                            }}
                          >
                            <td style={{ padding: '0 10px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: 'var(--fl-dim)', whiteSpace: 'nowrap', overflow: 'hidden' }}>
                              {fmtLocal(row.created_at)}
                            </td>
                            <td style={{ padding: '0 10px', overflow: 'hidden' }}>
                              <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, padding: '1px 6px', borderRadius: 3, background: 'color-mix(in srgb, var(--fl-accent) 8%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 20%, transparent)' }}>
                                {row.username || '—'}
                              </span>
                            </td>
                            <td style={{ padding: '0 10px', overflow: 'hidden' }}>
                              <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, padding: '1px 6px', borderRadius: 3, background: `color-mix(in srgb, ${mc} 8%, transparent)`, color: mc, border: `1px solid color-mix(in srgb, ${mc} 16%, transparent)`, textTransform: 'uppercase' }}>
                                {row.method}
                              </span>
                            </td>
                            <td style={{ padding: '0 10px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: 'var(--fl-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={row.path}>
                              {row.path}
                            </td>
                            <td style={{ padding: '0 10px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, fontWeight: 700, color: sc }}>
                              {row.status_code}
                            </td>
                            <td style={{ padding: '0 10px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: row.response_ms > 1000 ? 'var(--fl-warn)' : 'var(--fl-dim)' }}>
                              {row.response_ms != null ? `${row.response_ms}` : '—'}
                            </td>
                            <td style={{ padding: '0 10px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: 'var(--fl-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {row.ip_address || '—'}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Footer: load-more sentinel */}
              {nextCursor && (
                <div style={{ padding: '8px 14px', borderTop: '1px solid var(--fl-border)', display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ fontSize: 11, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                    {t('admin.logs.loaded_lines_ratio', { loaded: accessRows.length.toLocaleString(i18n.language), total: accessTotal?.toLocaleString(i18n.language) })}
                  </span>
                  <Button variant="ghost" size="sm" loading={accessLoading} onClick={loadMore}>{t('admin.logs.load_more', { count: ACCESS_FETCH_SIZE.toLocaleString(i18n.language) })}</Button>
                  <Button variant="primary" size="sm" loading={loadingAll} onClick={loadAll}>{t('admin.logs.load_all')}</Button>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ══ SERVER / APP LOGS ══ */}
      {subTab === 'server' && (
        <div>
          <div className="rounded-xl p-4 mb-4 border" style={{ background: 'var(--fl-panel)', borderColor: 'var(--fl-border)' }}>
            <div className="grid gap-3 mb-3" style={{ gridTemplateColumns: '1fr 1fr auto' }}>
              <div>
                <label className="fl-label">{t('common.search')}</label>
                <input value={logSearch} onChange={e => setLogSearch(e.target.value)} className="fl-input w-full" placeholder="error, migration, socket…" />
              </div>
              <div>
                <label className="fl-label">{t('admin.logs.level')}</label>
                <select value={logLevel} onChange={e => setLogLevel(e.target.value)} className="fl-select w-full">
                  <option value="">{t('admin.filter_all')}</option>
                  {['error', 'warn', 'info', 'http', 'debug'].map(l => <option key={l} value={l}>{l}</option>)}
                </select>
              </div>
              <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                <Button variant="ghost" size="sm" icon={RefreshCw} loading={logLoading} onClick={loadLogs}>
                  {t('common.refresh')}
                </Button>
              </div>
            </div>
            <span className="text-xs font-mono" style={{ color: 'var(--fl-muted)' }}>
              {t(logLines.length !== 1 ? 'admin.logs.displayed_count_many' : 'admin.logs.displayed_count_one', { shown: logLines.length.toLocaleString(i18n.language), total: logTotal.toLocaleString(i18n.language) })}
            </span>
          </div>

          {logNote && (
            <div style={{ marginBottom: 12, padding: '10px 14px', borderRadius: 8, background: 'color-mix(in srgb, var(--fl-warn) 6%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-warn) 20%, transparent)', fontSize: 12, color: 'var(--fl-warn)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
              ⚠ {logNote}
            </div>
          )}

          {logLoading ? (
            <Spinner full text={t('admin.logs.reading_file')} />
          ) : logLines.length === 0 ? (
            <EmptyState icon={FileText} title={t('admin.logs.no_entries')} subtitle={t('admin.logs.no_entries_sub')} />
          ) : (
            <div style={{ borderRadius: 8, border: '1px solid var(--fl-border)', overflow: 'hidden', background: 'var(--fl-panel)' }}>
              <div
                ref={logScrollRef}
                style={{ height: TABLE_HEIGHT, overflow: 'auto' }}
              >
                <div style={{ height: logVirt.getTotalSize(), position: 'relative' }}>
                  {logVirt.getVirtualItems().map(vi => {
                    const entry = logLines[vi.index];
                    const lc = LEVEL_COLOR[entry.level] || 'var(--fl-dim)';
                    return (
                      <div
                        key={vi.key}
                        style={{
                          position: 'absolute', top: vi.start, left: 0, right: 0,
                          height: LOG_ROW_H,
                          display: 'grid', gridTemplateColumns: '150px 44px 1fr',
                          gap: 10, padding: '0 14px', alignItems: 'center',
                          fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11,
                          borderBottom: '1px solid color-mix(in srgb, var(--fl-border) 40%, transparent)',
                        }}
                      >
                        <span style={{ color: 'var(--fl-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontSize: 10 }}>
                          {entry.timestamp ? new Date(entry.timestamp).toLocaleString(i18n.language) : '—'}
                        </span>
                        <span style={{ color: lc, fontWeight: 700, textTransform: 'uppercase', fontSize: 9 }}>
                          {entry.level || '?'}
                        </span>
                        <span style={{ color: 'var(--fl-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={typeof entry.message === 'string' ? entry.message : JSON.stringify(entry)}>
                          {typeof entry.message === 'string' ? entry.message : JSON.stringify(entry)}
                          {entry.requestId && <span style={{ color: 'var(--fl-muted)', marginLeft: 8 }}>[{entry.requestId}]</span>}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function AboutTab() {
  const { t } = useTranslation();
  const [open, setOpen] = React.useState(true);
  return (
    <div style={{ maxWidth: 760 }}>
      <div style={{ marginBottom: 24 }}>
        <h2 style={{ fontSize: 20, fontWeight: 600, color: 'var(--fl-text)', marginBottom: 4, fontFamily: 'var(--f-display, var(--f-ui))', letterSpacing: '-0.01em' }}>Heimdall DFIR</h2>
        <p style={{ fontSize: 13, color: 'var(--fl-muted)', lineHeight: 1.6 }}>
          {t('admin.about.subtitle')}
        </p>
      </div>

      <div style={{ background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 8, overflow: 'hidden', marginBottom: 24 }}>
        <button
          onClick={() => setOpen(v => !v)}
          style={{
            width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '14px 18px', background: 'none', border: 'none', cursor: 'pointer',
            color: 'var(--fl-text)', fontSize: 14, fontWeight: 700,
          }}
        >
          <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Shield size={16} style={{ color: 'var(--fl-accent)' }} />
            {t('admin.about.opensource_tools')}
          </span>
          <span style={{ fontSize: 11, color: 'var(--fl-muted)', fontWeight: 400 }}>{open ? t('admin.about.collapse') : t('admin.about.show')}</span>
        </button>

        {open && (
          <div style={{ padding: '0 18px 18px' }}>
            <p style={{ fontSize: 12, color: 'var(--fl-muted)', marginBottom: 16, lineHeight: 1.5 }}>
              {t('admin.about.credits_hint')}
            </p>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--fl-border)' }}>
                  <th style={{ textAlign: 'left', padding: '6px 10px', color: 'var(--fl-muted)', fontWeight: 600, fontSize: 11 }}>{t('admin.about.tool')}</th>
                  <th style={{ textAlign: 'left', padding: '6px 10px', color: 'var(--fl-muted)', fontWeight: 600, fontSize: 11 }}>{t('admin.about.author')}</th>
                  <th style={{ textAlign: 'left', padding: '6px 10px', color: 'var(--fl-muted)', fontWeight: 600, fontSize: 11 }}>{t('admin.about.license')}</th>
                  <th style={{ textAlign: 'left', padding: '6px 10px', color: 'var(--fl-muted)', fontWeight: 600, fontSize: 11 }}>{t('admin.about.description')}</th>
                </tr>
              </thead>
              <tbody>
                {OPEN_SOURCE_CREDITS.map((c, i) => (
                  <tr key={c.name} style={{ borderBottom: i < OPEN_SOURCE_CREDITS.length - 1 ? '1px solid var(--fl-border)' : 'none' }}>
                    <td style={{ padding: '10px 10px', verticalAlign: 'top' }}>
                      <span style={{ fontWeight: 600, color: 'var(--fl-accent)', fontSize: 12 }}>{c.name}</span>
                    </td>
                    <td style={{ padding: '10px 10px', verticalAlign: 'top', color: 'var(--fl-text)', whiteSpace: 'nowrap' }}>{c.author}</td>
                    <td style={{ padding: '10px 10px', verticalAlign: 'top', whiteSpace: 'nowrap' }}>
                      <span style={{
                        fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '2px 6px', borderRadius: 4,
                        background: 'var(--fl-card)',
                        color: 'var(--fl-muted)', border: '1px solid var(--fl-border)',
                      }}>{c.license}</span>
                    </td>
                    <td style={{ padding: '10px 10px', verticalAlign: 'top', color: 'var(--fl-muted)', lineHeight: 1.5 }}>{t(`admin.about.credit_descriptions.${c.descriptionKey}`)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div style={{ background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 8, padding: '14px 18px' }}>
        <p style={{ fontSize: 11, color: 'var(--fl-muted)', lineHeight: 1.6, margin: 0 }}>
          {t('admin.about.footer')}{' '}
          <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-accent)' }}>github.com/Heimdall-DFIR</span>
        </p>
      </div>
    </div>
  );
}
