import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useTheme } from '../utils/theme';
import { Settings, Plus, Shield, UserCheck, UserX, ScrollText, Trash2, Search, CheckCircle2, XCircle, RefreshCw, ShieldAlert, Activity, Database, Download, Cpu, MessageSquare, Bot } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { usersAPI, authAPI, casesAPI, adminAPI, feedbackAPI } from '../utils/api';
import { Button, Modal, TabGroup, Spinner, EmptyState, Pagination } from '../components/ui';
import { fmtLocal } from '../utils/formatters';

const ACTION_COLORS = {
  login: '#22c55e', login_failed: 'var(--fl-danger)', login_blocked: 'var(--fl-gold)',
  logout: 'var(--fl-dim)', token_refresh: 'var(--fl-accent)',
  import_collection: 'var(--fl-accent)', parse_collection: 'var(--fl-purple)', delete_collection_data: 'var(--fl-danger)', pcap_parse: '#06b6d4',
  create_case: 'var(--fl-warn)', update_case: 'var(--fl-warn)', hard_delete_case: 'var(--fl-danger)',
  upload_evidence: 'var(--fl-ok)', delete_evidence: 'var(--fl-danger)',
  add_mitre_technique: '#06b6d4', update_mitre_technique: '#06b6d4', delete_mitre_technique: 'var(--fl-danger)',
  create_user: '#06b6d4', update_user: 'var(--fl-warn)', delete_user: 'var(--fl-danger)', change_password: 'var(--fl-gold)',
  generate_report: 'var(--fl-purple)', create_ioc: 'var(--fl-gold)', delete_ioc: 'var(--fl-danger)',
  run_yara_scan: '#f472b6', run_sigma_hunt: '#8b5cf6', fetch_taxii: '#14b8a6', correlate_case: '#fb923c',
  run_hayabusa: 'var(--fl-danger)', upload_evidence_chunked: 'var(--fl-ok)', download_report: 'var(--fl-purple)',
  backup_db: 'var(--fl-accent)', download_backup: 'var(--fl-accent)', run_soar: '#a855f7',
};

const ACTION_LABELS = {
  login: 'Connexion', login_failed: 'Échec connexion', login_blocked: 'Compte bloqué',
  logout: 'Déconnexion', token_refresh: 'Renouvellement token',
  import_collection: 'Import collecte', parse_collection: 'Parsing', delete_collection_data: 'Suppression collecte', pcap_parse: 'Parse PCAP',
  create_case: 'Création cas', update_case: 'Modification cas', hard_delete_case: 'Purge RGPD',
  upload_evidence: 'Ajout preuve', delete_evidence: 'Suppression preuve',
  add_mitre_technique: 'Ajout MITRE', update_mitre_technique: 'Modif. MITRE', delete_mitre_technique: 'Suppression MITRE',
  create_user: 'Création compte', update_user: 'Modification compte', delete_user: 'Suppression compte', change_password: 'Changement MDP',
  generate_report: 'Génération rapport', create_ioc: 'Ajout IOC', delete_ioc: 'Suppression IOC',
  run_yara_scan: 'Scan YARA', run_sigma_hunt: 'Chasse Sigma', fetch_taxii: 'Sync TAXII', correlate_case: 'Corrélation Intel',
  run_hayabusa: 'Analyse Hayabusa', upload_evidence_chunked: 'Upload (chunked)', download_report: 'Téléchargement PDF',
  backup_db: 'Sauvegarde DB', download_backup: 'Téléch. sauvegarde', run_soar: 'Exécution SOAR',
};
const PRIORITY_COLOR = { critical: 'var(--fl-danger)', high: 'var(--fl-warn)', medium: 'var(--fl-gold)', low: 'var(--fl-ok)' };
const STATUS_LABEL   = { active: 'En cours', pending: 'En attente', closed: 'Clôturé' };
const AUDIT_PAGE_SIZE = 50;

export default function AdminPage() {
  const T = useTheme();
  const { t } = useTranslation();
  const { tab = 'users' } = useParams();

  const ADMIN_TABS = useMemo(() => [
    { id: 'users',    label: t('admin.tabs_accounts'), icon: Shield,        to: '/admin/users' },
    { id: 'audit',    label: t('admin.tabs_audit'),    icon: ScrollText,    to: '/admin/audit' },
    { id: 'jobs',     label: t('admin.tabs_jobs'),     icon: Cpu,           to: '/admin/jobs' },
    { id: 'feedback', label: t('admin.tabs_feedback'), icon: MessageSquare, to: '/admin/feedback' },
    { id: 'rgpd',     label: t('admin.tabs_rgpd'),     icon: Trash2,        to: '/admin/rgpd' },
    { id: 'health',   label: t('admin.tabs_health'),   icon: Activity,      to: '/admin/health' },
    { id: 'backups',  label: t('admin.tabs_backups'),  icon: Database,      to: '/admin/backups' },
    { id: 'docker',   label: t('admin.tabs_infra'),    icon: Cpu,           to: '/admin/docker' },
    { id: 'ai',       label: 'IA locale',              icon: Bot,           to: '/admin/ai' },
    { id: 'about',    label: 'À propos',               icon: Shield,        to: '/admin/about' },
  ], [t]);

  const [users, setUsers]     = useState([]);
  const [showNew, setShowNew] = useState(false);
  const [newUser, setNewUser] = useState({ username: '', full_name: '', password: '', role: 'analyst' });

  const [auditRows,          setAuditRows]          = useState([]);
  const [auditTotal,         setAuditTotal]         = useState(0);
  const [auditLoading,       setAuditLoading]       = useState(false);
  const [auditPage,          setAuditPage]          = useState(0);
  const [auditFilterAction,  setAuditFilterAction]  = useState('');
  const [auditFilterUser,    setAuditFilterUser]    = useState('');
  const [auditFilterEntity,  setAuditFilterEntity]  = useState('');
  const [auditFilterFrom,    setAuditFilterFrom]    = useState('');
  const [auditFilterTo,      setAuditFilterTo]      = useState('');

  const [casesList,          setCasesList]          = useState([]);
  const [casesLoading,       setCasesLoading]       = useState(false);
  const [caseSearch,         setCaseSearch]         = useState('');
  const [showPurgeCase,      setShowPurgeCase]      = useState(false);
  const [purgeTarget,        setPurgeTarget]        = useState(null);
  const [purgeConfirm,       setPurgeConfirm]       = useState('');
  const [purgeDeleting,      setPurgeDeleting]      = useState(false);
  const [purgeResult,        setPurgeResult]        = useState(null);

  useEffect(() => {
    usersAPI.list().then(({ data }) => setUsers(data)).catch(e => console.warn('[AdminPage] users load:', e.message));
  }, []);

  const loadAudit = useCallback(async (page = 0) => {
    setAuditLoading(true);
    try {
      const params = { limit: AUDIT_PAGE_SIZE, offset: page * AUDIT_PAGE_SIZE };
      if (auditFilterAction)  params.action      = auditFilterAction;
      if (auditFilterUser)    params.user_id     = auditFilterUser;
      if (auditFilterEntity)  params.entity_type = auditFilterEntity;
      if (auditFilterFrom)    params.date_from   = auditFilterFrom;
      if (auditFilterTo)      params.date_to     = auditFilterTo + 'T23:59:59Z';
      const { data } = await usersAPI.audit(params);
      setAuditRows(data.rows || []);
      setAuditTotal(data.total || 0);
      setAuditPage(page);
    } catch {
      setAuditRows([]);
      setAuditTotal(0);
    }
    setAuditLoading(false);
  }, [auditFilterAction, auditFilterUser, auditFilterEntity, auditFilterFrom, auditFilterTo]);

  useEffect(() => {
    if (tab === 'audit') loadAudit(0);
  }, [tab, loadAudit]);

  const loadCases = async () => {
    setCasesLoading(true);
    try {
      const { data } = await casesAPI.list({ limit: 200 });
      setCasesList(data.cases || []);
    } catch {
      setCasesList([]);
    }
    setCasesLoading(false);
  };

  useEffect(() => {
    if (tab === 'rgpd') loadCases();
  }, [tab]);

  const filteredCases = useMemo(() => {
    const q = caseSearch.trim().toLowerCase();
    if (!q) return casesList;
    return casesList.filter(c =>
      c.case_number?.toLowerCase().includes(q) ||
      c.title?.toLowerCase().includes(q) ||
      c.investigator_name?.toLowerCase().includes(q)
    );
  }, [casesList, caseSearch]);

  const createUser = async () => {
    if (!newUser.username || !newUser.full_name || !newUser.password || newUser.password.length < 8) return;
    try {
      await authAPI.register(newUser);
      const { data } = await usersAPI.list();
      setUsers(data);
    } catch {
      setUsers(p => [...p, { id: String(Date.now()), ...newUser, is_active: true, last_login: null, created_at: new Date().toISOString() }]);
    }
    setNewUser({ username: '', full_name: '', password: '', role: 'analyst' });
    setShowNew(false);
  };

  const toggleActive = async (id) => {
    const u = users.find(x => x.id === id);
    if (!u) return;
    try {
      await usersAPI.update(id, { is_active: !u.is_active });
      const { data } = await usersAPI.list();
      setUsers(data);
    } catch {
      setUsers(p => p.map(x => x.id === id ? { ...x, is_active: !x.is_active } : x));
    }
  };

  const changeRole = async (id, role) => {
    try {
      await usersAPI.update(id, { role });
      const { data } = await usersAPI.list();
      setUsers(data);
    } catch {
      setUsers(p => p.map(x => x.id === id ? { ...x, role } : x));
    }
  };

  const deleteUser = async (id) => {
    try {
      await usersAPI.delete(id);
      const { data } = await usersAPI.list();
      setUsers(data);
    } catch {
      setUsers(p => p.filter(x => x.id !== id));
    }
  };

  const openPurge = (c) => {
    setPurgeTarget(c);
    setPurgeConfirm('');
    setPurgeResult(null);
    setShowPurgeCase(true);
  };

  const closePurge = () => {
    if (purgeDeleting) return;
    const purgedId = purgeResult?.ok ? purgeTarget?.id : null;
    setShowPurgeCase(false);
    setPurgeTarget(null);
    setPurgeConfirm('');
    setPurgeResult(null);
    if (purgedId) {
      setCasesList(prev => prev.filter(c => c.id !== purgedId));
    }
  };

  const executePurge = async () => {
    if (!purgeTarget || purgeConfirm !== purgeTarget.case_number) return;
    setPurgeDeleting(true);
    try {
      const { data } = await casesAPI.hardDelete(purgeTarget.id);
      let verified = false;
      try {
        await casesAPI.get(purgeTarget.id);
      } catch (e) {
        verified = e.response?.status === 404;
      }
      setPurgeResult({
        ok: true,
        files_destroyed: data.files_destroyed ?? 0,
        files_errors:    data.files_errors    ?? [],
        verified,
      });
      setCasesList(prev => prev.filter(c => c.id !== purgeTarget.id));
    } catch (e) {
      setPurgeResult({ ok: false, error: e.response?.data?.error || e.message });
    }
    setPurgeDeleting(false);
  };

  return (
    <div className="p-6">
      <div className="fl-header">
        <div>
          <h1 className="fl-header-title">{t('admin.admin_title')}</h1>
          <p className="fl-header-sub">{t('admin.admin_subtitle', { n: users.length, m: users.filter(u => u.is_active).length })}</p>
        </div>
      </div>

      <TabGroup tabs={ADMIN_TABS} className="mb-6" />

      {tab === 'users' && (
        <div>
          <div className="grid grid-cols-3 gap-4 mb-6">
            {[
              [t('admin.count_admins'),   users.filter(u => u.role === 'admin').length,   'var(--fl-warn)',          Shield],
              [t('admin.count_analysts'), users.filter(u => u.role === 'analyst').length, 'var(--fl-accent)', UserCheck],
              [t('admin.count_inactive'), users.filter(u => !u.is_active).length,         'var(--fl-danger)', UserX],
            ].map(([l, v, c, Icon]) => (
              <div key={l} className="fl-stat-card" style={{ borderLeft: `3px solid ${c}` }}>
                <div className="fl-stat-label"><Icon size={14} style={{ color: c }} /> {l}</div>
                <div className="fl-stat-value">{v}</div>
              </div>
            ))}
          </div>

          <div className="flex justify-end mb-3">
            <Button variant="primary" icon={Plus} onClick={() => setShowNew(true)}>
              {t('admin.create_account')}
            </Button>
          </div>

          <div className="rounded-xl border overflow-hidden" style={{ background: 'var(--fl-panel)', borderColor: 'var(--fl-border)' }}>
            <table className="fl-table">
              <thead>
                <tr>
                  {[t('admin.col_user'), t('admin.col_login'), t('admin.col_role'), t('admin.col_status'), t('admin.col_last_login'), t('admin.col_actions')].map(h => (
                    <th key={h}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id}>
                    <td className="font-semibold">{u.full_name}</td>
                    <td className="font-mono text-xs" style={{ color: 'var(--fl-dim)' }}>@{u.username}</td>
                    <td>
                      <select
                        value={u.role}
                        onChange={e => changeRole(u.id, e.target.value)}
                        className="fl-select"
                        style={{
                          padding: '2px 6px', fontSize: 11, fontFamily: 'monospace', fontWeight: 700,
                          color: u.role === 'admin' ? 'var(--fl-warn)' : 'var(--fl-accent)',
                        }}
                      >
                        <option value="admin">admin</option>
                        <option value="analyst">analyst</option>
                      </select>
                    </td>
                    <td>
                      <span onClick={() => toggleActive(u.id)} className="cursor-pointer">
                        <span
                          className="px-2 py-0.5 rounded text-xs font-mono font-bold"
                          style={{
                            background: u.is_active ? 'color-mix(in srgb, var(--fl-ok) 10%, transparent)' : 'color-mix(in srgb, var(--fl-danger) 10%, transparent)',
                            color: u.is_active ? 'var(--fl-ok)' : 'var(--fl-danger)',
                            border: `1px solid ${u.is_active ? 'color-mix(in srgb, var(--fl-ok) 25%, transparent)' : 'color-mix(in srgb, var(--fl-danger) 25%, transparent)'}`,
                          }}
                        >
                          {u.is_active ? t('admin.status_active') : t('admin.status_inactive')}
                        </span>
                      </span>
                    </td>
                    <td className="text-xs" style={{ color: 'var(--fl-dim)' }}>
                      {u.last_login ? fmtLocal(u.last_login) : t('admin.never')}
                    </td>
                    <td>
                      {u.username !== 'admin' && (
                        <Button variant="ghost" size="xs" icon={Trash2} onClick={() => deleteUser(u.id)} style={{ color: 'var(--fl-danger)' }} />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'audit' && (
        <div>
          
          <div className="rounded-xl p-4 mb-4 border" style={{ background: 'var(--fl-panel)', borderColor: 'var(--fl-border)' }}>
            <div className="grid gap-3 mb-3" style={{ gridTemplateColumns: '1fr 1fr 1fr 1fr 1fr' }}>
              <div>
                <label className="fl-label">{t('admin.filter_label_action')}</label>
                <select
                  value={auditFilterAction}
                  onChange={e => setAuditFilterAction(e.target.value)}
                  className="fl-select w-full"
                >
                  <option value="">{t('admin.filter_all_actions')}</option>
                  {Object.entries(ACTION_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                </select>
              </div>
              <div>
                <label className="fl-label">{t('admin.filter_label_user')}</label>
                <select
                  value={auditFilterUser}
                  onChange={e => setAuditFilterUser(e.target.value)}
                  className="fl-select w-full"
                >
                  <option value="">{t('common.all')}</option>
                  {users.map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
                </select>
              </div>
              <div>
                <label className="fl-label">{t('admin.filter_label_entity')}</label>
                <select
                  value={auditFilterEntity}
                  onChange={e => setAuditFilterEntity(e.target.value)}
                  className="fl-select w-full"
                >
                  <option value="">{t('common.all')}</option>
                  {['case', 'evidence', 'user', 'collection', 'report', 'ioc'].map(ent => (
                    <option key={ent} value={ent}>{ent}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="fl-label">{t('admin.filter_label_from')}</label>
                <input
                  type="date"
                  value={auditFilterFrom}
                  onChange={e => setAuditFilterFrom(e.target.value)}
                  className="fl-input w-full"
                />
              </div>
              <div>
                <label className="fl-label">{t('admin.filter_label_to')}</label>
                <input
                  type="date"
                  value={auditFilterTo}
                  onChange={e => setAuditFilterTo(e.target.value)}
                  className="fl-input w-full"
                />
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono" style={{ color: 'var(--fl-muted)' }}>
                {auditTotal} entrée{auditTotal !== 1 ? 's' : ''} · page {auditPage + 1}/{Math.max(1, Math.ceil(auditTotal / AUDIT_PAGE_SIZE))}
              </span>
              <Button
                variant="ghost"
                size="sm"
                icon={RefreshCw}
                loading={auditLoading}
                onClick={() => loadAudit(0)}
              >
                {t('admin.audit_filter_apply')}
              </Button>
            </div>
          </div>

          {auditLoading ? (
            <Spinner full text={t('admin.loading_audit')} />
          ) : auditRows.length === 0 ? (
            <EmptyState icon={ShieldAlert} title={t('admin.empty_audit')} subtitle={t('admin.empty_audit_sub')} />
          ) : (
            <>
              <div className="rounded-xl border overflow-hidden" style={{ background: 'var(--fl-panel)', borderColor: 'var(--fl-border)' }}>
                <table className="fl-table">
                  <thead>
                    <tr>
                      {[t('admin.col_timestamp'), t('admin.col_user'), t('admin.filter_label_action'), t('admin.col_object'), t('admin.col_details'), t('admin.col_ip'), t('admin.col_integrity')].map(h => (
                        <th key={h}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {auditRows.map(a => {
                      const color = ACTION_COLORS[a.action] || 'var(--fl-dim)';
                      const label = ACTION_LABELS[a.action] || a.action;
                      const details = a.details || {};
                      const detailStr = details.filename || details.title || details.username || details.case_number || details.reason || details.value || '';
                      return (
                        <tr key={a.id}>
                          <td className="font-mono text-xs whitespace-nowrap" style={{ color: 'var(--fl-dim)' }}>
                            {fmtLocal(a.created_at)}
                          </td>
                          <td>
                            <span
                              className="px-2 py-0.5 rounded text-xs font-mono font-bold"
                              style={{
                                background: 'color-mix(in srgb, var(--fl-accent) 8%, transparent)',
                                color: 'var(--fl-accent)',
                                border: '1px solid color-mix(in srgb, var(--fl-accent) 20%, transparent)',
                              }}
                            >
                              {a.username || '—'}
                            </span>
                          </td>
                          <td>
                            <span
                              className="px-2 py-0.5 rounded text-xs font-mono font-bold"
                              style={{ background: `${color}14`, color, border: `1px solid ${color}28` }}
                            >
                              {label}
                            </span>
                          </td>
                          <td className="text-xs font-mono" style={{ color: 'var(--fl-dim)' }}>
                            {(a.entity_type === 'case' || a.entity_type === 'collection') && a.entity_id ? (
                              <a
                                href={`/cases/${a.entity_id}`}
                                onClick={e => { e.preventDefault(); window.location.href = `/cases/${a.entity_id}`; }}
                                style={{ color: 'var(--fl-accent)', textDecoration: 'none' }}
                              >
                                {a.entity_type}
                              </a>
                            ) : (
                              a.entity_type || '—'
                            )}
                          </td>
                          <td
                            className="text-xs font-mono"
                            style={{ color: 'var(--fl-text)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                            title={detailStr}
                          >
                            {detailStr}
                          </td>
                          <td className="text-xs font-mono" style={{ color: 'var(--fl-muted)' }}>{a.ip_address || '—'}</td>
                          <td className="text-xs">
                            {a.hmac
                              ? <span title={`HMAC: ${a.hmac}`} style={{ color: 'var(--fl-ok)' }}>✓ HMAC</span>
                              : <span style={{ color: 'var(--fl-warn)' }}>héritage</span>}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {auditTotal > AUDIT_PAGE_SIZE && (
                <Pagination
                  page={auditPage + 1}
                  totalPages={Math.ceil(auditTotal / AUDIT_PAGE_SIZE)}
                  onChange={p => loadAudit(p - 1)}
                />
              )}
            </>
          )}
        </div>
      )}

      {tab === 'rgpd' && (
        <div>
          <div className="rounded-xl p-5 border mb-4" style={{ background: 'var(--fl-panel)', borderColor: 'var(--fl-border)' }}>
            <h2 className="text-base font-bold mb-3 flex items-center gap-2" style={{ color: 'var(--fl-text)' }}>
              🔒 Conformité RGPD — Droit à l'effacement (Art. 17)
            </h2>
            <p className="text-sm mb-5" style={{ color: 'var(--fl-dim)', lineHeight: 1.6 }}>
              Conformément au Règlement Général sur la Protection des Données, cette fonctionnalité permet
              l'effacement définitif et irréversible de toutes les données personnelles et traces forensiques.
            </p>

            <div className="rounded-lg p-4 border mb-4" style={{ background: 'var(--fl-bg)', borderColor: 'var(--fl-border)' }}>
              <h3 className="text-sm font-bold mb-1" style={{ color: 'var(--fl-danger)' }}>Purge complète d'un cas</h3>
              <p className="text-xs mb-4" style={{ color: 'var(--fl-dim)', lineHeight: 1.6 }}>
                Supprime le cas, toutes les preuves (fichiers écrasés via{' '}
                <code style={{ color: 'var(--fl-danger)' }}>DoD 5220.22-M</code>),
                la timeline, les IOCs, les rapports PDF, les collectes et métadonnées associées.
              </p>

              <div style={{ position: 'relative', marginBottom: 10 }}>
                <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--fl-muted)', pointerEvents: 'none' }} />
                <input
                  value={caseSearch}
                  onChange={e => setCaseSearch(e.target.value)}
                  placeholder={t('cases.search_ph')}
                  className="fl-input w-full"
                  style={{ paddingLeft: 30 }}
                />
              </div>

              <div style={{ maxHeight: 260, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 4 }}>
                {casesLoading && (
                  <div style={{ padding: '12px 0' }}>
                    <Spinner text="Chargement des cas…" />
                  </div>
                )}
                {!casesLoading && filteredCases.length === 0 && (
                  <p className="text-xs font-mono" style={{ padding: '12px 0', color: 'var(--fl-muted)' }}>
                    {casesList.length === 0 ? 'Aucun cas en base de données.' : 'Aucun résultat.'}
                  </p>
                )}
                {filteredCases.map(c => (
                  <div
                    key={c.id}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 10,
                      padding: '8px 12px', borderRadius: 6,
                      background: 'var(--fl-bg)', border: '1px solid var(--fl-border)',
                    }}
                  >
                    <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-danger)', flexShrink: 0, minWidth: 126 }}>{c.case_number}</span>
                    <span style={{ flex: 1, fontSize: 12, color: 'var(--fl-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.title}</span>
                    <span style={{ fontSize: 10, fontFamily: 'monospace', color: PRIORITY_COLOR[c.priority] || 'var(--fl-dim)', flexShrink: 0 }}>
                      {(c.priority || '').toUpperCase()}
                    </span>
                    <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-muted)', flexShrink: 0 }}>
                      {STATUS_LABEL[c.status] || c.status}
                    </span>
                    <Button variant="danger" size="xs" icon={Trash2} onClick={() => openPurge(c)}>
                      PURGER
                    </Button>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-lg p-4 border" style={{ background: 'var(--fl-bg)', borderColor: 'var(--fl-border)' }}>
              <h3 className="text-sm font-bold mb-1" style={{ color: 'var(--fl-warn)' }}>Supprimer un utilisateur</h3>
              <p className="text-xs mb-1" style={{ color: 'var(--fl-dim)' }}>
                Gérez les comptes depuis l'onglet <strong style={{ color: 'var(--fl-warn)' }}>Comptes</strong> — bouton <Trash2 size={11} style={{ display: 'inline', verticalAlign: 'middle' }} /> sur chaque ligne.
              </p>
            </div>
          </div>

          <div className="rounded-lg p-3 text-xs" style={{ background: 'color-mix(in srgb, var(--fl-danger) 6%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 15%, transparent)', color: 'var(--fl-danger)' }}>
            ⚠ Les suppressions sont irréversibles. Un log d'audit anonymisé sera conservé pour la traçabilité légale
            conformément à l'article 17(3) du RGPD (obligation légale de conservation).
          </div>
        </div>
      )}

      <Modal
        open={showPurgeCase && !!purgeTarget}
        title={purgeResult ? 'Rapport de vérification' : `Purge RGPD — ${purgeTarget?.case_number ?? ''}`}
        onClose={closePurge}
        size="sm"
        accentColor="var(--fl-danger)"
      >
        <Modal.Body>
          
          {!purgeDeleting && !purgeResult && purgeTarget && (
            <>
              <div style={{ marginBottom: 14, padding: '10px 14px', borderRadius: 8, background: 'color-mix(in srgb, var(--fl-danger) 6%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 18%, transparent)', fontSize: 12, color: 'var(--fl-dim)', lineHeight: 1.7 }}>
                <div style={{ fontWeight: 600, color: 'var(--fl-text)', marginBottom: 4 }}>{purgeTarget.title}</div>
                Détruira tous les fichiers de preuves (<code style={{ color: 'var(--fl-danger)', fontFamily: 'monospace' }}>DoD 5220.22-M</code>),
                IOCs, timeline, rapports et toutes les métadonnées associées.<br />
                <span style={{ color: 'var(--fl-warn)', fontSize: 11 }}>Un enregistrement d'audit immutable sera conservé (Art. 17(3) RGPD).</span>
              </div>

              <div style={{ marginBottom: 6, fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-dim)' }}>
                Tapez <code style={{ color: 'var(--fl-danger)', letterSpacing: '0.05em' }}>{purgeTarget.case_number}</code> pour confirmer :
              </div>
              <input
                value={purgeConfirm}
                onChange={e => setPurgeConfirm(e.target.value)}
                placeholder={purgeTarget.case_number}
                autoFocus
                className="fl-input w-full"
                style={{
                  fontFamily: 'monospace', fontSize: 13,
                  borderColor: purgeConfirm === purgeTarget.case_number ? 'var(--fl-danger)' : undefined,
                }}
                autoComplete="off"
              />
            </>
          )}

          {purgeDeleting && (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '32px 0', gap: 14 }}>
              <Spinner size={32} color="var(--fl-danger)" />
              <div style={{ fontFamily: 'monospace', fontSize: 13, color: 'var(--fl-dim)' }}>Destruction sécurisée en cours…</div>
              <div style={{ fontSize: 11, color: 'var(--fl-muted)', fontFamily: 'monospace' }}>DoD 5220.22-M · cascade delete · audit log</div>
            </div>
          )}

          {purgeResult && purgeTarget && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{
                padding: '12px 14px', borderRadius: 8,
                background: purgeResult.ok && purgeResult.verified
                  ? 'color-mix(in srgb, var(--fl-ok) 5%, transparent)'
                  : 'color-mix(in srgb, var(--fl-danger) 5%, transparent)',
                border: `1px solid ${purgeResult.ok && purgeResult.verified
                  ? 'color-mix(in srgb, var(--fl-ok) 25%, transparent)'
                  : 'color-mix(in srgb, var(--fl-danger) 25%, transparent)'}`,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                  {purgeResult.ok
                    ? <CheckCircle2 size={16} style={{ color: 'var(--fl-ok)' }} />
                    : <XCircle     size={16} style={{ color: 'var(--fl-danger)' }} />
                  }
                  <span style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 700, color: purgeResult.ok ? 'var(--fl-ok)' : 'var(--fl-danger)' }}>
                    {purgeResult.ok ? 'Purge réussie — ' + purgeTarget.case_number : 'Échec de la purge'}
                  </span>
                </div>

                {purgeResult.ok && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginLeft: 24 }}>
                    <div style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--fl-ok)' }}>
                      ✓ {purgeResult.files_destroyed} fichier{purgeResult.files_destroyed !== 1 ? 's' : ''} détruit{purgeResult.files_destroyed !== 1 ? 's' : ''} (DoD 5220.22-M)
                    </div>
                    <div style={{ fontSize: 12, fontFamily: 'monospace', color: purgeResult.verified ? 'var(--fl-ok)' : 'var(--fl-danger)' }}>
                      {purgeResult.verified
                        ? '✓ Absence confirmée en base de données (HTTP 404)'
                        : '⚠ Le cas semble toujours accessible en base de données'}
                    </div>
                    {purgeResult.files_errors?.length > 0 && (
                      <div style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-warn)' }}>
                        ⚠ {purgeResult.files_errors.length} fichier(s) non écrasé(s) : {purgeResult.files_errors.join(', ')}
                      </div>
                    )}
                  </div>
                )}

                {!purgeResult.ok && (
                  <div style={{ marginLeft: 24, fontSize: 12, fontFamily: 'monospace', color: 'var(--fl-danger)' }}>
                    {purgeResult.error}
                  </div>
                )}
              </div>

              <div style={{ padding: '8px 12px', borderRadius: 6, background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-muted)' }}>
                Enregistrement d'audit conservé — Art. 17(3) RGPD (obligation légale de conservation).
              </div>
            </div>
          )}
        </Modal.Body>
        <Modal.Footer>
          {purgeResult ? (
            <Button variant="secondary" onClick={closePurge}>Fermer</Button>
          ) : (
            <>
              <Button variant="secondary" disabled={purgeDeleting} onClick={closePurge}>Annuler</Button>
              <Button
                variant="danger"
                icon={Trash2}
                loading={purgeDeleting}
                disabled={!purgeTarget || purgeConfirm !== purgeTarget?.case_number}
                onClick={executePurge}
              >
                {t('admin.purge_confirm')}
              </Button>
            </>
          )}
        </Modal.Footer>
      </Modal>

      <Modal open={showNew} title={t('admin.form_new_account')} onClose={() => setShowNew(false)} size="sm">
        <Modal.Body>
          <div className="space-y-4">
            {[[t('admin.form_full_name'), 'full_name', 'Agent Durand', 'text'], [t('admin.form_username_lbl'), 'username', 'durand', 'text']].map(([l, k, ph, type]) => (
              <div key={k}>
                <label className="fl-label">{l}</label>
                <input
                  type={type}
                  value={newUser[k]}
                  onChange={e => setNewUser(p => ({ ...p, [k]: e.target.value }))}
                  placeholder={ph}
                  className="fl-input w-full"
                />
              </div>
            ))}
            <div>
              <label className="fl-label">{t('admin.form_password')}</label>
              <input
                type="password"
                value={newUser.password}
                onChange={e => setNewUser(p => ({ ...p, password: e.target.value }))}
                placeholder={t('admin.password_hint')}
                className="fl-input w-full"
              />
            </div>
            <div>
              <label className="fl-label">{t('admin.form_role')}</label>
              <div className="flex gap-3">
                {['analyst', 'admin'].map(r => (
                  <button
                    key={r}
                    onClick={() => setNewUser(p => ({ ...p, role: r }))}
                    className="px-5 py-2 rounded-lg text-xs font-mono font-bold uppercase"
                    style={{
                      background: newUser.role === r ? `${r === 'admin' ? 'var(--fl-warn)' : 'var(--fl-accent)'}15` : 'var(--fl-bg)',
                      color: r === 'admin' ? 'var(--fl-warn)' : 'var(--fl-accent)',
                      border: `1px solid ${newUser.role === r ? (r === 'admin' ? 'var(--fl-warn)' : 'var(--fl-accent)') + '40' : 'var(--fl-border)'}`,
                    }}
                  >
                    {r}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowNew(false)}>{t('common.cancel')}</Button>
          <Button variant="primary" onClick={createUser}>{t('admin.create_btn')}</Button>
        </Modal.Footer>
      </Modal>

      {tab === 'health' && <HealthTab />}

      {tab === 'backups' && <BackupsTab />}

      {tab === 'jobs' && <JobsTab />}

      {tab === 'feedback' && <FeedbackTab />}

      {tab === 'docker' && <DockerTab />}

      {tab === 'ai' && <AiSettingsTab />}

      {tab === 'about' && <AboutTab />}
    </div>
  );
}

function HealthTab() {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try { const r = await adminAPI.health(); setData(r.data); }
    catch { setData(null); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); const iv = setInterval(load, 30_000); return () => clearInterval(iv); }, [load]);

  const STATUS_COLOR = { ok: 'var(--fl-ok)', warn: 'var(--fl-warn)', error: 'var(--fl-danger)' };

  function svcStatus(svc) {
    if (!svc) return 'error';
    if (svc.ok) return 'ok';
    return 'error';
  }

  const services = data?.services ? Object.entries(data.services) : [];

  return (
    <div>
      <div className="flex items-center gap-3 mb-6">
        <h3 className="font-semibold" style={{ color: 'var(--fl-text)' }}>État des Services</h3>
        <Button variant="ghost" size="sm" icon={RefreshCw} loading={loading} onClick={load}>
          Actualiser
        </Button>
        {data && (
          <span style={{ fontSize: 11, color: 'var(--fl-muted)' }}>
            {new Date(data.timestamp).toLocaleTimeString('fr-FR')}
          </span>
        )}
      </div>

      {loading && !data && <Spinner full text="Chargement des services…" />}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 16 }}>
        {services.map(([key, svc]) => {
          const st = svcStatus(svc);
          const color = STATUS_COLOR[st];
          return (
            <div
              key={key}
              style={{
                background: 'var(--fl-card)',
                border: `1px solid ${st === 'ok' ? 'color-mix(in srgb, var(--fl-ok) 20%, transparent)' : 'color-mix(in srgb, var(--fl-danger) 20%, transparent)'}`,
                borderRadius: 10, padding: '16px 18px',
              }}
            >
              <div className="flex items-center gap-3 mb-2">
                <div style={{ width: 10, height: 10, borderRadius: '50%', background: color, flexShrink: 0, boxShadow: `0 0 6px ${color}` }} />
                <span style={{ fontWeight: 700, fontSize: 14, color: 'var(--fl-text)' }}>{svc.name || key}</span>
                <span style={{ marginLeft: 'auto', fontSize: 11, fontWeight: 700, color, background: `color-mix(in srgb, ${color} 15%, transparent)`, borderRadius: 4, padding: '1px 8px' }}>
                  {st === 'ok' ? 'OK' : 'ERREUR'}
                </span>
              </div>
              {svc.reason && <p style={{ fontSize: 11, color: 'var(--fl-danger)', margin: 0 }}>{svc.reason}</p>}
              {svc.status && <p style={{ fontSize: 11, color: 'var(--fl-dim)', margin: 0 }}>ES status: <strong>{svc.status}</strong> — shards actifs: {svc.shards}</p>}
              {svc.waiting !== undefined && (
                <div style={{ fontSize: 11, color: 'var(--fl-dim)', marginTop: 4, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
                  <span>En attente : {svc.waiting}</span>
                  <span>Actifs : {svc.active}</span>
                  <span>Terminés : {svc.completed}</span>
                  <span style={{ color: svc.failed > 0 ? 'var(--fl-danger)' : 'var(--fl-dim)' }}>Échecs : {svc.failed}</span>
                </div>
              )}
            </div>
          );
        })}
      </div>
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
    try {
      const r = await adminAPI.triggerBackup();
      setMsg(`✓ Sauvegarde créée : ${r.data.filename} (${(r.data.size / 1024 / 1024).toFixed(1)} Mo)`);
      await load();
    } catch (e) {
      setMsg(`✗ Erreur : ${e.response?.data?.error || 'inconnue'}`);
    } finally { setTrig(false); }
  }

  function fmtSize(b) {
    if (b > 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} Mo`;
    if (b > 1024) return `${(b / 1024).toFixed(0)} Ko`;
    return `${b} o`;
  }

  const msgOk = msg.startsWith('✓');

  return (
    <div>
      <div className="flex items-center gap-3 mb-4">
        <h3 className="font-semibold" style={{ color: 'var(--fl-text)' }}>Sauvegardes PostgreSQL</h3>
        <Button
          variant="primary"
          size="sm"
          icon={Database}
          loading={triggering}
          onClick={trigger}
          style={{ marginLeft: 'auto' }}
        >
          Déclencher une sauvegarde
        </Button>
        <Button variant="ghost" size="sm" icon={RefreshCw} loading={loading} onClick={load} />
      </div>

      {msg && (
        <div style={{
          padding: '8px 14px', borderRadius: 6, marginBottom: 12,
          background: msgOk ? 'color-mix(in srgb, var(--fl-ok) 8%, transparent)' : 'color-mix(in srgb, var(--fl-danger) 8%, transparent)',
          border: `1px solid ${msgOk ? 'color-mix(in srgb, var(--fl-ok) 30%, transparent)' : 'color-mix(in srgb, var(--fl-danger) 30%, transparent)'}`,
          fontSize: 13, color: msgOk ? 'var(--fl-ok)' : 'var(--fl-danger)',
        }}>
          {msg}
        </div>
      )}

      <p style={{ fontSize: 12, color: 'var(--fl-muted)', marginBottom: 12 }}>
        Les sauvegardes sont compressées (gzip) et stockées dans le volume <code>backups_data</code>. La rétention manuelle est recommandée.
      </p>

      {loading && <Spinner full text="Chargement des sauvegardes…" />}

      {!loading && backups.length === 0 && (
        <EmptyState
          icon={Database}
          title={t('admin.no_backups')}
          subtitle={t('admin.no_backups_sub')}
        />
      )}

      {backups.length > 0 && (
        <table className="fl-table">
          <thead>
            <tr>
              {['Fichier', 'Taille', 'Date', ''].map(h => <th key={h}>{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {backups.map(b => (
              <tr key={b.name}>
                <td className="font-mono text-xs" style={{ color: 'var(--fl-text)' }}>{b.name}</td>
                <td style={{ color: 'var(--fl-dim)' }}>{fmtSize(b.size)}</td>
                <td className="whitespace-nowrap" style={{ color: 'var(--fl-dim)' }}>{fmtLocal(b.created_at)}</td>
                <td>
                  <a
                    href={adminAPI.downloadBackup(b.name)}
                    download
                    style={{ display: 'flex', alignItems: 'center', gap: 4, color: 'var(--fl-accent)', fontSize: 12, textDecoration: 'none' }}
                  >
                    <Download size={12} /> Télécharger
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
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
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  const STATUS_COLOR = { ok: 'var(--fl-ok)', degraded: 'var(--fl-warn)', error: 'var(--fl-danger)' };
  const STATUS_LABEL = { ok: 'OK', degraded: 'Dégradé', error: 'Erreur' };

  return (
    <div>
      <div className="flex items-center gap-3 mb-4">
        <h3 className="font-semibold" style={{ color: 'var(--fl-text)' }}>Jobs de Parsing</h3>
        <div style={{ display: 'flex', gap: 4, marginLeft: 'auto' }}>
          {[['all', 'Tous'], ['error', 'Erreurs seulement'], ['24h', 'Dernières 24h']].map(([v, l]) => (
            <button
              key={v}
              onClick={() => setFilter(v)}
              style={{
                padding: '3px 10px', borderRadius: 4, fontSize: 11, fontFamily: 'monospace',
                cursor: 'pointer', border: '1px solid var(--fl-border)',
                background: filter === v ? 'color-mix(in srgb, var(--fl-accent) 12%, transparent)' : 'transparent',
                color: filter === v ? 'var(--fl-accent)' : 'var(--fl-dim)',
              }}
            >
              {l}
            </button>
          ))}
        </div>
        <Button variant="ghost" size="sm" icon={RefreshCw} loading={loading} onClick={load} />
      </div>

      {loading && <Spinner full text="Chargement des jobs…" />}

      {!loading && jobs.length === 0 && (
        <EmptyState icon={Cpu} title={t('admin.no_jobs')} subtitle={t('admin.no_jobs_sub')} />
      )}

      {!loading && jobs.length > 0 && (
        <div className="rounded-xl border overflow-hidden" style={{ background: 'var(--fl-panel)', borderColor: 'var(--fl-border)' }}>
          <table className="fl-table">
            <thead>
              <tr>
                {['Cas', 'Statut', 'Enreg.', 'Analyste', 'Date'].map(h => <th key={h}>{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {jobs.map(job => {
                const color = STATUS_COLOR[job.status] || 'var(--fl-dim)';
                const label = STATUS_LABEL[job.status] || job.status;
                const isExp = expanded.has(job.id);
                return (
                  <React.Fragment key={job.id}>
                    <tr
                      onClick={() => toggleExpand(job.id)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td>
                        <a
                          href={`/cases/${job.case_id}`}
                          onClick={e => { e.stopPropagation(); e.preventDefault(); window.location.href = `/cases/${job.case_id}`; }}
                          style={{ color: 'var(--fl-accent)', textDecoration: 'none', fontFamily: 'monospace', fontSize: 11 }}
                        >
                          {job.case_number}
                        </a>
                        {job.case_title && (
                          <span style={{ marginLeft: 8, fontSize: 11, color: 'var(--fl-dim)' }}>{job.case_title}</span>
                        )}
                      </td>
                      <td>
                        <span style={{ padding: '1px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700, fontFamily: 'monospace', background: `${color}14`, color, border: `1px solid ${color}28` }}>
                          {label}
                        </span>
                      </td>
                      <td className="font-mono text-xs" style={{ color: 'var(--fl-dim)' }}>
                        {(job.record_count || 0).toLocaleString()}
                      </td>
                      <td className="text-xs" style={{ color: 'var(--fl-dim)' }}>{job.analyst || '—'}</td>
                      <td className="text-xs font-mono" style={{ color: 'var(--fl-dim)' }}>
                        {job.updated_at ? fmtLocal(job.updated_at) : '—'}
                      </td>
                    </tr>
                    {isExp && (
                      <tr>
                        <td colSpan={5} style={{ padding: '8px 14px', background: 'var(--fl-bg)', fontSize: 11, fontFamily: 'monospace' }}>
                          <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: 'var(--fl-dim)', fontSize: 10, maxHeight: 200, overflow: 'auto' }}>
                            {JSON.stringify(job.output_data, null, 2)}
                          </pre>
                        </td>
                      </tr>
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

  const STATUS_CONFIG = {
    open:        { label: 'Ouvert',   color: 'var(--fl-accent)' },
    in_progress: { label: 'En cours', color: 'var(--fl-warn)' },
    resolved:    { label: 'Résolu',   color: 'var(--fl-ok)' },
    closed:      { label: 'Fermé',    color: 'var(--fl-dim)' },
  };
  const TYPE_LABELS = { bug: '🐛 Bug', suggestion: '💡 Suggestion', autre: '📝 Autre' };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = statusFilter ? { status: statusFilter } : {};
      const { data } = await feedbackAPI.list(params);
      setRows(data || []);
    } catch { setRows([]); }
    setLoading(false);
  }, [statusFilter]);

  useEffect(() => { load(); }, [load]);

  async function saveReply(id) {
    setSaving(p => ({ ...p, [id]: true }));
    try {
      const row = rows.find(r => r.id === id);
      await feedbackAPI.update(id, {
        status: row?.status,
        admin_reply: replies[id] ?? row?.admin_reply ?? '',
      });
      await load();
    } catch {}
    setSaving(p => ({ ...p, [id]: false }));
  }

  async function updateStatus(id, status) {
    const row = rows.find(r => r.id === id);
    try {
      await feedbackAPI.update(id, { status, admin_reply: row?.admin_reply || null });
      setRows(prev => prev.map(r => r.id === id ? { ...r, status } : r));
    } catch {}
  }

  const openCount = rows.filter(r => r.status === 'open').length;

  return (
    <div>
      <div className="flex items-center gap-3 mb-4">
        <h3 className="font-semibold" style={{ color: 'var(--fl-text)' }}>
          Tickets Feedback
          {openCount > 0 && (
            <span style={{ marginLeft: 8, padding: '1px 7px', borderRadius: 10, fontSize: 10, fontWeight: 700, background: '#4d82c018', color: 'var(--fl-accent)', border: '1px solid #4d82c030' }}>
              {openCount} ouvert{openCount > 1 ? 's' : ''}
            </span>
          )}
        </h3>
        <div style={{ display: 'flex', gap: 4, marginLeft: 'auto' }}>
          {[['', 'Tous'], ['open', 'Ouverts'], ['in_progress', 'En cours'], ['resolved', 'Résolus']].map(([v, l]) => (
            <button
              key={v}
              onClick={() => setStatusFilter(v)}
              style={{
                padding: '3px 10px', borderRadius: 4, fontSize: 11, fontFamily: 'monospace',
                cursor: 'pointer', border: '1px solid var(--fl-border)',
                background: statusFilter === v ? 'color-mix(in srgb, var(--fl-accent) 12%, transparent)' : 'transparent',
                color: statusFilter === v ? 'var(--fl-accent)' : 'var(--fl-dim)',
              }}
            >
              {l}
            </button>
          ))}
        </div>
        <Button variant="ghost" size="sm" icon={RefreshCw} loading={loading} onClick={load} />
      </div>

      {loading && <Spinner full text="Chargement des tickets…" />}

      {!loading && rows.length === 0 && (
        <EmptyState icon={MessageSquare} title={t('admin.no_tickets')} subtitle={t('admin.no_tickets_sub')} />
      )}

      {!loading && rows.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {rows.map(row => {
            const sc = STATUS_CONFIG[row.status] || STATUS_CONFIG.open;
            return (
              <div key={row.id} style={{ borderRadius: 8, border: `1px solid var(--fl-border)`, background: 'var(--fl-panel)', overflow: 'hidden' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 14px', borderLeft: `3px solid ${sc.color}` }}>
                  <span style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-muted)' }}>
                    {TYPE_LABELS[row.type] || row.type}
                  </span>
                  <span style={{ flex: 1, fontSize: 12, color: 'var(--fl-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {row.title || row.description?.slice(0, 80)}
                  </span>
                  <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-muted)', flexShrink: 0 }}>
                    {row.username || '?'}
                  </span>
                  <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-muted)', flexShrink: 0 }}>
                    {new Date(row.created_at).toLocaleDateString('fr-FR')}
                  </span>
                  <select
                    value={row.status}
                    onChange={e => updateStatus(row.id, e.target.value)}
                    style={{
                      padding: '2px 6px', borderRadius: 4, fontSize: 10, fontFamily: 'monospace',
                      background: `${sc.color}18`, color: sc.color, border: `1px solid ${sc.color}30`,
                      cursor: 'pointer', flexShrink: 0,
                    }}
                  >
                    {Object.entries(STATUS_CONFIG).map(([k, v]) => (
                      <option key={k} value={k}>{v.label}</option>
                    ))}
                  </select>
                </div>
                <div style={{ padding: '8px 14px', background: 'var(--fl-bg)', borderTop: '1px solid var(--fl-border)' }}>
                  <p style={{ margin: '0 0 8px', fontSize: 11, color: 'var(--fl-dim)', lineHeight: 1.5 }}>{row.description}</p>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <textarea
                      placeholder="Réponse admin…"
                      value={replies[row.id] ?? (row.admin_reply || '')}
                      onChange={e => setReplies(p => ({ ...p, [row.id]: e.target.value }))}
                      rows={2}
                      style={{
                        flex: 1, padding: '5px 8px', borderRadius: 4, fontSize: 11, fontFamily: 'monospace',
                        background: 'var(--fl-card)', color: 'var(--fl-text)', border: '1px solid var(--fl-border)',
                        resize: 'vertical', outline: 'none',
                      }}
                    />
                    <Button
                      variant="primary"
                      size="xs"
                      loading={saving[row.id]}
                      onClick={() => saveReply(row.id)}
                    >
                      Enregistrer
                    </Button>
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
  const [data,    setData]    = useState(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState('');

  const load = useCallback(async () => {
    setLoading(true); setError('');
    try {
      const r = await adminAPI.dockerContainers();
      setData(r.data);
    } catch (e) {
      setError(e.response?.data?.error || e.message || 'Erreur inconnue');
      setData(null);
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); const iv = setInterval(load, 5000); return () => clearInterval(iv); }, [load]);

  function fmtMem(bytes) {
    if (!bytes) return '0 Mo';
    if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(1)} Go`;
    return `${(bytes / 1048576).toFixed(0)} Mo`;
  }

  const STATE_COLOR = {
    running:    'var(--fl-ok)',
    exited:     'var(--fl-danger)',
    paused:     'var(--fl-warn)',
    restarting: '#fb923c',
  };

  const TOOLTIP_STYLE = {
    background: 'var(--fl-card)',
    border: '1px solid var(--fl-border)',
    borderRadius: 6,
    fontSize: 12,
    color: 'var(--fl-text)',
  };

  const containers = data?.containers || [];
  const running    = containers.filter(c => c.state === 'running');

  const cpuChartData = [...running].sort((a, b) => b.cpu_percent - a.cpu_percent).slice(0, 10).map(c => ({
    name: c.name.length > 18 ? c.name.slice(0, 17) + '…' : c.name,
    cpu: c.cpu_percent,
  }));
  const ramChartData = [...running].sort((a, b) => b.mem_percent - a.mem_percent).slice(0, 10).map(c => ({
    name: c.name.length > 18 ? c.name.slice(0, 17) + '…' : c.name,
    ram: c.mem_percent,
  }));

  return (
    <div>
      
      <div className="flex items-center gap-3 mb-5">
        <h3 className="font-semibold" style={{ color: 'var(--fl-text)' }}>Infrastructure Docker</h3>
        <Button variant="ghost" size="sm" icon={RefreshCw} loading={loading} onClick={load}>
          Actualiser
        </Button>
        {data && (
          <span style={{ fontSize: 11, color: 'var(--fl-dim)', marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ color: 'var(--fl-ok)', fontWeight: 700 }}>{running.length}</span>
            <span style={{ color: 'var(--fl-muted)' }}>/</span>
            <span style={{ color: 'var(--fl-text)' }}>{containers.length}</span>
            <span style={{ color: 'var(--fl-muted)' }}>conteneurs actifs</span>
            <span style={{ color: 'var(--fl-border)', margin: '0 2px' }}>·</span>
            <span style={{ color: 'var(--fl-dim)' }}>{new Date(data.timestamp).toLocaleTimeString('fr-FR')}</span>
          </span>
        )}
      </div>

      {error && (
        <div style={{ padding: '10px 14px', borderRadius: 6, marginBottom: 14, background: 'color-mix(in srgb, var(--fl-danger) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 30%, transparent)', fontSize: 13, color: 'var(--fl-danger)' }}>
          ✗ {error}
        </div>
      )}

      {loading && !data && <Spinner full text="Chargement des conteneurs…" />}

      {running.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
          
          <div style={{ background: 'var(--fl-card)', border: '1px solid var(--fl-border)', borderRadius: 10, padding: '14px 16px' }}>
            <p style={{ fontSize: 12, fontWeight: 700, color: 'var(--fl-text)', marginBottom: 12, letterSpacing: '0.03em' }}>
              CPU % <span style={{ fontWeight: 400, color: 'var(--fl-dim)' }}>(conteneurs actifs)</span>
            </p>
            <ResponsiveContainer width="100%" height={running.length > 6 ? 200 : 160}>
              <BarChart data={cpuChartData} layout="vertical" margin={{ left: 0, right: 20, top: 0, bottom: 0 }}>
                <XAxis type="number" domain={[0, 100]} tick={{ fontSize: 11, fill: 'var(--fl-dim)' }} tickFormatter={v => v + '%'} axisLine={{ stroke: 'var(--fl-border)' }} tickLine={false} />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: 'var(--fl-text)' }} width={130} axisLine={false} tickLine={false} />
                <Tooltip
                  formatter={(v) => [`${v.toFixed(2)} %`, 'CPU']}
                  contentStyle={TOOLTIP_STYLE}
                  labelStyle={{ color: 'var(--fl-dim)', marginBottom: 2 }}
                  cursor={{ fill: '#ffffff08' }}
                />
                <Bar dataKey="cpu" radius={[0, 4, 4, 0]} barSize={12}>
                  {cpuChartData.map((entry, i) => (
                    <Cell key={i} fill={entry.cpu > 80 ? '#ff7b72' : entry.cpu > 50 ? '#e3b341' : '#58a6ff'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div style={{ background: 'var(--fl-card)', border: '1px solid var(--fl-border)', borderRadius: 10, padding: '14px 16px' }}>
            <p style={{ fontSize: 12, fontWeight: 700, color: 'var(--fl-text)', marginBottom: 12, letterSpacing: '0.03em' }}>
              RAM % <span style={{ fontWeight: 400, color: 'var(--fl-dim)' }}>(conteneurs actifs)</span>
            </p>
            <ResponsiveContainer width="100%" height={running.length > 6 ? 200 : 160}>
              <BarChart data={ramChartData} layout="vertical" margin={{ left: 0, right: 20, top: 0, bottom: 0 }}>
                <XAxis type="number" domain={[0, 100]} tick={{ fontSize: 11, fill: 'var(--fl-dim)' }} tickFormatter={v => v + '%'} axisLine={{ stroke: 'var(--fl-border)' }} tickLine={false} />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: 'var(--fl-text)' }} width={130} axisLine={false} tickLine={false} />
                <Tooltip
                  formatter={(v) => [`${v.toFixed(2)} %`, 'RAM']}
                  contentStyle={TOOLTIP_STYLE}
                  labelStyle={{ color: 'var(--fl-dim)', marginBottom: 2 }}
                  cursor={{ fill: '#ffffff08' }}
                />
                <Bar dataKey="ram" radius={[0, 4, 4, 0]} barSize={12}>
                  {ramChartData.map((entry, i) => (
                    <Cell key={i} fill={entry.ram > 80 ? '#ff7b72' : entry.ram > 60 ? '#e3b341' : 'var(--fl-ok)'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {containers.length > 0 && (
        <div style={{ border: '1px solid var(--fl-border)', borderRadius: 8, overflow: 'hidden' }}>
          <table className="fl-table">
            <thead>
              <tr>
                {['Conteneur', 'Image', 'État', 'CPU', 'RAM', 'RAM utilisée'].map(h => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {containers.map((c, idx) => {
                const stColor = STATE_COLOR[c.state] || 'var(--fl-dim)';
                return (
                  <tr key={c.id}>
                    <td className="font-mono text-xs font-bold" style={{ color: 'var(--fl-text)' }}>{c.name}</td>
                    <td className="font-mono text-xs" style={{ color: 'var(--fl-dim)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.image}</td>
                    <td>
                      <span style={{
                        fontSize: 11, fontWeight: 700, color: stColor,
                        background: `color-mix(in srgb, ${stColor} 13%, transparent)`,
                        border: `1px solid color-mix(in srgb, ${stColor} 33%, transparent)`,
                        borderRadius: 4, padding: '2px 8px',
                      }}>
                        {c.state.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      {c.state === 'running' ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <div style={{ width: 64, height: 7, background: 'var(--fl-border)', borderRadius: 4, overflow: 'hidden' }}>
                            <div style={{ height: '100%', width: `${Math.min(c.cpu_percent, 100)}%`, background: c.cpu_percent > 80 ? '#ff7b72' : c.cpu_percent > 50 ? '#e3b341' : '#58a6ff', borderRadius: 4, transition: 'width 0.3s' }} />
                          </div>
                          <span style={{ fontSize: 12, color: 'var(--fl-text)', minWidth: 42, fontVariantNumeric: 'tabular-nums' }}>{c.cpu_percent.toFixed(1)}%</span>
                        </div>
                      ) : <span style={{ color: 'var(--fl-muted)', fontSize: 12 }}>—</span>}
                    </td>
                    <td>
                      {c.state === 'running' ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <div style={{ width: 64, height: 7, background: 'var(--fl-border)', borderRadius: 4, overflow: 'hidden' }}>
                            <div style={{ height: '100%', width: `${Math.min(c.mem_percent, 100)}%`, background: c.mem_percent > 80 ? '#ff7b72' : c.mem_percent > 60 ? '#e3b341' : 'var(--fl-ok)', borderRadius: 4, transition: 'width 0.3s' }} />
                          </div>
                          <span style={{ fontSize: 12, color: 'var(--fl-text)', minWidth: 42, fontVariantNumeric: 'tabular-nums' }}>{c.mem_percent.toFixed(1)}%</span>
                        </div>
                      ) : <span style={{ color: 'var(--fl-muted)', fontSize: 12 }}>—</span>}
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--fl-dim)', fontVariantNumeric: 'tabular-nums' }}>
                      {c.state === 'running' ? `${fmtMem(c.mem_used)} / ${fmtMem(c.mem_limit)}` : <span style={{ color: 'var(--fl-muted)' }}>—</span>}
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
  { id: 'qwen2.5:7b',      label: 'Qwen 2.5 7B',       size: '4.7 Go',  desc: 'Recommandé — bon équilibre vitesse/qualité',  tag: 'recommandé' },
  { id: 'qwen2.5:14b',     label: 'Qwen 2.5 14B',      size: '9 Go',    desc: 'Meilleure qualité, nécessite 16 Go RAM',       tag: 'qualité' },
  { id: 'deepseek-r1:8b',  label: 'DeepSeek R1 8B',    size: '4.9 Go',  desc: 'Raisonnement avancé, idéal pour l\'analyse',   tag: 'raisonnement' },
  { id: 'llama3.2:3b',     label: 'Llama 3.2 3B',      size: '2 Go',    desc: 'Très léger, réponses rapides',                 tag: 'léger' },
  { id: 'mistral:7b',      label: 'Mistral 7B',         size: '4.1 Go',  desc: 'Polyvalent, bonnes performances générales',    tag: '' },
  { id: 'phi3:mini',       label: 'Phi-3 Mini',         size: '2.3 Go',  desc: 'Ultra léger (3.8B), idéal machine limitée',   tag: 'léger' },
  { id: 'gemma2:9b',       label: 'Gemma 2 9B',         size: '5.4 Go',  desc: 'Modèle Google, excellente compréhension',      tag: '' },
  { id: 'llama3.1:8b',     label: 'Llama 3.1 8B',      size: '4.7 Go',  desc: 'Meta, performant pour l\'analyse de texte',    tag: '' },
];

const TAG_COLOR = {
  'recommandé':   '#22c55e',
  'qualité':      '#a855f7',
  'raisonnement': 'var(--fl-accent)',
  'léger':        '#f97316',
};

function AiSettingsTab() {
  const [status, setStatus]           = useState(null);
  const [loading, setLoading]         = useState(false);
  const [testModel, setTestModel]     = useState('');
  const [testResult, setTestResult]   = useState('');
  const [testing, setTesting]         = useState(false);
  const [pullState, setPullState]     = useState({});
  const [deleting, setDeleting]       = useState({});
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

  useEffect(() => { load(); loadOllamaStatus(); }, [load, loadOllamaStatus]);

  async function installOllama() {
    if (ollamaInstall?.phase === 'pull' || ollamaInstall?.phase === 'create' || ollamaInstall?.phase === 'starting') return;
    setOllamaInstall({ phase: 'connecting', message: 'Connexion à Docker…', pct: 0, error: null });
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
        body: JSON.stringify({ model: testModel, prompt: 'Réponds en une phrase : qu\'est-ce que le MFT en forensique Windows ?', stream: true }),
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
    } catch (e) { setTestResult(`Erreur : ${e.message}`); }
    finally { setTesting(false); }
  }

  async function pullModel(modelId) {
    if (pullState[modelId]?.pulling) return;
    const ctrl = new AbortController();
    abortRefs.current[modelId] = ctrl;
    setPullState(p => ({ ...p, [modelId]: { pulling: true, phase: 'Connexion…', pct: 0, done: false, error: null } }));
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
            setPullState(p => ({ ...p, [modelId]: { pulling: true, phase: j.status || 'Téléchargement…', pct: pct || p[modelId]?.pct || 0, done: false, error: null } }));
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
        borderRadius: 10, padding: '16px 20px',
      }}>
        <div className="flex items-center gap-3 mb-3">
          <div style={{ width: 10, height: 10, borderRadius: '50%', background: ollamaRunning ? 'var(--fl-ok)' : ollamaExists ? '#f97316' : 'var(--fl-danger)', boxShadow: ollamaRunning ? '0 0 6px var(--fl-ok)' : 'none', flexShrink: 0 }} />
          <h4 style={{ fontWeight: 700, fontSize: 14, color: 'var(--fl-text)', margin: 0 }}>Service Ollama</h4>
          <span style={{ fontSize: 11, fontFamily: 'monospace', color: ollamaRunning ? 'var(--fl-ok)' : ollamaExists ? '#f97316' : 'var(--fl-muted)' }}>
            {ollamaStatus === null ? '…' : ollamaRunning ? 'En cours d\'exécution' : ollamaExists ? `Arrêté (${ollamaStatus.state})` : 'Non installé'}
          </span>
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
            <Button variant="ghost" size="sm" icon={RefreshCw} onClick={loadOllamaStatus} />
            {ollamaRunning ? (
              <Button variant="danger" size="sm" loading={ollamaStopping} onClick={stopOllama}>Arrêter Ollama</Button>
            ) : (
              <Button variant="primary" size="sm" icon={Bot} loading={installBusy} onClick={installOllama}>
                {ollamaExists ? 'Démarrer Ollama' : 'Installer Ollama'}
              </Button>
            )}
          </div>
        </div>

        {ollamaInstall && (
          <div style={{ marginTop: 8 }}>
            {ollamaInstall.phase !== 'error' && ollamaInstall.phase !== 'done' && (
              <div style={{ marginBottom: 6 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                  <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#f97316' }}>{ollamaInstall.message}</span>
                  {ollamaInstall.pct > 0 && <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#f97316' }}>{ollamaInstall.pct}%</span>}
                </div>
                <div style={{ height: 5, background: 'var(--fl-border)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: ollamaInstall.pct > 0 ? `${ollamaInstall.pct}%` : '100%', background: 'linear-gradient(90deg, #f97316, #fb923c)', borderRadius: 3, transition: 'width 0.3s', animation: ollamaInstall.pct === 0 ? 'indeterminate 1.5s ease-in-out infinite' : 'none' }} />
                </div>
              </div>
            )}
            {ollamaInstall.phase === 'done' && <div style={{ fontSize: 11, color: 'var(--fl-ok)' }}>✓ {ollamaInstall.message}</div>}
            {ollamaInstall.phase === 'error' && <div style={{ fontSize: 11, color: 'var(--fl-danger)' }}>⚠ {ollamaInstall.error}</div>}
          </div>
        )}

        {!ollamaRunning && ollamaInstall?.phase !== 'done' && (
          <p style={{ fontSize: 11, color: 'var(--fl-muted)', margin: '8px 0 0' }}>
            Ollama sera démarré via l'API Docker. L'image <code style={{ color: 'var(--fl-accent)' }}>ollama/ollama:latest</code> sera téléchargée (~1.5 Go) puis un container sera créé sur le réseau interne <code style={{ color: 'var(--fl-accent)' }}>aesir-net</code>. Ajoutez ensuite <code style={{ color: 'var(--fl-accent)' }}>OLLAMA_URL=http://ollama:11434</code> dans votre configuration.
          </p>
        )}
      </div>

      <div className="flex items-center gap-3 mb-5">
        <h3 className="font-semibold" style={{ color: 'var(--fl-text)' }}>Modèles installés</h3>
        <Button variant="ghost" size="sm" icon={RefreshCw} loading={loading} onClick={load}>Actualiser</Button>
        <span style={{
          marginLeft: 'auto', fontSize: 11, fontWeight: 700, fontFamily: 'monospace',
          padding: '2px 10px', borderRadius: 10,
          background: ok ? 'color-mix(in srgb, var(--fl-ok) 12%, transparent)' : 'color-mix(in srgb, var(--fl-danger) 12%, transparent)',
          color: ok ? 'var(--fl-ok)' : 'var(--fl-danger)',
          border: `1px solid ${ok ? 'color-mix(in srgb, var(--fl-ok) 30%, transparent)' : 'color-mix(in srgb, var(--fl-danger) 30%, transparent)'}`,
        }}>
          {loading ? '…' : ok ? '● CONNECTÉ' : '● NON DISPONIBLE'}
        </span>
      </div>

      {!ok && !loading && (
        <div style={{ background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 10, padding: '18px 22px', marginBottom: 24 }}>
          <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--fl-text)', marginBottom: 10 }}>Comment activer Ollama ?</h4>
          <p style={{ fontSize: 12, color: 'var(--fl-muted)', marginBottom: 8 }}>1. Démarrer le service Ollama :</p>
          <pre style={{ background: 'var(--fl-bg)', borderRadius: 6, padding: '7px 12px', fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-accent)', border: '1px solid var(--fl-border)', margin: '0 0 12px' }}>docker compose --profile ai up -d ollama</pre>
          <p style={{ fontSize: 12, color: 'var(--fl-muted)', marginBottom: 8 }}>2. Ajouter dans le <code style={{ color: 'var(--fl-accent)' }}>.env</code> du backend :</p>
          <pre style={{ background: 'var(--fl-bg)', borderRadius: 6, padding: '7px 12px', fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-accent)', border: '1px solid var(--fl-border)', margin: 0 }}>OLLAMA_URL=http://ollama:11434</pre>
          <p style={{ fontSize: 11, color: 'var(--fl-muted)', marginTop: 10 }}>Une fois Ollama connecté, installez un modèle depuis le catalogue ci-dessous en un seul clic.</p>
        </div>
      )}

      {ok && installed.size > 0 && (
        <div style={{ background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 10, padding: '14px 18px', marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 12, color: 'var(--fl-text)', fontWeight: 600 }}>Tester</span>
            <select value={testModel} onChange={e => setTestModel(e.target.value)} className="fl-select" style={{ flex: 1, maxWidth: 260 }}>
              {[...installed].map(m => <option key={m} value={m}>{m}</option>)}
            </select>
            <Button variant="primary" size="sm" loading={testing} onClick={runTest} icon={Bot}>Lancer le test</Button>
          </div>
          {(testing || testResult) && (
            <div style={{ marginTop: 10, background: 'var(--fl-bg)', borderRadius: 6, padding: '10px 14px', fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-text)', minHeight: 36, whiteSpace: 'pre-wrap', border: '1px solid var(--fl-border)' }}>
              {testing && !testResult ? <span style={{ color: 'var(--fl-muted)' }}>Génération…</span> : testResult}
            </div>
          )}
        </div>
      )}

      <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--fl-text)', marginBottom: 12 }}>
        Catalogue de modèles
        <span style={{ fontSize: 11, fontWeight: 400, color: 'var(--fl-muted)', marginLeft: 8 }}>— clic sur « Installer » pour télécharger</span>
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
              
              <div style={{ width: 9, height: 9, borderRadius: '50%', flexShrink: 0, background: isInstalled ? 'var(--fl-ok)' : ps?.pulling ? '#f97316' : ps?.done ? 'var(--fl-ok)' : 'var(--fl-border)', boxShadow: isInstalled ? '0 0 5px var(--fl-ok)' : 'none' }} />

              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
                  <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--fl-text)' }}>{m.label}</span>
                  <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-muted)' }}>{m.id}</span>
                  {m.tag && <span style={{ fontSize: 9, fontFamily: 'monospace', padding: '1px 6px', borderRadius: 3, background: `${TAG_COLOR[m.tag]}18`, color: TAG_COLOR[m.tag], border: `1px solid ${TAG_COLOR[m.tag]}30` }}>{m.tag}</span>}
                  <span style={{ fontSize: 10, color: 'var(--fl-muted)', marginLeft: 'auto' }}>{m.size}</span>
                </div>
                <div style={{ fontSize: 11, color: 'var(--fl-muted)' }}>{m.desc}</div>

                {ps?.pulling && (
                  <div style={{ marginTop: 6 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                      <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#f97316' }}>{ps.phase}</span>
                      <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#f97316' }}>{ps.pct}%</span>
                    </div>
                    <div style={{ height: 4, background: 'var(--fl-border)', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${ps.pct}%`, background: 'linear-gradient(90deg, #f97316, #fb923c)', borderRadius: 2, transition: 'width 0.3s' }} />
                    </div>
                  </div>
                )}
                {ps?.error && <div style={{ fontSize: 10, color: 'var(--fl-danger)', marginTop: 4 }}>⚠ {ps.error}</div>}
                {ps?.done && !isInstalled && <div style={{ fontSize: 10, color: 'var(--fl-ok)', marginTop: 4 }}>✓ Installation terminée — actualisez</div>}
              </div>

              <div style={{ flexShrink: 0, display: 'flex', gap: 6 }}>
                {isInstalled ? (
                  <>
                    <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-ok)', padding: '3px 8px', border: '1px solid color-mix(in srgb, var(--fl-ok) 30%, transparent)', borderRadius: 4 }}>✓ Installé</span>
                    <Button variant="danger" size="sm" loading={isDel} onClick={() => removeModel(m.id)}>Supprimer</Button>
                  </>
                ) : ps?.pulling ? (
                  <Button variant="secondary" size="sm" onClick={() => { abortRefs.current[m.id]?.abort(); }}>Annuler</Button>
                ) : (
                  <Button variant="primary" size="sm" icon={Bot} disabled={!ok} onClick={() => pullModel(m.id)}>
                    {ok ? 'Installer' : 'Ollama requis'}
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
    description: "Outils d'analyse forensique Windows (MFT, Prefetch, LNK, Registre, EVTX)",
  },
  {
    name: 'Hayabusa',
    author: 'Yamato Security',
    license: 'GNU GPL 3.0',
    description: 'Outil de chasse aux menaces et de réponse aux incidents basé sur les règles Sigma',
  },
  {
    name: 'VolWeb',
    author: 'k1nd0ne',
    license: 'MIT',
    description: "Plateforme centralisée d'analyse de mémoire vive (forensics RAM)",
  },
  {
    name: 'Volatility 3',
    author: 'Volatility Foundation',
    license: 'Volatility Software License',
    description: "Framework d'analyse forensique de la mémoire vive",
  },
];

function AboutTab() {
  const [open, setOpen] = React.useState(true);
  return (
    <div style={{ maxWidth: 760 }}>
      <div style={{ marginBottom: 24 }}>
        <h2 style={{ fontSize: 20, fontWeight: 700, color: 'var(--fl-text)', marginBottom: 4 }}>Heimdall DFIR</h2>
        <p style={{ fontSize: 13, color: 'var(--fl-muted)', lineHeight: 1.6 }}>
          Plateforme forensique numérique open-source. Conçue pour les enquêteurs DFIR, les équipes SOC et les analystes en réponse aux incidents.
        </p>
      </div>

      <div style={{ background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 10, overflow: 'hidden', marginBottom: 24 }}>
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
            Outils open-source intégrés
          </span>
          <span style={{ fontSize: 11, color: 'var(--fl-muted)', fontWeight: 400 }}>{open ? '▲ Réduire' : '▼ Afficher'}</span>
        </button>

        {open && (
          <div style={{ padding: '0 18px 18px' }}>
            <p style={{ fontSize: 12, color: 'var(--fl-muted)', marginBottom: 16, lineHeight: 1.5 }}>
              Heimdall s'appuie sur les outils DFIR open-source suivants. Leurs auteurs et licences doivent être respectés lors de toute redistribution.
            </p>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--fl-border)' }}>
                  <th style={{ textAlign: 'left', padding: '6px 10px', color: 'var(--fl-muted)', fontWeight: 600, fontSize: 11 }}>Outil</th>
                  <th style={{ textAlign: 'left', padding: '6px 10px', color: 'var(--fl-muted)', fontWeight: 600, fontSize: 11 }}>Auteur</th>
                  <th style={{ textAlign: 'left', padding: '6px 10px', color: 'var(--fl-muted)', fontWeight: 600, fontSize: 11 }}>Licence</th>
                  <th style={{ textAlign: 'left', padding: '6px 10px', color: 'var(--fl-muted)', fontWeight: 600, fontSize: 11 }}>Description</th>
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
                        fontSize: 10, fontFamily: 'monospace', padding: '2px 6px', borderRadius: 4,
                        background: 'color-mix(in srgb, var(--fl-accent) 12%, transparent)',
                        color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 25%, transparent)',
                      }}>{c.license}</span>
                    </td>
                    <td style={{ padding: '10px 10px', verticalAlign: 'top', color: 'var(--fl-muted)', lineHeight: 1.5 }}>{c.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div style={{ background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 10, padding: '14px 18px' }}>
        <p style={{ fontSize: 11, color: 'var(--fl-muted)', lineHeight: 1.6, margin: 0 }}>
          Heimdall DFIR est distribué sous licence open-source. Pour signaler un bug ou contribuer :{' '}
          <span style={{ fontFamily: 'monospace', color: 'var(--fl-accent)' }}>github.com/Heimdall-DFIR</span>
        </p>
      </div>
    </div>
  );
}
