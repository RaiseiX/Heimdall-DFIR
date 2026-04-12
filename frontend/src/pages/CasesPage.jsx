import { useState, useEffect, useMemo } from 'react';
import { useTheme } from '../utils/theme';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  Plus, Search, AlertTriangle, FolderOpen, X, FileText,
  Crosshair, Trash2, CheckCircle2, XCircle, ShieldAlert, Clock, User,
} from 'lucide-react';
import { casesAPI } from '../utils/api';
import { Button, Modal, Badge, EmptyState, Spinner } from '../components/ui';
import { StatusPill, PriorityPill, RiskPill, TimePill, fmtDuration } from '../components/ui/StatusPill';

function minDeadline() {
  const d = new Date();
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
  return d.toISOString().slice(0, 16);
}

export default function CasesPage({ user }) {
  const T = useTheme();
  const navigate = useNavigate();
  const { t, i18n } = useTranslation();

  const PRIORITY = useMemo(() => ({
    critical: { label: t('cases.prio_critical'), variant: 'danger' },
    high:     { label: t('cases.prio_high'),     variant: 'warn'   },
    medium:   { label: t('cases.prio_medium'),   variant: 'gold'   },
    low:      { label: t('cases.prio_low'),      variant: 'ok'     },
  }), [t]);

  const STATUS = useMemo(() => ({
    active:  { label: t('case.status_active'),   variant: 'accent' },
    pending: { label: t('case.status_pending'),  variant: 'warn'   },
    closed:  { label: t('case.status_closed'),   variant: 'dim'    },
  }), [t]);

  const [cases, setCases] = useState([]);
  const [search, setSearch] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [filterPriority, setFilterPriority] = useState('');
  const [showNew, setShowNew] = useState(false);
  const [newCase, setNewCase] = useState({ title: '', description: '', priority: 'medium', report_deadline: '' });

  const [selected, setSelected] = useState(new Set());
  const [showBulkDelete, setShowBulkDelete] = useState(false);
  const [bulkDeleting, setBulkDeleting] = useState(false);
  const [deleteResults, setDeleteResults] = useState(null);
  const [timeStats, setTimeStats] = useState({});

  const isAdmin = user?.role === 'admin';

  useEffect(() => { loadCases(); }, [search, filterStatus, filterPriority]);

  useEffect(() => {
    if (cases.length > 0) {
      setSelected(prev => {
        const caseIds = new Set(cases.map(c => c.id));
        const cleaned = new Set([...prev].filter(id => caseIds.has(id)));
        return cleaned.size !== prev.size ? cleaned : prev;
      });
    }
  }, [cases]);

  const loadCases = async () => {
    try {
      const { data } = await casesAPI.list({ search, status: filterStatus, priority: filterPriority });
      setCases(data.cases);
      // Load time stats for each case in parallel (silent)
      const stats = {};
      await Promise.all((data.cases || []).map(async c => {
        try {
          const r = await casesAPI.timeStats(c.id);
          stats[c.id] = r.data;
        } catch (_) {}
      }));
      setTimeStats(stats);
    } catch {
      setCases([
        { id: '1', case_number: 'CASE-2026-001', title: 'Intrusion Serveur Principal', status: 'active', priority: 'critical', investigator_name: 'Agent Dupont', created_at: '2026-02-10T08:30:00Z', evidence_count: 5, ioc_count: 5, tags: ['intrusion', 'apt'] },
        { id: '2', case_number: 'CASE-2026-002', title: 'Ransomware Département Finance', status: 'active', priority: 'high', investigator_name: 'Agent Martin', created_at: '2026-02-12T14:15:00Z', evidence_count: 3, ioc_count: 3, tags: ['ransomware', 'lockbit'] },
        { id: '3', case_number: 'CASE-2026-003', title: 'Analyse Clé USB Suspecte', status: 'pending', priority: 'medium', investigator_name: 'Agent Lefèvre', created_at: '2026-02-14T09:00:00Z', evidence_count: 1, ioc_count: 0, tags: ['usb', 'malware'] },
      ]);
    }
  };

  const handleCreate = async () => {
    if (!newCase.title.trim()) return;
    try {
      const payload = { ...newCase, report_deadline: newCase.report_deadline || null };
      const { data } = await casesAPI.create(payload);
      setShowNew(false);
      setNewCase({ title: '', description: '', priority: 'medium', report_deadline: '' });
      navigate(`/cases/${data.id}`);
    } catch {
      setShowNew(false);
      setNewCase({ title: '', description: '', priority: 'medium', report_deadline: '' });
    }
  };

  const toggleSelect = (e, id) => {
    e.stopPropagation();
    setSelected(prev => { const next = new Set(prev); next.has(id) ? next.delete(id) : next.add(id); return next; });
  };

  const toggleAll = () => {
    if (selected.size === cases.length) setSelected(new Set());
    else setSelected(new Set(cases.map(c => c.id)));
  };

  const selectedCases = cases.filter(c => selected.has(c.id));

  const handleBulkDelete = async () => {
    setBulkDeleting(true);
    const results = [];
    for (const c of selectedCases) {
      try {
        const { data } = await casesAPI.hardDelete(c.id);
        let verified = false;
        try { await casesAPI.get(c.id); verified = false; }
        catch (verErr) { verified = verErr.response?.status === 404; }
        results.push({ id: c.id, case_number: c.case_number, title: c.title, ok: true, files_destroyed: data.files_destroyed ?? 0, files_errors: data.files_errors ?? [], verified });
      } catch (err) {
        results.push({ id: c.id, case_number: c.case_number, title: c.title, ok: false, error: err.response?.data?.error || err.message, verified: false });
      }
    }
    setBulkDeleting(false);
    setDeleteResults(results);
    const deletedIds = new Set(results.filter(r => r.ok).map(r => r.id));
    setCases(prev => prev.filter(c => !deletedIds.has(c.id)));
    setSelected(new Set());
  };

  const criticalCount = cases.filter(c => c.priority === 'critical').length;
  const activeCount = cases.filter(c => c.status === 'active').length;

  return (
    <div className="p-6">
      
      <div style={{ display: 'flex', flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 18, marginBottom: 20, borderBottom: '1px solid var(--fl-border)' }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <h1 style={{ fontFamily: 'monospace', fontSize: 17, fontWeight: 700, color: 'var(--fl-text)', lineHeight: 1.25 }}>{t('cases.title')}</h1>
          <p style={{ fontFamily: 'monospace', fontSize: 13, color: 'var(--fl-dim)', marginTop: 3 }}>
            {t('cases.subtitle', { n: cases.length, m: activeCount })}
            {criticalCount > 0 && (
              <span style={{ color: 'var(--fl-danger)' }}>
                {' '}{t(criticalCount > 1 ? 'cases.criticals_pl' : 'cases.criticals', { n: criticalCount })}
              </span>
            )}
          </p>
        </div>
        <div style={{ flexShrink: 0, marginLeft: 16 }}>
          <Button variant="primary" icon={Plus} onClick={() => setShowNew(true)}>
            {t('cases.new')}
          </Button>
        </div>
      </div>

      {isAdmin && selected.size > 0 && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 12,
          padding: '10px 16px', marginBottom: 12, borderRadius: 8,
          background: 'color-mix(in srgb, var(--fl-danger) 7%, transparent)',
          border: '1px solid color-mix(in srgb, var(--fl-danger) 25%, transparent)',
        }}>
          <ShieldAlert size={15} style={{ color: 'var(--fl-danger)', flexShrink: 0 }} />
          <span style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--fl-danger)', flex: 1 }}>
            <strong>{selected.size}</strong> {t(selected.size > 1 ? 'cases.selected_rgpd_pl' : 'cases.selected_rgpd', { n: selected.size })}
          </span>
          <Button variant="danger" size="sm" icon={Trash2} onClick={() => { setShowBulkDelete(true); setDeleteResults(null); }}>
            {t('cases.destroy_selection')}
          </Button>
          <Button variant="secondary" size="sm" icon={X} onClick={() => setSelected(new Set())}>
            {t('cases.deselect')}
          </Button>
        </div>
      )}

      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 14 }}>
        <div className="fl-search" style={{ flex: 1, minWidth: 200 }}>
          <Search size={14} className="fl-search-icon" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder={t('cases.search_ph')}
            className="fl-input"
            style={{ paddingLeft: 34 }}
          />
        </div>

        <div style={{ display: 'flex', gap: 4, alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{ fontSize: 10, color: 'var(--fl-subtle)', fontFamily: 'monospace' }}>Statut :</span>
          {[['', 'Tous'], ['active', 'Actif'], ['pending', 'En attente'], ['closed', 'Fermé']].map(([val, lbl]) => (
            <button key={val} onClick={() => setFilterStatus(val)}
              style={{
                padding: '3px 10px', borderRadius: 20, fontSize: 10, fontFamily: 'monospace',
                cursor: 'pointer', border: '1px solid',
                background: filterStatus === val ? (val === '' ? 'var(--fl-accent)' : val === 'active' ? 'var(--fl-accent)' : val === 'pending' ? 'var(--fl-warn)' : 'var(--fl-dim)') + '20' : 'transparent',
                color: filterStatus === val ? (val === '' ? 'var(--fl-accent)' : val === 'active' ? 'var(--fl-accent)' : val === 'pending' ? 'var(--fl-warn)' : 'var(--fl-dim)') : 'var(--fl-muted)',
                borderColor: filterStatus === val ? (val === '' ? 'var(--fl-accent)' : val === 'active' ? 'var(--fl-accent)' : val === 'pending' ? 'var(--fl-warn)' : 'var(--fl-dim)') + '50' : 'var(--fl-border)',
                fontWeight: filterStatus === val ? 700 : 400,
              }}>
              {lbl}
            </button>
          ))}
        </div>

        <div style={{ display: 'flex', gap: 4, alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{ fontSize: 10, color: 'var(--fl-subtle)', fontFamily: 'monospace' }}>Priorité :</span>
          {[
            ['', 'Toutes', 'var(--fl-dim)'],
            ['critical', 'Critique', 'var(--fl-danger)'],
            ['high', 'Haut', 'var(--fl-warn)'],
            ['medium', 'Moyen', 'var(--fl-gold)'],
            ['low', 'Faible', 'var(--fl-ok)'],
          ].map(([val, lbl, col]) => (
            <button key={val} onClick={() => setFilterPriority(val)}
              style={{
                padding: '3px 10px', borderRadius: 20, fontSize: 10, fontFamily: 'monospace',
                cursor: 'pointer', border: '1px solid',
                background: filterPriority === val ? col + '20' : 'transparent',
                color: filterPriority === val ? col : 'var(--fl-muted)',
                borderColor: filterPriority === val ? col + '50' : 'var(--fl-border)',
                fontWeight: filterPriority === val ? 700 : 400,
              }}>
              {lbl}
            </button>
          ))}
        </div>

        {(search || filterStatus || filterPriority) && (
          <Button variant="ghost" size="sm" icon={X} onClick={() => { setSearch(''); setFilterStatus(''); setFilterPriority(''); }}>
            {t('cases.clear_filters')}
          </Button>
        )}
      </div>

      {cases.length === 0 ? (
        <div className="fl-card" style={{ overflow: 'hidden' }}>
          <EmptyState
            icon={FolderOpen}
            title={t('cases.empty_title')}
            subtitle={search || filterStatus || filterPriority ? t('cases.empty_filter') : t('cases.empty_start')}
            action={!search && !filterStatus && !filterPriority ? (
              <Button variant="primary" size="sm" icon={Plus} onClick={() => setShowNew(true)}>{t('cases.new')}</Button>
            ) : undefined}
          />
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 12 }}>
          {cases.map(c => {
            const isSelected = selected.has(c.id);
            const prioColor = c.priority === 'critical' ? 'var(--fl-danger)'
              : c.priority === 'high' ? 'var(--fl-warn)'
              : c.priority === 'medium' ? 'var(--fl-gold)'
              : 'var(--fl-border)';
            const ts = timeStats[c.id];
            const deadlineSoon = c.report_deadline && new Date(c.report_deadline) < new Date(Date.now() + 48 * 3600 * 1000);
            return (
              <div
                key={c.id}
                onClick={() => navigate(`/cases/${c.id}`)}
                style={{
                  borderRadius: 10, overflow: 'hidden', cursor: 'pointer',
                  background: isSelected ? 'color-mix(in srgb, var(--fl-danger) 5%, var(--fl-card))' : 'var(--fl-card)',
                  border: `1px solid ${isSelected ? 'color-mix(in srgb, var(--fl-danger) 30%, transparent)' : 'var(--fl-border)'}`,
                  borderLeft: `4px solid ${prioColor}`,
                  transition: 'border-color 0.15s, box-shadow 0.15s',
                }}
                onMouseEnter={e => { e.currentTarget.style.boxShadow = `0 4px 16px rgba(0,0,0,0.35)`; e.currentTarget.style.borderColor = prioColor + '80'; }}
                onMouseLeave={e => { e.currentTarget.style.boxShadow = ''; e.currentTarget.style.borderColor = isSelected ? 'color-mix(in srgb, var(--fl-danger) 30%, transparent)' : 'var(--fl-border)'; }}
              >
                {/* Card header */}
                <div style={{ padding: '12px 14px 8px', display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                  {isAdmin && (
                    <div onClick={e => toggleSelect(e, c.id)} style={{ paddingTop: 2, flexShrink: 0 }}>
                      <input type="checkbox" checked={isSelected} onChange={() => {}}
                        style={{ cursor: 'pointer', accentColor: 'var(--fl-danger)' }} />
                    </div>
                  )}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                      <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-subtle)' }}>{c.case_number}</span>
                      <StatusPill status={c.status} />
                      <PriorityPill priority={c.priority} />
                    </div>
                    <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--fl-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={c.title}>
                      {c.title}
                    </div>
                    {(c.tags || []).length > 0 && (
                      <div style={{ display: 'flex', gap: 4, marginTop: 5, flexWrap: 'wrap' }}>
                        {(c.tags || []).map(tag => <span key={tag} className="fl-tag">{tag}</span>)}
                      </div>
                    )}
                  </div>
                  <RiskPill riskLevel={c.risk_level} riskScore={c.risk_score} />
                </div>

                {/* Card footer */}
                <div style={{
                  padding: '7px 14px 9px', borderTop: '1px solid var(--fl-sep)',
                  display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap',
                }}>
                  {c.investigator_name && (
                    <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-muted)' }}>
                      <User size={9} />{c.investigator_name}
                    </span>
                  )}
                  <span style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-accent)' }}>
                    <FileText size={9} />{c.evidence_count || 0}
                  </span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: 10, fontFamily: 'monospace', color: c.ioc_count > 0 ? 'var(--fl-warn)' : 'var(--fl-muted)' }}>
                    <Crosshair size={9} />{c.ioc_count || 0}
                  </span>
                  {ts && ts.grand_total_seconds > 0 && (
                    <TimePill totalSeconds={ts.grand_total_seconds} analystCount={ts.analysts?.length || 0} compact />
                  )}
                  <span style={{ marginLeft: 'auto', fontSize: 10, fontFamily: 'monospace', color: deadlineSoon ? 'var(--fl-danger)' : 'var(--fl-subtle)', whiteSpace: 'nowrap' }}>
                    {c.report_deadline
                      ? (deadlineSoon ? '⚠ ' : '') + new Date(c.report_deadline).toLocaleDateString(i18n.language)
                      : new Date(c.created_at).toLocaleDateString(i18n.language)}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <Modal open={showNew} title={t('cases.new_title')} onClose={() => setShowNew(false)} size="md">
        <Modal.Body>
          <div className="space-y-4">
            <div>
              <label className="fl-label">{t('cases.title_label')} <span style={{ color: 'var(--fl-danger)' }}>*</span></label>
              <input value={newCase.title} onChange={e => setNewCase({ ...newCase, title: e.target.value })}
                className="fl-input w-full" placeholder={t('cases.title_ph')} autoFocus
                onKeyDown={e => e.key === 'Enter' && handleCreate()} />
            </div>
            <div>
              <label className="fl-label">{t('cases.desc_label')}</label>
              <textarea value={newCase.description} onChange={e => setNewCase({ ...newCase, description: e.target.value })}
                className="fl-input w-full" rows={3} placeholder={t('cases.desc_ph')} style={{ resize: 'vertical' }} />
            </div>
            <div>
              <label className="fl-label">{t('cases.priority_label')}</label>
              <div className="flex gap-2 flex-wrap">
                {Object.entries(PRIORITY).map(([key, { label, variant }]) => (
                  <Button key={key} size="xs" variant={newCase.priority === key ? 'danger' : 'ghost'}
                    icon={key === 'critical' ? AlertTriangle : undefined}
                    onClick={() => setNewCase({ ...newCase, priority: key })}
                    style={{ fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: newCase.priority === key ? 700 : 500 }}>
                    {label}
                  </Button>
                ))}
              </div>
            </div>
            <div>
              <label className="fl-label">{t('cases.deadline_label')}</label>
              <input type="datetime-local" value={newCase.report_deadline} min={minDeadline()}
                onChange={e => setNewCase({ ...newCase, report_deadline: e.target.value })} className="fl-input w-full" />
              <div className="text-xs mt-1" style={{ color: 'var(--fl-muted)' }}>{t('cases.deadline_optional')}</div>
            </div>
          </div>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowNew(false)}>{t('common.cancel')}</Button>
          <Button variant="primary" onClick={handleCreate} disabled={!newCase.title.trim()}>{t('cases.create')}</Button>
        </Modal.Footer>
      </Modal>

      <Modal
        open={showBulkDelete}
        title={deleteResults ? t('cases.report_title') : t('cases.destroy_title', { n: selectedCases.length })}
        onClose={() => setShowBulkDelete(false)}
        size="md"
        accentColor="var(--fl-danger)"
      >
        <Modal.Body>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {!deleteResults && !bulkDeleting && (
              <>
                <div style={{ padding: '10px 14px', borderRadius: 8,
                  background: 'color-mix(in srgb, var(--fl-danger) 6%, transparent)',
                  border: '1px solid color-mix(in srgb, var(--fl-danger) 18%, transparent)',
                  fontSize: 12, color: 'var(--fl-muted)', lineHeight: 1.7 }}>
                  {t('cases.rgpd_warning').replace('DoD 5220.22-M', '')}
                  <code style={{ color: 'var(--fl-danger)', fontFamily: 'monospace' }}>DoD 5220.22-M</code>.
                  {' '}{t('cases.rgpd_warning').split('.').slice(1).join('.').trim()}<br />
                  <span style={{ color: 'var(--fl-gold)' }}>{t('cases.rgpd_audit')}</span>
                </div>
                <div style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  {t('cases.selected_label', { n: selectedCases.length })}
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {selectedCases.map(c => (
                    <div key={c.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', borderRadius: 6,
                      background: 'var(--fl-bg)', border: '1px solid color-mix(in srgb, var(--fl-danger) 15%, transparent)' }}>
                      <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-danger)', flexShrink: 0, minWidth: 120 }}>{c.case_number}</span>
                      <span style={{ fontSize: 12, color: 'var(--fl-muted)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.title}</span>
                      <Badge variant={PRIORITY[c.priority]?.variant || 'dim'}>{PRIORITY[c.priority]?.label || c.priority}</Badge>
                    </div>
                  ))}
                </div>
              </>
            )}
            {bulkDeleting && (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '32px 0', gap: 14 }}>
                <Spinner size={32} color="var(--fl-danger)" />
                <div style={{ fontFamily: 'monospace', fontSize: 13, color: 'var(--fl-muted)' }}>{t('cases.destroying')}</div>
                <div style={{ fontSize: 11, color: 'var(--fl-dim)', fontFamily: 'monospace' }}>DoD 5220.22-M · cascade delete · audit log</div>
              </div>
            )}
            {deleteResults && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {deleteResults.map(r => (
                  <div key={r.id} style={{ padding: '10px 14px', borderRadius: 8,
                    border: `1px solid color-mix(in srgb, ${r.ok && r.verified ? 'var(--fl-ok)' : 'var(--fl-danger)'} 25%, transparent)`,
                    background: `color-mix(in srgb, ${r.ok && r.verified ? 'var(--fl-ok)' : 'var(--fl-danger)'} 5%, transparent)` }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: r.ok ? 6 : 0 }}>
                      {r.ok && r.verified ? <CheckCircle2 size={15} style={{ color: 'var(--fl-ok)', flexShrink: 0 }} /> : <XCircle size={15} style={{ color: 'var(--fl-danger)', flexShrink: 0 }} />}
                      <span style={{ fontFamily: 'monospace', fontSize: 11, color: r.ok ? 'var(--fl-ok)' : 'var(--fl-danger)', fontWeight: 700 }}>{r.case_number}</span>
                      <span style={{ fontSize: 12, color: 'var(--fl-muted)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.title}</span>
                    </div>
                    {r.ok && (
                      <div style={{ display: 'flex', gap: 16, marginLeft: 23, flexWrap: 'wrap' }}>
                        <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-ok)' }}>
                          ✓ {t(r.files_destroyed > 1 ? 'cases.files_destroyed_pl' : 'cases.files_destroyed', { n: r.files_destroyed })}
                        </span>
                        <span style={{ fontSize: 11, fontFamily: 'monospace', color: r.verified ? 'var(--fl-ok)' : 'var(--fl-danger)' }}>
                          {r.verified ? `✓ ${t('cases.db_confirmed')}` : `⚠ ${t('cases.db_still_exists')}`}
                        </span>
                        {r.files_errors?.length > 0 && (
                          <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-gold)' }}>
                            ⚠ {t('cases.file_errors', { n: r.files_errors.length })}
                          </span>
                        )}
                      </div>
                    )}
                    {!r.ok && (
                      <div style={{ marginLeft: 23, fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-danger)' }}>
                        {t('common.error')}: {r.error}
                      </div>
                    )}
                  </div>
                ))}
                <div style={{ marginTop: 4, padding: '8px 14px', borderRadius: 6,
                  background: 'var(--fl-bg)', border: '1px solid var(--fl-border)',
                  fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-dim)', display: 'flex', gap: 20 }}>
                  <span style={{ color: 'var(--fl-ok)' }}>
                    ✓ {t(deleteResults.filter(r => r.ok).length > 1 ? 'cases.deleted_count_pl' : 'cases.deleted_count', { n: deleteResults.filter(r => r.ok).length })}
                  </span>
                  {deleteResults.filter(r => !r.ok).length > 0 && (
                    <span style={{ color: 'var(--fl-danger)' }}>
                      ✗ {t(deleteResults.filter(r => !r.ok).length > 1 ? 'cases.error_count_pl' : 'cases.error_count', { n: deleteResults.filter(r => !r.ok).length })}
                    </span>
                  )}
                  {deleteResults.filter(r => r.ok && !r.verified).length > 0 && (
                    <span style={{ color: 'var(--fl-gold)' }}>
                      ⚠ {t(deleteResults.filter(r => r.ok && !r.verified).length > 1 ? 'cases.unverified_count_pl' : 'cases.unverified_count', { n: deleteResults.filter(r => r.ok && !r.verified).length })}
                    </span>
                  )}
                </div>
              </div>
            )}
          </div>
        </Modal.Body>
        <Modal.Footer>
          {deleteResults ? (
            <Button variant="secondary" size="sm" onClick={() => setShowBulkDelete(false)}>{t('common.close')}</Button>
          ) : (
            <>
              <Button variant="secondary" size="sm" disabled={bulkDeleting} onClick={() => setShowBulkDelete(false)}>{t('common.cancel')}</Button>
              <Button variant="danger" size="sm" icon={bulkDeleting ? undefined : Trash2} loading={bulkDeleting} onClick={handleBulkDelete}>
                {bulkDeleting ? t('cases.confirming') : t('cases.confirm_destroy')}
              </Button>
            </>
          )}
        </Modal.Footer>
      </Modal>
    </div>
  );
}
