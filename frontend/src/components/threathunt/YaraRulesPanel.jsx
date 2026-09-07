import { useState, useEffect, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Shield, Search, Plus, Trash2, Pencil, ToggleLeft, ToggleRight } from 'lucide-react';
import { threatHuntingAPI } from '../../utils/api';
import {
  Button, Modal, Spinner, DataTable, constantColumns, ScopeBar,
  SearchInput, FilterChip, EmptyState, Alert,
} from '../ui';
import { isDestructionConfirmed } from '../../utils/destructiveConfirm';
import {
  mergeRuleStats, filterYaraRules, sortByMatchCountDesc, computeYaraRuleStats, SCOPE_CANDIDATE_COLUMNS,
} from '../../pages/yaraRulesTable';
import { isRuleDimmed } from '../../pages/ruleDimming';
import { C, fmtDate } from './shared';

const YARA_TEMPLATE = `rule ExempleMalware {
    meta:
        description = "Detects the MZ signature (PE executable)"
        author      = "Heimdall DFIR"
    strings:
        $mz = { 4D 5A }
        $pe = "This program cannot be run in DOS mode"
    condition:
        $mz at 0 and $pe
}`;

export default function YaraRulesPanel() {
  const { t, i18n } = useTranslation();
  const [rules, setRules]        = useState([]);
  const [ruleStats, setRuleStats] = useState([]);
  const [loading, setLoading]    = useState(true);
  const [loadError, setLoadError] = useState('');
  const [statsError, setStatsError] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [editing, setEditing]    = useState(null);
  const [form, setForm]          = useState({ name: '', description: '', content: '', tags: '' });
  const [saving, setSaving]      = useState(false);
  const [error, setError]        = useState('');

  const [search, setSearch]       = useState('');
  const [filter, setFilter]       = useState('all');
  const [restoredScope, setRestoredScope] = useState(() => new Set());

  const [pendingDelete, setPendingDelete] = useState(null);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');
  const [deleting, setDeleting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true); setLoadError(''); setStatsError('');
    try {
      const rulesRes = await threatHuntingAPI.yaraRules();
      setRules(rulesRes.data.rules ?? []);
    } catch (e) {
      setLoadError(e.response?.data?.error || e.message || t('threat_hunt.errors.load_rules'));
      setLoading(false);
      return;
    }
    try {
      const statsRes = await threatHuntingAPI.yaraRuleStats();
      setRuleStats(statsRes.data.stats ?? []);
    } catch (e) {
      setRuleStats([]);
      setStatsError(e.response?.data?.error || e.message || t('threat_hunt.errors.load_rule_stats'));
    }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const rows = useMemo(() => mergeRuleStats(rules, ruleStats), [rules, ruleStats]);
  const stats = useMemo(() => computeYaraRuleStats(rows), [rows]);
  const segmentCounts = useMemo(() => ({
    all: rows.length,
    matched: rows.filter(r => r.match_count > 0).length,
    muted: rows.filter(r => r.match_count === 0).length,
    inactive: rows.filter(r => !r.is_active).length,
  }), [rows]);
  const visibleRows = useMemo(
    () => sortByMatchCountDesc(filterYaraRules(rows, { search, filter })),
    [rows, search, filter],
  );

  const constantKeys = useMemo(() => constantColumns(rows, SCOPE_CANDIDATE_COLUMNS), [rows]);
  const liftedKeys = useMemo(
    () => constantKeys.filter(key => !restoredScope.has(key)),
    [constantKeys, restoredScope],
  );

  function restoreScopeColumn(...keys) {
    setRestoredScope(prev => {
      const next = new Set(prev);
      keys.forEach(k => next.add(k));
      return next;
    });
  }

  const scopeTokens = useMemo(() => {
    const first = rows[0];
    if (!first) return [];
    const tokens = [];

    if (liftedKeys.includes('description')) {
      tokens.push({
        key: 'description',
        label: t('threat_hunt.yara.columns.description'),
        value: first.description || '—',
        onRemove: () => restoreScopeColumn('description'),
      });
    }
    if (liftedKeys.includes('tagsKey')) {
      tokens.push({
        key: 'tagsKey',
        label: t('threat_hunt.yara.columns.tags'),
        value: (first.tags || []).join(', ') || '—',
        onRemove: () => restoreScopeColumn('tagsKey'),
      });
    }
    const authorLifted = liftedKeys.includes('author_username');
    const dateLifted   = liftedKeys.includes('created_at');
    if (authorLifted && dateLifted) {
      tokens.push({
        key: 'author_date',
        label: t('threat_hunt.yara.columns.author'),
        value: t('threat_hunt.by_author', { author: first.author_username || '—', date: fmtDate(first.created_at, i18n.language) }),
        onRemove: () => restoreScopeColumn('author_username', 'created_at'),
      });
    } else {
      if (authorLifted) {
        tokens.push({
          key: 'author_username',
          label: t('threat_hunt.yara.columns.author'),
          value: first.author_username || '—',
          onRemove: () => restoreScopeColumn('author_username'),
        });
      }
      if (dateLifted) {
        tokens.push({
          key: 'created_at',
          label: t('threat_hunt.yara.columns.created_at'),
          value: fmtDate(first.created_at, i18n.language),
          onRemove: () => restoreScopeColumn('created_at'),
        });
      }
    }
    return tokens;
  }, [liftedKeys, rows, t, i18n.language]);

  function openCreate() {
    setEditing(null);
    setForm({ name: '', description: '', content: YARA_TEMPLATE, tags: '' });
    setError(''); setShowModal(true);
  }
  function openEdit(r) {
    setEditing(r);
    setForm({ name: r.name, description: r.description || '', content: r.content, tags: (r.tags || []).join(', ') });
    setError(''); setShowModal(true);
  }

  async function save() {
    if (!form.name.trim() || !form.content.trim()) { setError(t('threat_hunt.errors.name_content_required')); return; }
    setSaving(true); setError('');
    try {
      const tags = form.tags.split(',').map(t => t.trim()).filter(Boolean);
      const data = { name: form.name, description: form.description, content: form.content, tags };
      if (editing) await threatHuntingAPI.updateYaraRule(editing.id, data);
      else         await threatHuntingAPI.createYaraRule(data);
      setShowModal(false); load();
    } catch (e) {
      setError(e.response?.data?.error || t('threat_hunt.errors.save_failed'));
    } finally { setSaving(false); }
  }

  function requestDelete(r) {
    setPendingDelete(r);
    setDeleteConfirmText('');
  }

  async function confirmDelete() {
    if (!pendingDelete) return;
    setDeleting(true);
    try { await threatHuntingAPI.deleteYaraRule(pendingDelete.id); setPendingDelete(null); load(); }
    catch (_e) { }
    finally { setDeleting(false); }
  }

  async function toggle(r) {
    try { await threatHuntingAPI.updateYaraRule(r.id, { is_active: !r.is_active }); load(); }
    catch (_e) {}
  }

  const columns = useMemo(() => {
    const cols = [
      {
        key: 'state', width: 34,
        header: <span className="sr-only">{t('threat_hunt.yara.columns.state')}</span>,
        render: r => <span className={`rt-state-dot${r.is_active ? ' rt-state-dot--active' : ''}`} aria-hidden="true" />,
      },
      {
        key: 'name', header: t('threat_hunt.yara.columns.rule'), mono: true,
        render: r => <span className={isRuleDimmed(r) ? 'rt-name-muted' : undefined}>{r.name}</span>,
      },
    ];

    if (restoredScope.has('description')) {
      cols.push({ key: 'description', header: t('threat_hunt.yara.columns.description') });
    }
    if (restoredScope.has('tagsKey')) {
      cols.push({
        key: 'tagsDisplay', header: t('threat_hunt.yara.columns.tags'),
        render: r => (r.tags || []).join(', ') || '—',
      });
    }
    if (restoredScope.has('author_username')) {
      cols.push({ key: 'author_username', header: t('threat_hunt.yara.columns.author') });
    }
    if (restoredScope.has('created_at')) {
      cols.push({
        key: 'created_at_display', header: t('threat_hunt.yara.columns.created_at'), mono: true,
        render: r => fmtDate(r.created_at, i18n.language),
      });
    }

    cols.push(
      {
        key: 'match_count', header: t('threat_hunt.yara.columns.matches'), width: 120, align: 'right', mono: true,
        render: r => r.match_count > 0
          ? <span className="yara-match-count">{r.match_count}</span>
          : <span className="yara-match-count--zero">—</span>,
      },
      {
        key: 'last_matched_at', header: t('threat_hunt.yara.columns.last'), width: 150, mono: true,
        render: r => r.last_matched_at
          ? fmtDate(r.last_matched_at, i18n.language)
          : <span className="yara-last-never">{t('threat_hunt.yara.never_matched')}</span>,
      },
      {
        key: 'actions', width: 110,
        header: <span className="sr-only">{t('threat_hunt.yara.columns.actions')}</span>,
        render: r => (
          <div className="dt-row-actions">
            <button
              type="button" className="rt-action-btn"
              aria-label={t(r.is_active ? 'threat_hunt.yara.aria.disable_rule' : 'threat_hunt.yara.aria.enable_rule', { name: r.name })}
              onClick={() => toggle(r)}
            >
              {r.is_active ? <ToggleRight size={14} /> : <ToggleLeft size={14} />}
            </button>
            <button
              type="button" className="rt-action-btn"
              aria-label={t('threat_hunt.yara.aria.edit_rule', { name: r.name })}
              onClick={() => openEdit(r)}
            >
              <Pencil size={12} />
            </button>
            <button
              type="button" className="rt-action-btn rt-action-btn--danger"
              aria-label={t('threat_hunt.yara.aria.delete_rule', { name: r.name })}
              onClick={() => requestDelete(r)}
            >
              <Trash2 size={12} />
            </button>
          </div>
        ),
      },
    );
    return cols;
  }, [restoredScope, t, i18n.language]);

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <p style={{ margin: 0, fontSize: 13, color: 'var(--fl-dim)' }}>
          {t('threat_hunt.yara.rules_count', { count: rules.length })}
        </p>
        <div style={{ display: 'flex', gap: 8 }}>
          <Button variant="primary" size="sm" icon={Plus} onClick={openCreate}>{t('threat_hunt.buttons.new_rule')}</Button>
        </div>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: 40 }}>
          <Spinner size={24} />
        </div>
      ) : loadError ? (
        <Alert variant="danger" message={loadError} />
      ) : rows.length === 0 ? (
        <EmptyState icon={Shield} title={t('threat_hunt.no_yara')} />
      ) : (
        <>
          {statsError && <Alert variant="warn" message={statsError} />}

          <div className="rt-stat-row">
            <span>{t('threat_hunt.yara.stat_rules', { count: stats.total })}</span>
            <span>{t('threat_hunt.yara.stat_active', { count: stats.active })}</span>
            <span>{t('threat_hunt.yara.stat_matched', { count: stats.matched })}</span>
            <span>{t('threat_hunt.yara.stat_muted', { count: stats.muted })}</span>
            <span>{t('threat_hunt.yara.stat_matches', { count: stats.totalMatches })}</span>
          </div>

          <ScopeBar tokens={scopeTokens} />

          <div className="rt-toolbar">
            <SearchInput
              value={search}
              onChange={setSearch}
              onClear={() => setSearch('')}
              placeholder={t('threat_hunt.yara.search_placeholder')}
              style={{ minWidth: 240 }}
            />
            <div className="rt-toolbar-filters">
              <FilterChip active={filter === 'all'} onClick={() => setFilter('all')} count={segmentCounts.all}>
                {t('threat_hunt.yara.filter_all')}
              </FilterChip>
              <FilterChip active={filter === 'matched'} color="var(--fl-warn)" onClick={() => setFilter('matched')} count={segmentCounts.matched}>
                {t('threat_hunt.yara.filter_matched')}
              </FilterChip>
              <FilterChip active={filter === 'muted'} onClick={() => setFilter('muted')} count={segmentCounts.muted}>
                {t('threat_hunt.yara.filter_muted')}
              </FilterChip>
              <FilterChip active={filter === 'inactive'} color="var(--fl-subtle)" onClick={() => setFilter('inactive')} count={segmentCounts.inactive}>
                {t('threat_hunt.yara.filter_inactive')}
              </FilterChip>
            </div>
          </div>

          {visibleRows.length === 0 ? (
            <EmptyState icon={Search} title={t('threat_hunt.yara.no_search_results')} />
          ) : (
            <div className="rt-table-wrap">
              <DataTable columns={columns} rows={visibleRows} rowKey={r => r.id} density="compact" />
            </div>
          )}
        </>
      )}

      <Modal
        open={showModal}
        title={editing ? t('threat_hunt.yara.edit_title') : t('threat_hunt.yara.new_title')}
        onClose={() => setShowModal(false)}
        size="lg"
        accentColor={C.yara}
      >
        <Modal.Body>
          <div style={{ marginBottom: 14 }}>
            <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>{t('threat_hunt.form.name')}</label>
            <input className="fl-input" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder={t('threat_hunt.yara.name_ph')} />
          </div>
          <div style={{ marginBottom: 14 }}>
            <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>{t('threat_hunt.form.description_optional')}</label>
            <input className="fl-input" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} placeholder={t('threat_hunt.form.description_ph')} />
          </div>
          <div style={{ marginBottom: 14 }}>
            <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>{t('threat_hunt.form.tags_csv')}</label>
            <input className="fl-input" value={form.tags} onChange={e => setForm(f => ({ ...f, tags: e.target.value }))} placeholder={t('threat_hunt.yara.tags_ph')} />
          </div>
          <div style={{ marginBottom: 14 }}>
            <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>{t('threat_hunt.yara.content')}</label>
            <textarea className="fl-input" value={form.content} onChange={e => setForm(f => ({ ...f, content: e.target.value }))} rows={14} style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', resize: 'vertical' }} />
          </div>
          {error && (
            <div style={{ background: 'color-mix(in srgb, var(--fl-danger) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 30%, transparent)', borderRadius: 6, padding: '8px 12px', marginBottom: 12, fontSize: 12, color: 'var(--fl-danger)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
              {error}
            </div>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowModal(false)}>{t('common.cancel')}</Button>
          <Button variant="primary" loading={saving} onClick={save}>{t('common.save')}</Button>
        </Modal.Footer>
      </Modal>

      <Modal
        open={!!pendingDelete}
        title={t('threat_hunt.yara.delete_modal_title')}
        onClose={() => setPendingDelete(null)}
        size="sm"
        accentColor="var(--fl-danger)"
      >
        <Modal.Body>
          <p className="rt-delete-warning">{t('threat_hunt.yara.delete_modal_warning')}</p>
          <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>
            {t('threat_hunt.yara.delete_modal_type_prompt', { name: pendingDelete?.name })}
          </label>
          <input
            className="fl-input"
            value={deleteConfirmText}
            onChange={e => setDeleteConfirmText(e.target.value)}
            autoComplete="off"
          />
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" disabled={deleting} onClick={() => setPendingDelete(null)}>{t('common.cancel')}</Button>
          <Button
            variant="danger"
            icon={deleting ? undefined : Trash2}
            loading={deleting}
            disabled={!isDestructionConfirmed(deleteConfirmText, pendingDelete?.name)}
            onClick={confirmDelete}
          >
            {t('common.delete')}
          </Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
}
