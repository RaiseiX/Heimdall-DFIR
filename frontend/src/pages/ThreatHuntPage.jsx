
import { useState, useEffect, useCallback, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  Shield, Scan, FileCode2, Search, Plus, Trash2, Pencil,
  ToggleLeft, ToggleRight, Clock, Github, Download, X,
  Monitor, ExternalLink, Loader, RefreshCw, Play, Rocket,
} from 'lucide-react';
import { casesAPI, evidenceAPI, threatHuntingAPI, timelineAPI } from '../utils/api';
import {
  Button, Modal, TabGroup, Badge, Spinner,
  DataTable, constantColumns, ScopeBar, SearchInput, FilterChip, EmptyState, Alert,
  CommandPalette,
} from '../components/ui';
import { fmtLocal } from '../utils/formatters';
import { isDestructionConfirmed } from '../utils/destructiveConfirm';
import {
  mergeRuleStats, filterYaraRules, sortByMatchCountDesc, computeYaraRuleStats, SCOPE_CANDIDATE_COLUMNS,
} from './yaraRulesTable';
import { deriveYaraScanStats, matchedStringsTitle } from './yaraScanTable';
import {
  sigmaLevelRank, sigmaLevelColor, sigmaLevelLabel, fmtNum, isRetiredUpstream, withTagsKey,
  filterSigmaRules, sortBySeverityDesc, computeSigmaRuleStats, SIGMA_SCOPE_CANDIDATE_COLUMNS,
  SIGMA_UPSTREAM_STATUSES,
} from './sigmaRulesTable';
import { isRuleDimmed } from './ruleDimming';
import { resolveThreatHuntTab } from './threatHuntTabs';
import GitHubImportModal from '../components/threathunt/GitHubImportModal';
import { C, fmtDate } from '../components/threathunt/shared';

function localeFor(lang) {
  return lang?.startsWith('en') ? 'en-US' : 'fr-FR';
}

function fmtSize(b) {
  if (!b) return '0 B';
  const k = 1024, s = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(Math.floor(Math.log(b) / Math.log(k)), s.length - 1);
  return `${(b / Math.pow(k, i)).toFixed(1)} ${s[i]}`;
}




function ScanProgressBar({ progress, color }) {
  if (!progress) return null;
  const pct = progress.total > 0 ? Math.round((progress.current / progress.total) * 100) : 0;
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--fl-dim)', marginBottom: 5 }}>
        <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '80%' }}>
          {progress.current}/{progress.total} — {progress.name}
        </span>
        <span style={{ flexShrink: 0 }}>{pct}%</span>
      </div>
      <div style={{ height: 5, background: 'var(--fl-border, var(--fl-border))', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: color || C.yara, borderRadius: 3, transition: 'width 0.15s ease' }} />
      </div>
    </div>
  );
}

function YaraScanTab() {
  const { t, i18n } = useTranslation();
  const [cases, setCases]         = useState([]);
  const [caseId, setCaseId]       = useState('');
  const [evidence, setEvidence]   = useState([]);
  const [results, setResults]     = useState([]);
  const [scanning, setScanning]   = useState(false);
  const [scopeInfo, setScopeInfo] = useState(null);
  const [progress, setProgress]   = useState(null);
  const [scanStats, setScanStats] = useState(null);
  const [scanError, setScanError] = useState('');
  const [scopeExplainOpen, setScopeExplainOpen] = useState(false);
  const [headerMeta, setHeaderMeta] = useState(null);

  useEffect(() => {
    casesAPI.list().then(r => setCases(r.data.cases || [])).catch(() => {});
  }, []);

  useEffect(() => {
    setScopeInfo(null); setProgress(null); setScanStats(null); setScanError('');
    if (!caseId) { setEvidence([]); setResults([]); setHeaderMeta(null); return; }
    evidenceAPI.list(caseId).then(r => setEvidence(r.data.evidence || [])).catch(() => {});
    threatHuntingAPI.yaraResultsCase(caseId).then(r => setResults(r.data.results || [])).catch(() => {});
    timelineAPI.list(caseId, { limit: 1 })
      .then(r => setHeaderMeta({ hosts: r.data?.hosts_available || [] }))
      .catch(() => setHeaderMeta(null));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseId]);

  async function scanAll() {
    if (!caseId) return;
    setScanning(true); setScopeInfo(null); setProgress(null); setScanStats(null); setScanError('');
    try {
      const token = localStorage.getItem('heimdall_token');
      const resp = await fetch(`/api/threat-hunting/yara/scan-case/${caseId}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop();
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const ev = JSON.parse(line.slice(6));
            if (ev.type === 'start') {
              setScopeInfo({
                evidenceTotal: ev.total,
                rulesTotal: ev.rules,
                filesToScan: ev.files_to_scan ?? ev.total,
                skippedMemory: ev.skipped_memory || 0,
                skippedSize: ev.skipped_size || 0,
              });
            }
            if (ev.type === 'progress') {
              setProgress({
                current: ev.current, total: ev.total, name: ev.name,
                matchesSoFar: ev.matches_so_far ?? 0, filesFlaggedSoFar: ev.files_flagged_so_far ?? 0,
              });
            }
            if (ev.type === 'done') {
              setProgress(null);
              const summary = ev.summary || [];
              const matchedRuleNames = new Set();
              summary.forEach(s => (s.matches || []).forEach(m => matchedRuleNames.add(m.rule_name)));
              setScanStats({
                filesScanned: ev.files_scanned ?? summary.filter(s => !s.skipped).length,
                filesSkipped: ev.files_skipped ?? summary.filter(s => s.skipped).length,
                rulesChecked: ev.rules_checked ?? null,
                filesFlagged: ev.files_flagged ?? summary.filter(s => !s.skipped && (s.matches || []).length > 0).length,
                rulesMatched: matchedRuleNames.size,
                totalMatches: ev.total_rule_matches ?? summary.reduce((a, s) => a + (s.matches || []).length, 0),
              });
              const r = await threatHuntingAPI.yaraResultsCase(caseId);
              setResults(r.data.results || []);
            }
            if (ev.type === 'error') setScanError(ev.error);
          } catch (_e) {}
        }
      }
    } catch (e) {
      setScanError(t('threat_hunt.errors.scan_failed'));
    } finally { setScanning(false); setProgress(null); }
  }

  const selectedCase = cases.find(c => c.id === caseId) || null;

  const hostsLabel = useMemo(() => {
    if (!headerMeta) return null;
    const hosts = headerMeta.hosts || [];
    if (hosts.length === 0) return t('threat_hunt.sigma.meta_hosts_none');
    if (hosts.length === 1) return t('threat_hunt.sigma.meta_host', { host: hosts[0] });
    return t('threat_hunt.sigma.meta_hosts_count', { count: hosts.length, n: fmtNum(hosts.length, i18n.language) });
  }, [headerMeta, t, i18n.language]);

  const volumeLabel = useMemo(() => {
    if (!caseId) return null;
    const totalSize = evidence.reduce((a, e) => a + (Number(e.file_size) || 0), 0);
    return t('threat_hunt.yara.meta_volume', { count: evidence.length, n: fmtNum(evidence.length, i18n.language), size: fmtSize(totalSize) });
  }, [caseId, evidence, t, i18n.language]);

  const lastMatchLabel = useMemo(() => {
    const last = results[0]?.scanned_at;
    return last
      ? t('threat_hunt.yara.meta_last_match', { date: fmtDate(last, i18n.language) })
      : t('threat_hunt.yara.meta_last_match_none');
  }, [results, t, i18n.language]);

  const skippedTotal     = scopeInfo ? scopeInfo.skippedMemory + scopeInfo.skippedSize : 0;
  const scopeStatus      = scanError ? 'error' : scanning ? 'running' : scanStats ? 'done' : null;
  const scopeStatusColor = scopeStatus === 'error' ? 'var(--fl-danger)' : scopeStatus === 'running' ? C.yara : 'var(--fl-ok)';

  const derivedStats = useMemo(() => {
    if (scanStats) return scanStats;
    if (!results.length) return null;
    const fallback = deriveYaraScanStats(results);
    return {
      filesScanned: null, filesSkipped: null, rulesChecked: null,
      filesFlagged: fallback.filesFlagged, rulesMatched: fallback.rulesMatched, totalMatches: fallback.totalMatches,
    };
  }, [scanStats, results]);

  const columns = useMemo(() => [
    { key: 'evidence_name', header: t('threat_hunt.yara.columns.evidence'), mono: true },
    {
      key: 'rule_name', header: t('threat_hunt.yara.columns.rule'), mono: true,
      render: r => <span className="rt-cell-danger">{r.rule_name}</span>,
    },
    {
      key: 'matched_strings', header: t('threat_hunt.yara.columns.matched_strings'), width: 160, align: 'right', mono: true,
      render: r => {
        const count = (r.matched_strings || []).length;
        if (count === 0) return <span className="rt-name-muted">{t('threat_hunt.yara.match_without_strings')}</span>;
        return <span title={matchedStringsTitle(r.matched_strings)}>{fmtNum(count, i18n.language)}</span>;
      },
    },
    {
      key: 'scanned_at', header: t('threat_hunt.yara.columns.scanned_at'), width: 170, mono: true,
      render: r => (r.scanned_at ? fmtDate(r.scanned_at, i18n.language) : '—'),
    },
  ], [t, i18n.language]);

  return (
    <div>
      <div className="rt-control-row">
        <div className="rt-field">
          <label className="fl-label">{t('threat_hunt.case_label')}</label>
          <select value={caseId} onChange={e => setCaseId(e.target.value)} className="fl-input">
            <option value="">{t('threat_hunt.select_case')}</option>
            {cases.map(c => <option key={c.id} value={c.id}>{c.case_number} — {c.title}</option>)}
          </select>
        </div>
        <Button variant="primary" size="sm" icon={scanning ? undefined : Scan} loading={scanning} disabled={!caseId} onClick={scanAll}>
          {t('threat_hunt.yara.scan_all_files')}
        </Button>
      </div>

      {scanError && <Alert variant="danger" message={scanError} />}

      {!caseId ? (
        <EmptyState icon={Scan} title={t('threat_hunt.yara.pick_case_prompt')} />
      ) : (
        <>
          <div className="rt-hunt-header">
            <h3 className="rt-case-title">{selectedCase ? `${selectedCase.case_number} — ${selectedCase.title}` : caseId}</h3>
            <div className="rt-stat-row">
              {volumeLabel && <span>{volumeLabel}</span>}
              {hostsLabel  && <span>{hostsLabel}</span>}
              <span>{lastMatchLabel}</span>
            </div>
          </div>

          {scopeInfo && (
            <div className="rt-toolbar">
              <Badge color={C.yara}>{t('threat_hunt.yara.scope_rules', { count: scopeInfo.rulesTotal, n: fmtNum(scopeInfo.rulesTotal, i18n.language) })}</Badge>
              {scopeStatus && <Badge color={scopeStatusColor}>{t(`threat_hunt.yara.status.${scopeStatus}`)}</Badge>}
              {skippedTotal > 0 && (
                <FilterChip active color="var(--fl-warn)" onClick={() => setScopeExplainOpen(true)}>
                  {t('threat_hunt.yara.scope_skipped', { count: skippedTotal, n: fmtNum(skippedTotal, i18n.language) })}
                </FilterChip>
              )}
              <span className="rt-name-muted">
                {t('threat_hunt.yara.scope_will_scan', {
                  count: scopeInfo.filesToScan,
                  n: fmtNum(scopeInfo.filesToScan, i18n.language),
                  total: fmtNum(scopeInfo.evidenceTotal, i18n.language),
                })}
              </span>
            </div>
          )}

          {scanning && progress && (
            <div>
              <div className="rt-stat-row">
                <span className="rt-progress-found">{t('threat_hunt.yara.progress_matches', { count: progress.matchesSoFar, n: fmtNum(progress.matchesSoFar, i18n.language) })}</span>
                {progress.filesFlaggedSoFar > 0 && (
                  <span>{t('threat_hunt.yara.files_flagged', { count: progress.filesFlaggedSoFar, n: fmtNum(progress.filesFlaggedSoFar, i18n.language) })}</span>
                )}
              </div>
              <ScanProgressBar progress={progress} color={C.yara} />
            </div>
          )}

          {derivedStats && (
            <div className="rt-stat-row">
              <span>
                {derivedStats.filesScanned != null
                  ? t('threat_hunt.yara.stat_files_scanned', { count: derivedStats.filesScanned, n: fmtNum(derivedStats.filesScanned, i18n.language) })
                  : t('threat_hunt.yara.stat_files_scanned_unknown')}
              </span>
              {derivedStats.filesSkipped > 0 && (
                <span>{t('threat_hunt.yara.stat_files_skipped', { count: derivedStats.filesSkipped, n: fmtNum(derivedStats.filesSkipped, i18n.language) })}</span>
              )}
              <span>{t('threat_hunt.yara.files_flagged', { count: derivedStats.filesFlagged, n: fmtNum(derivedStats.filesFlagged, i18n.language) })}</span>
              <span>{t('threat_hunt.sigma.rules_with_hits', { count: derivedStats.rulesMatched, n: fmtNum(derivedStats.rulesMatched, i18n.language) })}</span>
              <span>{t('threat_hunt.yara.stat_total_matches', { count: derivedStats.totalMatches, n: fmtNum(derivedStats.totalMatches, i18n.language) })}</span>
            </div>
          )}

          <div className="rt-table-wrap">
            <DataTable
              columns={columns}
              rows={results}
              rowKey={r => r.id}
              density="compact"
              emptyState={<EmptyState icon={Scan} title={t('threat_hunt.yara.no_scan_results')} />}
            />
          </div>
        </>
      )}

      <Modal
        open={scopeExplainOpen}
        title={t('threat_hunt.yara.scope_explain_title')}
        onClose={() => setScopeExplainOpen(false)}
        size="sm"
        accentColor={C.yara}
      >
        <Modal.Body>
          {scopeInfo?.skippedMemory > 0 && (
            <p>{t('threat_hunt.yara.scope_explain_memory', { count: scopeInfo.skippedMemory, n: fmtNum(scopeInfo.skippedMemory, i18n.language) })}</p>
          )}
          {scopeInfo?.skippedSize > 0 && (
            <p>{t('threat_hunt.yara.scope_explain_size', { count: scopeInfo.skippedSize, n: fmtNum(scopeInfo.skippedSize, i18n.language) })}</p>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setScopeExplainOpen(false)}>{t('common.close')}</Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
}

const SIGMA_TEMPLATE = `title: Suspicious PowerShell execution
description: Detects a PowerShell launch with encoding or bypass arguments
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\powershell.exe'
        CommandLine|contains:
            - '-enc '
            - '-EncodedCommand '
            - '-nop '
            - 'bypass'
    condition: selection
tags:
    - attack.execution
    - attack.t1059.001`;

function SigmaRulesTab() {
  const { t, i18n } = useTranslation();
  const [rules, setRules]         = useState([]);
  const [loading, setLoading]     = useState(true);
  const [loadError, setLoadError] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [showGithub, setShowGithub] = useState(false);
  const [editing, setEditing]     = useState(null);
  const [form, setForm]           = useState({ name: '', content: '', tags: '' });
  const [saving, setSaving]       = useState(false);
  const [error, setError]         = useState('');
  const [loadingRule, setLoadingRule] = useState(false);

  const [search, setSearch]       = useState('');
  const [filter, setFilter]       = useState('all');
  const [restoredScope, setRestoredScope] = useState(() => new Set());

  const [pendingDelete, setPendingDelete] = useState(null);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');
  const [deleting, setDeleting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true); setLoadError('');
    try { const r = await threatHuntingAPI.sigmaRules(); setRules(r.data.rules ?? []); }
    catch (e) { setLoadError(e.response?.data?.error || e.message || t('threat_hunt.errors.load_rules')); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const rows = useMemo(() => withTagsKey(rules), [rules]);
  const stats = useMemo(() => computeSigmaRuleStats(rows), [rows]);
  const segmentCounts = useMemo(() => ({
    all: rows.length,
    critical: rows.filter(r => r.level === 'critical').length,
    high: rows.filter(r => r.level === 'high').length,
    retired: rows.filter(isRetiredUpstream).length,
  }), [rows]);
  const visibleRows = useMemo(
    () => sortBySeverityDesc(filterSigmaRules(rows, { search, filter })),
    [rows, search, filter],
  );

  const constantKeys = useMemo(() => constantColumns(rows, SIGMA_SCOPE_CANDIDATE_COLUMNS), [rows]);
  const liftedKeys = useMemo(
    () => constantKeys.filter(key => !restoredScope.has(key)),
    [constantKeys, restoredScope],
  );

  function restoreScopeColumn(key) {
    setRestoredScope(prev => new Set(prev).add(key));
  }

  const scopeTokens = useMemo(() => {
    const first = rows[0];
    if (!first) return [];
    const tokens = [];

    if (liftedKeys.includes('tagsKey')) {
      tokens.push({
        key: 'tagsKey',
        label: t('threat_hunt.sigma.columns.tags'),
        value: (first.tags || []).join(', ') || '—',
        onRemove: () => restoreScopeColumn('tagsKey'),
      });
    }
    if (liftedKeys.includes('author_username')) {
      tokens.push({
        key: 'author_username',
        label: t('threat_hunt.sigma.columns.author'),
        value: first.author_username || '—',
        onRemove: () => restoreScopeColumn('author_username'),
      });
    }
    return tokens;
  }, [liftedKeys, rows, t]);

  function openCreate() {
    setEditing(null);
    setForm({ name: '', content: SIGMA_TEMPLATE, tags: '' });
    setError(''); setShowModal(true);
  }
  async function openEdit(r) {
    setEditing(r);
    setForm({ name: r.name, content: '', tags: (r.tags || []).join(', ') });
    setError(''); setLoadingRule(true); setShowModal(true);
    try {
      const res = await threatHuntingAPI.sigmaRule(r.id);
      setForm(f => ({ ...f, content: res.data.rule?.content || '' }));
    } catch (e) {
      setError(e.response?.data?.error || t('threat_hunt.errors.load_rule_content'));
    } finally {
      setLoadingRule(false);
    }
  }

  async function save() {
    if (!form.name.trim() || !form.content.trim()) { setError(t('threat_hunt.errors.name_content_required')); return; }
    setSaving(true); setError('');
    try {
      const tags = form.tags.split(',').map(t => t.trim()).filter(Boolean);
      const data = { name: form.name, content: form.content, tags };
      if (editing) await threatHuntingAPI.updateSigmaRule(editing.id, data);
      else         await threatHuntingAPI.createSigmaRule(data);
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
    try { await threatHuntingAPI.deleteSigmaRule(pendingDelete.id); setPendingDelete(null); load(); }
    catch (_e) { }
    finally { setDeleting(false); }
  }

  async function toggle(r) {
    try { await threatHuntingAPI.updateSigmaRule(r.id, { is_active: !r.is_active }); load(); }
    catch (_e) {}
  }

  function dimCls(r) {
    return isRuleDimmed(r) ? 'rt-name-muted' : undefined;
  }

  const columns = useMemo(() => {
    const cols = [
      {
        key: 'level', header: t('threat_hunt.sigma.columns.severity'), width: 140,
        render: r => (
          <span className="rt-inline-dot">
            <span className="rt-state-dot" style={{ background: sigmaLevelColor(r.level) }} aria-hidden="true" />
            <span className={dimCls(r)}>{sigmaLevelLabel(r.level, t)}</span>
          </span>
        ),
      },
      {
        key: 'name', header: t('threat_hunt.sigma.columns.rule'), mono: true,
        render: r => <span className={dimCls(r)}>{r.name}</span>,
      },
    ];

    if (restoredScope.has('tagsKey')) {
      cols.push({
        key: 'tagsDisplay', header: t('threat_hunt.sigma.columns.tags'),
        render: r => <span className={dimCls(r)}>{(r.tags || []).join(', ') || '—'}</span>,
      });
    }
    if (restoredScope.has('author_username')) {
      cols.push({
        key: 'author_username', header: t('threat_hunt.sigma.columns.author'),
        render: r => <span className={dimCls(r)}>{r.author_username || '—'}</span>,
      });
    }

    cols.push(
      {
        key: 'logsource_product', header: t('threat_hunt.sigma.columns.platform'), width: 130,
        render: r => <span className={dimCls(r)}>{r.logsource_product || '—'}</span>,
      },
      {
        key: 'mitre', header: t('threat_hunt.sigma.columns.technique'), width: 110, mono: true,
        render: r => (
          <span className={dimCls(r)} title={r.mitre_techniques?.join(', ')}>
            {r.mitre_techniques?.length ? r.mitre_techniques[0] : '—'}
          </span>
        ),
      },
      {
        key: 'upstream_status', header: t('threat_hunt.sigma.columns.status'), width: 130,
        render: r => (
          <span className={dimCls(r)}>
            {t(`threat_hunt.sigma.upstream_status.${r.upstream_status && SIGMA_UPSTREAM_STATUSES.has(r.upstream_status) ? r.upstream_status : 'unknown'}`)}
          </span>
        ),
      },
      {
        key: 'actions', width: 110,
        header: <span className="sr-only">{t('threat_hunt.sigma.columns.actions')}</span>,
        render: r => (
          <div className="dt-row-actions">
            <button
              type="button" className="rt-action-btn"
              aria-label={t(r.is_active ? 'threat_hunt.sigma.aria.disable_rule' : 'threat_hunt.sigma.aria.enable_rule', { name: r.name })}
              onClick={() => toggle(r)}
            >
              {r.is_active ? <ToggleRight size={14} /> : <ToggleLeft size={14} />}
            </button>
            <button
              type="button" className="rt-action-btn"
              aria-label={t('threat_hunt.sigma.aria.edit_rule', { name: r.name })}
              onClick={() => openEdit(r)}
            >
              <Pencil size={12} />
            </button>
            <button
              type="button" className="rt-action-btn rt-action-btn--danger"
              aria-label={t('threat_hunt.sigma.aria.delete_rule', { name: r.name })}
              onClick={() => requestDelete(r)}
            >
              <Trash2 size={12} />
            </button>
          </div>
        ),
      },
    );
    return cols;
  }, [restoredScope, t]);

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <p style={{ margin: 0, fontSize: 13, color: 'var(--fl-dim)' }}>
          {t('threat_hunt.sigma.rules_count', { count: rules.length })}
        </p>
        <div style={{ display: 'flex', gap: 8 }}>
          <Button variant="secondary" size="sm" icon={Github} onClick={() => setShowGithub(true)}>{t('threat_hunt.buttons.import_github')}</Button>
          <Button variant="primary" size="sm" icon={Plus} onClick={openCreate}>{t('threat_hunt.buttons.new_rule')}</Button>
        </div>
      </div>

      <GitHubImportModal open={showGithub} type="sigma" onClose={() => setShowGithub(false)} onImported={load} />

      {loading ? (
        <div style={{ textAlign: 'center', padding: 40 }}>
          <Spinner size={24} />
        </div>
      ) : loadError ? (
        <Alert variant="danger" message={loadError} />
      ) : rows.length === 0 ? (
        <EmptyState icon={FileCode2} title={t('threat_hunt.no_sigma')} />
      ) : (
        <>
          <div className="rt-stat-row">
            <span>{t('threat_hunt.sigma.stat_rules', { count: stats.total, n: fmtNum(stats.total, i18n.language) })}</span>
            <span>{t('threat_hunt.sigma.count_critical', { count: stats.critical, n: fmtNum(stats.critical, i18n.language) })}</span>
            <span>{t('threat_hunt.sigma.count_high', { count: stats.high, n: fmtNum(stats.high, i18n.language) })}</span>
            <span>{t('threat_hunt.sigma.stat_retired', { count: stats.retired, n: fmtNum(stats.retired, i18n.language) })}</span>
            <span>{t('threat_hunt.sigma.stat_platforms', { count: stats.platforms, n: fmtNum(stats.platforms, i18n.language) })}</span>
          </div>

          <ScopeBar tokens={scopeTokens} />

          <div className="rt-toolbar">
            <SearchInput
              value={search}
              onChange={setSearch}
              onClear={() => setSearch('')}
              placeholder={t('threat_hunt.sigma.search_placeholder')}
              style={{ minWidth: 240 }}
            />
            <div className="rt-toolbar-filters">
              <FilterChip active={filter === 'all'} onClick={() => setFilter('all')} count={segmentCounts.all}>
                {t('threat_hunt.sigma.filter_all')}
              </FilterChip>
              <FilterChip active={filter === 'critical'} color="var(--fl-danger)" onClick={() => setFilter('critical')} count={segmentCounts.critical}>
                {t('threat_hunt.sigma.filter_critical')}
              </FilterChip>
              <FilterChip active={filter === 'high'} color="var(--fl-warn)" onClick={() => setFilter('high')} count={segmentCounts.high}>
                {t('threat_hunt.sigma.filter_high')}
              </FilterChip>
              <FilterChip active={filter === 'retired'} onClick={() => setFilter('retired')} count={segmentCounts.retired}>
                {t('threat_hunt.sigma.filter_retired')}
              </FilterChip>
            </div>
          </div>

          {visibleRows.length === 0 ? (
            <EmptyState icon={Search} title={t('threat_hunt.sigma.no_search_results')} />
          ) : (
            <div className="rt-table-wrap">
              <DataTable columns={columns} rows={visibleRows} rowKey={r => r.id} density="compact" />
            </div>
          )}
        </>
      )}

      <Modal
        open={showModal}
        title={editing ? t('threat_hunt.sigma.edit_title') : t('threat_hunt.sigma.new_title')}
        onClose={() => setShowModal(false)}
        size="lg"
        accentColor={C.sigma}
      >
        <Modal.Body>
          <div style={{ marginBottom: 14 }}>
            <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>{t('threat_hunt.form.name')}</label>
            <input className="fl-input" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder={t('threat_hunt.sigma.name_ph')} />
          </div>
          <div style={{ marginBottom: 14 }}>
            <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>{t('threat_hunt.form.tags_csv')}</label>
            <input className="fl-input" value={form.tags} onChange={e => setForm(f => ({ ...f, tags: e.target.value }))} placeholder={t('threat_hunt.sigma.tags_ph')} />
          </div>
          <div style={{ marginBottom: 14 }}>
            <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>{t('threat_hunt.sigma.content')}</label>
            <textarea className="fl-input" value={form.content} disabled={loadingRule}
              placeholder={loadingRule ? t('common.loading') : undefined}
              onChange={e => setForm(f => ({ ...f, content: e.target.value }))} rows={16} style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', resize: 'vertical' }} />
          </div>
          {error && (
            <div style={{ background: 'color-mix(in srgb, var(--fl-danger) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 30%, transparent)', borderRadius: 6, padding: '8px 12px', marginBottom: 12, fontSize: 12, color: 'var(--fl-danger)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
              {error}
            </div>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowModal(false)}>{t('common.cancel')}</Button>
          <Button variant="primary" loading={saving} disabled={loadingRule} onClick={save}>{t('common.save')}</Button>
        </Modal.Footer>
      </Modal>

      <Modal
        open={!!pendingDelete}
        title={t('threat_hunt.sigma.delete_modal_title')}
        onClose={() => setPendingDelete(null)}
        size="sm"
        accentColor="var(--fl-danger)"
      >
        <Modal.Body>
          <p className="rt-delete-warning">{t('threat_hunt.sigma.delete_modal_warning')}</p>
          <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>
            {t('threat_hunt.sigma.delete_modal_type_prompt', { name: pendingDelete?.name })}
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

const ARTIFACT_COLORS = {
  evtx: 'var(--fl-accent)', hayabusa: 'var(--fl-danger)', mft: 'var(--fl-purple)', prefetch: 'var(--fl-ok)',
  lnk: 'var(--fl-warn)', registry: 'var(--fl-pink)', amcache: 'var(--fl-gold)',
};
function ac(t) { return ARTIFACT_COLORS[t] || 'var(--fl-dim)'; }

function SigmaHuntTab() {
  const { t, i18n } = useTranslation();
  const [cases, setCases]           = useState([]);
  const [sigmaRules, setSigmaRules] = useState([]);
  const [rulesError, setRulesError] = useState('');
  const [caseId, setCaseId]         = useState('');
  const [ruleId, setRuleId]         = useState('');
  const [pickerOpen, setPickerOpen] = useState(false);
  const [hunting, setHunting]       = useState(false);
  const [huntError, setHuntError]   = useState('');
  const [scanning, setScanning]     = useState(false);
  const [scopeInfo, setScopeInfo]   = useState(null);
  const [progress, setProgress]     = useState(null);
  const [scanStats, setScanStats]   = useState(null);
  const [scanError, setScanError]   = useState('');
  const [scopeExplainOpen, setScopeExplainOpen] = useState(false);
  const [history, setHistory]       = useState([]);
  const [historyError, setHistoryError] = useState('');
  const [headerMeta, setHeaderMeta] = useState(null);

  useEffect(() => {
    casesAPI.list().then(r => setCases(r.data.cases || [])).catch(() => {});
    threatHuntingAPI.sigmaRules()
      .then(r => setSigmaRules(r.data.rules || []))
      .catch(e => setRulesError(e.response?.data?.error || e.message || t('threat_hunt.errors.load_rules')));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    setScopeInfo(null); setProgress(null); setScanStats(null); setScanError(''); setHuntError('');
    if (!caseId) { setHistory([]); setHistoryError(''); setHeaderMeta(null); return; }
    threatHuntingAPI.sigmaHunts(caseId)
      .then(r => { setHistory(r.data.hunts || []); setHistoryError(''); })
      .catch(e => { setHistory([]); setHistoryError(e.response?.data?.error || e.message || t('threat_hunt.sigma.errors.load_history')); });
    timelineAPI.list(caseId, { limit: 1 })
      .then(r => setHeaderMeta({ total: r.data?.total ?? 0, hosts: r.data?.hosts_available || [] }))
      .catch(() => setHeaderMeta(null));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseId]);

  async function hunt(pickedRuleId) {
    if (!caseId || !pickedRuleId) return;
    setHunting(true); setHuntError('');
    try {
      await threatHuntingAPI.sigmaHunt(caseId, pickedRuleId);
      const h = await threatHuntingAPI.sigmaHunts(caseId);
      setHistory(h.data.hunts || []);
    } catch (e) {
      setHuntError(e.response?.data?.error || t('threat_hunt.errors.hunt_failed'));
    } finally { setHunting(false); }
  }

  async function scanAll() {
    if (!caseId) return;
    setScanning(true); setScopeInfo(null); setProgress(null); setScanStats(null); setScanError('');
    try {
      const token = localStorage.getItem('heimdall_token');
      const resp = await fetch(`/api/threat-hunting/sigma/scan-case/${caseId}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop();
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const ev = JSON.parse(line.slice(6));
            if (ev.type === 'start') {
              setScopeInfo({
                total: ev.total,
                rulesToRun: ev.rules_to_run ?? Math.max(0, ev.total - (ev.skipped_platform || 0)),
                skippedPlatform: ev.skipped_platform || 0,
                collectionPlatform: ev.collection_platform,
              });
            }
            if (ev.type === 'progress') {
              setProgress({
                current: ev.current, total: ev.total, name: ev.name,
                matchedSoFar: ev.matched_so_far ?? 0, criticalSoFar: ev.critical_so_far ?? 0,
              });
            }
            if (ev.type === 'done') {
              setProgress(null);
              const summary = ev.summary || [];
              setScanStats({
                rulesChecked: ev.rules_checked ?? summary.length,
                rulesMatched: ev.rules_matched ?? summary.filter(s => s.match_count > 0).length,
                totalMatches: ev.total_matches ?? summary.reduce((a, s) => a + (s.match_count || 0), 0),
                critical: summary.filter(s => s.match_count > 0 && s.level === 'critical').length,
                high:     summary.filter(s => s.match_count > 0 && s.level === 'high').length,
              });
              const h = await threatHuntingAPI.sigmaHunts(caseId);
              setHistory(h.data.hunts || []);
            }
            if (ev.type === 'error') setScanError(ev.error);
          } catch (_e) {}
        }
      }
    } catch (e) {
      setScanError(t('threat_hunt.errors.scan_failed'));
    } finally { setScanning(false); setProgress(null); }
  }

  const selectedCase = cases.find(c => c.id === caseId) || null;
  const selectedRule = sigmaRules.find(r => r.id === ruleId) || null;

  const ruleItems = useMemo(() => sigmaRules.map(r => ({
    id: r.id,
    label: r.name,
    sub: [r.level ? sigmaLevelLabel(r.level, t) : null, r.mitre_techniques?.[0] || null].filter(Boolean).join(' · ') || undefined,
  })), [sigmaRules, t]);

  function pickRule(item) { setRuleId(item.id); }

  const hostsLabel = useMemo(() => {
    if (!headerMeta) return null;
    const hosts = headerMeta.hosts || [];
    if (hosts.length === 0) return t('threat_hunt.sigma.meta_hosts_none');
    if (hosts.length === 1) return t('threat_hunt.sigma.meta_host', { host: hosts[0] });
    return t('threat_hunt.sigma.meta_hosts_count', { count: hosts.length, n: fmtNum(hosts.length, i18n.language) });
  }, [headerMeta, t, i18n.language]);

  const eventsLabel = useMemo(() => {
    if (!headerMeta) return null;
    return t('threat_hunt.sigma.meta_events', { count: headerMeta.total, n: fmtNum(headerMeta.total, i18n.language) });
  }, [headerMeta, t, i18n.language]);

  const lastHuntLabel = useMemo(() => {
    const last = history[0]?.hunted_at;
    return last
      ? t('threat_hunt.sigma.meta_last_hunt', { date: fmtDate(last, i18n.language) })
      : t('threat_hunt.sigma.meta_last_hunt_never');
  }, [history, t, i18n.language]);

  const sortedHistory = useMemo(() => {
    return [...history].sort((a, b) => {
      const r = sigmaLevelRank(b.level) - sigmaLevelRank(a.level);
      return r !== 0 ? r : (b.match_count || 0) - (a.match_count || 0);
    });
  }, [history]);

  const derivedStats = useMemo(() => {
    if (scanStats) return scanStats;
    if (!history.length) return null;
    return {
      rulesChecked: null,
      rulesMatched: history.filter(h => h.match_count > 0).length,
      totalMatches: history.reduce((a, h) => a + (h.match_count || 0), 0),
      critical: history.filter(h => h.match_count > 0 && h.level === 'critical').length,
      high:     history.filter(h => h.match_count > 0 && h.level === 'high').length,
    };
  }, [scanStats, history]);

  const skippedTotal  = scopeInfo ? Math.max(0, scopeInfo.total - scopeInfo.rulesToRun) : 0;
  const skippedStatus = scopeInfo ? Math.max(0, skippedTotal - scopeInfo.skippedPlatform) : 0;
  const scopeStatus      = scanError ? 'error' : scanning ? 'running' : scanStats ? 'done' : null;
  const scopeStatusColor = scopeStatus === 'error' ? 'var(--fl-danger)' : scopeStatus === 'running' ? C.sigma : 'var(--fl-ok)';

  const columns = useMemo(() => [
    {
      key: 'level', header: t('threat_hunt.sigma.columns.severity'), width: 140,
      render: r => {
        const dotStyle = { background: sigmaLevelColor(r.level) };
        return (
          <span className="rt-inline-dot">
            <span className="rt-state-dot" style={dotStyle} aria-hidden="true" />
            {sigmaLevelLabel(r.level, t)}
          </span>
        );
      },
    },
    { key: 'rule_name', header: t('threat_hunt.sigma.columns.rule'), mono: true },
    {
      key: 'mitre', header: t('threat_hunt.sigma.columns.technique'), width: 110, mono: true,
      render: r => (r.mitre_techniques?.length
        ? <span title={r.mitre_techniques.join(', ')}>{r.mitre_techniques[0]}</span>
        : '—'),
    },
    {
      key: 'match_count', header: t('threat_hunt.sigma.columns.matches'), width: 150, align: 'right', mono: true,
      render: r => {
        if (r.match_count == null) return '—';
        const matchFmt = fmtNum(r.match_count, i18n.language);
        if (r.match_count === 0) return <span className="rt-name-muted">{matchFmt}</span>;
        if (r.sample_size == null) {
          return <span>{matchFmt} <span className="rt-name-muted">{t('threat_hunt.sigma.sample_unknown')}</span></span>;
        }
        if (r.sample_size < r.match_count) {
          return (
            <span>
              {matchFmt}{' '}
              <span className="rt-name-muted">
                {t('threat_hunt.sigma.sample_of', { count: r.sample_size, n: fmtNum(r.sample_size, i18n.language) })}
              </span>
            </span>
          );
        }
        return <span>{matchFmt}</span>;
      },
    },
    {
      key: 'first_match', header: t('threat_hunt.sigma.columns.first_match'), width: 180, mono: true,
      render: r => (r.matched_events?.[0]?.timestamp ? fmtLocal(r.matched_events[0].timestamp) : '—'),
    },
  ], [t, i18n.language]);

  return (
    <div>
      <div className="rt-control-row">
        <div className="rt-field">
          <label className="fl-label">{t('threat_hunt.case_label')}</label>
          <select value={caseId} onChange={e => setCaseId(e.target.value)} className="fl-input">
            <option value="">{t('threat_hunt.select_case')}</option>
            {cases.map(c => <option key={c.id} value={c.id}>{c.case_number} — {c.title}</option>)}
          </select>
        </div>
        <Button variant="primary" size="sm" icon={scanning ? undefined : Scan} loading={scanning} disabled={!caseId} onClick={scanAll}>
          {t('threat_hunt.sigma.scan_all_rules')}
        </Button>
      </div>

      <div className="rt-control-row">
        <div className="rt-field">
          <label className="fl-label">{t('threat_hunt.sigma.rule_label')}</label>
          <Button
            variant="secondary" icon={Search} disabled={!caseId}
            title={t('threat_hunt.sigma.aria.open_picker')}
            onClick={() => setPickerOpen(true)}
          >
            {selectedRule ? selectedRule.name : t('threat_hunt.sigma.pick_rule_placeholder')}
          </Button>
        </div>
        <Button variant="secondary" size="sm" icon={hunting ? undefined : Search} loading={hunting} disabled={!caseId || !ruleId} onClick={() => hunt(ruleId)}>
          {t('threat_hunt.sigma.run_hunt')}
        </Button>
      </div>

      <CommandPalette
        open={pickerOpen}
        onClose={() => setPickerOpen(false)}
        items={ruleItems}
        onSelect={pickRule}
        placeholder={t('threat_hunt.sigma.picker_placeholder')}
        title={t('threat_hunt.sigma.picker_title')}
      />

      {rulesError   && <Alert variant="warn"   message={rulesError} />}
      {huntError    && <Alert variant="danger" message={huntError} />}
      {scanError    && <Alert variant="danger" message={scanError} />}
      {historyError && <Alert variant="warn"   message={historyError} />}

      {!caseId ? (
        <EmptyState icon={Shield} title={t('threat_hunt.sigma.pick_case_prompt')} />
      ) : (
        <>
          <div className="rt-hunt-header">
            <h3 className="rt-case-title">{selectedCase ? `${selectedCase.case_number} — ${selectedCase.title}` : caseId}</h3>
            <div className="rt-stat-row">
              {eventsLabel && <span>{eventsLabel}</span>}
              {hostsLabel  && <span>{hostsLabel}</span>}
              <span>{lastHuntLabel}</span>
            </div>
          </div>

          {scopeInfo && (
            <div className="rt-toolbar">
              <Badge color={C.sigma}>
                {scopeInfo.collectionPlatform?.length
                  ? t('threat_hunt.sigma.scope_platform_known', { platforms: scopeInfo.collectionPlatform.join(', ') })
                  : t('threat_hunt.sigma.scope_platform_unknown')}
              </Badge>
              {scopeStatus && <Badge color={scopeStatusColor}>{t(`threat_hunt.sigma.status.${scopeStatus}`)}</Badge>}
              {skippedTotal > 0 && (
                <FilterChip active color="var(--fl-warn)" onClick={() => setScopeExplainOpen(true)}>
                  {t('threat_hunt.sigma.scope_skipped', { count: skippedTotal, n: fmtNum(skippedTotal, i18n.language) })}
                </FilterChip>
              )}
              <span className="rt-name-muted">
                {t('threat_hunt.sigma.scope_will_run', {
                  count: scopeInfo.rulesToRun,
                  n: fmtNum(scopeInfo.rulesToRun, i18n.language),
                  total: fmtNum(scopeInfo.total, i18n.language),
                })}
              </span>
            </div>
          )}

          {scanning && progress && (
            <div>
              <div className="rt-stat-row">
                <span>{t('threat_hunt.sigma.progress_matched', { count: progress.matchedSoFar, n: fmtNum(progress.matchedSoFar, i18n.language) })}</span>
                {progress.criticalSoFar > 0 && (
                  <span className="sigma-progress-critical">
                    {t('threat_hunt.sigma.count_critical', { count: progress.criticalSoFar, n: fmtNum(progress.criticalSoFar, i18n.language) })}
                  </span>
                )}
              </div>
              <ScanProgressBar progress={progress} color={C.sigma} />
            </div>
          )}

          {derivedStats && (
            <div className="rt-stat-row">
              <span>
                {derivedStats.rulesChecked != null
                  ? t('threat_hunt.sigma.stat_rules_evaluated', { count: derivedStats.rulesChecked, n: fmtNum(derivedStats.rulesChecked, i18n.language) })
                  : t('threat_hunt.sigma.stat_rules_evaluated_unknown')}
              </span>
              <span>{t('threat_hunt.sigma.count_critical', { count: derivedStats.critical, n: fmtNum(derivedStats.critical, i18n.language) })}</span>
              <span>{t('threat_hunt.sigma.count_high', { count: derivedStats.high, n: fmtNum(derivedStats.high, i18n.language) })}</span>
              <span>{t('threat_hunt.sigma.rules_with_hits', { count: derivedStats.rulesMatched, n: fmtNum(derivedStats.rulesMatched, i18n.language) })}</span>
              <span>{t('threat_hunt.sigma.total_events', { count: derivedStats.totalMatches, n: fmtNum(derivedStats.totalMatches, i18n.language) })}</span>
            </div>
          )}

          <div className="rt-table-wrap">
            <DataTable
              columns={columns}
              rows={sortedHistory}
              rowKey={r => r.id}
              density="compact"
              rowHref={r => (r.match_count > 0 ? `/super-timeline?caseId=${caseId}&huntId=${r.id}` : null)}
              emptyState={<EmptyState icon={Search} title={t('threat_hunt.sigma.no_history')} />}
            />
          </div>
        </>
      )}

      <Modal
        open={scopeExplainOpen}
        title={t('threat_hunt.sigma.scope_explain_title')}
        onClose={() => setScopeExplainOpen(false)}
        size="sm"
        accentColor={C.sigma}
      >
        <Modal.Body>
          {scopeInfo?.skippedPlatform > 0 && (
            <p>{t('threat_hunt.sigma.scope_explain_platform', { count: scopeInfo.skippedPlatform, n: fmtNum(scopeInfo.skippedPlatform, i18n.language) })}</p>
          )}
          {skippedStatus > 0 && (
            <p>{t('threat_hunt.sigma.scope_explain_status', { count: skippedStatus, n: fmtNum(skippedStatus, i18n.language) })}</p>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setScopeExplainOpen(false)}>{t('common.close')}</Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
}

function getTabs(t) {
  return [
    { id: 'yara-scan',   label: t('threat_hunt.tabs.yara_scan'),   icon: Scan,      color: C.yara,  to: '/threat-hunt/yara-scan' },
    { id: 'sigma-rules', label: t('threat_hunt.tabs.sigma_rules'), icon: FileCode2, color: C.sigma, to: '/threat-hunt/sigma-rules' },
    { id: 'sigma-hunt',  label: t('threat_hunt.tabs.sigma_hunt'),  icon: Search,    color: C.sigma, to: '/threat-hunt/sigma-hunt' },
    { id: 'sysmon',      label: t('threat_hunt.tabs.sysmon'),      icon: Monitor, color: 'var(--fl-gold)', to: '/threat-hunt/sysmon' },
    { id: 'run-all',     label: t('threat_hunt.tabs.run_all'),     icon: Rocket,  color: 'var(--fl-accent)', to: '/threat-hunt/run-all' },
  ];
}

const SYSMON_CONFIGS = [
  {
    key: 'swiftonsecurity',
    name: 'SwiftOnSecurity · sysmon-config',
    author: '@SwiftOnSecurity',
    licenseKey: 'threat_hunt.sysmon.configs.swiftonsecurity.license',
    recommended: true,
    descKey: 'threat_hunt.sysmon.configs.swiftonsecurity.desc',
    repo: 'https://github.com/SwiftOnSecurity/sysmon-config',
    url: 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml',
  },
  {
    key: 'sysmon-modular',
    name: 'Olaf Hartong · sysmon-modular',
    author: '@olafhartong',
    license: 'GPL-3.0',
    recommended: true,
    descKey: 'threat_hunt.sysmon.configs.sysmon-modular.desc',
    repo: 'https://github.com/olafhartong/sysmon-modular',
    url: 'https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml',
  },
  {
    key: 'neo23x0',
    name: 'Florian Roth · Neo23x0/sysmon-config',
    author: '@Neo23x0 (Nextron)',
    licenseKey: 'threat_hunt.sysmon.configs.neo23x0.license',
    recommended: true,
    descKey: 'threat_hunt.sysmon.configs.neo23x0.desc',
    repo: 'https://github.com/Neo23x0/sysmon-config',
    url: 'https://raw.githubusercontent.com/Neo23x0/sysmon-config/master/sysmonconfig-export.xml',
  },
  {
    key: 'ion-storm',
    name: 'ion-storm · sysmon-config',
    author: '@ion-storm',
    license: 'CC BY 4.0',
    recommended: false,
    descKey: 'threat_hunt.sysmon.configs.ion-storm.desc',
    repo: 'https://github.com/ion-storm/sysmon-config',
    url: 'https://raw.githubusercontent.com/ion-storm/sysmon-config/master/sysmonconfig-export.xml',
  },
  {
    key: 'sysmon-modular-filedelete',
    name: 'Olaf Hartong · sysmon-modular (file-delete)',
    author: '@olafhartong',
    license: 'GPL-3.0',
    recommended: false,
    descKey: 'threat_hunt.sysmon.configs.sysmon-modular-filedelete.desc',
    repo: 'https://github.com/olafhartong/sysmon-modular',
    url: 'https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig-with-filedelete.xml',
  },
];

function SysmonTab() {
  const { t, i18n } = useTranslation();
  const [busy, setBusy] = useState(null);
  const [err, setErr]   = useState({});
  const [lib, setLib]   = useState({});

  const loadLib = useCallback(() => {
    threatHuntingAPI.sysmonLibrary()
      .then(r => setLib(Object.fromEntries((r.data?.configs || []).map(c => [c.config_key, c]))))
      .catch(() => {});
  }, []);
  useEffect(() => { loadLib(); }, [loadLib]);

  async function importCfg(cfg) {
    setBusy(cfg.key); setErr(e => ({ ...e, [cfg.key]: null }));
    try {
      await threatHuntingAPI.sysmonImport(cfg.key);
      loadLib();
    } catch (e) {
      setErr(er => ({ ...er, [cfg.key]: t('threat_hunt.sysmon.import_failed', { error: e.response?.data?.error || e.message }) }));
    } finally { setBusy(null); }
  }
  async function removeCfg(key) {
    try { await threatHuntingAPI.sysmonLibraryDelete(key); loadLib(); } catch { }
  }
  async function downloadStored(cfg) {
    try {
      const r = await threatHuntingAPI.sysmonLibraryContent(cfg.key);
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([r.data], { type: 'application/xml' }));
      a.download = `${cfg.key}-sysmonconfig.xml`;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(a.href);
    } catch { }
  }

  const importedEntries   = Object.values(lib);
  const importedCount     = importedEntries.length;
  const notImportedCount  = SYSMON_CONFIGS.length - importedCount;
  const storedBytes       = importedEntries.reduce((sum, c) => sum + (c.size || 0), 0);
  const lastImportedAt    = importedEntries.reduce((latest, c) => (
    c.imported_at && (!latest || new Date(c.imported_at) > new Date(latest)) ? c.imported_at : latest
  ), null);

  return (
    <div>
      <div className="rt-hunt-header">
        <h3 className="rt-case-title">{t('threat_hunt.sysmon.header_title')}</h3>
        <p className="rt-intro-text">
          {t('threat_hunt.sysmon.intro_before')}
          <code className="rt-inline-code">sysmon -c config.xml</code>
          {t('threat_hunt.sysmon.intro_after')}
        </p>
      </div>

      <div className="rt-stat-row">
        <span>{t('threat_hunt.sysmon.stat_total', { count: SYSMON_CONFIGS.length })}</span>
        <span>{t('threat_hunt.sysmon.stat_imported', { count: importedCount })}</span>
        <span>{t('threat_hunt.sysmon.stat_not_imported', { count: notImportedCount })}</span>
        <span>{t('threat_hunt.sysmon.stat_stored_size', { size: fmtSize(storedBytes) })}</span>
        <span>
          {lastImportedAt
            ? t('threat_hunt.sysmon.stat_last_import', { date: fmtDate(lastImportedAt, i18n.language) })
            : t('threat_hunt.sysmon.stat_last_import_none')}
        </span>
      </div>

      <div className="rt-catalog-list">
        {SYSMON_CONFIGS.map(cfg => {
          const imported = lib[cfg.key];
          return (
            <div key={cfg.key} className="fl-card rt-catalog-card">
              <div className="rt-catalog-card-main">
                <div className="rt-catalog-card-head">
                  <span className="rt-catalog-name">{cfg.name}</span>
                  {cfg.recommended && <Badge variant="accent">{t('threat_hunt.sysmon.recommended')}</Badge>}
                  {imported && <Badge variant="ok">{t('threat_hunt.sysmon.imported')}</Badge>}
                </div>
                <p className="rt-catalog-desc">{t(cfg.descKey)}</p>
                <div className="rt-catalog-meta">
                  <span className="rt-catalog-meta-item">{cfg.author}</span>
                  <span className="rt-catalog-meta-tag">{cfg.licenseKey ? t(cfg.licenseKey) : cfg.license}</span>
                  <a href={cfg.repo} target="_blank" rel="noreferrer" className="rt-catalog-repo-link">
                    <Github size={11} /> {t('threat_hunt.sysmon.repository')} <ExternalLink size={9} />
                  </a>
                  {imported && (
                    <span className="rt-catalog-meta-item">
                      {t('threat_hunt.sysmon.size_kb', { size: (imported.size / 1024).toFixed(0) })} · {fmtDate(imported.imported_at, i18n.language)}
                    </span>
                  )}
                </div>
                {err[cfg.key] && <p className="rt-catalog-error">{err[cfg.key]}</p>}
              </div>
              <div className="rt-catalog-actions">
                {imported && (
                  <>
                    <button
                      type="button" className="rt-action-btn"
                      aria-label={t('threat_hunt.sysmon.download_title')}
                      onClick={() => downloadStored(cfg)}
                    >
                      <Download size={12} />
                    </button>
                    <button
                      type="button" className="rt-action-btn rt-action-btn--danger"
                      aria-label={t('threat_hunt.sysmon.remove_title')}
                      onClick={() => removeCfg(cfg.key)}
                    >
                      <Trash2 size={12} />
                    </button>
                  </>
                )}
                <Button
                  variant={imported ? 'secondary' : 'primary'} size="sm"
                  icon={busy === cfg.key ? undefined : (imported ? RefreshCw : Download)}
                  loading={busy === cfg.key}
                  onClick={() => importCfg(cfg)}
                >
                  {busy === cfg.key ? t('threat_hunt.sysmon.importing') : (imported ? t('threat_hunt.sysmon.reimport') : t('common.import'))}
                </Button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function RunAllTab() {
  const { t, i18n } = useTranslation();
  const [cases, setCases]         = useState([]);
  const [caseId, setCaseId]       = useState('');
  const [job, setJob]             = useState(null);
  const [launching, setLaunching] = useState(false);
  const [scope, setScope]         = useState(null);
  const [scopeError, setScopeError] = useState('');
  const [headerMeta, setHeaderMeta] = useState(null);

  useEffect(() => { casesAPI.list().then(r => setCases(r.data.cases || [])).catch(() => {}); }, []);

  useEffect(() => {
    setScope(null); setScopeError('');
    if (!caseId) { setJob(null); setHeaderMeta(null); return; }
    threatHuntingAPI.runAllStatus(caseId).then(r => setJob(r.data)).catch(() => setJob(null));
    threatHuntingAPI.runAllScope(caseId).then(r => setScope(r.data))
      .catch(() => setScopeError(t('threat_hunt.run_all.scope_error')));
    timelineAPI.list(caseId, { limit: 1 })
      .then(r => setHeaderMeta({ hosts: r.data?.hosts_available || [] }))
      .catch(() => setHeaderMeta(null));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseId]);

  useEffect(() => {
    if (job?.status !== 'running' || !caseId) return;
    const iv = setInterval(() => { threatHuntingAPI.runAllStatus(caseId).then(r => setJob(r.data)).catch(() => {}); }, 3000);
    return () => clearInterval(iv);
  }, [job?.status, caseId]);

  async function launch() {
    if (!caseId) return;
    setLaunching(true);
    try { const r = await threatHuntingAPI.runAll(caseId); setJob(r.data); } catch { } finally { setLaunching(false); }
  }

  const selectedCase = cases.find(c => c.id === caseId) || null;
  const running  = job?.status === 'running';
  const steps    = job?.steps || [];
  const hasSteps = steps.length > 0;
  const doneCount  = steps.filter(s => s.status === 'done').length;
  const errorCount = steps.filter(s => s.status === 'error').length;
  const totalHits  = steps.reduce((s, st) => s + (st.count || 0), 0);
  const STATUS_C = { pending: 'var(--fl-subtle)', running: 'var(--fl-accent)', done: 'var(--fl-ok)', error: 'var(--fl-danger)' };

  const hostsLabel = useMemo(() => {
    if (!headerMeta) return null;
    const hosts = headerMeta.hosts || [];
    if (hosts.length === 0) return t('threat_hunt.sigma.meta_hosts_none');
    if (hosts.length === 1) return t('threat_hunt.sigma.meta_host', { host: hosts[0] });
    return t('threat_hunt.sigma.meta_hosts_count', { count: hosts.length, n: fmtNum(hosts.length, i18n.language) });
  }, [headerMeta, t, i18n.language]);

  const lastRunLabel = useMemo(() => {
    if (!job || job.status === 'idle') return t('threat_hunt.run_all.meta_last_run_never');
    const date = job.finished_at || job.started_at;
    return date
      ? t('threat_hunt.run_all.meta_last_run', { date: fmtDate(date, i18n.language) })
      : t('threat_hunt.run_all.meta_last_run_never');
  }, [job, t, i18n.language]);

  const columns = useMemo(() => [
    { key: 'label', header: t('threat_hunt.run_all.columns.engine'), mono: true },
    {
      key: 'status', header: t('threat_hunt.run_all.columns.status'), width: 130,
      render: st => (
        <span className="rt-inline-dot">
          {st.status === 'running'
            ? <Loader size={12} className="animate-spin" aria-hidden="true" />
            : <span className="rt-state-dot" style={{ background: STATUS_C[st.status] }} aria-hidden="true" />}
          {t(`threat_hunt.run_all.status.${st.status}`)}
        </span>
      ),
    },
    {
      key: 'count', header: t('threat_hunt.run_all.columns.findings'), width: 140, align: 'right', mono: true,
      render: st => {
        if (st.status === 'error') return <span className="rt-cell-danger" title={st.error || undefined}>{t('threat_hunt.run_all.status.error')}</span>;
        if (st.status === 'done')  return <span className={(st.count || 0) > 0 ? 'rt-cell-danger' : 'rt-name-muted'}>{fmtNum(st.count ?? 0, i18n.language)}</span>;
        return <span className="rt-name-muted">—</span>;
      },
    },
  ], [t, i18n.language]);

  return (
    <div>
      <p className="rt-intro-text">
        {t('threat_hunt.run_all.intro_before_engines')}<strong>{t('threat_hunt.run_all.all_engines')}</strong>{t('threat_hunt.run_all.intro_between')}<strong>{t('threat_hunt.run_all.background')}</strong>{t('threat_hunt.run_all.intro_after')}
      </p>

      <div className="rt-control-row">
        <div className="rt-field">
          <label className="fl-label">{t('threat_hunt.case_label')}</label>
          <select value={caseId} onChange={e => setCaseId(e.target.value)} className="fl-input">
            <option value="">{t('threat_hunt.select_case')}</option>
            {cases.map(c => <option key={c.id} value={c.id}>{c.case_number} — {c.title}</option>)}
          </select>
        </div>
        <Button variant="primary" size="sm" icon={running ? undefined : Rocket} loading={running || launching} disabled={!caseId || running || launching} onClick={launch}>
          {running ? t('threat_hunt.run_all.running') : t('threat_hunt.run_all.launch')}
        </Button>
      </div>

      {!caseId ? (
        <EmptyState icon={Rocket} title={t('threat_hunt.run_all.pick_case_prompt')} />
      ) : (
        <>
          <div className="rt-hunt-header">
            <h3 className="rt-case-title">{selectedCase ? `${selectedCase.case_number} — ${selectedCase.title}` : caseId}</h3>
            <div className="rt-stat-row">
              {hostsLabel && <span>{hostsLabel}</span>}
              <span>{lastRunLabel}</span>
            </div>
          </div>

          {scopeError && <Alert variant="warn" message={scopeError} />}

          {scope && (
            <div>
              <div className="rt-scope-line">
                {'YARA · '}
                <strong>{t('threat_hunt.run_all.scope_rules_count', { count: scope.yara.rules, n: fmtNum(scope.yara.rules, i18n.language) })}</strong>
                {` ${t('threat_hunt.run_all.scope_over')} `}
                <strong>{t('threat_hunt.run_all.scope_yara_files', { count: scope.yara.evidence_files, n: fmtNum(scope.yara.evidence_files, i18n.language) })}</strong>
              </div>
              <div className="rt-scope-line">
                {'Sigma · '}
                <strong>{t('threat_hunt.run_all.scope_rules_count', { count: scope.sigma.rules_to_run, n: fmtNum(scope.sigma.rules_to_run, i18n.language) })}</strong>
                {` ${t('threat_hunt.run_all.scope_over')} `}
                <strong>{t('threat_hunt.sigma.meta_events', { count: scope.sigma.total_events, n: fmtNum(scope.sigma.total_events, i18n.language) })}</strong>
                {scope.sigma.skipped > 0 && (
                  <>
                    {', '}
                    <strong>{t('threat_hunt.run_all.scope_sigma_skipped', { count: scope.sigma.skipped, n: fmtNum(scope.sigma.skipped, i18n.language) })}</strong>
                  </>
                )}
              </div>
            </div>
          )}

          {running && (
            <div className="rt-stat-row">
              <span>{t('threat_hunt.run_all.engines_done', { done: doneCount, total: steps.length })}</span>
              <span className="rt-progress-found">{t('threat_hunt.results_count', { count: totalHits })}</span>
            </div>
          )}

          {hasSteps && !running && (
            <div className="rt-stat-row">
              <span>{t('threat_hunt.run_all.done')}</span>
              <span>{t('threat_hunt.run_all.engines_done', { done: doneCount, total: steps.length })}</span>
              <span>{t('threat_hunt.results_count', { count: totalHits })}</span>
              {errorCount > 0 && (
                <span className="rt-cell-danger">{t('threat_hunt.run_all.stat_errors', { count: errorCount, n: fmtNum(errorCount, i18n.language) })}</span>
              )}
            </div>
          )}

          <div className="rt-table-wrap">
            <DataTable
              columns={columns}
              rows={steps}
              rowKey={st => st.key}
              density="compact"
              emptyState={<EmptyState icon={Rocket} title={t('threat_hunt.run_all.not_launched_yet')} />}
            />
          </div>
        </>
      )}
    </div>
  );
}

export default function ThreatHuntPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { tab } = useParams();
  const active = resolveThreatHuntTab(tab);
  const tabs = getTabs(t);

  useEffect(() => {
    if (active !== tab) navigate(`/threat-hunt/${active}`, { replace: true });
  }, [active, tab, navigate]);

  return (
    <div style={{ padding: '24px', maxWidth: 1100, margin: '0 auto' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ margin: '0 0 5px', fontSize: 22, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 10, fontFamily: 'var(--f-display, var(--f-ui))', letterSpacing: '-0.01em', color: 'var(--fl-text)' }}>
          <Shield size={20} color="var(--fl-accent)" strokeWidth={1.6} />
          {t('threat_hunt.title')}
        </h1>
        <p style={{ margin: 0, fontSize: 12.5, color: 'var(--fl-muted)', fontFamily: 'var(--f-ui, sans-serif)' }}>
          {t('threat_hunt.subtitle')}
        </p>
      </div>

      <div style={{ display: 'inline-flex', gap: 2, padding: 3, marginBottom: 22, borderRadius: 9, background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', maxWidth: '100%', overflowX: 'auto' }}>
        {tabs.map(it => {
          const on = active === it.id; const Ico = it.icon;
          return (
            <button key={it.id} onClick={() => navigate(it.to)}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 7, padding: '6px 13px', borderRadius: 7, border: 'none', cursor: 'pointer', whiteSpace: 'nowrap', flexShrink: 0,
                fontFamily: 'var(--f-ui, "Inter", sans-serif)', fontSize: 12.5, fontWeight: on ? 600 : 500,
                background: on ? 'var(--fl-card)' : 'transparent', color: on ? it.color : 'var(--fl-muted)',
                boxShadow: on ? 'var(--fl-shadow-sm)' : 'none', transition: 'color 0.12s, background 0.12s' }}
              onMouseEnter={e => { if (!on) e.currentTarget.style.color = 'var(--fl-dim)'; }}
              onMouseLeave={e => { if (!on) e.currentTarget.style.color = 'var(--fl-muted)'; }}>
              <Ico size={13} strokeWidth={1.6} style={{ flexShrink: 0 }} />{it.label}
            </button>
          );
        })}
      </div>

      {active === 'yara-scan'   && <YaraScanTab />}
      {active === 'sigma-rules' && <SigmaRulesTab />}
      {active === 'sigma-hunt'  && <SigmaHuntTab />}
      {active === 'sysmon'      && <SysmonTab />}
      {active === 'run-all'     && <RunAllTab />}
    </div>
  );
}
