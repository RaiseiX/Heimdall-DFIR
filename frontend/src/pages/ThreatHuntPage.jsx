
import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  Shield, Scan, FileCode2, Search, Plus, Trash2, Pencil,
  ChevronDown, ChevronRight, CheckCircle2, AlertCircle,
  Tag, ToggleLeft, ToggleRight, Clock, Github, Download, X,
  Monitor, ExternalLink, Loader, RefreshCw, Play, Rocket,
} from 'lucide-react';
import { casesAPI, evidenceAPI, threatHuntingAPI } from '../utils/api';
import { Button, Modal, TabGroup, Badge, Spinner } from '../components/ui';
import { fmtLocal } from '../utils/formatters';

const C = {
  yara:    'var(--fl-accent)',
  sigma:   'var(--fl-purple)',
  match:   'var(--fl-danger)',
  clean:   'var(--fl-ok)',
  warn:    'var(--fl-warn)',
  surface: 'var(--fl-card)',
  border:  'var(--fl-border)',
};

function localeFor(lang) {
  return lang?.startsWith('en') ? 'en-US' : 'fr-FR';
}

function fmtDate(d, lang = 'fr') {
  if (!d) return '—';
  return new Date(d).toLocaleDateString(localeFor(lang), { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}
function fmtSize(b) {
  if (!b) return '0 B';
  const k = 1024, s = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(Math.floor(Math.log(b) / Math.log(k)), s.length - 1);
  return `${(b / Math.pow(k, i)).toFixed(1)} ${s[i]}`;
}

function GitHubImportModal({ open, type, onClose, onImported }) {
  const { t } = useTranslation();
  const accentColor = type === 'sigma' ? C.sigma : C.yara;

  const [step, setStep]       = useState('repos');
  const [repos, setRepos]     = useState([]);
  const [selRepo, setSelRepo] = useState(null);
  const [result, setResult]   = useState(null);

  useEffect(() => {
    if (!open) return;
    setStep('repos'); setSelRepo(null); setResult(null);
    threatHuntingAPI.githubRepos(type)
      .then(r => setRepos(r.data.repos ?? []))
      .catch(() => {});
  }, [open, type]);

  async function doImport() {
    setStep('importing');
    try {
      const r = await threatHuntingAPI.githubImportZip({
        owner: selRepo.owner, repo: selRepo.repo,
        branch: selRepo.branch, type,
      });
      setResult(r.data);
      onImported?.();
    } catch (e) {
      setResult({ total: 0, imported: 0, skipped: 0, errors: [e.response?.data?.error || e.message] });
    }
    setStep('done');
  }

  if (!open) return null;

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(0,0,0,0.65)', backdropFilter: 'blur(4px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20,
    }} onClick={e => { if (e.target === e.currentTarget && step !== 'importing') onClose(); }}>
      <div style={{
        background: 'var(--fl-panel)', border: `1px solid color-mix(in srgb, ${accentColor} 25%, transparent)`,
        borderRadius: 12, width: '100%', maxWidth: 560,
        display: 'flex', flexDirection: 'column',
        boxShadow: 'var(--fl-shadow-lg)',
      }}>
        
        <div style={{ padding: '16px 20px', borderBottom: `1px solid ${C.border}`, display: 'flex', alignItems: 'center', gap: 10 }}>
          <Github size={18} style={{ color: accentColor }} />
          <span style={{ fontWeight: 700, fontSize: 15, color: 'var(--fl-text)' }}>
            {t('threat_hunt.github.title', { type: type === 'sigma' ? t('threat_hunt.sigma_rules_lower') : t('threat_hunt.yara_rules_lower') })}
          </span>
          {step !== 'importing' && (
            <button onClick={onClose} style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-dim)', padding: 4 }}>
              <X size={16} />
            </button>
          )}
        </div>

        <div style={{ padding: '20px' }}>

          {step === 'repos' && (
            <div>
              <p style={{ margin: '0 0 14px', fontSize: 13, color: 'var(--fl-dim)' }}>
                {t('threat_hunt.github.select_repo_desc')}
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {repos.map(r => (
                  <button key={`${r.owner}/${r.repo}`}
                    onClick={() => { setSelRepo(r); setStep('confirm'); }}
                    style={{
                      background: C.surface, border: `1px solid ${C.border}`,
                      borderRadius: 8, padding: '14px 16px', cursor: 'pointer',
                      textAlign: 'left', transition: 'border-color 0.15s',
                    }}
                    onMouseEnter={e => e.currentTarget.style.borderColor = accentColor + '80'}
                    onMouseLeave={e => e.currentTarget.style.borderColor = C.border}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                      <Github size={14} style={{ color: accentColor }} />
                      <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--fl-text)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                        {r.owner}/{r.repo}
                      </span>
                    </div>
                    <p style={{ margin: 0, fontSize: 12, color: 'var(--fl-dim)' }}>{r.description}</p>
                  </button>
                ))}
              </div>
            </div>
          )}

          
          {step === 'confirm' && selRepo && (
            <div style={{ textAlign: 'center', padding: '8px 0' }}>
              <Download size={32} style={{ color: accentColor, marginBottom: 14 }} />
              <p style={{ margin: '0 0 6px', fontWeight: 700, fontSize: 15, color: 'var(--fl-text)' }}>
                {t('threat_hunt.github.confirm_title')}
              </p>
              <p style={{ margin: '0 0 4px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 13, color: accentColor }}>
                {selRepo.owner}/{selRepo.repo}
              </p>
              <p style={{ margin: '0 0 20px', fontSize: 12, color: 'var(--fl-dim)' }}>
                {selRepo.description}
              </p>
              <div style={{ padding: '10px 14px', background: 'var(--fl-card)', border: `1px solid ${C.border}`, borderRadius: 8, fontSize: 12, color: 'var(--fl-dim)', textAlign: 'left' }}>
                {t('threat_hunt.github.confirm_desc_before')}
                <strong style={{ color: 'var(--fl-text)' }}>{t('threat_hunt.github.confirm_desc_emphasis')}</strong>
                {t('threat_hunt.github.confirm_desc_after')}
              </div>
            </div>
          )}

          {step === 'importing' && (
            <div style={{ textAlign: 'center', padding: '32px 0' }}>
              <Spinner size={32} />
              <p style={{ marginTop: 16, fontWeight: 600, fontSize: 14, color: 'var(--fl-text)' }}>
                {t('threat_hunt.github.importing')}
              </p>
              <p style={{ margin: '6px 0 0', fontSize: 12, color: 'var(--fl-dim)' }}>
                {t('threat_hunt.github.importing_steps')}
              </p>
              <p style={{ margin: '4px 0 0', fontSize: 12, color: 'var(--fl-muted)' }}>
                {t('threat_hunt.github.keep_open')}
              </p>
            </div>
          )}

          {step === 'done' && result && (
            <div>
              <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
                <div style={{ flex: 1, textAlign: 'center', padding: '14px 10px', background: 'color-mix(in srgb, var(--fl-ok) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-ok) 22%, transparent)', borderRadius: 8 }}>
                  <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--fl-ok)' }}>{result.imported}</div>
                  <div style={{ fontSize: 12, color: 'var(--fl-dim)' }}>{t('threat_hunt.github.imported')}</div>
                </div>
                <div style={{ flex: 1, textAlign: 'center', padding: '14px 10px', background: 'rgba(217,124,32,0.08)', border: '1px solid rgba(217,124,32,0.25)', borderRadius: 8 }}>
                  <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--fl-warn)' }}>{result.skipped}</div>
                  <div style={{ fontSize: 12, color: 'var(--fl-dim)' }}>{t('threat_hunt.github.skipped_invalid')}</div>
                </div>
                {result.total > 0 && (
                  <div style={{ flex: 1, textAlign: 'center', padding: '14px 10px', background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8 }}>
                    <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--fl-dim)' }}>{result.total}</div>
                    <div style={{ fontSize: 12, color: 'var(--fl-dim)' }}>{t('threat_hunt.github.found')}</div>
                  </div>
                )}
              </div>
              {result.errors?.length > 0 && (
                <div>
                  <p style={{ fontSize: 12, color: 'var(--fl-dim)', margin: '0 0 6px' }}>
                    {t('threat_hunt.github.errors_count', { count: result.errors.length })}
                  </p>
                  <div style={{ maxHeight: 140, overflowY: 'auto', background: C.surface, borderRadius: 6, padding: '8px 12px', border: `1px solid ${C.border}` }}>
                    {result.errors.map((e, i) => (
                      <div key={i} style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-danger)', marginBottom: 3 }}>
                        {e}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        <div style={{ padding: '12px 20px', borderTop: `1px solid ${C.border}`, display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          {step === 'repos' && (
            <Button variant="secondary" onClick={onClose}>{t('common.close')}</Button>
          )}
          {step === 'confirm' && (
            <>
              <Button variant="secondary" onClick={() => setStep('repos')}>{t('common.back')}</Button>
              <Button variant="primary" onClick={doImport} style={{ background: accentColor }}>
                {t('threat_hunt.github.import_all')}
              </Button>
            </>
          )}
          {step === 'importing' && (
            <Button variant="secondary" disabled>{t('threat_hunt.github.importing')}</Button>
          )}
          {step === 'done' && (
            <Button variant="primary" onClick={onClose}>{t('common.close')}</Button>
          )}
        </div>
      </div>
    </div>
  );
}

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

function YaraRulesTab() {
  const { t, i18n } = useTranslation();
  const [rules, setRules]        = useState([]);
  const [loading, setLoading]    = useState(true);
  const [loadError, setLoadError] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [showGithub, setShowGithub] = useState(false);
  const [editing, setEditing]    = useState(null);
  const [form, setForm]          = useState({ name: '', description: '', content: '', tags: '' });
  const [saving, setSaving]      = useState(false);
  const [error, setError]        = useState('');

  const load = useCallback(async () => {
    setLoading(true); setLoadError('');
    try { const r = await threatHuntingAPI.yaraRules(); setRules(r.data.rules ?? []); }
    catch (e) { setLoadError(e.response?.data?.error || e.message || t('threat_hunt.errors.load_rules')); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

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

  async function del(id) {
    if (!confirm(t('threat_hunt.yara.confirm_delete'))) return;
    try { await threatHuntingAPI.deleteYaraRule(id); load(); } catch (_e) {}
  }

  async function toggle(r) {
    try { await threatHuntingAPI.updateYaraRule(r.id, { is_active: !r.is_active }); load(); }
    catch (_e) {}
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <p style={{ margin: 0, fontSize: 13, color: 'var(--fl-dim)' }}>
          {t('threat_hunt.yara.rules_count', { count: rules.length })}
        </p>
        <div style={{ display: 'flex', gap: 8 }}>
          <Button variant="secondary" size="sm" icon={Github} onClick={() => setShowGithub(true)}>{t('threat_hunt.buttons.import_github')}</Button>
          <Button variant="primary" size="sm" icon={Plus} onClick={openCreate}>{t('threat_hunt.buttons.new_rule')}</Button>
        </div>
      </div>

      <GitHubImportModal open={showGithub} type="yara" onClose={() => setShowGithub(false)} onImported={load} />

      {loading ? (
        <div style={{ textAlign: 'center', padding: 40 }}>
          <Spinner size={24} />
        </div>
      ) : loadError ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '12px 16px', background: 'rgba(218,54,51,0.08)', border: '1px solid rgba(218,54,51,0.25)', borderRadius: 8, color: 'var(--fl-danger)', fontSize: 13 }}>
          <AlertCircle size={16} />
          {loadError}
        </div>
      ) : rules.length === 0 ? (
        <div style={{ textAlign: 'center', padding: 60, color: 'var(--fl-dim)' }}>
          <Shield size={40} style={{ marginBottom: 12, opacity: 0.3 }} />
          <p>{t('threat_hunt.no_yara')}</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {rules.map(r => (
            <div key={r.id} style={{
              background: C.surface, border: `1px solid ${C.border}`,
              borderRadius: 10, padding: '12px 16px',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ width: 7, height: 7, borderRadius: 2, background: r.is_active ? C.yara : 'var(--fl-subtle)', flexShrink: 0 }} />
                    <span style={{ fontWeight: 600, color: 'var(--fl-text)', fontSize: 14 }}>{r.name}</span>
                  </span>
                  {r.description && (
                    <p style={{ margin: '3px 0 0', fontSize: 12, color: 'var(--fl-dim)' }}>{r.description}</p>
                  )}
                  <div style={{ display: 'flex', gap: 6, marginTop: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                    {(r.tags || []).map(t => <Badge key={t} variant="accent">{t}</Badge>)}
                    <span style={{ fontSize: 11, color: 'var(--fl-muted)' }}>
                      {t('threat_hunt.by_author', { author: r.author_username || '—', date: fmtDate(r.created_at, i18n.language) })}
                    </span>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                  <button onClick={() => toggle(r)} title={r.is_active ? t('threat_hunt.disable') : t('threat_hunt.enable')}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: r.is_active ? 'var(--fl-ok)' : 'var(--fl-dim)' }}>
                    {r.is_active ? <ToggleRight size={20} /> : <ToggleLeft size={20} />}
                  </button>
                  <Button variant="ghost" size="sm" onClick={() => openEdit(r)}><Pencil size={12} /></Button>
                  <Button variant="ghost" size="sm" onClick={() => del(r.id)}><Trash2 size={12} style={{ color: 'var(--fl-danger)' }} /></Button>
                </div>
              </div>
            </div>
          ))}
        </div>
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
    </div>
  );
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
  const [cases, setCases]       = useState([]);
  const [caseId, setCaseId]     = useState('');
  const [evidence, setEvidence] = useState([]);
  const [results, setResults]   = useState([]);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(null);
  const [expanded, setExpanded] = useState({});

  useEffect(() => {
    casesAPI.list().then(r => setCases(r.data.cases || [])).catch(() => {});
  }, []);

  useEffect(() => {
    if (!caseId) { setEvidence([]); setResults([]); return; }
    evidenceAPI.list(caseId).then(r => setEvidence(r.data.evidence || [])).catch(() => {});
    threatHuntingAPI.yaraResultsCase(caseId).then(r => setResults(r.data.results || [])).catch(() => {});
  }, [caseId]);

  async function scanAll() {
    if (!caseId) return;
    setScanning(true);
    setProgress(null);
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
            if (ev.type === 'start')    setProgress({ current: 0, total: ev.total, name: '' });
            if (ev.type === 'progress') setProgress({ current: ev.current, total: ev.total, name: ev.name });
            if (ev.type === 'done') {
              setProgress(null);
              const r = await threatHuntingAPI.yaraResultsCase(caseId);
              setResults(r.data.results || []);
            }
          } catch (_e) {}
        }
      }
    } catch (_e) {} finally { setScanning(false); setProgress(null); }
  }

  const grouped = results.reduce((acc, r) => {
    if (!acc[r.evidence_id]) acc[r.evidence_id] = { evidence_name: r.evidence_name, matches: [] };
    acc[r.evidence_id].matches.push(r);
    return acc;
  }, {});

  return (
    <div>
      <div style={{ display: 'flex', gap: 12, marginBottom: 16, alignItems: 'flex-end', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 240 }}>
          <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>{t('threat_hunt.case_label')}</label>
          <select value={caseId} onChange={e => setCaseId(e.target.value)} className="fl-input">
            <option value="">{t('threat_hunt.select_case')}</option>
            {cases.map(c => <option key={c.id} value={c.id}>{c.case_number} — {c.title}</option>)}
          </select>
        </div>
        <Button variant="primary" size="sm" icon={scanning ? undefined : Scan} loading={scanning} disabled={!caseId} onClick={scanAll}>
          {t('threat_hunt.yara.scan_all_files')}
        </Button>
      </div>

      <ScanProgressBar progress={progress} color={C.yara} />

      {caseId && evidence.length > 0 && !scanning && (
        <div style={{ marginBottom: 16 }}>
          <p style={{ fontSize: 12, color: 'var(--fl-dim)', margin: '0 0 8px' }}>
            {t('threat_hunt.yara.files_in_case', { count: evidence.length })}
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {evidence.map(e => (
              <span key={e.id} style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '3px 8px', borderRadius: 4, background: C.surface, border: `1px solid ${C.border}`, color: 'var(--fl-dim)' }}>
                {e.name} <span style={{ opacity: 0.5 }}>({fmtSize(e.file_size)})</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {Object.keys(grouped).length === 0 && !scanning && caseId && (
        <div style={{ textAlign: 'center', padding: 40, color: 'var(--fl-dim)' }}>
          <Scan size={32} style={{ opacity: 0.3, marginBottom: 8 }} />
          <p style={{ margin: 0 }}>{t('threat_hunt.yara.no_scan_results')}</p>
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {Object.entries(grouped).map(([evId, group]) => {
          const hasMatch = group.matches.length > 0;
          const isOpen   = expanded[evId];
          return (
            <div key={evId} style={{
              background: C.surface,
              border: `1px solid ${hasMatch ? C.match + '50' : C.border}`,
              borderRadius: 8, overflow: 'hidden',
            }}>
              <button onClick={() => setExpanded(x => ({ ...x, [evId]: !x[evId] }))}
                style={{ width: '100%', background: 'none', border: 'none', cursor: 'pointer', padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 10 }}>
                {isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 13, color: 'var(--fl-text)', flex: 1, textAlign: 'left' }}>
                  {group.evidence_name}
                </span>
                {hasMatch
                  ? <Badge variant="danger"><AlertCircle size={11} /> {t('threat_hunt.yara.matching_rules', { count: group.matches.length })}</Badge>
                  : <Badge variant="ok"><CheckCircle2 size={11} /> {t('threat_hunt.clean')}</Badge>}
              </button>
              {isOpen && hasMatch && (
                <div style={{ padding: '0 16px 14px', borderTop: `1px solid ${C.border}` }}>
                  {group.matches.map(m => (
                    <div key={m.id} style={{ marginTop: 10 }}>
                      <p style={{ margin: '0 0 4px', fontWeight: 700, color: 'var(--fl-danger)', fontSize: 13 }}>{m.rule_name}</p>
                      {(m.matched_strings || []).length > 0 ? (
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                          <thead>
                            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                              {[t('threat_hunt.table.identifier'), t('threat_hunt.table.offset'), t('threat_hunt.table.data')].map(h => (
                                <th key={h} style={{ textAlign: 'left', padding: '3px 8px', color: 'var(--fl-dim)', fontWeight: 600 }}>{h}</th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {m.matched_strings.map((s, i) => (
                              <tr key={i} style={{ borderBottom: `1px solid ${C.border}` }}>
                                <td style={{ padding: '3px 8px', color: C.yara }}>{s.identifier}</td>
                                <td style={{ padding: '3px 8px', color: 'var(--fl-dim)' }}>0x{s.offset.toString(16)}</td>
                                <td style={{ padding: '3px 8px', color: 'var(--fl-text)' }}>{s.data}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      ) : (
                        <p style={{ margin: 0, fontSize: 11, color: 'var(--fl-dim)' }}>{t('threat_hunt.yara.match_without_strings')}</p>
                      )}
                      <p style={{ margin: '4px 0 0', fontSize: 10, color: 'var(--fl-muted)' }}>{t('threat_hunt.scanned_at', { date: fmtDate(m.scanned_at, i18n.language) })}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
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

  const load = useCallback(async () => {
    setLoading(true); setLoadError('');
    try { const r = await threatHuntingAPI.sigmaRules(); setRules(r.data.rules ?? []); }
    catch (e) { setLoadError(e.response?.data?.error || e.message || t('threat_hunt.errors.load_rules')); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  function openCreate() {
    setEditing(null);
    setForm({ name: '', content: SIGMA_TEMPLATE, tags: '' });
    setError(''); setShowModal(true);
  }
  function openEdit(r) {
    setEditing(r);
    setForm({ name: r.name, content: r.content, tags: (r.tags || []).join(', ') });
    setError(''); setShowModal(true);
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

  async function del(id) {
    if (!confirm(t('threat_hunt.sigma.confirm_delete'))) return;
    try { await threatHuntingAPI.deleteSigmaRule(id); load(); } catch (_e) {}
  }

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
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '12px 16px', background: 'rgba(218,54,51,0.08)', border: '1px solid rgba(218,54,51,0.25)', borderRadius: 8, color: 'var(--fl-danger)', fontSize: 13 }}>
          <AlertCircle size={16} />
          {loadError}
        </div>
      ) : rules.length === 0 ? (
        <div style={{ textAlign: 'center', padding: 60, color: 'var(--fl-dim)' }}>
          <FileCode2 size={40} style={{ marginBottom: 12, opacity: 0.3 }} />
          <p>{t('threat_hunt.no_sigma')}</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {rules.map(r => (
            <div key={r.id} style={{
              background: C.surface, border: `1px solid ${C.border}`,
              borderRadius: 10, padding: '12px 16px',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ width: 7, height: 7, borderRadius: 2, background: r.is_active ? C.sigma : 'var(--fl-subtle)', flexShrink: 0 }} />
                    <span style={{ fontWeight: 600, color: 'var(--fl-text)', fontSize: 14 }}>{r.name}</span>
                  </span>
                  <div style={{ display: 'flex', gap: 6, marginTop: 4, flexWrap: 'wrap', alignItems: 'center' }}>
                    {r.logsource_category && <Badge variant="purple">{r.logsource_category}</Badge>}
                    {r.logsource_product  && <Badge variant="dim">{r.logsource_product}</Badge>}
                    {(r.tags || []).map(t => <Badge key={t} variant="purple"><Tag size={9} /> {t}</Badge>)}
                    <span style={{ fontSize: 11, color: 'var(--fl-muted)' }}>
                      {t('threat_hunt.by_author', { author: r.author_username || '—', date: fmtDate(r.created_at, i18n.language) })}
                    </span>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 6 }}>
                  <Button variant="ghost" size="sm" onClick={() => openEdit(r)}><Pencil size={12} /></Button>
                  <Button variant="ghost" size="sm" onClick={() => del(r.id)}><Trash2 size={12} style={{ color: 'var(--fl-danger)' }} /></Button>
                </div>
              </div>
            </div>
          ))}
        </div>
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
            <textarea className="fl-input" value={form.content} onChange={e => setForm(f => ({ ...f, content: e.target.value }))} rows={16} style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', resize: 'vertical' }} />
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
  const [caseId, setCaseId]         = useState('');
  const [ruleId, setRuleId]         = useState('');
  const [hunting, setHunting]       = useState(false);
  const [scanning, setScanning]     = useState(false);
  const [progress, setProgress]     = useState(null);
  const [huntResult, setHuntResult] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [history, setHistory]       = useState([]);
  const [expandedHistory, setExpandedHistory] = useState({});

  useEffect(() => {
    casesAPI.list().then(r => setCases(r.data.cases || [])).catch(() => {});
    threatHuntingAPI.sigmaRules().then(r => setSigmaRules(r.data.rules || [])).catch(() => {});
  }, []);

  useEffect(() => {
    if (!caseId) { setHistory([]); setScanResult(null); return; }
    threatHuntingAPI.sigmaHunts(caseId).then(r => setHistory(r.data.hunts || [])).catch(() => {});
  }, [caseId]);

  async function hunt() {
    if (!caseId || !ruleId) return;
    setHunting(true); setHuntResult(null);
    try {
      const r = await threatHuntingAPI.sigmaHunt(caseId, ruleId);
      setHuntResult(r.data);
      const h = await threatHuntingAPI.sigmaHunts(caseId);
      setHistory(h.data.hunts || []);
    } catch (e) {
      setHuntResult({ error: e.response?.data?.error || t('threat_hunt.errors.hunt_failed') });
    } finally { setHunting(false); }
  }

  async function scanAll() {
    if (!caseId) return;
    setScanning(true); setScanResult(null); setProgress(null);
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
            if (ev.type === 'start')    setProgress({ current: 0, total: ev.total, name: '' });
            if (ev.type === 'progress') setProgress({ current: ev.current, total: ev.total, name: ev.name });
            if (ev.type === 'done') {
              setProgress(null);
              setScanResult(ev);
              const h = await threatHuntingAPI.sigmaHunts(caseId);
              setHistory(h.data.hunts || []);
            }
            if (ev.type === 'error') setScanResult({ error: ev.error });
          } catch (_e) {}
        }
      }
    } catch (e) {
      setScanResult({ error: t('threat_hunt.errors.scan_failed') });
    } finally { setScanning(false); setProgress(null); }
  }

  return (
    <div>
      
      <div style={{ display: 'flex', gap: 12, marginBottom: 12, alignItems: 'flex-end', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 240 }}>
          <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>{t('threat_hunt.case_label')}</label>
          <select value={caseId} onChange={e => { setCaseId(e.target.value); setHuntResult(null); setScanResult(null); }} className="fl-input">
            <option value="">{t('threat_hunt.select_case')}</option>
            {cases.map(c => <option key={c.id} value={c.id}>{c.case_number} — {c.title}</option>)}
          </select>
        </div>
        <Button variant="secondary" size="sm" icon={scanning ? undefined : Scan} loading={scanning} disabled={!caseId} onClick={scanAll}>
          {t('threat_hunt.sigma.scan_all_rules')}
        </Button>
      </div>

      <ScanProgressBar progress={progress} color={C.sigma} />

      {scanResult && (
        <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: 14, marginBottom: 20 }}>
          {scanResult.error ? (
            <p style={{ margin: 0, color: 'var(--fl-danger)', fontSize: 13 }}>{scanResult.error}</p>
          ) : (
            <>
              <div style={{ display: 'flex', gap: 16, marginBottom: scanResult.rules_matched > 0 ? 12 : 0, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 13 }}><strong>{scanResult.rules_checked}</strong> {t('threat_hunt.sigma.rules_tested', { count: scanResult.rules_checked })}</span>
                <span style={{ fontSize: 13, color: scanResult.rules_matched > 0 ? 'var(--fl-danger)' : 'var(--fl-ok)' }}>
                  <strong>{scanResult.rules_matched}</strong> {t('threat_hunt.sigma.rules_with_hits', { count: scanResult.rules_matched })}
                </span>
                <span style={{ fontSize: 13 }}><strong>{scanResult.total_matches}</strong> {t('threat_hunt.sigma.total_events', { count: scanResult.total_matches })}</span>
              </div>
              {scanResult.summary?.filter(s => s.match_count > 0).length > 0 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {scanResult.summary.filter(s => s.match_count > 0).map(s => (
                    <div key={s.rule_id} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                      <AlertCircle size={12} style={{ color: 'var(--fl-danger)', flexShrink: 0 }} />
                      <span style={{ flex: 1, color: 'var(--fl-text)' }}>{s.rule_name}</span>
                      <Badge variant="danger">{t('threat_hunt.hits_count', { count: s.match_count })}</Badge>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}

      <div style={{ display: 'flex', gap: 12, marginBottom: 20, alignItems: 'flex-end', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 240 }}>
          <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>{t('threat_hunt.sigma.rule_label')}</label>
          <select value={ruleId} onChange={e => { setRuleId(e.target.value); setHuntResult(null); }} className="fl-input">
            <option value="">{t('threat_hunt.sigma.select_rule')}</option>
            {sigmaRules.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
          </select>
        </div>
        <Button variant="primary" size="sm" icon={hunting ? undefined : Search} loading={hunting} disabled={!caseId || !ruleId} onClick={hunt}>
          {t('threat_hunt.sigma.run_hunt')}
        </Button>
      </div>

      {huntResult && (
        <div style={{
          background: huntResult.error ? 'color-mix(in srgb, var(--fl-danger) 8%, transparent)' : huntResult.match_count > 0 ? 'color-mix(in srgb, var(--fl-danger) 8%, transparent)' : 'color-mix(in srgb, var(--fl-ok) 8%, transparent)',
          border: `1px solid ${huntResult.error ? 'color-mix(in srgb, var(--fl-danger) 40%, transparent)' : huntResult.match_count > 0 ? 'color-mix(in srgb, var(--fl-danger) 40%, transparent)' : 'color-mix(in srgb, var(--fl-ok) 40%, transparent)'}`,
          borderRadius: 8, padding: 16, marginBottom: 20,
        }}>
          {huntResult.error ? (
            <p style={{ margin: 0, color: 'var(--fl-danger)', fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
              <AlertCircle size={14} /> {huntResult.error}
            </p>
          ) : (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: huntResult.events?.length > 0 ? 14 : 0 }}>
                {huntResult.match_count > 0
                  ? <AlertCircle size={16} style={{ color: 'var(--fl-danger)' }} />
                  : <CheckCircle2 size={16} style={{ color: 'var(--fl-ok)' }} />}
                <span style={{ fontWeight: 700, fontSize: 15, color: huntResult.match_count > 0 ? 'var(--fl-danger)' : 'var(--fl-ok)' }}>
                  {t('threat_hunt.sigma.matching_events', { count: huntResult.match_count })}
                </span>
                <span style={{ fontSize: 12, color: 'var(--fl-dim)' }}>— {huntResult.rule_name}</span>
              </div>
              {huntResult.events?.length > 0 && (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                    <thead>
                      <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                        {[t('threat_hunt.table.timestamp'), t('threat_hunt.table.type'), t('threat_hunt.table.source'), t('threat_hunt.table.description')].map(h => (
                          <th key={h} style={{ textAlign: 'left', padding: '5px 8px', color: 'var(--fl-dim)', fontWeight: 600 }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {huntResult.events.map((e, i) => (
                        <tr key={i} style={{ borderBottom: `1px solid ${C.border}` }}>
                          <td style={{ padding: '4px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)', whiteSpace: 'nowrap' }}>
                            {e.timestamp ? fmtLocal(e.timestamp) : '—'}
                          </td>
                          <td style={{ padding: '4px 8px' }}>
                            {e.artifact_type && <Badge color={ac(e.artifact_type)}>{e.artifact_type}</Badge>}
                          </td>
                          <td style={{ padding: '4px 8px', color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {e.source || '—'}
                          </td>
                          <td style={{ padding: '4px 8px', color: 'var(--fl-text)', maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {e.description || '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {huntResult.match_count > huntResult.events.length && (
                    <p style={{ margin: '8px 0 0', fontSize: 11, color: 'var(--fl-muted)' }}>
                      {t('threat_hunt.sigma.showing_results', { shown: huntResult.events.length, total: huntResult.match_count })}
                    </p>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      )}

      {history.length > 0 && (
        <div>
          <h4 style={{ margin: '0 0 10px', fontSize: 13, fontWeight: 700, color: 'var(--fl-dim)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <Clock size={13} /> {t('threat_hunt.sigma.hunt_history')}
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {history.map(h => {
              const isOpen = expandedHistory[h.id];
              return (
                <div key={h.id} style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, overflow: 'hidden' }}>
                  <button onClick={() => setExpandedHistory(x => ({ ...x, [h.id]: !x[h.id] }))}
                    style={{ width: '100%', background: 'none', border: 'none', cursor: 'pointer', padding: '9px 14px', display: 'flex', alignItems: 'center', gap: 10 }}>
                    {isOpen ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                    <span style={{ flex: 1, textAlign: 'left', fontSize: 13, color: 'var(--fl-text)' }}>{h.rule_name}</span>
                    {h.match_count > 0
                      ? <Badge variant="danger">{t('threat_hunt.hits_count', { count: h.match_count })}</Badge>
                      : <Badge variant="ok">{t('threat_hunt.hits_count', { count: 0 })}</Badge>}
                    <span style={{ fontSize: 11, color: 'var(--fl-muted)' }}>{fmtDate(h.hunted_at, i18n.language)}</span>
                  </button>
                  {isOpen && (h.matched_events || []).length > 0 && (
                    <div style={{ padding: '0 14px 12px', borderTop: `1px solid ${C.border}` }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, marginTop: 8 }}>
                        <tbody>
                          {h.matched_events.map((e, i) => (
                            <tr key={i} style={{ borderBottom: `1px solid ${C.border}` }}>
                              <td style={{ padding: '3px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)', whiteSpace: 'nowrap' }}>
                                {e.timestamp ? fmtLocal(e.timestamp) : '—'}
</td>
                              <td style={{ padding: '3px 8px' }}>
                                {e.artifact_type && <Badge color={ac(e.artifact_type)}>{e.artifact_type}</Badge>}
                              </td>
                              <td style={{ padding: '3px 8px', color: 'var(--fl-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 350 }}>
                                {e.description || '—'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

function getTabs(t) {
  return [
    { id: 'yara-rules',  label: t('threat_hunt.tabs.yara_rules'),  icon: Shield,    color: C.yara,  to: '/threat-hunt/yara-rules' },
    { id: 'yara-scan',   label: t('threat_hunt.tabs.yara_scan'),   icon: Scan,      color: C.yara,  to: '/threat-hunt/yara-scan' },
    { id: 'sigma-rules', label: t('threat_hunt.tabs.sigma_rules'), icon: FileCode2, color: C.sigma, to: '/threat-hunt/sigma-rules' },
    { id: 'sigma-hunt',  label: t('threat_hunt.tabs.sigma_hunt'),  icon: Search,    color: C.sigma, to: '/threat-hunt/sigma-hunt' },
    { id: 'sysmon',      label: t('threat_hunt.tabs.sysmon'),      icon: Monitor, color: 'var(--fl-gold)', to: '/threat-hunt/sysmon' },
    { id: 'run-all',     label: t('threat_hunt.tabs.run_all'),     icon: Rocket,  color: 'var(--fl-accent)', to: '/threat-hunt/run-all' },
  ];
}

// ── Community Sysmon configurations (downloaded straight from their GitHub) ──
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
  const [lib, setLib]   = useState({});   // key -> { imported_at, size }

  const loadLib = useCallback(() => {
    threatHuntingAPI.sysmonLibrary()
      .then(r => setLib(Object.fromEntries((r.data?.configs || []).map(c => [c.config_key, c]))))
      .catch(() => {});
  }, []);
  useEffect(() => { loadLib(); }, [loadLib]);

  async function importCfg(cfg) {
    setBusy(cfg.key); setErr(e => ({ ...e, [cfg.key]: null }));
    try {
      await threatHuntingAPI.sysmonImport(cfg.key);   // server fetches + stores
      loadLib();
    } catch (e) {
      setErr(er => ({ ...er, [cfg.key]: t('threat_hunt.sysmon.import_failed', { error: e.response?.data?.error || e.message }) }));
    } finally { setBusy(null); }
  }
  async function removeCfg(key) {
    try { await threatHuntingAPI.sysmonLibraryDelete(key); loadLib(); } catch { /* ignore */ }
  }
  async function downloadStored(cfg) {
    try {
      const r = await threatHuntingAPI.sysmonLibraryContent(cfg.key);
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([r.data], { type: 'application/xml' }));
      a.download = `${cfg.key}-sysmonconfig.xml`;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(a.href);
    } catch { /* ignore */ }
  }

  return (
    <div>
      <p style={{ fontSize: 12.5, color: 'var(--fl-muted)', fontFamily: 'var(--f-ui, sans-serif)', margin: '0 0 16px', maxWidth: 760, lineHeight: 1.5 }}>
        {t('threat_hunt.sysmon.intro_before')}
        <code style={{ fontFamily: 'var(--f-mono, monospace)', color: 'var(--fl-dim)' }}>sysmon -c config.xml</code>
        {t('threat_hunt.sysmon.intro_after')}
      </p>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {SYSMON_CONFIGS.map(cfg => {
          const imported = lib[cfg.key];
          return (
          <div key={cfg.key} style={{ background: C.surface, border: '1px solid var(--fl-border)', borderRadius: 10, padding: '14px 16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
              <div style={{ minWidth: 0 }}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ width: 7, height: 7, borderRadius: 2, background: cfg.recommended ? 'var(--fl-accent)' : 'var(--fl-subtle)', flexShrink: 0 }} />
                  <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--fl-text)' }}>{cfg.name}</span>
                  {imported && <span style={{ fontSize: 9.5, fontFamily: 'var(--f-mono, monospace)', padding: '1px 7px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-ok) 10%, transparent)', color: 'var(--fl-ok)', border: '1px solid color-mix(in srgb, var(--fl-ok) 21%, transparent)' }}>{t('threat_hunt.sysmon.imported')}</span>}
                </span>
                <p style={{ margin: '5px 0 0', fontSize: 12, color: 'var(--fl-dim)', lineHeight: 1.5 }}>{t(cfg.descKey)}</p>
                <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                  <span style={{ fontSize: 10.5, fontFamily: 'var(--f-mono, monospace)', color: 'var(--fl-muted)' }}>{cfg.author}</span>
                  <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, monospace)', padding: '1px 7px', borderRadius: 4, background: 'var(--fl-card)', color: 'var(--fl-muted)', border: '1px solid var(--fl-border)' }}>{cfg.licenseKey ? t(cfg.licenseKey) : cfg.license}</span>
                  {cfg.recommended && <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, monospace)', padding: '1px 7px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-accent) 10%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 21%, transparent)' }}>{t('threat_hunt.sysmon.recommended')}</span>}
                  <a href={cfg.repo} target="_blank" rel="noreferrer" style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 11, fontFamily: 'var(--f-mono, monospace)', color: 'var(--fl-accent)', textDecoration: 'none' }}>
                    <Github size={11} /> {t('threat_hunt.sysmon.repository')} <ExternalLink size={9} />
                  </a>
                  {imported && <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, monospace)', color: 'var(--fl-subtle)' }}>· {t('threat_hunt.sysmon.size_kb', { size: (imported.size/1024).toFixed(0) })} · {new Date(imported.imported_at).toLocaleDateString(localeFor(i18n.language))}</span>}
                </div>
                {err[cfg.key] && <p style={{ margin: '8px 0 0', fontSize: 11, fontFamily: 'var(--f-mono, monospace)', color: 'var(--fl-danger)' }}>{err[cfg.key]}</p>}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                {imported && (
                  <>
                    <button onClick={() => downloadStored(cfg)} title={t('threat_hunt.sysmon.download_title')}
                      style={{ display: 'inline-flex', alignItems: 'center', padding: '7px 9px', borderRadius: 7, cursor: 'pointer', background: 'transparent', color: 'var(--fl-muted)', border: '1px solid var(--fl-border)' }}>
                      <Download size={12} />
                    </button>
                    <button onClick={() => removeCfg(cfg.key)} title={t('threat_hunt.sysmon.remove_title')}
                      style={{ display: 'inline-flex', alignItems: 'center', padding: '7px 9px', borderRadius: 7, cursor: 'pointer', background: 'transparent', color: 'var(--fl-subtle)', border: '1px solid var(--fl-border)' }}>
                      <Trash2 size={12} />
                    </button>
                  </>
                )}
                <button onClick={() => importCfg(cfg)} disabled={busy === cfg.key}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '7px 13px', borderRadius: 7, cursor: busy === cfg.key ? 'wait' : 'pointer',
                    background: imported ? 'var(--fl-card)' : 'var(--fl-accent)', color: imported ? 'var(--fl-dim)' : '#fff',
                    border: `1px solid ${imported ? 'var(--fl-border)' : 'var(--fl-accent)'}`, fontFamily: 'var(--f-mono, monospace)', fontSize: 11.5, fontWeight: 600 }}>
                  {busy === cfg.key ? <Loader size={12} style={{ animation: 'spin 1s linear infinite' }} /> : (imported ? <RefreshCw size={12} /> : <Download size={12} />)}
                  {busy === cfg.key ? t('threat_hunt.sysmon.importing') : (imported ? t('threat_hunt.sysmon.reimport') : t('common.import'))}
                </button>
              </div>
            </div>
          </div>
          );
        })}
      </div>
    </div>
  );
}

// ── "Run all" — launch every engine on a case in the background ──────────────
function RunAllTab() {
  const { t } = useTranslation();
  const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
  const [cases, setCases]       = useState([]);
  const [caseId, setCaseId]     = useState('');
  const [job, setJob]           = useState(null);
  const [launching, setLaunching] = useState(false);

  useEffect(() => { casesAPI.list().then(r => setCases(r.data.cases || [])).catch(() => {}); }, []);
  useEffect(() => {
    if (!caseId) { setJob(null); return; }
    threatHuntingAPI.runAllStatus(caseId).then(r => setJob(r.data)).catch(() => setJob(null));
  }, [caseId]);
  useEffect(() => {
    if (job?.status !== 'running' || !caseId) return;
    const iv = setInterval(() => { threatHuntingAPI.runAllStatus(caseId).then(r => setJob(r.data)).catch(() => {}); }, 3000);
    return () => clearInterval(iv);
  }, [job?.status, caseId]);

  async function launch() {
    if (!caseId) return;
    setLaunching(true);
    try { const r = await threatHuntingAPI.runAll(caseId); setJob(r.data); } catch { /* ignore */ } finally { setLaunching(false); }
  }

  const running = job?.status === 'running';
  const totalHits = (job?.steps || []).reduce((s, st) => s + (st.count || 0), 0);
  const STATUS_C = { pending: 'var(--fl-subtle)', running: 'var(--fl-accent)', done: 'var(--fl-ok)', error: 'var(--fl-danger)' };

  return (
    <div>
      <p style={{ fontSize: 12.5, color: 'var(--fl-muted)', fontFamily: 'var(--f-ui, sans-serif)', margin: '0 0 16px', maxWidth: 760, lineHeight: 1.5 }}>
        {t('threat_hunt.run_all.intro_before_engines')}<strong>{t('threat_hunt.run_all.all_engines')}</strong>{t('threat_hunt.run_all.intro_between')}<strong>{t('threat_hunt.run_all.background')}</strong>{t('threat_hunt.run_all.intro_after')}
      </p>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 18, flexWrap: 'wrap' }}>
        <select value={caseId} onChange={e => setCaseId(e.target.value)}
          style={{ minWidth: 280, padding: '8px 10px', borderRadius: 7, background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', color: 'var(--fl-text)', fontFamily: MONO, fontSize: 12, cursor: 'pointer' }}>
          <option value="">{t('threat_hunt.select_case')}</option>
          {cases.map(c => <option key={c.id} value={c.id}>{c.case_number} — {c.title}</option>)}
        </select>
        <button onClick={launch} disabled={!caseId || running || launching}
          style={{ display: 'inline-flex', alignItems: 'center', gap: 7, padding: '8px 16px', borderRadius: 7, fontFamily: MONO, fontSize: 12, fontWeight: 600,
            cursor: (!caseId || running) ? 'not-allowed' : 'pointer', background: (!caseId || running) ? 'var(--fl-card)' : 'var(--fl-accent)',
            color: (!caseId || running) ? 'var(--fl-muted)' : '#fff', border: `1px solid ${(!caseId || running) ? 'var(--fl-border)' : 'var(--fl-accent)'}` }}>
          {running ? <Loader size={13} style={{ animation: 'spin 1s linear infinite' }} /> : <Rocket size={13} />}
          {running ? t('threat_hunt.run_all.running') : t('threat_hunt.run_all.launch')}
        </button>
      </div>

      {job && job.steps?.length > 0 && (
        <div style={{ border: '1px solid var(--fl-border)', borderRadius: 10, overflow: 'hidden', background: 'var(--fl-card)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '11px 16px', borderBottom: '1px solid var(--fl-border2)' }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: running ? 'var(--fl-accent)' : 'var(--fl-ok)' }} className={running ? 'fl-pulse' : ''} />
            <span style={{ fontSize: 13, fontWeight: 600, fontFamily: 'var(--f-ui, sans-serif)', color: 'var(--fl-text)' }}>
              {running ? t('threat_hunt.run_all.running') : t('threat_hunt.run_all.done')}
            </span>
            <span style={{ flex: 1 }} />
            <span style={{ fontSize: 12, fontFamily: MONO, color: totalHits > 0 ? 'var(--fl-danger)' : 'var(--fl-muted)', fontFeatureSettings: '"tnum"' }}>{t('threat_hunt.results_count', { count: totalHits })}</span>
          </div>
          {job.steps.map(st => (
            <div key={st.key} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 16px', borderBottom: '1px solid var(--fl-border2)' }}>
              {st.status === 'running'
                ? <Loader size={12} style={{ animation: 'spin 1s linear infinite', color: 'var(--fl-accent)', flexShrink: 0 }} />
                : <span style={{ width: 8, height: 8, borderRadius: 2, background: STATUS_C[st.status], flexShrink: 0 }} />}
              <span style={{ fontSize: 12.5, fontFamily: 'var(--f-ui, sans-serif)', color: 'var(--fl-text)', flex: 1 }}>{st.label}</span>
              {st.error
                ? <span style={{ fontSize: 10.5, fontFamily: MONO, color: 'var(--fl-danger)', maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={st.error}>{st.error}</span>
                : st.status === 'done'
                  ? <span style={{ fontSize: 12, fontFamily: MONO, color: (st.count || 0) > 0 ? 'var(--fl-danger)' : 'var(--fl-muted)', fontFeatureSettings: '"tnum"' }}>{st.count ?? 0}</span>
                  : <span style={{ fontSize: 11, fontFamily: MONO, color: 'var(--fl-subtle)' }}>{st.status === 'running' ? '…' : t('threat_hunt.run_all.pending')}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function ThreatHuntPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { tab = 'yara-rules' } = useParams();
  const tabs = getTabs(t);

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

      {/* Segmented control nav (active tint = section colour: YARA accent / Sigma steel) */}
      <div style={{ display: 'inline-flex', gap: 2, padding: 3, marginBottom: 22, borderRadius: 9, background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', maxWidth: '100%', overflowX: 'auto' }}>
        {tabs.map(it => {
          const on = tab === it.id; const Ico = it.icon;
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

      {tab === 'yara-rules'  && <YaraRulesTab />}
      {tab === 'yara-scan'   && <YaraScanTab />}
      {tab === 'sigma-rules' && <SigmaRulesTab />}
      {tab === 'sigma-hunt'  && <SigmaHuntTab />}
      {tab === 'sysmon'      && <SysmonTab />}
      {tab === 'run-all'     && <RunAllTab />}
    </div>
  );
}
