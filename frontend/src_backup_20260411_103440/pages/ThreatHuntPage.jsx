
import { useState, useEffect, useCallback } from 'react';
import { useParams } from 'react-router-dom';
import {
  Shield, Scan, FileCode2, Search, Plus, Trash2, Pencil,
  ChevronDown, ChevronRight, CheckCircle2, AlertCircle,
  Tag, ToggleLeft, ToggleRight, Clock, Github, Download, X,
} from 'lucide-react';
import { casesAPI, evidenceAPI, threatHuntingAPI } from '../utils/api';
import { Button, Modal, TabGroup, Badge, Spinner } from '../components/ui';

const C = {
  yara:    '#4d82c0',
  sigma:   '#8b72d6',
  match:   '#da3633',
  clean:   '#3fb950',
  warn:    '#d97c20',
  surface: 'rgba(255,255,255,0.04)',
  border:  'rgba(255,255,255,0.08)',
};

function fmtDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}
function fmtSize(b) {
  if (!b) return '0 B';
  const k = 1024, s = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(Math.floor(Math.log(b) / Math.log(k)), s.length - 1);
  return `${(b / Math.pow(k, i)).toFixed(1)} ${s[i]}`;
}

function GitHubImportModal({ open, type, onClose, onImported }) {
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
        background: 'var(--fl-surface)', border: `1px solid ${accentColor}40`,
        borderRadius: 12, width: '100%', maxWidth: 560,
        display: 'flex', flexDirection: 'column',
        boxShadow: `0 0 40px ${accentColor}20`,
      }}>
        
        <div style={{ padding: '16px 20px', borderBottom: `1px solid ${C.border}`, display: 'flex', alignItems: 'center', gap: 10 }}>
          <Github size={18} style={{ color: accentColor }} />
          <span style={{ fontWeight: 700, fontSize: 15, color: 'var(--fl-text)' }}>
            Importer depuis GitHub — {type === 'sigma' ? 'règles Sigma' : 'règles YARA'}
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
                Sélectionnez un dépôt — toutes ses règles valides seront téléchargées et importées en une seule fois,
                sans passer par l'API GitHub.
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
                      <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--fl-text)', fontFamily: 'monospace' }}>
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
                Importer tout le dépôt ?
              </p>
              <p style={{ margin: '0 0 4px', fontFamily: 'monospace', fontSize: 13, color: accentColor }}>
                {selRepo.owner}/{selRepo.repo}
              </p>
              <p style={{ margin: '0 0 20px', fontSize: 12, color: 'var(--fl-dim)' }}>
                {selRepo.description}
              </p>
              <div style={{ padding: '10px 14px', background: 'rgba(255,255,255,0.04)', border: `1px solid ${C.border}`, borderRadius: 8, fontSize: 12, color: 'var(--fl-dim)', textAlign: 'left' }}>
                Le ZIP du dépôt sera téléchargé directement depuis github.com (sans API),
                extrait côté serveur, puis chaque règle sera validée syntaxiquement avant insertion.
                L'opération peut prendre <strong style={{ color: 'var(--fl-text)' }}>plusieurs minutes</strong> selon la taille du dépôt.
              </div>
            </div>
          )}

          {step === 'importing' && (
            <div style={{ textAlign: 'center', padding: '32px 0' }}>
              <Spinner size={32} />
              <p style={{ marginTop: 16, fontWeight: 600, fontSize: 14, color: 'var(--fl-text)' }}>
                Import en cours…
              </p>
              <p style={{ margin: '6px 0 0', fontSize: 12, color: 'var(--fl-dim)' }}>
                Téléchargement du ZIP · Extraction · Validation · Insertion en base
              </p>
              <p style={{ margin: '4px 0 0', fontSize: 12, color: 'var(--fl-muted)' }}>
                Ne fermez pas cette fenêtre
              </p>
            </div>
          )}

          {step === 'done' && result && (
            <div>
              <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
                <div style={{ flex: 1, textAlign: 'center', padding: '14px 10px', background: 'rgba(63,185,80,0.08)', border: '1px solid rgba(63,185,80,0.25)', borderRadius: 8 }}>
                  <div style={{ fontSize: 26, fontWeight: 700, color: '#3fb950' }}>{result.imported}</div>
                  <div style={{ fontSize: 12, color: 'var(--fl-dim)' }}>importées</div>
                </div>
                <div style={{ flex: 1, textAlign: 'center', padding: '14px 10px', background: 'rgba(217,124,32,0.08)', border: '1px solid rgba(217,124,32,0.25)', borderRadius: 8 }}>
                  <div style={{ fontSize: 26, fontWeight: 700, color: '#d97c20' }}>{result.skipped}</div>
                  <div style={{ fontSize: 12, color: 'var(--fl-dim)' }}>ignorées (invalides)</div>
                </div>
                {result.total > 0 && (
                  <div style={{ flex: 1, textAlign: 'center', padding: '14px 10px', background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8 }}>
                    <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--fl-dim)' }}>{result.total}</div>
                    <div style={{ fontSize: 12, color: 'var(--fl-dim)' }}>trouvées</div>
                  </div>
                )}
              </div>
              {result.errors?.length > 0 && (
                <div>
                  <p style={{ fontSize: 12, color: 'var(--fl-dim)', margin: '0 0 6px' }}>
                    Erreurs ({result.errors.length}) :
                  </p>
                  <div style={{ maxHeight: 140, overflowY: 'auto', background: C.surface, borderRadius: 6, padding: '8px 12px', border: `1px solid ${C.border}` }}>
                    {result.errors.map((e, i) => (
                      <div key={i} style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-danger)', marginBottom: 3 }}>
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
            <Button variant="secondary" onClick={onClose}>Fermer</Button>
          )}
          {step === 'confirm' && (
            <>
              <Button variant="secondary" onClick={() => setStep('repos')}>Retour</Button>
              <Button variant="primary" onClick={doImport} style={{ background: accentColor }}>
                Tout importer
              </Button>
            </>
          )}
          {step === 'importing' && (
            <Button variant="secondary" disabled>Import en cours…</Button>
          )}
          {step === 'done' && (
            <Button variant="primary" onClick={onClose}>Fermer</Button>
          )}
        </div>
      </div>
    </div>
  );
}

const YARA_TEMPLATE = `rule ExempleMalware {
    meta:
        description = "Détecte la signature MZ (exécutable PE)"
        author      = "Heimdall DFIR"
    strings:
        $mz = { 4D 5A }
        $pe = "This program cannot be run in DOS mode"
    condition:
        $mz at 0 and $pe
}`;

function YaraRulesTab() {
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
    catch (e) { setLoadError(e.response?.data?.error || e.message || 'Erreur chargement règles'); }
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
    if (!form.name.trim() || !form.content.trim()) { setError('Nom et contenu requis'); return; }
    setSaving(true); setError('');
    try {
      const tags = form.tags.split(',').map(t => t.trim()).filter(Boolean);
      const data = { name: form.name, description: form.description, content: form.content, tags };
      if (editing) await threatHuntingAPI.updateYaraRule(editing.id, data);
      else         await threatHuntingAPI.createYaraRule(data);
      setShowModal(false); load();
    } catch (e) {
      setError(e.response?.data?.error || 'Erreur lors de l\'enregistrement');
    } finally { setSaving(false); }
  }

  async function del(id) {
    if (!confirm('Supprimer cette règle YARA ?')) return;
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
          {rules.length} règle{rules.length !== 1 ? 's' : ''} — utilisées pour scanner les fichiers evidence
        </p>
        <div style={{ display: 'flex', gap: 8 }}>
          <Button variant="secondary" size="sm" icon={Github} onClick={() => setShowGithub(true)}>Importer GitHub</Button>
          <Button variant="primary" size="sm" icon={Plus} onClick={openCreate}>Nouvelle règle</Button>
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
          <p>Aucune règle YARA. Créez-en une pour commencer.</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {rules.map(r => (
            <div key={r.id} style={{
              background: C.surface, border: `1px solid ${C.border}`,
              borderRadius: 8, padding: '12px 16px',
              borderLeft: `3px solid ${r.is_active ? C.yara : 'transparent'}`,
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <span style={{ fontWeight: 700, color: r.is_active ? C.yara : 'var(--fl-dim)', fontSize: 14 }}>
                    {r.name}
                  </span>
                  {r.description && (
                    <p style={{ margin: '3px 0 0', fontSize: 12, color: 'var(--fl-dim)' }}>{r.description}</p>
                  )}
                  <div style={{ display: 'flex', gap: 6, marginTop: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                    {(r.tags || []).map(t => <Badge key={t} variant="accent">{t}</Badge>)}
                    <span style={{ fontSize: 11, color: 'var(--fl-muted)' }}>
                      par {r.author_username || '—'} · {fmtDate(r.created_at)}
                    </span>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                  <button onClick={() => toggle(r)} title={r.is_active ? 'Désactiver' : 'Activer'}
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
        title={editing ? 'Modifier la règle YARA' : 'Nouvelle règle YARA'}
        onClose={() => setShowModal(false)}
        size="lg"
        accentColor={C.yara}
      >
        <Modal.Body>
          <div style={{ marginBottom: 14 }}>
            <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>Nom</label>
            <input className="fl-input" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="ex: Détection PE malveillant" />
          </div>
          <div style={{ marginBottom: 14 }}>
            <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>Description (optionnel)</label>
            <input className="fl-input" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} placeholder="Description courte" />
          </div>
          <div style={{ marginBottom: 14 }}>
            <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>Tags (séparés par virgule)</label>
            <input className="fl-input" value={form.tags} onChange={e => setForm(f => ({ ...f, tags: e.target.value }))} placeholder="ex: malware, pe, ransomware" />
          </div>
          <div style={{ marginBottom: 14 }}>
            <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>Contenu YARA</label>
            <textarea className="fl-input" value={form.content} onChange={e => setForm(f => ({ ...f, content: e.target.value }))} rows={14} style={{ fontFamily: 'monospace', resize: 'vertical' }} />
          </div>
          {error && (
            <div style={{ background: 'color-mix(in srgb, var(--fl-danger) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 30%, transparent)', borderRadius: 6, padding: '8px 12px', marginBottom: 12, fontSize: 12, color: 'var(--fl-danger)', fontFamily: 'monospace' }}>
              {error}
            </div>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowModal(false)}>Annuler</Button>
          <Button variant="primary" loading={saving} onClick={save}>Enregistrer</Button>
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
        <span style={{ fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '80%' }}>
          {progress.current}/{progress.total} — {progress.name}
        </span>
        <span style={{ flexShrink: 0 }}>{pct}%</span>
      </div>
      <div style={{ height: 5, background: 'var(--fl-border, #30363d)', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: color || C.yara, borderRadius: 3, transition: 'width 0.15s ease' }} />
      </div>
    </div>
  );
}

function YaraScanTab() {
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
          <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>Cas</label>
          <select value={caseId} onChange={e => setCaseId(e.target.value)} className="fl-input">
            <option value="">— Sélectionner un cas —</option>
            {cases.map(c => <option key={c.id} value={c.id}>{c.case_number} — {c.title}</option>)}
          </select>
        </div>
        <Button variant="primary" size="sm" icon={scanning ? undefined : Scan} loading={scanning} disabled={!caseId} onClick={scanAll}>
          Scanner tous les fichiers
        </Button>
      </div>

      <ScanProgressBar progress={progress} color={C.yara} />

      {caseId && evidence.length > 0 && !scanning && (
        <div style={{ marginBottom: 16 }}>
          <p style={{ fontSize: 12, color: 'var(--fl-dim)', margin: '0 0 8px' }}>
            {evidence.length} fichier{evidence.length !== 1 ? 's' : ''} dans ce cas
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {evidence.map(e => (
              <span key={e.id} style={{ fontSize: 11, fontFamily: 'monospace', padding: '3px 8px', borderRadius: 4, background: C.surface, border: `1px solid ${C.border}`, color: 'var(--fl-dim)' }}>
                {e.name} <span style={{ opacity: 0.5 }}>({fmtSize(e.file_size)})</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {Object.keys(grouped).length === 0 && !scanning && caseId && (
        <div style={{ textAlign: 'center', padding: 40, color: 'var(--fl-dim)' }}>
          <Scan size={32} style={{ opacity: 0.3, marginBottom: 8 }} />
          <p style={{ margin: 0 }}>Aucun résultat — lancez un scan pour analyser les fichiers</p>
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
                <span style={{ fontFamily: 'monospace', fontSize: 13, color: 'var(--fl-text)', flex: 1, textAlign: 'left' }}>
                  {group.evidence_name}
                </span>
                {hasMatch
                  ? <Badge variant="danger"><AlertCircle size={11} /> {group.matches.length} règle{group.matches.length !== 1 ? 's' : ''} correspondante{group.matches.length !== 1 ? 's' : ''}</Badge>
                  : <Badge variant="ok"><CheckCircle2 size={11} /> Propre</Badge>}
              </button>
              {isOpen && hasMatch && (
                <div style={{ padding: '0 16px 14px', borderTop: `1px solid ${C.border}` }}>
                  {group.matches.map(m => (
                    <div key={m.id} style={{ marginTop: 10 }}>
                      <p style={{ margin: '0 0 4px', fontWeight: 700, color: 'var(--fl-danger)', fontSize: 13 }}>{m.rule_name}</p>
                      {(m.matched_strings || []).length > 0 ? (
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, fontFamily: 'monospace' }}>
                          <thead>
                            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                              {['Identifiant', 'Offset', 'Données'].map(h => (
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
                        <p style={{ margin: 0, fontSize: 11, color: 'var(--fl-dim)' }}>Match sans chaînes détaillées</p>
                      )}
                      <p style={{ margin: '4px 0 0', fontSize: 10, color: 'var(--fl-muted)' }}>Scanné le {fmtDate(m.scanned_at)}</p>
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

const SIGMA_TEMPLATE = `title: Exécution PowerShell suspecte
description: Détecte un lancement PowerShell avec arguments d'encodage ou de bypass
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
    catch (e) { setLoadError(e.response?.data?.error || e.message || 'Erreur chargement règles'); }
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
    if (!form.name.trim() || !form.content.trim()) { setError('Nom et contenu requis'); return; }
    setSaving(true); setError('');
    try {
      const tags = form.tags.split(',').map(t => t.trim()).filter(Boolean);
      const data = { name: form.name, content: form.content, tags };
      if (editing) await threatHuntingAPI.updateSigmaRule(editing.id, data);
      else         await threatHuntingAPI.createSigmaRule(data);
      setShowModal(false); load();
    } catch (e) {
      setError(e.response?.data?.error || 'Erreur lors de l\'enregistrement');
    } finally { setSaving(false); }
  }

  async function del(id) {
    if (!confirm('Supprimer cette règle Sigma ?')) return;
    try { await threatHuntingAPI.deleteSigmaRule(id); load(); } catch (_e) {}
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <p style={{ margin: 0, fontSize: 13, color: 'var(--fl-dim)' }}>
          {rules.length} règle{rules.length !== 1 ? 's' : ''} — utilisées pour la chasse dans la Super Timeline
        </p>
        <div style={{ display: 'flex', gap: 8 }}>
          <Button variant="secondary" size="sm" icon={Github} onClick={() => setShowGithub(true)}>Importer GitHub</Button>
          <Button variant="primary" size="sm" icon={Plus} onClick={openCreate}>Nouvelle règle</Button>
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
          <p>Aucune règle Sigma. Créez-en une pour commencer.</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {rules.map(r => (
            <div key={r.id} style={{
              background: C.surface, border: `1px solid ${C.border}`,
              borderRadius: 8, padding: '12px 16px',
              borderLeft: `3px solid ${r.is_active ? C.sigma : 'transparent'}`,
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <span style={{ fontWeight: 700, color: r.is_active ? C.sigma : 'var(--fl-dim)', fontSize: 14 }}>
                    {r.name}
                  </span>
                  <div style={{ display: 'flex', gap: 6, marginTop: 4, flexWrap: 'wrap', alignItems: 'center' }}>
                    {r.logsource_category && <Badge variant="purple">{r.logsource_category}</Badge>}
                    {r.logsource_product  && <Badge variant="dim">{r.logsource_product}</Badge>}
                    {(r.tags || []).map(t => <Badge key={t} variant="purple"><Tag size={9} /> {t}</Badge>)}
                    <span style={{ fontSize: 11, color: 'var(--fl-muted)' }}>
                      par {r.author_username || '—'} · {fmtDate(r.created_at)}
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
        title={editing ? 'Modifier la règle Sigma' : 'Nouvelle règle Sigma'}
        onClose={() => setShowModal(false)}
        size="lg"
        accentColor={C.sigma}
      >
        <Modal.Body>
          <div style={{ marginBottom: 14 }}>
            <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>Nom</label>
            <input className="fl-input" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="ex: Exécution PowerShell suspecte" />
          </div>
          <div style={{ marginBottom: 14 }}>
            <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>Tags (séparés par virgule)</label>
            <input className="fl-input" value={form.tags} onChange={e => setForm(f => ({ ...f, tags: e.target.value }))} placeholder="ex: attack.execution, t1059.001" />
          </div>
          <div style={{ marginBottom: 14 }}>
            <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>Contenu Sigma (YAML)</label>
            <textarea className="fl-input" value={form.content} onChange={e => setForm(f => ({ ...f, content: e.target.value }))} rows={16} style={{ fontFamily: 'monospace', resize: 'vertical' }} />
          </div>
          {error && (
            <div style={{ background: 'color-mix(in srgb, var(--fl-danger) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 30%, transparent)', borderRadius: 6, padding: '8px 12px', marginBottom: 12, fontSize: 12, color: 'var(--fl-danger)', fontFamily: 'monospace' }}>
              {error}
            </div>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowModal(false)}>Annuler</Button>
          <Button variant="primary" loading={saving} onClick={save}>Enregistrer</Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
}

const ARTIFACT_COLORS = {
  evtx: '#4d82c0', hayabusa: '#da3633', mft: '#8b72d6', prefetch: '#22c55e',
  lnk: '#d97c20', registry: '#c96898', amcache: '#c89d1d',
};
function ac(t) { return ARTIFACT_COLORS[t] || '#7d8590'; }

function SigmaHuntTab() {
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
      setHuntResult({ error: e.response?.data?.error || 'Erreur lors de la chasse' });
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
      setScanResult({ error: 'Erreur lors du scan' });
    } finally { setScanning(false); setProgress(null); }
  }

  return (
    <div>
      
      <div style={{ display: 'flex', gap: 12, marginBottom: 12, alignItems: 'flex-end', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 240 }}>
          <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>Cas</label>
          <select value={caseId} onChange={e => { setCaseId(e.target.value); setHuntResult(null); setScanResult(null); }} className="fl-input">
            <option value="">— Sélectionner un cas —</option>
            {cases.map(c => <option key={c.id} value={c.id}>{c.case_number} — {c.title}</option>)}
          </select>
        </div>
        <Button variant="secondary" size="sm" icon={scanning ? undefined : Scan} loading={scanning} disabled={!caseId} onClick={scanAll}>
          Scanner toutes les règles
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
                <span style={{ fontSize: 13 }}><strong>{scanResult.rules_checked}</strong> règles testées</span>
                <span style={{ fontSize: 13, color: scanResult.rules_matched > 0 ? 'var(--fl-danger)' : 'var(--fl-ok)' }}>
                  <strong>{scanResult.rules_matched}</strong> règle{scanResult.rules_matched !== 1 ? 's' : ''} avec hits
                </span>
                <span style={{ fontSize: 13 }}><strong>{scanResult.total_matches}</strong> événements total</span>
              </div>
              {scanResult.summary?.filter(s => s.match_count > 0).length > 0 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {scanResult.summary.filter(s => s.match_count > 0).map(s => (
                    <div key={s.rule_id} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                      <AlertCircle size={12} style={{ color: 'var(--fl-danger)', flexShrink: 0 }} />
                      <span style={{ flex: 1, color: 'var(--fl-text)' }}>{s.rule_name}</span>
                      <Badge variant="danger">{s.match_count} hits</Badge>
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
          <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>Règle Sigma</label>
          <select value={ruleId} onChange={e => { setRuleId(e.target.value); setHuntResult(null); }} className="fl-input">
            <option value="">— Sélectionner une règle —</option>
            {sigmaRules.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
          </select>
        </div>
        <Button variant="primary" size="sm" icon={hunting ? undefined : Search} loading={hunting} disabled={!caseId || !ruleId} onClick={hunt}>
          Lancer la chasse
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
                  {huntResult.match_count} événement{huntResult.match_count !== 1 ? 's' : ''} correspondant{huntResult.match_count !== 1 ? 's' : ''}
                </span>
                <span style={{ fontSize: 12, color: 'var(--fl-dim)' }}>— {huntResult.rule_name}</span>
              </div>
              {huntResult.events?.length > 0 && (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                    <thead>
                      <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                        {['Horodatage', 'Type', 'Source', 'Description'].map(h => (
                          <th key={h} style={{ textAlign: 'left', padding: '5px 8px', color: 'var(--fl-dim)', fontWeight: 600 }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {huntResult.events.map((e, i) => (
                        <tr key={i} style={{ borderBottom: `1px solid ${C.border}` }}>
                          <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: 'var(--fl-dim)', whiteSpace: 'nowrap' }}>
                            {e.timestamp ? new Date(e.timestamp).toLocaleString('fr-FR') : '—'}
                          </td>
                          <td style={{ padding: '4px 8px' }}>
                            {e.artifact_type && <Badge color={ac(e.artifact_type)}>{e.artifact_type}</Badge>}
                          </td>
                          <td style={{ padding: '4px 8px', color: 'var(--fl-dim)', fontFamily: 'monospace', fontSize: 11, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
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
                      Affichage de {huntResult.events.length} sur {huntResult.match_count} résultats
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
            <Clock size={13} /> Historique des chasses
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
                      ? <Badge variant="danger">{h.match_count} hits</Badge>
                      : <Badge variant="ok">0 hits</Badge>}
                    <span style={{ fontSize: 11, color: 'var(--fl-muted)' }}>{fmtDate(h.hunted_at)}</span>
                  </button>
                  {isOpen && (h.matched_events || []).length > 0 && (
                    <div style={{ padding: '0 14px 12px', borderTop: `1px solid ${C.border}` }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, marginTop: 8 }}>
                        <tbody>
                          {h.matched_events.map((e, i) => (
                            <tr key={i} style={{ borderBottom: `1px solid ${C.border}` }}>
                              <td style={{ padding: '3px 8px', fontFamily: 'monospace', color: 'var(--fl-dim)', whiteSpace: 'nowrap' }}>
                                {e.timestamp ? new Date(e.timestamp).toLocaleString('fr-FR') : '—'}
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

const TABS = [
  { id: 'yara-rules',  label: 'Règles YARA',  icon: Shield,    color: C.yara,  to: '/threat-hunt/yara-rules' },
  { id: 'yara-scan',   label: 'Scan YARA',     icon: Scan,      color: C.yara,  to: '/threat-hunt/yara-scan' },
  { id: 'sigma-rules', label: 'Règles Sigma',  icon: FileCode2, color: C.sigma, to: '/threat-hunt/sigma-rules' },
  { id: 'sigma-hunt',  label: 'Chasse Sigma',  icon: Search,    color: C.sigma, to: '/threat-hunt/sigma-hunt' },
];

export default function ThreatHuntPage() {
  const { tab = 'yara-rules' } = useParams();

  return (
    <div style={{ padding: '24px', maxWidth: 1100, margin: '0 auto' }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ margin: '0 0 6px', fontSize: 22, fontWeight: 800, display: 'flex', alignItems: 'center', gap: 10 }}>
          <Shield size={22} color={C.yara} />
          Threat Hunting
        </h1>
        <p style={{ margin: 0, fontSize: 13, color: 'var(--fl-dim)' }}>
          Détection proactive par règles YARA (binaires) et Sigma (timeline)
        </p>
      </div>

      <TabGroup tabs={TABS} />

      {tab === 'yara-rules'  && <YaraRulesTab />}
      {tab === 'yara-scan'   && <YaraScanTab />}
      {tab === 'sigma-rules' && <SigmaRulesTab />}
      {tab === 'sigma-hunt'  && <SigmaHuntTab />}
    </div>
  );
}
