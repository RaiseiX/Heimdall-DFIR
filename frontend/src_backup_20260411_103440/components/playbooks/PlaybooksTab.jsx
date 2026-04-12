import { useState, useEffect, useCallback } from 'react';
import { BookOpen, ChevronDown, ChevronRight, CheckSquare, Square, Plus, RefreshCw, FileText } from 'lucide-react';
import { playbooksAPI } from '../../utils/api';
import { Spinner } from '../ui';

const INCIDENT_LABELS = {
  ransomware:   'Ransomware',
  rdp:          'Intrusion RDP',
  phishing:     'Phishing',
  lateral:      'Mouvement latéral',
  insider:      'Menace interne',
  malware:      'Malware générique',
  generic:      'Générique',
};

const INCIDENT_COLORS = {
  ransomware: '#da3633',
  rdp:        '#d97c20',
  phishing:   '#c89d1d',
  lateral:    '#4d82c0',
  insider:    '#8b72d6',
  malware:    '#da3633',
  generic:    '#7d8590',
};

function ProgressBar({ done, total }) {
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;
  const color = pct === 100 ? '#3fb950' : pct >= 50 ? '#4d82c0' : '#7d8590';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 4, borderRadius: 2, background: '#1c2a3a', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 2, transition: 'width 0.3s' }} />
      </div>
      <span style={{ fontFamily: 'monospace', fontSize: 10, color, width: 42, textAlign: 'right', flexShrink: 0 }}>
        {done}/{total}
      </span>
    </div>
  );
}

function StepItem({ step, instanceId, caseId, onUpdated }) {
  const [saving, setSaving] = useState(false);
  const [showNote, setShowNote] = useState(false);
  const [noteVal, setNoteVal] = useState(step.note || '');

  const toggle = async () => {
    if (saving) return;
    const newCompleted = !step.completed;
    if (newCompleted && step.note_required && !noteVal.trim()) {
      setShowNote(true);
      return;
    }
    setSaving(true);
    try {
      await playbooksAPI.updateStep(caseId, instanceId, step.id, {
        completed: newCompleted,
        note: noteVal || null,
      });
      onUpdated();
    } catch (e) {
      alert('Erreur : ' + (e.response?.data?.error || e.message));
    } finally {
      setSaving(false);
    }
  };

  const submitWithNote = async () => {
    if (!noteVal.trim()) return;
    setSaving(true);
    try {
      await playbooksAPI.updateStep(caseId, instanceId, step.id, {
        completed: true,
        note: noteVal,
      });
      setShowNote(false);
      onUpdated();
    } catch (e) {
      alert('Erreur : ' + (e.response?.data?.error || e.message));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ borderBottom: '1px solid rgba(30,42,60,0.4)' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: '7px 0' }}>
        <button
          onClick={toggle}
          disabled={saving}
          style={{ background: 'none', border: 'none', cursor: saving ? 'not-allowed' : 'pointer',
            padding: '1px 0', flexShrink: 0, opacity: saving ? 0.5 : 1 }}
        >
          {saving ? (
            <Spinner size={14} />
          ) : step.completed ? (
            <CheckSquare size={15} style={{ color: '#3fb950' }} />
          ) : (
            <Square size={15} style={{ color: '#484f58' }} />
          )}
        </button>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{
            fontSize: 12, color: step.completed ? '#484f58' : '#e6edf3',
            textDecoration: step.completed ? 'line-through' : 'none',
          }}>
            <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#3d5070', marginRight: 6 }}>
              {step.step_order}.
            </span>
            {step.title}
            {step.note_required && !step.completed && (
              <span style={{ fontSize: 9, fontFamily: 'monospace', marginLeft: 6,
                color: '#d97c20', border: '1px solid #d97c2030', padding: '0 4px', borderRadius: 3 }}>
                note requise
              </span>
            )}
          </div>
          {step.description && (
            <div style={{ fontSize: 11, color: '#7d8590', marginTop: 2, lineHeight: 1.5 }}>
              {step.description}
            </div>
          )}
          {step.completed && step.note && (
            <div style={{ fontSize: 10, fontFamily: 'monospace', color: '#4d82c0', marginTop: 3,
              padding: '2px 6px', borderRadius: 3, background: '#4d82c010', border: '1px solid #4d82c020',
              display: 'inline-block' }}>
              Note: {step.note}
            </div>
          )}
          {step.completed && step.completed_by_name && (
            <div style={{ fontSize: 9, fontFamily: 'monospace', color: '#3d5070', marginTop: 2 }}>
              Complété par {step.completed_by_name} · {step.completed_at ? new Date(step.completed_at).toLocaleString('fr-FR') : ''}
            </div>
          )}
        </div>
      </div>

      {showNote && (
        <div style={{ padding: '6px 0 8px 23px', display: 'flex', gap: 6, alignItems: 'flex-end' }}>
          <textarea
            autoFocus
            value={noteVal}
            onChange={e => setNoteVal(e.target.value)}
            placeholder="Note obligatoire avant de cocher cette étape…"
            rows={2}
            style={{
              flex: 1, fontSize: 11, fontFamily: 'monospace', padding: '5px 8px',
              borderRadius: 5, border: '1px solid #30363d', background: '#0d1117',
              color: '#e6edf3', resize: 'vertical',
            }}
          />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <button
              onClick={submitWithNote}
              disabled={saving || !noteVal.trim()}
              style={{ fontSize: 10, fontFamily: 'monospace', padding: '3px 8px', borderRadius: 4,
                background: '#4d82c0', color: '#e6edf3', border: 'none', cursor: 'pointer',
                opacity: (!noteVal.trim() || saving) ? 0.5 : 1 }}
            >
              OK
            </button>
            <button
              onClick={() => setShowNote(false)}
              style={{ fontSize: 10, fontFamily: 'monospace', padding: '3px 8px', borderRadius: 4,
                background: 'none', color: '#7d8590', border: '1px solid #30363d', cursor: 'pointer' }}
            >
              ✕
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function PlaybookInstance({ instance, caseId, onRefresh }) {
  const [open, setOpen] = useState(false);
  const [steps, setSteps] = useState([]);
  const [loadingSteps, setLoadingSteps] = useState(false);
  const color = INCIDENT_COLORS[instance.incident_type] || '#7d8590';
  const isDone = !!instance.completed_at;

  const loadSteps = useCallback(async () => {
    setLoadingSteps(true);
    try {
      const res = await playbooksAPI.instanceSteps(caseId, instance.id);
      setSteps(Array.isArray(res.data) ? res.data : []);
    } catch (_e) {}
    finally { setLoadingSteps(false); }
  }, [caseId, instance.id]);

  const handleToggle = () => {
    if (!open) loadSteps();
    setOpen(o => !o);
  };

  const handleStepUpdated = () => {
    loadSteps();
    onRefresh();
  };

  return (
    <div style={{ borderRadius: 8, border: `1px solid ${isDone ? '#3fb95030' : '#30363d'}`,
      background: isDone ? '#0a1a12' : '#0d1117', overflow: 'hidden', marginBottom: 10 }}>
      <button
        onClick={handleToggle}
        style={{ display: 'flex', alignItems: 'center', gap: 10, width: '100%',
          padding: '10px 14px', background: 'none', border: 'none', cursor: 'pointer', textAlign: 'left' }}
      >
        <span style={{ color: '#484f58', flexShrink: 0 }}>
          {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: '#e6edf3' }}>{instance.title}</span>
            <span style={{ fontSize: 9, fontFamily: 'monospace', padding: '1px 5px', borderRadius: 3,
              background: `${color}18`, color, border: `1px solid ${color}35` }}>
              {INCIDENT_LABELS[instance.incident_type] || instance.incident_type}
            </span>
            {isDone && (
              <span style={{ fontSize: 9, fontFamily: 'monospace', padding: '1px 5px', borderRadius: 3,
                background: '#3fb95018', color: '#3fb950', border: '1px solid #3fb95030' }}>
                TERMINÉ
              </span>
            )}
          </div>
          <ProgressBar done={instance.done_steps} total={instance.total_steps} />
        </div>
        <div style={{ fontSize: 10, fontFamily: 'monospace', color: '#484f58', marginLeft: 8, flexShrink: 0 }}>
          Démarré par {instance.started_by_name || '—'}<br />
          <span style={{ color: '#3d5070' }}>{new Date(instance.started_at).toLocaleDateString('fr-FR')}</span>
        </div>
      </button>

      {open && (
        <div style={{ padding: '0 14px 12px 14px', borderTop: '1px solid #1c2a3a' }}>
          {loadingSteps ? (
            <div style={{ padding: '16px 0', display: 'flex', justifyContent: 'center' }}>
              <Spinner size={14} text="Chargement des étapes…" />
            </div>
          ) : steps.length === 0 ? (
            <div style={{ padding: '12px 0', fontSize: 11, color: '#484f58', fontFamily: 'monospace' }}>
              Aucune étape définie
            </div>
          ) : (
            <div style={{ paddingTop: 8 }}>
              {steps.map(step => (
                <StepItem
                  key={step.id}
                  step={step}
                  instanceId={instance.id}
                  caseId={caseId}
                  onUpdated={handleStepUpdated}
                />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function PlaybooksTab({ caseId }) {
  const [instances, setInstances] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showStartMenu, setShowStartMenu] = useState(false);
  const [starting, setStarting] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [instRes, tplRes] = await Promise.all([
        playbooksAPI.caseInstances(caseId),
        playbooksAPI.list(),
      ]);
      setInstances(Array.isArray(instRes.data) ? instRes.data : []);
      setTemplates(Array.isArray(tplRes.data) ? tplRes.data : []);
    } catch (_e) {}
    finally { setLoading(false); }
  }, [caseId]);

  useEffect(() => { load(); }, [load]);

  const startPlaybook = async (playbookId) => {
    setStarting(playbookId);
    setShowStartMenu(false);
    try {
      await playbooksAPI.start(caseId, playbookId);
      await load();
    } catch (e) {
      alert('Erreur : ' + (e.response?.data?.error || e.message));
    } finally {
      setStarting(null);
    }
  };

  const activeIds = new Set(instances.map(i => i.playbook_id));

  return (
    <div style={{ maxWidth: 860, margin: '0 auto' }}>
      
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <BookOpen size={14} style={{ color: '#4d82c0' }} />
          <span style={{ fontSize: 11, fontFamily: 'monospace', textTransform: 'uppercase',
            letterSpacing: '0.08em', color: '#7d8590' }}>
            Playbooks d'Investigation
          </span>
          {instances.length > 0 && (
            <span style={{ fontSize: 10, fontFamily: 'monospace', padding: '1px 6px', borderRadius: 4,
              background: '#4d82c018', color: '#4d82c0', border: '1px solid #4d82c030' }}>
              {instances.length} actif{instances.length > 1 ? 's' : ''}
            </span>
          )}
        </div>
        <div style={{ position: 'relative' }}>
          <button
            onClick={() => setShowStartMenu(v => !v)}
            disabled={!!starting}
            style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontFamily: 'monospace',
              padding: '4px 10px', borderRadius: 5, border: '1px solid #4d82c040',
              background: '#4d82c015', color: '#4d82c0', cursor: 'pointer',
              opacity: starting ? 0.5 : 1 }}
          >
            <Plus size={12} />
            Démarrer un playbook
            <ChevronDown size={10} />
          </button>

          {showStartMenu && (
            <div style={{
              position: 'absolute', right: 0, top: '100%', marginTop: 4,
              minWidth: 260, borderRadius: 6, border: '1px solid #30363d',
              background: '#161b22', boxShadow: '0 8px 24px rgba(0,0,0,0.5)',
              zIndex: 100, overflow: 'hidden',
            }}>
              {templates.length === 0 ? (
                <div style={{ padding: '12px 14px', fontSize: 11, color: '#484f58', fontFamily: 'monospace' }}>
                  Aucun playbook disponible
                </div>
              ) : (
                templates.map(tpl => {
                  const color = INCIDENT_COLORS[tpl.incident_type] || '#7d8590';
                  const already = activeIds.has(tpl.id);
                  return (
                    <button
                      key={tpl.id}
                      onClick={() => !already && startPlaybook(tpl.id)}
                      disabled={already || !!starting}
                      style={{ display: 'flex', alignItems: 'center', gap: 10, width: '100%',
                        padding: '8px 12px', background: 'none', border: 'none',
                        borderBottom: '1px solid #1c2a3a', cursor: already ? 'default' : 'pointer',
                        textAlign: 'left', opacity: already ? 0.45 : 1,
                      }}
                    >
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 12, color: '#e6edf3', marginBottom: 2 }}>
                          {tpl.title}
                          {already && <span style={{ fontSize: 9, fontFamily: 'monospace', marginLeft: 6, color: '#3fb950' }}>déjà actif</span>}
                        </div>
                        {tpl.description && (
                          <div style={{ fontSize: 10, color: '#7d8590', whiteSpace: 'nowrap',
                            overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {tpl.description}
                          </div>
                        )}
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 2, flexShrink: 0 }}>
                        <span style={{ fontSize: 9, fontFamily: 'monospace', padding: '1px 4px', borderRadius: 3,
                          background: `${color}18`, color, border: `1px solid ${color}35` }}>
                          {INCIDENT_LABELS[tpl.incident_type] || tpl.incident_type}
                        </span>
                        <span style={{ fontSize: 9, color: '#484f58', fontFamily: 'monospace' }}>
                          {tpl.step_count} étape{tpl.step_count !== 1 ? 's' : ''}
                        </span>
                      </div>
                    </button>
                  );
                })
              )}
            </div>
          )}
        </div>
      </div>

      
      {showStartMenu && (
        <div
          onClick={() => setShowStartMenu(false)}
          style={{ position: 'fixed', inset: 0, zIndex: 99 }}
        />
      )}

      
      {starting && (
        <div style={{ marginBottom: 12, padding: '8px 12px', borderRadius: 6,
          background: '#4d82c010', border: '1px solid #4d82c030',
          fontSize: 11, fontFamily: 'monospace', color: '#4d82c0',
          display: 'flex', alignItems: 'center', gap: 8 }}>
          <Spinner size={12} />
          Démarrage du playbook…
        </div>
      )}

      {loading ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: '40px 0' }}>
          <Spinner size={16} text="Chargement des playbooks…" />
        </div>
      ) : instances.length === 0 ? (
        <div style={{ padding: '40px 20px', textAlign: 'center',
          borderRadius: 10, border: '1px solid #30363d', background: '#0d1117' }}>
          <BookOpen size={32} style={{ color: '#1e2a3a', margin: '0 auto 12px' }} />
          <div style={{ fontSize: 13, color: '#7d8590', marginBottom: 4 }}>
            Aucun playbook actif sur ce cas
          </div>
          <div style={{ fontSize: 11, color: '#484f58' }}>
            Démarrez un playbook pour suivre les étapes d'investigation DFIR
          </div>
        </div>
      ) : (
        <div>
          {instances.map(inst => (
            <PlaybookInstance
              key={inst.id}
              instance={inst}
              caseId={caseId}
              onRefresh={load}
            />
          ))}
        </div>
      )}
    </div>
  );
}
