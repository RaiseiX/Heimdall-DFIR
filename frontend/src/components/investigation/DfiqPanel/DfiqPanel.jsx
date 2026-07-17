import { useEffect, useState, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { HelpCircle, ChevronDown, ChevronRight, X, Plus, ListChecks } from 'lucide-react';
import { bookmarksAPI } from '../../../utils/api';
import { currentUser } from '../../../utils/auth';
import { useDfiqStore } from './useDfiqStore';
import DfiqCustomModal from './DfiqCustomModal';

const ELEVATED = new Set(['admin', 'team_lead']);
const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

const STATUS_COLOR = {
  todo: 'var(--fl-subtle)',
  answered: 'var(--fl-ok)',
  not_applicable: 'var(--fl-dim)',
};

export default function DfiqPanel({ caseId }) {
  const { t } = useTranslation();
  const {
    catalog, scenario, caseInstances, answers, loading,
    loadCatalog, loadScenario, loadCaseInstances, attach, detach,
    loadAnswers, setAnswer, addEvidence, removeEvidence,
  } = useDfiqStore();

  const [openInstance, setOpenInstance] = useState(null);
  const [findings, setFindings] = useState([]);
  const [showApproaches, setShowApproaches] = useState({});
  const [evidencePickerFor, setEvidencePickerFor] = useState(null);
  const [showCustomModal, setShowCustomModal] = useState(false);

  const isElevated = ELEVATED.has(currentUser().role);

  useEffect(() => { loadCatalog(); loadCaseInstances(caseId); setOpenInstance(null); }, [caseId, loadCatalog, loadCaseInstances]);

  useEffect(() => {
    if (!caseId) return;
    bookmarksAPI.list(caseId)
      .then(res => setFindings((res.data || []).filter(b => b.source !== 'mitre')))
      .catch(() => setFindings([]));
  }, [caseId]);

  useEffect(() => {
    if (openInstance) loadAnswers(caseId, openInstance);
  }, [openInstance, caseId, loadAnswers]);

  const instance = useMemo(() => caseInstances.find(ci => ci.instance_id === openInstance), [caseInstances, openInstance]);

  useEffect(() => {
    if (instance?.scenario_id) loadScenario(instance.scenario_id);
  }, [instance?.scenario_id, loadScenario]);

  const titleById = useMemo(() => new Map(findings.map(f => [f.id, f.title])), [findings]);

  const approachesByQuestion = useMemo(() => {
    const m = {};
    if (instance?.scenario_id && scenario?.scenario?.id === instance.scenario_id) {
      (scenario?.approaches || []).forEach(a => { (m[a.question_id] ||= []).push(a); });
    }
    return m;
  }, [scenario, instance]);

  const byFacet = useMemo(() => {
    const m = {};
    answers.forEach(a => { (m[a.facet_name || '—'] ||= []).push(a); });
    return m;
  }, [answers]);

  const refreshCatalog = useCallback(() => loadCatalog(), [loadCatalog]);

  const toggleInstance = (instanceId) => {
    setOpenInstance(o => (o === instanceId ? null : instanceId));
  };

  const handleDetach = async (instanceId) => {
    if (!window.confirm(t('dfiq.detach_confirm'))) return;
    await detach(caseId, instanceId);
    if (openInstance === instanceId) setOpenInstance(null);
  };

  const commitNote = (instanceId, questionId, status, value) => {
    setAnswer(caseId, instanceId, questionId, { status, note: value });
  };

  const btn = {
    display: 'flex', alignItems: 'center', gap: 4, background: 'none',
    border: '1px solid var(--fl-sep)', borderRadius: 4, cursor: 'pointer',
    padding: '3px 8px', color: 'var(--fl-subtle)', fontSize: 10, fontFamily: MONO,
  };

  const selectSt = {
    background: 'var(--fl-bg)', border: '1px solid var(--fl-sep)', borderRadius: 5,
    color: 'var(--fl-on-dark)', fontSize: 11, fontFamily: MONO, padding: '4px 7px', outline: 'none',
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <ListChecks size={13} style={{ color: 'var(--fl-accent)' }} />
          <span style={{ fontFamily: MONO, fontSize: 11, fontWeight: 700, color: '#8aa0bc', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            {t('dfiq.title')} ({caseInstances.length})
          </span>
        </div>
        {isElevated && (
          <button onClick={() => setShowCustomModal(true)} style={{ ...btn, color: 'var(--fl-accent)', borderColor: '#2a4a6a' }}>
            <Plus size={11} /> {t('dfiq.custom_new')}
          </button>
        )}
      </div>

      <select
        value=""
        onChange={e => { if (e.target.value) attach(caseId, e.target.value); }}
        style={selectSt}
      >
        <option value="">{t('dfiq.attach_placeholder')}</option>
        {catalog.length === 0 && <option value="" disabled>{t('dfiq.attach_empty')}</option>}
        {catalog
          .filter(s => !caseInstances.some(ci => ci.scenario_id === s.id))
          .map(s => (
            <option key={s.id} value={s.id}>
              {s.title}{s.is_custom ? ` (${t('dfiq.custom_badge')})` : ''} · {s.question_count}q
            </option>
          ))}
      </select>

      {loading && caseInstances.length === 0 && (
        <div style={{ textAlign: 'center', color: 'var(--fl-subtle)', fontFamily: MONO, fontSize: 11, padding: 16 }}>
          {t('dfiq.loading')}
        </div>
      )}

      {!loading && caseInstances.length === 0 && (
        <div style={{ textAlign: 'center', color: 'var(--fl-muted)', fontFamily: MONO, fontSize: 11, padding: '24px 16px', border: '1px dashed var(--fl-sep)', borderRadius: 8 }}>
          {t('dfiq.empty')}
        </div>
      )}

      {caseInstances.map(ci => {
        const open = openInstance === ci.instance_id;
        const pct = ci.total > 0 ? Math.round((ci.answered / ci.total) * 100) : 0;
        return (
          <div key={ci.instance_id} style={{
            borderRadius: 8, border: '1px solid var(--fl-sep)', background: 'var(--fl-bg)',
            overflow: 'hidden',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 12px' }}>
              <button
                onClick={() => toggleInstance(ci.instance_id)}
                style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'none', border: 'none', cursor: 'pointer', flex: 1, textAlign: 'left', padding: 0 }}
              >
                {open ? <ChevronDown size={13} style={{ color: 'var(--fl-subtle)' }} /> : <ChevronRight size={13} style={{ color: 'var(--fl-subtle)' }} />}
                <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--fl-on-dark)' }}>{ci.title}</span>
                <span style={{ fontSize: 10, fontFamily: MONO, color: 'var(--fl-muted)' }}>{ci.answered}/{ci.total}</span>
              </button>
              <div style={{ width: 60, height: 5, borderRadius: 3, background: 'var(--fl-sep)', overflow: 'hidden', flexShrink: 0 }}>
                <div style={{ width: `${pct}%`, height: '100%', background: pct === 100 ? 'var(--fl-ok)' : 'var(--fl-accent)' }} />
              </div>
              <button onClick={() => handleDetach(ci.instance_id)} title={t('dfiq.detach')} style={{ background: 'none', border: '1px solid color-mix(in srgb, var(--fl-danger) 19%, transparent)', borderRadius: 4, cursor: 'pointer', color: 'var(--fl-danger)', padding: '4px 7px', flexShrink: 0 }}>
                <X size={11} />
              </button>
            </div>

            {open && (
              <div style={{ borderTop: '1px solid var(--fl-sep)', padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 14 }}>
                {Object.entries(byFacet).map(([facet, qs]) => (
                  <div key={facet} style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    <span style={{ fontSize: 10, fontWeight: 700, fontFamily: MONO, color: 'var(--fl-gold)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      {facet}
                    </span>
                    {qs.map(a => {
                      const approaches = approachesByQuestion[a.question_id] || [];
                      const approachesOpen = !!showApproaches[a.question_id];
                      const pickerOpen = evidencePickerFor === a.question_id;
                      const evidence = a.evidence || [];
                      return (
                        <div key={a.question_id} style={{
                          borderRadius: 7, border: '1px solid var(--fl-sep)', padding: '9px 10px',
                          display: 'flex', flexDirection: 'column', gap: 7,
                        }}>
                          <div style={{ fontSize: 11, color: 'var(--fl-on-dark)', lineHeight: 1.4 }}>{a.text}</div>

                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                            <select
                              value={a.status}
                              onChange={e => commitNote(ci.instance_id, a.question_id, e.target.value, a.note)}
                              style={{ ...selectSt, color: STATUS_COLOR[a.status] || 'var(--fl-on-dark)', fontSize: 10, padding: '3px 6px' }}
                            >
                              <option value="todo">{t('dfiq.status_todo')}</option>
                              <option value="answered">{t('dfiq.status_answered')}</option>
                              <option value="not_applicable">{t('dfiq.status_not_applicable')}</option>
                            </select>

                            {approaches.length > 0 && (
                              <button
                                onClick={() => setShowApproaches(prev => ({ ...prev, [a.question_id]: !prev[a.question_id] }))}
                                style={{ ...btn, padding: '2px 7px' }}
                              >
                                <HelpCircle size={10} /> {t('dfiq.approaches_toggle')} ({approaches.length})
                              </button>
                            )}
                          </div>

                          {approachesOpen && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, borderLeft: '2px solid var(--fl-sep)', paddingLeft: 8 }}>
                              {approaches.length === 0 && (
                                <span style={{ fontSize: 10, color: 'var(--fl-muted)', fontFamily: MONO }}>{t('dfiq.approaches_empty')}</span>
                              )}
                              {approaches.map(ap => (
                                <div key={ap.id} style={{ fontSize: 10, color: 'var(--fl-subtle)', lineHeight: 1.4 }}>
                                  <span style={{ fontWeight: 700, color: 'var(--fl-dim)' }}>{ap.name}</span>
                                  {ap.description && <div>{ap.description}</div>}
                                  {(ap.data_sources || []).length > 0 && (
                                    <div style={{ fontFamily: MONO, color: 'var(--fl-muted)' }}>{ap.data_sources.join(', ')}</div>
                                  )}
                                </div>
                              ))}
                            </div>
                          )}

                          <textarea
                            defaultValue={a.note || ''}
                            placeholder={t('dfiq.note_placeholder')}
                            onBlur={e => commitNote(ci.instance_id, a.question_id, a.status, e.target.value)}
                            rows={2}
                            style={{
                              width: '100%', boxSizing: 'border-box', resize: 'vertical',
                              background: 'var(--fl-bg)', border: '1px solid var(--fl-sep)', borderRadius: 5,
                              color: 'var(--fl-on-dark)', fontSize: 11, fontFamily: 'var(--f-ui, sans-serif)', padding: '5px 8px', outline: 'none',
                            }}
                          />

                          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                              <span style={{ fontSize: 9, fontFamily: MONO, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                                {t('dfiq.evidence_label')} ({evidence.length})
                              </span>
                              <button
                                onClick={() => setEvidencePickerFor(pickerOpen ? null : a.question_id)}
                                style={{ ...btn, padding: '2px 6px' }}
                              >
                                <Plus size={9} />
                              </button>
                            </div>

                            {pickerOpen && (
                              <select
                                value=""
                                onChange={e => {
                                  if (e.target.value) addEvidence(caseId, ci.instance_id, a.question_id, e.target.value);
                                  setEvidencePickerFor(null);
                                }}
                                style={{ ...selectSt, fontSize: 10 }}
                              >
                                <option value="">{t('dfiq.evidence_add_placeholder')}</option>
                                {findings
                                  .filter(f => !evidence.some(e => e.bookmark_id === f.id))
                                  .map(f => <option key={f.id} value={f.id}>{f.title}</option>)}
                              </select>
                            )}

                            {evidence.length === 0 && !pickerOpen && (
                              <span style={{ fontSize: 10, color: 'var(--fl-muted)', fontFamily: MONO }}>{t('dfiq.evidence_empty')}</span>
                            )}

                            {evidence.length > 0 && (
                              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                                {evidence.map(e => (
                                  <button
                                    key={e.bookmark_id}
                                    onClick={() => removeEvidence(caseId, ci.instance_id, a.question_id, e.bookmark_id)}
                                    title={t('common.close')}
                                    style={{
                                      display: 'flex', alignItems: 'center', gap: 3, fontSize: 9, fontFamily: MONO,
                                      background: 'color-mix(in srgb, var(--fl-accent) 9%, transparent)',
                                      color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 21%, transparent)',
                                      borderRadius: 4, padding: '2px 6px', cursor: 'pointer',
                                    }}
                                  >
                                    {titleById.get(e.bookmark_id) || e.bookmark_id} <X size={8} />
                                  </button>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}

      {showCustomModal && (
        <DfiqCustomModal
          onClose={() => setShowCustomModal(false)}
          onCreated={() => { refreshCatalog(); setShowCustomModal(false); }}
        />
      )}
    </div>
  );
}
