import { useState, useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { collectionAPI } from '../../utils/api';
import { controlStyle } from '../ui/controlIdiom';
import { buildTreeRows, markKernel, collapsibleIds } from './processTree';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

const WRAP = { display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 };
const BARRE = {
  display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px',
  borderBottom: '1px solid var(--fl-border)', flexShrink: 0, flexWrap: 'wrap',
};
const SOMMAIRE = { marginLeft: 'auto', display: 'flex', gap: 16, fontSize: 11, color: 'var(--fl-dim)' };
const FORT = { fontFamily: MONO, color: 'var(--fl-text)', fontVariantNumeric: 'tabular-nums' };
const PANNEAUX = { display: 'grid', gridTemplateColumns: 'minmax(0,1fr) 320px', flex: 1, minHeight: 0 };
const COL = { overflow: 'auto', minHeight: 0 };
const TABLE = { width: '100%', borderCollapse: 'collapse', fontFamily: MONO, fontSize: 12 };
const TH = {
  position: 'sticky', top: 0, zIndex: 1, background: 'var(--fl-bg)',
  textAlign: 'left', fontSize: 10, letterSpacing: '.06em', textTransform: 'uppercase',
  color: 'var(--fl-dim)', padding: '7px 10px', borderBottom: '1px solid var(--fl-border)',
  whiteSpace: 'nowrap', fontFamily: 'inherit',
};
const TD = { padding: '3px 10px', whiteSpace: 'nowrap', verticalAlign: 'baseline' };
const NUM = { ...TD, textAlign: 'right', fontVariantNumeric: 'tabular-nums', color: 'var(--fl-dim)' };
const DETAIL = { overflow: 'auto', minHeight: 0, padding: '12px 14px', borderLeft: '1px solid var(--fl-border)' };
const ETIQ = {
  fontSize: 10, letterSpacing: '.06em', textTransform: 'uppercase',
  color: 'var(--fl-dim)', marginBottom: 3,
};
const VAL = { fontFamily: MONO, fontSize: 11, wordBreak: 'break-all', marginBottom: 12 };

export default function CollectionProcessesTab({ caseId, collectionId }) {
  const { t } = useTranslation();
  const [donnees, setDonnees] = useState(null);
  const [erreur, setErreur] = useState(null);
  const [chargement, setChargement] = useState(true);
  const [vue, setVue] = useState('arbre');
  const [recherche, setRecherche] = useState('');
  const [replies, setReplies] = useState(() => new Set());
  const [sansNoyau, setSansNoyau] = useState(false);
  const [choisi, setChoisi] = useState(null);
  const [fichierChoisi, setFichierChoisi] = useState(null);
  const [comptes, setComptes] = useState(null);
  const [source, setSource] = useState('snapshot');
  const [evts, setEvts] = useState(null);
  const [evtsPour, setEvtsPour] = useState(null);

  useEffect(() => {
    if (!caseId || !collectionId) return;
    let vivant = true;
    setChargement(true);
    setErreur(null);
    collectionAPI.processes(caseId, collectionId)
      .then(r => {
        if (!vivant) return;
        if ((r.data?.processes || []).length > 0) { setDonnees(r.data); setSource('snapshot'); return null; }
        return collectionAPI.windowsProcesses(caseId, collectionId).then(w => {
          if (!vivant) return;
          setDonnees({ ...w.data, shared: [] });
          setSource('events');
        });
      })
      .catch(e => {
        if (vivant) setErreur(e?.response?.data?.error || e?.message || t('processes.unreachable'));
      })
      .finally(() => { if (vivant) setChargement(false); });
    return () => { vivant = false; };
  }, [caseId, collectionId, t]);

  useEffect(() => {
    if (!caseId || !collectionId) return;
    let vivant = true;
    setComptes(null);
    collectionAPI.processFileCounts(caseId, collectionId)
      .then(r => { if (vivant) setComptes(r.data?.counts || []); })
      .catch(() => { if (vivant) setComptes([]); });
    return () => { vivant = false; };
  }, [caseId, collectionId]);

  const procs = useMemo(() => {
    const brut = (donnees?.processes || []).map(p => p.name
      ? p
      : { ...p, name: String(p.image || '').split(/[\\/]/).pop() || String(p.pid) });
    const base = markKernel(brut);
    if (source === 'events' || !comptes) return base;
    const parPid = new Map(comptes.map(c => [c.pid, c]));
    return base.map(p => {
      const c = parPid.get(p.pid);
      return { ...p, fd: Number(c?.fd || 0), maps: Number(c?.maps || 0), deleted_count: Number(c?.deleted_count || 0) };
    });
  }, [donnees, comptes, source]);
  const lignes = useMemo(
    () => buildTreeRows(procs, { replies, recherche, sansNoyau }),
    [procs, replies, recherche, sansNoyau],
  );
  const parPid = useMemo(() => new Map(procs.map(p => [p.pid, p])), [procs]);
  const partages = donnees?.shared || [];

  const sommaire = useMemo(() => ({
    total: procs.length,
    racines: procs.filter(p => !p.ppid).length,
    avecFichiers: procs.filter(p => p.fd > 0 || p.maps > 0).length,
    deleted_count: procs.filter(p => p.deleted_count > 0).length,
    comptesPrets: comptes != null,
  }), [procs, comptes]);

  const chargerEvenements = (p) => {
    setEvtsPour(p.pid);
    setEvts('chargement');
    collectionAPI.processEvents(caseId, collectionId, p.pid, p.name)
      .then(r => setEvts(r.data))
      .catch(() => setEvts({ events: [], scope: null, reason: 'error' }));
  };

  const basculer = (pid) => setReplies(prev => {
    const s = new Set(prev);
    s.has(pid) ? s.delete(pid) : s.add(pid);
    return s;
  });

  if (chargement) {
    return <div style={{ padding: 16, color: 'var(--fl-dim)', fontSize: 12 }}>{t('processes.loading')}</div>;
  }
  if (erreur) {
    return (
      <div style={{ padding: 16, color: 'var(--fl-danger)', fontFamily: MONO, fontSize: 11 }}>
        {t('processes.failed')} — {erreur}
      </div>
    );
  }
  if (!procs.length) {
    const vide = source === 'events' ? 'processes.none_windows' : 'processes.none';
    return (
      <div style={{ padding: 16, color: 'var(--fl-dim)', fontSize: 12, maxWidth: '70ch', lineHeight: 1.6 }}>
        {t(vide)}
      </div>
    );
  }

  const selection = choisi != null ? parPid.get(choisi) : null;
  const parent = selection ? parPid.get(selection.ppid) : null;
  const porteurs = fichierChoisi
    ? (partages.find(f => f.target === fichierChoisi)?.pids || [])
    : [];

  return (
    <div style={WRAP}>
      <div style={BARRE}>
        <button type="button" onClick={() => setVue('arbre')} aria-pressed={vue === 'arbre'}
          style={{ ...controlStyle, color: vue === 'arbre' ? 'var(--fl-accent)' : 'var(--fl-dim)' }}>
          {t('processes.view_tree')}
        </button>
        {source !== 'events' && <button type="button" onClick={() => setVue('partage')} aria-pressed={vue === 'partage'}
          style={{ ...controlStyle, color: vue === 'partage' ? 'var(--fl-accent)' : 'var(--fl-dim)' }}>
          {t('processes.view_shared')}
        </button>}

        {vue === 'arbre' && (
          <>
            <input type="search" value={recherche} onChange={e => setRecherche(e.target.value)}
              placeholder={t('processes.filter_placeholder')} aria-label={t('processes.filter_placeholder')}
              style={{ ...controlStyle, fontFamily: MONO, width: 230 }} />
            <button type="button" onClick={() => setReplies(new Set())} style={controlStyle}>
              {t('processes.expand_all')}
            </button>
            <button type="button" onClick={() => setReplies(collapsibleIds(procs))} style={controlStyle}>
              {t('processes.collapse_all')}
            </button>
            <button type="button" onClick={() => setSansNoyau(v => !v)} aria-pressed={sansNoyau}
              style={{ ...controlStyle, color: sansNoyau ? 'var(--fl-accent)' : 'var(--fl-dim)' }}>
              {t('processes.hide_kernel')}
            </button>
          </>
        )}

        <div style={SOMMAIRE}>
          <span><b style={FORT}>{sommaire.total}</b> {t('processes.count_processes')}</span>
          <span><b style={FORT}>{sommaire.racines}</b> {t('processes.count_roots')}</span>
          {source === 'events' ? null : sommaire.comptesPrets ? (
            <>
              <span><b style={FORT}>{sommaire.avecFichiers}</b> {t('processes.count_with_files')}</span>
              <span><b style={FORT}>{sommaire.deleted_count}</b> {t('processes.count_holding_deleted')}</span>
            </>
          ) : (
            <span>{t('processes.counting_files')}</span>
          )}
        </div>
      </div>

      <div style={{ padding: '7px 12px', fontSize: 11, color: 'var(--fl-dim)',
                    borderBottom: '1px solid var(--fl-border)', lineHeight: 1.5 }}>
        {source === 'events'
          ? t('processes.source_events', {
              n: procs.length,
              from: procs.length ? new Date(procs[0].timestamp).toLocaleString() : '',
              to: procs.length ? new Date(procs[procs.length - 1].timestamp).toLocaleString() : '',
            })
          : t('processes.source_snapshot')}
      </div>

      {vue === 'arbre' ? (
        <div style={PANNEAUX}>
          <div style={COL}>
            <table style={TABLE}>
              <thead>
                <tr>
                  <th style={TH}>{t('processes.col_process')}</th>
                  <th style={TH}>{t('processes.col_pid')}</th>
                  <th style={TH}>{t('processes.col_user')}</th>
                  <th style={TH}>{t('processes.col_state')}</th>
                  <th style={{ ...TH, textAlign: 'right' }}>{t('processes.col_fd')}</th>
                  <th style={{ ...TH, textAlign: 'right' }}>{t('processes.col_maps')}</th>
                  <th style={{ ...TH, textAlign: 'right' }}>{t('processes.col_deleted')}</th>
                </tr>
              </thead>
              <tbody>
                {lignes.map(({ pid, name, profondeur, aDesEnfants, proc }) => (
                  <tr key={pid} onClick={() => setChoisi(pid)}
                    aria-selected={choisi === pid}
                    style={{
                      borderBottom: '1px solid var(--fl-border-soft, var(--fl-border))',
                      cursor: 'pointer',
                      background: choisi === pid ? 'var(--fl-accent-soft, transparent)' : undefined,
                    }}>
                    <td style={TD}>
                      <span style={{ color: 'var(--fl-dim)', userSelect: 'none' }}>
                        {'  '.repeat(profondeur)}
                      </span>
                      <span role={aDesEnfants ? 'button' : undefined}
                        onClick={aDesEnfants ? (e) => { e.stopPropagation(); basculer(pid); } : undefined}
                        style={{ display: 'inline-block', width: 14, color: 'var(--fl-dim)' }}>
                        {aDesEnfants ? (replies.has(pid) ? '+' : '−') : ' '}
                      </span>
                      <span style={{ color: proc.noyau ? 'var(--fl-dim)' : 'var(--fl-text)' }}>{nom}</span>
                    </td>
                    <td style={NUM}>{pid}</td>
                    <td style={TD}>{proc.user_name || '—'}</td>
                    <td style={TD}>{proc.state || ''}</td>
                    <td style={NUM}>{comptes == null ? '' : (proc.fd || '·')}</td>
                    <td style={NUM}>{comptes == null ? '' : (proc.maps || '·')}</td>
                    <td style={{ ...NUM, color: proc.deleted_count ? 'var(--fl-warning, var(--fl-dim))' : 'var(--fl-dim)' }}>
                      {comptes == null ? '' : (proc.deleted_count || '·')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <aside style={DETAIL}>
            {!selection ? (
              <div style={{ color: 'var(--fl-dim)', fontSize: 12 }}>{t('processes.pick_a_row')}</div>
            ) : (
              <>
                <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 2 }}>{selection.name}</div>
                <div style={{ fontFamily: MONO, fontSize: 11, color: 'var(--fl-dim)', marginBottom: 14 }}>
                  pid {selection.pid} · {selection.user_name || '—'} · {selection.state || ''}
                </div>
                <div style={ETIQ}>{t('processes.started_by')}</div>
                <div style={VAL}>{parent ? `${parent.name} (pid ${parent.pid})` : t('processes.is_root')}</div>
                <div style={ETIQ}>{t('processes.command_line')}</div>
                <div style={VAL}>{selection.command_line || t('processes.not_collected')}</div>
                <div style={{ marginBottom: 14 }}>
                  <button type="button" style={controlStyle}
                    onClick={() => chargerEvenements(selection)}>
                    {t('processes.events_button')}
                  </button>
                </div>

                {evtsPour === selection.pid && (
                  <div style={{ marginBottom: 14 }}>
                    {evts === 'chargement' ? (
                      <div style={{ fontSize: 11, color: 'var(--fl-dim)' }}>{t('processes.events_loading')}</div>
                    ) : !evts?.scope ? (
                      <div style={{ fontSize: 11, color: 'var(--fl-warning, var(--fl-dim))', lineHeight: 1.5 }}>
                        {t('processes.events_no_boot')}
                      </div>
                    ) : (
                      <>
                        <div style={{ fontSize: 10, color: 'var(--fl-dim)', lineHeight: 1.5, marginBottom: 6 }}>
                          {t('processes.events_scope', {
                            taken: new Date(evts.scope.taken_at).toLocaleString(),
                          })}
                          {evts.capped ? ' ' + t('processes.events_capped', { n: evts.events.length }) : ''}
                        </div>
                        {evts.events.length === 0 ? (
                          <div style={{ fontSize: 11, color: 'var(--fl-dim)' }}>{t('processes.events_none')}</div>
                        ) : (
                          <ul style={{ listStyle: 'none', margin: 0, padding: 0, fontFamily: MONO, fontSize: 10 }}>
                            {evts.events.slice(0, 60).map(e => (
                              <li key={e.id} style={{ padding: '2px 0', borderBottom: '1px solid var(--fl-border-soft, var(--fl-border))' }}>
                                <span style={{ color: 'var(--fl-dim)' }}>
                                  {new Date(e.timestamp).toISOString().slice(0, 19).replace('T', ' ')}
                                </span>
                                <span> {e.description}</span>
                              </li>
                            ))}
                          </ul>
                        )}
                      </>
                    )}
                  </div>
                )}

                <div style={ETIQ}>{t('processes.holds_open')}</div>
                <div style={VAL}>
                  {comptes == null ? t('processes.counting_files') : t('processes.holds_summary', {
                    fd: selection.fd, maps: selection.maps, deleted: selection.deleted_count,
                  })}
                </div>
              </>
            )}
          </aside>
        </div>
      ) : (
        <div style={PANNEAUX}>
          <div style={COL}>
            <div style={{ padding: '10px 14px', fontSize: 12, color: 'var(--fl-dim)', maxWidth: '76ch', lineHeight: 1.6 }}>
              {t('processes.shared_explainer')}
            </div>
            <table style={TABLE}>
              <thead>
                <tr>
                  <th style={{ ...TH, textAlign: 'right' }}>{t('processes.col_holders')}</th>
                  <th style={TH}>{t('processes.col_deleted_file')}</th>
                </tr>
              </thead>
              <tbody>
                {partages.map(f => (
                  <tr key={f.target} onClick={() => setFichierChoisi(f.target)}
                    aria-selected={fichierChoisi === f.target}
                    style={{
                      borderBottom: '1px solid var(--fl-border-soft, var(--fl-border))',
                      cursor: 'pointer',
                      background: fichierChoisi === f.target ? 'var(--fl-accent-soft, transparent)' : undefined,
                    }}>
                    <td style={NUM}>{f.holders}</td>
                    <td style={{ ...TD, direction: 'rtl', textAlign: 'left', maxWidth: 420, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {f.target}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <aside style={DETAIL}>
            {!fichierChoisi ? (
              <div style={{ color: 'var(--fl-dim)', fontSize: 12 }}>{t('processes.pick_a_file')}</div>
            ) : (
              <>
                <div style={ETIQ}>{t('processes.col_deleted_file')}</div>
                <div style={VAL}>{fichierChoisi}</div>
                <div style={ETIQ}>{t('processes.holders_count', { count: porteurs.length })}</div>
                <ul style={{ listStyle: 'none', margin: 0, padding: 0, fontFamily: MONO, fontSize: 11 }}>
                  {porteurs.map(pid => {
                    const p = parPid.get(pid);
                    return (
                      <li key={pid} style={{ padding: '2px 0', borderBottom: '1px solid var(--fl-border-soft, var(--fl-border))' }}>
                        <span style={{ color: p ? 'var(--fl-text)' : 'var(--fl-dim)' }}>
                          {p ? p.name : t('processes.absent_from_tree')}
                        </span>
                        <span style={{ color: 'var(--fl-dim)' }}> {pid}</span>
                      </li>
                    );
                  })}
                </ul>
              </>
            )}
          </aside>
        </div>
      )}
    </div>
  );
}
