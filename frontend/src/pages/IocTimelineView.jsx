import { useMemo, useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Globe, Hash, FileText, User, Server, HelpCircle,
  AlertTriangle, ExternalLink, ChevronDown, ChevronRight, Loader2, Pencil,
} from 'lucide-react';
import { collectionAPI, iocsAPI } from '../utils/api';
import IocNotesCell from '../components/iocs/IocNotesCell';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

const TYPE_ICON = {
  ip: Globe, domain: Globe, url: Server,
  hash_md5: Hash, hash_sha1: Hash, hash_sha256: Hash,
  filename: FileText, registry_key: FileText,
  mutex: FileText, user_agent: User, email: User, other: HelpCircle,
};

const TYPE_LABEL = {
  ip: 'IP', domain: 'Domain', url: 'URL',
  hash_md5: 'MD5', hash_sha1: 'SHA1', hash_sha256: 'SHA256',
  filename: 'File', registry_key: 'Registry', mutex: 'Mutex',
  user_agent: 'UserAgent', email: 'Email', other: 'Other',
};

function verdictOf(ioc) {
  if (ioc.is_malicious === true)  return 'malicious';
  if (ioc.is_malicious === false) return 'benign';
  return 'suspect';
}

const VERDICT_COLOR = {
  malicious: 'var(--fl-danger)',
  suspect:   'var(--fl-gold)',
  benign:    'var(--fl-ok)',
};

const VERDICT_LABEL = { malicious: 'Malicious', suspect: 'Suspect', benign: 'Benign' };

// The IOC's own time is the originating event's timestamp: first_seen is set at
// creation from the source event (fallback to created_at for manually-added IOCs).
const anchorTs = (i) => i.first_seen || i.created_at;

function fmtDate(ts, lang) {
  if (!ts) return '—';
  const d = new Date(ts);
  return isNaN(d.getTime()) ? String(ts) : d.toLocaleString(lang, {
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
  });
}

// ── Vertical time ruler + density histogram on top, chronological rows below ──
// `onUpdateIoc(id, patch)` is optional: it lets the parent refresh its own IOC
// list after a note is saved (the API call itself happens here).
export default function IocTimelineView({ iocs, onUpdateIoc }) {
  const { t, i18n } = useTranslation();
  const [selectedId, setSelectedId] = useState(null);
  const [matches, setMatches] = useState([]);
  const [matchTotal, setMatchTotal] = useState(0);
  const [matchLoading, setMatchLoading] = useState(false);
  const [matchErr, setMatchErr] = useState('');
  const [items, setItems] = useState(iocs);
  const [editingNoteId, setEditingNoteId] = useState(null);

  // Keep the local copy in sync when the parent refreshes the IOC list.
  useEffect(() => { setItems(iocs); }, [iocs]);

  const saveNote = async (ioc, notes) => {
    await iocsAPI.update(ioc.id, { notes });
    setItems(prev => prev.map(i => i.id === ioc.id ? { ...i, notes } : i));
    if (onUpdateIoc) onUpdateIoc(ioc.id, { notes });
  };

  const rows = useMemo(() => {
    return [...items]
      .filter(i => anchorTs(i))
      .sort((a, b) => new Date(anchorTs(a)) - new Date(anchorTs(b)));
  }, [items]);

  const range = useMemo(() => {
    let min = Infinity, max = -Infinity;
    for (const i of [...items, ...matches]) {
      const tv = [anchorTs(i), i.first_seen, i.last_seen].filter(Boolean);
      for (const ts of tv) {
        const ms = new Date(ts).getTime();
        if (isNaN(ms)) continue;
        if (ms < min) min = ms;
        if (ms > max) max = ms;
      }
    }
    if (!isFinite(min)) return null;
    if (min === max) { max = min + 86400000; }
    return { min, max, span: max - min };
  }, [items, matches]);

  // Density histogram by UTC-day bucket, stacked by verdict.
  const histo = useMemo(() => {
    if (!range) return [];
    const DAY = 86400000;
    const days = Math.max(1, Math.ceil(range.span / DAY));
    const buckets = Array.from({ length: days }, () => ({ malicious: 0, suspect: 0, benign: 0 }));
    for (const i of rows) {
      const ms = new Date(anchorTs(i)).getTime();
      if (isNaN(ms)) continue;
      const idx = Math.min(days - 1, Math.floor((ms - range.min) / DAY));
      buckets[idx][verdictOf(i)] += 1;
    }
    const max = Math.max(1, ...buckets.map(b => b.malicious + b.suspect + b.benign));
    return { buckets, max, days };
  }, [rows, range]);

  const pos = (ts) => {
    if (!range || !ts) return null;
    const ms = new Date(ts).getTime();
    if (isNaN(ms)) return null;
    return Math.max(0, Math.min(100, ((ms - range.min) / range.span) * 100));
  };

  async function loadMatches(ioc) {
    if (selectedId === ioc.id) { setSelectedId(null); setMatches([]); return; }
    setSelectedId(ioc.id);
    setMatches([]);
    setMatchLoading(true);
    setMatchErr('');
    try {
      const res = await collectionAPI.timeline(ioc.case_id, {
        search: ioc.value, search_op: 'contains',
        limit: 200, sort_dir: 'asc',
      });
      setMatches(res.data?.records || []);
      setMatchTotal(res.data?.total ?? (res.data?.records || []).length);
    } catch {
      setMatchErr(t('iocs.match_error'));
    } finally {
      setMatchLoading(false);
    }
  }

  return (
    <div className="fl-card" style={{ overflow: 'hidden' }}>
      {/* Density histogram */}
      {range && (
        <div style={{ padding: '16px 20px 8px' }}>
          <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height: 60 }}>
            {histo.buckets.map((b, idx) => {
              const total = b.malicious + b.suspect + b.benign;
              if (total === 0) return <div key={idx} style={{ flex: 1 }} />;
              return (
                <div key={idx} title={`${total} IOC`} style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'flex-end' }}>
                  {b.malicious > 0 && <div style={{ height: `${(b.malicious / histo.max) * 100}%`, background: VERDICT_COLOR.malicious, borderRadius: '2px 2px 0 0', minHeight: 2 }} />}
                  {b.suspect > 0 && <div style={{ height: `${(b.suspect / histo.max) * 100}%`, background: VERDICT_COLOR.suspect }} />}
                  {b.benign > 0 && <div style={{ height: `${(b.benign / histo.max) * 100}%`, background: VERDICT_COLOR.benign }} />}
                </div>
              );
            })}
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, fontFamily: MONO, color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.08em', marginTop: 5 }}>
            <span>{fmtDate(range.min, i18n.language)}</span>
            <span>{t('iocs.timeline_density', { defaultValue: 'IOC density per day' })}</span>
            <span>{fmtDate(range.max, i18n.language)}</span>
          </div>
        </div>
      )}

      {/* Legend */}
      <div style={{ padding: '4px 20px 12px', display: 'flex', gap: 14, alignItems: 'center', fontSize: 10.5, fontFamily: MONO, color: 'var(--fl-muted)' }}>
        {Object.entries(VERDICT_LABEL).map(([k, lab]) => (
          <span key={k} style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: VERDICT_COLOR[k] }} />
            {t(`iocs.verdict_${k}`, { defaultValue: lab })}
          </span>
        ))}
        <span style={{ marginLeft: 'auto', color: 'var(--fl-subtle)' }}>
          {rows.length.toLocaleString(i18n.language)} {t('iocs.indicators')}
        </span>
      </div>

      {/* Chronological list — viewport-proportional so many IOCs are visible at once */}
      <div style={{ borderTop: '1px solid var(--fl-border2)', maxHeight: 'calc(100vh - 300px)', minHeight: 320, overflowY: 'auto' }}>
        {rows.map(ioc => {
          const Icon = TYPE_ICON[ioc.ioc_type] || Globe;
          const verdict = verdictOf(ioc);
          const color = VERDICT_COLOR[verdict];
          const sev = ioc.severity || 5;
          const sevColor = sev >= 8 ? 'var(--fl-danger)' : sev >= 6 ? 'var(--fl-warn)' : sev >= 4 ? 'var(--fl-gold)' : 'var(--fl-ok)';
          const beginP = pos(Math.min(new Date(anchorTs(ioc)).getTime(), ioc.last_seen ? new Date(ioc.last_seen).getTime() : Infinity));
          const endP = pos(Math.max(ioc.last_seen ? new Date(ioc.last_seen).getTime() : new Date(anchorTs(ioc)).getTime(), new Date(anchorTs(ioc)).getTime()));
          const expanded = selectedId === ioc.id;
          return (
            <div key={ioc.id} style={{ borderBottom: '1px solid var(--fl-border2)' }}>
              <button
                onClick={() => loadMatches(ioc)}
                style={{
                  width: '100%', display: 'flex', alignItems: 'center', gap: 12, padding: '9px 20px',
                  background: expanded ? 'color-mix(in srgb, var(--fl-accent) 6%, transparent)' : 'none',
                  border: 'none', cursor: 'pointer', textAlign: 'left', transition: 'background 0.12s ease',
                }}
              >
                <span style={{ width: 88, flexShrink: 0, fontFamily: MONO, fontSize: 11, color: 'var(--fl-dim)' }}>
                  {fmtDate(anchorTs(ioc), i18n.language)}
                </span>
                <span style={{ width: 10, flexShrink: 0, fontSize: 8, color: 'var(--fl-subtle)' }}>
                  {expanded ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
                </span>
                <span style={{ width: 90, flexShrink: 0, display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 10, color: 'var(--fl-muted)' }}>
                  <Icon size={10} />{t(`iocs.types.${ioc.ioc_type}`, { defaultValue: TYPE_LABEL[ioc.ioc_type] || ioc.ioc_type })}
                </span>
                <span style={{ flex: 1, minWidth: 0, fontFamily: MONO, fontSize: 12, fontWeight: 600, color: verdict === 'malicious' ? 'var(--fl-danger)' : 'var(--fl-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {ioc.value}
                </span>
                <span style={{ flexShrink: 0, fontSize: 10, color: 'var(--fl-muted)', fontFamily: MONO, maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {ioc.case_number || ''}{ioc.case_number ? ' · ' : ''}{ioc.case_title || ''}
                </span>
                <span style={{ flexShrink: 0, padding: '2px 6px', borderRadius: 4, fontFamily: MONO, fontSize: 10.5, fontWeight: 700, background: `color-mix(in srgb, ${sevColor} 12%, transparent)`, color: sevColor, border: `1px solid color-mix(in srgb, ${sevColor} 25%, transparent)` }}>
                  {sev}
                </span>
                <span style={{ flexShrink: 0, display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 10, fontWeight: 700, color, background: `color-mix(in srgb, ${color} 10%, transparent)`, border: `1px solid color-mix(in srgb, ${color} 22%, transparent)`, borderRadius: 4, padding: '2px 7px' }}>
                  {verdict === 'malicious' && <AlertTriangle size={9} />}
                  {t(`iocs.verdict_${verdict}`, { defaultValue: VERDICT_LABEL[verdict] })}
                </span>
              </button>

              {/* Range bar under the row */}
              <div style={{ padding: '0 20px 8px 120px' }}>
                {range && (
                  <div style={{ position: 'relative', height: 4, borderRadius: 2, background: 'color-mix(in srgb, var(--fl-text) 6%, transparent)' }}>
                    {beginP != null && endP != null && (
                      <div style={{ position: 'absolute', top: 0, height: '100%', borderRadius: 2, background: color, opacity: 0.85, left: `${beginP}%`, width: `${Math.max(0.5, endP - beginP)}%` }} />
                    )}
                  </div>
                )}
              </div>

              {/* Analyst note — editable inline */}
              {editingNoteId === ioc.id ? (
                <div style={{ padding: '0 20px 8px 120px' }}>
                  <IocNotesCell
                    value={ioc.notes || ''}
                    onSave={notes => saveNote(ioc, notes)}
                    onClose={() => setEditingNoteId(null)}
                  />
                </div>
              ) : ioc.notes ? (
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6, padding: '0 20px 8px 120px' }}>
                  <span style={{ flex: 1, minWidth: 0, fontSize: 11, color: 'var(--fl-gold)', fontFamily: MONO, lineHeight: 1.45, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                    ✎ {ioc.notes}
                  </span>
                  <button onClick={() => setEditingNoteId(ioc.id)} title="Modifier la note"
                    style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, padding: 2, borderRadius: 4, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-subtle)' }}
                    onMouseEnter={e => e.currentTarget.style.color = 'var(--fl-gold)'}
                    onMouseLeave={e => e.currentTarget.style.color = 'var(--fl-subtle)'}>
                    <Pencil size={10} />
                  </button>
                </div>
              ) : (
                <div style={{ padding: '0 20px 8px 120px' }}>
                  <button onClick={() => setEditingNoteId(ioc.id)} title="Ajouter une note"
                    style={{ fontSize: 10, fontFamily: MONO, color: 'var(--fl-subtle)', border: '1px dashed var(--fl-border2)', borderRadius: 4, padding: '1px 8px', background: 'none', cursor: 'pointer' }}
                    onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-gold)'; e.currentTarget.style.borderColor = 'color-mix(in srgb, var(--fl-gold) 40%, transparent)'; }}
                    onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-subtle)'; e.currentTarget.style.borderColor = 'var(--fl-border2)'; }}>
                    ✎ Note
                  </button>
                </div>
              )}

              {/* Matched events (Part 2) */}
              {expanded && (
                <div style={{ padding: '2px 20px 14px 120px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                    <span style={{ fontSize: 10.5, fontFamily: MONO, color: 'var(--fl-accent)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                      {t('iocs.matched_events', { defaultValue: 'Matched events' })}
                    </span>
                    {!matchLoading && matchTotal > 0 && (
                      <span style={{ fontSize: 10.5, fontFamily: MONO, color: 'var(--fl-dim)' }}>
                        {matchTotal.toLocaleString(i18n.language)}
                      </span>
                    )}
                    <span style={{ marginLeft: 'auto' }}>
                      <button
                        onClick={() => { window.location.href = `/super-timeline?caseId=${ioc.case_id}&search=${encodeURIComponent(ioc.value)}`; }}
                        title={t('iocs.open_timeline')}
                        style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 10, fontFamily: MONO, background: 'none', border: '1px solid var(--fl-border)', color: 'var(--fl-accent)', borderRadius: 4, padding: '2px 8px', cursor: 'pointer' }}
                      >
                        <ExternalLink size={10} />{t('iocs.open_timeline', { defaultValue: 'Open in timeline' })}
                      </button>
                    </span>
                  </div>

                  {matchLoading ? (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, fontFamily: MONO, color: 'var(--fl-muted)' }}>
                      <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} />{t('iocs.match_searching', { defaultValue: 'Searching events…' })}
                    </div>
                  ) : matchErr ? (
                    <div style={{ fontSize: 11, color: 'var(--fl-danger)', fontFamily: MONO }}>{matchErr}</div>
                  ) : matchTotal === 0 ? (
                    <div style={{ fontSize: 11, color: 'var(--fl-dim)', fontFamily: MONO }}>{t('iocs.match_none', { defaultValue: 'No matching event in this case.' })}</div>
                  ) : (
                    <div style={{ maxHeight: 340, overflowY: 'auto', border: '1px solid var(--fl-border)', borderRadius: 6, background: 'var(--fl-bg)' }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11.5 }}>
                        <tbody>
                          {matches.map((r, idx) => (
                            <tr key={r.id || idx} style={{ borderBottom: '1px solid var(--fl-border2)' }}>
                              <td style={{ padding: '5px 10px', fontFamily: MONO, fontSize: 10.5, color: 'var(--fl-dim)', whiteSpace: 'nowrap', width: 150 }}>
                                {fmtDate(r.timestamp, i18n.language)}
                              </td>
                              <td style={{ padding: '5px 10px', fontFamily: MONO, fontSize: 10.5, color: 'var(--fl-accent)', whiteSpace: 'nowrap' }}>
                                {r.host_name || '—'}
                              </td>
                              <td style={{ padding: '5px 10px', fontFamily: MONO, fontSize: 10.5, color: 'var(--fl-muted)', whiteSpace: 'nowrap' }}>
                                {r.artifact_type}
                              </td>
                              <td style={{ padding: '5px 10px', color: 'var(--fl-text)', maxWidth: 420, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.description || ''}>
                                {r.description || ''}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
