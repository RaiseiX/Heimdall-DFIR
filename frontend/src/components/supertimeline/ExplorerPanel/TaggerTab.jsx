import { useState, useEffect, useCallback } from 'react';
import { Loader2, Tag, Play, RefreshCw, X, CheckCircle2 } from 'lucide-react';
import { useTimelineStore } from '../store/useTimelineStore';
import { collectionAPI } from '../../../utils/api';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

export default function TaggerTab() {
  const { caseId, evidenceId, setFilter, applyFilters, tagFilter } = useTimelineStore();

  const [rules, setRules] = useState([]);
  const [tagCounts, setTagCounts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [runResult, setRunResult] = useState(null);
  const [error, setError] = useState('');
  const [expanded, setExpanded] = useState(null); // rule name expanded to show pattern

  const load = useCallback(async () => {
    if (!caseId) return;
    setLoading(true);
    setError('');
    try {
      const res = await collectionAPI.tagger(caseId, evidenceId ? { evidence_id: evidenceId } : {});
      setRules(res.data?.rules || []);
      setTagCounts(res.data?.tag_counts || []);
    } catch (e) {
      setError(e.response?.data?.error || e.message || 'Failed to load tagger');
    } finally {
      setLoading(false);
    }
  }, [caseId, evidenceId]);

  useEffect(() => { load(); }, [load]);

  const runTagger = async () => {
    if (!caseId || running) return;
    setRunning(true);
    setError('');
    setRunResult(null);
    try {
      const res = await collectionAPI.taggerRun(caseId, evidenceId ? { evidence_id: evidenceId } : {});
      setRunResult(res.data);
      load();
    } catch (e) {
      const detail = e.response?.data?.detail;
      setError(detail ? `${e.response.data.error}: ${detail}` : (e.response?.data?.error || e.message || 'Tagger run failed'));
    } finally {
      setRunning(false);
    }
  };

  const filterByTag = (tag) => {
    setFilter('tagFilter', tag === tagFilter ? '' : tag);
    applyFilters();
  };

  return (
    <div style={{ flex: 1, minHeight: 0, height: '100%', display: 'flex', flexDirection: 'column', padding: '8px 10px', overflow: 'hidden' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0, marginBottom: 8 }}>
        <Tag size={11} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} />
        <span style={{ fontSize: 8, color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 700, flex: 1 }}>
          Tagger
        </span>
        <button
          onClick={runTagger}
          disabled={running}
          title="Re-run the keyword rules over the collection's rows"
          style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '3px 7px', borderRadius: 5, cursor: running ? 'wait' : 'pointer', background: 'color-mix(in srgb, var(--fl-accent) 12%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 28%, transparent)', fontFamily: MONO, fontSize: 9, fontWeight: 600, flexShrink: 0 }}
        >
          {running ? <Loader2 size={10} style={{ animation: 'spin 1s linear infinite' }} /> : <Play size={10} />}
          Re-run
        </button>
        <button
          onClick={load}
          title="Refresh"
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-subtle)', padding: 3, display: 'inline-flex' }}
          onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-accent)'; }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-subtle)'; }}
        >
          <RefreshCw size={11} />
        </button>
      </div>

      {error && (
        <div style={{ padding: '6px 8px', borderRadius: 5, background: 'color-mix(in srgb, var(--fl-danger) 10%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 25%, transparent)', color: 'var(--fl-danger)', fontFamily: MONO, fontSize: 9.5, marginBottom: 8, flexShrink: 0 }}>
          {error}
        </div>
      )}

      {runResult && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '6px 8px', borderRadius: 5, background: 'color-mix(in srgb, var(--fl-ok) 10%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-ok) 25%, transparent)', color: 'var(--fl-ok)', fontFamily: MONO, fontSize: 9.5, marginBottom: 8, flexShrink: 0 }}>
          <CheckCircle2 size={11} style={{ flexShrink: 0 }} />
          {runResult.rows_tagged} row(s) tagged · {runResult.tags_added} tag(s) added · {runResult.scanned} scanned
          <button onClick={() => setRunResult(null)} style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: 'inherit', padding: 0, display: 'inline-flex' }}>
            <X size={10} />
          </button>
        </div>
      )}

      {loading ? (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, padding: 24, color: 'var(--fl-dim)', fontFamily: MONO, fontSize: 10 }}>
          <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} /> Loading…
        </div>
      ) : (
        <div style={{ flex: 1, minHeight: 0, overflowY: 'auto' }}>
          {/* Tag distribution */}
          <div style={{ fontSize: 8, color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 700, marginBottom: 6 }}>
            Tags in this collection
          </div>
          {tagCounts.length === 0 ? (
            <div style={{ color: 'var(--fl-subtle)', fontSize: 9.5, fontFamily: MONO, padding: '2px 0', marginBottom: 6 }}>No tags yet — run the tagger or add tags manually.</div>
          ) : (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 10 }}>
              {tagCounts.map(t => {
                const active = tagFilter === t.tag;
                return (
                  <button
                    key={t.tag}
                    onClick={() => filterByTag(t.tag)}
                    title={`${t.tag} — filter timeline`}
                    style={{
                      display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 6px', borderRadius: 4,
                      background: active ? 'color-mix(in srgb, var(--fl-accent) 16%, transparent)' : 'var(--fl-card)',
                      border: `1px solid ${active ? 'color-mix(in srgb, var(--fl-accent) 35%, transparent)' : 'var(--fl-border2)'}`,
                      color: active ? 'var(--fl-accent)' : 'var(--fl-dim)', cursor: 'pointer', fontFamily: MONO, fontSize: 9,
                    }}
                  >
                    {t.tag}
                    <span style={{ color: 'var(--fl-subtle)', fontSize: 8.5 }}>{t.cnt}</span>
                  </button>
                );
              })}
            </div>
          )}

          {/* Rules */}
          <div style={{ fontSize: 8, color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 700, marginBottom: 6 }}>
            Rules ({rules.length})
          </div>
          {rules.length === 0 ? (
            <div style={{ color: 'var(--fl-subtle)', fontSize: 9.5, fontFamily: MONO }}>No keyword rules loaded.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {rules.map(r => {
                const open = expanded === r.name;
                return (
                  <div key={r.name} style={{ border: '1px solid var(--fl-border2)', borderRadius: 5, overflow: 'hidden', flexShrink: 0 }}>
                    <button
                      onClick={() => setExpanded(open ? null : r.name)}
                      style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 6, padding: '4px 7px', background: 'var(--fl-card)', border: 'none', cursor: 'pointer', textAlign: 'left', color: 'var(--fl-text)', fontFamily: MONO, fontSize: 9.5 }}
                    >
                      <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.name}</span>
                      <span style={{ color: 'var(--fl-subtle)', fontSize: 8.5, flexShrink: 0 }}>{r.tags?.length} tag(s)</span>
                    </button>
                    {open && (
                      <div style={{ padding: '5px 7px', borderTop: '1px solid var(--fl-border2)', background: 'var(--fl-bg)' }}>
                        <div style={{ fontSize: 9, color: 'var(--fl-muted)', marginBottom: 3, wordBreak: 'break-all', lineHeight: 1.4 }}>
                          {r.pattern}
                        </div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                          {(r.tags || []).map(tag => (
                            <button
                              key={tag}
                              onClick={() => filterByTag(tag)}
                              style={{ padding: '1px 5px', borderRadius: 3, background: 'color-mix(in srgb, var(--fl-accent) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 20%, transparent)', color: 'var(--fl-accent)', cursor: 'pointer', fontFamily: MONO, fontSize: 8.5 }}
                            >
                              {tag}
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
