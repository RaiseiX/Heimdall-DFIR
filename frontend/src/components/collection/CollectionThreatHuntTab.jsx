import { useState, useEffect, useCallback } from 'react';
import {
  Crosshair, Scan, Search, AlertCircle, CheckCircle2,
  ChevronDown, ChevronRight, Clock, Shield, FileCode2,
} from 'lucide-react';
import { threatHuntingAPI } from '../../utils/api';
import { Button, Badge, Spinner } from '../ui';
import { fmtLocal } from '../../utils/formatters';

const C = {
  yara:   'var(--fl-accent)',
  sigma:  'var(--fl-purple)',
  match:  'var(--fl-danger)',
  ok:     'var(--fl-ok)',
  surface:'var(--fl-card)',
  border: 'var(--fl-border)',
};

function fmtDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}
function parseStrings(v) {
  if (!v) return [];
  if (Array.isArray(v)) return v;
  try { return JSON.parse(v); } catch { return []; }
}

function Card({ accent, icon: Icon, title, desc, children, action }) {
  return (
    <div style={{ background: 'var(--fl-panel)', border: `1px solid ${C.border}`, borderRadius: 12, padding: '16px 18px' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 14 }}>
        <div style={{ width: 30, height: 30, borderRadius: 8, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', background: `color-mix(in srgb, ${accent} 12%, transparent)`, border: `1px solid color-mix(in srgb, ${accent} 26%, transparent)` }}>
          <Icon size={15} style={{ color: accent }} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--fl-text)' }}>{title}</div>
          <div style={{ fontSize: 12, color: 'var(--fl-dim)', marginTop: 2 }}>{desc}</div>
        </div>
        {action}
      </div>
      {children}
    </div>
  );
}

// YARA scan scoped to a single evidence (= this collection).
function YaraSection({ evidenceId }) {
  const [results, setResults] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [scanned, setScanned]   = useState(false);
  const [error, setError]       = useState('');
  const [rulesChecked, setRulesChecked] = useState(null);

  const load = useCallback(async () => {
    try {
      const r = await threatHuntingAPI.yaraResultsEvidence(evidenceId);
      const rows = r.data.results || [];
      setResults(rows);
      if (rows.length) setScanned(true);
    } catch { /* keep silent — empty state covers it */ }
  }, [evidenceId]);

  useEffect(() => { load(); }, [load]);

  async function scan() {
    setScanning(true); setError('');
    try {
      const r = await threatHuntingAPI.scanEvidence(evidenceId);
      setRulesChecked(r.data.rules_checked ?? null);
      await load();
      setScanned(true);
    } catch (e) {
      setError(e.response?.data?.error || e.message || 'Scan error');
    } finally { setScanning(false); }
  }

  return (
    <Card
      accent={C.yara} icon={Shield}
      title="YARA - this evidence"
      desc="Scans the file in this collection with all active YARA rules."
      action={
        <Button variant="primary" size="sm" icon={scanning ? undefined : Scan} loading={scanning} onClick={scan}>
          Scan this evidence
        </Button>
      }
    >
      {error && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 12px', background: 'color-mix(in srgb, var(--fl-danger) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 25%, transparent)', borderRadius: 8, color: 'var(--fl-danger)', fontSize: 12, marginBottom: 12 }}>
          <AlertCircle size={14} /> {error}
        </div>
      )}

      {rulesChecked != null && (
        <p style={{ fontSize: 11, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', margin: '0 0 10px' }}>
          {rulesChecked} rule{rulesChecked !== 1 ? 's' : ''} tested{rulesChecked !== 1 ? 's' : ''}
        </p>
      )}

      {results.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '24px 0', color: 'var(--fl-dim)' }}>
          {scanned
            ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7, color: 'var(--fl-ok)', fontSize: 13 }}><CheckCircle2 size={15} /> No matches - clean file</span>
            : <span style={{ fontSize: 13 }}>Not scanned yet.</span>}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {results.map(m => {
            const strings = parseStrings(m.matched_strings);
            return (
              <div key={m.id} style={{ background: C.surface, border: `1px solid color-mix(in srgb, ${C.match} 35%, var(--fl-border))`, borderRadius: 8, padding: '10px 14px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: strings.length ? 8 : 0 }}>
                  <AlertCircle size={13} style={{ color: C.match, flexShrink: 0 }} />
                  <span style={{ fontWeight: 700, color: C.match, fontSize: 13, flex: 1 }}>{m.rule_name}</span>
                  <span style={{ fontSize: 10, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{fmtDate(m.scanned_at)}</span>
                </div>
                {strings.length > 0 && (
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                    <thead>
                      <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                        {['Identifier', 'Offset', 'Data'].map(h => (
                          <th key={h} style={{ textAlign: 'left', padding: '3px 8px', color: 'var(--fl-dim)', fontWeight: 600 }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {strings.map((s, i) => (
                        <tr key={i} style={{ borderBottom: `1px solid ${C.border}` }}>
                          <td style={{ padding: '3px 8px', color: C.yara }}>{s.identifier}</td>
                          <td style={{ padding: '3px 8px', color: 'var(--fl-dim)' }}>0x{Number(s.offset || 0).toString(16)}</td>
                          <td style={{ padding: '3px 8px', color: 'var(--fl-text)', maxWidth: 380, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.data}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            );
          })}
        </div>
      )}
    </Card>
  );
}

const ARTIFACT_COLORS = {
  evtx: 'var(--fl-accent)', hayabusa: 'var(--fl-danger)', mft: 'var(--fl-purple)', prefetch: 'var(--fl-ok)',
  lnk: 'var(--fl-warn)', registry: 'var(--fl-pink)', amcache: 'var(--fl-gold)',
};
function ac(t) { return ARTIFACT_COLORS[t] || 'var(--fl-dim)'; }

// Sigma hunting runs on the case timeline (collection_timeline).
function SigmaSection({ caseId }) {
  const [rules, setRules]   = useState([]);
  const [ruleId, setRuleId] = useState('');
  const [hunting, setHunting] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(null);
  const [result, setResult] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [openHist, setOpenHist] = useState({});

  useEffect(() => {
    threatHuntingAPI.sigmaRules().then(r => setRules(r.data.rules || [])).catch(() => {});
  }, []);
  const loadHistory = useCallback(() => {
    threatHuntingAPI.sigmaHunts(caseId).then(r => setHistory(r.data.hunts || [])).catch(() => {});
  }, [caseId]);
  useEffect(() => { loadHistory(); }, [loadHistory]);

  async function hunt() {
    if (!ruleId) return;
    setHunting(true); setResult(null);
    try {
      const r = await threatHuntingAPI.sigmaHunt(caseId, ruleId);
      setResult(r.data);
      loadHistory();
    } catch (e) {
      setResult({ error: e.response?.data?.error || 'Hunt error' });
    } finally { setHunting(false); }
  }

  async function scanAll() {
    setScanning(true); setScanResult(null); setProgress(null);
    try {
      const token = localStorage.getItem('heimdall_token');
      const resp = await fetch(`/api/threat-hunting/sigma/scan-case/${caseId}`, {
        method: 'POST', headers: { Authorization: `Bearer ${token}` },
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
            if (ev.type === 'done')  { setProgress(null); setScanResult(ev); loadHistory(); }
            if (ev.type === 'error') setScanResult({ error: ev.error });
          } catch { /* skip malformed SSE line */ }
        }
      }
    } catch {
      setScanResult({ error: 'Scan error' });
    } finally { setScanning(false); setProgress(null); }
  }

  const pct = progress && progress.total > 0 ? Math.round((progress.current / progress.total) * 100) : 0;

  return (
    <Card
      accent={C.sigma} icon={FileCode2}
      title="Sigma - hunt on the case timeline"
      desc="Sigma hunting runs on the full case timeline (all parsed artifacts)."
      action={
        <Button variant="secondary" size="sm" icon={scanning ? undefined : Scan} loading={scanning} onClick={scanAll}>
          All rules
        </Button>
      }
    >
      {progress && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--fl-dim)', marginBottom: 5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '80%' }}>{progress.current}/{progress.total} — {progress.name}</span>
            <span>{pct}%</span>
          </div>
          <div style={{ height: 5, background: 'var(--fl-border)', borderRadius: 3, overflow: 'hidden' }}>
            <div style={{ height: '100%', width: `${pct}%`, background: C.sigma, borderRadius: 3, transition: 'width 0.15s ease' }} />
          </div>
        </div>
      )}

      {scanResult && (
        <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, padding: 14, marginBottom: 14 }}>
          {scanResult.error ? (
            <p style={{ margin: 0, color: 'var(--fl-danger)', fontSize: 13 }}>{scanResult.error}</p>
          ) : (
            <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', fontSize: 13 }}>
              <span><strong>{scanResult.rules_checked}</strong> rules tested</span>
                <span style={{ color: scanResult.rules_matched > 0 ? 'var(--fl-danger)' : 'var(--fl-ok)' }}>
                <strong>{scanResult.rules_matched}</strong> matches
              </span>
              <span><strong>{scanResult.total_matches}</strong> events</span>
            </div>
          )}
        </div>
      )}

      <div style={{ display: 'flex', gap: 10, alignItems: 'flex-end', flexWrap: 'wrap', marginBottom: result ? 14 : 0 }}>
        <div style={{ flex: 1, minWidth: 220 }}>
          <label className="fl-label" style={{ display: 'block', marginBottom: 5 }}>Sigma rule</label>
          <select value={ruleId} onChange={e => { setRuleId(e.target.value); setResult(null); }} className="fl-input">
            <option value="">— Select a rule —</option>
            {rules.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
          </select>
        </div>
        <Button variant="primary" size="sm" icon={hunting ? undefined : Search} loading={hunting} disabled={!ruleId} onClick={hunt}>
          Lancer la chasse
        </Button>
      </div>

      {result && !result.error && (
        <div style={{ background: result.match_count > 0 ? 'color-mix(in srgb, var(--fl-danger) 8%, transparent)' : 'color-mix(in srgb, var(--fl-ok) 8%, transparent)', border: `1px solid ${result.match_count > 0 ? 'color-mix(in srgb, var(--fl-danger) 35%, transparent)' : 'color-mix(in srgb, var(--fl-ok) 35%, transparent)'}`, borderRadius: 8, padding: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: result.events?.length ? 12 : 0 }}>
            {result.match_count > 0 ? <AlertCircle size={15} style={{ color: 'var(--fl-danger)' }} /> : <CheckCircle2 size={15} style={{ color: 'var(--fl-ok)' }} />}
            <span style={{ fontWeight: 700, fontSize: 14, color: result.match_count > 0 ? 'var(--fl-danger)' : 'var(--fl-ok)' }}>
              {result.match_count} matching event{result.match_count !== 1 ? 's' : ''}{result.match_count !== 1 ? '' : ''}
            </span>
            <span style={{ fontSize: 12, color: 'var(--fl-dim)' }}>— {result.rule_name}</span>
          </div>
          {result.events?.length > 0 && (
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
                  {result.events.map((e, i) => (
                    <tr key={i} style={{ borderBottom: `1px solid ${C.border}` }}>
                      <td style={{ padding: '4px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)', whiteSpace: 'nowrap' }}>{e.timestamp ? fmtLocal(e.timestamp) : '—'}</td>
                      <td style={{ padding: '4px 8px' }}>{e.artifact_type && <Badge color={ac(e.artifact_type)}>{e.artifact_type}</Badge>}</td>
                      <td style={{ padding: '4px 8px', color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.source || '—'}</td>
                      <td style={{ padding: '4px 8px', color: 'var(--fl-text)', maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.description || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {result.match_count > result.events.length && (
                <p style={{ margin: '8px 0 0', fontSize: 11, color: 'var(--fl-muted)' }}>Showing {result.events.length} of {result.match_count} results</p>
              )}
            </div>
          )}
        </div>
      )}
      {result?.error && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 12px', background: 'color-mix(in srgb, var(--fl-danger) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 25%, transparent)', borderRadius: 8, color: 'var(--fl-danger)', fontSize: 12 }}>
          <AlertCircle size={14} /> {result.error}
        </div>
      )}

      {history.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <h4 style={{ margin: '0 0 10px', fontSize: 12, fontWeight: 700, color: 'var(--fl-dim)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <Clock size={12} /> Hunt history
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {history.map(h => {
              const isOpen = openHist[h.id];
              return (
                <div key={h.id} style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, overflow: 'hidden' }}>
                  <button onClick={() => setOpenHist(x => ({ ...x, [h.id]: !x[h.id] }))}
                    style={{ width: '100%', background: 'none', border: 'none', cursor: 'pointer', padding: '8px 12px', display: 'flex', alignItems: 'center', gap: 10 }}>
                    {isOpen ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                    <span style={{ flex: 1, textAlign: 'left', fontSize: 12, color: 'var(--fl-text)' }}>{h.rule_name}</span>
                    {h.match_count > 0
                      ? <Badge variant="danger">{h.match_count} hits</Badge>
                      : <Badge variant="ok">clean</Badge>}
                    <span style={{ fontSize: 10, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{fmtDate(h.created_at)}</span>
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </Card>
  );
}

export default function CollectionThreatHuntTab({ caseId, collectionId, collName }) {
  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '18px 22px' }}>
      <div style={{ maxWidth: 1000, margin: '0 auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
          <Crosshair size={18} style={{ color: 'var(--fl-accent)' }} />
          <h2 style={{ margin: 0, fontSize: 18, fontWeight: 700, color: 'var(--fl-text)', fontFamily: 'var(--f-display, inherit)' }}>Threat hunting</h2>
        </div>
        <p style={{ margin: '0 0 18px', fontSize: 12.5, color: 'var(--fl-dim)' }}>
          Launch a YARA / Sigma hunt directly on this collection{collName ? ` - ${collName}` : ''}.
          Rules are managed in the Settings panel.
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <YaraSection evidenceId={collectionId} />
          <SigmaSection caseId={caseId} />
        </div>
      </div>
    </div>
  );
}
