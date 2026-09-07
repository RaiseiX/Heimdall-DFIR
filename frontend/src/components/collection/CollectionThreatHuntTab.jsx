import { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Crosshair, Scan, Search, AlertCircle, CheckCircle2,
  ChevronDown, ChevronRight, Clock, Shield, FileCode2,
} from 'lucide-react';
import { threatHuntingAPI } from '../../utils/api';
import { Button, Badge, Alert, CommandPalette, FilterChip } from '../ui';
import { fmtLocal } from '../../utils/formatters';
import { LEVEL_ORDER, levelColor, ruleSubline, facetCounts, pickerItems } from '../../utils/sigmaRulePicker';
import YaraRulesPanel from '../threathunt/YaraRulesPanel';
import { VERDICT_CHOICES, verdictLabel, verdictColor, isFaded, parseEvents } from './verdictDisplay';

const C = {
  yara:   'var(--fl-accent)',
  sigma:  'var(--fl-purple)',
  match:  'var(--fl-danger)',
  ok:     'var(--fl-ok)',
  surface:'var(--fl-card)',
  border: 'var(--fl-border)',
};

const FS_MICRO = 9;
const FS_XS = 10;
const FS_SM = 11;
const FS_MD = 12;

const REASON_STYLE = {
  display: 'block', marginTop: 4, color: 'var(--fl-muted)',
  fontFamily: 'var(--f-mono, "IBM Plex Mono", monospace)', fontSize: FS_SM,
};
const ALERT_STYLE = { marginBottom: 12 };
const HIST_BODY_STYLE = { borderTop: '1px solid var(--fl-border)', padding: 12 };
const SECT_STYLE = { fontSize: FS_SM, letterSpacing: '.04em', textTransform: 'uppercase',
  color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "IBM Plex Mono", monospace)', margin: '0 0 7px' };
const SEG_STYLE = { display: 'inline-flex', border: '1px solid var(--fl-border3)',
  borderRadius: 6, overflow: 'hidden' };
const NOTE_STYLE = { width: '100%', marginTop: 11 };
const ATTRIB_STYLE = { fontSize: FS_SM, color: 'var(--fl-muted)',
  fontFamily: 'var(--f-mono, "IBM Plex Mono", monospace)', margin: '9px 0 0' };
const SAMPLE_SECT_STYLE = { ...SECT_STYLE, margin: '15px 0 7px' };
const RUNS_STYLE = { fontSize: FS_XS, color: 'var(--fl-muted)',
  fontFamily: 'var(--f-mono, "IBM Plex Mono", monospace)' };

const segButtonStyle = (active, color) => ({
  background: active ? `color-mix(in srgb, ${color} 15%, transparent)` : 'none',
  border: 'none', borderRight: '1px solid var(--fl-border3)',
  color: active ? color : 'var(--fl-dim)', fontFamily: 'inherit', fontSize: FS_MD,
  fontWeight: active ? 600 : 400, padding: '5px 12px', cursor: 'pointer',
});

const verdictPillStyle = (color) => ({
  padding: '1px 6px', borderRadius: 3, fontSize: FS_MICRO, fontWeight: 700,
  fontFamily: 'var(--f-mono, "IBM Plex Mono", monospace)',
  background: `color-mix(in srgb, ${color} 13%, transparent)`, color,
  border: `1px solid color-mix(in srgb, ${color} 31%, transparent)`,
});

const HIST_ROW_STYLE = { background: 'var(--fl-card)', border: '1px solid var(--fl-border)',
  borderRadius: 8, overflow: 'hidden' };
const HIST_HEAD_STYLE = { width: '100%', background: 'none', border: 'none', cursor: 'pointer',
  padding: '8px 12px', display: 'flex', alignItems: 'center', gap: 10 };
const SAMPLE_WRAP_STYLE = { overflowX: 'auto' };
const SAMPLE_TABLE_STYLE = { width: '100%', borderCollapse: 'collapse', fontSize: FS_MD };
const SAMPLE_HEAD_ROW_STYLE = { borderBottom: '1px solid var(--fl-border)' };
const SAMPLE_TH_STYLE = { textAlign: 'left', padding: '5px 8px', color: 'var(--fl-dim)', fontWeight: 600 };
const SAMPLE_TD_STYLE = { padding: '4px 8px' };
const SAMPLE_TD_MONO_STYLE = { padding: '4px 8px', color: 'var(--fl-dim)', whiteSpace: 'nowrap',
  fontFamily: 'var(--f-mono, "IBM Plex Mono", monospace)' };
const SAMPLE_TD_TRUNC_STYLE = { padding: '4px 8px', color: 'var(--fl-text)', maxWidth: 400,
  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' };

const PICKED_SUB_STYLE = { margin: '6px 0 0', fontSize: FS_SM, color: 'var(--fl-muted)',
  fontFamily: 'var(--f-mono, "IBM Plex Mono", monospace)' };
const RETIRED_CHIP_STYLE = { marginLeft: 'auto' };
const MAX_PRODUCT_FACETS = 4;

function facetToggle(list, setList, value) {
  setList(list.includes(value) ? list.filter(v => v !== value) : [...list, value]);
}

const histNameStyle = (faded) => ({
  flex: 1, textAlign: 'left', fontSize: FS_MD,
  color: faded ? 'var(--fl-muted)' : 'var(--fl-text)',
});

export function huntDate(h) {
  return h?.hunted_at ?? h?.created_at ?? null;
}
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

function YaraSection({ evidenceId }) {
  const [results, setResults] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [scanned, setScanned]   = useState(false);
  const [error, setError]       = useState('');
  const [outcome, setOutcome] = useState(null);

  const load = useCallback(async () => {
    try {
      const r = await threatHuntingAPI.yaraResultsEvidence(evidenceId);
      const rows = r.data.results || [];
      setResults(rows);
      if (rows.length) setScanned(true);
    } catch { }
  }, [evidenceId]);

  useEffect(() => { load(); }, [load]);

  async function scan() {
    setScanning(true); setError(''); setOutcome(null);
    try {
      const r = await threatHuntingAPI.scanEvidence(evidenceId);
      setOutcome(r.data);
      await load();
      setScanned(true);
    } catch (e) {
      setError(e.response?.data?.error || e.message || 'Erreur de scan');
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

      {outcome && (outcome.status === 'failed' || outcome.status === 'partial') && (
        <Alert
          variant={outcome.status === 'failed' ? 'danger' : 'warn'}
          message={
            <>
              {outcome.message}
              {outcome.error_reason && (
                <span style={REASON_STYLE}>motif dominant : {outcome.error_reason}</span>
              )}
            </>
          }
          style={ALERT_STYLE}
        />
      )}

      {results.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '24px 0', color: 'var(--fl-dim)' }}>
          {outcome?.status === 'failed'
            ? null
            : scanned
              ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7, color: 'var(--fl-ok)', fontSize: 13 }}><CheckCircle2 size={15} /> {outcome?.message || 'Aucune correspondance'}</span>
              : <span style={{ fontSize: 13 }}>Pas encore analysé.</span>}
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
  const [pickerOpen, setPickerOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [levels, setLevels] = useState([]);
  const [products, setProducts] = useState([]);
  const [hideRetired, setHideRetired] = useState(true);

  useEffect(() => {
    threatHuntingAPI.sigmaRules().then(r => setRules(r.data.rules || [])).catch(() => {});
  }, []);

  const counts = useMemo(() => facetCounts(rules), [rules]);
  const picked = useMemo(() => {
    const p = pickerItems(rules, { search: query, levels, products, hideRetired });
    return {
      ...p,
      items: p.items.map(i => (i.retired
        ? { ...i, categoryLabel: 'retirée amont', categoryColor: 'var(--fl-warn)' }
        : i)),
    };
  }, [rules, query, levels, products, hideRetired]);
  const selectedRule = rules.find(r => r.id === ruleId) || null;
  const loadHistory = useCallback(() => {
    threatHuntingAPI.sigmaHunts(caseId).then(r => setHistory(r.data.hunts || [])).catch(() => {});
  }, [caseId]);
  useEffect(() => { loadHistory(); }, [loadHistory]);

  async function saveVerdict(ruleId, status, note) {
    try {
      await threatHuntingAPI.sigmaSetVerdict(caseId, ruleId, status, note || null);
      loadHistory();
    } catch { }
  }

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
          } catch { }
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
          <Button variant="secondary" icon={Search} onClick={() => { setQuery(''); setPickerOpen(true); }}>
            {selectedRule ? selectedRule.name : 'Choisir une règle'}
          </Button>
          {selectedRule && <p style={PICKED_SUB_STYLE}>{ruleSubline(selectedRule)}</p>}
        </div>
        <Button variant="primary" size="sm" icon={hunting ? undefined : Search} loading={hunting} disabled={!ruleId} onClick={hunt}>
          Lancer la chasse
        </Button>
      </div>

      <CommandPalette
        open={pickerOpen}
        onClose={() => setPickerOpen(false)}
        items={picked.items}
        onSelect={item => { setRuleId(item.id); setResult(null); }}
        onQueryChange={setQuery}
        title="Règles Sigma"
        placeholder="Chercher une règle — nom, technique, catégorie"
        toolbar={
          <>
            {LEVEL_ORDER.filter(l => counts.levels[l]).map(l => (
              <FilterChip key={l} active={levels.includes(l)} color={levelColor(l)} count={counts.levels[l]}
                onClick={() => facetToggle(levels, setLevels, l)}>
                {l}
              </FilterChip>
            ))}
            {counts.products.slice(0, MAX_PRODUCT_FACETS).map(p => (
              <FilterChip key={p.product} active={products.includes(p.product)} count={p.count}
                onClick={() => facetToggle(products, setProducts, p.product)}>
                {p.product}
              </FilterChip>
            ))}
            {counts.retired > 0 && (
              <FilterChip active={hideRetired} color="var(--fl-warn)" count={counts.retired}
                style={RETIRED_CHIP_STYLE} onClick={() => setHideRetired(v => !v)}>
                masquer retirées amont
              </FilterChip>
            )}
          </>
        }
        tally={
          <>
            <span>{picked.matched === picked.total
              ? `${picked.total.toLocaleString('fr-FR')} règles`
              : `${picked.matched.toLocaleString('fr-FR')} règles sur ${picked.total.toLocaleString('fr-FR')}`}</span>
            <span>{picked.items.length} affichées</span>
          </>
        }
        note={picked.hidden > 0
          ? `${picked.hidden.toLocaleString('fr-FR')} autres correspondances non affichées — affinez la recherche ou une facette.`
          : null}
      />

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
              const label = verdictLabel(h.verdict_status);
              const color = verdictColor(h.verdict_status);
              const events = parseEvents(h.matched_events);
              return (
                <div key={h.id} style={HIST_ROW_STYLE}>
                  <button onClick={() => setOpenHist(x => ({ ...x, [h.id]: !x[h.id] }))} style={HIST_HEAD_STYLE}>
                    {isOpen ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                    <span style={histNameStyle(isFaded(h.verdict_status))}>{h.rule_name}</span>
                    {label && <span style={verdictPillStyle(color)}>{label.toUpperCase()}</span>}
                    {h.run_count > 1 && <span style={RUNS_STYLE}>{h.run_count} passages</span>}
                    {h.match_count > 0
                      ? <Badge variant="danger">{h.match_count} hits</Badge>
                      : <Badge variant="ok">clean</Badge>}
                    <span style={RUNS_STYLE}>{fmtDate(huntDate(h))}</span>
                  </button>

                  {isOpen && (
                    <div style={HIST_BODY_STYLE}>
                      {h.verdict_stale && (
                        <Alert variant="warn" style={ALERT_STYLE}
                          message="La règle a été modifiée depuis ce verdict — il ne s'applique plus à son contenu actuel." />
                      )}

                      <p style={SECT_STYLE}>Verdict</p>
                      <div style={SEG_STYLE}>
                        {VERDICT_CHOICES.map(c => (
                          <button key={c.status} onClick={() => saveVerdict(h.rule_id, c.status, h.verdict_note)}
                            style={segButtonStyle(h.verdict_status === c.status, verdictColor(c.status))}>
                            {c.label}
                          </button>
                        ))}
                      </div>

                      <input className="fl-input" style={NOTE_STYLE} defaultValue={h.verdict_note || ''}
                        placeholder="Motif — pourquoi ce verdict ? (facultatif)"
                        onBlur={e => h.verdict_status !== 'new' && saveVerdict(h.rule_id, h.verdict_status, e.target.value)} />

                      {label && (
                        <p style={ATTRIB_STYLE}>
                          {label.toLowerCase()}{h.verdict_by ? ` par ${h.verdict_by}` : ''}
                          {h.verdict_decided_at ? ` · ${fmtDate(h.verdict_decided_at)}` : ''}
                        </p>
                      )}

                      {events.length > 0 && (
                        <>
                          <p style={SAMPLE_SECT_STYLE}>Échantillon — {events.length} sur {h.match_count}</p>
                          <div style={SAMPLE_WRAP_STYLE}>
                            <table style={SAMPLE_TABLE_STYLE}>
                              <thead>
                                <tr style={SAMPLE_HEAD_ROW_STYLE}>
                                  {['Horodatage', 'Type', 'Description'].map(t => (
                                    <th key={t} style={SAMPLE_TH_STYLE}>{t}</th>
                                  ))}
                                </tr>
                              </thead>
                              <tbody>
                                {events.slice(0, 10).map((e, i) => (
                                  <tr key={i} style={SAMPLE_HEAD_ROW_STYLE}>
                                    <td style={SAMPLE_TD_MONO_STYLE}>{e.timestamp ? fmtLocal(e.timestamp) : '—'}</td>
                                    <td style={SAMPLE_TD_STYLE}>{e.artifact_type && <Badge color={ac(e.artifact_type)}>{e.artifact_type}</Badge>}</td>
                                    <td style={SAMPLE_TD_TRUNC_STYLE}>{e.description || '—'}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </Card>
  );
}

const PANES = [
  { id: 'scan',  label: 'Scan de la preuve' },
  { id: 'yara',  label: 'Bibliothèque YARA' },
  { id: 'sigma', label: 'Chasse Sigma' },
];

const SEG_ROW_STYLE = { display: 'flex', gap: 18, alignItems: 'baseline', margin: '0 0 16px' };
const segStyle = (active) => ({
  background: 'none', border: 'none', cursor: 'pointer', padding: '0 0 3px',
  fontFamily: 'var(--f-mono, "IBM Plex Mono", monospace)', fontSize: FS_SM,
  color: active ? 'var(--fl-text)' : 'var(--fl-muted)',
  borderBottom: `1px solid ${active ? 'var(--fl-accent)' : 'transparent'}`,
});

export default function CollectionThreatHuntTab({ caseId, collectionId, collName }) {
  const [pane, setPane] = useState('scan');

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '18px 22px' }}>
      <div style={{ maxWidth: 1000, margin: '0 auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
          <Crosshair size={18} style={{ color: 'var(--fl-accent)' }} />
          <h2 style={{ margin: 0, fontSize: 18, fontWeight: 700, color: 'var(--fl-text)', fontFamily: 'var(--f-display, inherit)' }}>Threat hunting</h2>
        </div>
        <p style={{ margin: '0 0 18px', fontSize: 12.5, color: 'var(--fl-dim)' }}>
          Launch a YARA / Sigma hunt directly on this collection{collName ? ` - ${collName}` : ''}.
        </p>

        <div style={SEG_ROW_STYLE}>
          {PANES.map(p => (
            <button key={p.id} onClick={() => setPane(p.id)} style={segStyle(pane === p.id)}>
              {p.label}
            </button>
          ))}
        </div>

        {pane === 'scan'  && <YaraSection evidenceId={collectionId} />}
        {pane === 'yara'  && <YaraRulesPanel />}
        {pane === 'sigma' && <SigmaSection caseId={caseId} />}
      </div>
    </div>
  );
}
