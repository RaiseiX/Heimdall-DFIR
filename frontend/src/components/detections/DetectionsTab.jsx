import { useState, useCallback, useEffect, useRef } from 'react';
import {
  Clock, FileWarning, Radio, Shield, Activity,
  ChevronDown, ChevronRight, RefreshCw, CheckCircle2, Copy, Play,
} from 'lucide-react';
import { detectionsAPI } from '../../utils/api';
import { Button, EmptyState } from '../ui';
import { useDateFormat } from '../../hooks/useDateFormat';

const SEV = {
  CRITIQUE: { color: 'var(--fl-danger)' },
  ÉLEVÉ:    { color: 'var(--fl-warn)' },
  MOYEN:    { color: 'var(--fl-gold)' },
  FAIBLE:   { color: '#22c55e' },
};
const SEV_ORDER = ['CRITIQUE', 'ÉLEVÉ', 'MOYEN', 'FAIBLE'];

const HAY_LEVEL_COL = {
  critical: 'var(--fl-danger)',
  high:     'var(--fl-warn)',
  medium:   'var(--fl-gold)',
  low:      '#22c55e',
};

const TH_STYLE = {
  position: 'sticky', top: 0, zIndex: 2,
  padding: '7px 8px', fontFamily: 'monospace', fontSize: 10,
  fontWeight: 700, letterSpacing: '0.07em', textTransform: 'uppercase',
  color: 'var(--fl-accent)', background: 'var(--fl-bg)', whiteSpace: 'nowrap',
  borderBottom: '1px solid var(--fl-sep)', textAlign: 'left',
};

const TD = { padding: '5px 8px', borderBottom: '1px solid #0f1a2a', verticalAlign: 'middle' };

function topSeverity(items) {
  for (const sev of SEV_ORDER) {
    if (items.some(it => it.severity === sev)) return sev;
  }
  return null;
}

function countsBySev(items) {
  const c = { CRITIQUE: 0, ÉLEVÉ: 0, MOYEN: 0, FAIBLE: 0 };
  for (const it of items) if (it.severity in c) c[it.severity]++;
  return c;
}

function SevBadge({ severity }) {
  const s = SEV[severity] || SEV.FAIBLE;
  return (
    <span style={{
      display: 'inline-block', padding: '1px 7px', borderRadius: 4,
      fontSize: 10, fontWeight: 700, letterSpacing: '0.05em', fontFamily: 'monospace',
      background: `${s.color}18`, border: `1px solid ${s.color}40`, color: s.color,
    }}>
      {severity}
    </span>
  );
}

function CopyCell({ value, style, maxWidth = 200 }) {
  const [hover, setHover] = useState(false);
  const [copied, setCopied] = useState(false);

  const copy = useCallback((e) => {
    e.stopPropagation();
    navigator.clipboard?.writeText(value).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, [value]);

  return (
    <span
      style={{ display: 'flex', alignItems: 'center', gap: 4 }}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
    >
      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth, ...style }} title={value || undefined}>
        {value || '—'}
      </span>
      {value && hover && (
        <button onClick={copy} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: copied ? '#22c55e' : 'var(--fl-accent)', flexShrink: 0 }} title="Copier">
          {copied ? <CheckCircle2 size={10} /> : <Copy size={10} />}
        </button>
      )}
    </span>
  );
}

function Section({ icon: Icon, title, badge, severity, children, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen);
  const accent = severity ? (SEV[severity]?.color ?? '#1e3a5f') : '#1e3a5f';
  return (
    <div style={{
      marginBottom: 10, background: '#0f1623',
      border: '1px solid #1a2540', borderLeft: `3px solid ${accent}`,
      borderRadius: 6, overflow: 'hidden',
    }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: '100%', display: 'flex', alignItems: 'center', gap: 8,
          padding: '9px 12px', background: 'none', border: 'none', cursor: 'pointer',
          color: 'var(--fl-on-dark)', fontFamily: 'monospace', fontWeight: 700, fontSize: 11,
          textTransform: 'uppercase', letterSpacing: '0.05em', textAlign: 'left',
        }}
      >
        {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        <Icon size={13} style={{ flexShrink: 0, color: accent }} />
        <span style={{ flex: 1 }}>{title}</span>
        {badge !== undefined && (
          <span style={{
            background: badge > 0 ? '#ef444418' : '#22c55e18',
            color: badge > 0 ? 'var(--fl-danger)' : '#22c55e',
            border: `1px solid ${badge > 0 ? '#ef444440' : '#22c55e40'}`,
            borderRadius: 10, padding: '1px 7px', fontSize: 10, fontWeight: 700, fontFamily: 'monospace',
          }}>
            {badge}
          </span>
        )}
      </button>
      {open && <div style={{ padding: '0 12px 12px' }}>{children}</div>}
    </div>
  );
}

function DetTable({ headers, children }) {
  return (
    <div style={{ overflowX: 'auto', borderRadius: 4, border: '1px solid var(--fl-sep)', maxHeight: 400, overflowY: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, background: '#0b111a' }}>
        <thead>
          <tr>
            {headers.map(h => <th key={h} style={TH_STYLE}>{h}</th>)}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

function TimestompingSection({ caseId, runSignal, hiddenSevs, onComplete, onCounts }) {
  const { fmtDateTime } = useDateFormat();
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(false);
  const [threshold, setThr]   = useState(1);
  const cbRef = useRef({ onComplete, onCounts });
  useEffect(() => { cbRef.current = { onComplete, onCounts }; });

  const run = useCallback(async () => {
    setLoading(true);
    try {
      const r = await detectionsAPI.timestomping(caseId, { threshold_days: threshold });
      setData(r.data);
    } catch {
      setData({ items: [], count: 0 });
    } finally {
      setLoading(false);
      cbRef.current.onComplete?.();
    }
  }, [caseId, threshold]);

  useEffect(() => { if (runSignal > 0) run(); }, [runSignal]);

  const items = data?.items ?? [];
  useEffect(() => { if (data) cbRef.current.onCounts?.(countsBySev(items)); }, [data]);

  const visible = items.filter(it => !hiddenSevs.has(it.severity));

  return (
    <Section icon={Clock} title="Timestomping ($SIA vs $FN)" badge={data ? items.length : undefined} severity={topSeverity(items)}>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 10 }}>
        <label style={{ color: 'var(--fl-accent)', fontSize: 11, fontFamily: 'monospace' }}>Seuil (jours) :</label>
        <select
          value={threshold}
          onChange={e => setThr(Number(e.target.value))}
          style={{ background: 'var(--fl-bg)', border: '1px solid #1a2540', borderRadius: 4, color: 'var(--fl-on-dark)', padding: '3px 8px', fontSize: 11, fontFamily: 'monospace' }}
        >
          {[0, 1, 7, 30].map(v => <option key={v} value={v}>{v === 0 ? 'Tout écart' : `${v} jour(s)`}</option>)}
        </select>
        <Button size="sm" icon={loading ? undefined : RefreshCw} loading={loading} onClick={run} disabled={loading}>
          Analyser
        </Button>
      </div>

      {!data && !loading && (
        <p style={{ color: 'var(--fl-subtle)', fontSize: 11, fontFamily: 'monospace', margin: 0 }}>Cliquez sur Analyser pour détecter les incohérences de dates MFT ($SIA ≠ $FN).</p>
      )}
      {data && items.length === 0 && (
        <EmptyState icon={CheckCircle2} title="Aucun timestomping détecté" subtitle="Aucune incohérence $SIA / $FN avec ce seuil." />
      )}
      {visible.length > 0 && (
        <DetTable headers={['Fichier', 'Source', '$SIA Created', '$FN Created', 'Écart (j)', 'Sévérité']}>
          {visible.map((it, i) => (
            <tr key={i} style={{ background: i % 2 ? 'transparent' : 'rgba(255,255,255,0.02)' }}>
              <td style={{ ...TD, color: 'var(--fl-on-dark)' }}><CopyCell value={it.description} maxWidth={220} /></td>
              <td style={{ ...TD, color: 'var(--fl-accent)' }}>{it.source || '—'}</td>
              <td style={{ ...TD, color: 'var(--fl-on-dark)', whiteSpace: 'nowrap', fontFamily: 'monospace', fontSize: 11 }}>{fmtDateTime(it.sia_created)}</td>
              <td style={{ ...TD, color: 'var(--fl-on-dark)', whiteSpace: 'nowrap', fontFamily: 'monospace', fontSize: 11 }}>{fmtDateTime(it.fn_created)}</td>
              <td style={{ ...TD, color: 'var(--fl-gold)', fontWeight: 700, fontFamily: 'monospace' }}>{it.diff_days != null ? it.diff_days.toFixed(1) : '—'}</td>
              <td style={TD}><SevBadge severity={it.severity} /></td>
            </tr>
          ))}
        </DetTable>
      )}
    </Section>
  );
}

function DoubleExtSection({ caseId, runSignal, hiddenSevs, onComplete, onCounts }) {
  const { fmtDateTime } = useDateFormat();
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(false);
  const cbRef = useRef({ onComplete, onCounts });
  useEffect(() => { cbRef.current = { onComplete, onCounts }; });

  const run = useCallback(async () => {
    setLoading(true);
    try {
      const r = await detectionsAPI.doubleExt(caseId);
      setData(r.data);
    } catch {
      setData({ items: [], count: 0 });
    } finally {
      setLoading(false);
      cbRef.current.onComplete?.();
    }
  }, [caseId]);

  useEffect(() => { if (runSignal > 0) run(); }, [runSignal]);

  const items = data?.items ?? [];
  useEffect(() => { if (data) cbRef.current.onCounts?.(countsBySev(items)); }, [data]);

  const visible = items.filter(it => !hiddenSevs.has(it.severity));

  return (
    <Section icon={FileWarning} title="Double Extension (*.pdf.exe, *.docx.scr…)" badge={data ? items.length : undefined} severity={topSeverity(items)}>
      <div style={{ marginBottom: 10 }}>
        <Button size="sm" icon={loading ? undefined : RefreshCw} loading={loading} onClick={run} disabled={loading}>
          Scanner
        </Button>
      </div>

      {!data && !loading && (
        <p style={{ color: 'var(--fl-subtle)', fontSize: 11, fontFamily: 'monospace', margin: 0 }}>Cliquez sur Scanner pour chercher les fichiers à double extension dangereuse.</p>
      )}
      {data && items.length === 0 && (
        <EmptyState icon={CheckCircle2} title="Aucune double extension détectée" subtitle="Aucun fichier à double extension dangereuse trouvé." />
      )}
      {visible.length > 0 && (
        <DetTable headers={['Fichier', 'Ext. leurre', 'Ext. danger', 'Source', 'Horodatage', 'Sévérité']}>
          {visible.map((it, i) => (
            <tr key={i} style={{ background: i % 2 ? 'transparent' : 'rgba(255,255,255,0.02)' }}>
              <td style={{ ...TD, color: 'var(--fl-on-dark)' }}><CopyCell value={it.description} maxWidth={240} /></td>
              <td style={{ ...TD, color: 'var(--fl-accent)', fontFamily: 'monospace' }}>.{it.decoy_ext}</td>
              <td style={{ ...TD, color: 'var(--fl-danger)', fontWeight: 700, fontFamily: 'monospace' }}>.{it.danger_ext}</td>
              <td style={{ ...TD, color: 'var(--fl-accent)' }}>{it.source || '—'}</td>
              <td style={{ ...TD, color: 'var(--fl-on-dark)', whiteSpace: 'nowrap', fontFamily: 'monospace', fontSize: 11 }}>{fmtDateTime(it.timestamp)}</td>
              <td style={TD}><SevBadge severity={it.severity} /></td>
            </tr>
          ))}
        </DetTable>
      )}
    </Section>
  );
}

function BeaconingSection({ caseId, runSignal, hiddenSevs, onComplete, onCounts }) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(false);
  const [minScore, setMin]    = useState(60);
  const cbRef = useRef({ onComplete, onCounts });
  useEffect(() => { cbRef.current = { onComplete, onCounts }; });

  const run = useCallback(async () => {
    setLoading(true);
    try {
      const r = await detectionsAPI.beaconing(caseId, { min_score: minScore });
      setData(r.data);
    } catch {
      setData({ candidates: [], count: 0 });
    } finally {
      setLoading(false);
      cbRef.current.onComplete?.();
    }
  }, [caseId, minScore]);

  useEffect(() => { if (runSignal > 0) run(); }, [runSignal]);

  const items = data?.candidates ?? [];
  useEffect(() => { if (data) cbRef.current.onCounts?.(countsBySev(items)); }, [data]);

  const visible = items.filter(it => !hiddenSevs.has(it.severity));

  function fmtInterval(sec) {
    if (sec < 60)   return `${sec.toFixed(0)}s`;
    if (sec < 3600) return `${(sec / 60).toFixed(1)} min`;
    return `${(sec / 3600).toFixed(1)} h`;
  }

  return (
    <Section icon={Radio} title="Beaconing C2 (connexions périodiques)" badge={data ? items.length : undefined} severity={topSeverity(items)}>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 10 }}>
        <label style={{ color: 'var(--fl-accent)', fontSize: 11, fontFamily: 'monospace' }}>Score minimum :</label>
        <select
          value={minScore}
          onChange={e => setMin(Number(e.target.value))}
          style={{ background: 'var(--fl-bg)', border: '1px solid #1a2540', borderRadius: 4, color: 'var(--fl-on-dark)', padding: '3px 8px', fontSize: 11, fontFamily: 'monospace' }}
        >
          {[40, 60, 75, 90].map(v => <option key={v} value={v}>{v}%</option>)}
        </select>
        <Button size="sm" icon={loading ? undefined : RefreshCw} loading={loading} onClick={run} disabled={loading}>
          Détecter
        </Button>
      </div>

      {!data && !loading && (
        <p style={{ color: 'var(--fl-subtle)', fontSize: 11, fontFamily: 'monospace', margin: 0 }}>Cliquez sur Détecter pour analyser les connexions périodiques suspectes (C2 beaconing).</p>
      )}
      {data && items.length === 0 && (
        <EmptyState icon={CheckCircle2} title="Aucun beaconing détecté" subtitle="Aucune connexion périodique suspecte avec ce seuil." />
      )}
      {visible.length > 0 && (
        <DetTable headers={['IP Destination', 'Connexions', 'Intervalle moyen', 'Score beacon', 'Sévérité']}>
          {visible.map((it, i) => (
            <tr key={i} style={{ background: i % 2 ? 'transparent' : 'rgba(255,255,255,0.02)' }}>
              <td style={{ ...TD, color: 'var(--fl-accent)', fontFamily: 'monospace' }}><CopyCell value={it.dest_ip} style={{ color: 'var(--fl-accent)', fontFamily: 'monospace' }} maxWidth={160} /></td>
              <td style={{ ...TD, color: 'var(--fl-on-dark)', textAlign: 'right', fontFamily: 'monospace' }}>{it.connection_count}</td>
              <td style={{ ...TD, color: 'var(--fl-on-dark)', fontFamily: 'monospace' }}>{fmtInterval(it.avg_interval_sec)}</td>
              <td style={TD}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                  <div style={{ flex: '1 1 60px', minWidth: 40, maxWidth: 100, background: 'var(--fl-panel)', borderRadius: 4, height: 6, overflow: 'hidden' }}>
                    <div style={{
                      width: `${it.beacon_score}%`, height: '100%', borderRadius: 4,
                      background: it.beacon_score >= 75 ? 'var(--fl-danger)' : it.beacon_score >= 60 ? 'var(--fl-warn)' : 'var(--fl-gold)',
                    }} />
                  </div>
                  <span style={{ color: 'var(--fl-on-dark)', fontWeight: 700, fontSize: 11, fontFamily: 'monospace', flexShrink: 0 }}>{Math.round(it.beacon_score)}%</span>
                </div>
              </td>
              <td style={TD}><SevBadge severity={it.severity} /></td>
            </tr>
          ))}
        </DetTable>
      )}
    </Section>
  );
}

function PersistenceSection({ caseId, runSignal, hiddenSevs, onComplete, onCounts }) {
  const { fmtDateTime } = useDateFormat();
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(false);
  const cbRef = useRef({ onComplete, onCounts });
  useEffect(() => { cbRef.current = { onComplete, onCounts }; });

  const run = useCallback(async () => {
    setLoading(true);
    try {
      const r = await detectionsAPI.persistence(caseId);
      setData(r.data);
    } catch {
      setData({ vectors: [], total: 0 });
    } finally {
      setLoading(false);
      cbRef.current.onComplete?.();
    }
  }, [caseId]);

  useEffect(() => { if (runSignal > 0) run(); }, [runSignal]);

  const vectors = data?.vectors ?? [];
  const allItems = vectors.flatMap(v => v.items ?? []);
  useEffect(() => { if (data) cbRef.current.onCounts?.(countsBySev(allItems)); }, [data]);

  return (
    <Section icon={Shield} title="Persistance Windows (Registry, LNK, BITS, Hayabusa)" badge={data ? data.total : undefined} severity={topSeverity(allItems)} defaultOpen>
      <div style={{ marginBottom: 10 }}>
        <Button size="sm" icon={loading ? undefined : RefreshCw} loading={loading} onClick={run} disabled={loading}>
          Analyser
        </Button>
      </div>

      {!data && !loading && (
        <p style={{ color: 'var(--fl-subtle)', fontSize: 11, fontFamily: 'monospace', margin: 0 }}>
          Cliquez sur Analyser pour détecter les mécanismes de persistance (Registry RunKeys, LNK Startup, BITS Jobs, règles Sigma Hayabusa).
        </p>
      )}
      {data && vectors.length === 0 && (
        <EmptyState icon={CheckCircle2} title="Aucun vecteur de persistance détecté" subtitle="Aucun mécanisme de persistance trouvé dans les artefacts collectés." />
      )}

      {vectors.map(v => {
        const visibleItems = (v.items ?? []).filter(it => !hiddenSevs.has(it.severity));
        if (visibleItems.length === 0) return null;
        return (
          <div key={v.id} style={{ marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <SevBadge severity={v.severity} />
              <span style={{ fontSize: 12, fontWeight: 700, fontFamily: 'monospace', color: 'var(--fl-on-dark)' }}>{v.label}</span>
              {v.mitre && (
                <span style={{ fontSize: 10, fontFamily: 'monospace', padding: '1px 7px', borderRadius: 4,
                  background: '#4d82c014', color: 'var(--fl-accent)', border: '1px solid #4d82c028' }}>
                  {v.mitre}
                </span>
              )}
              <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-subtle)' }}>
                {v.count} artefact{v.count > 1 ? 's' : ''}
              </span>
            </div>
            <DetTable headers={['Horodatage', 'Type', 'Description', 'Source', 'Machine']}>
              {visibleItems.map((it, i) => {
                const hayCol = it.hay_level ? HAY_LEVEL_COL[it.hay_level] : null;
                return (
                  <tr key={i} style={{ background: i % 2 ? 'transparent' : 'rgba(255,255,255,0.02)', borderLeft: `3px solid ${hayCol || '#1a2540'}` }}>
                    <td style={{ ...TD, color: 'var(--fl-accent)', whiteSpace: 'nowrap', fontFamily: 'monospace', fontSize: 11 }}>
                      {fmtDateTime(it.timestamp)}
                    </td>
                    <td style={TD}>
                      <span style={{ fontSize: 10, fontFamily: 'monospace', padding: '1px 5px', borderRadius: 3,
                        background: 'var(--fl-sep)', color: 'var(--fl-accent)', border: '1px solid #1a2540' }}>
                        {it.artifact_type}
                      </span>
                      {it.hay_level && (
                        <span style={{ marginLeft: 4, fontSize: 10, fontFamily: 'monospace', padding: '1px 5px', borderRadius: 3,
                          background: `${hayCol}18`, color: hayCol, border: `1px solid ${hayCol}30` }}>
                          {it.hay_level}
                        </span>
                      )}
                    </td>
                    <td style={{ ...TD, color: 'var(--fl-on-dark)' }}><CopyCell value={it.description} maxWidth={240} /></td>
                    <td style={{ ...TD, color: 'var(--fl-accent)' }}><CopyCell value={it.source} maxWidth={180} style={{ color: 'var(--fl-accent)' }} /></td>
                    <td style={{ ...TD, color: 'var(--fl-subtle)', fontFamily: 'monospace', fontSize: 11, whiteSpace: 'nowrap' }}>
                      {it.host_name || '—'}
                    </td>
                  </tr>
                );
              })}
            </DetTable>
          </div>
        );
      })}
    </Section>
  );
}

function SysmonBehaviorSection({ caseId, runSignal, hiddenSevs, onComplete, onCounts }) {
  const { fmtDateTime } = useDateFormat();
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(false);
  const cbRef = useRef({ onComplete, onCounts });
  useEffect(() => { cbRef.current = { onComplete, onCounts }; });

  const run = useCallback(async () => {
    setLoading(true);
    try {
      const r = await detectionsAPI.sysmonBehavior(caseId);
      setData(r.data);
    } catch {
      setData({ vectors: [], total: 0 });
    } finally {
      setLoading(false);
      cbRef.current.onComplete?.();
    }
  }, [caseId]);

  useEffect(() => { if (runSignal > 0) run(); }, [runSignal]);

  const vectors = data?.vectors ?? [];
  const allItems = vectors.flatMap(v => v.items ?? []);
  useEffect(() => { if (data) cbRef.current.onCounts?.(countsBySev(allItems)); }, [data]);

  return (
    <Section icon={Activity} title="Comportement Sysmon (EventID 1/3/7/8/10/11/25)" badge={data ? data.total : undefined} severity={topSeverity(allItems)}>
      <div style={{ marginBottom: 10 }}>
        <Button size="sm" icon={loading ? undefined : RefreshCw} loading={loading} onClick={run} disabled={loading}>
          Analyser
        </Button>
      </div>

      {!data && !loading && (
        <p style={{ color: 'var(--fl-subtle)', fontSize: 11, fontFamily: 'monospace', margin: 0 }}>
          Analyse les logs Sysmon pour détecter : exécution depuis %TEMP%, injection de processus (EID 8),
          accès LSASS (EID 10), DLL non signées (EID 7), connexions réseau suspectes (EID 3), altération de processus (EID 25).
        </p>
      )}
      {data && vectors.length === 0 && (
        <EmptyState icon={CheckCircle2} title="Aucun comportement suspect Sysmon détecté" subtitle="Aucun événement Sysmon correspondant aux techniques adversariales connues." />
      )}

      {vectors.map(v => {
        const visibleItems = (v.items ?? []).filter(it => !hiddenSevs.has(it.severity));
        if (visibleItems.length === 0) return null;
        return (
          <div key={v.id} style={{ marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <SevBadge severity={v.severity} />
              <span style={{ fontSize: 12, fontWeight: 700, fontFamily: 'monospace', color: 'var(--fl-on-dark)' }}>{v.label}</span>
              {v.mitre && (
                <span style={{ fontSize: 10, fontFamily: 'monospace', padding: '1px 7px', borderRadius: 4,
                  background: '#4d82c014', color: 'var(--fl-accent)', border: '1px solid #4d82c028' }}>
                  {v.mitre}
                </span>
              )}
              <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-subtle)' }}>
                {v.count} événement{v.count > 1 ? 's' : ''}
              </span>
            </div>
            <DetTable headers={['Horodatage', 'Type', 'Description', 'Processus / Cible', 'Machine']}>
              {visibleItems.map((it, i) => {
                const proc = it.raw?.Image || it.raw?.TargetImage || it.raw?.TargetFilename || '';
                return (
                  <tr key={i} style={{ background: i % 2 ? 'transparent' : 'rgba(255,255,255,0.02)' }}>
                    <td style={{ ...TD, color: 'var(--fl-accent)', whiteSpace: 'nowrap', fontFamily: 'monospace', fontSize: 11 }}>
                      {fmtDateTime(it.timestamp)}
                    </td>
                    <td style={TD}>
                      <span style={{ fontSize: 10, fontFamily: 'monospace', padding: '1px 5px', borderRadius: 3,
                        background: 'var(--fl-sep)', color: 'var(--fl-accent)', border: '1px solid #1a2540' }}>
                        {it.artifact_type}{it.raw?.EventID ? ` EID:${it.raw.EventID}` : ''}
                      </span>
                    </td>
                    <td style={{ ...TD, color: 'var(--fl-on-dark)' }}><CopyCell value={it.description} maxWidth={220} /></td>
                    <td style={{ ...TD, color: '#f0883e' }}><CopyCell value={proc} maxWidth={200} style={{ color: '#f0883e', fontFamily: 'monospace', fontSize: 11 }} /></td>
                    <td style={{ ...TD, color: 'var(--fl-subtle)', fontFamily: 'monospace', fontSize: 11 }}>
                      {it.host_name || '—'}
                    </td>
                  </tr>
                );
              })}
            </DetTable>
          </div>
        );
      })}
    </Section>
  );
}

const SECTION_COUNT = 5;

export default function DetectionsTab({ caseId }) {
  const [runSignal, setRunSignal]         = useState(0);
  const [completedCount, setCompleted]    = useState(0);
  const [isRunningAll, setIsRunningAll]   = useState(false);
  const [hiddenSevs, setHiddenSevs]       = useState(new Set());
  const [totalSevCounts, setTotalCounts]  = useState({ CRITIQUE: 0, ÉLEVÉ: 0, MOYEN: 0, FAIBLE: 0 });
  const sectionCountsRef = useRef({});

  const handleRunAll = () => {
    setCompleted(0);
    setIsRunningAll(true);
    setRunSignal(s => s + 1);
  };

  const handleComplete = useCallback((sectionId) => {
    setCompleted(c => {
      const next = c + 1;
      if (next >= SECTION_COUNT) setIsRunningAll(false);
      return next;
    });
  }, []);

  const handleCounts = useCallback((sectionId, counts) => {
    sectionCountsRef.current[sectionId] = counts;
    const agg = { CRITIQUE: 0, ÉLEVÉ: 0, MOYEN: 0, FAIBLE: 0 };
    for (const c of Object.values(sectionCountsRef.current)) {
      for (const [sev, n] of Object.entries(c)) {
        if (sev in agg) agg[sev] += n;
      }
    }
    setTotalCounts(agg);
  }, []);

  const toggleSev = (sev) => setHiddenSevs(prev => {
    const next = new Set(prev);
    next.has(sev) ? next.delete(sev) : next.add(sev);
    return next;
  });

  const totalFindings = Object.values(totalSevCounts).reduce((a, b) => a + b, 0);

  const sectionProps = (id) => ({
    caseId,
    runSignal,
    hiddenSevs,
    onComplete: () => handleComplete(id),
    onCounts: (c) => handleCounts(id, c),
  });

  return (
    <div style={{ padding: '0 4px' }}>

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
        <p style={{ flex: 1, color: 'var(--fl-subtle)', fontSize: 11, fontFamily: 'monospace', margin: 0 }}>
          Détection automatique de techniques adversariales dans les artefacts collectés (MFT, EVTX, Sysmon, Hayabusa).
        </p>
        <Button
          size="sm"
          icon={isRunningAll ? undefined : Play}
          loading={isRunningAll}
          onClick={handleRunAll}
          disabled={isRunningAll}
        >
          {isRunningAll ? `Analyse… (${completedCount}/${SECTION_COUNT})` : 'Analyser tout'}
        </Button>
      </div>

      {totalFindings > 0 && (
        <div style={{ display: 'flex', gap: 6, marginBottom: 12, flexWrap: 'wrap' }}>
          {SEV_ORDER.map(key => {
            const { color } = SEV[key];
            const count = totalSevCounts[key] ?? 0;
            const active = !hiddenSevs.has(key);
            return (
              <button key={key} onClick={() => toggleSev(key)} style={{
                display: 'flex', alignItems: 'center', gap: 5,
                padding: '3px 8px', borderRadius: 5,
                background: active ? `${color}20` : 'transparent',
                border: `1px solid ${active ? color + '60' : '#1a2540'}`,
                color: active ? color : 'var(--fl-subtle)',
                cursor: 'pointer', fontSize: 11, fontFamily: 'monospace', fontWeight: 700,
                transition: 'all 0.1s',
              }}>
                <span style={{ color }}>●</span>
                {key}
                <span style={{
                  background: active ? `${color}30` : '#0f1a2a',
                  borderRadius: 8, padding: '0 5px', fontSize: 10,
                  color: active ? color : 'var(--fl-subtle)',
                }}>
                  {count}
                </span>
              </button>
            );
          })}
        </div>
      )}

      <PersistenceSection    {...sectionProps('persistence')} />
      <SysmonBehaviorSection {...sectionProps('sysmon')} />
      <TimestompingSection   {...sectionProps('timestomping')} />
      <DoubleExtSection      {...sectionProps('doubleext')} />
      <BeaconingSection      {...sectionProps('beaconing')} />

    </div>
  );
}
