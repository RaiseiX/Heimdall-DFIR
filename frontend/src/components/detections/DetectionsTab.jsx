import { useState, useCallback, useEffect, useRef, createContext, useContext } from 'react';
import {
  Clock, FileWarning, Radio, Shield, Activity, HardDrive,
  ChevronDown, ChevronRight, RefreshCw, CheckCircle2, Copy, Play, FlagOff, X,
} from 'lucide-react';
import { detectionsAPI, iocsAPI, threatHuntingAPI } from '../../utils/api';
import { Crosshair, Rocket, Loader } from 'lucide-react';
import { Button, EmptyState } from '../ui';
import { useDateFormat } from '../../hooks/useDateFormat';
import { useTranslation } from 'react-i18next';

function guessIocType(v) {
  const s = String(v || '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return 'ip';
  if (/^[a-f0-9]{64}$/i.test(s)) return 'sha256';
  if (/^[a-f0-9]{40}$/i.test(s)) return 'sha1';
  if (/^[a-f0-9]{32}$/i.test(s)) return 'md5';
  if (/^https?:\/\//i.test(s)) return 'url';
  if (/^[\w.-]+\.[a-z]{2,}$/i.test(s) && !/[\\/]/.test(s)) return 'domain';
  return 'other';
}

// Pick the most identifying string of a detection result to suppress on.
function fpValue(it) {
  return it.filename || it.dest_ip || it.value || it.CommandLine || it.command_line ||
    it.Image || it.process || it.path || it.target || it.description || it.source || '';
}

// "False positive" button — stores a reusable suppression then reloads the section.
// Flag = false positive. Click = this case · Shift+click = global (all cases).
function FpBtn({ caseId, detectionType, item, onDone }) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const value = fpValue(item);
  if (!value) return null;
  const mark = async (e) => {
    e.stopPropagation();
    if (busy) return;
    const scope = e.shiftKey ? 'global' : 'case';
    setBusy(true);
    try {
      await detectionsAPI.addException(caseId, { detection_type: detectionType, match_value: value, scope });
      onDone?.();
    } catch { /* ignore */ } finally { setBusy(false); }
  };
  return (
    <button onClick={mark} disabled={busy} title={t('detections.actions.false_positive_title', { value: String(value).slice(0, 50) })}
      style={{ background: 'none', border: 'none', cursor: busy ? 'wait' : 'pointer', color: 'var(--fl-subtle)', padding: '2px 4px', display: 'inline-flex' }}
      onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-warn)'; }}
      onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-subtle)'; }}>
      <FlagOff size={13} />
    </button>
  );
}

// Promote a detection result to a case IOC.
function IocBtn({ caseId, item }) {
  const { t } = useTranslation();
  const [state, setState] = useState('idle'); // idle | done
  const value = fpValue(item);
  if (!value) return null;
  const promote = async (e) => {
    e.stopPropagation();
    if (state === 'done') return;
    try {
      await iocsAPI.create(caseId, { ioc_type: guessIocType(value), value: String(value).slice(0, 500), is_malicious: true, severity: 7, description: 'Promoted from detection' });
      setState('done');
    } catch { /* ignore */ }
  };
  return (
    <button onClick={promote} title={state === 'done' ? t('detections.actions.added_to_iocs') : t('detections.actions.promote_ioc')}
      style={{ background: 'none', border: 'none', cursor: 'pointer', color: state === 'done' ? 'var(--fl-ok)' : 'var(--fl-subtle)', padding: '2px 4px', display: 'inline-flex' }}
      onMouseEnter={e => { if (state !== 'done') e.currentTarget.style.color = 'var(--fl-accent)'; }}
      onMouseLeave={e => { if (state !== 'done') e.currentTarget.style.color = 'var(--fl-subtle)'; }}>
      {state === 'done' ? <CheckCircle2 size={13} /> : <Crosshair size={13} />}
    </button>
  );
}

// Combined per-result actions (FP + promote to IOC) — drop-in for the old <FpBtn>.
function ResultActions({ caseId, detectionType, item, onDone }) {
  return (
    <span style={{ display: 'inline-flex', gap: 2 }}>
      <IocBtn caseId={caseId} item={item} />
      <FpBtn caseId={caseId} detectionType={detectionType} item={item} onDone={onDone} />
    </span>
  );
}

const SEV = {
  CRITICAL: { color: 'var(--fl-danger)' },
  HIGH:     { color: 'var(--fl-warn)' },
  MEDIUM:   { color: 'var(--fl-gold)' },
  LOW:      { color: 'var(--fl-ok)' },
};
const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const SEV_I18N = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };
const SEV_ALIAS = {
  CRITIQUE: 'CRITICAL',
  ELEVE: 'HIGH',
  ELEVEE: 'HIGH',
  MOYEN: 'MEDIUM',
  FAIBLE: 'LOW',
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
};
const normalizeSeverity = (severity) => {
  const raw = String(severity || '');
  const key = raw.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toUpperCase();
  return SEV_ALIAS[key] || key;
};

const HAY_LEVEL_COL = {
  critical: 'var(--fl-danger)',
  high:     'var(--fl-warn)',
  medium:   'var(--fl-gold)',
  low:      'var(--fl-ok)',
};

const TH_STYLE = {
  position: 'sticky', top: 0, zIndex: 2,
  padding: '7px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10,
  fontWeight: 700, letterSpacing: '0.07em', textTransform: 'uppercase',
  color: 'var(--fl-muted)', background: 'var(--fl-bg)', whiteSpace: 'nowrap',
  borderBottom: '1px solid var(--fl-sep)', textAlign: 'left',
};

const TD = { padding: '5px 8px', borderBottom: '1px solid var(--fl-border2)', verticalAlign: 'middle' };

function topSeverity(items) {
  for (const sev of SEV_ORDER) {
    if (items.some(it => normalizeSeverity(it.severity) === sev)) return sev;
  }
  return null;
}

function countsBySev(items) {
  const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const it of items) {
    const sev = normalizeSeverity(it.severity);
    if (sev in c) c[sev]++;
  }
  return c;
}

function SevBadge({ severity }) {
  const { t } = useTranslation();
  const sKey = normalizeSeverity(severity);
  const s = SEV[sKey] || SEV.LOW;
  return (
    <span style={{
      display: 'inline-block', padding: '1px 7px', borderRadius: 4,
      fontSize: 10, fontWeight: 700, letterSpacing: '0.05em', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
      background: `color-mix(in srgb, ${s.color} 9%, transparent)`, border: `1px solid color-mix(in srgb, ${s.color} 25%, transparent)`, color: s.color,
    }}>
      {t(`detections.severity.${SEV_I18N[sKey] || 'low'}`)}
    </span>
  );
}

// Confidence = true-positive likelihood (distinct axis from severity). Lets analysts sort the signal.
const CONF = {
  high:   { color: 'var(--fl-ok)' },
  medium: { color: 'var(--fl-gold)' },
  low:    { color: 'var(--fl-subtle)' },
};
const CONF_ORDER = { high: 0, medium: 1, low: 2 };

function ConfBadge({ confidence }) {
  const { t } = useTranslation();
  if (!confidence) return null;
  const c = CONF[confidence] || CONF.medium;
  return (
    <span title={t(`detections.confidence.${confidence || 'medium'}_title`)} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 9, fontWeight: 700, letterSpacing: '0.06em',
      fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: c.color }}>
      <span style={{ width: 6, height: 6, borderRadius: 2, background: c.color, flexShrink: 0 }} />
      {t(`detections.confidence.${confidence || 'medium'}`)}
    </span>
  );
}

function CopyCell({ value, style, maxWidth = 200 }) {
  const { t } = useTranslation();
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
        <button onClick={copy} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: copied ? 'var(--fl-ok)' : 'var(--fl-accent)', flexShrink: 0 }} title={t('detections.actions.copy')}>
          {copied ? <CheckCircle2 size={10} /> : <Copy size={10} />}
        </button>
      )}
    </span>
  );
}

// Description cell: wraps onto 2 lines (no jarring native tooltip) and reveals a
// copy button on hover. Gives the primary content the room reclaimed from the
// empty process/host columns.
function DescCell({ value }) {
  const { t } = useTranslation();
  const [hover, setHover] = useState(false);
  const [copied, setCopied] = useState(false);
  const copy = useCallback((e) => {
    e.stopPropagation();
    navigator.clipboard?.writeText(value || '').catch(() => {});
    setCopied(true); setTimeout(() => setCopied(false), 1500);
  }, [value]);
  return (
    <span style={{ display: 'flex', alignItems: 'flex-start', gap: 6 }}
      onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}>
      <span style={{
        flex: 1, minWidth: 0, color: 'var(--fl-on-dark)', lineHeight: 1.4,
        display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical',
        overflow: 'hidden', wordBreak: 'break-word',
      }}>
        {value || '—'}
      </span>
      {value && hover && (
        <button onClick={copy} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, marginTop: 1, color: copied ? 'var(--fl-ok)' : 'var(--fl-accent)', flexShrink: 0 }} title={t('detections.actions.copy')}>
          {copied ? <CheckCircle2 size={10} /> : <Copy size={10} />}
        </button>
      )}
    </span>
  );
}

// ── Row detail drawer ──────────────────────────────────────────────────────
// A single shared drawer surfaces the full record behind any detection row.
const DetailContext = createContext(null);

// Clickable table row — opens the detail drawer with the row's full payload.
// Action buttons inside cells call stopPropagation, so they don't trigger this.
function Row({ i, detail, children }) {
  const open = useContext(DetailContext);
  const base = i % 2 ? 'transparent' : 'rgba(255,255,255,0.02)';
  return (
    <tr onClick={() => open?.(detail)}
      style={{ background: base, cursor: 'pointer', transition: 'background 0.1s' }}
      onMouseEnter={e => { e.currentTarget.style.background = 'color-mix(in srgb, var(--fl-accent) 8%, transparent)'; }}
      onMouseLeave={e => { e.currentTarget.style.background = base; }}>
      {children}
    </tr>
  );
}

const FIELD_LABEL_KEYS = {
  timestamp: 'timestamp', description: 'description', source: 'source', host_name: 'host_name',
  artifact_type: 'artifact_type', severity: 'severity', confidence: 'confidence',
  dest_ip: 'dest_ip', connection_count: 'connection_count', avg_interval_sec: 'avg_interval_sec',
  beacon_score: 'beacon_score', sia_created: 'sia_created', fn_created: 'fn_created',
  diff_days: 'diff_days', decoy_ext: 'decoy_ext', danger_ext: 'danger_ext',
  filename: 'filename', hay_level: 'hay_level', mitre: 'mitre', label: 'label', value: 'value',
};
const SKIP_FIELDS = new Set(['raw', 'items', 'id', '_id']);

function humanizeKey(k, t) {
  const labelKey = FIELD_LABEL_KEYS[k];
  return labelKey ? t(`detections.fields.${labelKey}`) : k.replace(/_/g, ' ').replace(/^\w/, c => c.toUpperCase());
}
function fmtFieldVal(v) {
  if (v == null) return '—';
  if (typeof v === 'object') return JSON.stringify(v, null, 2);
  return String(v);
}

function FieldRow({ fk, fv }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  const text = fmtFieldVal(fv);
  const isBlock = typeof fv === 'object' || text.length > 80;
  const copy = () => { navigator.clipboard?.writeText(text).catch(() => {}); setCopied(true); setTimeout(() => setCopied(false), 1300); };
  return (
    <div style={{ display: 'flex', flexDirection: isBlock ? 'column' : 'row', gap: isBlock ? 4 : 10, padding: '8px 0', borderBottom: '1px solid var(--fl-border2)' }}>
      <div style={{ flexShrink: 0, width: isBlock ? 'auto' : 150, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--fl-muted)', paddingTop: 1 }}>
        {humanizeKey(fk, t)}
      </div>
      <div style={{ flex: 1, minWidth: 0, display: 'flex', alignItems: 'flex-start', gap: 6 }}>
        <span style={{ flex: 1, minWidth: 0, fontSize: 12, color: 'var(--fl-text)',
          fontFamily: isBlock ? 'var(--f-mono, "JetBrains Mono", monospace)' : 'inherit',
          whiteSpace: isBlock ? 'pre-wrap' : 'normal', wordBreak: 'break-word',
          background: isBlock ? 'var(--fl-bg)' : 'transparent', border: isBlock ? '1px solid var(--fl-border2)' : 'none',
          borderRadius: isBlock ? 6 : 0, padding: isBlock ? '8px 10px' : 0 }}>
          {text}
        </span>
        <button onClick={copy} title={t('detections.actions.copy')} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, flexShrink: 0, color: copied ? 'var(--fl-ok)' : 'var(--fl-subtle)' }}>
          {copied ? <CheckCircle2 size={12} /> : <Copy size={12} />}
        </button>
      </div>
    </div>
  );
}

function DetailDrawer({ detail, onClose, caseId }) {
  const { t } = useTranslation();
  useEffect(() => {
    const onKey = e => { if (e.key === 'Escape') onClose(); };
    if (detail) window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [detail, onClose]);
  if (!detail) return null;
  const { item = {}, vector, detectionType, sectionTitle } = detail;
  const title = item.description || item.filename || item.dest_ip || vector?.label || sectionTitle || t('detections.detail.fallback_title');
  const severity = item.severity || vector?.severity;
  const mitre = item.mitre || vector?.mitre;
  const confidence = vector?.confidence || item.confidence;
  const entries = Object.entries(item).filter(([k, v]) => !SKIP_FIELDS.has(k) && v != null && v !== '');
  const rawEntries = item.raw && typeof item.raw === 'object' ? Object.entries(item.raw).filter(([, v]) => v != null && v !== '') : [];
  const fieldTotal = entries.length + rawEntries.length;

  return (
    <>
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, zIndex: 1200, background: 'rgba(0,0,0,0.45)', animation: 'fl-fade 120ms ease' }} />
      <div style={{ position: 'fixed', top: 0, right: 0, bottom: 0, zIndex: 1201, width: 'min(560px, 92vw)',
        background: 'var(--fl-panel)', borderLeft: '1px solid var(--fl-border)', boxShadow: 'var(--fl-shadow-lg)',
        display: 'flex', flexDirection: 'column', animation: 'fl-drawer-in 170ms var(--ease, ease)' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '14px 16px', borderBottom: '1px solid var(--fl-border)' }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 9.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-muted)', marginBottom: 5 }}>
              {t('detections.detail.title', { target: sectionTitle || detectionType })}
            </div>
            <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--fl-text)', wordBreak: 'break-word', lineHeight: 1.35 }}>{title}</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
              {severity && <SevBadge severity={severity} />}
              {confidence && <ConfBadge confidence={confidence} />}
              {mitre && (
                <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 7px', borderRadius: 4,
                  background: 'color-mix(in srgb, var(--fl-accent) 8%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 16%, transparent)' }}>{mitre}</span>
              )}
            </div>
          </div>
          <button onClick={onClose} title={t('detections.detail.close_title')} style={{ flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', width: 28, height: 28, borderRadius: 6, background: 'var(--fl-card)', border: '1px solid var(--fl-border)', color: 'var(--fl-muted)', cursor: 'pointer' }}>
            <X size={15} />
          </button>
        </div>
        <div style={{ flex: 1, overflowY: 'auto', padding: '6px 16px 16px' }}>
          {entries.map(([k, v]) => <FieldRow key={k} fk={k} fv={v} />)}
          {rawEntries.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{ fontSize: 9.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-muted)', margin: '0 0 4px' }}>
                {t('detections.detail.raw_data')}
              </div>
              {rawEntries.map(([k, v]) => <FieldRow key={k} fk={k} fv={v} />)}
            </div>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, padding: '12px 16px', borderTop: '1px solid var(--fl-border)' }}>
          <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-subtle)' }}>
            {fieldTotal} {t(fieldTotal > 1 ? 'detections.detail.fields_count_plural' : 'detections.detail.fields_count')}
          </span>
          {detectionType && <ResultActions caseId={caseId} detectionType={detectionType} item={item} onDone={onClose} />}
        </div>
      </div>
    </>
  );
}

function Section({ icon: Icon, title, badge, severity, children, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen);
  const sevColor = severity ? (SEV[severity]?.color ?? 'var(--fl-subtle)') : 'var(--fl-subtle)';
  return (
    <div style={{
      marginBottom: 10, background: 'var(--fl-card)',
      border: '1px solid var(--fl-border)',
      borderRadius: 8, overflow: 'hidden',
    }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: '100%', display: 'flex', alignItems: 'center', gap: 8,
          padding: '9px 12px', background: 'none', border: 'none', cursor: 'pointer',
          color: 'var(--fl-on-dark)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, fontSize: 11,
          textTransform: 'uppercase', letterSpacing: '0.05em', textAlign: 'left',
        }}
      >
        {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        <span style={{ width: 8, height: 8, borderRadius: 2, background: sevColor, flexShrink: 0 }} />
        <Icon size={13} style={{ flexShrink: 0, color: 'var(--fl-muted)' }} />
        <span style={{ flex: 1 }}>{title}</span>
        {badge !== undefined && (
          <span style={{
            background: badge > 0 ? 'color-mix(in srgb, var(--fl-danger) 9%, transparent)' : 'color-mix(in srgb, var(--fl-ok) 9%, transparent)',
            color: badge > 0 ? 'var(--fl-danger)' : 'var(--fl-ok)',
            border: `1px solid ${badge > 0 ? 'color-mix(in srgb, var(--fl-danger) 25%, transparent)' : 'color-mix(in srgb, var(--fl-ok) 25%, transparent)'}`,
            borderRadius: 10, padding: '1px 7px', fontSize: 10, fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
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
    <div style={{ overflowX: 'auto', borderRadius: 8, border: '1px solid var(--fl-border)', maxHeight: 400, overflowY: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, background: 'var(--fl-bg)' }}>
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
  const { t } = useTranslation();
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

  const visible = items.filter(it => !hiddenSevs.has(normalizeSeverity(it.severity)));

  return (
    <Section icon={Clock} title={t('detections.sections.timestomping.title')} badge={data ? items.length : undefined} severity={topSeverity(items)}>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 10 }}>
        <label style={{ color: 'var(--fl-accent)', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{t('detections.controls.threshold_days')}</label>
        <select
          value={threshold}
          onChange={e => setThr(Number(e.target.value))}
          style={{ background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', borderRadius: 4, color: 'var(--fl-on-dark)', padding: '3px 8px', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}
        >
          {[0, 1, 7, 30].map(v => <option key={v} value={v}>{v === 0 ? t('detections.controls.any_gap') : t('detections.controls.days_value', { count: v })}</option>)}
        </select>
        <Button size="sm" icon={loading ? undefined : RefreshCw} loading={loading} onClick={run} disabled={loading}>
          {t('detections.actions.analyze')}
        </Button>
      </div>

      {!data && !loading && (
        <p style={{ color: 'var(--fl-subtle)', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', margin: 0 }}>{t('detections.sections.timestomping.intro')}</p>
      )}
      {data && items.length === 0 && (
        <EmptyState icon={CheckCircle2} title={t('detections.sections.timestomping.empty_title')} subtitle={t('detections.sections.timestomping.empty_subtitle')} />
      )}
      {visible.length > 0 && (
        <DetTable headers={[t('detections.table.file'), t('detections.table.source'), '$SIA Created', '$FN Created', t('detections.table.gap_days_short'), t('detections.table.severity'), '']}>
          {visible.map((it, i) => (
            <Row key={i} i={i} detail={{ item: it, detectionType: 'timestomping', sectionTitle: t('detections.sections.timestomping.title') }}>
              <td style={{ ...TD, color: 'var(--fl-on-dark)' }}><CopyCell value={it.description} maxWidth={220} /></td>
              <td style={{ ...TD, color: 'var(--fl-accent)' }}>{it.source || '—'}</td>
              <td style={{ ...TD, color: 'var(--fl-on-dark)', whiteSpace: 'nowrap', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11 }}>{fmtDateTime(it.sia_created)}</td>
              <td style={{ ...TD, color: 'var(--fl-on-dark)', whiteSpace: 'nowrap', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11 }}>{fmtDateTime(it.fn_created)}</td>
              <td style={{ ...TD, color: 'var(--fl-gold)', fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{it.diff_days != null ? it.diff_days.toFixed(1) : '—'}</td>
              <td style={TD}><SevBadge severity={it.severity} /></td>
              <td style={TD}><ResultActions caseId={caseId} detectionType="timestomping" item={it} onDone={run} /></td>
            </Row>
          ))}
        </DetTable>
      )}
    </Section>
  );
}

function DoubleExtSection({ caseId, runSignal, hiddenSevs, onComplete, onCounts }) {
  const { t } = useTranslation();
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

  const visible = items.filter(it => !hiddenSevs.has(normalizeSeverity(it.severity)));

  return (
    <Section icon={FileWarning} title={t('detections.sections.double_ext.title')} badge={data ? items.length : undefined} severity={topSeverity(items)}>
      <div style={{ marginBottom: 10 }}>
        <Button size="sm" icon={loading ? undefined : RefreshCw} loading={loading} onClick={run} disabled={loading}>
          {t('detections.actions.scan')}
        </Button>
      </div>

      {!data && !loading && (
        <p style={{ color: 'var(--fl-subtle)', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', margin: 0 }}>{t('detections.sections.double_ext.intro')}</p>
      )}
      {data && items.length === 0 && (
        <EmptyState icon={CheckCircle2} title={t('detections.sections.double_ext.empty_title')} subtitle={t('detections.sections.double_ext.empty_subtitle')} />
      )}
      {visible.length > 0 && (
        <DetTable headers={[t('detections.table.file'), t('detections.table.decoy_ext'), t('detections.table.danger_ext'), t('detections.table.source'), t('detections.table.timestamp'), t('detections.table.severity'), '']}>
          {visible.map((it, i) => (
            <Row key={i} i={i} detail={{ item: it, detectionType: 'double-ext', sectionTitle: t('detections.sections.double_ext.detail_title') }}>
              <td style={{ ...TD, color: 'var(--fl-on-dark)' }}><CopyCell value={it.description} maxWidth={240} /></td>
              <td style={{ ...TD, color: 'var(--fl-accent)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>.{it.decoy_ext}</td>
              <td style={{ ...TD, color: 'var(--fl-danger)', fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>.{it.danger_ext}</td>
              <td style={{ ...TD, color: 'var(--fl-accent)' }}>{it.source || '—'}</td>
              <td style={{ ...TD, color: 'var(--fl-on-dark)', whiteSpace: 'nowrap', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11 }}>{fmtDateTime(it.timestamp)}</td>
              <td style={TD}><SevBadge severity={it.severity} /></td>
              <td style={TD}><ResultActions caseId={caseId} detectionType="double-ext" item={it} onDone={run} /></td>
            </Row>
          ))}
        </DetTable>
      )}
    </Section>
  );
}

function BeaconingSection({ caseId, runSignal, hiddenSevs, onComplete, onCounts }) {
  const { t } = useTranslation();
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

  const visible = items.filter(it => !hiddenSevs.has(normalizeSeverity(it.severity)));

  function fmtInterval(sec) {
    if (sec < 60)   return `${sec.toFixed(0)}s`;
    if (sec < 3600) return `${(sec / 60).toFixed(1)} min`;
    return `${(sec / 3600).toFixed(1)} h`;
  }

  return (
    <Section icon={Radio} title={t('detections.sections.beaconing.title')} badge={data ? items.length : undefined} severity={topSeverity(items)}>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 10 }}>
        <label style={{ color: 'var(--fl-accent)', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{t('detections.controls.min_score')}</label>
        <select
          value={minScore}
          onChange={e => setMin(Number(e.target.value))}
          style={{ background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', borderRadius: 4, color: 'var(--fl-on-dark)', padding: '3px 8px', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}
        >
          {[40, 60, 75, 90].map(v => <option key={v} value={v}>{v}%</option>)}
        </select>
        <Button size="sm" icon={loading ? undefined : RefreshCw} loading={loading} onClick={run} disabled={loading}>
          {t('detections.actions.detect')}
        </Button>
      </div>

      {!data && !loading && (
        <p style={{ color: 'var(--fl-subtle)', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', margin: 0 }}>{t('detections.sections.beaconing.intro')}</p>
      )}
      {data && items.length === 0 && (
        <EmptyState icon={CheckCircle2} title={t('detections.sections.beaconing.empty_title')} subtitle={t('detections.sections.beaconing.empty_subtitle')} />
      )}
      {visible.length > 0 && (
        <DetTable headers={[t('detections.table.dest_ip'), t('detections.table.connections'), t('detections.table.avg_interval'), t('detections.table.beacon_score'), t('detections.table.severity'), '']}>
          {visible.map((it, i) => (
            <Row key={i} i={i} detail={{ item: it, detectionType: 'beaconing', sectionTitle: t('detections.sections.beaconing.detail_title') }}>
              <td style={{ ...TD, color: 'var(--fl-accent)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}><CopyCell value={it.dest_ip} style={{ color: 'var(--fl-accent)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }} maxWidth={160} /></td>
              <td style={{ ...TD, color: 'var(--fl-on-dark)', textAlign: 'right', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{it.connection_count}</td>
              <td style={{ ...TD, color: 'var(--fl-on-dark)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{fmtInterval(it.avg_interval_sec)}</td>
              <td style={TD}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                  <div style={{ flex: '1 1 60px', minWidth: 40, maxWidth: 100, background: 'var(--fl-panel)', borderRadius: 4, height: 6, overflow: 'hidden' }}>
                    <div style={{
                      width: `${it.beacon_score}%`, height: '100%', borderRadius: 4,
                      background: it.beacon_score >= 75 ? 'var(--fl-danger)' : it.beacon_score >= 60 ? 'var(--fl-warn)' : 'var(--fl-gold)',
                    }} />
                  </div>
                  <span style={{ color: 'var(--fl-on-dark)', fontWeight: 700, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', flexShrink: 0 }}>{Math.round(it.beacon_score)}%</span>
                </div>
              </td>
              <td style={TD}><SevBadge severity={it.severity} /></td>
              <td style={TD}><ResultActions caseId={caseId} detectionType="beaconing" item={it} onDone={run} /></td>
            </Row>
          ))}
        </DetTable>
      )}
    </Section>
  );
}

function PersistenceSection({ caseId, runSignal, hiddenSevs, onComplete, onCounts }) {
  const { t } = useTranslation();
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

  const vectors = [...(data?.vectors ?? [])].sort((a, b) => (CONF_ORDER[a.confidence] ?? 1) - (CONF_ORDER[b.confidence] ?? 1));
  const allItems = vectors.flatMap(v => v.items ?? []);
  useEffect(() => { if (data) cbRef.current.onCounts?.(countsBySev(allItems)); }, [data]);

  return (
    <Section icon={Shield} title={t('detections.sections.persistence.title')} badge={data ? data.total : undefined} severity={topSeverity(allItems)} defaultOpen>
      <div style={{ marginBottom: 10 }}>
        <Button size="sm" icon={loading ? undefined : RefreshCw} loading={loading} onClick={run} disabled={loading}>
          {t('detections.actions.analyze')}
        </Button>
      </div>

      {!data && !loading && (
        <p style={{ color: 'var(--fl-subtle)', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', margin: 0 }}>
          {t('detections.sections.persistence.intro')}
        </p>
      )}
      {data && vectors.length === 0 && (
        <EmptyState icon={CheckCircle2} title={t('detections.sections.persistence.empty_title')} subtitle={t('detections.sections.persistence.empty_subtitle')} />
      )}

      {vectors.map(v => {
        const visibleItems = (v.items ?? []).filter(it => !hiddenSevs.has(normalizeSeverity(it.severity)));
        if (visibleItems.length === 0) return null;
        return (
          <div key={v.id} style={{ marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <SevBadge severity={v.severity} />
              <span style={{ fontSize: 12, fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-on-dark)' }}>{v.label}</span>
              {v.mitre && (
                <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 7px', borderRadius: 4,
                  background: 'color-mix(in srgb, var(--fl-accent) 8%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 16%, transparent)' }}>
                  {v.mitre}
                </span>
              )}
              <ConfBadge confidence={v.confidence} />
              <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-subtle)' }}>
                {v.count} {t(v.count > 1 ? 'detections.units.artifacts' : 'detections.units.artifact')}
              </span>
            </div>
            <DetTable headers={[t('detections.table.timestamp'), t('detections.table.type'), t('detections.table.description'), t('detections.table.source'), t('detections.table.host'), '']}>
              {visibleItems.map((it, i) => {
                const hayCol = it.hay_level ? HAY_LEVEL_COL[it.hay_level] : null;
                return (
                  <Row key={i} i={i} detail={{ item: it, vector: v, detectionType: 'persistence', sectionTitle: t('detections.sections.persistence.detail_title') }}>
                    <td style={{ ...TD, color: 'var(--fl-accent)', whiteSpace: 'nowrap', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11 }}>
                      {fmtDateTime(it.timestamp)}
                    </td>
                    <td style={TD}>
                      <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 5px', borderRadius: 3,
                        background: 'var(--fl-sep)', color: 'var(--fl-accent)', border: '1px solid var(--fl-border)' }}>
                        {it.artifact_type}
                      </span>
                      {it.hay_level && (
                        <span style={{ marginLeft: 4, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 5px', borderRadius: 3,
                          background: `color-mix(in srgb, ${hayCol} 9%, transparent)`, color: hayCol, border: `1px solid color-mix(in srgb, ${hayCol} 19%, transparent)` }}>
                          {it.hay_level}
                        </span>
                      )}
                    </td>
                    <td style={{ ...TD, color: 'var(--fl-on-dark)' }}><CopyCell value={it.description} maxWidth={240} /></td>
                    <td style={{ ...TD, color: 'var(--fl-accent)' }}><CopyCell value={it.source} maxWidth={180} style={{ color: 'var(--fl-accent)' }} /></td>
                    <td style={{ ...TD, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, whiteSpace: 'nowrap' }}>
                      {it.host_name || '—'}
                    </td>
                    <td style={TD}><ResultActions caseId={caseId} detectionType="persistence" item={it} onDone={run} /></td>
                  </Row>
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
  const { t } = useTranslation();
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

  const vectors = [...(data?.vectors ?? [])].sort((a, b) => (CONF_ORDER[a.confidence] ?? 1) - (CONF_ORDER[b.confidence] ?? 1));
  const allItems = vectors.flatMap(v => v.items ?? []);
  useEffect(() => { if (data) cbRef.current.onCounts?.(countsBySev(allItems)); }, [data]);

  return (
    <Section icon={Activity} title={t('detections.sections.sysmon.title')} badge={data ? data.total : undefined} severity={topSeverity(allItems)}>
      <div style={{ marginBottom: 10 }}>
        <Button size="sm" icon={loading ? undefined : RefreshCw} loading={loading} onClick={run} disabled={loading}>
          {t('detections.actions.analyze')}
        </Button>
      </div>

      {!data && !loading && (
        <p style={{ color: 'var(--fl-subtle)', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', margin: 0 }}>
          {t('detections.sections.sysmon.intro')}
        </p>
      )}
      {data && vectors.length === 0 && (
        <EmptyState icon={CheckCircle2} title={t('detections.sections.sysmon.empty_title')} subtitle={t('detections.sections.sysmon.empty_subtitle')} />
      )}

      {vectors.map(v => {
        const visibleItems = (v.items ?? []).filter(it => !hiddenSevs.has(normalizeSeverity(it.severity)));
        if (visibleItems.length === 0) return null;
        return (
          <div key={v.id} style={{ marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <SevBadge severity={v.severity} />
              <span style={{ fontSize: 12, fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-on-dark)' }}>{v.label}</span>
              {v.mitre && (
                <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 7px', borderRadius: 4,
                  background: 'color-mix(in srgb, var(--fl-accent) 8%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 16%, transparent)' }}>
                  {v.mitre}
                </span>
              )}
              <ConfBadge confidence={v.confidence} />
              <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-subtle)' }}>
                {v.count} {t(v.count > 1 ? 'detections.units.events' : 'detections.units.event')}
              </span>
            </div>
            <DetTable headers={[t('detections.table.timestamp'), t('detections.table.type'), t('detections.table.description'), t('detections.table.process_target'), t('detections.table.host'), '']}>
              {visibleItems.map((it, i) => {
                const proc = it.raw?.Image || it.raw?.TargetImage || it.raw?.TargetFilename || '';
                return (
                  <Row key={i} i={i} detail={{ item: it, vector: v, detectionType: 'sysmon-behavior', sectionTitle: t('detections.sections.sysmon.detail_title') }}>
                    <td style={{ ...TD, color: 'var(--fl-accent)', whiteSpace: 'nowrap', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11 }}>
                      {fmtDateTime(it.timestamp)}
                    </td>
                    <td style={TD}>
                      <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 5px', borderRadius: 3,
                        background: 'var(--fl-sep)', color: 'var(--fl-accent)', border: '1px solid var(--fl-border)' }}>
                        {it.artifact_type}{it.raw?.EventID ? ` EID:${it.raw.EventID}` : ''}
                      </span>
                    </td>
                    <td style={{ ...TD, color: 'var(--fl-on-dark)' }}><CopyCell value={it.description} maxWidth={220} /></td>
                    <td style={{ ...TD, color: 'var(--fl-warn)' }}><CopyCell value={proc} maxWidth={200} style={{ color: 'var(--fl-warn)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11 }} /></td>
                    <td style={{ ...TD, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11 }}>
                      {it.host_name || '—'}
                    </td>
                    <td style={TD}><ResultActions caseId={caseId} detectionType="sysmon-behavior" item={it} onDone={run} /></td>
                  </Row>
                );
              })}
            </DetTable>
          </div>
        );
      })}
    </Section>
  );
}

// Generic grouped detection section (reused for anti-forensic & execution-anomaly).
function GroupedSection({ caseId, runSignal, hiddenSevs, onComplete, onCounts, apiFn, detectionType, title, icon, intro }) {
  const { t } = useTranslation();
  const { fmtDateTime } = useDateFormat();
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(false);
  const cbRef = useRef({ onComplete, onCounts });
  useEffect(() => { cbRef.current = { onComplete, onCounts }; });

  const run = useCallback(async () => {
    setLoading(true);
    try { const r = await apiFn(caseId); setData(r.data); }
    catch { setData({ vectors: [], total: 0 }); }
    finally { setLoading(false); cbRef.current.onComplete?.(); }
  }, [caseId, apiFn]);
  useEffect(() => { if (runSignal > 0) run(); }, [runSignal]);

  const vectors = [...(data?.vectors ?? [])].sort((a, b) => (CONF_ORDER[a.confidence] ?? 1) - (CONF_ORDER[b.confidence] ?? 1));
  const allItems = vectors.flatMap(v => v.items ?? []);
  useEffect(() => { if (data) cbRef.current.onCounts?.(countsBySev(allItems)); }, [data]);

  return (
    <Section icon={icon} title={title} badge={data ? data.total : undefined} severity={topSeverity(allItems)}>
      <div style={{ marginBottom: 10 }}>
        <Button size="sm" icon={loading ? undefined : RefreshCw} loading={loading} onClick={run} disabled={loading}>{t('detections.actions.analyze')}</Button>
      </div>
      {!data && !loading && (
        <p style={{ color: 'var(--fl-subtle)', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', margin: 0 }}>{intro}</p>
      )}
      {data && vectors.length === 0 && (
        <EmptyState icon={CheckCircle2} title={t('detections.sections.grouped.empty_title')} subtitle={t('detections.sections.grouped.empty_subtitle')} />
      )}
      {vectors.map(v => {
        const visibleItems = (v.items ?? []).filter(it => !hiddenSevs.has(normalizeSeverity(it.severity)));
        if (visibleItems.length === 0) return null;

        // Adaptive columns: only render PROCESS / HOST when they actually carry
        // differentiating signal. MFT-based detections have no process; a single
        // shared host (e.g. one collection) is shown once in the vector header
        // instead of repeated down an otherwise-useless column.
        const procOf = it => it.raw?.Image || it.raw?.CommandLine || it.raw?.TargetImage || it.raw?.TargetFilename || '';
        const hostOf = it => (it.host_name && it.host_name !== '-') ? String(it.host_name) : '';
        const hasProc = visibleItems.some(it => procOf(it));
        const uniqHosts = [...new Set(visibleItems.map(hostOf).filter(Boolean))];
        const hasHostCol = uniqHosts.length > 1;          // varying hosts → keep column
        const singleHost = uniqHosts.length === 1 ? uniqHosts[0] : null;

        const headers = [
          t('detections.table.timestamp'),
          t('detections.table.type'),
          t('detections.table.description'),
          ...(hasProc ? [t('detections.table.process_target')] : []),
          ...(hasHostCol ? [t('detections.table.host')] : []),
          '',
        ];

        return (
          <div key={v.id} style={{ marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
              <SevBadge severity={v.severity} />
              <span style={{ fontSize: 12, fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-on-dark)' }}>{v.label}</span>
              {v.mitre && (
                <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 7px', borderRadius: 4,
                  background: 'color-mix(in srgb, var(--fl-accent) 8%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 16%, transparent)' }}>{v.mitre}</span>
              )}
              <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-subtle)' }}>{v.count} {t(v.count > 1 ? 'detections.units.events' : 'detections.units.event')}</span>
              {singleHost && (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-subtle)' }}>
                  <span style={{ width: 5, height: 5, borderRadius: 1, background: 'var(--fl-subtle)', flexShrink: 0 }} />
                  {singleHost}
                </span>
              )}
            </div>
            <DetTable headers={headers}>
              {visibleItems.map((it, i) => {
                const proc = procOf(it);
                return (
                  <Row key={i} i={i} detail={{ item: it, vector: v, detectionType, sectionTitle: title }}>
                    <td style={{ ...TD, color: 'var(--fl-accent)', whiteSpace: 'nowrap', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, verticalAlign: 'top' }}>{fmtDateTime(it.timestamp)}</td>
                    <td style={{ ...TD, verticalAlign: 'top' }}><span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 5px', borderRadius: 3, background: 'var(--fl-sep)', color: 'var(--fl-accent)', border: '1px solid var(--fl-border)', whiteSpace: 'nowrap' }}>{it.artifact_type}{it.raw?.EventID ? ` EID:${it.raw.EventID}` : ''}</span></td>
                    <td style={{ ...TD }}><DescCell value={it.description} /></td>
                    {hasProc && (
                      <td style={{ ...TD, color: 'var(--fl-warn)', verticalAlign: 'top' }}><CopyCell value={proc} maxWidth={200} style={{ color: 'var(--fl-warn)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11 }} /></td>
                    )}
                    {hasHostCol && (
                      <td style={{ ...TD, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, verticalAlign: 'top' }}>{hostOf(it) || '—'}</td>
                    )}
                    <td style={{ ...TD, verticalAlign: 'top' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4, justifyContent: 'flex-end' }}>
                        <ResultActions caseId={caseId} detectionType={detectionType} item={it} onDone={run} />
                        <ChevronRight size={13} style={{ color: 'var(--fl-subtle)', flexShrink: 0 }} />
                      </div>
                    </td>
                  </Row>
                );
              })}
            </DetTable>
          </div>
        );
      })}
    </Section>
  );
}

const SECTION_COUNT = 9;

export default function DetectionsTab({ caseId }) {
  const { t } = useTranslation();
  const [runSignal, setRunSignal]         = useState(0);
  const [completedCount, setCompleted]    = useState(0);
  const [isRunningAll, setIsRunningAll]   = useState(false);
  const [hiddenSevs, setHiddenSevs]       = useState(new Set());
  const [totalSevCounts, setTotalCounts]  = useState({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 });
  const sectionCountsRef = useRef({});
  const [exceptions, setExceptions] = useState([]);
  const [showExc, setShowExc]       = useState(false);
  const [detail, setDetail]         = useState(null); // row clicked → full-record drawer

  const loadExceptions = useCallback(() => {
    detectionsAPI.exceptions(caseId).then(r => setExceptions(r.data?.exceptions || [])).catch(() => {});
  }, [caseId]);
  useEffect(() => { loadExceptions(); }, [loadExceptions]);

  const removeException = async (exId) => {
    try { await detectionsAPI.deleteException(caseId, exId); loadExceptions(); } catch { /* ignore */ }
  };

  // Background "run all engines" (YARA/Sigma/Hayabusa/detections) — survives leaving the page.
  const [bgJob, setBgJob] = useState(null);
  useEffect(() => {
    threatHuntingAPI.runAllStatus(caseId).then(r => { if (r.data?.status && r.data.status !== 'idle') setBgJob(r.data); }).catch(() => {});
  }, [caseId]);
  useEffect(() => {
    if (bgJob?.status !== 'running') return;
    const iv = setInterval(() => threatHuntingAPI.runAllStatus(caseId).then(r => setBgJob(r.data)).catch(() => {}), 3000);
    return () => clearInterval(iv);
  }, [bgJob?.status, caseId]);
  const launchBg = async () => {
    try { const r = await threatHuntingAPI.runAll(caseId); setBgJob(r.data); } catch { /* ignore */ }
  };

  const handleRunAll = () => {
    setCompleted(0);
    setIsRunningAll(true);
    setRunSignal(s => s + 1);
  };

  // Auto-run all detections once when the tab opens.
  useEffect(() => { handleRunAll(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleComplete = useCallback((sectionId) => {
    setCompleted(c => {
      const next = c + 1;
      if (next >= SECTION_COUNT) setIsRunningAll(false);
      return next;
    });
  }, []);

  const handleCounts = useCallback((sectionId, counts) => {
    sectionCountsRef.current[sectionId] = counts;
    const agg = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
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
    <DetailContext.Provider value={setDetail}>
    <div style={{ padding: '0 4px' }}>

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
        <p style={{ flex: 1, color: 'var(--fl-subtle)', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', margin: 0 }}>
          {t('detections.header.intro')}
        </p>
        {exceptions.length > 0 && (
          <div style={{ position: 'relative' }}>
            <button onClick={() => { setShowExc(v => !v); loadExceptions(); }}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '4px 10px', borderRadius: 6, cursor: 'pointer',
                background: 'color-mix(in srgb, var(--fl-warn) 9%, transparent)', color: 'var(--fl-warn)', border: '1px solid color-mix(in srgb, var(--fl-warn) 21%, transparent)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11 }}>
              <FlagOff size={12} /> {exceptions.length} {t(exceptions.length > 1 ? 'detections.exceptions.suppressions' : 'detections.exceptions.suppression')}
            </button>
            {showExc && (
              <div style={{ position: 'absolute', right: 0, top: '110%', zIndex: 50, width: 360, maxHeight: 320, overflowY: 'auto', background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 8, boxShadow: 'var(--fl-shadow-md)', padding: 8 }}>
                <div style={{ fontSize: 9.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-muted)', padding: '4px 6px 8px' }}>{t('detections.exceptions.title')}</div>
                {exceptions.map(ex => (
                  <div key={ex.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 6px', borderTop: '1px solid var(--fl-border2)' }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={ex.match_value}>{ex.match_value}</div>
                      <div style={{ fontSize: 9.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)' }}>{ex.detection_type || t('detections.exceptions.all_types')} · {ex.case_id ? t('detections.exceptions.this_case') : t('detections.exceptions.global')}</div>
                    </div>
                    <button onClick={() => removeException(ex.id)} title={t('detections.exceptions.restore_title')}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-subtle)', fontSize: 16, lineHeight: 1, padding: '0 4px', flexShrink: 0 }}>x</button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
        {(() => {
          const running = bgJob?.status === 'running';
          const done = bgJob?.status === 'done';
          const steps = bgJob?.steps || [];
          const completed = steps.filter(s => s.status === 'done' || s.status === 'error').length;
          const hits = steps.reduce((s, st) => s + (st.count || 0), 0);
          return (
            <button onClick={launchBg} disabled={running}
              title={t('detections.header.run_background_title')}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '5px 11px', borderRadius: 6, cursor: running ? 'wait' : 'pointer',
                fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, fontWeight: 600,
                background: 'transparent', color: running ? 'var(--fl-accent)' : done ? 'var(--fl-ok)' : 'var(--fl-dim)',
                border: `1px solid ${running ? 'color-mix(in srgb, var(--fl-accent) 30%, transparent)' : 'var(--fl-border)'}` }}>
              {running ? <Loader size={12} style={{ animation: 'spin 1s linear infinite' }} /> : <Rocket size={12} />}
              {running ? t('detections.header.background_running', { completed, total: steps.length }) : done ? t('detections.header.background_done', { hits }) : t('detections.header.run_background')}
            </button>
          );
        })()}
        <Button
          size="sm"
          icon={isRunningAll ? undefined : Play}
          loading={isRunningAll}
          onClick={handleRunAll}
          disabled={isRunningAll}
        >
          {isRunningAll ? t('detections.header.analyzing_all', { completed: completedCount, total: SECTION_COUNT }) : t('detections.header.analyze_all')}
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
                background: active ? `color-mix(in srgb, ${color} 13%, transparent)` : 'transparent',
                border: `1px solid ${active ? color + '60' : 'var(--fl-border)'}`,
                color: active ? color : 'var(--fl-subtle)',
                cursor: 'pointer', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700,
                transition: 'all 0.1s',
              }}>
                <span style={{ color }}>●</span>
                {t(`detections.severity.${SEV_I18N[key] || 'low'}`)}
                <span style={{
                  background: active ? `color-mix(in srgb, ${color} 19%, transparent)` : 'var(--fl-border2)',
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
      <GroupedSection {...sectionProps('attack-tech')} apiFn={detectionsAPI.attackTechniques} detectionType="attack-techniques"
        title={t('detections.sections.attack_tech.title')} icon={Shield}
        intro={t('detections.sections.attack_tech.intro')} />
      <GroupedSection {...sectionProps('vuln-drivers')} apiFn={detectionsAPI.vulnDrivers} detectionType="vuln-drivers"
        title={t('detections.sections.vuln_drivers.title')} icon={HardDrive}
        intro={t('detections.sections.vuln_drivers.intro')} />
      <GroupedSection {...sectionProps('execanom')} apiFn={detectionsAPI.executionAnomaly} detectionType="execution-anomaly"
        title={t('detections.sections.execution_anomaly.title')} icon={Activity}
        intro={t('detections.sections.execution_anomaly.intro')} />
      <GroupedSection {...sectionProps('anti-forensic')} apiFn={detectionsAPI.antiForensic} detectionType="anti-forensic"
        title={t('detections.sections.anti_forensic.title')} icon={FileWarning}
        intro={t('detections.sections.anti_forensic.intro')} />
      <TimestompingSection   {...sectionProps('timestomping')} />
      <DoubleExtSection      {...sectionProps('doubleext')} />
      <BeaconingSection      {...sectionProps('beaconing')} />

    </div>
    <DetailDrawer detail={detail} onClose={() => setDetail(null)} caseId={caseId} />
    </DetailContext.Provider>
  );
}
