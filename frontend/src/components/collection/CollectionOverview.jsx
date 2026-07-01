import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  FolderOpen, Clock, Network, Shield, AlertTriangle, Activity, ScrollText,
  RefreshCw, Loader2, ArrowRight, Database, ShieldCheck,
} from 'lucide-react';
import { evidenceAPI, parsersAPI, collectionAPI } from '../../utils/api';
import { artifactColor } from '../../constants/artifactColors';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

function fmtSize(b) {
  if (b == null) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, n = Number(b);
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(n >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
}

// Quick-access tiles → this collection's other workspaces.
const QUICK_TABS = [
  { tab: 'timeline',   labelKey: 'collectionOverview.tiles.timeline',   fallback: 'Super Timeline', icon: Clock,          accent: 'var(--fl-ok)' },
  { tab: 'network',    labelKey: 'collectionOverview.tiles.network',    fallback: 'Network',        icon: Network,        accent: 'var(--fl-accent)' },
  { tab: 'detections', labelKey: 'collectionOverview.tiles.detections', fallback: 'Detections',     icon: AlertTriangle,  accent: 'var(--fl-warn)' },
  { tab: 'mitre',      labelKey: 'collectionOverview.tiles.mitre',      fallback: 'MITRE',          icon: Shield,         accent: 'var(--fl-accent)' },
  { tab: 'hayabusa',   labelKey: 'collectionOverview.tiles.hayabusa',   fallback: 'Hayabusa',       icon: Activity,       accent: 'var(--fl-danger)' },
  { tab: 'logs',       labelKey: 'collectionOverview.tiles.logs',       fallback: 'Logs',           icon: ScrollText,     accent: 'var(--fl-dim)' },
];

export default function CollectionOverview({ caseId, collectionId, collName }) {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();

  const [evidence, setEvidence] = useState(null);
  const [result, setResult]     = useState(null);   // { resultId, recordCount, parsedAt, parsedBy }
  const [breakdown, setBreakdown] = useState([]);   // [{ artifact_type, count }]
  const [loading, setLoading]   = useState(true);
  const [reparsing, setReparsing] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [evRes, prRes] = await Promise.all([
        evidenceAPI.list(caseId),
        parsersAPI.results(caseId),
      ]);
      const ev = (evRes.data || []).find(e => e.id === collectionId) || null;
      setEvidence(ev);

      // Match parser results to THIS collection by evidence_id; keep the richest run.
      const mine = (Array.isArray(prRes.data) ? prRes.data : [])
        .filter(r => r.evidence_id === collectionId)
        .sort((a, b) => (b.record_count ?? 0) - (a.record_count ?? 0));
      const top = mine[0] || null;

      if (top) {
        setResult({ resultId: top.id, recordCount: top.record_count ?? 0, parsedAt: top.created_at, parsedBy: top.parsed_by });
        try {
          const typesRes = await parsersAPI.resultTypes(top.id);
          const rows = (typesRes.data || []).filter(r => r.artifact_type).sort((a, b) => b.count - a.count);
          setBreakdown(rows);
        } catch { setBreakdown([]); }
      } else {
        setResult(null);
        setBreakdown([]);
      }
    } catch (e) {
      console.error('[CollectionOverview]', e);
    } finally {
      setLoading(false);
    }
  }, [caseId, collectionId]);

  useEffect(() => { load(); }, [load]);

  const handleReparse = () => {
    setReparsing(true);
    collectionAPI.parse(caseId, { evidence_id: collectionId })
      .catch(() => {})
      .finally(() => setTimeout(() => setReparsing(false), 1500));
  };

  const name = evidence?.name || collName || 'Collection';
  const isParsed = (result?.recordCount ?? 0) > 0;
  const totalRecords = result?.recordCount ?? 0;
  const maxCount = breakdown.length ? breakdown[0].count : 0;

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 8, color: 'var(--fl-dim)', fontFamily: MONO, fontSize: 13 }}>
        <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> {t('common.loading')}
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 1000, margin: '0 auto', width: '100%', padding: '20px 16px 48px' }}>

      {/* ── Header ── */}
      <div style={{
        display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16,
        paddingBottom: 16, borderBottom: '1px solid var(--fl-border)', marginBottom: 20,
      }}>
        <div style={{ minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 6 }}>
            <FolderOpen size={17} style={{ color: isParsed ? 'var(--fl-ok)' : 'var(--fl-muted)', flexShrink: 0 }} />
            <span style={{ fontFamily: 'var(--f-display, var(--f-sans))', fontSize: 18, fontWeight: 700, color: 'var(--fl-text)', letterSpacing: '-0.01em', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {name}
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14, fontFamily: MONO, fontSize: 11, color: 'var(--fl-dim)', flexWrap: 'wrap' }}>
            {evidence?.evidence_type && (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 6, height: 6, borderRadius: 2, background: 'var(--fl-accent)', flexShrink: 0 }} />
                {evidence.evidence_type}
              </span>
            )}
            <span style={{ fontFeatureSettings: '"tnum"' }}>{fmtSize(evidence?.file_size)}</span>
            {evidence?.created_at && <span>{new Date(evidence.created_at).toLocaleDateString(i18n.language)}</span>}
            {evidence?.scan_status === 'clean' && (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: 'var(--fl-ok)' }}>
                <ShieldCheck size={12} /> {t('collectionOverview.clean', 'Clean')}
              </span>
            )}
            {evidence?.scan_status === 'quarantined' && (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: 'var(--fl-danger)' }}>
                <AlertTriangle size={12} /> {t('casedetail.quarantine')}
              </span>
            )}
          </div>
        </div>

        <button
          onClick={handleReparse}
          disabled={reparsing}
          style={{
            display: 'inline-flex', alignItems: 'center', gap: 6, flexShrink: 0,
            padding: '7px 13px', borderRadius: 7, cursor: reparsing ? 'wait' : 'pointer',
            fontFamily: MONO, fontSize: 11.5, fontWeight: 600,
            background: 'transparent', color: 'var(--fl-dim)', border: '1px solid var(--fl-border)',
            transition: 'color 0.15s, border-color 0.15s',
          }}
          onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-accent)'; e.currentTarget.style.borderColor = 'color-mix(in srgb, var(--fl-accent) 35%, transparent)'; }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-dim)'; e.currentTarget.style.borderColor = 'var(--fl-border)'; }}
        >
          {reparsing ? <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} /> : <RefreshCw size={12} />}
          {t('casedetail.reparse')}
        </button>
      </div>

      {!isParsed ? (
        /* ── Empty state — collection imported but not yet parsed ── */
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '72px 16px', gap: 13, textAlign: 'center' }}>
          <div style={{ width: 46, height: 46, borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--fl-raised)', border: '1px solid var(--fl-border)' }}>
            <Database size={21} style={{ color: 'var(--fl-muted)' }} strokeWidth={1.5} />
          </div>
          <div style={{ fontFamily: 'var(--f-display, var(--f-sans))', fontSize: 15, fontWeight: 700, color: 'var(--fl-text)', letterSpacing: '-0.01em' }}>
            {t('collectionOverview.empty_title', 'Collecte non analysée')}
          </div>
          <div style={{ fontSize: 12.5, color: 'var(--fl-dim)', maxWidth: 360, lineHeight: 1.5 }}>
            {t('collectionOverview.empty_sub', 'Lancez le parsing pour extraire la timeline forensique de cette collecte.')}
          </div>
          <button
            onClick={handleReparse}
            disabled={reparsing}
            style={{ marginTop: 4, display: 'inline-flex', alignItems: 'center', gap: 6, padding: '8px 16px', borderRadius: 8, cursor: reparsing ? 'wait' : 'pointer', fontFamily: MONO, fontSize: 12, fontWeight: 600, background: 'color-mix(in srgb, var(--fl-accent) 12%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 28%, transparent)' }}
          >
            {reparsing ? <Loader2 size={13} style={{ animation: 'spin 1s linear infinite' }} /> : <RefreshCw size={13} />}
            {t('collectionOverview.parse_now', 'Lancer le parsing')}
          </button>
        </div>
      ) : (
        <>
          {/* ── Stat row ── */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 24, flexWrap: 'wrap', marginBottom: 24 }}>
            <div>
              <div style={{ fontFamily: MONO, fontSize: 26, fontWeight: 700, color: 'var(--fl-text)', fontFeatureSettings: '"tnum"', lineHeight: 1.1 }}>
                {totalRecords.toLocaleString(i18n.language)}
              </div>
              <div style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', marginTop: 3 }}>
                {t('collectionOverview.records', 'Enregistrements')}
              </div>
            </div>
            <div style={{ width: 1, height: 34, background: 'var(--fl-border)' }} />
            <div>
              <div style={{ fontFamily: MONO, fontSize: 26, fontWeight: 700, color: 'var(--fl-text)', fontFeatureSettings: '"tnum"', lineHeight: 1.1 }}>
                {breakdown.length}
              </div>
              <div style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', marginTop: 3 }}>
                {t('collectionOverview.artifact_types', 'Types d’artefacts')}
              </div>
            </div>
            {result?.parsedAt && (
              <>
                <div style={{ width: 1, height: 34, background: 'var(--fl-border)' }} />
                <div>
                  <div style={{ fontFamily: MONO, fontSize: 13, fontWeight: 600, color: 'var(--fl-dim)', fontFeatureSettings: '"tnum"', lineHeight: 1.1, paddingTop: 6 }}>
                    {new Date(result.parsedAt).toLocaleString(i18n.language, { dateStyle: 'short', timeStyle: 'short' })}
                  </div>
                  <div style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', marginTop: 3 }}>
                    {t('collectionOverview.parsed_at', 'Parsé le')}{result.parsedBy ? ` · ${result.parsedBy}` : ''}
                  </div>
                </div>
              </>
            )}
          </div>

          {/* ── Artifact breakdown ── */}
          {breakdown.length > 0 && (
            <div style={{ marginBottom: 28 }}>
              <div style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 600, marginBottom: 12 }}>
                {t('collectionOverview.breakdown', 'Répartition par artefact')}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                {breakdown.map(row => {
                  const color = artifactColor(row.artifact_type);
                  const pct = maxCount ? Math.max(2, (row.count / maxCount) * 100) : 0;
                  return (
                    <div key={row.artifact_type} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, width: 140, flexShrink: 0 }}>
                        <span style={{ width: 8, height: 8, borderRadius: 2, background: color, flexShrink: 0 }} />
                        <span style={{ fontFamily: MONO, fontSize: 11.5, color: 'var(--fl-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {row.artifact_type}
                        </span>
                      </div>
                      <div style={{ flex: 1, height: 6, borderRadius: 3, background: 'var(--fl-border2)', overflow: 'hidden' }}>
                        <div style={{ width: `${pct}%`, height: '100%', borderRadius: 3, background: `color-mix(in srgb, ${color} 55%, transparent)` }} />
                      </div>
                      <span style={{ width: 78, textAlign: 'right', fontFamily: MONO, fontSize: 11.5, color: 'var(--fl-dim)', fontFeatureSettings: '"tnum"', flexShrink: 0 }}>
                        {Number(row.count).toLocaleString(i18n.language)}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* ── Quick-access tiles ── */}
          <div>
            <div style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 600, marginBottom: 12 }}>
              {t('collectionOverview.explore', 'Explorer cette collecte')}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 10 }}>
              {QUICK_TABS.map(({ tab, labelKey, fallback, icon: Icon, accent }) => (
                <button
                  key={tab}
                  onClick={() => navigate(`/cases/${caseId}/collections/${collectionId}/${tab}`)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 11, textAlign: 'left',
                    padding: '13px 14px', borderRadius: 9, cursor: 'pointer',
                    background: 'var(--fl-panel)', border: '1px solid var(--fl-border)',
                    transition: 'border-color 0.15s, background 0.15s',
                  }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--fl-border3)'; e.currentTarget.style.background = 'var(--fl-raised)'; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--fl-border)'; e.currentTarget.style.background = 'var(--fl-panel)'; }}
                >
                  <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 32, height: 32, borderRadius: 8, background: `color-mix(in srgb, ${accent} 11%, transparent)`, flexShrink: 0 }}>
                    <Icon size={15} style={{ color: accent }} />
                  </span>
                  <span style={{ flex: 1, fontFamily: MONO, fontSize: 12, fontWeight: 600, color: 'var(--fl-text)' }}>
                    {t(labelKey, fallback)}
                  </span>
                  <ArrowRight size={13} style={{ color: 'var(--fl-subtle)', flexShrink: 0 }} />
                </button>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
