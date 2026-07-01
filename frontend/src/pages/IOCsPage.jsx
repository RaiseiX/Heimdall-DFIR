import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Crosshair, Plus, AlertTriangle, Globe, Hash, FileText,
  User, Server, Search, X, Shield, ShieldAlert, RefreshCw,
  CheckCircle, HelpCircle, Zap, Download, GitBranch, Info, Trash2, Loader2
} from 'lucide-react';
import { iocsAPI, casesAPI, networkAPI } from '../utils/api';
import { Button, Modal, Badge, EmptyState, Spinner } from '../components/ui';
import { downloadCSV } from '../utils/csvExport';

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

const SEV_VARIANT = (s) => s >= 8 ? 'danger' : s >= 5 ? 'warn' : 'dim';

function VTBadge({ ioc }) {
  const { t } = useTranslation();
  if (!ioc.vt_verdict) return null;
  const variant = {
    malicious: 'danger', suspicious: 'warn',
    clean: 'ok', unknown: 'dim',
  }[ioc.vt_verdict] || 'dim';
  const label = ioc.vt_malicious != null && ioc.vt_total != null
    ? `VT ${ioc.vt_malicious}/${ioc.vt_total}`
    : `VT ${ioc.vt_verdict}`;
  return (
    <Badge
      variant={variant}
      title={t('iocs.vt_title', { malicious: ioc.vt_malicious ?? '?', total: ioc.vt_total ?? '?' })}
    >
      <Shield size={9} className="inline mr-1" />{label}
    </Badge>
  );
}

function AbuseIPDBBadge({ ioc }) {
  const { t } = useTranslation();
  if (ioc.ioc_type !== 'ip' || ioc.abuseipdb_score == null) return null;
  const s = ioc.abuseipdb_score;
  const variant = s >= 80 ? 'danger' : s >= 40 ? 'warn' : s > 0 ? 'gold' : 'ok';
  return (
    <Badge
      variant={variant}
      title={t('iocs.abuse_title', { score: s })}
    >
      <ShieldAlert size={9} className="inline mr-1" />Abuse {s}%
    </Badge>
  );
}

function ShodanBadge({ ioc }) {
  const { t } = useTranslation();
  if (ioc.ioc_type !== 'ip') return null;
  const ports = ioc.enrichment_data?.shodan_ports ?? ioc.shodan_ports;
  const vulns = ioc.enrichment_data?.shodan_vulns ?? ioc.shodan_vulns;
  if (!Array.isArray(ports) || ports.length === 0) return null;
  const hasVulns = Array.isArray(vulns) && vulns.length > 0;
  const variant = hasVulns ? 'danger' : 'dim';
  const portsLabel = t('iocs.ports_count', { count: ports.length });
  const vulnsLabel = hasVulns ? ` / ${t('iocs.cves_count', { count: vulns.length })}` : '';
  const title = [
    t('iocs.shodan_ports_title', { ports: ports.join(', ') }),
    hasVulns ? t('iocs.shodan_cves_title', { cves: vulns.join(', ') }) : '',
  ].filter(Boolean).join('\n');
  return (
    <Badge variant={variant} title={title}>
      <Server size={9} className="inline mr-1" />Shodan: {portsLabel}{vulnsLabel}
    </Badge>
  );
}

function countryFlag(code) {
  if (!code || code.length !== 2) return '';
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}

function GeoBadge({ ioc }) {
  if (!ioc.geo_country_code && !ioc.geo_country) return null;
  const flag = countryFlag(ioc.geo_country_code);
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, fontSize: 11, color: 'var(--fl-dim)' }}>
      <span style={{ fontSize: 14 }}>{flag}</span>
      <span>{ioc.geo_country || ioc.geo_country_code}</span>
      {ioc.geo_is_proxy && <span style={{ fontSize: 10, padding: '1px 4px', background: 'color-mix(in srgb, var(--fl-warn) 13%, transparent)', color: 'var(--fl-warn)', borderRadius: 3, border: '1px solid color-mix(in srgb, var(--fl-warn) 25%, transparent)' }}>PROXY</span>}
      {ioc.geo_is_hosting && <span style={{ fontSize: 10, padding: '1px 4px', background: 'color-mix(in srgb, var(--fl-accent) 13%, transparent)', color: 'var(--fl-accent)', borderRadius: 3, border: '1px solid color-mix(in srgb, var(--fl-accent) 25%, transparent)' }}>HOSTING</span>}
    </span>
  );
}

function DgaPanel({ caseId }) {
  const { t } = useTranslation();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  const analyze = async () => {
    if (!caseId) return;
    setLoading(true);
    try {
      const res = await networkAPI.dgaAnalysis(caseId);
      setData(res.data);
    } catch {}
    setLoading(false);
  };

  if (!caseId) return null;

  return (
    <div style={{ marginTop: 16, background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 8, overflow: 'hidden' }}>
      <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--fl-panel)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--fl-text)', display: 'flex', alignItems: 'center', gap: 6 }}>
          <span>🧬</span> {t('iocs.dga_title')}
          {data && <span style={{ fontSize: 11, color: 'var(--fl-dim)', fontWeight: 400 }}>— {t('iocs.dga_summary', { total: data.total, suspicious: data.suspicious_count })}</span>}
        </div>
        <button onClick={analyze} disabled={loading} style={{ fontSize: 11, padding: '4px 10px', background: 'var(--fl-accent)', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer' }}>
          {loading ? '…' : t('iocs.analyze')}
        </button>
      </div>
      {data && data.domains.length > 0 && (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ background: 'var(--fl-bg)' }}>
              {[t('iocs.col_domain'), t('iocs.col_entropy'), t('iocs.col_consonants'), t('iocs.col_length'), t('iocs.col_dga_score'), t('iocs.col_status')].map(h => (
                <th key={h} style={{ padding: '6px 12px', textAlign: 'left', color: 'var(--fl-dim)', fontWeight: 600, borderBottom: '1px solid var(--fl-panel)' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.domains.map((d, i) => (
              <tr key={d.domain} style={{ background: d.is_suspicious ? '#2d1515' : i % 2 === 0 ? 'var(--fl-panel)' : 'var(--fl-bg)', borderBottom: '1px solid #21303f10' }}>
                <td style={{ padding: '5px 12px', color: 'var(--fl-text)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{d.domain}</td>
                <td style={{ padding: '5px 12px', color: d.entropy > 3.5 ? 'var(--fl-warn)' : 'var(--fl-dim)' }}>{d.entropy}</td>
                <td style={{ padding: '5px 12px', color: d.consonant_ratio > 0.65 ? 'var(--fl-warn)' : 'var(--fl-dim)' }}>{(d.consonant_ratio * 100).toFixed(0)}%</td>
                <td style={{ padding: '5px 12px', color: 'var(--fl-dim)' }}>{d.length}</td>
                <td style={{ padding: '5px 12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <div style={{ flex: 1, height: 6, background: 'var(--fl-panel)', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${d.dga_score}%`, background: d.dga_score >= 60 ? 'var(--fl-danger)' : d.dga_score >= 40 ? 'var(--fl-warn)' : 'var(--fl-ok)', borderRadius: 3 }} />
                    </div>
                    <span style={{ fontSize: 11, color: 'var(--fl-dim)', minWidth: 28 }}>{d.dga_score}</span>
                  </div>
                </td>
                <td style={{ padding: '5px 12px' }}>
                  {d.is_suspicious
                    ? <span style={{ fontSize: 10, padding: '2px 6px', background: 'color-mix(in srgb, var(--fl-danger) 13%, transparent)', color: 'var(--fl-danger)', borderRadius: 4, border: '1px solid color-mix(in srgb, var(--fl-danger) 25%, transparent)' }}>SUSPECT</span>
                    : <span style={{ fontSize: 10, padding: '2px 6px', background: 'color-mix(in srgb, var(--fl-ok) 13%, transparent)', color: 'var(--fl-ok)', borderRadius: 4 }}>OK</span>
                  }
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data && data.domains.length === 0 && (
        <div style={{ padding: 24, textAlign: 'center', color: 'var(--fl-dim)', fontSize: 12 }}>{t('iocs.no_domain')}</div>
      )}
    </div>
  );
}

export default function IOCsPage() {
  const { t, i18n } = useTranslation();
  const [iocs, setIocs] = useState([]);
  const [cases, setCases] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [verdictFilter, setVerdictFilter] = useState('all');
  const [showAdd, setShowAdd] = useState(false);
  const [newIOC, setNewIOC] = useState({ ioc_type: 'ip', value: '', description: '', severity: 5, is_malicious: false, case_id: '' });
  const [enriching, setEnriching] = useState({});
  const [enrichingAll, setEnrichingAll] = useState(false);
  const [error, setError] = useState('');
  const [pivotIOC, setPivotIOC] = useState(null);
  const [pivotResults, setPivotResults] = useState([]);
  const [pivotLoading, setPivotLoading] = useState(false);
  const [confirmingId, setConfirmingId] = useState(null);
  const [deletingId, setDeletingId] = useState(null);
  const [confirmConf, setConfirmConf] = useState('confirmed');
  const [confirmNote, setConfirmNote] = useState('');
  const [confirmedIds, setConfirmedIds] = useState(new Set());
  const [sharedCountMap, setSharedCountMap] = useState({});

  const loadData = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [iocsRes, casesRes, sharedRes] = await Promise.all([
        iocsAPI.searchGlobal(search || undefined, typeFilter !== 'all' ? typeFilter : undefined),
        casesAPI.list(),
        iocsAPI.topShared().catch(() => ({ data: [] })),
      ]);
      setIocs(iocsRes.data.results || []);

      const map = {};
      (sharedRes.data || []).forEach(row => { map[row.ioc_value] = parseInt(row.case_count, 10); });
      setSharedCountMap(map);
      setCases(casesRes.data?.cases || casesRes.data || []);
    } catch {
      setError(t('iocs.load_error'));
    } finally {
      setLoading(false);
    }
  }, [search, typeFilter]);

  useEffect(() => { loadData(); }, [loadData]);

  useEffect(() => {
    const t = setTimeout(loadData, 400);
    return () => clearTimeout(t);
  }, [search]);

  async function handleEnrich(ioc) {
    setEnriching(p => ({ ...p, [ioc.id]: true }));
    try {
      const res = await iocsAPI.enrich(ioc.id);
      const enrichment = res.data.enrichment;
      setIocs(prev => prev.map(i => i.id !== ioc.id ? i : {
        ...i,
        vt_malicious: enrichment.virustotal?.malicious ?? null,
        vt_total: enrichment.virustotal?.total ?? null,
        vt_verdict: enrichment.virustotal?.verdict ?? null,
        abuseipdb_score: enrichment.abuseipdb?.score ?? null,
        shodan_ports: enrichment.shodan_ports ?? enrichment.shodan?.ports ?? null,
        shodan_org: enrichment.shodan_org ?? enrichment.shodan?.org ?? null,
        shodan_vulns: enrichment.shodan_vulns ?? enrichment.shodan?.vulns ?? null,
        geo_country: enrichment.geo?.country,
        geo_country_code: enrichment.geo?.country_code,
        geo_city: enrichment.geo?.city,
        geo_org: enrichment.geo?.org,
        geo_asn: enrichment.geo?.asn,
        geo_is_proxy: enrichment.geo?.is_proxy,
        geo_is_hosting: enrichment.geo?.is_hosting,
        enriched_at: new Date().toISOString(),
        enrichment_data: enrichment,
      }));
    } catch {

    } finally {
      setEnriching(p => { const n = { ...p }; delete n[ioc.id]; return n; });
    }
  }

  async function handleEnrichAll() {
    const caseIds = [...new Set(iocs.map(i => i.case_id).filter(Boolean))];
    if (!caseIds.length) return;
    setEnrichingAll(true);
    try {
      await Promise.all(caseIds.map(caseId => iocsAPI.enrichCase(caseId)));

      setTimeout(loadData, 3000);
    } finally {
      setEnrichingAll(false);
    }
  }

  async function handleCrossCase(ioc) {
    setPivotIOC(ioc);
    setPivotResults([]);
    setPivotLoading(true);
    try {
      const { data } = await iocsAPI.crossCase(ioc.value);
      setPivotResults(data || []);
    } catch {
      setPivotResults([]);
    }
    setPivotLoading(false);
  }

  async function handleConfirmIOC(ioc) {
    try {
      await iocsAPI.confirmIOC(ioc.id, { confidence: confirmConf, notes: confirmNote });
      setConfirmedIds(prev => new Set([...prev, ioc.id]));
      setIocs(prev => prev.map(i => i.id === ioc.id ? { ...i, is_malicious: true } : i));
    } catch {

    } finally {
      setConfirmingId(null);
      setConfirmConf('confirmed');
      setConfirmNote('');
    }
  }

  async function handleDelete(ioc) {
    if (!confirm(t('iocs.delete_confirm', { value: ioc.value }))) return;
    setDeletingId(ioc.id);
    try {
      await iocsAPI.remove(ioc.id);
      setIocs(prev => prev.filter(i => i.id !== ioc.id));
    } catch (e) {
      setError(e.response?.data?.error || t('iocs.delete_error'));
    } finally {
      setDeletingId(null);
    }
  }

  async function handleCreate() {
    if (!newIOC.value.trim() || !newIOC.case_id) return;
    try {
      const res = await iocsAPI.create(newIOC.case_id, {
        ioc_type: newIOC.ioc_type,
        value: newIOC.value.trim(),
        description: newIOC.description,
        severity: newIOC.severity,
        is_malicious: newIOC.is_malicious,
      });
      setIocs(prev => [res.data, ...prev]);
      setShowAdd(false);
      setNewIOC({ ioc_type: 'ip', value: '', description: '', severity: 5, is_malicious: false, case_id: '' });
    } catch {
      setError(t('iocs.create_error'));
    }
  }

  const [dgaCaseId, setDgaCaseId] = useState('');

  const malCount = iocs.filter(i => i.is_malicious).length;
  const enrichedCount = iocs.filter(i => i.enriched_at).length;
  const benignCount  = iocs.filter(i => i.is_malicious === false).length;
  const suspectCount = iocs.filter(i => i.is_malicious == null).length;
  const types = [...new Set(iocs.map(i => i.ioc_type))].filter(Boolean);

  const VERDICT_TABS = [
    { key: 'all',       label: t('common.all'), count: iocs.length },
    { key: 'malicious', label: t('iocs.tab_malicious'), count: malCount, color: 'var(--fl-danger)' },
    { key: 'suspect',   label: t('iocs.tab_suspect'), count: suspectCount, color: 'var(--fl-gold)' },
    { key: 'benign',    label: t('iocs.tab_benign'), count: benignCount, color: 'var(--fl-ok)' },
  ];
  const visibleIocs = iocs.filter(i =>
    verdictFilter === 'all' ? true
    : verdictFilter === 'malicious' ? i.is_malicious === true
    : verdictFilter === 'benign' ? i.is_malicious === false
    : i.is_malicious == null);

  return (
    <div className="p-6">
      
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, marginBottom: 18 }}>
        <div>
          <h1 style={{ fontFamily: 'var(--f-display, var(--f-ui))', fontSize: 22, fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--fl-text)', margin: 0 }}>
            {t('iocs.explorer_title')}
          </h1>
          <p style={{ margin: '5px 0 0', fontSize: 12.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)', display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <span><span style={{ color: 'var(--fl-dim)', fontFeatureSettings: '"tnum"' }}>{iocs.length.toLocaleString(i18n.language)}</span> {t('iocs.indicators')}</span>
            {malCount > 0 && <span>· <span style={{ color: 'var(--fl-danger)' }}>{t('iocs.malicious_count', { count: malCount })}</span></span>}
            {enrichedCount > 0 && <span>· <span style={{ color: 'var(--fl-ok)' }}>{t('iocs.enriched_count', { count: enrichedCount })}</span></span>}
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="secondary"
            icon={Download}
            disabled={iocs.length === 0}
            onClick={() => downloadCSV(iocs, [
              { key: 'ioc_type',    label: 'Type' },
              { key: 'value',       label: t('iocs.value') },
              { key: 'description', label: 'Description' },
              { key: 'severity',    label: t('iocs.severity') },
              { key: 'is_malicious',label: t('iocs.malicious') },
              { key: 'source',      label: 'Source' },
              { key: 'tags',        label: 'Tags' },
              { key: 'case_id',     label: t('iocs.case_label') },
              { key: 'vt_verdict',  label: 'VT Verdict' },
              { key: 'created_at',  label: t('settings.api_keys.created_at') },
            ], `iocs_${new Date().toISOString().slice(0,10)}.csv`)}
            title={t('iocs.tooltip_export_iocs')}
          >
            CSV
          </Button>
          <Button
            variant="secondary"
            icon={enrichingAll ? undefined : Zap}
            loading={enrichingAll}
            disabled={enrichingAll || iocs.length === 0}
            onClick={handleEnrichAll}
            title={t('iocs.tooltip_enrich_iocs')}
          >
            {t('iocs.enrich_all_btn')}
          </Button>
          <Button variant="primary" icon={Plus} onClick={() => setShowAdd(true)}>
            {t('iocs.add_ioc_btn')}
          </Button>
        </div>
      </div>

      {error && (
        <div className="mb-4 p-3 rounded text-sm" style={{ background: 'color-mix(in srgb, var(--fl-danger) 8%, transparent)', color: 'var(--fl-danger)', border: '1px solid color-mix(in srgb, var(--fl-danger) 20%, transparent)' }}>
          {error}
        </div>
      )}

      <div className="fl-filters mb-4">
        <div className="fl-search" style={{ flex: 1 }}>
          <Search size={14} className="fl-search-icon" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder={t('iocs.search_ph')}
            className="fl-input"
            style={{ paddingLeft: 34 }}
          />
        </div>
        <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)} className="fl-select">
          <option value="all">{t('iocs.all_types')}</option>
          {types.map(tp => <option key={tp} value={tp}>{t(`iocs.types.${tp}`, { defaultValue: TYPE_LABEL[tp] || tp })}</option>)}
        </select>
        {(search || typeFilter !== 'all') && (
          <Button variant="ghost" size="sm" icon={X} onClick={() => { setSearch(''); setTypeFilter('all'); }}>
            {t('cases.clear_filters')}
          </Button>
        )}
        <Button variant="ghost" size="sm" icon={RefreshCw} onClick={loadData} title={t('iocs.tooltip_refresh')} />
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 14, borderBottom: '1px solid var(--fl-border2)' }}>
        {VERDICT_TABS.map(tab => {
          const active = verdictFilter === tab.key;
          return (
            <button key={tab.key} onClick={() => setVerdictFilter(tab.key)}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 7, padding: '8px 12px', background: 'none', border: 'none', cursor: 'pointer',
                fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12, fontWeight: 600,
                color: active ? 'var(--fl-text)' : 'var(--fl-muted)',
                borderBottom: `2px solid ${active ? 'var(--fl-accent)' : 'transparent'}`, marginBottom: -1 }}>
              {tab.color && <span style={{ width: 7, height: 7, borderRadius: 2, background: tab.color, flexShrink: 0 }} />}
              {tab.label}
              <span style={{ fontSize: 10.5, color: active ? 'var(--fl-dim)' : 'var(--fl-subtle)', fontFeatureSettings: '"tnum"' }}>{tab.count.toLocaleString(i18n.language)}</span>
            </button>
          );
        })}
      </div>

      <div className="mb-4" style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)' }}>
        <Info size={12} style={{ flexShrink: 0, color: 'var(--fl-subtle)' }} />
        {t('iocs.enrichment_hint')} <code style={{ color: 'var(--fl-dim)' }}>.env</code>.
      </div>

      {loading ? (
        <div className="fl-empty">
          <Spinner size={28} color="var(--fl-accent)" />
        </div>
      ) : iocs.length === 0 ? (
        <EmptyState
          icon={Crosshair}
          title={t('iocs.empty_title')}
          subtitle={t('iocs.empty_sub')}
          action={
            <Button variant="primary" size="sm" icon={Plus} onClick={() => setShowAdd(true)}>
              {t('iocs.add_ioc_btn')}
            </Button>
          }
        />
      ) : (
        <div className="fl-card" style={{ overflow: 'hidden' }}>
          <table className="fl-table">
            <thead>
              <tr>
                <th style={{ width: 44 }}>{t('iocs.severity_short')}</th>
                <th>{t('iocs.type_value')}</th>
                <th>Description</th>
                <th>{t('iocs.enrichment')}</th>
                <th>{t('iocs.case_label')}</th>
                <th>Tags</th>
                <th style={{ width: 80 }}></th>
              </tr>
            </thead>
            <tbody>
              {visibleIocs.map(ioc => {
                const Icon = TYPE_ICON[ioc.ioc_type] || Globe;
                const isEnriching = enriching[ioc.id];
                const sev = ioc.severity || 5;
                const sevColor = sev >= 8 ? 'var(--fl-danger)' : sev >= 6 ? 'var(--fl-warn)' : sev >= 4 ? 'var(--fl-gold)' : 'var(--fl-ok)';
                return (
                  <tr key={ioc.id}>

                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', minWidth: 30, padding: '3px 6px', borderRadius: 5, fontFamily: 'var(--f-mono, monospace)', fontSize: 12, fontWeight: 700, background: `color-mix(in srgb, ${sevColor} 12%, transparent)`, color: sevColor, border: `1px solid color-mix(in srgb, ${sevColor} 25%, transparent)` }}>
                        {sev}
                      </span>
                    </td>

                    <td>
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <Badge variant="accent">
                          <Icon size={10} className="inline mr-1" />{t(`iocs.types.${ioc.ioc_type}`, { defaultValue: TYPE_LABEL[ioc.ioc_type] || ioc.ioc_type })}
                        </Badge>
                        {ioc.is_malicious && (
                          <Badge variant="danger">
                            <AlertTriangle size={9} className="inline mr-1" />{t('iocs.malicious_badge')}
                          </Badge>
                        )}
                      </div>
                      <div className="font-mono text-xs font-semibold" style={{ color: ioc.is_malicious ? 'var(--fl-danger)' : 'var(--fl-text)', wordBreak: 'break-all' }}>
                        {ioc.value}
                      </div>
                    </td>

                    <td style={{ color: 'var(--fl-muted)', maxWidth: 200 }}>{ioc.description}</td>

                    <td>
                      <div className="flex flex-wrap gap-1 items-center min-w-[120px]">
                        {ioc.enriched_at ? (
                          <>
                            <VTBadge ioc={ioc} />
                            <AbuseIPDBBadge ioc={ioc} />
                            <ShodanBadge ioc={ioc} />
                            <GeoBadge ioc={ioc} />
                            {!ioc.vt_verdict && !ioc.abuseipdb_score && !(ioc.shodan_ports?.length) && !ioc.geo_country_code && (
                              <span className="text-xs" style={{ color: 'var(--fl-muted)' }}>
                                <CheckCircle size={12} className="inline mr-1" />{t('iocs.enriched')}
                              </span>
                            )}
                          </>
                        ) : (
                          <span className="text-xs" style={{ color: 'var(--fl-dim)' }}>—</span>
                        )}
                      </div>
                    </td>

                    <td className="fl-td-mono fl-td-dim text-xs" style={{ maxWidth: 160 }}>
                      {ioc.case_number && <div style={{ color: 'var(--fl-accent)' }}>{ioc.case_number}</div>}
                      {ioc.case_title && <div style={{ color: 'var(--fl-muted)', fontSize: 11 }}>{ioc.case_title}</div>}
                      {sharedCountMap[ioc.value] > 1 && (
                        <button
                          onClick={() => handleCrossCase(ioc)}
                          title={t('iocs.view_shared_cases')}
                          style={{
                            marginTop: 4, display: 'inline-flex', alignItems: 'center', gap: 4,
                            fontSize: 10, padding: '1px 6px', borderRadius: 4, cursor: 'pointer',
                            background: 'color-mix(in srgb, var(--fl-warn) 12%, transparent)',
                            color: 'var(--fl-warn)', border: '1px solid color-mix(in srgb, var(--fl-warn) 30%, transparent)',
                            fontFamily: 'JetBrains Mono, monospace', fontWeight: 700,
                          }}
                        >
                          🔗 {t('iocs.shared_cases_count', { count: sharedCountMap[ioc.value] })}
                        </button>
                      )}
                    </td>

                    <td>
                      <div className="flex flex-wrap gap-1">
                        {(ioc.tags || []).map(t => <span key={t} className="fl-tag">{t}</span>)}
                      </div>
                    </td>

                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 5 }}>
                        {/* Enrich */}
                        <button onClick={() => handleEnrich(ioc)} disabled={isEnriching} title={t('iocs.enrich_title')}
                          style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 4, cursor: isEnriching ? 'wait' : 'pointer', fontFamily: 'var(--f-mono, monospace)', fontSize: 10.5, background: 'none', color: 'var(--fl-muted)', border: 'none', whiteSpace: 'nowrap' }}
                          onMouseEnter={e => e.currentTarget.style.color = 'var(--fl-text)'}
                          onMouseLeave={e => e.currentTarget.style.color = 'var(--fl-muted)'}>
                          {isEnriching ? <Loader2 size={11} style={{ animation: 'spin 1s linear infinite' }} /> : <Shield size={11} />}
                          {ioc.enriched_at ? t('iocs.reenrich') : t('iocs.enrich')}
                        </button>
                        {/* Cross-case */}
                        <button onClick={() => handleCrossCase(ioc)} title={t('iocs.search_all')}
                          style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', padding: '3px 6px', borderRadius: 4, cursor: 'pointer', background: 'none', color: 'var(--fl-subtle)', border: 'none' }}
                          onMouseEnter={e => e.currentTarget.style.color = 'var(--fl-accent)'}
                          onMouseLeave={e => e.currentTarget.style.color = 'var(--fl-subtle)'}>
                          <GitBranch size={12} />
                        </button>
                        {/* Confirm */}
                        {confirmedIds.has(ioc.id) ? (
                          <span style={{ fontSize: 10, padding: '2px 8px', background: 'color-mix(in srgb, var(--fl-ok) 13%, transparent)', color: 'var(--fl-ok)', borderRadius: 4, border: '1px solid color-mix(in srgb, var(--fl-ok) 25%, transparent)', fontWeight: 700 }}>
                            {t('iocs.confirmed_badge')}
                          </span>
                        ) : confirmingId === ioc.id ? (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, alignItems: 'flex-end' }}>
                            <select value={confirmConf} onChange={e => setConfirmConf(e.target.value)}
                              style={{ fontSize: 10, padding: '2px 4px', background: 'var(--fl-panel)', color: 'var(--fl-text)', border: '1px solid var(--fl-border)', borderRadius: 3 }}>
                              <option value="confirmed">{t('iocs.conf_confirmed')}</option>
                              <option value="high">{t('iocs.conf_high')}</option>
                              <option value="medium">{t('iocs.conf_medium')}</option>
                            </select>
                            <input value={confirmNote} onChange={e => setConfirmNote(e.target.value)} placeholder={t('iocs.note_ph')}
                              style={{ fontSize: 10, padding: '2px 4px', background: 'var(--fl-panel)', color: 'var(--fl-text)', border: '1px solid var(--fl-border)', borderRadius: 3 }} />
                            <div style={{ display: 'flex', gap: 4 }}>
                              <button onClick={() => handleConfirmIOC(ioc)}
                                style={{ fontSize: 10, padding: '2px 6px', background: 'color-mix(in srgb, var(--fl-ok) 13%, transparent)', color: 'var(--fl-ok)', border: '1px solid color-mix(in srgb, var(--fl-ok) 25%, transparent)', borderRadius: 3, cursor: 'pointer' }}>OK</button>
                              <button onClick={() => { setConfirmingId(null); setConfirmConf('confirmed'); setConfirmNote(''); }}
                                style={{ fontSize: 10, padding: '2px 6px', background: 'transparent', color: 'var(--fl-dim)', border: '1px solid var(--fl-border)', borderRadius: 3, cursor: 'pointer' }}>✕</button>
                            </div>
                          </div>
                        ) : (
                          <button onClick={() => setConfirmingId(ioc.id)} title={t('iocs.confirm_ioc_title')}
                            style={{ fontSize: 10, padding: '2px 8px', background: 'color-mix(in srgb, var(--fl-ok) 6%, transparent)', color: 'var(--fl-ok)', border: '1px solid color-mix(in srgb, var(--fl-ok) 19%, transparent)', borderRadius: 4, cursor: 'pointer', fontFamily: 'var(--f-mono, monospace)' }}>
                            {t('common.confirm')}
                          </button>
                        )}
                        {/* Delete */}
                        <button onClick={() => handleDelete(ioc)} disabled={deletingId === ioc.id} title={t('iocs.delete_title')}
                          style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', padding: '3px 6px', background: 'none', color: 'var(--fl-subtle)', border: 'none', borderRadius: 4, cursor: deletingId === ioc.id ? 'wait' : 'pointer', opacity: deletingId === ioc.id ? 0.5 : 1 }}
                          onMouseEnter={e => e.currentTarget.style.color = 'var(--fl-danger)'}
                          onMouseLeave={e => e.currentTarget.style.color = 'var(--fl-subtle)'}>
                          <Trash2 size={13} />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <Modal
        open={showAdd}
        title={t('iocs.add_ioc_modal_title')}
        onClose={() => setShowAdd(false)}
        size="sm"
      >
        <Modal.Body>
          <div className="space-y-4">
            <div>
              <label className="fl-label">{t('iocs.case_label')} <span style={{ color: 'var(--fl-danger)' }}>*</span></label>
              <select
                value={newIOC.case_id}
                onChange={e => setNewIOC(p => ({ ...p, case_id: e.target.value }))}
                className="fl-select w-full"
              >
                <option value="">{t('iocs.select_case')}</option>
                {cases.map(c => (
                  <option key={c.id} value={c.id}>{c.case_number} — {c.title}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="fl-label">Type</label>
              <select
                value={newIOC.ioc_type}
                onChange={e => setNewIOC(p => ({ ...p, ioc_type: e.target.value }))}
                className="fl-select w-full"
              >
                {Object.entries(TYPE_LABEL).map(([v, l]) => (
                  <option key={v} value={v}>{t(`iocs.types.${v}`, { defaultValue: l })}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="fl-label">{t('iocs.value')} <span style={{ color: 'var(--fl-danger)' }}>*</span></label>
              <input
                value={newIOC.value}
                onChange={e => setNewIOC(p => ({ ...p, value: e.target.value }))}
                placeholder={t('iocs.value_ph')}
                className="fl-input w-full"
                style={{ fontFamily: 'JetBrains Mono, monospace' }}
              />
            </div>
            <div>
              <label className="fl-label">Description</label>
              <input
                value={newIOC.description}
                onChange={e => setNewIOC(p => ({ ...p, description: e.target.value }))}
                placeholder={t('iocs.desc_ph')}
                className="fl-input w-full"
              />
            </div>
            <div className="flex gap-4 items-center">
              <div className="flex-1">
                <label className="fl-label">{t('iocs.severity_range')}</label>
                <input
                  type="number" min={1} max={10}
                  value={newIOC.severity}
                  onChange={e => setNewIOC(p => ({ ...p, severity: Number(e.target.value) }))}
                  className="fl-input w-full"
                />
              </div>
              <div>
                <label className="fl-label">{t('iocs.malicious')}</label>
                <label className="flex items-center gap-2 cursor-pointer mt-2 text-sm" style={{ color: newIOC.is_malicious ? 'var(--fl-danger)' : 'var(--fl-muted)' }}>
                  <input
                    type="checkbox"
                    checked={newIOC.is_malicious}
                    onChange={e => setNewIOC(p => ({ ...p, is_malicious: e.target.checked }))}
                  />
                  {newIOC.is_malicious ? t('common.yes') : t('common.no')}
                </label>
              </div>
            </div>
          </div>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowAdd(false)}>{t('common.cancel')}</Button>
          <Button
            variant="primary"
            onClick={handleCreate}
            disabled={!newIOC.value.trim() || !newIOC.case_id}
          >
            {t('common.add')}
          </Button>
        </Modal.Footer>
      </Modal>

      {cases.length > 0 && (
        <div style={{ marginTop: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span style={{ fontSize: 12, color: 'var(--fl-muted)' }}>{t('iocs.dga_label')}</span>
            <select
              value={dgaCaseId}
              onChange={e => setDgaCaseId(e.target.value)}
              className="fl-select"
              style={{ fontSize: 12 }}
            >
              <option value="">{t('iocs.select_case')}</option>
              {cases.map(c => (
                <option key={c.id} value={c.id}>{c.case_number} — {c.title}</option>
              ))}
            </select>
          </div>
          <DgaPanel caseId={dgaCaseId} />
        </div>
      )}

      
      {pivotIOC && (
        <Modal
          open={!!pivotIOC}
          title={t('iocs.pivot_title')}
          onClose={() => { setPivotIOC(null); setPivotResults([]); }}
          size="md"
        >
          <Modal.Body>
            <div style={{ marginBottom: 12, padding: '8px 12px', borderRadius: 6, background: 'color-mix(in srgb, var(--fl-accent) 6%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 20%, transparent)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12, wordBreak: 'break-all', color: 'var(--fl-accent)' }}>
              {pivotIOC.value}
            </div>
            {pivotLoading ? (
              <div style={{ textAlign: 'center', padding: '24px 0' }}>
                <span style={{ color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12 }}>{t('iocs.searching')}</span>
              </div>
            ) : pivotResults.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '24px 0', color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12 }}>
                {t('iocs.no_shared_case')}
              </div>
            ) : (
              <>
                <p style={{ fontSize: 12, color: 'var(--fl-dim)', marginBottom: 10 }}>
                  {t('iocs.shared_case_summary', { count: pivotResults.length })}
                </p>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--fl-border)' }}>
                      {[t('iocs.col_case'), t('iocs.col_title'), t('iocs.col_status'), t('iocs.col_type'), t('iocs.col_first_seen')].map(h => (
                        <th key={h} style={{ textAlign: 'left', padding: '4px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: 'var(--fl-muted)', fontWeight: 700, textTransform: 'uppercase' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {pivotResults.map((r, i) => (
                      <tr key={`${r.id}-${i}`} style={{ borderBottom: '1px solid var(--fl-border)' }}>
                        <td style={{ padding: '6px 8px' }}>
                          <a href={`/cases/${r.id}`} style={{ color: 'var(--fl-accent)', textDecoration: 'none', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11 }} onClick={e => { e.preventDefault(); window.location.href = `/cases/${r.id}`; }}>
                            {r.case_number}
                          </a>
                        </td>
                        <td style={{ padding: '6px 8px', color: 'var(--fl-dim)', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.title}</td>
                        <td style={{ padding: '6px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: 'var(--fl-muted)' }}>{r.status}</td>
                        <td style={{ padding: '6px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: 'var(--fl-dim)' }}>{t(`iocs.types.${r.ioc_type}`, { defaultValue: TYPE_LABEL[r.ioc_type] || r.ioc_type })}</td>
                        <td style={{ padding: '6px 8px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: 'var(--fl-muted)', whiteSpace: 'nowrap' }}>
                          {r.ioc_created_at ? new Date(r.ioc_created_at).toLocaleDateString(i18n.language) : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </Modal.Body>
          <Modal.Footer>
            <Button variant="secondary" onClick={() => { setPivotIOC(null); setPivotResults([]); }}>{t('common.close')}</Button>
          </Modal.Footer>
        </Modal>
      )}
    </div>
  );
}
