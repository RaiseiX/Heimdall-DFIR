import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Crosshair, Plus, AlertTriangle, Globe, Hash, FileText,
  User, Server, Search, X, Shield, ShieldAlert, RefreshCw,
  CheckCircle, HelpCircle, Zap, Download, GitBranch
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
  filename: 'Fichier', registry_key: 'Registry', mutex: 'Mutex',
  user_agent: 'UserAgent', email: 'Email', other: 'Autre',
};

const SEV_VARIANT = (s) => s >= 8 ? 'danger' : s >= 5 ? 'warn' : 'dim';

function VTBadge({ ioc }) {
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
      title={`VirusTotal — ${ioc.vt_malicious ?? '?'} moteurs malveillants sur ${ioc.vt_total ?? '?'}`}
    >
      <Shield size={9} className="inline mr-1" />{label}
    </Badge>
  );
}

function AbuseIPDBBadge({ ioc }) {
  if (ioc.ioc_type !== 'ip' || ioc.abuseipdb_score == null) return null;
  const s = ioc.abuseipdb_score;
  const variant = s >= 80 ? 'danger' : s >= 40 ? 'warn' : s > 0 ? 'gold' : 'ok';
  return (
    <Badge
      variant={variant}
      title={`AbuseIPDB — Score de confiance : ${s}%`}
    >
      <ShieldAlert size={9} className="inline mr-1" />Abuse {s}%
    </Badge>
  );
}

function ShodanBadge({ ioc }) {
  if (ioc.ioc_type !== 'ip') return null;
  const ports = ioc.enrichment_data?.shodan_ports ?? ioc.shodan_ports;
  const vulns = ioc.enrichment_data?.shodan_vulns ?? ioc.shodan_vulns;
  if (!Array.isArray(ports) || ports.length === 0) return null;
  const hasVulns = Array.isArray(vulns) && vulns.length > 0;
  const variant = hasVulns ? 'danger' : 'dim';
  const portsLabel = `${ports.length} port${ports.length > 1 ? 's' : ''}`;
  const vulnsLabel = hasVulns ? ` / ${vulns.length} CVE${vulns.length > 1 ? 's' : ''}` : '';
  const title = [
    `Shodan — Ports ouverts : ${ports.join(', ')}`,
    hasVulns ? `CVEs : ${vulns.join(', ')}` : '',
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
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, fontSize: 11, color: '#7d8590' }}>
      <span style={{ fontSize: 14 }}>{flag}</span>
      <span>{ioc.geo_country || ioc.geo_country_code}</span>
      {ioc.geo_is_proxy && <span style={{ fontSize: 10, padding: '1px 4px', background: '#d97c2020', color: '#d97c20', borderRadius: 3, border: '1px solid #d97c2040' }}>PROXY</span>}
      {ioc.geo_is_hosting && <span style={{ fontSize: 10, padding: '1px 4px', background: '#8b5cf620', color: '#8b5cf6', borderRadius: 3, border: '1px solid #8b5cf640' }}>HOSTING</span>}
    </span>
  );
}

function DgaPanel({ caseId }) {
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
    <div style={{ marginTop: 16, background: '#161b22', border: '1px solid #30363d', borderRadius: 8, overflow: 'hidden' }}>
      <div style={{ padding: '10px 16px', borderBottom: '1px solid #21303f', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: '#e6edf3', display: 'flex', alignItems: 'center', gap: 6 }}>
          <span>🧬</span> Détection DGA (Domain Generation Algorithm)
          {data && <span style={{ fontSize: 11, color: '#7d8590', fontWeight: 400 }}>— {data.total} domaines, {data.suspicious_count} suspects</span>}
        </div>
        <button onClick={analyze} disabled={loading} style={{ fontSize: 11, padding: '4px 10px', background: '#1c6ef2', color: '#fff', border: 'none', borderRadius: 5, cursor: 'pointer' }}>
          {loading ? '…' : 'Analyser'}
        </button>
      </div>
      {data && data.domains.length > 0 && (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ background: '#0d1117' }}>
              {['Domaine', 'Entropie', 'Ratio consonnes', 'Longueur', 'Score DGA', 'Statut'].map(h => (
                <th key={h} style={{ padding: '6px 12px', textAlign: 'left', color: '#7d8590', fontWeight: 600, borderBottom: '1px solid #21303f' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.domains.map((d, i) => (
              <tr key={d.domain} style={{ background: d.is_suspicious ? '#2d1515' : i % 2 === 0 ? '#161b22' : '#0d1117', borderBottom: '1px solid #21303f10' }}>
                <td style={{ padding: '5px 12px', color: '#e6edf3', fontFamily: 'monospace' }}>{d.domain}</td>
                <td style={{ padding: '5px 12px', color: d.entropy > 3.5 ? '#f97316' : '#7d8590' }}>{d.entropy}</td>
                <td style={{ padding: '5px 12px', color: d.consonant_ratio > 0.65 ? '#f97316' : '#7d8590' }}>{(d.consonant_ratio * 100).toFixed(0)}%</td>
                <td style={{ padding: '5px 12px', color: '#7d8590' }}>{d.length}</td>
                <td style={{ padding: '5px 12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <div style={{ flex: 1, height: 6, background: '#21303f', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${d.dga_score}%`, background: d.dga_score >= 60 ? '#da3633' : d.dga_score >= 40 ? '#d97c20' : '#22c55e', borderRadius: 3 }} />
                    </div>
                    <span style={{ fontSize: 11, color: '#7d8590', minWidth: 28 }}>{d.dga_score}</span>
                  </div>
                </td>
                <td style={{ padding: '5px 12px' }}>
                  {d.is_suspicious
                    ? <span style={{ fontSize: 10, padding: '2px 6px', background: '#da363320', color: '#da3633', borderRadius: 4, border: '1px solid #da363340' }}>SUSPECT</span>
                    : <span style={{ fontSize: 10, padding: '2px 6px', background: '#22c55e20', color: '#22c55e', borderRadius: 4 }}>OK</span>
                  }
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data && data.domains.length === 0 && (
        <div style={{ padding: 24, textAlign: 'center', color: '#7d8590', fontSize: 12 }}>Aucun domaine IOC trouvé dans ce cas</div>
      )}
    </div>
  );
}

export default function IOCsPage() {
  const { t } = useTranslation();
  const [iocs, setIocs] = useState([]);
  const [cases, setCases] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [showAdd, setShowAdd] = useState(false);
  const [newIOC, setNewIOC] = useState({ ioc_type: 'ip', value: '', description: '', severity: 5, is_malicious: false, case_id: '' });
  const [enriching, setEnriching] = useState({});
  const [enrichingAll, setEnrichingAll] = useState(false);
  const [error, setError] = useState('');
  const [pivotIOC, setPivotIOC] = useState(null);
  const [pivotResults, setPivotResults] = useState([]);
  const [pivotLoading, setPivotLoading] = useState(false);
  const [confirmingId, setConfirmingId] = useState(null);
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
      setError('Erreur de chargement des IOCs.');
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
      setError('Erreur lors de la création de l\'IOC.');
    }
  }

  const [dgaCaseId, setDgaCaseId] = useState('');

  const malCount = iocs.filter(i => i.is_malicious).length;
  const enrichedCount = iocs.filter(i => i.enriched_at).length;
  const types = [...new Set(iocs.map(i => i.ioc_type))].filter(Boolean);

  return (
    <div className="p-6">
      
      <div className="fl-header">
        <div>
          <h1 className="fl-header-title">Indicateurs de Compromission</h1>
          <p className="fl-header-sub">
            {iocs.length} IOCs
            {malCount > 0 && <> · <span style={{ color: 'var(--fl-danger)' }}>{malCount} malveillants</span></>}
            {enrichedCount > 0 && <> · <span style={{ color: 'var(--fl-ok)' }}>{enrichedCount} enrichis</span></>}
            {typeFilter !== 'all' && <span style={{ color: 'var(--fl-accent)' }}> · filtre : {typeFilter}</span>}
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="secondary"
            icon={Download}
            disabled={iocs.length === 0}
            onClick={() => downloadCSV(iocs, [
              { key: 'ioc_type',    label: 'Type' },
              { key: 'value',       label: 'Valeur' },
              { key: 'description', label: 'Description' },
              { key: 'severity',    label: 'Sévérité' },
              { key: 'is_malicious',label: 'Malveillant' },
              { key: 'source',      label: 'Source' },
              { key: 'tags',        label: 'Tags' },
              { key: 'case_id',     label: 'Cas' },
              { key: 'vt_verdict',  label: 'VT Verdict' },
              { key: 'created_at',  label: 'Créé le' },
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
          {types.map(tp => <option key={tp} value={tp}>{TYPE_LABEL[tp] || tp}</option>)}
        </select>
        {(search || typeFilter !== 'all') && (
          <Button variant="ghost" size="sm" icon={X} onClick={() => { setSearch(''); setTypeFilter('all'); }}>
            {t('cases.clear_filters')}
          </Button>
        )}
        <Button variant="ghost" size="sm" icon={RefreshCw} onClick={loadData} title={t('iocs.tooltip_refresh')} />
      </div>

      <div className="mb-4 p-3 rounded-lg text-xs" style={{ background: 'color-mix(in srgb, var(--fl-accent) 5%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 15%, transparent)', color: 'var(--fl-accent)' }}>
        Enrichissement via VirusTotal et AbuseIPDB — cache 24h. Les clés API se configurent dans <code>.env</code> (VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY).
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
                <th style={{ width: 44 }}>Sév.</th>
                <th>Type / Valeur</th>
                <th>Description</th>
                <th>Enrichissement</th>
                <th>Cas</th>
                <th>Tags</th>
                <th style={{ width: 80 }}></th>
              </tr>
            </thead>
            <tbody>
              {iocs.map(ioc => {
                const Icon = TYPE_ICON[ioc.ioc_type] || Globe;
                const sevVariant = SEV_VARIANT(ioc.severity || 5);
                const isEnriching = enriching[ioc.id];
                return (
                  <tr key={ioc.id} style={{ borderLeft: `3px solid ${ioc.is_malicious ? 'var(--fl-danger)' : 'var(--fl-border)'}` }}>
                    
                    <td>
                      <Badge variant={sevVariant} style={{ minWidth: 32, justifyContent: 'center', display: 'inline-flex' }}>
                        {ioc.severity || 5}
                      </Badge>
                    </td>

                    <td>
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <Badge variant="accent">
                          <Icon size={10} className="inline mr-1" />{TYPE_LABEL[ioc.ioc_type] || ioc.ioc_type}
                        </Badge>
                        {ioc.is_malicious && (
                          <Badge variant="danger">
                            <AlertTriangle size={9} className="inline mr-1" />MALVEILLANT
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
                                <CheckCircle size={12} className="inline mr-1" />enrichi
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
                          title="Voir tous les cas partageant cet IOC"
                          style={{
                            marginTop: 4, display: 'inline-flex', alignItems: 'center', gap: 4,
                            fontSize: 10, padding: '1px 6px', borderRadius: 4, cursor: 'pointer',
                            background: 'color-mix(in srgb, var(--fl-warn) 12%, transparent)',
                            color: 'var(--fl-warn)', border: '1px solid color-mix(in srgb, var(--fl-warn) 30%, transparent)',
                            fontFamily: 'JetBrains Mono, monospace', fontWeight: 700,
                          }}
                        >
                          🔗 {sharedCountMap[ioc.value]} cas
                        </button>
                      )}
                    </td>

                    <td>
                      <div className="flex flex-wrap gap-1">
                        {(ioc.tags || []).map(t => <span key={t} className="fl-tag">{t}</span>)}
                      </div>
                    </td>

                    <td>
                      <div style={{ display: 'flex', gap: 4, alignItems: 'center', flexWrap: 'wrap' }}>
                        <Button
                          variant="ghost"
                          size="sm"
                          icon={isEnriching ? undefined : Shield}
                          loading={isEnriching}
                          onClick={() => handleEnrich(ioc)}
                          title={t('iocs.enrich_title')}
                          style={{ whiteSpace: 'nowrap' }}
                        >
                          {ioc.enriched_at ? 'Ré-enrichir' : 'Enrichir'}
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          icon={GitBranch}
                          onClick={() => handleCrossCase(ioc)}
                          title={t('iocs.search_all')}
                        />
                        {confirmedIds.has(ioc.id) ? (
                          <span style={{ fontSize: 10, padding: '2px 7px', background: '#22c55e20', color: '#22c55e', borderRadius: 4, border: '1px solid #22c55e40', fontWeight: 700, whiteSpace: 'nowrap' }}>
                            CONFIRMÉ ✓
                          </span>
                        ) : confirmingId === ioc.id ? (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, padding: '4px 0' }}>
                            <select
                              value={confirmConf}
                              onChange={e => setConfirmConf(e.target.value)}
                              style={{ fontSize: 10, padding: '2px 4px', background: '#161b22', color: '#e6edf3', border: '1px solid #30363d', borderRadius: 3 }}
                            >
                              <option value="confirmed">Confirmé</option>
                              <option value="high">Haute confiance</option>
                              <option value="medium">Confiance moyenne</option>
                            </select>
                            <input
                              value={confirmNote}
                              onChange={e => setConfirmNote(e.target.value)}
                              placeholder={t('iocs.note_ph')}
                              style={{ fontSize: 10, padding: '2px 4px', background: '#161b22', color: '#e6edf3', border: '1px solid #30363d', borderRadius: 3 }}
                            />
                            <div style={{ display: 'flex', gap: 4 }}>
                              <button
                                onClick={() => handleConfirmIOC(ioc)}
                                style={{ fontSize: 10, padding: '2px 6px', background: '#22c55e20', color: '#22c55e', border: '1px solid #22c55e40', borderRadius: 3, cursor: 'pointer' }}
                              >
                                OK
                              </button>
                              <button
                                onClick={() => { setConfirmingId(null); setConfirmConf('confirmed'); setConfirmNote(''); }}
                                style={{ fontSize: 10, padding: '2px 6px', background: 'transparent', color: '#7d8590', border: '1px solid #30363d', borderRadius: 3, cursor: 'pointer' }}
                              >
                                ✕
                              </button>
                            </div>
                          </div>
                        ) : (
                          <button
                            onClick={() => setConfirmingId(ioc.id)}
                            title={t('iocs.confirm_ioc_title')}
                            style={{ fontSize: 10, padding: '2px 7px', background: '#22c55e10', color: '#22c55e', border: '1px solid #22c55e30', borderRadius: 4, cursor: 'pointer', whiteSpace: 'nowrap' }}
                          >
                            Confirmer
                          </button>
                        )}
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
              <label className="fl-label">Cas <span style={{ color: 'var(--fl-danger)' }}>*</span></label>
              <select
                value={newIOC.case_id}
                onChange={e => setNewIOC(p => ({ ...p, case_id: e.target.value }))}
                className="fl-select w-full"
              >
                <option value="">— Sélectionner un cas —</option>
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
                  <option key={v} value={v}>{l}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="fl-label">Valeur <span style={{ color: 'var(--fl-danger)' }}>*</span></label>
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
                <label className="fl-label">Sévérité (1–10)</label>
                <input
                  type="number" min={1} max={10}
                  value={newIOC.severity}
                  onChange={e => setNewIOC(p => ({ ...p, severity: Number(e.target.value) }))}
                  className="fl-input w-full"
                />
              </div>
              <div>
                <label className="fl-label">Malveillant</label>
                <label className="flex items-center gap-2 cursor-pointer mt-2 text-sm" style={{ color: newIOC.is_malicious ? 'var(--fl-danger)' : 'var(--fl-muted)' }}>
                  <input
                    type="checkbox"
                    checked={newIOC.is_malicious}
                    onChange={e => setNewIOC(p => ({ ...p, is_malicious: e.target.checked }))}
                  />
                  {newIOC.is_malicious ? 'Oui' : 'Non'}
                </label>
              </div>
            </div>
          </div>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowAdd(false)}>Annuler</Button>
          <Button
            variant="primary"
            onClick={handleCreate}
            disabled={!newIOC.value.trim() || !newIOC.case_id}
          >
            Ajouter
          </Button>
        </Modal.Footer>
      </Modal>

      {cases.length > 0 && (
        <div style={{ marginTop: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span style={{ fontSize: 12, color: 'var(--fl-muted)' }}>Cas pour l'analyse DGA :</span>
            <select
              value={dgaCaseId}
              onChange={e => setDgaCaseId(e.target.value)}
              className="fl-select"
              style={{ fontSize: 12 }}
            >
              <option value="">— Sélectionner un cas —</option>
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
          title="Pivot Multi-Cas"
          onClose={() => { setPivotIOC(null); setPivotResults([]); }}
          size="md"
        >
          <Modal.Body>
            <div style={{ marginBottom: 12, padding: '8px 12px', borderRadius: 6, background: 'color-mix(in srgb, var(--fl-accent) 6%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 20%, transparent)', fontFamily: 'monospace', fontSize: 12, wordBreak: 'break-all', color: 'var(--fl-accent)' }}>
              {pivotIOC.value}
            </div>
            {pivotLoading ? (
              <div style={{ textAlign: 'center', padding: '24px 0' }}>
                <span style={{ color: 'var(--fl-muted)', fontFamily: 'monospace', fontSize: 12 }}>Recherche en cours…</span>
              </div>
            ) : pivotResults.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '24px 0', color: 'var(--fl-muted)', fontFamily: 'monospace', fontSize: 12 }}>
                Aucun autre cas ne partage cet indicateur.
              </div>
            ) : (
              <>
                <p style={{ fontSize: 12, color: 'var(--fl-dim)', marginBottom: 10 }}>
                  {pivotResults.length} cas partage{pivotResults.length > 1 ? 'nt' : ''} cet indicateur :
                </p>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--fl-border)' }}>
                      {['Cas', 'Titre', 'Statut', 'Type IOC', 'Première vue'].map(h => (
                        <th key={h} style={{ textAlign: 'left', padding: '4px 8px', fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-muted)', fontWeight: 700, textTransform: 'uppercase' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {pivotResults.map((r, i) => (
                      <tr key={`${r.id}-${i}`} style={{ borderBottom: '1px solid var(--fl-border)' }}>
                        <td style={{ padding: '6px 8px' }}>
                          <a href={`/cases/${r.id}`} style={{ color: 'var(--fl-accent)', textDecoration: 'none', fontFamily: 'monospace', fontSize: 11 }} onClick={e => { e.preventDefault(); window.location.href = `/cases/${r.id}`; }}>
                            {r.case_number}
                          </a>
                        </td>
                        <td style={{ padding: '6px 8px', color: 'var(--fl-dim)', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.title}</td>
                        <td style={{ padding: '6px 8px', fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-muted)' }}>{r.status}</td>
                        <td style={{ padding: '6px 8px', fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-dim)' }}>{TYPE_LABEL[r.ioc_type] || r.ioc_type}</td>
                        <td style={{ padding: '6px 8px', fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-muted)', whiteSpace: 'nowrap' }}>
                          {r.ioc_created_at ? new Date(r.ioc_created_at).toLocaleDateString('fr-FR') : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </Modal.Body>
          <Modal.Footer>
            <Button variant="secondary" onClick={() => { setPivotIOC(null); setPivotResults([]); }}>Fermer</Button>
          </Modal.Footer>
        </Modal>
      )}
    </div>
  );
}
