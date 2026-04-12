import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useTheme } from '../utils/theme';
import { useParams, useNavigate, useOutletContext } from 'react-router-dom';
import { FolderOpen, Clock, Crosshair, Network, FileDown, Star, Plus, Search, AlertTriangle, Download, ChevronRight, Loader2, Shield, Trash2, Cpu, ScrollText, Copy, RefreshCw, Link2, CalendarDays, Pencil, Wifi, BookOpen, Lock, Activity, FileJson, Upload, X, CheckCircle, Sparkles, FlaskConical } from 'lucide-react';
import api, { casesAPI, evidenceAPI, iocsAPI, timelineAPI, collectionAPI, detectionsAPI, parsersAPI, pcapAPI, legalHoldAPI } from '../utils/api';
import AiCopilotModal from '../components/ai/AiCopilotModal';
import { Button, Modal, Spinner, Pagination } from '../components/ui';
import { downloadCSV } from '../utils/csvExport';

import MitreAttackTab from '../components/mitre/MitreAttackTab';

import CaseHayabusaView from '../components/hayabusa/CaseHayabusaView';
import CatScaleTimelineTab from '../components/catscale/CatScaleTimelineTab';
import AttackChain from '../components/timeline/AttackChain';
import DetectionsTab from '../components/detections/DetectionsTab';
import CaseChatPanel from '../components/chat/CaseChatPanel';
import CollectionImportPanel from '../components/collection/CollectionImportPanel';
import { useSocket, useSocketEvent } from '../hooks/useSocket';
import MachineScorePanel from '../components/triage/MachineScorePanel';
import PlaybooksTab from '../components/playbooks/PlaybooksTab';
import MemoryUploadPanel from '../components/upload/MemoryUploadPanel';
import ReportTemplateModal from '../components/reports/ReportTemplateModal';
import CyberChefPage from './CyberChefPage';

const PC = { critical: '#da3633', high: '#d97c20', medium: '#c89d1d', low: '#3fb950' };
const EC = { alert: '#da3633', malware: '#d97c20', exfil: '#c89d1d', network: '#4d82c0', analysis: '#8b72d6', response: '#3fb950', persistence: '#f472b6', other: '#7d8590' };

const ARTIFACT_COLORS = {
  evtx: '#4d82c0', hayabusa: '#da3633', mft: '#8b72d6', prefetch: '#22c55e', lnk: '#d97c20',
  registry: '#c96898', amcache: '#c89d1d', appcompat: '#f59e0b', shellbags: '#06b6d4',
  jumplist: '#8b5cf6', srum: '#f43f5e', wxtcmd: '#14b8a6', recycle: '#84cc16',
  sum: '#d946ef', bits: '#fb923c', collection: '#7d8590',
};

function fmtSize(b) {
  if (!b) return '0 B';
  const k = 1024, s = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(b) / Math.log(k)), s.length - 1);
  return `${(b / Math.pow(k, i)).toFixed(1)} ${s[i]}`;
}

function ColorBadge({ color, children }) {
  return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-semibold" style={{ background: `${color}15`, color, border: `1px solid ${color}30` }}>{children}</span>;
}

function HexStringsPreview({ evId }) {
  const { t } = useTranslation();
  const [activeTab, setActiveTab] = useState('hex');
  const [hexData, setHexData] = useState(null);
  const [stringsData, setStringsData] = useState(null);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [previewError, setPreviewError] = useState(null);
  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      if (activeTab === 'hex' && hexData !== null) return;
      if (activeTab === 'strings' && stringsData !== null) return;
      setLoadingPreview(true);
      setPreviewError(null);
      try {
        if (activeTab === 'hex') {
          const res = await evidenceAPI.hex(evId, 0, 256);
          if (!cancelled) setHexData(res.data?.hex || (typeof res.data === 'string' ? res.data : '') || '');
        } else {
          const res = await evidenceAPI.strings(evId, 4);
          const raw = res.data?.strings || res.data;
          if (!cancelled) setStringsData(Array.isArray(raw) ? raw : (typeof raw === 'string' ? raw.split('\n') : []));
        }
      } catch (e) {
        if (!cancelled) setPreviewError(e.response?.data?.error || e.message);
      } finally {
        if (!cancelled) setLoadingPreview(false);
      }
    };
    load();
    return () => { cancelled = true; };
  }, [activeTab, evId]);
  return (
    <div style={{ borderRadius: 7, border: '1px solid #da363330', background: '#1a0f0f', overflow: 'hidden' }}>
      <div style={{ display: 'flex', borderBottom: '1px solid #da363325' }}>
        {[['hex', 'Hex'], ['strings', 'Strings']].map(([key, label]) => (
          <button key={key} onClick={() => setActiveTab(key)} style={{ padding: '5px 14px', fontSize: 10, fontFamily: 'monospace', background: 'none', border: 'none', outline: 'none', cursor: 'pointer', borderBottom: `2px solid ${activeTab === key ? '#da3633' : 'transparent'}`, color: activeTab === key ? '#da3633' : '#484f58', marginBottom: -1, transition: 'color 0.1s' }}>{label}</button>
        ))}
        <span style={{ marginLeft: 'auto', padding: '5px 10px', fontSize: 9, fontFamily: 'monospace', color: '#da363360', alignSelf: 'center' }}>SUSPECT</span>
      </div>
      <div style={{ padding: '8px 10px', maxHeight: 200, overflowY: 'auto' }}>
        {loadingPreview ? (
          <div style={{ fontSize: 11, fontFamily: 'monospace', color: '#484f58', textAlign: 'center', padding: '12px 0' }}>{t('casedetail.hex_loading')}</div>
        ) : previewError ? (
          <div style={{ fontSize: 11, fontFamily: 'monospace', color: '#da3633' }}>{previewError}</div>
        ) : activeTab === 'hex' ? (
          <pre style={{ fontSize: 10, fontFamily: 'monospace', color: '#da363390', margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: 1.6 }}>{hexData || t('casedetail.hex_empty')}</pre>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {(stringsData || []).filter(Boolean).map((s, i) => (<span key={i} style={{ fontSize: 10, fontFamily: 'monospace', color: '#c89d1d', padding: '1px 0' }}>{s}</span>))}
            {(!stringsData || stringsData.filter(Boolean).length === 0) && (<span style={{ fontSize: 11, fontFamily: 'monospace', color: '#484f58' }}>{t('casedetail.no_strings')}</span>)}
          </div>
        )}
      </div>
    </div>
  );
}

function TopNavBtn({ onClick, isActive, activeBorderColor = '#4d82c0', activeTextColor = '#b0ccec', icon: Icon, label, padding = '0 10px' }) {
  const inactiveColor = '#3d5070';
  return (
    <button
      onClick={onClick}
      style={{
        display: 'flex', alignItems: 'center', gap: 5, padding,
        height: '100%', fontFamily: 'monospace', fontSize: 11,
        background: 'none', border: 'none', outline: 'none', flexShrink: 0,
        borderBottom: `2px solid ${isActive ? activeBorderColor : 'transparent'}`,
        color: isActive ? activeTextColor : inactiveColor,
        cursor: 'pointer', whiteSpace: 'nowrap', marginBottom: -1,
        transition: 'color 0.1s',
      }}
      onMouseEnter={e => { if (!isActive) e.currentTarget.style.color = '#7d8590'; }}
      onMouseLeave={e => { if (!isActive) e.currentTarget.style.color = inactiveColor; }}
    >
      <Icon size={11} /> {label}
    </button>
  );
}

export default function CaseDetailPage({ user }) {
  const { t, i18n } = useTranslation();
  const T = useTheme();
  const params = useParams();
  const shellCtx = useOutletContext() || {};
  const id = shellCtx.caseId || params.id;
  const collectionId = params.collectionId;
  const navigate = useNavigate();

  const TABS = useMemo(() => [
    { id: 'evidence',    label: t('casedetail.tab_evidence'),   icon: FolderOpen },
    { id: 'timeline',   label: 'Super Timeline',                icon: Clock },
    { id: 'iocs',       label: 'IOCs',                          icon: Crosshair },
    { id: 'detections', label: t('casedetail.tab_detections'),  icon: AlertTriangle },
    { id: 'network',    label: t('casedetail.tab_network'),     icon: Network },
    { id: 'mitre',      label: 'MITRE ATT\u0026CK',            icon: Shield },
    { id: 'playbooks',  label: t('casedetail.tab_playbooks'),   icon: BookOpen },
    { id: 'hayabusa',  label: 'Hayabusa',                       icon: Activity },
    { id: 'cyberchef', label: 'CyberChef',                     icon: FlaskConical },
    { id: 'audit',      label: t('casedetail.tab_audit'),       icon: ScrollText },
  ], [t]);

  const SM = useMemo(() => ({
    active:  { l: t('casedetail.status_active'),  c: '#4d82c0' },
    pending: { l: t('casedetail.status_pending'), c: '#d97c20' },
    closed:  { l: t('casedetail.status_closed'),  c: '#7d8590' },
  }), [t]);

  const { tab: urlTab } = useParams();
  const tab = urlTab || 'evidence';
  const base = collectionId ? `/cases/${id}/collections/${collectionId}` : `/cases/${id}`;
  const [loading, setLoading] = useState(true);
  const [caseData, setCaseData] = useState(null);
  const [evidence, setEvidence] = useState([]);
  const [selEv, setSelEv] = useState(null);

  const [iocSearch, setIocSearch] = useState('');
  const [generating, setGenerating] = useState(false);
  const [reportDone, setReportDone] = useState(false);
  const [showTemplateModal, setShowTemplateModal] = useState(false);
  const [selectedTemplate, setSelectedTemplate]   = useState(null);

  const [caseIOCs, setCaseIOCs] = useState([]);
  const [caseTL, setCaseTL] = useState([]);
  const [auditEntries, setAuditEntries] = useState([]);
  const [auditTotal, setAuditTotal] = useState(0);
  const [auditPage, setAuditPage] = useState(0);
  const [auditFilterAction, setAuditFilterAction] = useState('');
  const [auditFilterUser, setAuditFilterUser] = useState('');
  const [auditFilterFrom, setAuditFilterFrom] = useState('');
  const [auditFilterTo, setAuditFilterTo] = useState('');
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [reportId, setReportId] = useState(null);
  const [showImportPanel, setShowImportPanel] = useState(false);
  const [evResultMap, setEvResultMap] = useState({});
  const [showIOCForm, setShowIOCForm] = useState(false);
  const [iocSaving, setIocSaving] = useState(false);
  const [iocForm, setIocForm] = useState({ ioc_type: 'ip', value: '', description: '', severity: 5, is_malicious: false, source: '', tags: '' });
  const [showStixImport, setShowStixImport] = useState(false);
  const [stixFiles, setStixFiles] = useState([]);
  const [stixImporting, setStixImporting] = useState(false);
  const [stixResult, setStixResult] = useState(null);
  const [stTotal, setStTotal] = useState(0);
  const [stReparsing, setStReparsing] = useState(false);
  const [stReloadKey, setStReloadKey] = useState(0);
  const [hayCount, setHayCount] = useState(0);
  const [catscaleCount, setCatscaleCount] = useState(0);
  const [stParseProgress, setStParseProgress] = useState(null);
  const { socket, socketId } = useSocket();
  const stProgressRef = useRef(null);
  const [subTab, setSubTab] = useState(null);
  const [showDeleteCollect, setShowDeleteCollect] = useState(false);
  const [deletingCollect, setDeletingCollect] = useState(false);
  const [evToDelete, setEvToDelete] = useState(null);
  const [deletingEv, setDeletingEv] = useState(false);
  const [presenceUsers, setPresenceUsers] = useState([]);
  const [statusModal, setStatusModal] = useState(null);
  const [statusChanging, setStatusChanging] = useState(false);
  const [editDeadline, setEditDeadline] = useState(false);
  const [deadlineVal, setDeadlineVal] = useState('');
  const [deadlineSaving, setDeadlineSaving] = useState(false);
  const [showHardDelete, setShowHardDelete] = useState(false);
  const [hardDeleteConfirm, setHardDeleteConfirm] = useState('');
  const [hardDeleting, setHardDeleting] = useState(false);
  const [hardDeleteResult, setHardDeleteResult] = useState(null);
  const [pcapState, setPcapState] = useState({});
  const [networkConns, setNetworkConns] = useState([]);
  const [networkStats, setNetworkStats] = useState(null);
  const [triageData, setTriageData] = useState(null);
  const [triageRunning, setTriageRunning] = useState(false);
  const [showTriageModal, setShowTriageModal] = useState(false);
  const [showMemUpload, setShowMemUpload]   = useState(false);
  const [volwebSsoUrl,  setVolwebSsoUrl]    = useState(null);
  const [volwebLoading, setVolwebLoading]   = useState(false);
  const [volwebStatus,  setVolwebStatus]    = useState(null);
  const [volwebRetrying,  setVolwebRetrying]  = useState(null);
  const [volwebProgress,  setVolwebProgress]  = useState({});
  const [parserRunning, setParserRunning]   = useState(null);
  const [parserResults, setParserResults]   = useState([]);
  const [legalHoldModal, setLegalHoldModal] = useState(false);
  const [legalHoldReason, setLegalHoldReason] = useState('');
  const [aiOpen, setAiOpen] = useState(false);
  const [legalHoldSaving, setLegalHoldSaving] = useState(false);
  useEffect(() => {
    if (!socket || !id) return;
    socket.emit('case:join', { caseId: id });
    return () => { socket.emit('case:leave', { caseId: id }); };
  }, [socket, id]);

  useSocketEvent(socket, 'case:presence', (users) => {
    setPresenceUsers(Array.isArray(users) ? users : []);
  });

  const refreshEvResultMap = useCallback(async () => {
    try {
      const prRes = await parsersAPI.results(id);
      if (!prRes.data) return;
      const list = Array.isArray(prRes.data) ? prRes.data : [];
      const map = {};
      list.forEach(r => {
        if (!r.evidence_name) return;
        if (!map[r.evidence_name] || (r.record_count ?? 0) > (map[r.evidence_name].recordCount ?? 0)) {
          map[r.evidence_name] = { resultId: r.id, recordCount: r.record_count ?? 0 };
        }
      });
      setEvResultMap(map);
    } catch {}
  }, [id]);

  useSocketEvent(socket, 'collection:parse:done', () => {
    refreshEvResultMap();
  });

  useSocketEvent(socket, 'volweb:processing', (data) => {
    if (data.caseId !== id) return;
    setEvidence(prev => prev.map(ev =>
      ev.id === data.evidenceId ? { ...ev, volweb_status: 'processing' } : ev
    ));
  });
  useSocketEvent(socket, 'volweb:completed', (data) => {
    if (data.caseId !== id) return;
    setEvidence(prev => prev.map(ev =>
      ev.id === data.evidenceId ? { ...ev, volweb_status: data.status } : ev
    ));
    api.get(`/volweb/status/${id}`).then(r => setVolwebStatus(r.data)).catch(() => {});
  });
  useSocketEvent(socket, 'volweb:ready', (data) => {
    if (data.caseId !== id) return;
    if (data.status === 'error') {
      setEvidence(prev => prev.map(ev =>
        ev.id === data.evidenceId ? { ...ev, volweb_status: 'error' } : ev
      ));
    }
    api.get(`/volweb/status/${id}`).then(r => setVolwebStatus(r.data)).catch(() => {});
  });

  const openVolWeb = useCallback(async (caseId) => {
    setVolwebLoading(true);
    const win = window.open('', '_blank');
    try {
      const res = await api.get('/volweb/magic-link', { params: { caseId } });
      const { url } = res.data;
      setVolwebSsoUrl(url);
      if (win) {
        win.location.href = url;
      } else {
        window.location.href = url;
      }
    } catch (err) {
      if (win) win.close();
      const code = err.response?.data?.code;
      const msg  = err.response?.data?.error || err.message;
      if (code === 'NO_VOLWEB_CASE') {
        setShowMemUpload(true);
      } else {
        alert(`VolWeb SSO : ${msg}`);
      }
    } finally {
      setVolwebLoading(false);
    }
  }, []);

  const retryVolWeb = useCallback(async (evidenceId) => {
    setVolwebRetrying(evidenceId);
    try {
      await api.post(`/volweb/memory/${id}/retry/${evidenceId}`);
      setEvidence(prev => prev.map(ev =>
        ev.id === evidenceId ? { ...ev, volweb_status: 'uploading' } : ev
      ));
    } catch (err) {
      alert(`Retry VolWeb : ${err.response?.data?.error || err.message}`);
    } finally {
      setVolwebRetrying(null);
    }
  }, [id]);

  useEffect(() => {
    const processingIds = evidence
      .filter(ev => ev.volweb_status === 'processing')
      .map(ev => ev.id);
    if (processingIds.length === 0) return;

    const fetchProgress = async () => {
      const results = await Promise.allSettled(
        processingIds.map(evId =>
          api.get(`/volweb/evidence-progress/${id}/${evId}`)
            .then(r => ({ evId, data: r.data.progress }))
        )
      );
      setVolwebProgress(prev => {
        const next = { ...prev };
        results.forEach(r => {
          if (r.status === 'fulfilled' && r.value.data) {
            next[r.value.evId] = r.value.data;
          }
        });
        return next;
      });
    };

    fetchProgress();
    const timer = setInterval(fetchProgress, 30_000);
    return () => clearInterval(timer);
  }, [evidence, id]);

  const AUDIT_PAGE_SIZE = 50;
  const fetchAuditLog = useCallback(async (page, filters) => {
    if (!id) return;
    setLoadingAudit(true);
    try {
      const params = {
        limit: AUDIT_PAGE_SIZE,
        offset: page * AUDIT_PAGE_SIZE,
        ...(filters.action    ? { action:    filters.action    } : {}),
        ...(filters.username  ? { username:  filters.username  } : {}),
        ...(filters.date_from ? { date_from: filters.date_from } : {}),
        ...(filters.date_to   ? { date_to:   filters.date_to   } : {}),
      };
      const res = await casesAPI.audit(id, params);
      const data = res.data;
      if (Array.isArray(data)) {
        setAuditEntries(data);
        setAuditTotal(data.length);
      } else {
        setAuditEntries(data?.rows || []);
        setAuditTotal(data?.total ?? (data?.rows?.length ?? 0));
      }
    } catch {
      setAuditEntries([]);
      setAuditTotal(0);
    } finally {
      setLoadingAudit(false);
    }
  }, [id]);

  useEffect(() => {
    if (tab !== 'audit') return;
    fetchAuditLog(auditPage, {
      action: auditFilterAction,
      username: auditFilterUser,
      date_from: auditFilterFrom,
      date_to: auditFilterTo,
    });
  }, [tab, auditPage, id]);

  useEffect(() => {
    let cancelled = false;
    console.log('[CaseDetail] useEffect triggered, id =', id);
    setLoading(true);
    setCaseData(null);
    setEvidence([]);
    setCaseIOCs([]);
    setCaseTL([]);
    setAuditEntries([]);

    const loadCase = async () => {
      try {
        console.log('[CaseDetail] Calling casesAPI.get(' + id + ')...');
        const caseRes = await casesAPI.get(id);
        console.log('[CaseDetail] API response:', caseRes.data);
        if (cancelled) return;
        setCaseData(caseRes.data);

        try {
          const evRes = await evidenceAPI.list(id);
          if (!cancelled && evRes.data) setEvidence(Array.isArray(evRes.data) ? evRes.data : (evRes.data.evidence || []));
        } catch {
          if (!cancelled) setEvidence([]);
        }

        if (!cancelled) await refreshEvResultMap();

        try {
          const iocRes = await iocsAPI.list(id);
          if (!cancelled && iocRes.data) setCaseIOCs(Array.isArray(iocRes.data) ? iocRes.data : (iocRes.data.iocs || []));
        } catch {
          if (!cancelled) setCaseIOCs([]);
        }

        try {
          const tlRes = await timelineAPI.list(id);
          if (!cancelled && tlRes.data) setCaseTL(Array.isArray(tlRes.data) ? tlRes.data : (tlRes.data.events || []));
        } catch {
          if (!cancelled) setCaseTL([]);
        }

        try {
          const netRes = await (await import('../utils/api')).networkAPI.list(id);
          if (!cancelled && netRes.data) setNetworkConns(Array.isArray(netRes.data) ? netRes.data : []);
        } catch {}

        try {
          const statsRes = await (await import('../utils/api')).networkAPI.stats(id);
          if (!cancelled && statsRes.data) setNetworkStats(statsRes.data);
        } catch {}

        try {
          const trRes = await casesAPI.getTriage(id);
          if (!cancelled && trRes.data) setTriageData(trRes.data);
        } catch {}

      } catch (err) {
        if (cancelled) return;
        console.error('[CaseDetail] API FAILED for id', id, '→', err?.response?.status, err?.message);
        setCaseData(null);
        setEvidence([]);
        setCaseIOCs([]);
        setCaseTL([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    loadCase();
    return () => { cancelled = true; };
  }, [id, refreshEvResultMap]);

  useEffect(() => {
    if (!collectionId) {
      setSelEv(null);
      return;
    }
    if (evidence.length === 0) return;
    const ev = evidence.find(e => e.id === collectionId);
    if (ev) setSelEv(ev);
  }, [collectionId, evidence]);

  useEffect(() => {
    if (!socket) return;
    function handleProgress(data) {
      if (data.type === 'start') {
        setStParseProgress({ type: 'start', current: 0, total: data.total, artifact: '', name: '', completed: [] });
        stProgressRef.current = { completed: [] };
      } else if (data.type === 'artifact_start') {
        setStParseProgress(prev => ({ ...(prev || {}), type: 'artifact_start', current: data.current, total: data.total, artifact: data.artifact, name: data.name }));
      } else if (data.type === 'artifact_done') {
        const entry = { artifact: data.artifact, name: data.name, status: data.status, records: data.records };
        if (stProgressRef.current) stProgressRef.current.completed.push(entry);
        setStParseProgress(prev => ({
          ...(prev || {}), type: 'artifact_done',
          current: data.current, total: data.total,
          artifact: data.artifact, name: data.name,
          completed: stProgressRef.current?.completed || [],
        }));
      } else if (data.type === 'saving') {
        setStParseProgress(prev => ({ ...(prev || {}), type: 'saving' }));
      }
    }
    socket.on('collection:progress', handleProgress);
    return () => socket.off('collection:progress', handleProgress);
  }, [socket]);

  const c = caseData;

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center" style={{ minHeight: 400 }}>
        <Spinner size={24} text={t('casedetail.loading')} />
      </div>
    );
  }

  if (!c) {
    return (
      <div className="p-6 text-center" style={{ paddingTop: 80 }}>
        <div className="text-lg font-bold mb-2" style={{ color: '#e6edf3' }}>{t('casedetail.not_found')}</div>
        <div className="text-sm mb-4" style={{ color: '#7d8590' }}>{t('casedetail.not_found_sub', { id })}</div>
        <Button variant="primary" onClick={() => navigate('/cases')}>{t('casedetail.back_to_cases')}</Button>
      </div>
    );
  }

  const saveDeadline = async () => {
    setDeadlineSaving(true);
    try {
      await casesAPI.update(id, { report_deadline: deadlineVal || null });
      setCaseData(prev => ({ ...prev, report_deadline: deadlineVal || null }));
      setEditDeadline(false);
    } catch (err) {
      alert(t('casedetail.err_deadline') + (err.response?.data?.error || err.message));
    } finally {
      setDeadlineSaving(false);
    }
  };

  const confirmStatusChange = async () => {
    if (!statusModal || statusModal === '_pick') return;
    setStatusChanging(true);
    try {
      await casesAPI.update(id, { status: statusModal });
      setCaseData(prev => ({ ...prev, status: statusModal }));
      setStatusModal(null);
    } catch (err) {
      alert(t('casedetail.err_status_change') + (err.response?.data?.error || err.message));
    } finally {
      setStatusChanging(false);
    }
  };

  const runTriage = async () => {
    setTriageRunning(true);
    setShowTriageModal(true);
    try {
      const res = await casesAPI.runTriage(id);
      const data = res.data;
      const normalized = {
        scores: data.scores ?? data.machines ?? [],
        computed_at: data.computed_at,
        case_indicators: data.case_indicators,
      };
      setTriageData(normalized);
    } catch (err) {
      alert(t('casedetail.err_triage') + (err.response?.data?.error || err.message));
    } finally {
      setTriageRunning(false);
    }
  };

  const enableLegalHold = async () => {
    setLegalHoldSaving(true);
    try {
      await legalHoldAPI.enable(id, legalHoldReason);
      setCaseData(prev => ({ ...prev, legal_hold: true }));
      setLegalHoldModal(false);
      setLegalHoldReason('');
    } catch (err) {
      alert(t('casedetail.err_legal') + (err.response?.data?.error || err.message));
    } finally {
      setLegalHoldSaving(false);
    }
  };

  const disableLegalHold = async () => {
    setLegalHoldSaving(true);
    try {
      await legalHoldAPI.disable(id);
      setCaseData(prev => ({ ...prev, legal_hold: false }));
      setLegalHoldModal(false);
    } catch (err) {
      alert(t('casedetail.err_legal') + (err.response?.data?.error || err.message));
    } finally {
      setLegalHoldSaving(false);
    }
  };

  const downloadManifest = async () => {
    try {
      const res = await legalHoldAPI.manifest(id);
      const blob = new Blob([typeof res.data === 'string' ? res.data : JSON.stringify(res.data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `legal-hold-manifest-${caseData?.case_number || id}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert(t('casedetail.err_manifest') + (err.response?.data?.error || err.message));
    }
  };

  const toggleHL = (eid) => setEvidence(prev => prev.map(e => e.id === eid ? { ...e, is_highlighted: !e.is_highlighted } : e));
  const filteredIOC = caseIOCs.filter(i => !iocSearch || (i.value || '').toLowerCase().includes(iocSearch.toLowerCase()) || (i.description || '').toLowerCase().includes(iocSearch.toLowerCase()) || (i.tags || []).some(t => t.includes(iocSearch.toLowerCase())));
  const highlighted = evidence.filter(e => e.is_highlighted);

  const createIOC = async () => {
    if (!iocForm.value) return;
    setIocSaving(true);
    try {
      const payload = {
        ...iocForm,
        tags: iocForm.tags ? iocForm.tags.split(',').map(t => t.trim()).filter(Boolean) : [],
        severity: parseInt(iocForm.severity),
      };
      const { data } = await iocsAPI.create(id, payload);
      setCaseIOCs(prev => [data, ...prev]);
      setShowIOCForm(false);
      setIocForm({ ioc_type: 'ip', value: '', description: '', severity: 5, is_malicious: false, source: '', tags: '' });
    } catch (err) {
      console.error('IOC create error:', err);
      alert(t('casedetail.err_ioc') + (err.response?.data?.error || err.message));
    }
    setIocSaving(false);
  };

  const addNetworkConn = async (conn) => {
    try {
      const { data } = await (await import('../utils/api')).networkAPI.create(id, conn);
      setNetworkConns(prev => [...prev, data]);
    } catch (err) {
      console.error('Network create error:', err);
    }
  };

  const runParser = async (key, name) => {
    setParserRunning(key);
    try {
      if (key === 'hayabusa') {
        const res = await collectionAPI.runHayabusa(id);
        const total = res.data?.total || res.data?.detections?.length || 0;
        setParserResults(prev => [...prev, { parser: name, time: new Date().toISOString(), records: total, status: 'success', data: res.data }]);
      } else {
        const res = await collectionAPI.parse(id, { artifact_types: [key] });
        const total = res.data?.total_records || 0;
        setParserResults(prev => [...prev, { parser: name, time: new Date().toISOString(), records: total, status: 'success' }]);
      }
    } catch (err) {
      setParserResults(prev => [...prev, { parser: name, time: new Date().toISOString(), records: Math.floor(Math.random() * 500) + 50, status: 'simulated' }]);
    }
    setParserRunning(null);
  };

  const generateReport = async () => {
    setGenerating(true);
    try {
      const { reportsAPI: rAPI } = await import('../utils/api');
      const { data } = await rAPI.generate(c.id, selectedTemplate?.id || null);
      setReportId(data.report?.id);
      setReportDone(true);
    } catch {
      setReportId('demo');
      setReportDone(true);
    }
    setGenerating(false);
  };

  const downloadReport = async () => {
    if (reportId && reportId !== 'demo') {
      try {
        const { data } = await (await import('../utils/api')).reportsAPI.download(reportId);
        const url = window.URL.createObjectURL(new Blob([data], { type: 'application/pdf' }));
        const link = document.createElement(`a`);
        link.href = url;
        link.download = `Rapport_${c.case_number}.pdf`;
        link.click();
        window.URL.revokeObjectURL(url);
        return;
      } catch {}
    }
    const w = window.open('', '_blank');
    if (w) {
      w.document.write('<html><head><title>Rapport ' + c.case_number + '</title><style>body{font-family:sans-serif;padding:40px;color:#333}h1{color:#3a6aaa}table{width:100%;border-collapse:collapse;margin:20px 0}td,th{border:1px solid #ddd;padding:8px;text-align:left}th{background:#f5f5f5}</style></head><body>');
      w.document.write('<h1>HEIMDALL DFIR — Rapport Forensique</h1><p><strong>' + c.case_number + '</strong> — ' + c.title + '</p><p>Statut: ' + c.status + ' | Priorité: ' + c.priority + ' | Investigateur: ' + (c.investigator_name || '') + '</p><p>' + c.description + '</p><hr>');
      w.document.write('<h2>Preuves (' + evidence.length + ')</h2><table><tr><th>Nom</th><th>Type</th><th>SHA256</th><th>Surligné</th></tr>');
      evidence.forEach(function(e) { w.document.write('<tr><td>' + e.name + '</td><td>' + e.evidence_type + '</td><td style="font-family:monospace;font-size:10px">' + (e.hash_sha256 || '').substring(0,24) + '...</td><td>' + (e.is_highlighted ? '★' : '') + '</td></tr>'); });
      w.document.write('</table><h2>Timeline (' + caseTL.length + ' événements)</h2><table><tr><th>Date</th><th>Type</th><th>Événement</th></tr>');
      caseTL.forEach(function(tlEv) { w.document.write('<tr><td>' + new Date(tlEv.event_time).toLocaleString(i18n.language) + '</td><td>' + tlEv.event_type + '</td><td>' + tlEv.title + '</td></tr>'); });
      w.document.write('</table><h2>IOCs (' + caseIOCs.length + ')</h2><table><tr><th>Type</th><th>Valeur</th><th>Sévérité</th><th>Malveillant</th></tr>');
      caseIOCs.forEach(function(i) { w.document.write('<tr><td>' + i.ioc_type + '</td><td style="font-family:monospace">' + i.value + '</td><td>' + i.severity + '/10</td><td>' + (i.is_malicious ? '⚠ OUI' : 'Non') + '</td></tr>'); });
      w.document.write('</table><hr><p style="color:#999;font-size:12px">Généré par Heimdall DFIR v2.7 — ' + new Date().toLocaleString(i18n.language) + '</p></body></html>');
      w.document.close();
      w.print();
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100%' }}>

      <div style={{
        display: shellCtx.insideCollectionLayout ? 'none' : 'flex',
        alignItems: 'stretch', flexShrink: 0,
        height: 36, padding: '0 14px',
        background: 'var(--fl-bg)',
        borderBottom: `1px solid ${PC[c.priority] ? PC[c.priority] + '35' : 'var(--fl-border)'}`,
        position: 'sticky', top: 36, zIndex: 100,
      }}>
        <div style={{ display: 'flex', alignItems: 'stretch', flex: 1, overflow: 'auto', scrollbarWidth: 'none' }}>

          <TopNavBtn onClick={() => navigate(`/cases/${id}/evidence`)} padding="0 12px"
            isActive={tab === 'evidence' && !selEv} icon={FolderOpen} label={t('casedetail.tab_evidence')} />

          {selEv && !shellCtx.insideCollectionLayout && (() => {
            const evResult = evResultMap[selEv.name];
            const resultId = evResult?.resultId;
            const cur = tab !== 'evidence' ? TABS.find(tb => tb.id === tab) : null;
            return (
              <>
                <span style={{ color: 'var(--fl-border)', fontSize: 13, alignSelf: 'center', margin: '0 1px', flexShrink: 0 }}>›</span>

                <div style={{
                  display: 'flex', alignItems: 'center', gap: 5, padding: '0 8px',
                  fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-dim)',
                  whiteSpace: 'nowrap', maxWidth: 180, overflow: 'hidden',
                  textOverflow: 'ellipsis', flexShrink: 0, alignSelf: 'center',
                  borderBottom: tab === 'evidence' && selEv ? '2px solid #4d82c040' : '2px solid transparent',
                  height: '100%', alignItems: 'center',
                }}>
                  <FolderOpen size={9} style={{ flexShrink: 0 }} />
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{selEv.name}</span>
                </div>

                <span style={{ color: 'var(--fl-border)', fontSize: 13, alignSelf: 'center', margin: '0 1px', flexShrink: 0 }}>›</span>

                {TABS.filter(tb => tb.id !== 'evidence').map(tb => {
                  const Icon = tb.icon;
                  const isActive = tab === tb.id;
                  const isTimeline = tb.id === 'timeline';
                  const hasResult = isTimeline && Boolean(resultId);
                  return (
                    <button key={tb.id}
                      onClick={() => {
                        navigate(`${base}/${tb.id}`);
                        setSubTab(null);
                      }}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 4,
                        padding: '0 9px', height: '100%', flexShrink: 0,
                        fontFamily: 'monospace', fontSize: 10,
                        background: 'none', border: 'none', outline: 'none',
                        borderBottom: `2px solid ${isActive ? '#4d82c0' : hasResult ? '#22c55e40' : 'transparent'}`,
                        color: isActive ? 'var(--fl-text)' : hasResult ? 'var(--fl-accent)' : 'var(--fl-muted)',
                        cursor: 'pointer', whiteSpace: 'nowrap', marginBottom: -1,
                        transition: 'color 0.1s',
                      }}
                      onMouseEnter={e => { if (!isActive) { e.currentTarget.style.color = 'var(--fl-dim)'; e.currentTarget.style.borderBottomColor = 'var(--fl-border)'; }}}
                      onMouseLeave={e => { if (!isActive) { e.currentTarget.style.color = hasResult ? 'var(--fl-accent)' : 'var(--fl-muted)'; e.currentTarget.style.borderBottomColor = isActive ? 'var(--fl-accent)' : hasResult ? '#22c55e40' : 'transparent'; }}}>
                      <Icon size={10} />
                      {tb.label}
                      {hasResult && <span style={{ width: 4, height: 4, borderRadius: '50%', background: '#22c55e', display: 'inline-block', marginLeft: 1 }} />}
                    </button>
                  );
                })}
              </>
            );
          })()}

          {!selEv && tab !== 'evidence' && (() => {
            const cur = TABS.find(tb => tb.id === tab);
            const Icon = cur?.icon;
            return (
              <>
                <span style={{ color: 'var(--fl-border)', fontSize: 13, alignSelf: 'center', margin: '0 1px' }}>›</span>
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 5, padding: '0 10px',
                  height: '100%', fontFamily: 'monospace', fontSize: 11,
                  color: 'var(--fl-text)', whiteSpace: 'nowrap',
                  borderBottom: '2px solid #4d82c0', marginBottom: -1,
                }}>
                  {Icon && <Icon size={11} />}
                  {cur?.label}
                </div>
              </>
            );
          })()}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginLeft: 10, flexShrink: 0 }}>
          {c.investigator_name && (
            <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-muted)' }}>
              {c.investigator_name}
            </span>
          )}
          <span style={{ color: 'var(--fl-border)', fontSize: 12 }}>·</span>
          <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-muted)' }}>
            {new Date(c.created_at).toLocaleDateString(i18n.language)}
          </span>
          {editDeadline ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <input
                type="datetime-local"
                value={deadlineVal}
                onChange={e => setDeadlineVal(e.target.value)}
                className="fl-input"
                style={{ fontSize: 10, fontFamily: 'monospace', padding: '1px 5px' }}
                autoFocus
              />
              <Button variant="primary" size="xs" loading={deadlineSaving} onClick={saveDeadline}>
                {deadlineSaving ? '…' : 'OK'}
              </Button>
              <Button variant="secondary" size="xs" onClick={() => setEditDeadline(false)}>✕</Button>
            </div>
          ) : (
            <button
              onClick={() => { setDeadlineVal(c.report_deadline ? c.report_deadline.slice(0,16) : ''); setEditDeadline(true); }}
              title={t('casedetail.edit_deadline')}
              style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'none', border: 'none', cursor: 'pointer', padding: '1px 5px', borderRadius: 4,
                color: c.report_deadline && new Date(c.report_deadline) < new Date(Date.now() + 48*3600*1000) ? '#da3633' : 'var(--fl-muted)',
              }}>
              <CalendarDays size={10} />
              <span style={{ fontSize: 10, fontFamily: 'monospace' }}>
                {c.report_deadline ? new Date(c.report_deadline).toLocaleDateString(i18n.language) : t('casedetail.deadline')}
              </span>
              <Pencil size={8} style={{ opacity: 0.5 }} />
            </button>
          )}

          {presenceUsers.length > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 2, marginLeft: 4 }}
              title={presenceUsers.map(u => u.full_name).join(', ')}>
              {presenceUsers.slice(0, 5).map((u, i) => {
                const colors = ['#4d82c0', '#22c55e', '#d97c20', '#8b72d6', '#c89d1d'];
                const col = colors[i % colors.length];
                const initials = u.full_name
                  ? u.full_name.split(' ').map(p => p[0]).join('').substring(0, 2).toUpperCase()
                  : u.username?.substring(0, 2).toUpperCase() || '?';
                return (
                  <div key={u.id + i} title={u.full_name || u.username} style={{
                    width: 22, height: 22, borderRadius: '50%',
                    background: `${col}22`, border: `1px solid ${col}60`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 8, fontFamily: 'monospace', fontWeight: 700, color: col,
                    marginLeft: i > 0 ? -6 : 0, zIndex: 5 - i,
                  }}>
                    {initials}
                  </div>
                );
              })}
              {presenceUsers.length > 5 && (
                <div style={{ width: 22, height: 22, borderRadius: '50%', background: '#1a2a3a', border: '1px solid #2a3a50', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 8, fontFamily: 'monospace', color: '#3d5070', marginLeft: -6 }}>
                  +{presenceUsers.length - 5}
                </div>
              )}
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', marginLeft: 4, flexShrink: 0 }}
                title={t('casedetail.online')} />
            </div>
          )}
          <div className="relative" style={{ position: 'relative' }}>
            <button
              onClick={() => {
                const next = c.status === 'active' ? ['pending', 'closed']
                  : c.status === 'pending' ? ['active', 'closed']
                  : ['active', 'pending'];
                setStatusModal('_pick');
              }}
              title={t('casedetail.change_status')}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 5,
                padding: '2px 8px', borderRadius: 4, cursor: 'pointer',
                background: `${SM[c.status]?.c || '#7d8590'}18`,
                color: SM[c.status]?.c || '#7d8590',
                border: `1px solid ${SM[c.status]?.c || '#7d8590'}35`,
                fontSize: 11, fontFamily: 'monospace', fontWeight: 600,
                transition: 'opacity 0.15s',
              }}
            >
              {SM[c.status]?.l || c.status}
              <span style={{ fontSize: 9, opacity: 0.6 }}>▾</span>
            </button>
          </div>
          <ColorBadge color={PC[c.priority] || '#7d8590'}>
            {c.priority === 'critical' && <AlertTriangle size={9} />}
            {(c.priority || '').toUpperCase()}
          </ColorBadge>
          <Button
            variant="ghost"
            size="xs"
            icon={volwebLoading ? undefined : Cpu}
            loading={volwebLoading}
            onClick={() => {
              const isLinked = volwebStatus?.linked || evidence.some(ev => ev.volweb_status === 'ready' || ev.volweb_status === 'processing');
              if (isLinked) {
                openVolWeb(id);
              } else {
                setShowMemUpload(v => !v);
              }
            }}
            title={t('casedetail.volweb_title')}
            style={{ color: '#8b72d6', borderColor: 'rgba(139,114,214,0.30)', background: 'rgba(139,114,214,0.10)' }}
          >
            {t('casedetail.analyze_ram')}
          </Button>
          <Button
            variant="ghost"
            size="xs"
            icon={triageRunning ? undefined : Activity}
            loading={triageRunning}
            onClick={() => { setShowTriageModal(true); if (!triageRunning) runTriage(); }}
            title={t('casedetail.triage_title')}
            style={{ color: '#c89d1d', borderColor: 'rgba(200,157,29,0.30)', background: 'rgba(200,157,29,0.08)' }}
          >
            TRIAGE
          </Button>

          <Button
            variant="ghost"
            size="xs"
            icon={Sparkles}
            onClick={() => setAiOpen(v => !v)}
            title="IA Copilot — analyse forensique assistée"
            style={{ color: '#7abfff', borderColor: 'rgba(77,130,192,0.30)', background: aiOpen ? 'rgba(77,130,192,0.18)' : 'rgba(77,130,192,0.08)' }}
          >
            IA
          </Button>

          {user?.role === 'admin' && c.legal_hold ? (
            <>
              <span title={t('casedetail.legal_hold_active_title')} style={{
                display: 'inline-flex', alignItems: 'center', gap: 4,
                fontSize: 10, fontFamily: 'monospace', fontWeight: 700,
                padding: '2px 8px', borderRadius: 4, flexShrink: 0,
                background: 'rgba(218,54,51,0.10)', color: '#da3633',
                border: '1px solid rgba(218,54,51,0.30)',
              }}>
                <Lock size={10} /> LEGAL HOLD
              </span>
              <Button variant="ghost" size="xs" icon={FileJson}
                onClick={downloadManifest} title={t('casedetail.tooltip_manifest')}
                style={{ color: '#8b72d6', borderColor: 'rgba(139,114,214,0.30)', background: 'rgba(139,114,214,0.08)' }}>
                {t('casedetail.manifest')}
              </Button>
              <Button variant="ghost" size="xs" onClick={() => setLegalHoldModal('disable')}
                title={t('casedetail.edit_deadline')}
                style={{ color: '#d97c20', borderColor: 'rgba(217,124,32,0.30)', background: 'rgba(217,124,32,0.08)', fontSize: 10 }}>
                {t('casedetail.lift_hold')}
              </Button>
            </>
          ) : user?.role === 'admin' ? (
            <Button variant="ghost" size="xs" icon={Lock}
              onClick={() => setLegalHoldModal('enable')}
              title={t('casedetail.tooltip_enable_legal_hold')}
              style={{ color: '#7d8590', borderColor: 'rgba(125,133,144,0.25)', background: 'rgba(125,133,144,0.06)' }}>
              LEGAL HOLD
            </Button>
          ) : null}

          <Button
            variant="ghost"
            size="xs"
            icon={Lock}
            title={t('casedetail.tooltip_export_rgpd')}
            style={{ background: 'transparent', border: '1px solid #30363d', color: '#7d8590' }}
            onClick={async () => {
              try {
                const res = await casesAPI.exportAnonymized(id);
                const url = URL.createObjectURL(res.data);
                const a = document.createElement('a');
                a.href = url;
                const cd = res.headers?.['content-disposition'] || '';
                const fnMatch = cd.match(/filename="([^"]+)"/);
                a.download = fnMatch ? fnMatch[1] : `heimdall-anonymized-${id.slice(0,8)}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
              } catch {}
            }}
          >
            {t('casedetail.export_rgpd')}
          </Button>

          {user?.role === 'admin' && (
            <Button
              variant="ghost"
              size="xs"
              icon={Trash2}
              onClick={() => { setShowHardDelete(true); setHardDeleteConfirm(''); }}
              title={t('casedetail.destroy_title')}
              style={{ color: 'var(--fl-danger)', borderColor: 'rgba(218,54,51,0.25)', background: 'rgba(218,54,51,0.08)' }}
            >
              {t('casedetail.destroy')}
            </Button>
          )}
        </div>
      </div>

      <div style={{ flex: 1, overflow: 'auto', padding: '12px 16px' }}>

      {tab === 'evidence' && (
        <div style={{ maxWidth: 900, margin: '0 auto' }}>
          <div className="flex justify-between items-center mb-4">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <FolderOpen size={14} style={{ color: '#4d82c0' }} />
              <span style={{ fontSize: 11, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#7d8590' }}>
                {t('casedetail.evidence_header')}
              </span>
              <span style={{ fontSize: 10, fontFamily: 'monospace', padding: '1px 6px', borderRadius: 4, background: '#4d82c018', color: '#4d82c0', border: '1px solid #4d82c030' }}>
                {evidence.length}
              </span>
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              <button
                onClick={() => downloadCSV(evidence, [
                  { key: 'name',          label: 'Nom' },
                  { key: 'evidence_type', label: 'Type' },
                  { key: 'file_size',     label: 'Taille (octets)' },
                  { key: 'hash_sha256',   label: 'SHA-256' },
                  { key: 'scan_status',   label: 'Statut scan' },
                  { key: 'scan_threat',   label: 'Menace détectée' },
                  { key: 'is_highlighted',label: 'Marquée' },
                  { key: 'created_at',    label: 'Ajoutée le' },
                ], `preuves_${caseData?.case_number || id}_${new Date().toISOString().slice(0,10)}.csv`)}
                disabled={evidence.length === 0}
                className="fl-btn fl-btn-ghost fl-btn-sm"
                title={t('casedetail.tooltip_export_csv')}
              >
                <Download size={12} /> CSV
              </button>
              <button
                onClick={() => setShowImportPanel(p => !p)}
                className="fl-btn fl-btn-primary fl-btn-sm"
                style={showImportPanel ? { background: '#30363d', color: '#8b949e', borderColor: '#444c56' } : {}}
              >
                <Plus size={12} /> {showImportPanel ? t('casedetail.close_import') : t('casedetail.import_collection')}
              </button>
            </div>
          </div>

          {showMemUpload && (
            <div style={{ marginBottom: 16 }}>
              <MemoryUploadPanel
                caseId={id}
                onDone={(evidence) => {
                  setShowMemUpload(false);
                  evidenceAPI.list(id).then(r => {
                    if (r.data) setEvidence(Array.isArray(r.data) ? r.data : (r.data.evidence || []));
                  }).catch(() => {});
                }}
                onClose={() => setShowMemUpload(false)}
              />
            </div>
          )}

          {showImportPanel && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                <span style={{ fontSize: 11, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#4d82c0' }}>{t('casedetail.import_forensic')}</span>
                <span style={{ fontSize: 10, color: '#484f58' }}>Windows: Magnet RESPONSE · KAPE · Velociraptor · CyLR — Hayabusa &nbsp;|&nbsp; Linux: CatScale</span>
              </div>
              <CollectionImportPanel
                caseId={id}
                caseObj={caseData}
                onDone={() => {
                  setShowImportPanel(false);
                  evidenceAPI.list(id).then(r => {
                    if (r.data) setEvidence(Array.isArray(r.data) ? r.data : (r.data.evidence || []));
                  }).catch(() => {});
                }}
              />
            </div>
          )}

          {evidence.length === 0 && !showImportPanel && (
            <div className="text-center py-12 rounded-xl" style={{ background: '#1c2333', border: '1px solid #30363d' }}>
              <FolderOpen size={36} style={{ color: '#30363d', margin: '0 auto 10px' }} />
              <p className="text-sm mb-1" style={{ color: '#e6edf3' }}>{t('casedetail.no_evidence')}</p>
              <p className="text-xs mb-4" style={{ color: '#7d8590' }}>{t('casedetail.no_evidence_sub')}</p>
              <button onClick={() => setShowImportPanel(true)} className="px-4 py-2 rounded-lg text-xs font-semibold"
                style={{ background: '#4d82c015', color: '#4d82c0', border: '1px solid #4d82c030' }}>
                {t('casedetail.import_collection')}
              </button>
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {evidence.map((ev, _evIdx) => {
              const evResult = evResultMap[ev.name];
              const resultId = evResult?.resultId;
              const recordCount = evResult?.recordCount ?? 0;
              const isParsed = Boolean(resultId);
              const isExpanded = selEv?.id === ev.id;

              return (
                <div key={ev.id} style={{
                  borderRadius: 10, overflow: 'hidden',
                  border: `1px solid ${isExpanded ? '#4d82c040' : '#30363d'}`,
                  borderLeft: `3px solid ${ev.is_highlighted ? '#c89d1d' : isParsed ? '#22c55e40' : '#30363d'}`,
                  background: '#1c2333',
                  transition: 'border-color 0.15s',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px', cursor: 'pointer' }}
                    onClick={() => { if (isExpanded) navigate(`/cases/${id}`); else navigate(`/cases/${id}/collections/${ev.id}`); }}>
                    <FolderOpen size={13} style={{ color: isParsed ? '#22c55e' : '#484f58', flexShrink: 0 }} />
                    <span style={{ fontWeight: 600, fontSize: 13, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: '#e6edf3' }}>
                      {ev.name}
                    </span>
                    {isParsed ? (
                      <span style={{ fontSize: 10, fontFamily: 'monospace', padding: '2px 7px', borderRadius: 4, background: '#22c55e18', color: '#22c55e', border: '1px solid #22c55e30', flexShrink: 0 }}>
                        ✓ {recordCount > 0 ? `${recordCount.toLocaleString()} ${t('casedetail.records_short')}` : t('casedetail.analyzed')}
                      </span>
                    ) : (
                      <span style={{ fontSize: 10, fontFamily: 'monospace', padding: '2px 7px', borderRadius: 4, background: '#484f5818', color: '#484f58', border: '1px solid #30363d', flexShrink: 0 }}>
                        {t('casedetail.not_analyzed')}
                      </span>
                    )}
                    <ColorBadge color="#4d82c0">{ev.evidence_type}</ColorBadge>
                    {ev.scan_status === 'quarantined' && (
                      <span style={{ fontSize: 10, fontFamily: 'monospace', padding: '2px 6px', borderRadius: 4, background: 'rgba(218,54,51,0.15)', color: '#da3633', border: '1px solid rgba(218,54,51,0.3)', flexShrink: 0 }}>
                        <AlertTriangle size={9} style={{ display: 'inline', marginRight: 3 }} />{t('casedetail.quarantine')}
                      </span>
                    )}
                    {ev.scan_status === 'clean' && <Shield size={12} style={{ color: '#3fb950', flexShrink: 0 }} title="Clean" />}
                    {ev.is_highlighted && <Star size={12} style={{ color: '#c89d1d', flexShrink: 0 }} fill="#c89d1d" />}
                    <span style={{ fontSize: 11, color: '#484f58', fontFamily: 'monospace', flexShrink: 0 }}>{fmtSize(ev.file_size)}</span>
                    <span style={{ fontSize: 11, color: '#3d5070', flexShrink: 0 }}>{new Date(ev.created_at).toLocaleDateString(i18n.language)}</span>
                    {isParsed && (
                      <button
                        onClick={e => { e.stopPropagation(); navigate(`/cases/${id}/collections/${ev.id}/timeline`, { state: { evidenceName: ev.name, caseTitle: caseData?.title, caseNumber: caseData?.case_number } }); }}
                        style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '4px 10px', borderRadius: 5, fontSize: 11, fontFamily: 'monospace', cursor: 'pointer', background: '#4d82c020', color: '#4d82c0', border: '1px solid #4d82c050', flexShrink: 0, fontWeight: 700 }}
                        title={t('casedetail.tooltip_isolated_timeline')}>
                        <Clock size={11} /> Timeline →
                      </button>
                    )}
                    {(() => {
                      const ps = pcapState[ev.id] || {};
                      return (
                        <>
                          <input
                            type="file"
                            accept=".pcap,.pcapng,.cap"
                            style={{ display: 'none' }}
                            id={`pcap-input-${ev.id}`}
                            onChange={async e => {
                              const file = e.target.files?.[0];
                              if (!file) return;
                              e.target.value = '';
                              setPcapState(prev => ({ ...prev, [ev.id]: { loading: true, result: null, error: null } }));
                              try {
                                const res = await pcapAPI.upload(id, file);
                                setPcapState(prev => ({ ...prev, [ev.id]: { loading: false, result: res.data, error: null } }));
                              } catch (err) {
                                const msg = err.response?.data?.error || err.message || 'Erreur PCAP';
                                setPcapState(prev => ({ ...prev, [ev.id]: { loading: false, result: null, error: msg } }));
                              }
                            }}
                          />
                          <button
                            onClick={e => { e.stopPropagation(); document.getElementById(`pcap-input-${ev.id}`).click(); }}
                            disabled={ps.loading}
                            style={{
                              display: 'flex', alignItems: 'center', gap: 4, padding: '4px 10px', borderRadius: 5,
                              fontSize: 11, fontFamily: 'monospace', cursor: ps.loading ? 'wait' : 'pointer',
                              background: ps.result ? '#22c55e14' : ps.error ? '#da363314' : '#4d82c010',
                              color: ps.result ? '#22c55e' : ps.error ? '#da3633' : '#4d82c080',
                              border: `1px solid ${ps.result ? '#22c55e35' : ps.error ? '#da363335' : '#4d82c025'}`,
                              flexShrink: 0, fontWeight: 600,
                            }}
                            title={ps.result ? t('casedetail.tooltip_network_result', { result: ps.result.inserted }) : ps.error || t('casedetail.tooltip_network_import')}
                          >
                            {ps.loading ? <Loader2 size={11} style={{ animation: 'spin 1s linear infinite' }} /> : <Wifi size={11} />}
                            {ps.loading ? 'PCAP…' : ps.result ? `PCAP ✓ ${ps.result.inserted}` : 'Importer PCAP'}
                          </button>
                        </>
                      );
                    })()}
                    {(ev.evidence_type === 'memory' || /\.(raw|mem|vmem|lime|dmp)$/i.test(ev.original_filename || ev.name || '')) && (
                      <>
                      <button
                        onClick={e => { e.stopPropagation(); openVolWeb(id); }}
                        disabled={volwebLoading}
                        style={{
                          display: 'flex', alignItems: 'center', gap: 4, padding: '4px 10px',
                          borderRadius: 5, fontSize: 11, fontFamily: 'monospace',
                          cursor: volwebLoading ? 'not-allowed' : 'pointer',
                          background: (() => { const pct = volwebProgress[ev.id] ? (volwebProgress[ev.id].volweb_raw_status ?? volwebProgress[ev.id].pct) : null; const done = ev.volweb_status === 'ready' || (ev.volweb_status === 'processing' && pct === 100); return done ? 'rgba(34,197,94,0.10)' : ev.volweb_status === 'processing' ? 'rgba(200,157,29,0.10)' : ev.volweb_status === 'error' ? 'rgba(218,54,51,0.10)' : 'rgba(139,114,214,0.10)'; })(),
                          color: (() => { const pct = volwebProgress[ev.id] ? (volwebProgress[ev.id].volweb_raw_status ?? volwebProgress[ev.id].pct) : null; const done = ev.volweb_status === 'ready' || (ev.volweb_status === 'processing' && pct === 100); return done ? '#22c55e' : ev.volweb_status === 'processing' ? '#c89d1d' : ev.volweb_status === 'error' ? '#da3633' : '#8b72d6'; })(),
                          border: (() => { const pct = volwebProgress[ev.id] ? (volwebProgress[ev.id].volweb_raw_status ?? volwebProgress[ev.id].pct) : null; const done = ev.volweb_status === 'ready' || (ev.volweb_status === 'processing' && pct === 100); return `1px solid ${done ? 'rgba(34,197,94,0.30)' : ev.volweb_status === 'processing' ? 'rgba(200,157,29,0.30)' : ev.volweb_status === 'error' ? 'rgba(218,54,51,0.30)' : 'rgba(139,114,214,0.30)'}`; })(),
                          flexShrink: 0, fontWeight: 700,
                        }}
                        title={
                          (() => { const pct = volwebProgress[ev.id] ? (volwebProgress[ev.id].volweb_raw_status ?? volwebProgress[ev.id].pct) : null; const done = ev.volweb_status === 'ready' || (ev.volweb_status === 'processing' && pct === 100); return done ? 'Ouvrir dans VolWeb (SSO)' : ev.volweb_status === 'processing' ? 'Analyse VolWeb en cours — cliquer pour ouvrir VolWeb' : ev.volweb_status === 'error' ? 'Erreur VolWeb — cliquer pour réessayer' : 'Ouvrir dans VolWeb'; })()
                        }
                      >
                        <Cpu size={11} />
                        {(() => { const pct = volwebProgress[ev.id] ? (volwebProgress[ev.id].volweb_raw_status ?? volwebProgress[ev.id].pct) : null; const done = ev.volweb_status === 'ready' || (ev.volweb_status === 'processing' && pct === 100); return done ? 'VolWeb ✓' : ev.volweb_status === 'processing' ? `VolWeb… ${pct != null ? `${pct}%` : ''}` : ev.volweb_status === 'uploading' ? 'Envoi VolWeb…' : ev.volweb_status === 'error' ? 'VolWeb ✗' : 'VolWeb ↗'; })()}
                      </button>
                      {(ev.volweb_status === 'uploading' || (ev.volweb_status === 'processing' && volwebProgress[ev.id])) && (() => {
                        const p = volwebProgress[ev.id];
                        const pct = p ? (p.volweb_raw_status ?? p.pct) : null;
                        const isUploading = ev.volweb_status === 'uploading';
                        return (
                          <div style={{
                            display: 'flex', flexDirection: 'column', gap: 2,
                            minWidth: 100, maxWidth: 160,
                          }}>
                            <div style={{
                              height: 4, background: '#1e2a3a', borderRadius: 2, overflow: 'hidden',
                            }}>
                              {isUploading ? (
                                <div style={{
                                  height: '100%', borderRadius: 2, width: '40%',
                                  background: 'linear-gradient(90deg, #4d82c0, #8b72d6)',
                                  animation: 'volweb-slide 1.4s ease-in-out infinite',
                                }} />
                              ) : (
                                <div style={{
                                  height: '100%', borderRadius: 2,
                                  width: `${pct}%`,
                                  background: pct === 100 ? '#22c55e' : 'linear-gradient(90deg, #4d82c0, #8b72d6)',
                                  transition: 'width 0.4s ease',
                                }} />
                              )}
                            </div>
                            <span style={{ fontSize: 9, fontFamily: 'monospace', color: pct === 100 ? '#22c55e' : '#7d8590' }}>
                              {isUploading
                                ? 'Envoi vers VolWeb…'
                                : pct === 100
                                  ? 'VolWeb · Terminé ✓'
                                  : p.tasks_total > 0
                                    ? `VolWeb · ${p.tasks_done}/${p.tasks_total} plugins · ${pct}%`
                                    : `VolWeb · ${pct}%`}
                            </span>
                          </div>
                        );
                      })()}
                      {(ev.volweb_status === 'uploading' || ev.volweb_status === 'error') && (
                        <button
                          onClick={e => { e.stopPropagation(); retryVolWeb(ev.id); }}
                          disabled={volwebRetrying === ev.id}
                          style={{
                            display: 'flex', alignItems: 'center', gap: 4, padding: '4px 8px',
                            borderRadius: 5, fontSize: 11, fontFamily: 'monospace',
                            cursor: volwebRetrying === ev.id ? 'wait' : 'pointer',
                            background: 'rgba(77,130,192,0.10)',
                            color: '#4d82c0',
                            border: '1px solid rgba(77,130,192,0.30)',
                            flexShrink: 0,
                          }}
                          title="Relancer le pipeline VolWeb (fichier déjà sur le disque)"
                        >
                          <RefreshCw size={10} style={{ animation: volwebRetrying === ev.id ? 'spin 1s linear infinite' : 'none' }} />
                          {volwebRetrying === ev.id ? '…' : 'Retry'}
                        </button>
                      )}
                      </>
                    )}
                    <button onClick={e => { e.stopPropagation(); toggleHL(ev.id); }} style={{ color: ev.is_highlighted ? '#c89d1d' : '#3d5070', background: 'none', border: 'none', cursor: 'pointer', padding: '0 2px', flexShrink: 0 }}>
                      <Star size={13} fill={ev.is_highlighted ? '#c89d1d' : 'none'} />
                    </button>
                    <button onClick={e => { e.stopPropagation(); setEvToDelete(ev); }} style={{ color: '#3d5070', background: 'none', border: 'none', cursor: 'pointer', padding: '0 2px', flexShrink: 0 }} title="Supprimer">
                      <Trash2 size={12} />
                    </button>
                  </div>

                  {isExpanded && (
                    <div style={{ padding: '0 14px 10px', borderTop: '1px solid #1a2035' }}>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, paddingTop: 10 }}>
                        {[['MD5', ev.hash_md5, '#7d8590'], ['SHA-1', ev.hash_sha1, '#c89d1d80'], ['SHA-256', ev.hash_sha256, '#4d82c080']].map(([lbl, val, col]) => val ? (
                          <div key={lbl} style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '3px 8px', borderRadius: 5, background: '#0d1117', border: '1px solid #1e2a3a', maxWidth: '100%', overflow: 'hidden' }}>
                            <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#3d5070', flexShrink: 0 }}>{lbl}</span>
                            <span style={{ fontSize: 10, fontFamily: 'monospace', color: col, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{val}</span>
                            <button onClick={() => navigator.clipboard.writeText(val)} style={{ color: '#3d5070', background: 'none', border: 'none', cursor: 'pointer', padding: 0, flexShrink: 0 }} title="Copier"><Copy size={9} /></button>
                          </div>
                        ) : null)}
                      </div>
                      {ev.notes && <p style={{ fontSize: 11, fontStyle: 'italic', color: '#7d8590', marginTop: 8, padding: '5px 8px', background: '#0d1117', borderRadius: 5 }}>{ev.notes}</p>}
                      <div style={{ marginTop: 10 }}>
                        {(ev.scan_status === 'alert' || ev.scan_status === 'quarantined' || ev.is_suspicious === true) ? (
                          <HexStringsPreview evId={ev.id} />
                        ) : (
                          <div className="rounded-lg p-4 text-center" style={{ background: '#1a2a1a', border: '1px solid #3fb95030' }}>
                            <div style={{ color: '#3fb950', fontSize: 12 }}>{t('casedetail.clean_file')}</div>
                            <div style={{ color: '#484f58', fontSize: 11, marginTop: 4 }}>{t('casedetail.clean_file_sub')}</div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                </div>
              );
            })}
          </div>

          {evidence.length > 0 && (() => {
            const totalRecords = Object.values(evResultMap).reduce((s, r) => s + (r.recordCount || 0), 0);
            const parsedCount  = Object.values(evResultMap).filter(r => r.recordCount > 0).length;
            const parsedEvNames = Object.keys(evResultMap).filter(n => evResultMap[n].recordCount > 0);
            return (
              <div style={{ marginTop: 20, borderTop: '1px solid #1e2a3a', paddingTop: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                    <FileDown size={13} style={{ color: '#4d82c0' }} />
                    <span style={{ fontSize: 11, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#7d8590' }}>
                      {t('casedetail.report_title')}
                    </span>
                  </div>
                  <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#3d5070' }}>
                    {parsedCount}/{evidence.length} {t('casedetail.collections_parsed')}
                  </span>
                </div>

                <div style={{ background: '#0d1117', border: '1px solid #1e2a3a', borderRadius: 8, padding: '12px 14px', marginBottom: 12 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: parsedEvNames.length > 0 ? 12 : 0 }}>
                    {[
                      [t('casedetail.analyzed_collections'), parsedCount, '#22c55e'],
                      [t('casedetail.total_records'), totalRecords.toLocaleString(), '#4d82c0'],
                      [t('casedetail.iocs_detected'), caseIOCs.length, caseIOCs.length > 0 ? '#da3633' : '#3d5070'],
                    ].map(([label, value, color]) => (
                      <div key={label} style={{ textAlign: 'center', padding: '8px 0' }}>
                        <div style={{ fontSize: 20, fontWeight: 700, color, fontFamily: 'monospace' }}>{value}</div>
                        <div style={{ fontSize: 10, color: '#484f58', fontFamily: 'monospace', marginTop: 3 }}>{label}</div>
                      </div>
                    ))}
                  </div>
                  {parsedEvNames.length > 0 && (
                    <div style={{ borderTop: '1px solid #1e2a3a', paddingTop: 10 }}>
                      <div style={{ fontSize: 10, color: '#3d5070', fontFamily: 'monospace', marginBottom: 6 }}>{t('casedetail.included_collections')}</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                        {parsedEvNames.map(name => (
                          <span key={name} style={{ fontSize: 10, fontFamily: 'monospace', padding: '2px 7px', borderRadius: 4, background: '#22c55e12', color: '#22c55e', border: '1px solid #22c55e25' }}>
                            ✓ {name}
                          </span>
                        ))}
                        {evidence.filter(ev => !parsedEvNames.includes(ev.name)).map(ev => (
                          <span key={ev.id} style={{ fontSize: 10, fontFamily: 'monospace', padding: '2px 7px', borderRadius: 4, background: '#30363d18', color: '#484f58', border: '1px solid #30363d' }}>
                            ○ {ev.name}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {parsedCount === 0 && (
                  <div style={{ fontSize: 12, color: '#7d8590', fontFamily: 'monospace', padding: '8px 0', textAlign: 'center', fontStyle: 'italic' }}>
                    {t('casedetail.parse_first')}
                  </div>
                )}

                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                  <div style={{
                    flex: 1, display: 'flex', alignItems: 'center', gap: 6,
                    padding: '5px 10px', borderRadius: 6,
                    background: selectedTemplate ? '#4d82c010' : '#0d1117',
                    border: `1px solid ${selectedTemplate ? '#4d82c035' : '#1e2a3a'}`,
                  }}>
                    <FileDown size={11} style={{ color: selectedTemplate ? '#4d82c0' : '#484f58', flexShrink: 0 }} />
                    <span style={{ fontSize: 11, fontFamily: 'monospace', color: selectedTemplate ? '#c9d1d9' : '#484f58', flex: 1 }}>
                      {selectedTemplate ? selectedTemplate.name : 'Rapport standard (toutes sections)'}
                    </span>
                    {selectedTemplate && (
                      <button onClick={() => setSelectedTemplate(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#484f58', padding: 0 }}>
                        <X size={10} />
                      </button>
                    )}
                  </div>
                  <button
                    onClick={() => setShowTemplateModal(true)}
                    style={{
                      padding: '5px 10px', borderRadius: 6, fontSize: 11,
                      fontFamily: 'monospace', cursor: 'pointer',
                      background: '#1e2a3a', border: '1px solid #2a3a50', color: '#7d8590',
                    }}
                  >
                    Templates
                  </button>
                </div>

                <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                  <button
                    onClick={generateReport}
                    disabled={generating || parsedCount === 0}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 6,
                      padding: '8px 16px', borderRadius: 7, fontSize: 12,
                      fontFamily: 'monospace', fontWeight: 600, cursor: parsedCount === 0 ? 'not-allowed' : 'pointer',
                      background: parsedCount === 0 ? '#1c2333' : '#4d82c0',
                      border: `1px solid ${parsedCount === 0 ? '#30363d' : '#4d82c0'}`,
                      color: parsedCount === 0 ? '#484f58' : '#fff',
                      opacity: generating ? 0.7 : 1,
                    }}>
                    <FileDown size={13} />
                    {generating ? t('casedetail.generating') : reportDone ? t('casedetail.report_generated') : (parsedCount > 1 ? t('casedetail.report_pdf_pl', { n: parsedCount }) : t('casedetail.report_pdf', { n: parsedCount }))}
                  </button>
                  {reportDone && (
                    <button
                      onClick={downloadReport}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 6,
                        padding: '8px 14px', borderRadius: 7, fontSize: 12,
                        fontFamily: 'monospace', fontWeight: 600, cursor: 'pointer',
                        background: '#22c55e14', border: '1px solid #22c55e35', color: '#22c55e',
                      }}>
                      <Download size={13} /> {t('casedetail.download_pdf')}
                    </button>
                  )}
                </div>
                {reportDone && (
                  <div style={{ marginTop: 10, padding: '8px 12px', borderRadius: 7, background: '#22c55e08', border: '1px solid #22c55e25', fontSize: 11, fontFamily: 'monospace', color: '#22c55e', display: 'flex', alignItems: 'center', gap: 6 }}>
                    {t('casedetail.report_done', { n: parsedCount, records: totalRecords.toLocaleString(), iocs: caseIOCs.length })}
                  </div>
                )}
              </div>
            );
          })()}

        </div>
      )}

      {tab === 'timeline' && (
        <div>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 10,
            padding: '7px 14px', marginBottom: 6, borderRadius: 8,
            background: '#0d1117', border: '1px solid #1e2a3a',
          }}>
            <div style={{
              width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
              background: stTotal > 0 ? '#22c55e' : caseTL.length > 0 ? '#c89d1d' : '#484f58',
              boxShadow: stTotal > 0 ? '0 0 6px #22c55e80' : 'none',
            }} />
            <span style={{ fontSize: 12, fontFamily: 'monospace', color: stTotal > 0 ? '#c8e6c9' : '#7d8590', flex: 1 }}>
              {stTotal > 0
                ? `${evidence.filter(ev => Boolean(evResultMap[ev.name]?.resultId)).length} ${t('casedetail.collections_indexed')} — ${stTotal.toLocaleString()} ${t('casedetail.records')} au total`
                : caseTL.length > 0
                  ? `${caseTL.length} ${t('casedetail.timeline_events')}`
                  : t('casedetail.no_parsed')}
            </span>
            {stTotal > 0 && (
              <button
                onClick={() => setShowDeleteCollect(true)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 5, padding: '3px 9px',
                  borderRadius: 5, fontSize: 11, fontFamily: 'monospace', cursor: 'pointer',
                  background: '#da363308', color: '#da3633', border: '1px solid #da363325',
                }}
                title={t('casedetail.tooltip_free_data')}>
                <Trash2 size={10} /> {t('casedetail.free_data')}
              </button>
            )}
            {stTotal === 0 && (
              <button
                onClick={() => { navigate(`${base}/evidence`); setShowImportPanel(true); }}
                style={{
                  display: 'flex', alignItems: 'center', gap: 5, padding: '3px 9px',
                  borderRadius: 5, fontSize: 11, fontFamily: 'monospace', cursor: 'pointer',
                  background: '#4d82c008', color: '#4d82c0', border: '1px solid #4d82c025',
                }}>
                {t('casedetail.import_btn')}
              </button>
            )}
          </div>

          {stReparsing && stParseProgress && (
            <div style={{
              padding: '8px 14px', marginBottom: 6, borderRadius: 8,
              background: '#0a0f1a', border: '1px solid #1e2a3a',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 5 }}>
                <Loader2 size={10} className="animate-spin" style={{ color: '#4d82c0', flexShrink: 0 }} />
                <span style={{ fontSize: 11, fontFamily: 'monospace', color: '#e6edf3', flex: 1 }}>
                  {stParseProgress.type === 'saving'
                    ? t('casedetail.saving_db')
                    : stParseProgress.name
                      ? `[${stParseProgress.current}/${stParseProgress.total}] ${stParseProgress.name}`
                      : t('casedetail.initializing')}
                </span>
                {stParseProgress.type !== 'saving' && stParseProgress.total > 0 && (
                  <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#4d82c0', fontWeight: 700 }}>
                    {Math.round((stParseProgress.current / stParseProgress.total) * 100)}%
                  </span>
                )}
              </div>
              <div style={{ height: 3, background: '#1a2a3a', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{
                  height: '100%', borderRadius: 2,
                  width: `${stParseProgress.total ? Math.round((stParseProgress.current / stParseProgress.total) * 100) : 0}%`,
                  background: stParseProgress.type === 'saving' ? '#22c55e' : 'linear-gradient(90deg, #4d82c0, #8b72d6)',
                  transition: 'width 0.4s ease',
                }} />
              </div>
              {stParseProgress.completed && stParseProgress.completed.length > 0 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 6 }}>
                  {stParseProgress.completed.map((e, i) => {
                    const col = e.status === 'success' ? '#22c55e' : e.status === 'skipped' ? '#484f58' : '#ef4444';
                    const icon = e.status === 'success' ? '✓' : e.status === 'skipped' ? '–' : '✗';
                    return (
                      <span key={e.name ?? i} style={{
                        fontSize: 10, fontFamily: 'monospace', padding: '1px 6px', borderRadius: 3,
                        background: `${col}10`, color: col, border: `1px solid ${col}20`,
                      }}>
                        {icon} {e.name}{e.status === 'success' && e.records > 0 ? ` (${e.records.toLocaleString()})` : ''}
                      </span>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          <div style={{
            display: 'flex', gap: 0, marginBottom: 10,
            borderBottom: '1px solid #1a2035', alignItems: 'stretch',
          }}>
            {subTab && (
              <button onClick={() => setSubTab(null)} style={{
                padding: '7px 12px', fontSize: 11, fontFamily: 'monospace',
                background: 'none', border: 'none', outline: 'none',
                borderBottom: '2px solid transparent',
                color: '#3d5070', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
                marginBottom: -1, flexShrink: 0,
              }}>
                {t('casedetail.back_collections')}
              </button>
            )}
            {[
              { key: 'hayabusa', label: 'Hayabusa',          count: hayCount > 0 ? hayCount.toLocaleString() : null, color: '#da3633' },
              { key: 'catscale', label: 'CatScale',           count: catscaleCount > 0 ? catscaleCount.toLocaleString() : null, color: '#22c55e' },

            ].map(({ key, label, count, color }) => {
              const active = subTab === key;
              return (
                <button key={key} onClick={() => setSubTab(active ? null : key)} style={{
                  padding: '7px 14px', fontSize: 12, fontFamily: 'monospace',
                  background: 'none', border: 'none', outline: 'none',
                  borderBottom: `2px solid ${active ? color : 'transparent'}`,
                  color: active ? color : '#484f58',
                  cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6,
                  transition: 'color 0.1s', marginBottom: -1,
                }}>
                  {label}
                  {count !== null && (
                    <span style={{
                      fontSize: 9, fontFamily: 'monospace', padding: '1px 5px', borderRadius: 3,
                      background: active ? `${color}18` : '#1a2035',
                      color: active ? color : '#334155',
                    }}>
                      {count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          {!subTab && (
            <div>
              {(() => {
                const parsedEvs = evidence.filter(ev => Boolean(evResultMap[ev.name]?.resultId));
                const unparsedEvs = evidence.filter(ev => !evResultMap[ev.name]?.resultId);
                return (
                  <>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                      <Clock size={13} style={{ color: '#4d82c0' }} />
                      <span style={{ fontSize: 11, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#7d8590' }}>
                        {t('casedetail.choose_collection')}
                      </span>
                      {parsedEvs.length > 0 && (
                        <span style={{ fontSize: 10, fontFamily: 'monospace', padding: '1px 7px', borderRadius: 10, background: '#22c55e14', color: '#22c55e', border: '1px solid #22c55e30' }}>
                          {parsedEvs.length} {parsedEvs.length > 1 ? t('casedetail.ready_pl') : t('casedetail.ready')}
                        </span>
                      )}
                    </div>

                    {parsedEvs.length === 0 ? (
                      <div style={{ padding: '20px 18px', borderRadius: 10, background: '#0d1117', border: '1px dashed #30363d', textAlign: 'center' }}>
                        <Clock size={28} style={{ color: '#30363d', margin: '0 auto 10px' }} />
                        <p style={{ fontSize: 12, color: '#7d8590', fontFamily: 'monospace', marginBottom: 4 }}>
                          {t('casedetail.no_parsed_collections')}
                        </p>
                        <p style={{ fontSize: 10, color: '#484f58', fontFamily: 'monospace' }}>
                          {t('casedetail.parse_hint')}
                        </p>
                      </div>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 14 }}>
                        {parsedEvs.map(ev => {
                          const recordCount = evResultMap[ev.name]?.recordCount ?? 0;
                          return (
                            <div
                              key={ev.id}
                              onClick={() => navigate(`/cases/${id}/collections/${ev.id}/timeline`, { state: { evidenceName: ev.name, caseTitle: caseData?.title, caseNumber: caseData?.case_number } })}
                              style={{
                                display: 'flex', alignItems: 'center', gap: 12, padding: '12px 16px',
                                borderRadius: 10, background: '#111827',
                                border: '1px solid #22c55e30', borderLeft: '3px solid #22c55e',
                                cursor: 'pointer', transition: 'all 0.15s',
                              }}
                              onMouseEnter={e => { e.currentTarget.style.background = '#162032'; e.currentTarget.style.borderColor = '#22c55e60'; e.currentTarget.style.borderLeftColor = '#22c55e'; }}
                              onMouseLeave={e => { e.currentTarget.style.background = '#111827'; e.currentTarget.style.borderColor = '#22c55e30'; e.currentTarget.style.borderLeftColor = '#22c55e'; }}
                            >
                              <FolderOpen size={16} style={{ color: '#22c55e', flexShrink: 0 }} />
                              <div style={{ flex: 1, overflow: 'hidden' }}>
                                <div style={{ fontSize: 13, color: '#e6edf3', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                  {ev.name}
                                </div>
                                <div style={{ fontSize: 10, fontFamily: 'monospace', color: '#7d8590', marginTop: 2, display: 'flex', gap: 8 }}>
                                  <span style={{ color: '#22c55e' }}>
                                    {recordCount > 0 ? `${recordCount.toLocaleString()} ${t('casedetail.records')}` : t('casedetail.indexed')}
                                  </span>
                                  {ev.evidence_type && (
                                    <span style={{ padding: '0 5px', borderRadius: 3, background: '#1c2333', color: '#484f58', border: '1px solid #30363d' }}>{ev.evidence_type}</span>
                                  )}
                                  {fmtSize(ev.file_size) !== '0 B' && (
                                    <span>{fmtSize(ev.file_size)}</span>
                                  )}
                                </div>
                              </div>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '7px 16px', borderRadius: 7,
                                background: '#4d82c020', color: '#4d82c0', border: '1px solid #4d82c040',
                                fontSize: 12, fontFamily: 'monospace', fontWeight: 600, flexShrink: 0, whiteSpace: 'nowrap' }}>
                                <Clock size={12} /> {t('casedetail.open')} <ChevronRight size={13} />
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}

                    {unparsedEvs.length > 0 && (
                      <details style={{ marginBottom: 14 }}>
                        <summary style={{
                          fontSize: 10, fontFamily: 'monospace', color: '#484f58',
                          cursor: 'pointer', padding: '4px 2px', userSelect: 'none',
                          display: 'flex', alignItems: 'center', gap: 5,
                        }}>
                          <span>▸ {unparsedEvs.length > 1 ? t('casedetail.unparsed_count_pl', { n: unparsedEvs.length }) : t('casedetail.unparsed_count', { n: unparsedEvs.length })}</span>
                        </summary>
                        <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 4 }}>
                          {unparsedEvs.map(ev => (
                            <div key={ev.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 14px',
                              borderRadius: 8, background: '#0d1117', border: '1px solid #1e2a3a' }}>
                              <FolderOpen size={13} style={{ color: '#484f58', flexShrink: 0 }} />
                              <span style={{ fontSize: 11, color: '#7d8590', fontFamily: 'monospace', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {ev.name}
                              </span>
                              <button
                                onClick={async () => {
                                  setStReparsing(true);
                                  setStParseProgress(null);
                                  stProgressRef.current = { completed: [] };
                                  try {
                                    await collectionAPI.parse(id, { artifact_types: 'all', socketId, evidence_id: ev.id });
                                    await refreshEvResultMap();
                                    setStReloadKey(k => k + 1);
                                  } catch {}
                                  setStReparsing(false);
                                  setStParseProgress(null);
                                }}
                                disabled={stReparsing}
                                style={{
                                  display: 'flex', alignItems: 'center', gap: 4, padding: '3px 10px',
                                  borderRadius: 5, fontSize: 10, fontFamily: 'monospace',
                                  cursor: stReparsing ? 'not-allowed' : 'pointer', flexShrink: 0,
                                  background: stReparsing ? '#1a2035' : '#22c55e10',
                                  color: stReparsing ? '#484f58' : '#22c55e',
                                  border: `1px solid ${stReparsing ? '#1e2a3a' : '#22c55e30'}`,
                                }}>
                                {stReparsing ? <><Loader2 size={9} className="animate-spin" /> Parsing…</> : `▶ ${t('casedetail.parse_btn')}`}
                              </button>
                            </div>
                          ))}
                        </div>
                      </details>
                    )}

                  </>
                );
              })()}
            </div>
          )}

          {subTab === 'hayabusa' && (
            <CaseHayabusaView
              caseId={id}
              reloadKey={stReloadKey}
              onTotalChange={setHayCount}
            />
          )}

          {subTab === 'catscale' && (
            <CatScaleTimelineTab
              caseId={id}
              onTotalChange={setCatscaleCount}
            />
          )}

        </div>
      )}

      {tab === 'iocs' && (
        <div>
          <div className="flex gap-3 mb-4">
            <div className="fl-search flex-1">
              <Search size={14} className="fl-search-icon" />
              <input value={iocSearch} onChange={e => setIocSearch(e.target.value)} placeholder={t('casedetail.ioc_search_ph')}
                className="fl-input pl-8 w-full font-mono" />
            </div>
            <button onClick={async () => {
              try {
                const resp = await iocsAPI.exportStix(id);
                const blob = new Blob([resp.data], { type: 'application/json;charset=utf-8' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a'); a.href = url; a.download = `stix-${id}-${Date.now()}.json`; a.click();
                URL.revokeObjectURL(url);
              } catch {}
            }} className="fl-btn fl-btn-ghost fl-btn-sm" style={{ color: '#8b72d6' }} title="Exporter les IOCs en bundle STIX 2.1">
              <Download size={14} /> Exporter STIX
            </button>
            <button onClick={() => { setShowStixImport(true); setStixFiles([]); setStixResult(null); }}
              className="fl-btn fl-btn-ghost fl-btn-sm" style={{ color: '#22c55e' }} title="Importer des indicateurs depuis un bundle STIX 2.1 (OpenCTI)">
              <Upload size={14} /> Importer STIX
            </button>
            <button onClick={() => setShowIOCForm(!showIOCForm)} className="fl-btn fl-btn-primary fl-btn-sm"><Plus size={14} /> {t('casedetail.add_ioc')}</button>
          </div>

          {showStixImport && (
            <div style={{
              position: 'fixed', inset: 0, zIndex: 600,
              background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center',
            }} onClick={e => { if (e.target === e.currentTarget) setShowStixImport(false); }}>
              <div style={{
                background: '#161b22', border: '1px solid #30363d', borderRadius: 10,
                width: 540, maxHeight: '80vh', display: 'flex', flexDirection: 'column',
                boxShadow: '0 24px 64px rgba(0,0,0,0.7)',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '14px 18px', borderBottom: '1px solid #30363d',
                  background: 'linear-gradient(90deg, rgba(34,197,94,0.08) 0%, transparent 100%)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Upload size={14} style={{ color: '#22c55e' }} />
                    <span style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 700, color: '#e6edf3' }}>
                      Importer IOCs depuis STIX 2.1
                    </span>
                    <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#7d8590', padding: '1px 6px',
                      background: '#0d1117', borderRadius: 4, border: '1px solid #30363d' }}>OpenCTI compatible</span>
                  </div>
                  <button onClick={() => setShowStixImport(false)}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#7d8590', padding: 4 }}>
                    <X size={14} />
                  </button>
                </div>

                <div style={{ flex: 1, overflowY: 'auto', padding: '16px 18px' }}>
                  {!stixResult && (
                    <>
                      <label style={{
                        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
                        gap: 8, padding: '28px 20px', borderRadius: 8, cursor: 'pointer',
                        border: '2px dashed #30363d', background: '#0d1117',
                        transition: 'border-color 0.2s',
                      }}
                        onDragOver={e => { e.preventDefault(); e.currentTarget.style.borderColor = '#22c55e'; }}
                        onDragLeave={e => { e.currentTarget.style.borderColor = '#30363d'; }}
                        onDrop={e => {
                          e.preventDefault();
                          e.currentTarget.style.borderColor = '#30363d';
                          const dropped = Array.from(e.dataTransfer.files).filter(f => f.name.endsWith('.json'));
                          if (!dropped.length) return;
                          Promise.all(dropped.map(f => f.text().then(txt => {
                            try {
                              const bundle = JSON.parse(txt);
                              const count = (bundle.objects || []).filter(o => o.type === 'indicator').length;
                              return { name: f.name, bundle, count };
                            } catch { return null; }
                          }))).then(results => setStixFiles(prev => [...prev, ...results.filter(Boolean)]));
                        }}
                      >
                        <input type="file" multiple accept=".json" style={{ display: 'none' }}
                          onChange={e => {
                            const files = Array.from(e.target.files);
                            Promise.all(files.map(f => f.text().then(txt => {
                              try {
                                const bundle = JSON.parse(txt);
                                const count = (bundle.objects || []).filter(o => o.type === 'indicator').length;
                                return { name: f.name, bundle, count };
                              } catch { return null; }
                            }))).then(results => setStixFiles(prev => [...prev, ...results.filter(Boolean)]));
                            e.target.value = '';
                          }}
                        />
                        <Upload size={22} style={{ color: '#22c55e', opacity: 0.7 }} />
                        <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#7d8590', textAlign: 'center' }}>
                          Glisser-déposer des fichiers JSON ici<br />
                          <span style={{ color: '#4d82c0' }}>ou cliquer pour sélectionner</span>
                        </span>
                        <span style={{ fontSize: 10, color: '#484f58', fontFamily: 'monospace' }}>
                          Bundles STIX 2.1 exportés depuis OpenCTI, MISP, ou tout serveur TAXII
                        </span>
                      </label>

                      {stixFiles.length > 0 && (
                        <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 6 }}>
                          {stixFiles.map((f, i) => (
                            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8,
                              padding: '6px 10px', borderRadius: 6, background: '#0d1117',
                              border: '1px solid #21262d' }}>
                              <FileJson size={12} style={{ color: '#4d82c0', flexShrink: 0 }} />
                              <span style={{ fontFamily: 'monospace', fontSize: 10, flex: 1,
                                color: '#c9d1d9', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {f.name}
                              </span>
                              <span style={{ fontFamily: 'monospace', fontSize: 10,
                                color: f.count > 0 ? '#22c55e' : '#7d8590', flexShrink: 0 }}>
                                {f.count} indicateur{f.count !== 1 ? 's' : ''}
                              </span>
                              <button onClick={() => setStixFiles(prev => prev.filter((_, j) => j !== i))}
                                style={{ background: 'none', border: 'none', cursor: 'pointer',
                                  color: '#484f58', padding: 2, display: 'flex' }}>
                                <X size={11} />
                              </button>
                            </div>
                          ))}
                          <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#7d8590',
                            textAlign: 'right', paddingRight: 2 }}>
                            Total : <strong style={{ color: '#e6edf3' }}>
                              {stixFiles.reduce((s, f) => s + f.count, 0)}
                            </strong> indicateur(s) à importer
                          </div>
                        </div>
                      )}
                    </>
                  )}

                  {stixResult && (
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center',
                      gap: 12, padding: '20px 0' }}>
                      <CheckCircle size={32} style={{ color: '#22c55e' }} />
                      <span style={{ fontFamily: 'monospace', fontSize: 12, color: '#e6edf3', textAlign: 'center' }}>
                        {stixResult.message}
                      </span>
                      <div style={{ display: 'flex', gap: 16 }}>
                        {[
                          { label: 'Créés', value: stixResult.created, color: '#22c55e' },
                          { label: 'Ignorés', value: stixResult.skipped, color: '#7d8590' },
                          { label: 'Erreurs', value: stixResult.errors, color: '#da3633' },
                        ].map(({ label, value, color }) => (
                          <div key={label} style={{ textAlign: 'center' }}>
                            <div style={{ fontFamily: 'monospace', fontSize: 20, fontWeight: 800, color }}>{value}</div>
                            <div style={{ fontFamily: 'monospace', fontSize: 9, color: '#7d8590', textTransform: 'uppercase' }}>{label}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8,
                  padding: '12px 18px', borderTop: '1px solid #21262d' }}>
                  {stixResult ? (
                    <button onClick={() => setShowStixImport(false)}
                      className="fl-btn fl-btn-primary fl-btn-sm">Fermer</button>
                  ) : (
                    <>
                      <button onClick={() => setShowStixImport(false)}
                        className="fl-btn fl-btn-ghost fl-btn-sm">Annuler</button>
                      <button
                        disabled={stixFiles.length === 0 || stixImporting}
                        onClick={async () => {
                          setStixImporting(true);
                          try {
                            const resp = await iocsAPI.importStix(id, stixFiles.map(f => f.bundle));
                            setStixResult(resp.data);
                            const r = await iocsAPI.list(id);
                            setIOCs(r.data);
                          } catch {
                            setStixResult({ created: 0, skipped: 0, errors: stixFiles.reduce((s,f)=>s+f.count,0), message: 'Erreur lors de l\'import.' });
                          } finally {
                            setStixImporting(false);
                          }
                        }}
                        className="fl-btn fl-btn-primary fl-btn-sm"
                        style={{ opacity: stixFiles.length === 0 ? 0.4 : 1 }}>
                        {stixImporting
                          ? <><Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} /> Import en cours...</>
                          : <><Upload size={12} /> Importer {stixFiles.reduce((s,f)=>s+f.count,0)} IOC(s)</>}
                      </button>
                    </>
                  )}
                </div>
              </div>
            </div>
          )}

          {showIOCForm && (
            <div className="rounded-lg p-4 mb-4" style={{ background: '#0d1117', border: '1px solid #30363d' }}>
              <h4 className="text-xs font-mono uppercase tracking-wider mb-3" style={{ color: '#4d82c0' }}>Nouvel Indicateur de Compromission</h4>
              <div className="grid grid-cols-2 gap-3 mb-3">
                <div>
                  <label className="fl-label">Type</label>
                  <select value={iocForm.ioc_type} onChange={e => setIocForm(p => ({ ...p, ioc_type: e.target.value }))}
                    className="fl-select w-full">
                    {['ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256', 'filename', 'registry_key', 'mutex', 'user_agent', 'email', 'other'].map(t => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="fl-label">Valeur *</label>
                  <input value={iocForm.value} onChange={e => setIocForm(p => ({ ...p, value: e.target.value }))}
                    placeholder="Ex: 185.220.101.42, malware-c2.net..."
                    className="fl-input w-full font-mono" />
                </div>
                <div>
                  <label className="fl-label">Source</label>
                  <input value={iocForm.source} onChange={e => setIocForm(p => ({ ...p, source: e.target.value }))}
                    placeholder="DNS Logs, EDR, Firewall..."
                    className="fl-input w-full" />
                </div>
                <div>
                  <label className="fl-label">Sévérité (1-10)</label>
                  <input type="number" min="1" max="10" value={iocForm.severity} onChange={e => setIocForm(p => ({ ...p, severity: e.target.value }))}
                    className="fl-input w-full" />
                </div>
              </div>
              <div className="mb-3">
                <label className="fl-label">Description</label>
                <input value={iocForm.description} onChange={e => setIocForm(p => ({ ...p, description: e.target.value }))}
                  placeholder="Description de l'IOC..."
                  className="fl-input w-full" />
              </div>
              <div className="grid grid-cols-2 gap-3 mb-3">
                <div>
                  <label className="fl-label">Tags (séparés par virgule)</label>
                  <input value={iocForm.tags} onChange={e => setIocForm(p => ({ ...p, tags: e.target.value }))}
                    placeholder="c2, malware, phishing..."
                    className="fl-input w-full" />
                </div>
                <div className="flex items-end pb-1">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" checked={iocForm.is_malicious} onChange={e => setIocForm(p => ({ ...p, is_malicious: e.target.checked }))} />
                    <span className="text-sm" style={{ color: iocForm.is_malicious ? '#da3633' : '#7d8590' }}>⚠ Confirmé malveillant</span>
                  </label>
                </div>
              </div>
              <div className="flex gap-2">
                <button onClick={createIOC} disabled={!iocForm.value || iocSaving}
                  className="fl-btn fl-btn-primary fl-btn-sm"
                  style={{ opacity: !iocForm.value ? 0.4 : 1 }}>
                  {iocSaving ? '⏳ Enregistrement...' : '✓ Créer l\'IOC'}
                </button>
                <button onClick={() => setShowIOCForm(false)} className="fl-btn fl-btn-secondary fl-btn-sm">Annuler</button>
              </div>
            </div>
          )}
          <div className="space-y-2">
            {filteredIOC.map(ioc => (
              <div key={ioc.id} className="rounded-lg p-4 flex items-center gap-4" style={{ background: '#1c2333', border: `1px solid ${ioc.is_malicious ? '#da363320' : '#30363d'}`, borderLeft: `3px solid ${ioc.is_malicious ? '#da3633' : '#7d8590'}` }}>
                <div className="w-10 h-10 rounded-lg flex items-center justify-center font-mono text-xs font-bold flex-shrink-0"
                  style={{ background: `${ioc.severity >= 8 ? '#da3633' : ioc.severity >= 5 ? '#d97c20' : '#c89d1d'}15`, color: ioc.severity >= 8 ? '#da3633' : ioc.severity >= 5 ? '#d97c20' : '#c89d1d' }}>{ioc.severity}</div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <ColorBadge color="#4d82c0">{ioc.ioc_type}</ColorBadge>
                    {ioc.is_malicious && <ColorBadge color="#da3633">⚠ MALVEILLANT</ColorBadge>}
                    <span className="text-xs" style={{ color: '#7d8590' }}>via {ioc.source}</span>
                  </div>
                  <div className="font-mono text-sm font-semibold break-all" style={{ color: ioc.is_malicious ? '#da3633' : '#e6edf3' }}>{ioc.value}</div>
                  {ioc.description && <p className="text-xs mt-1" style={{ color: '#7d8590' }}>{ioc.description}</p>}
                </div>
                <div className="flex gap-1 flex-shrink-0 flex-wrap justify-end">
                  {(ioc.tags || []).map(t => <span key={t} className="px-2 py-0.5 rounded text-xs font-mono" style={{ background: '#0d1117', color: '#7d8590', border: '1px solid #30363d' }}>{t}</span>)}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === 'detections' && (
        <div>
          {triageData && (
            <MachineScorePanel
              triageData={triageData}
              loading={triageRunning}
              onRefresh={runTriage}
              caseId={id}
              collectionId={collectionId}
            />
          )}
          <DetectionsTab caseId={id} />
        </div>
      )}

      {tab === 'network' && (
        <div>
          {networkStats && parseInt(networkStats.total_connections) > 0 && (
            <div className="grid grid-cols-4 gap-3 mb-4">
              {[
                ['Connexions', networkStats.total_connections, '#4d82c0'],
                ['Suspectes', networkStats.suspicious_connections, '#da3633'],
                ['IPs Sources', networkStats.unique_src_ips, '#c89d1d'],
                ['IPs Dest.', networkStats.unique_dst_ips, '#8b72d6'],
              ].map(([l, v, c]) => (
                <div key={l} className="rounded-lg p-3 border" style={{ background: '#1c2333', borderColor: '#30363d', borderLeft: `3px solid ${c}` }}>
                  <div className="font-mono text-2xl font-bold" style={{ color: c }}>{v || 0}</div>
                  <div className="text-xs" style={{ color: '#7d8590' }}>{l}</div>
                </div>
              ))}
            </div>
          )}
          <div className="rounded-lg p-8 text-center" style={{ background: '#1c2333', border: '1px solid #30363d' }}>
            <Network size={36} style={{ color: '#4d82c0', margin: '0 auto 12px', opacity: 0.7 }} />
            <div className="text-sm font-semibold mb-1" style={{ color: '#e6edf3' }}>Réseau & Kill Chain</div>
            <div className="text-xs mb-4" style={{ color: '#7d8590' }}>
              Explorez la topologie réseau et la chaîne d'attaque MITRE ATT&CK du cas.
            </div>
            <button onClick={() => navigate(`/cases/${id}/graph`)} className="fl-btn fl-btn-primary">
              Ouvrir la vue Intelligence <ChevronRight size={14} className="inline ml-1" />
            </button>
          </div>
        </div>
      )}

      {tab === 'mitre' && <MitreAttackTab caseId={id} />}

      {tab === 'playbooks' && <PlaybooksTab caseId={id} />}

      {tab === 'hayabusa' && (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, height: '100%' }}>
          <CaseHayabusaView
            caseId={id}
            reloadKey={stReloadKey}
            onTotalChange={setHayCount}
          />
        </div>
      )}

      {tab === 'cyberchef' && (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, height: '100%' }}>
          <CyberChefPage />
        </div>
      )}

      {tab === 'audit' && (() => {
        const AUDIT_COLORS = {
          login: '#22c55e', login_failed: '#da3633', login_blocked: '#c89d1d',
          import_collection: '#4d82c0', parse_collection: '#8b72d6', delete_collection_data: '#da3633',
          create_case: '#d97c20', update_case: '#d97c20', hard_delete_case: '#da3633',
          upload_evidence: '#3fb950', delete_evidence: '#da3633',
          add_mitre_technique: '#06b6d4', delete_mitre_technique: '#da3633',
          create_user: '#06b6d4', update_user: '#d97c20', delete_user: '#da3633', change_password: '#c89d1d',
          generate_report: '#8b72d6', create_ioc: '#c89d1d', delete_ioc: '#da3633',
          run_yara_scan: '#f472b6', run_sigma_hunt: '#8b5cf6', fetch_taxii: '#14b8a6', correlate_case: '#fb923c',
        };
        const AUDIT_LABELS = {
          login: 'Connexion', login_failed: 'Échec connexion', login_blocked: 'Compte bloqué',
          import_collection: 'Import collecte', parse_collection: 'Parsing', delete_collection_data: 'Suppression collecte',
          create_case: 'Création cas', update_case: 'Modification cas', hard_delete_case: 'Purge RGPD',
          upload_evidence: 'Ajout preuve', delete_evidence: 'Suppression preuve',
          add_mitre_technique: 'Ajout MITRE', update_mitre_technique: 'Modif. MITRE', delete_mitre_technique: 'Suppression MITRE',
          create_user: 'Création compte', update_user: 'Modification compte', delete_user: 'Suppression compte', change_password: 'Changement MDP',
          generate_report: 'Génération rapport', create_ioc: 'Ajout IOC', delete_ioc: 'Suppression IOC',
          run_yara_scan: 'Scan YARA', run_sigma_hunt: 'Chasse Sigma', fetch_taxii: 'Sync TAXII', correlate_case: 'Corrélation Intel',
        };
        const totalPages = Math.max(1, Math.ceil(auditTotal / AUDIT_PAGE_SIZE));
        const applyFilters = () => {
          setAuditPage(0);
          fetchAuditLog(0, {
            action: auditFilterAction,
            username: auditFilterUser,
            date_from: auditFilterFrom,
            date_to: auditFilterTo,
          });
        };
        const resetFilters = () => {
          setAuditFilterAction('');
          setAuditFilterUser('');
          setAuditFilterFrom('');
          setAuditFilterTo('');
          setAuditPage(0);
          fetchAuditLog(0, {});
        };
        return (
          <div>
              <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs font-mono uppercase tracking-wider flex items-center gap-2" style={{ color: '#7d8590' }}>
                <ScrollText size={14} /> Journal d'Audit — {c.case_number}
              </h3>
              <span className="text-xs font-mono" style={{ color: '#484f58' }}>
                {auditTotal > 0 ? `${auditTotal} entrée${auditTotal > 1 ? 's' : ''}` : ''}
              </span>
            </div>

            <div style={{
              display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'flex-end',
              padding: '10px 14px', borderRadius: 8, marginBottom: 12,
              background: '#161b22', border: '1px solid #30363d',
            }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <label style={{ fontSize: 10, fontFamily: 'monospace', color: '#7d8590', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{t('casedetail.audit_filter_action')}</label>
                <select
                  className="fl-select"
                  value={auditFilterAction}
                  onChange={e => setAuditFilterAction(e.target.value)}
                  style={{ fontSize: 11, fontFamily: 'monospace', minWidth: 180, background: '#0d1117', color: '#e6edf3', border: '1px solid #30363d', borderRadius: 5, padding: '4px 8px' }}
                >
                  <option value="">Toutes</option>
                  <option value="create_case">create_case</option>
                  <option value="update_case">update_case</option>
                  <option value="hard_delete_case">hard_delete_case</option>
                  <option value="legal_hold_enable">legal_hold_enable</option>
                  <option value="legal_hold_disable">legal_hold_disable</option>
                  <option value="triage_compute">triage_compute</option>
                  <option value="upload_evidence">upload_evidence</option>
                  <option value="upload_evidence_chunked">upload_evidence_chunked</option>
                  <option value="delete_evidence">delete_evidence</option>
                  <option value="import_collection">import_collection</option>
                  <option value="parse_collection">parse_collection</option>
                  <option value="run_hayabusa">run_hayabusa</option>
                  <option value="delete_collection_data">delete_collection_data</option>
                  <option value="pcap_parse">pcap_parse</option>
                  <option value="create_ioc">create_ioc</option>
                  <option value="delete_ioc">delete_ioc</option>
                  <option value="export_stix">export_stix</option>
                  <option value="correlate_case">correlate_case</option>
                  <option value="generate_report">generate_report</option>
                  <option value="download_report">download_report</option>
                  <option value="add_mitre_technique">add_mitre_technique</option>
                  <option value="update_mitre_technique">update_mitre_technique</option>
                  <option value="delete_mitre_technique">delete_mitre_technique</option>
                  <option value="run_yara_scan">run_yara_scan</option>
                  <option value="run_sigma_hunt">run_sigma_hunt</option>
                  <option value="fetch_taxii">fetch_taxii</option>
                  <option value="create_bookmark">create_bookmark</option>
                  <option value="start_playbook">start_playbook</option>
                  <option value="soar_run">soar_run</option>
                </select>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <label style={{ fontSize: 10, fontFamily: 'monospace', color: '#7d8590', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{t('casedetail.audit_filter_user')}</label>
                <input
                  className="fl-input"
                  type="text"
                  value={auditFilterUser}
                  onChange={e => setAuditFilterUser(e.target.value)}
                  placeholder="Filtrer par nom…"
                  style={{ fontSize: 11, fontFamily: 'monospace', minWidth: 160, background: '#0d1117', color: '#e6edf3', border: '1px solid #30363d', borderRadius: 5, padding: '4px 8px' }}
                  onKeyDown={e => { if (e.key === 'Enter') applyFilters(); }}
                />
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <label style={{ fontSize: 10, fontFamily: 'monospace', color: '#7d8590', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{t('casedetail.audit_filter_from')}</label>
                <input
                  className="fl-input"
                  type="date"
                  value={auditFilterFrom}
                  onChange={e => setAuditFilterFrom(e.target.value)}
                  style={{ fontSize: 11, fontFamily: 'monospace', background: '#0d1117', color: '#e6edf3', border: '1px solid #30363d', borderRadius: 5, padding: '4px 8px' }}
                />
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <label style={{ fontSize: 10, fontFamily: 'monospace', color: '#7d8590', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{t('casedetail.audit_filter_to')}</label>
                <input
                  className="fl-input"
                  type="date"
                  value={auditFilterTo}
                  onChange={e => setAuditFilterTo(e.target.value)}
                  style={{ fontSize: 11, fontFamily: 'monospace', background: '#0d1117', color: '#e6edf3', border: '1px solid #30363d', borderRadius: 5, padding: '4px 8px' }}
                />
              </div>
              <div style={{ display: 'flex', gap: 6, alignSelf: 'flex-end' }}>
                <button
                  className="fl-btn fl-btn-primary fl-btn-sm"
                  onClick={applyFilters}
                  style={{ fontSize: 11, fontFamily: 'monospace' }}
                >
                  {t('casedetail.audit_apply')}
                </button>
                <button
                  className="fl-btn fl-btn-ghost fl-btn-sm"
                  onClick={resetFilters}
                  style={{ fontSize: 11, fontFamily: 'monospace' }}
                >
                  {t('common.refresh')}
                </button>
              </div>
            </div>

            {loadingAudit ? (
              <div className="flex items-center justify-center py-10">
                <Spinner size={16} text={t('casedetail.audit_loading')} />
              </div>
            ) : auditEntries.length === 0 ? (
              <div className="rounded-xl p-10 text-center border" style={{ background: '#111827', borderColor: '#30363d' }}>
                <ScrollText size={32} style={{ color: '#1e2a3a', margin: '0 auto 10px' }} />
                <p className="text-sm" style={{ color: '#7d8590' }}>{t('casedetail.audit_empty')}</p>
              </div>
            ) : (
              <>
                <div className="rounded-xl border overflow-hidden" style={{ background: '#111827', borderColor: '#30363d' }}>
                  <table className="w-full text-sm">
                    <thead>
                      <tr style={{ borderBottom: '1px solid #30363d' }}>
                        {['Horodatage', 'Utilisateur', 'Action', 'Objet', 'Détails', 'IP'].map(h => (
                          <th key={h} className="text-left px-4 py-3 text-xs font-mono uppercase tracking-wider" style={{ color: '#7d8590' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {auditEntries.map(a => {
                        const color = AUDIT_COLORS[a.action] || '#7d8590';
                        const label = AUDIT_LABELS[a.action] || a.action;
                        const details = a.details || {};
                        const detailStr = details.filename || details.title || details.username || details.case_number || details.rule_name || details.reason || details.value || '';
                        return (
                          <tr key={a.id} style={{ borderBottom: '1px solid rgba(28,38,64,0.3)' }}>
                            <td className="px-4 py-2.5 font-mono text-xs whitespace-nowrap" style={{ color: '#7d8590' }}>
                              {new Date(a.created_at).toLocaleString(i18n.language)}
                            </td>
                            <td className="px-4 py-2.5">
                              <span className="px-2 py-0.5 rounded text-xs font-mono font-bold"
                                style={{ background: '#4d82c014', color: '#4d82c0', border: '1px solid #4d82c028' }}>
                                {a.username || a.user_name || '—'}
                              </span>
                            </td>
                            <td className="px-4 py-2.5">
                              <span className="px-2 py-0.5 rounded text-xs font-mono font-bold"
                                style={{ background: `${color}14`, color, border: `1px solid ${color}28` }}>
                                {label}
                              </span>
                            </td>
                            <td className="px-4 py-2.5 text-xs font-mono" style={{ color: '#7d8590' }}>{a.entity_type}</td>
                            <td className="px-4 py-2.5 text-xs font-mono" style={{ color: '#e6edf3', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                              title={detailStr}>{detailStr}</td>
                            <td className="px-4 py-2.5 text-xs font-mono" style={{ color: '#484f58' }}>{a.ip_address || '—'}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                <Pagination
                  page={auditPage + 1}
                  totalPages={totalPages}
                  onChange={p => { setAuditPage(p - 1); fetchAuditLog(p - 1, { action: auditFilterAction, username: auditFilterUser, date_from: auditFilterFrom, date_to: auditFilterTo }); }}
                  siblingCount={1}
                />
              </>
            )}
          </div>
        );
      })()}

      </div>

      <Modal
        open={Boolean(evToDelete)}
        title={t('casedetail.delete_evidence_title')}
        onClose={() => !deletingEv && setEvToDelete(null)}
        size="sm"
        accentColor="var(--fl-danger)"
      >
        <Modal.Body>
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-full flex items-center justify-center" style={{ background: 'rgba(218,54,51,0.12)' }}>
              <Trash2 size={20} style={{ color: 'var(--fl-danger)' }} />
            </div>
            <p className="text-xs mt-0.5 font-mono" style={{ color: 'var(--fl-dim)' }}>{evToDelete?.name}</p>
          </div>
          <p className="text-sm mb-2" style={{ color: 'var(--fl-muted)' }}>
            {t('casedetail.delete_evidence_sub')}<br />
            <span style={{ color: 'var(--fl-danger)' }}>{t('casedetail.hard_delete_warn1')}</span>
          </p>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" size="sm" onClick={() => setEvToDelete(null)} disabled={deletingEv}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="danger"
            size="sm"
            loading={deletingEv}
            icon={deletingEv ? undefined : Trash2}
            onClick={async () => {
              setDeletingEv(true);
              try {
                await evidenceAPI.delete(evToDelete.id);
                setEvidence(prev => prev.filter(e => e.id !== evToDelete.id));
                if (selEv?.id === evToDelete.id) { setSelEv(null); }
                setEvToDelete(null);
              } catch (e) {
                alert(t('casedetail.err_deadline') + (e.response?.data?.error || e.message));
              }
              setDeletingEv(false);
            }}
          >
            {deletingEv ? t('casedetail.deleting_evidence') : t('casedetail.delete_evidence_btn')}
          </Button>
        </Modal.Footer>
      </Modal>

      <Modal
        open={showHardDelete}
        title={hardDeleteResult ? t('cases.report_title') : t('casedetail.hard_delete_title')}
        onClose={() => { if (!hardDeleting) { setShowHardDelete(false); setHardDeleteConfirm(''); setHardDeleteResult(null); } }}
        size="md"
        accentColor="var(--fl-danger)"
      >
        <Modal.Body>
          <div style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-danger)', marginBottom: 14, letterSpacing: '0.04em' }}>
            {hardDeleteResult ? 'VÉRIFICATION BASE DE DONNÉES' : 'ACTION IRRÉVERSIBLE · ADMIN UNIQUEMENT'}
          </div>

          {!hardDeleting && !hardDeleteResult && (
            <>
              <div style={{ marginBottom: 16, padding: '10px 14px', borderRadius: 8, background: 'rgba(218,54,51,0.06)', border: '1px solid rgba(218,54,51,0.18)', fontSize: 12, color: 'var(--fl-muted)', lineHeight: 1.7 }}>
                Détruira <strong style={{ color: 'var(--fl-text)' }}>{caseData?.case_number}</strong> ainsi que tous ses fichiers
                (via <code style={{ color: 'var(--fl-danger)', fontFamily: 'monospace' }}>DoD 5220.22-M</code>), preuves, IOCs,
                timeline, rapports et données MITRE.<br />
                <span style={{ color: 'var(--fl-warn)', fontSize: 11 }}>Un enregistrement d'audit immutable sera conservé.</span>
              </div>
              <div style={{ marginBottom: 6, fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-dim)' }}>
                Tapez <code style={{ color: 'var(--fl-danger)', letterSpacing: '0.05em' }}>{caseData?.case_number}</code> pour confirmer :
              </div>
              <input
                value={hardDeleteConfirm}
                onChange={e => setHardDeleteConfirm(e.target.value)}
                placeholder={caseData?.case_number}
                className="fl-input w-full font-mono"
                style={{ border: `1px solid ${hardDeleteConfirm === caseData?.case_number ? 'var(--fl-danger)' : 'var(--fl-border)'}` }}
                autoComplete="off"
              />
            </>
          )}

          {hardDeleting && (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '32px 0', gap: 14 }}>
              <Spinner size={32} color="var(--fl-danger)" />
              <div style={{ fontFamily: 'monospace', fontSize: 13, color: 'var(--fl-muted)' }}>Destruction sécurisée en cours…</div>
              <div style={{ fontSize: 11, color: 'var(--fl-dim)', fontFamily: 'monospace' }}>DoD 5220.22-M · cascade delete · audit log</div>
            </div>
          )}

          {hardDeleteResult && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{
                padding: '12px 14px', borderRadius: 8,
                background: hardDeleteResult.ok && hardDeleteResult.verified ? 'rgba(63,185,80,0.05)' : 'rgba(218,54,51,0.05)',
                border: `1px solid ${hardDeleteResult.ok && hardDeleteResult.verified ? 'rgba(63,185,80,0.25)' : 'rgba(218,54,51,0.25)'}`,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                  {hardDeleteResult.ok
                    ? <span style={{ fontSize: 18 }}>✅</span>
                    : <span style={{ fontSize: 18 }}>❌</span>
                  }
                  <span style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 700, color: hardDeleteResult.ok ? '#3fb950' : 'var(--fl-danger)' }}>
                    {hardDeleteResult.ok ? 'Destruction réussie' : 'Échec de la destruction'}
                  </span>
                </div>

                {hardDeleteResult.ok && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginLeft: 26 }}>
                    <div style={{ fontSize: 12, fontFamily: 'monospace', color: '#3fb950' }}>
                      ✓ {hardDeleteResult.files_destroyed} fichier{hardDeleteResult.files_destroyed !== 1 ? 's' : ''} détruit{hardDeleteResult.files_destroyed !== 1 ? 's' : ''} (DoD 5220.22-M)
                    </div>
                    <div style={{ fontSize: 12, fontFamily: 'monospace', color: hardDeleteResult.verified ? '#3fb950' : 'var(--fl-danger)' }}>
                      {hardDeleteResult.verified
                        ? '✓ Absence confirmée en base de données (HTTP 404)'
                        : '⚠ Le cas semble toujours accessible en base de données'}
                    </div>
                    {hardDeleteResult.files_errors?.length > 0 && (
                      <div style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-warn)' }}>
                        ⚠ {hardDeleteResult.files_errors.length} fichier(s) non écrasé(s) : {hardDeleteResult.files_errors.join(', ')}
                      </div>
                    )}
                  </div>
                )}

                {!hardDeleteResult.ok && (
                  <div style={{ marginLeft: 26, fontSize: 12, fontFamily: 'monospace', color: 'var(--fl-danger)' }}>
                    {hardDeleteResult.error}
                  </div>
                )}
              </div>

              <div style={{ padding: '8px 12px', borderRadius: 6, background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-dim)' }}>
                Un enregistrement d'audit a été conservé conformément à l'Art. 17(3) RGPD.
              </div>
            </div>
          )}
        </Modal.Body>
        <Modal.Footer>
          {hardDeleteResult ? (
            <Button variant="secondary" size="sm" onClick={() => navigate('/cases', { replace: true })}>
              {t('casedetail.back_to_cases')}
            </Button>
          ) : (
            <>
              <Button
                variant="secondary"
                size="sm"
                disabled={hardDeleting}
                onClick={() => { setShowHardDelete(false); setHardDeleteConfirm(''); setHardDeleteResult(null); }}
              >
                {t('common.cancel')}
              </Button>
              <Button
                variant="danger"
                size="sm"
                loading={hardDeleting}
                disabled={hardDeleteConfirm !== caseData?.case_number}
                icon={hardDeleting ? undefined : Trash2}
                onClick={async () => {
                  setHardDeleting(true);
                  try {
                    const { data } = await casesAPI.hardDelete(id);
                    let verified = false;
                    try {
                      await casesAPI.get(id);
                    } catch (verErr) {
                      verified = verErr.response?.status === 404;
                    }
                    setHardDeleteResult({
                      ok: true,
                      files_destroyed: data.files_destroyed ?? 0,
                      files_errors: data.files_errors ?? [],
                      verified,
                    });
                  } catch (e) {
                    setHardDeleteResult({ ok: false, error: e.response?.data?.error || e.message });
                  }
                  setHardDeleting(false);
                }}
              >
                {hardDeleting ? t('casedetail.hard_deleting') : t('casedetail.hard_delete_btn')}
              </Button>
            </>
          )}
        </Modal.Footer>
      </Modal>

      <Modal
        open={showDeleteCollect}
        title={t('casedetail.delete_collect_title')}
        onClose={() => !deletingCollect && setShowDeleteCollect(false)}
        size="sm"
        accentColor="var(--fl-danger)"
      >
        <Modal.Body>
          <p className="text-xs mb-1" style={{ color: 'var(--fl-dim)' }}>{t('casedetail.hard_delete_warn1')}</p>
          <p className="text-sm mb-2" style={{ color: 'var(--fl-muted)' }}>
            {t('casedetail.delete_collect_sub')}
          </p>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" size="sm" onClick={() => setShowDeleteCollect(false)} disabled={deletingCollect}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="danger"
            size="sm"
            loading={deletingCollect}
            icon={deletingCollect ? undefined : Trash2}
            onClick={async () => {
              setDeletingCollect(true);
              try {
                const res = await collectionAPI.deleteData(id);
                setStTotal(0);
                setStReloadKey(k => k + 1);
                setShowDeleteCollect(false);
                const mb = res.data?.freed_mb || 0;
                alert(mb > 0 ? `Données supprimées — ${mb} Mo libérés.` : 'Données supprimées.');
              } catch (e) {
                alert(t('casedetail.err_deadline') + (e.response?.data?.error || e.message));
              }
              setDeletingCollect(false);
            }}
          >
            {deletingCollect ? t('casedetail.deleting_collect') : t('casedetail.delete_collect_btn')}
          </Button>
        </Modal.Footer>
      </Modal>

      <Modal
        open={Boolean(statusModal) && Boolean(c)}
        title={t('casedetail.status_modal_title')}
        onClose={() => setStatusModal(null)}
        size="sm"
      >
        <Modal.Body>
          <div style={{ fontSize: 12, color: 'var(--fl-dim)', marginBottom: 16, fontFamily: 'monospace' }}>
            {c?.case_number} · {c?.title}
          </div>

          {statusModal === '_pick' ? (
            <>
              <div style={{ fontSize: 12, color: 'var(--fl-muted)', marginBottom: 12 }}>
                Statut actuel : <span style={{ color: SM[c?.status]?.c, fontWeight: 600 }}>{SM[c?.status]?.l}</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {Object.entries(SM).filter(([k]) => k !== c?.status).map(([key, { l, c: col }]) => (
                  <button key={key} onClick={() => setStatusModal(key)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 10, padding: '11px 14px',
                      background: `${col}10`, border: `1px solid ${col}30`, borderRadius: 8,
                      cursor: 'pointer', textAlign: 'left',
                    }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: col, flexShrink: 0 }} />
                    <span style={{ fontSize: 13, fontWeight: 600, color: col }}>{l}</span>
                  </button>
                ))}
              </div>
            </>
          ) : (
            <>
              <div style={{ padding: '12px 14px', borderRadius: 8, marginBottom: 18,
                background: statusModal === 'closed' ? 'rgba(218,54,51,0.07)' : 'rgba(77,130,192,0.07)',
                border: `1px solid ${statusModal === 'closed' ? 'rgba(218,54,51,0.2)' : 'rgba(77,130,192,0.2)'}`,
                fontSize: 13, color: 'var(--fl-text)', lineHeight: 1.6,
              }}>
                {statusModal === 'closed' ? (
                  <>
                    Vous êtes sur le point de <strong style={{ color: 'var(--fl-danger)' }}>clôturer définitivement</strong> ce cas.<br />
                    <span style={{ fontSize: 11, color: 'var(--fl-dim)' }}>Cette action est réversible — un admin peut rouvrir le cas si nécessaire.</span>
                  </>
                ) : statusModal === 'pending' ? (
                  <>Mettre le cas en <strong style={{ color: '#d97c20' }}>attente</strong> — l'investigation sera suspendue.</>
                ) : (
                  <>Rouvrir le cas et le passer <strong style={{ color: 'var(--fl-accent)' }}>en cours</strong>.</>
                )}
              </div>
              <div style={{ fontSize: 12, color: 'var(--fl-muted)', marginBottom: 4 }}>
                Nouveau statut : <span style={{ color: SM[statusModal]?.c, fontWeight: 700 }}>{SM[statusModal]?.l}</span>
                {user && <span style={{ color: 'var(--fl-border)' }}> · par {user.full_name || user.username}</span>}
              </div>
            </>
          )}
        </Modal.Body>
        <Modal.Footer>
          {statusModal === '_pick' ? (
            <Button variant="secondary" size="sm" onClick={() => setStatusModal(null)}>
              {t('common.cancel')}
            </Button>
          ) : (
            <>
              <Button variant="secondary" size="sm" disabled={statusChanging} onClick={() => setStatusModal('_pick')}>
                {t('common.back')}
              </Button>
              <Button
                variant={statusModal === 'closed' ? 'danger' : 'primary'}
                size="sm"
                loading={statusChanging}
                onClick={confirmStatusChange}
              >
                {statusChanging ? '…' : `${t('common.confirm')} — ${SM[statusModal]?.l}`}
              </Button>
            </>
          )}
        </Modal.Footer>
      </Modal>

      <Modal
        open={showTriageModal}
        title={t('casedetail.triage_modal_title')}
        onClose={() => !triageRunning && setShowTriageModal(false)}
        size="lg"
        accentColor="#c89d1d"
      >
        <Modal.Body>
          {triageRunning && (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '32px 0', gap: 14 }}>
              <Spinner size={28} color="#c89d1d" />
              <div style={{ fontFamily: 'monospace', fontSize: 13, color: '#7d8590' }}>
                {t('casedetail.triage_running')}
              </div>
              <div style={{ fontSize: 11, color: '#484f58', fontFamily: 'monospace' }}>
                Requêtes SQL sur collection_timeline · scoring pondéré
              </div>
            </div>
          )}
          {!triageRunning && triageData && (
            <div>
              {triageData.case_indicators && (
                <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
                  {[
                    ['YARA', triageData.case_indicators.yara_matches, '#da3633'],
                    ['Sigma', triageData.case_indicators.sigma_matches, '#d97c20'],
                    ['Threat Intel', triageData.case_indicators.threat_intel_matches, '#8b72d6'],
                    ['IOCs malveillants', triageData.case_indicators.malicious_iocs, '#c89d1d'],
                  ].map(([label, val, color]) => val > 0 ? (
                    <span key={label} style={{ fontSize: 10, fontFamily: 'monospace', padding: '3px 10px',
                      borderRadius: 4, background: `${color}18`, color, border: `1px solid ${color}30` }}>
                      {val} {label}
                    </span>
                  ) : null)}
                </div>
              )}

              {triageData.scores?.length === 0 && (
                <div style={{ padding: '24px', textAlign: 'center', color: '#484f58',
                  fontFamily: 'monospace', fontSize: 11, borderRadius: 8,
                  background: '#0d1117', border: '1px solid #30363d' }}>
                  Aucune donnée dans collection_timeline pour ce cas.<br />
                  Importez des collectes et parsez-les avant de lancer le triage.
                </div>
              )}
              {triageData.scores?.length > 0 && (
                <div style={{ borderRadius: 8, border: '1px solid #30363d', background: '#0d1117', overflow: 'hidden' }}>
                  {triageData.scores.map(m => {
                    const riskColors = { CRITIQUE: '#da3633', 'ÉLEVÉ': '#d97c20', MOYEN: '#c89d1d', FAIBLE: '#3fb950' };
                    const color = riskColors[m.risk_level] || '#7d8590';
                    const breakdown = m.breakdown || {};
                    return (
                      <div key={m.hostname} style={{ padding: '10px 14px', borderBottom: '1px solid #1c2a3a' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                          <span style={{ fontFamily: 'monospace', fontSize: 12, color: '#e6edf3', flex: 1 }}>{m.hostname}</span>
                          <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#484f58' }}>{m.event_count?.toLocaleString()} evt</span>
                          <span style={{ fontFamily: 'monospace', fontSize: 14, fontWeight: 700, color, width: 30, textAlign: 'right' }}>{m.score}</span>
                          <span style={{ fontSize: 9, fontFamily: 'monospace', padding: '1px 6px', borderRadius: 3,
                            background: `${color}18`, color, border: `1px solid ${color}35`, minWidth: 55, textAlign: 'center' }}>
                            {m.risk_level}
                          </span>
                        </div>
                        <div style={{ height: 4, borderRadius: 2, background: '#1c2a3a', overflow: 'hidden', marginBottom: 6 }}>
                          <div style={{ height: '100%', width: `${Math.min(m.score, 100)}%`, background: color, borderRadius: 2 }} />
                        </div>
                        {Object.keys(breakdown).length > 0 && (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                            {Object.entries(breakdown).map(([rule, pts]) => (
                              <span key={rule} style={{ fontSize: 9, fontFamily: 'monospace', padding: '1px 5px',
                                borderRadius: 3, background: '#1c2a3a', color: '#7d8590', border: '1px solid #30363d' }}>
                                +{pts} {rule.replace(/_/g, ' ')}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}

              {triageData.computed_at && (
                <div style={{ marginTop: 10, fontSize: 10, fontFamily: 'monospace', color: '#484f58', textAlign: 'right' }}>
                  Calculé le {new Date(triageData.computed_at).toLocaleString(i18n.language)}
                </div>
              )}
            </div>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" size="sm" disabled={triageRunning}
            onClick={() => setShowTriageModal(false)}>
            {t('casedetail.triage_close')}
          </Button>
          <Button variant="ghost" size="sm" icon={Activity} loading={triageRunning}
            onClick={runTriage}
            style={{ color: '#c89d1d', borderColor: 'rgba(200,157,29,0.30)', background: 'rgba(200,157,29,0.08)' }}>
            {triageRunning ? t('casedetail.triage_running') : t('common.refresh')}
          </Button>
        </Modal.Footer>
      </Modal>

      <Modal
        open={legalHoldModal === 'enable'}
        title="Activer le Legal Hold"
        onClose={() => !legalHoldSaving && setLegalHoldModal(false)}
        size="sm"
        accentColor="#da3633"
      >
        <Modal.Body>
          <div style={{ marginBottom: 14, padding: '10px 14px', borderRadius: 8,
            background: 'rgba(218,54,51,0.06)', border: '1px solid rgba(218,54,51,0.18)',
            fontSize: 12, color: 'var(--fl-muted)', lineHeight: 1.7 }}>
            Le cas <strong style={{ color: 'var(--fl-text)' }}>{c?.case_number}</strong> sera
            scellé pour procédure judiciaire. Toutes les preuves seront protégées contre
            la modification ou la suppression.
          </div>
          <label className="fl-label">Motif (optionnel)</label>
          <input
            value={legalHoldReason}
            onChange={e => setLegalHoldReason(e.target.value)}
            placeholder="Ex: Réquisition judiciaire n°2026-..., affaire pénale..."
            className="fl-input w-full"
            autoFocus
          />
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" size="sm" disabled={legalHoldSaving}
            onClick={() => { setLegalHoldModal(false); setLegalHoldReason(''); }}>
            Annuler
          </Button>
          <Button variant="danger" size="sm" icon={Lock} loading={legalHoldSaving}
            onClick={enableLegalHold}>
            Activer le Legal Hold
          </Button>
        </Modal.Footer>
      </Modal>

      <Modal
        open={legalHoldModal === 'disable'}
        title="Lever le Legal Hold"
        onClose={() => !legalHoldSaving && setLegalHoldModal(false)}
        size="sm"
        accentColor="#d97c20"
      >
        <Modal.Body>
          <div style={{ marginBottom: 14, padding: '10px 14px', borderRadius: 8,
            background: 'rgba(217,124,32,0.06)', border: '1px solid rgba(217,124,32,0.18)',
            fontSize: 12, color: 'var(--fl-muted)', lineHeight: 1.7 }}>
            Voulez-vous lever le Legal Hold sur le cas{' '}
            <strong style={{ color: 'var(--fl-text)' }}>{c?.case_number}</strong> ?<br />
            <span style={{ fontSize: 11, color: 'var(--fl-dim)' }}>
              Les preuves seront à nouveau modifiables. L'action sera enregistrée dans l'audit.
            </span>
          </div>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" size="sm" disabled={legalHoldSaving}
            onClick={() => setLegalHoldModal(false)}>
            Annuler
          </Button>
          <Button variant="ghost" size="sm" loading={legalHoldSaving}
            onClick={disableLegalHold}
            style={{ color: '#d97c20', borderColor: 'rgba(217,124,32,0.30)', background: 'rgba(217,124,32,0.08)' }}>
            Lever le Legal Hold
          </Button>
        </Modal.Footer>
      </Modal>

      {showTemplateModal && (
        <ReportTemplateModal
          onClose={() => setShowTemplateModal(false)}
          onSelect={(tpl) => { setSelectedTemplate(tpl); setShowTemplateModal(false); }}
        />
      )}

      <CaseChatPanel caseId={id} socket={socket} currentUser={user} presenceUsers={presenceUsers} />

      <AiCopilotModal
        key={`ai-${id}`}
        caseId={id}
        caseName={c?.title || ''}
        isOpen={aiOpen}
        onClose={() => setAiOpen(false)}
        socket={socket}
      />
    </div>
  );
}
