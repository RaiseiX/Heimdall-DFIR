import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useTheme } from '../utils/theme';
import { useParams, useNavigate, useOutletContext } from 'react-router-dom';
import { FolderOpen, Clock, Globe, FileDown, Star, Plus, AlertTriangle, Download, Loader2, Shield, Trash2, Cpu, Copy, RefreshCw, CalendarDays, Pencil, Wifi, Lock, Activity, FileJson, Sparkles, X, Info, BookOpen, Crosshair } from 'lucide-react';
import api, { casesAPI, evidenceAPI, iocsAPI, collectionAPI, parsersAPI, pcapAPI, legalHoldAPI } from '../utils/api';
import AiCopilotModal from '../components/ai/AiCopilotModal';
import { Button, Modal, Spinner } from '../components/ui';
import { TimePill, fmtDuration } from '../components/ui/StatusPill';
import { downloadCSV } from '../utils/csvExport';
import { fmtLocal } from '../utils/formatters';

import CaseChatPanel from '../components/chat/CaseChatPanel';
import CollectionImportPanel from '../components/collection/CollectionImportPanel';
import ParsingMonitor from '../components/collection/ParsingMonitor';
import RdpCacheGallery from '../components/collection/RdpCacheGallery';
import RightDrawer from '../components/ui/RightDrawer';
import Icon from '../components/ui/Icon';
import DetectionsTab from '../components/detections/DetectionsTab';
import MitreAttackTab from '../components/mitre/MitreAttackTab';
import { useSocket, useSocketEvent } from '../hooks/useSocket';
import MemoryUploadPanel from '../components/upload/MemoryUploadPanel';
import ReportTemplateModal from '../components/reports/ReportTemplateModal';
import ReportAiEditor from '../components/reports/ReportAiEditor';
import GlobalNetworkMapPage from './GlobalNetworkMapPage';
import NotebookPanel from '../components/notebook/NotebookPanel';
import InvestigationWorkspace from '../components/investigation/InvestigationWorkspace';

const PC = { critical: 'var(--fl-danger)', high: 'var(--fl-warn)', medium: 'var(--fl-gold)', low: 'var(--fl-ok)' };
const EC = { alert: 'var(--fl-danger)', malware: 'var(--fl-warn)', exfil: 'var(--fl-gold)', network: 'var(--fl-accent)', analysis: 'var(--fl-purple)', response: 'var(--fl-ok)', persistence: '#f472b6', other: 'var(--fl-dim)' };

const ARTIFACT_COLORS = {
  evtx: 'var(--fl-accent)', hayabusa: 'var(--fl-danger)', mft: 'var(--fl-purple)', prefetch: 'var(--fl-ok)', lnk: 'var(--fl-warn)',
  registry: 'var(--fl-pink)', amcache: 'var(--fl-gold)', appcompat: 'var(--fl-warn)', shellbags: 'var(--fl-purple)',
  jumplist: 'var(--fl-accent)', srum: 'var(--fl-danger)', wxtcmd: '#14b8a6', recycle: 'var(--fl-ok)',
  sum: 'var(--fl-pink)', bits: '#fb923c', collection: 'var(--fl-dim)',
};

function fmtSize(b) {
  if (!b) return '0 B';
  const k = 1024, s = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(b) / Math.log(k)), s.length - 1);
  return `${(b / Math.pow(k, i)).toFixed(1)} ${s[i]}`;
}

function ColorBadge({ color, children }) {
  return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-semibold" style={{ background: `color-mix(in srgb, ${color} 8%, transparent)`, color, border: `1px solid color-mix(in srgb, ${color} 19%, transparent)` }}>{children}</span>;
}

function volwebVisual(ev, progress) {
  const pct = progress ? (progress.volweb_raw_status ?? progress.pct) : null;
  const done = ev.volweb_status === 'ready' || (ev.volweb_status === 'processing' && pct === 100);
  if (done)                              return { bg: 'color-mix(in srgb, var(--fl-ok) 10%, transparent)',     fg: 'var(--fl-ok)',     bd: 'color-mix(in srgb, var(--fl-ok) 30%, transparent)' };
  if (ev.volweb_status === 'processing') return { bg: 'color-mix(in srgb, var(--fl-gold) 10%, transparent)',   fg: 'var(--fl-gold)',   bd: 'color-mix(in srgb, var(--fl-gold) 30%, transparent)' };
  if (ev.volweb_status === 'error')      return { bg: 'color-mix(in srgb, var(--fl-danger) 10%, transparent)', fg: 'var(--fl-danger)', bd: 'color-mix(in srgb, var(--fl-danger) 30%, transparent)' };
  return                                        { bg: 'color-mix(in srgb, var(--fl-purple) 10%, transparent)', fg: 'var(--fl-purple)', bd: 'color-mix(in srgb, var(--fl-purple) 30%, transparent)' };
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
    <div style={{ borderRadius: 7, border: '1px solid color-mix(in srgb, var(--fl-danger) 19%, transparent)', background: '#1a0f0f', overflow: 'hidden' }}>
      <div style={{ display: 'flex', borderBottom: '1px solid color-mix(in srgb, var(--fl-danger) 15%, transparent)' }}>
        {[['hex', 'Hex'], ['strings', 'Strings']].map(([key, label]) => (
          <button key={key} onClick={() => setActiveTab(key)} style={{ padding: '5px 14px', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'none', border: 'none', outline: 'none', cursor: 'pointer', borderBottom: `2px solid ${activeTab === key ? 'var(--fl-danger)' : 'transparent'}`, color: activeTab === key ? 'var(--fl-danger)' : 'var(--fl-muted)', marginBottom: -1, transition: 'color 0.1s' }}>{label}</button>
        ))}
        <span style={{ marginLeft: 'auto', padding: '5px 10px', fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'color-mix(in srgb, var(--fl-danger) 38%, transparent)', alignSelf: 'center' }}>SUSPECT</span>
      </div>
      <div style={{ padding: '8px 10px', maxHeight: 200, overflowY: 'auto' }}>
        {loadingPreview ? (
          <div style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)', textAlign: 'center', padding: '12px 0' }}>{t('casedetail.hex_loading')}</div>
        ) : previewError ? (
          <div style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-danger)' }}>{previewError}</div>
        ) : activeTab === 'hex' ? (
          <pre style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'color-mix(in srgb, var(--fl-danger) 56%, transparent)', margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: 1.6 }}>{hexData || t('casedetail.hex_empty')}</pre>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {(stringsData || []).filter(Boolean).map((s, i) => (<span key={i} style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-gold)', padding: '1px 0' }}>{s}</span>))}
            {(!stringsData || stringsData.filter(Boolean).length === 0) && (<span style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)' }}>{t('casedetail.no_strings')}</span>)}
          </div>
        )}
      </div>
    </div>
  );
}

function TopNavBtn({ onClick, isActive, icon: Icon, label, padding = '0 12px' }) {
  const inactiveColor = 'var(--fl-subtle)';
  return (
    <button
      onClick={onClick}
      style={{
        display: 'flex', alignItems: 'center', gap: 5, padding,
        height: 24, alignSelf: 'center', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11,
        outline: 'none', flexShrink: 0, borderRadius: 6,
        background: isActive ? 'color-mix(in srgb, var(--fl-accent) 13%, transparent)' : 'transparent',
        border: `1px solid ${isActive ? 'color-mix(in srgb, var(--fl-accent) 26%, transparent)' : 'transparent'}`,
        color: isActive ? 'var(--fl-accent)' : inactiveColor,
        cursor: 'pointer', whiteSpace: 'nowrap', transition: 'all 0.12s',
      }}
      onMouseEnter={e => { if (!isActive) { e.currentTarget.style.color = 'var(--fl-dim)'; e.currentTarget.style.background = 'var(--fl-card)'; } }}
      onMouseLeave={e => { if (!isActive) { e.currentTarget.style.color = inactiveColor; e.currentTarget.style.background = 'transparent'; } }}
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
    { id: 'evidence',       label: t('casedetail.tab_evidence'), icon: FolderOpen },
    { id: 'global-network', label: t('casedetail.tab_global_network'), icon: Globe },
    { id: 'investigation',  label: t('casedetail.tab_investigation'), icon: Crosshair },
    { id: 'notebook',       label: t('casedetail.tab_notebook'), icon: BookOpen },
  ], [t]);

  const SM = useMemo(() => ({
    active:  { l: t('casedetail.status_active'),  c: 'var(--fl-accent)' },
    pending: { l: t('casedetail.status_pending'), c: 'var(--fl-warn)' },
    closed:  { l: t('casedetail.status_closed'),  c: 'var(--fl-dim)' },
  }), [t]);

  const { tab: urlTab } = useParams();
  const tab = urlTab || 'evidence';
  const base = collectionId ? `/cases/${id}/collections/${collectionId}` : `/cases/${id}`;
  const [loading, setLoading] = useState(true);
  const [caseData, setCaseData] = useState(null);
  const [evidence, setEvidence] = useState([]);
  const [selEv, setSelEv] = useState(null);
  const [drawerEv, setDrawerEv] = useState(null); // evidence metadata quick-peek drawer

  const [generating, setGenerating] = useState(false);
  const [reportDone, setReportDone] = useState(false);
  const [showTemplateModal, setShowTemplateModal] = useState(false);
  const [selectedTemplate, setSelectedTemplate]   = useState(null);

  const [caseIOCs, setCaseIOCs] = useState([]);
  const [showAddIoc, setShowAddIoc] = useState(false);
  const [addingIoc, setAddingIoc]   = useState(false);
  const [newIoc, setNewIoc] = useState({ ioc_type: 'ip', value: '', severity: 5, is_malicious: false, description: '' });
  const [iocVerdictFilter, setIocVerdictFilter] = useState('all');
  const [iocEnriching, setIocEnriching] = useState({});
  const refetchIOCs = () => iocsAPI.list(id)
    .then(r => setCaseIOCs(Array.isArray(r.data) ? r.data : (r.data?.iocs || [])))
    .catch(() => {});
  const addIoc = async () => {
    if (!newIoc.value.trim() || addingIoc) return;
    setAddingIoc(true);
    try {
      await iocsAPI.create(id, { ...newIoc, value: newIoc.value.trim(), severity: Number(newIoc.severity) || 5 });
      setNewIoc({ ioc_type: 'ip', value: '', severity: 5, is_malicious: false, description: '' });
      setShowAddIoc(false);
      await refetchIOCs();
    } catch (e) { /* surfaced inline via disabled/retry */ }
    finally { setAddingIoc(false); }
  };
  const deleteIoc = async (iocId) => {
    if (!window.confirm(t('casedetail.ioc_delete_confirm'))) return;
    try {
      await iocsAPI.remove(iocId);
      await refetchIOCs();
    } catch (e) { /* non-fatal */ }
  };
  const handleIocEnrich = async (ioc) => {
    setIocEnriching(p => ({ ...p, [ioc.id]: true }));
    try {
      await iocsAPI.enrich(ioc.id);
      await refetchIOCs();
    } catch (e) {}
    finally { setIocEnriching(p => { const n = { ...p }; delete n[ioc.id]; return n; }); }
  };
  const [auditRows, setAuditRows] = useState([]);
  const [auditLoading, setAuditLoading] = useState(false);
  const [reportId, setReportId] = useState(null);
  const [showComposer, setShowComposer] = useState(false);
  const [reportGroups, setReportGroups] = useState(() => new Set(['mitre', 'killchain', 'findings', 'iocs', 'timeline', 'evidence']));
  const [reportNote, setReportNote] = useState('');
  const [aiEnabled, setAiEnabled] = useState(true);
  const [aiDraft, setAiDraft] = useState(null);       // editable AI narrative
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState('');
  const [showImportPanel, setShowImportPanel] = useState(false);
  const [evResultMap, setEvResultMap] = useState({});
  const { socket, socketId } = useSocket();
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
  const [triageData, setTriageData] = useState(null);
  const [triageRunning, setTriageRunning] = useState(false);
  const [showTriageModal, setShowTriageModal] = useState(false);
  const [showMemUpload, setShowMemUpload]   = useState(false);
  const [volwebSsoUrl,  setVolwebSsoUrl]    = useState(null);
  const [volwebLoading, setVolwebLoading]   = useState(false);
  const [volwebStatus,  setVolwebStatus]    = useState(null);
  const [volwebRetrying,  setVolwebRetrying]  = useState(null);
  const [volwebProgress,  setVolwebProgress]  = useState({});
  const [volwebSteps,     setVolwebSteps]     = useState({});
  const [parseProg,       setParseProg]       = useState(null);
  const [legalHoldModal, setLegalHoldModal] = useState(false);
  const [legalHoldReason, setLegalHoldReason] = useState('');
  const [aiOpen, setAiOpen] = useState(false);
  const [legalHoldSaving, setLegalHoldSaving] = useState(false);
  const [caseTimeStats, setCaseTimeStats] = useState(null);
  const [showTimeTooltip, setShowTimeTooltip] = useState(false);
  const [showActionsMenu, setShowActionsMenu] = useState(false);
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
  useSocketEvent(socket, 'volweb:step', (data) => {
    if (data.caseId !== id) return;
    setVolwebSteps(prev => ({ ...prev, [data.evidenceId]: data.message }));
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

  // Poll server-side parse progress so the monitor re-attaches after navigation
  // (the parse itself runs detached server-side and survives leaving the page).
  useEffect(() => {
    if (!id || tab !== 'evidence') { setParseProg(null); return; }
    let alive = true;
    const poll = () => collectionAPI.parseProgress(id)
      .then(r => { if (alive) setParseProg(r.data?.active ? r.data : null); })
      .catch(() => {});
    poll();
    const timer = setInterval(poll, 2500);
    return () => { alive = false; clearInterval(timer); };
  }, [id, tab]);

  // Case audit log — fetched when the Audit tab is opened.
  useEffect(() => {
    if (tab !== 'audit' || !id) return;
    let alive = true;
    setAuditLoading(true);
    casesAPI.audit(id, { limit: 200 })
      .then(r => { if (alive) setAuditRows(r.data?.rows || []); })
      .catch(() => { if (alive) setAuditRows([]); })
      .finally(() => { if (alive) setAuditLoading(false); });
    return () => { alive = false; };
  }, [id, tab]);


  useEffect(() => {
    let cancelled = false;
    console.log('[CaseDetail] useEffect triggered, id =', id);
    setLoading(true);
    setCaseData(null);
    setEvidence([]);
    setCaseIOCs([]);

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
          const trRes = await casesAPI.getTriage(id);
          if (!cancelled && trRes.data) setTriageData(trRes.data);
        } catch {}

      } catch (err) {
        if (cancelled) return;
        console.error('[CaseDetail] API FAILED for id', id, '→', err?.response?.status, err?.message);
        setCaseData(null);
        setEvidence([]);
        setCaseIOCs([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    loadCase();
    // Load time stats silently
    casesAPI.timeStats(id).then(r => setCaseTimeStats(r.data)).catch(() => {});
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


  const c = caseData;

  if (loading) return (
    <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>
      {[0,1,2,3].map(i => (
        <div key={i} className="fl-skeleton" style={{ height: 56, borderRadius: 8, background: 'var(--fl-card)' }} />
      ))}
    </div>
  );

  if (!c) {
    return (
      <div className="p-6 text-center" style={{ paddingTop: 80 }}>
        <div className="text-lg font-bold mb-2" style={{ color: 'var(--fl-text)' }}>{t('casedetail.not_found')}</div>
        <div className="text-sm mb-4" style={{ color: 'var(--fl-dim)' }}>{t('casedetail.not_found_sub', { id })}</div>
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

  const exportRGPD = async () => {
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
  };

  const toggleHL = (eid) => setEvidence(prev => prev.map(e => e.id === eid ? { ...e, is_highlighted: !e.is_highlighted } : e));
  const highlighted = evidence.filter(e => e.is_highlighted);






  const GROUP_SECTIONS = {
    mitre: ['mitre'],
    killchain: ['killchain', 'workflow'],
    findings: ['hayabusa', 'sigma', 'yara'],
    iocs: ['iocs'],
    timeline: ['timeline'],
    evidence: ['evidence', 'custody'],
  };

  const generateAiDraft = async () => {
    setAiLoading(true); setAiError('');
    try {
      const { reportsAPI: rAPI } = await import('../utils/api');
      // Pass the analyst's note so the AI grounds its analysis on it (+ the case's
      // bookmarks/pins/notes are pulled server-side).
      const { data } = await rAPI.aiDraft(c.id, reportNote.trim() ? { notes: reportNote.trim() } : {});
      setAiDraft(data.narrative || {});
    } catch (e) {
      setAiError(e?.response?.data?.error || t('casedetail.ai_generation_failed'));
    }
    setAiLoading(false);
  };

  const generateReport = async () => {
    setGenerating(true);
    try {
      const { reportsAPI: rAPI } = await import('../utils/api');
      let opts;
      if (selectedTemplate?.id) {
        opts = { templateId: selectedTemplate.id };
      } else {
        // Analyst-chosen sections (executive summary is always included) — not defaulted to "everything".
        opts = { sections: ['summary', ...[...reportGroups].flatMap(g => GROUP_SECTIONS[g] || [])] };
      }
      if (reportNote.trim()) opts.notes = reportNote.trim();
      // AI: use the analyst-edited draft if present; otherwise let the backend generate it (or disable).
      opts.use_ai = aiEnabled;
      if (aiEnabled && aiDraft && Object.keys(aiDraft).length) opts.ai_narrative = aiDraft;
      const { data } = await rAPI.generate(c.id, opts);
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
        link.download = `${t('casedetail.report_filename_prefix')}_${c.case_number}.pdf`;
        link.click();
        window.URL.revokeObjectURL(url);
        return;
      } catch {}
    }
    const w = window.open('', '_blank');
    if (w) {
      function esc(s) {
        return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
      }
      function fmtUtc(ts) {
        if (!ts) return '—';
        try {
          const d = new Date(ts);
          const p = (n, l = 2) => String(n).padStart(l, '0');
          return `${d.getUTCFullYear()}-${p(d.getUTCMonth()+1)}-${p(d.getUTCDate())} `
               + `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} UTC`;
        } catch { return String(ts); }
      }
      w.document.write('<html><head><title>' + esc(t('casedetail.print_report_title', { caseNumber: c.case_number })) + '</title><style>body{font-family:sans-serif;padding:40px;color:#333}h1{color:#3a6aaa}table{width:100%;border-collapse:collapse;margin:20px 0}td,th{border:1px solid #ddd;padding:8px;text-align:left}th{background:#f5f5f5}</style></head><body>');
      w.document.write('<h1>' + esc(t('casedetail.print_report_h1')) + '</h1><p><strong>' + esc(c.case_number) + '</strong> — ' + esc(c.title) + '</p><p>' + esc(t('casedetail.print_status')) + ': ' + esc(c.status) + ' | ' + esc(t('casedetail.print_priority')) + ': ' + esc(c.priority) + ' | ' + esc(t('casedetail.print_investigator')) + ': ' + esc(c.investigator_name || '') + '</p><p>' + esc(c.description) + '</p><hr>');
      w.document.write('<h2>' + esc(t('casedetail.print_evidence_count', { count: evidence.length })) + '</h2><table><tr><th>' + esc(t('casedetail.col_name')) + '</th><th>' + esc(t('casedetail.col_type')) + '</th><th>SHA256</th><th>' + esc(t('casedetail.col_highlighted')) + '</th></tr>');
      evidence.forEach(function(e) { w.document.write('<tr><td>' + esc(e.name) + '</td><td>' + esc(e.evidence_type) + '</td><td style="font-family:monospace;font-size:10px">' + esc((e.hash_sha256 || '').substring(0,24)) + '...</td><td>' + (e.is_highlighted ? '★' : '') + '</td></tr>'); });
      w.document.write('</table><h2>' + esc(t('casedetail.print_iocs_count', { count: caseIOCs.length })) + '</h2><table><tr><th>' + esc(t('casedetail.col_type')) + '</th><th>' + esc(t('casedetail.col_value')) + '</th><th>' + esc(t('casedetail.col_severity')) + '</th><th>' + esc(t('casedetail.col_malicious')) + '</th></tr>');
      caseIOCs.forEach(function(i) { w.document.write('<tr><td>' + esc(i.ioc_type) + '</td><td style="font-family:monospace">' + esc(i.value) + '</td><td>' + esc(String(i.severity)) + '/10</td><td>' + (i.is_malicious ? '⚠ ' + esc(t('common.yes').toUpperCase()) : esc(t('common.no'))) + '</td></tr>'); });
      w.document.write('</table><hr><p style="color:#999;font-size:12px">' + esc(t('casedetail.print_generated_by', { date: fmtUtc(new Date().toISOString()) })) + '</p></body></html>');
      w.document.close();
      w.print();
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>

      {!shellCtx.insideCollectionLayout && (
      <div style={{ position: 'sticky', top: 36, zIndex: 100, flexShrink: 0 }}>

        {/* ── Tier 1 — Cockpit state strip: status chip + SLA / metadata ─── */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8,
          padding: '0 14px', height: 30,
          background: 'var(--fl-panel)', borderBottom: '1px solid var(--fl-sep)',
          fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
        }}>
          {/* Status — single clickable source of truth (no longer duplicated in the CaseShell strip) */}
          <button onClick={() => setStatusModal('_pick')} title={t('casedetail.change_status')} style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '2px 9px', borderRadius: 5, cursor: 'pointer', background: `color-mix(in srgb, ${SM[c.status]?.c || 'var(--fl-dim)'} 11%, transparent)`, color: SM[c.status]?.c || 'var(--fl-dim)', border: `1px solid color-mix(in srgb, ${SM[c.status]?.c || 'var(--fl-dim)'} 26%, transparent)`, fontSize: 10.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 600, flexShrink: 0 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'currentColor', flexShrink: 0 }} />
            {SM[c.status]?.l || c.status}<span style={{ fontSize: 8, opacity: 0.6 }}>▾</span>
          </button>

          <span style={{ width: 1, height: 14, background: 'var(--fl-sep)', flexShrink: 0 }} />

          {/* Metadata: opened · investigator · deadline · time — separated by hairline dots */}
          <Clock size={10} style={{ color: 'var(--fl-subtle)', flexShrink: 0 }} />
          <span style={{ fontSize: 10, color: 'var(--fl-subtle)', whiteSpace: 'nowrap', flexShrink: 0 }}>{t('casedetail.opened_on', { date: new Date(c.created_at).toLocaleDateString(i18n.language) })}</span>
          {c.investigator_name && (
            <><span style={{ color: 'var(--fl-sep)', fontSize: 11 }}>·</span>
            <span style={{ fontSize: 10, color: 'var(--fl-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 160 }}>{c.investigator_name}</span></>
          )}
          <span style={{ color: 'var(--fl-sep)', fontSize: 11 }}>·</span>
          {editDeadline ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
              <input type="datetime-local" value={deadlineVal} onChange={e => setDeadlineVal(e.target.value)} className="fl-input" style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '0 4px', height: 20 }} autoFocus />
              <Button variant="primary" size="xs" loading={deadlineSaving} onClick={saveDeadline}>{deadlineSaving ? '…' : 'OK'}</Button>
              <Button variant="secondary" size="xs" onClick={() => setEditDeadline(false)}>✕</Button>
            </div>
          ) : (
            <button onClick={() => { setDeadlineVal(c.report_deadline ? c.report_deadline.slice(0,16) : ''); setEditDeadline(true); }} title={t('casedetail.edit_deadline')} style={{ display: 'flex', alignItems: 'center', gap: 3, background: 'none', border: 'none', cursor: 'pointer', padding: '1px 4px', borderRadius: 3, flexShrink: 0, color: c.report_deadline && new Date(c.report_deadline) < new Date(Date.now() + 48*3600*1000) ? 'var(--fl-danger)' : 'var(--fl-muted)' }}>
              <CalendarDays size={9} />
              <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{c.report_deadline ? new Date(c.report_deadline).toLocaleDateString(i18n.language) : t('casedetail.deadline')}</span>
              <Pencil size={7} style={{ opacity: 0.4 }} />
            </button>
          )}
          {caseTimeStats && caseTimeStats.grand_total_seconds > 0 && (
            <><span style={{ color: 'var(--fl-sep)', fontSize: 11 }}>·</span>
            <div style={{ position: 'relative', flexShrink: 0 }}>
              <button onMouseEnter={() => setShowTimeTooltip(true)} onMouseLeave={() => setShowTimeTooltip(false)} style={{ background: 'none', border: 'none', cursor: 'default', padding: 0 }}>
                <TimePill totalSeconds={caseTimeStats.grand_total_seconds} analystCount={caseTimeStats.analysts?.length || 0} />
              </button>
              {showTimeTooltip && caseTimeStats.analysts?.length > 0 && (
                <div style={{ position: 'absolute', left: 0, top: '100%', marginTop: 6, zIndex: 500, background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 8, padding: '8px 12px', minWidth: 200, boxShadow: 'var(--fl-shadow-lg)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                  <div style={{ fontSize: 9, color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>{t('casedetail.analytic_time')}</div>
                  {caseTimeStats.analysts.map(a => (
                    <div key={a.id} style={{ display: 'flex', justifyContent: 'space-between', gap: 12, fontSize: 11, padding: '2px 0', color: 'var(--fl-dim)' }}>
                      <span>{a.full_name || a.username}</span>
                      <span style={{ color: 'var(--fl-text)', fontWeight: 600 }}>{fmtDuration(a.total_seconds)}</span>
                    </div>
                  ))}
                  <div style={{ borderTop: '1px solid var(--fl-sep)', marginTop: 5, paddingTop: 5, display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
                    <span style={{ color: 'var(--fl-subtle)' }}>{t('casedetail.total')}</span>
                    <span style={{ color: 'var(--fl-accent)', fontWeight: 700 }}>{fmtDuration(caseTimeStats.grand_total_seconds)}</span>
                  </div>
                </div>
              )}
            </div></>
          )}

          <span style={{ flex: 1, minWidth: 8 }} />

          {/* Live analyst presence — pushed to the right edge of the cockpit strip */}
          {presenceUsers.length > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 2, flexShrink: 0 }} title={presenceUsers.map(u => u.full_name || u.username).join(', ')}>
              {presenceUsers.slice(0, 4).map((u, i) => {
                const col = ['var(--fl-accent)', 'var(--fl-ok)', 'var(--fl-warn)', 'var(--fl-purple)'][i % 4];
                const ini = u.full_name ? u.full_name.split(' ').map(p => p[0]).join('').substring(0, 2).toUpperCase() : u.username?.substring(0, 2).toUpperCase() || '?';
                return (
                  <div key={u.id + i} title={u.full_name || u.username} style={{ width: 18, height: 18, borderRadius: '50%', background: `color-mix(in srgb, ${col} 13%, transparent)`, border: `1px solid color-mix(in srgb, ${col} 38%, transparent)`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 7, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, color: col, marginLeft: i > 0 ? -5 : 0, zIndex: 4 - i }}>
                    {ini}
                  </div>
                );
              })}
              {presenceUsers.length > 4 && <div style={{ width: 18, height: 18, borderRadius: '50%', background: 'var(--fl-card)', border: '1px solid var(--fl-sep)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 7, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-subtle)', marginLeft: -5 }}>+{presenceUsers.length - 4}</div>}
              <div style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--fl-ok)', marginLeft: 3 }} title={t('casedetail.online')} />
            </div>
          )}
        </div>

        {/* ── Row 2 — Navigation tabs + compact action buttons ─── */}
        <div style={{
          display: 'flex', alignItems: 'stretch', height: 32, padding: '0 14px',
          background: 'var(--fl-bg)',
          borderBottom: `1px solid ${PC[c.priority] ? PC[c.priority] + '35' : 'var(--fl-border)'}`,
        }}>
        <div style={{ display: 'flex', alignItems: 'stretch', flex: 1, overflow: 'auto', scrollbarWidth: 'none' }}>

          <TopNavBtn onClick={() => navigate(`/cases/${id}/evidence`)} padding="0 12px"
            isActive={tab === 'evidence' && !selEv} icon={FolderOpen}
            label={<>
              {t('casedetail.tab_evidence')}
              {evidence.length > 0 && (
                <span style={{ marginLeft: 4, padding: '0px 5px', borderRadius: 8, fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, background: 'var(--fl-card)', color: 'var(--fl-accent)', border: '1px solid var(--fl-border)' }}>
                  {evidence.length}
                </span>
              )}
            </>}
          />

          {/* Evidence breadcrumb — only when evidence is expanded */}
          {selEv && !shellCtx.insideCollectionLayout && (
            <>
              <span style={{ color: 'var(--fl-border)', fontSize: 13, alignSelf: 'center', margin: '0 1px', flexShrink: 0 }}>›</span>
              <div style={{
                display: 'flex', alignItems: 'center', gap: 5, padding: '0 8px',
                fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: 'var(--fl-dim)',
                whiteSpace: 'nowrap', maxWidth: 180, overflow: 'hidden',
                textOverflow: 'ellipsis', flexShrink: 0, alignSelf: 'center',
                height: 24, borderRadius: 6,
                background: tab === 'evidence' ? 'color-mix(in srgb, var(--fl-accent) 8%, transparent)' : 'transparent',
              }}>
                <FolderOpen size={9} style={{ flexShrink: 0 }} />
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{selEv.name}</span>
              </div>
            </>
          )}

          {/* All case tabs — always visible */}
          {!shellCtx.insideCollectionLayout && (() => {
            const evResult = selEv ? evResultMap[selEv.name] : null;
            const resultId = evResult?.resultId;
            const isMemory = selEv && (
              selEv.evidence_type === 'memory' ||
              /\.(raw|mem|vmem|lime|dmp)$/i.test(selEv.original_filename || selEv.name || '')
            );
            return (
              <>
                <span style={{ color: 'var(--fl-border)', fontSize: 13, alignSelf: 'center', margin: '0 1px', flexShrink: 0 }}>›</span>
                {TABS.filter(tb => {
                  if (tb.id === 'evidence') return false;
                  if (isMemory) return ['cyberchef', 'audit'].includes(tb.id);
                  return true;
                }).map(tb => {
                  const Icon = tb.icon;
                  const isActive = tab === tb.id;
                  const isTimeline = tb.id === 'timeline';
                  const hasResult = isTimeline && Boolean(resultId);
                  return (
                    <button key={tb.id}
                      title={!isActive ? tb.label : undefined}
                      onClick={() => navigate(`${base}/${tb.id}`)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: isActive ? 4 : 5,
                        padding: '0 10px', height: 24, alignSelf: 'center', flexShrink: 0,
                        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10,
                        outline: 'none', borderRadius: 6,
                        background: isActive ? 'color-mix(in srgb, var(--fl-accent) 13%, transparent)' : 'transparent',
                        border: `1px solid ${isActive ? 'color-mix(in srgb, var(--fl-accent) 26%, transparent)' : 'transparent'}`,
                        color: isActive ? 'var(--fl-accent)' : hasResult ? 'var(--fl-accent)' : 'var(--fl-muted)',
                        cursor: 'pointer', whiteSpace: 'nowrap', transition: 'all 0.12s',
                      }}
                      onMouseEnter={e => { if (!isActive) { e.currentTarget.style.color = hasResult ? 'var(--fl-accent)' : 'var(--fl-dim)'; e.currentTarget.style.background = 'var(--fl-card)'; }}}
                      onMouseLeave={e => { if (!isActive) { e.currentTarget.style.color = hasResult ? 'var(--fl-accent)' : 'var(--fl-muted)'; e.currentTarget.style.background = 'transparent'; }}}>
                      <Icon size={isActive ? 10 : 11} />
                      {isActive && tb.label}
                      {isActive && tb.id === 'iocs' && caseIOCs.length > 0 && <span style={{ marginLeft: 3, padding: '0 4px', borderRadius: 8, fontSize: 9, fontWeight: 700, background: 'var(--fl-card)', color: caseIOCs.some(i => i.is_malicious) ? 'var(--fl-warn)' : 'var(--fl-dim)', border: '1px solid var(--fl-border)' }}>{caseIOCs.length}</span>}
                      {!isActive && tb.id === 'iocs' && caseIOCs.length > 0 && <span style={{ width: 4, height: 4, borderRadius: '50%', background: caseIOCs.some(i => i.is_malicious) ? 'var(--fl-warn)' : 'var(--fl-accent)', display: 'inline-block', marginLeft: 2 }} />}
                      {hasResult && <span style={{ width: 4, height: 4, borderRadius: '50%', background: 'var(--fl-ok)', display: 'inline-block', marginLeft: isActive ? 1 : 2 }} />}
                    </button>
                  );
                })}
              </>
            );
          })()}
        </div>

        {/* Compact action buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 3, flexShrink: 0, paddingLeft: 8, borderLeft: '1px solid var(--fl-sep)', marginLeft: 4 }}>
          <Button
            variant="ghost" size="xs"
            icon={volwebLoading ? undefined : Cpu} loading={volwebLoading}
            onClick={() => {
              const isLinked = volwebStatus?.linked || evidence.some(ev => ev.volweb_status === 'ready' || ev.volweb_status === 'processing');
              if (isLinked) { openVolWeb(id); } else { setShowMemUpload(v => !v); }
            }}
            title={t('casedetail.volweb_title')}
            style={{ color: 'var(--fl-purple)', borderColor: 'color-mix(in srgb, var(--fl-purple) 30%, transparent)', background: 'color-mix(in srgb, var(--fl-purple) 10%, transparent)' }}
          >
            RAM
          </Button>
          <Button
            variant="ghost" size="xs"
            icon={triageRunning ? undefined : Activity} loading={triageRunning}
            onClick={() => { setShowTriageModal(true); if (!triageRunning) runTriage(); }}
            title={t('casedetail.triage_title')}
            style={{ color: 'var(--fl-gold)', borderColor: 'color-mix(in srgb, var(--fl-gold) 30%, transparent)', background: 'color-mix(in srgb, var(--fl-gold) 9%, transparent)' }}
          >
            TRIAGE
          </Button>
          <Button
            variant="ghost" size="xs" icon={Sparkles}
            onClick={() => setAiOpen(v => !v)}
            title={t('casedetail.ai_copilot_title')}
            style={{ color: 'var(--fl-accent)', borderColor: 'color-mix(in srgb, var(--fl-accent) 30%, transparent)', background: aiOpen ? 'color-mix(in srgb, var(--fl-accent) 18%, transparent)' : 'color-mix(in srgb, var(--fl-accent) 8%, transparent)' }}
          >
            IA
          </Button>
          {user?.role === 'admin' && c.legal_hold && (
            <span title={t('casedetail.legal_hold_active_title')} style={{ display: 'inline-flex', alignItems: 'center', gap: 3, fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, padding: '1px 6px', borderRadius: 3, background: 'color-mix(in srgb, var(--fl-danger) 10%, transparent)', color: 'var(--fl-danger)', border: '1px solid color-mix(in srgb, var(--fl-danger) 30%, transparent)' }}>
              <Lock size={8} /> HOLD
            </span>
          )}
          <div style={{ position: 'relative' }}>
            {showActionsMenu && <div style={{ position: 'fixed', inset: 0, zIndex: 599 }} onClick={() => setShowActionsMenu(false)} />}
            <button
              onClick={() => setShowActionsMenu(v => !v)}
              title={t('casedetail.more_actions')}
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 26, height: 26, borderRadius: 3, background: showActionsMenu ? 'var(--fl-card)' : 'transparent', border: `1px solid ${showActionsMenu ? 'var(--fl-border)' : 'var(--fl-sep)'}`, color: 'var(--fl-muted)', cursor: 'pointer', fontSize: 14, letterSpacing: 1 }}
            >···</button>
            {showActionsMenu && (
              <div style={{ position: 'absolute', right: 0, top: '100%', marginTop: 4, zIndex: 600, background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 8, padding: 4, minWidth: 180, boxShadow: 'var(--fl-shadow-lg)' }}>
                {user?.role === 'admin' && (c.legal_hold ? (
                  <>
                    <button onClick={() => { setShowActionsMenu(false); downloadManifest(); }} style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%', padding: '5px 10px', background: 'none', border: 'none', borderRadius: 4, cursor: 'pointer', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-purple)' }}><FileJson size={11} />{t('casedetail.manifest')}</button>
                    <button onClick={() => { setShowActionsMenu(false); setLegalHoldModal('disable'); }} style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%', padding: '5px 10px', background: 'none', border: 'none', borderRadius: 4, cursor: 'pointer', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-warn)' }}><Lock size={11} />{t('casedetail.lift_hold')}</button>
                  </>
                ) : (
                  <button onClick={() => { setShowActionsMenu(false); setLegalHoldModal('enable'); }} style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%', padding: '5px 10px', background: 'none', border: 'none', borderRadius: 4, cursor: 'pointer', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)' }}><Lock size={11} />{t('casedetail.legal_hold')}</button>
                ))}
                <button onClick={() => { setShowActionsMenu(false); exportRGPD(); }} style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%', padding: '5px 10px', background: 'none', border: 'none', borderRadius: 4, cursor: 'pointer', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)' }}><Lock size={11} />{t('casedetail.export_rgpd')}</button>
                {user?.role === 'admin' && (
                  <>
                    <div style={{ height: 1, background: 'var(--fl-sep)', margin: '3px 6px' }} />
                    <button onClick={() => { setShowActionsMenu(false); setShowHardDelete(true); setHardDeleteConfirm(''); }} style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%', padding: '5px 10px', background: 'none', border: 'none', borderRadius: 4, cursor: 'pointer', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-danger)' }}><Trash2 size={11} />{t('casedetail.destroy')}</button>
                  </>
                )}
              </div>
            )}
          </div>
        </div>
        </div>

      </div>
      )}

      <div style={{ flex: 1, overflow: tab === 'global-network' ? 'hidden' : 'auto', padding: tab === 'global-network' ? 0 : '12px 16px', position: 'relative' }}>

      <div key={tab} style={{ animation: 'fl-fade 120ms var(--ease, ease)' }}>

      {tab === 'global-network' && (
        <div style={{ position: 'absolute', inset: 0 }}>
          <GlobalNetworkMapPage />
        </div>
      )}

      {tab === 'detections' && <DetectionsTab caseId={id} />}

      {tab === 'mitre' && <MitreAttackTab caseId={id} />}

      {tab === 'investigation' && <InvestigationWorkspace caseId={id} />}

      {tab === 'notebook' && <NotebookPanel caseId={id} />}

      {tab === 'audit' && (
        <div style={{ maxWidth: 1100, margin: '0 auto' }}>
          <div className="flex items-center mb-4" style={{ gap: 8 }}>
            <Icon name="ScrollText" size={14} style={{ color: 'var(--fl-accent)' }} />
            <span style={{ fontSize: 11, fontFamily: 'var(--f-mono, monospace)', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-dim)' }}>{t('casedetail.audit_log')}</span>
            {auditRows.length > 0 && <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, monospace)', padding: '1px 6px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-accent) 9%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 19%, transparent)' }}>{auditRows.length}</span>}
          </div>
          {auditLoading ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {[0,1,2,3,4].map(i => <div key={i} className="fl-skeleton" style={{ height: 40, borderRadius: 6, background: 'var(--fl-card)' }} />)}
            </div>
          ) : auditRows.length === 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '48px 16px', gap: 8 }}>
              <Icon name="ScrollText" size={22} style={{ color: 'var(--fl-border)' }} />
              <span style={{ fontSize: 12, fontFamily: 'var(--f-mono, monospace)', color: 'var(--fl-muted)' }}>{t('casedetail.audit_empty')}</span>
            </div>
          ) : (
            <div style={{ border: '1px solid var(--fl-border)', borderRadius: 8, overflow: 'hidden' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--f-ui, sans-serif)' }}>
                <thead>
                  <tr style={{ background: 'var(--fl-bg)', borderBottom: '1px solid var(--fl-border)' }}>
                    {[[t('casedetail.col_date'), 150], [t('casedetail.col_actor'), 150], [t('casedetail.col_action'), null], [t('casedetail.col_entity'), 120], ['IP', 120]].map(([l, w]) => (
                      <th key={l} style={{ textAlign: 'left', padding: '7px 10px', width: w || undefined, fontSize: 9.5, fontFamily: 'var(--f-mono, monospace)', textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-muted)', fontWeight: 600, whiteSpace: 'nowrap' }}>{l}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {auditRows.map((r, i) => {
                    const td = { padding: '0 10px', height: 38, borderBottom: '1px solid var(--fl-border2)', verticalAlign: 'middle' };
                    return (
                      <tr key={r.id || i}>
                        <td style={{ ...td, fontSize: 10.5, fontFamily: 'var(--f-mono, monospace)', color: 'var(--fl-dim)', whiteSpace: 'nowrap' }}>{r.created_at ? new Date(r.created_at).toLocaleString(i18n.language) : '—'}</td>
                        <td style={{ ...td, fontSize: 11, color: 'var(--fl-text)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 150 }}>{r.user_name || r.username || t('dashboard.system_actor')}</td>
                        <td style={{ ...td, fontSize: 11, fontFamily: 'var(--f-mono, monospace)', color: 'var(--fl-accent)' }}>{(r.action || '').replace(/_/g, ' ')}</td>
                        <td style={{ ...td, fontSize: 11, fontFamily: 'var(--f-mono, monospace)', color: 'var(--fl-muted)' }}>{(r.entity_type || '').replace(/_/g, ' ') || '—'}</td>
                        <td style={{ ...td, fontSize: 10.5, fontFamily: 'var(--f-mono, monospace)', color: 'var(--fl-subtle)', whiteSpace: 'nowrap' }}>{r.ip_address || '—'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {tab === 'iocs' && (() => {
        const iocMalCount    = caseIOCs.filter(i => i.is_malicious === true).length;
        const iocSuspectCount= caseIOCs.filter(i => i.is_malicious == null).length;
        const iocBenignCount = caseIOCs.filter(i => i.is_malicious === false).length;
        const VERDICT_TABS = [
          { key: 'all',       label: t('common.all'),            count: caseIOCs.length },
          { key: 'malicious', label: t('iocs.tab_malicious'),    count: iocMalCount,     color: 'var(--fl-danger)' },
          { key: 'suspect',   label: t('iocs.tab_suspect'),      count: iocSuspectCount, color: 'var(--fl-gold)' },
          { key: 'benign',    label: t('iocs.tab_benign'),       count: iocBenignCount,  color: 'var(--fl-ok)' },
        ];
        const visibleIOCs = caseIOCs.filter(i =>
          iocVerdictFilter === 'all'      ? true
          : iocVerdictFilter === 'malicious' ? i.is_malicious === true
          : iocVerdictFilter === 'benign'    ? i.is_malicious === false
          : i.is_malicious == null
        );
        const SEV_COLOR = s => s >= 8 ? 'var(--fl-danger)' : s >= 6 ? 'var(--fl-warn)' : s >= 4 ? 'var(--fl-gold)' : 'var(--fl-ok)';
        const TYPE_LABEL = { ip: 'IP', domain: 'Domain', url: 'URL', email: 'Email', md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', filename: 'File', registry: 'Registry', other: 'Other' };

        return (
          <div style={{ maxWidth: 1200, margin: '0 auto' }}>

            {/* ── header row ── */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16, gap: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 11, fontFamily: 'var(--f-mono, monospace)', textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-dim)', fontWeight: 700 }}>IOCs</span>
                <span style={{ fontSize: 10.5, fontFamily: 'var(--f-mono, monospace)', padding: '1px 7px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-accent) 9%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 19%, transparent)' }}>{caseIOCs.length}</span>
              </div>
              <button onClick={() => setShowAddIoc(v => !v)}
                style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '5px 12px', borderRadius: 6, cursor: 'pointer', fontFamily: 'var(--f-mono, monospace)', fontSize: 11, fontWeight: 600,
                  background: showAddIoc ? 'var(--fl-card)' : 'var(--fl-accent)', color: showAddIoc ? 'var(--fl-dim)' : '#fff', border: `1px solid ${showAddIoc ? 'var(--fl-border)' : 'var(--fl-accent)'}` }}>
                {showAddIoc ? <><X size={12} /> {t('common.cancel')}</> : <><Plus size={12} /> {t('casedetail.add_ioc_long')}</>}
              </button>
            </div>

            {/* ── add form ── */}
            {showAddIoc && (
              <div style={{ marginBottom: 16, padding: 14, border: '1px solid var(--fl-border)', borderRadius: 8, background: 'var(--fl-panel)', display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
                <select value={newIoc.ioc_type} onChange={e => setNewIoc(s => ({ ...s, ioc_type: e.target.value }))}
                  style={{ padding: '7px 9px', borderRadius: 6, background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', color: 'var(--fl-text)', fontFamily: 'var(--f-mono, monospace)', fontSize: 11.5, cursor: 'pointer' }}>
                  {['ip', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256', 'filename', 'registry', 'other'].map(o => <option key={o} value={o}>{o}</option>)}
                </select>
                <input autoFocus value={newIoc.value} onChange={e => setNewIoc(s => ({ ...s, value: e.target.value }))} placeholder={t('casedetail.ioc_value_ph')}
                  onKeyDown={e => { if (e.key === 'Enter') addIoc(); }}
                  style={{ flex: '1 1 240px', minWidth: 200, padding: '7px 10px', borderRadius: 6, background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', color: 'var(--fl-text)', fontFamily: 'var(--f-mono, monospace)', fontSize: 12, outline: 'none' }} />
                <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <span style={{ fontSize: 10.5, fontFamily: 'var(--f-mono, monospace)', color: 'var(--fl-muted)' }}>{t('casedetail.severity_abbr')}</span>
                  <input type="number" min="1" max="10" value={newIoc.severity} onChange={e => setNewIoc(s => ({ ...s, severity: e.target.value }))}
                    style={{ width: 54, padding: '7px 8px', borderRadius: 6, textAlign: 'right', background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', color: 'var(--fl-text)', fontFamily: 'var(--f-mono, monospace)', fontSize: 12 }} />
                </div>
                <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11.5, fontFamily: 'var(--f-mono, monospace)', color: 'var(--fl-dim)', cursor: 'pointer' }}>
                  <input type="checkbox" checked={newIoc.is_malicious} onChange={e => setNewIoc(s => ({ ...s, is_malicious: e.target.checked }))} style={{ accentColor: 'var(--fl-danger)' }} />
                  {t('casedetail.malicious')}
                </label>
                <input value={newIoc.description} onChange={e => setNewIoc(s => ({ ...s, description: e.target.value }))} placeholder={t('casedetail.description_optional_ph')}
                  style={{ flex: '1 1 180px', minWidth: 140, padding: '7px 10px', borderRadius: 6, background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', color: 'var(--fl-text)', fontFamily: 'var(--f-ui, sans-serif)', fontSize: 12, outline: 'none' }} />
                <button onClick={addIoc} disabled={!newIoc.value.trim() || addingIoc}
                  style={{ padding: '7px 14px', borderRadius: 6, cursor: !newIoc.value.trim() || addingIoc ? 'not-allowed' : 'pointer', fontFamily: 'var(--f-mono, monospace)', fontSize: 11.5, fontWeight: 600,
                    background: !newIoc.value.trim() ? 'var(--fl-card)' : 'color-mix(in srgb, var(--fl-ok) 12%, transparent)', color: !newIoc.value.trim() ? 'var(--fl-muted)' : 'var(--fl-ok)', border: `1px solid ${!newIoc.value.trim() ? 'var(--fl-border)' : 'color-mix(in srgb, var(--fl-ok) 25%, transparent)'}` }}>
                  {addingIoc ? t('casedetail.adding') : t('common.add')}
                </button>
              </div>
            )}

            {/* ── verdict tabs ── */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 2, marginBottom: 10, borderBottom: '1px solid var(--fl-border2)' }}>
              {VERDICT_TABS.map(tb => {
                const active = iocVerdictFilter === tb.key;
                return (
                  <button key={tb.key} onClick={() => setIocVerdictFilter(tb.key)}
                    style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '7px 11px', background: 'none', border: 'none', cursor: 'pointer',
                      fontFamily: 'var(--f-mono, monospace)', fontSize: 11.5, fontWeight: 600,
                      color: active ? 'var(--fl-text)' : 'var(--fl-muted)',
                      borderBottom: `2px solid ${active ? 'var(--fl-accent)' : 'transparent'}`, marginBottom: -1 }}>
                    {tb.color && <span style={{ width: 6, height: 6, borderRadius: 2, background: tb.color, flexShrink: 0 }} />}
                    {tb.label}
                    <span style={{ fontSize: 10, color: active ? 'var(--fl-dim)' : 'var(--fl-subtle)', fontFeatureSettings: '"tnum"' }}>{tb.count}</span>
                  </button>
                );
              })}
            </div>

            {/* ── enrichment hint ── */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 14, fontSize: 11, fontFamily: 'var(--f-mono, monospace)', color: 'var(--fl-muted)' }}>
              <Info size={11} style={{ flexShrink: 0, color: 'var(--fl-subtle)' }} />
              {t('iocs.enrichment_hint')} <code style={{ color: 'var(--fl-dim)' }}>.env</code>
            </div>

            {/* ── table ── */}
            {caseIOCs.length === 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '64px 16px', gap: 12 }}>
                <div style={{
                  width: 44, height: 44, borderRadius: 12,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  background: 'var(--fl-raised)', border: '1px solid var(--fl-border)',
                }}>
                  <Crosshair size={20} style={{ color: 'var(--fl-muted)' }} strokeWidth={1.5} />
                </div>
                <span style={{ fontFamily: 'var(--f-display, var(--f-sans))', fontSize: 14, fontWeight: 700, color: 'var(--fl-text)', letterSpacing: '-0.01em' }}>{t('casedetail.no_iocs')}</span>
              </div>
            ) : (
              <div className="fl-card" style={{ overflow: 'hidden', padding: 0 }}>
                <table className="fl-table fl-ioc-table">
                  <thead>
                    <tr>
                      <th style={{ width: 58 }}>{t('iocs.severity_short')}</th>
                      <th>{t('iocs.type_value')}</th>
                      <th>Description</th>
                      <th style={{ width: 170 }}>{t('iocs.enrichment')}</th>
                      <th style={{ width: 160 }}>Tags</th>
                      <th style={{ width: 112 }}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleIOCs.map(ioc => {
                      const sev = Number(ioc.severity) || 5;
                      const sevColor = SEV_COLOR(sev);
                      const isEnriching = iocEnriching[ioc.id];
                      return (
                        <tr key={ioc.id}>
                          {/* SEV — square badge + severity gauge (severity is a signal) */}
                          <td>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 5, width: 36 }}>
                              <span style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: 36, height: 28, borderRadius: 6, fontFamily: 'var(--f-mono, monospace)', fontSize: 13, fontWeight: 700, fontFeatureSettings: '"tnum"', background: `color-mix(in srgb, ${sevColor} 12%, transparent)`, color: sevColor, border: `1px solid color-mix(in srgb, ${sevColor} 28%, transparent)` }}>
                                {sev}
                              </span>
                              <div style={{ height: 3, borderRadius: 2, background: 'var(--fl-border2)', overflow: 'hidden' }}>
                                <div style={{ width: `${Math.min(100, sev * 10)}%`, height: '100%', background: sevColor }} />
                              </div>
                            </div>
                          </td>

                          {/* TYPE + VALUE */}
                          <td>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5, flexWrap: 'wrap' }}>
                              <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, monospace)', padding: '1px 7px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-purple) 10%, transparent)', color: 'var(--fl-purple)', border: '1px solid color-mix(in srgb, var(--fl-purple) 22%, transparent)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                                {TYPE_LABEL[ioc.ioc_type] || ioc.ioc_type}
                              </span>
                              {ioc.is_malicious && (
                                <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, monospace)', padding: '1px 7px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-danger) 10%, transparent)', color: 'var(--fl-danger)', border: '1px solid color-mix(in srgb, var(--fl-danger) 22%, transparent)', textTransform: 'uppercase', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                                  <AlertTriangle size={9} />{t('iocs.malicious_badge')}
                                </span>
                              )}
                            </div>
                            <div onClick={() => navigator.clipboard?.writeText(ioc.value)} title={t('casedetail.copy_value_title', { value: ioc.value })}
                              style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontFamily: 'var(--f-mono, monospace)', fontSize: 11.5, fontWeight: 600, cursor: 'pointer', wordBreak: 'break-all',
                                color: ioc.is_malicious ? 'var(--fl-danger)' : 'var(--fl-text)' }}>
                              {ioc.value}
                              <Copy className="ioc-copy" size={11} style={{ color: 'var(--fl-muted)', flexShrink: 0 }} />
                            </div>
                          </td>

                          {/* DESCRIPTION */}
                          <td style={{ color: 'var(--fl-dim)', fontSize: 12, maxWidth: 240, lineHeight: 1.45 }} title={ioc.description || ''}>
                            {ioc.description
                              ? <span style={{ display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>{ioc.description}</span>
                              : <span style={{ color: 'var(--fl-subtle)' }}>—</span>}
                          </td>

                          {/* ENRICHMENT */}
                          <td>
                            {ioc.enriched_at ? (
                              <span style={{ fontSize: 10.5, fontFamily: 'var(--f-mono, monospace)', color: 'var(--fl-ok)', display: 'inline-flex', alignItems: 'center', gap: 5, padding: '2px 8px', borderRadius: 5, background: 'color-mix(in srgb, var(--fl-ok) 9%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-ok) 20%, transparent)' }}>
                                <span style={{ width: 6, height: 6, borderRadius: 2, background: 'var(--fl-ok)', flexShrink: 0 }} />
                                {ioc.vt_verdict || (ioc.vt_malicious != null ? `VT ${ioc.vt_malicious}/${ioc.vt_total}` : t('iocs.enriched'))}
                              </span>
                            ) : (
                              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 10.5, fontFamily: 'var(--f-mono, monospace)', color: 'var(--fl-subtle)' }}>
                                <span style={{ width: 6, height: 6, borderRadius: 2, background: 'var(--fl-border3)', flexShrink: 0 }} />
                                {t('iocs.not_enriched')}
                              </span>
                            )}
                          </td>

                          {/* TAGS */}
                          <td>
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                              {(ioc.tags || []).length === 0
                                ? <span style={{ color: 'var(--fl-subtle)', fontSize: 11 }}>—</span>
                                : (ioc.tags || []).map(tag => (
                                  <span key={tag} style={{ fontSize: 9.5, fontFamily: 'var(--f-mono, monospace)', padding: '2px 7px', borderRadius: 4, background: 'var(--fl-raised)', border: '1px solid var(--fl-border)', color: 'var(--fl-dim)' }}>{tag}</span>
                                ))}
                            </div>
                          </td>

                          {/* ACTIONS */}
                          <td>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 4 }}>
                              <button onClick={() => handleIocEnrich(ioc)} disabled={isEnriching} title={t('iocs.enrich_title')}
                                style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '5px 10px', borderRadius: 6, cursor: isEnriching ? 'wait' : 'pointer', fontFamily: 'var(--f-mono, monospace)', fontSize: 10.5, fontWeight: 600,
                                  background: 'transparent', color: 'var(--fl-dim)', border: '1px solid var(--fl-border)', transition: 'color 0.12s, border-color 0.12s' }}
                                onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-accent)'; e.currentTarget.style.borderColor = 'color-mix(in srgb, var(--fl-accent) 35%, transparent)'; }}
                                onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-dim)'; e.currentTarget.style.borderColor = 'var(--fl-border)'; }}>
                                {isEnriching ? <Loader2 size={11} style={{ animation: 'spin 1s linear infinite' }} /> : <Shield size={11} />}
                                {ioc.enriched_at ? t('iocs.reenrich') : t('iocs.enrich')}
                              </button>
                              <button onClick={() => deleteIoc(ioc.id)} title={t('common.delete')}
                                style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: 28, height: 28, borderRadius: 6, cursor: 'pointer',
                                  background: 'transparent', color: 'var(--fl-subtle)', border: '1px solid transparent', transition: 'color 0.12s, border-color 0.12s' }}
                                onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-danger)'; e.currentTarget.style.borderColor = 'color-mix(in srgb, var(--fl-danger) 30%, transparent)'; }}
                                onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-subtle)'; e.currentTarget.style.borderColor = 'transparent'; }}>
                                <Trash2 size={11} />
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
          </div>
        );
      })()}

      {tab === 'evidence' && (
        <div style={{ maxWidth: 900, margin: '0 auto' }}>
          {parseProg?.active && (
            <ParsingMonitor
              caseId={id}
              parsers={Object.entries(parseProg.parsers || {}).map(([key, v]) => ({ key, name: v.name || key, color: ARTIFACT_COLORS[key] || 'var(--fl-muted)' }))}
              states={parseProg.parsers || {}}
              globalPct={parseProg.globalPct}
              live={parseProg.live}
            />
          )}

          <RightDrawer open={!!drawerEv} onClose={() => setDrawerEv(null)} title={drawerEv?.name}>
            {drawerEv && (
              <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 16, height: '100%', overflowY: 'auto' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '8px 14px' }}>
                  {[
                    [t('casedetail.col_type'), drawerEv.evidence_type || '—'],
                    [t('casedetail.size'), fmtSize(drawerEv.file_size)],
                    [t('casedetail.added_on'), drawerEv.created_at ? new Date(drawerEv.created_at).toLocaleString(i18n.language) : '—'],
                    ['Scan', drawerEv.scan_status || '—'],
                  ].map(([l, v]) => (
                    <div key={l} style={{ display: 'contents' }}>
                      <span style={{ fontSize: 10.5, fontFamily: 'var(--f-mono, monospace)', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-muted)', whiteSpace: 'nowrap' }}>{l}</span>
                      <span style={{ fontSize: 12, color: 'var(--fl-text)', fontFamily: 'var(--f-mono, monospace)', wordBreak: 'break-word' }}>{v}</span>
                    </div>
                  ))}
                </div>
                <div>
                  <div style={{ fontSize: 10, fontFamily: 'var(--f-mono, monospace)', textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-muted)', marginBottom: 6 }}>{t('casedetail.hashes')}</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {[['MD5', drawerEv.hash_md5], ['SHA-1', drawerEv.hash_sha1], ['SHA-256', drawerEv.hash_sha256]].filter(([, v]) => v).map(([l, v]) => (
                      <div key={l} onClick={() => navigator.clipboard?.writeText(v)} title={t('common.copy')}
                        style={{ cursor: 'pointer', padding: '6px 8px', borderRadius: 6, background: 'var(--fl-card)', border: '1px solid var(--fl-border)' }}>
                        <div style={{ fontSize: 9, fontFamily: 'var(--f-mono, monospace)', color: 'var(--fl-muted)', marginBottom: 2 }}>{l}</div>
                        <div style={{ fontSize: 10.5, fontFamily: 'var(--f-mono, monospace)', color: 'var(--fl-dim)', wordBreak: 'break-all' }}>{v}</div>
                      </div>
                    ))}
                    {![drawerEv.hash_md5, drawerEv.hash_sha1, drawerEv.hash_sha256].some(Boolean) && (
                      <span style={{ fontSize: 11, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, monospace)' }}>{t('casedetail.no_hashes')}</span>
                    )}
                  </div>
                </div>
                {drawerEv.notes && (
                  <p style={{ fontSize: 11, fontStyle: 'italic', color: 'var(--fl-dim)', padding: '6px 8px', background: 'var(--fl-card)', borderRadius: 6, margin: 0 }}>{drawerEv.notes}</p>
                )}
                {drawerEv.additional_files?.length > 0 && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {drawerEv.additional_files.map(f => (
                      <span key={f.name} style={{ fontSize: 9, fontFamily: 'var(--f-mono, monospace)', background: 'color-mix(in srgb, var(--fl-accent) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 18%, transparent)', borderRadius: 3, padding: '1px 6px', color: 'var(--fl-dim)' }}>
                        📎 {f.original_name} · {fmtSize(f.size)}
                      </span>
                    ))}
                  </div>
                )}
                {(drawerEv.scan_status === 'alert' || drawerEv.scan_status === 'quarantined' || drawerEv.is_suspicious === true) ? (
                  <HexStringsPreview evId={drawerEv.id} />
                ) : (
                  <div style={{ borderRadius: 8, padding: 12, textAlign: 'center', background: 'color-mix(in srgb, var(--fl-ok) 7%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-ok) 22%, transparent)' }}>
                    <div style={{ color: 'var(--fl-ok)', fontSize: 12 }}>{t('casedetail.clean_file')}</div>
                    <div style={{ color: 'var(--fl-muted)', fontSize: 11, marginTop: 4 }}>{t('casedetail.clean_file_sub')}</div>
                  </div>
                )}
                <button
                  onClick={() => { const tid = drawerEv.id; setDrawerEv(null); navigate(`/cases/${id}/collections/${tid}`); }}
                  style={{ marginTop: 'auto', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, padding: '8px 12px', borderRadius: 6, cursor: 'pointer', background: 'var(--fl-accent)', color: '#fff', border: 'none', fontFamily: 'var(--f-mono, monospace)', fontSize: 12, fontWeight: 600 }}>
                  {t('casedetail.open_collection_arrow')}
                </button>
              </div>
            )}
          </RightDrawer>

          <div className="flex justify-between items-center mb-4">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <FolderOpen size={14} style={{ color: 'var(--fl-accent)' }} />
              <span style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-dim)' }}>
                {t('casedetail.evidence_header')}
              </span>
              <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 6px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-accent) 9%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 19%, transparent)' }}>
                {evidence.length}
              </span>
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              <button
                onClick={() => downloadCSV(evidence, [
                  { key: 'name',          label: t('casedetail.col_name') },
                  { key: 'evidence_type', label: t('casedetail.col_type') },
                  { key: 'file_size',     label: t('casedetail.col_size_bytes') },
                  { key: 'hash_sha256',   label: 'SHA-256' },
                  { key: 'scan_status',   label: t('casedetail.col_scan_status') },
                  { key: 'scan_threat',   label: t('casedetail.col_threat_detected') },
                  { key: 'is_highlighted',label: t('casedetail.col_marked') },
                  { key: 'created_at',    label: t('casedetail.added_on') },
                ], `${t('casedetail.evidence_filename_prefix')}_${caseData?.case_number || id}_${new Date().toISOString().slice(0,10)}.csv`)}
                disabled={evidence.length === 0}
                className="fl-btn fl-btn-ghost fl-btn-sm"
                title={t('casedetail.tooltip_export_csv')}
              >
                <Download size={12} /> CSV
              </button>
              <button
                onClick={() => setShowImportPanel(p => !p)}
                className="fl-btn fl-btn-primary fl-btn-sm"
                style={showImportPanel ? { background: 'var(--fl-border)', color: 'var(--fl-dim)', borderColor: '#444c56' } : {}}
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
                <span style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-accent)' }}>{t('casedetail.import_forensic')}</span>
                <span style={{ fontSize: 10, color: 'var(--fl-muted)' }}>Windows: Magnet RESPONSE · KAPE · Velociraptor · CyLR — Hayabusa &nbsp;|&nbsp; Linux: CatScale</span>
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
            <div className="text-center py-12 rounded-xl" style={{ background: 'var(--fl-card)', border: '1px solid var(--fl-border)' }}>
              <FolderOpen size={36} style={{ color: 'var(--fl-border)', margin: '0 auto 10px' }} />
              <p className="text-sm mb-1" style={{ color: 'var(--fl-text)' }}>{t('casedetail.no_evidence')}</p>
              <p className="text-xs mb-4" style={{ color: 'var(--fl-dim)' }}>{t('casedetail.no_evidence_sub')}</p>
              <button onClick={() => setShowImportPanel(true)} className="px-4 py-2 rounded-lg text-xs font-semibold"
                style={{ background: 'color-mix(in srgb, var(--fl-accent) 8%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 19%, transparent)' }}>
                {t('casedetail.import_collection')}
              </button>
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {evidence.map((ev, _evIdx) => {
              const evResult = evResultMap[ev.name];
              const resultId = evResult?.resultId;
              const recordCount = evResult?.recordCount ?? 0;
              // "Analyzed" reflects ACTUAL parse completion (real records written at the
              // end of the job), not the mere existence of a parser_results row — that row
              // is created at import/start, which made the badge flip to "analyzed" too early.
              const isParsed = recordCount > 0;
              const isAnalyzing = !isParsed && Boolean(parseProg?.active);
              const isExpanded = selEv?.id === ev.id;
              const vw = volwebVisual(ev, volwebProgress[ev.id]);
              const isMemory = ev.evidence_type === 'memory' || /\.(raw|mem|vmem|lime|dmp)$/i.test(ev.original_filename || ev.name || '');

              return (
                <div key={ev.id} style={{
                  borderRadius: 8, overflow: 'hidden',
                  border: `1px solid ${isExpanded ? 'color-mix(in srgb, var(--fl-accent) 25%, transparent)' : 'var(--fl-border)'}`,
                  background: 'var(--fl-panel)',
                  transition: 'border-color 0.15s',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px', cursor: 'pointer' }}
                    onClick={() => { if (isExpanded) navigate(`/cases/${id}`); else navigate(`/cases/${id}/collections/${ev.id}`); }}>
                    <FolderOpen size={13} style={{ color: isParsed ? 'var(--fl-ok)' : 'var(--fl-muted)', flexShrink: 0 }} />
                    <div style={{ flex: 1, overflow: 'hidden', minWidth: 0 }}>
                      <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--fl-text)', display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {ev.name}
                      </span>
                      {ev.additional_files?.length > 0 && (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, marginTop: 3 }}>
                          {ev.additional_files.map(f => (
                            <span key={f.name} style={{
                              fontSize: 9, fontFamily: 'monospace',
                              background: 'rgba(139,114,214,0.08)',
                              border: '1px solid rgba(139,114,214,0.20)',
                              borderRadius: 3, padding: '1px 6px',
                              color: 'var(--fl-dim)',
                            }}>
                              📎 {f.original_name} · {fmtSize(f.size)}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                    {isParsed ? (
                      <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '2px 7px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-ok) 9%, transparent)', color: 'var(--fl-ok)', border: '1px solid color-mix(in srgb, var(--fl-ok) 19%, transparent)', flexShrink: 0 }}>
                        ✓ {recordCount.toLocaleString()} {t('casedetail.records_short')}
                      </span>
                    ) : isAnalyzing ? (
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '2px 7px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-accent) 9%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 22%, transparent)', flexShrink: 0 }}>
                        <Loader2 size={9} style={{ animation: 'fl-spin 0.9s linear infinite' }} /> {t('casedetail.analyzing')}
                      </span>
                    ) : (
                      <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '2px 7px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-muted) 9%, transparent)', color: 'var(--fl-muted)', border: '1px solid var(--fl-border)', flexShrink: 0 }}>
                        {t('casedetail.not_analyzed')}
                      </span>
                    )}
                    <ColorBadge color="var(--fl-accent)">{ev.evidence_type}</ColorBadge>
                    {ev.scan_status === 'quarantined' && (
                      <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '2px 6px', borderRadius: 4, background: 'rgba(218,54,51,0.15)', color: 'var(--fl-danger)', border: '1px solid rgba(218,54,51,0.3)', flexShrink: 0 }}>
                        <AlertTriangle size={9} style={{ display: 'inline', marginRight: 3 }} />{t('casedetail.quarantine')}
                      </span>
                    )}
                    {ev.scan_status === 'clean' && <Shield size={12} style={{ color: 'var(--fl-ok)', flexShrink: 0 }} title="Clean" />}
                    {ev.is_highlighted && <Star size={12} style={{ color: 'var(--fl-gold)', flexShrink: 0 }} fill="var(--fl-gold)" />}
                    <span style={{ fontSize: 11, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', flexShrink: 0 }}>{fmtSize(ev.file_size)}</span>
                    <span style={{ fontSize: 11, color: 'var(--fl-subtle)', flexShrink: 0 }}>{new Date(ev.created_at).toLocaleDateString(i18n.language)}</span>
                    <button
                      onClick={e => { e.stopPropagation(); setDrawerEv(ev); }}
                      title={t('casedetail.details_title')}
                      style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 26, height: 26, borderRadius: 5, cursor: 'pointer', background: 'transparent', color: 'var(--fl-muted)', border: '1px solid var(--fl-border)', flexShrink: 0 }}
                      onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-accent)'; e.currentTarget.style.borderColor = 'var(--fl-border3)'; }}
                      onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; e.currentTarget.style.borderColor = 'var(--fl-border)'; }}>
                      <Icon name="Info" size={13} />
                    </button>
                    <button
                      onClick={e => { e.stopPropagation(); collectionAPI.parse(id, { evidence_id: ev.id, socketId }).catch(() => {}); }}
                      title={t('casedetail.reparse_title')}
                      style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '4px 9px', borderRadius: 5, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer', background: 'transparent', color: 'var(--fl-muted)', border: '1px solid var(--fl-border)', flexShrink: 0 }}
                      onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-accent)'; e.currentTarget.style.borderColor = 'var(--fl-border3)'; }}
                      onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; e.currentTarget.style.borderColor = 'var(--fl-border)'; }}>
                      <RefreshCw size={11} /> {t('casedetail.reparse')}
                    </button>
                    {isParsed && (
                      <button
                        onClick={e => { e.stopPropagation(); navigate(`/cases/${id}/collections/${ev.id}/timeline`, { state: { evidenceName: ev.name, caseTitle: caseData?.title, caseNumber: caseData?.case_number } }); }}
                        style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '4px 10px', borderRadius: 5, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer', background: 'color-mix(in srgb, var(--fl-accent) 13%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 31%, transparent)', flexShrink: 0, fontWeight: 700 }}
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
                                const msg = err.response?.data?.error || err.message || t('casedetail.pcap_error');
                                setPcapState(prev => ({ ...prev, [ev.id]: { loading: false, result: null, error: msg } }));
                              }
                            }}
                          />
                          <button
                            onClick={e => { e.stopPropagation(); document.getElementById(`pcap-input-${ev.id}`).click(); }}
                            disabled={ps.loading}
                            style={{
                              display: 'flex', alignItems: 'center', gap: 4, padding: '4px 10px', borderRadius: 5,
                              fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: ps.loading ? 'wait' : 'pointer',
                              background: ps.result ? 'color-mix(in srgb, var(--fl-ok) 8%, transparent)' : ps.error ? 'color-mix(in srgb, var(--fl-danger) 8%, transparent)' : 'color-mix(in srgb, var(--fl-accent) 6%, transparent)',
                              color: ps.result ? 'var(--fl-ok)' : ps.error ? 'var(--fl-danger)' : 'color-mix(in srgb, var(--fl-accent) 50%, transparent)',
                              border: `1px solid ${ps.result ? 'color-mix(in srgb, var(--fl-ok) 21%, transparent)' : ps.error ? 'color-mix(in srgb, var(--fl-danger) 21%, transparent)' : 'color-mix(in srgb, var(--fl-accent) 15%, transparent)'}`,
                              flexShrink: 0, fontWeight: 600,
                            }}
                            title={ps.result ? t('casedetail.tooltip_network_result', { result: ps.result.inserted }) : ps.error || t('casedetail.tooltip_network_import')}
                          >
                            {ps.loading ? <Loader2 size={11} style={{ animation: 'spin 1s linear infinite' }} /> : <Wifi size={11} />}
                            {ps.loading ? t('casedetail.pcap_loading') : ps.result ? t('casedetail.pcap_done', { count: ps.result.inserted }) : t('casedetail.import_pcap')}
                          </button>
                        </>
                      );
                    })()}
                    <button onClick={e => { e.stopPropagation(); toggleHL(ev.id); }} style={{ color: ev.is_highlighted ? 'var(--fl-gold)' : 'var(--fl-subtle)', background: 'none', border: 'none', cursor: 'pointer', padding: '0 2px', flexShrink: 0 }}>
                      <Star size={13} fill={ev.is_highlighted ? 'var(--fl-gold)' : 'none'} />
                    </button>
                    <button onClick={e => { e.stopPropagation(); setEvToDelete(ev); }} style={{ color: 'var(--fl-subtle)', background: 'none', border: 'none', cursor: 'pointer', padding: '0 2px', flexShrink: 0 }} title={t('common.delete')}>
                      <Trash2 size={12} />
                    </button>
                  </div>

                  {/* VolWeb strip — separate row so it never crowds the name/metadata line */}
                  {isMemory && (() => {
                    const p       = volwebProgress[ev.id];
                    const stepMsg = volwebSteps[ev.id];
                    const pct = p ? (p.volweb_raw_status ?? p.pct) : null;
                    const done         = ev.volweb_status === 'ready' || (ev.volweb_status === 'processing' && pct === 100);
                    const uploading    = ev.volweb_status === 'uploading';
                    const initializing = ev.volweb_status === 'processing' && !p;
                    const processing   = ev.volweb_status === 'processing' && p;
                    const showBar      = uploading || initializing || processing;
                    return (
                      <div
                        onClick={e => e.stopPropagation()}
                        style={{
                          borderTop: '1px solid var(--fl-border)',
                          padding: '6px 14px',
                          display: 'flex', alignItems: 'center', gap: 8,
                          background: ev.volweb_status === 'error'
                            ? 'color-mix(in srgb, var(--fl-danger) 4%, transparent)'
                            : uploading || processing
                              ? 'color-mix(in srgb, var(--fl-accent) 3%, transparent)'
                              : 'transparent',
                        }}
                      >
                        <Cpu size={11} style={{ color: vw.fg, flexShrink: 0 }} />
                        <button
                          onClick={() => openVolWeb(id)}
                          disabled={volwebLoading}
                          style={{
                            display: 'flex', alignItems: 'center', gap: 4, padding: '3px 9px',
                            borderRadius: 5, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                            cursor: volwebLoading ? 'not-allowed' : 'pointer',
                            background: vw.bg, color: vw.fg, border: `1px solid ${vw.bd}`,
                            flexShrink: 0, fontWeight: 700,
                          }}
                          title={done ? t('casedetail.volweb_open_sso') : ev.volweb_status === 'processing' ? t('casedetail.volweb_processing_title') : ev.volweb_status === 'error' ? t('casedetail.volweb_error_title') : t('casedetail.volweb_open')}
                        >
                          {done ? t('casedetail.volweb_done_short')
                            : uploading ? t('casedetail.volweb_uploading')
                            : ev.volweb_status === 'processing' ? t('casedetail.volweb_processing_short', { pct: pct != null ? `${pct}%` : '' })
                            : ev.volweb_status === 'error' ? t('casedetail.volweb_failed_short')
                            : t('casedetail.volweb_open_short')}
                        </button>
                        {showBar && (
                          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 2, minWidth: 60, maxWidth: 220 }}>
                            <div style={{ height: 3, background: 'var(--fl-card)', borderRadius: 2, overflow: 'hidden' }}>
                              {(uploading || initializing) ? (
                                <div style={{ height: '100%', borderRadius: 2, width: '40%', background: 'linear-gradient(90deg, var(--fl-accent), var(--fl-purple))', animation: 'volweb-slide 1.4s ease-in-out infinite' }} />
                              ) : (
                                <div style={{ height: '100%', borderRadius: 2, width: `${pct}%`, background: pct === 100 ? 'var(--fl-ok)' : 'linear-gradient(90deg, var(--fl-accent), var(--fl-purple))', transition: 'width 0.4s ease' }} />
                              )}
                            </div>
                            <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: pct === 100 ? 'var(--fl-ok)' : 'var(--fl-dim)' }}>
                              {uploading ? (stepMsg || t('casedetail.volweb_uploading_to'))
                                : initializing ? (stepMsg || t('casedetail.volweb_processing_short', { pct: '' }))
                                : pct === 100 ? t('casedetail.volweb_complete')
                                : p.tasks_total > 0 ? `${p.tasks_done}/${p.tasks_total} plugins · ${pct}%`
                                : `${pct}%`}
                            </span>
                          </div>
                        )}
                        {(uploading || ev.volweb_status === 'error') && (
                          <button
                            onClick={() => retryVolWeb(ev.id)}
                            disabled={volwebRetrying === ev.id}
                            style={{
                              display: 'flex', alignItems: 'center', gap: 4, padding: '3px 8px',
                              borderRadius: 5, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                              cursor: volwebRetrying === ev.id ? 'wait' : 'pointer',
                              background: 'rgba(77,130,192,0.10)', color: 'var(--fl-accent)',
                              border: '1px solid rgba(77,130,192,0.30)', flexShrink: 0,
                            }}
                            title={t('casedetail.volweb_retry_title')}
                          >
                            <RefreshCw size={10} style={{ animation: volwebRetrying === ev.id ? 'spin 1s linear infinite' : 'none' }} />
                            {volwebRetrying === ev.id ? '…' : 'Retry'}
                          </button>
                        )}
                      </div>
                    );
                  })()}

                </div>
              );
            })}
          </div>

          {evidence.length > 0 && (() => {
            // Count only over the collections actually displayed — an orphan evidence_name
            // (from a deleted/re-imported collection) must not inflate the count past evidence.length.
            const recsFor = (ev) => evResultMap[ev.name]?.recordCount || 0;
            const totalRecords = evidence.reduce((s, ev) => s + recsFor(ev), 0);
            const parsedCount  = evidence.filter(ev => recsFor(ev) > 0).length;
            const parsedEvNames = evidence.filter(ev => recsFor(ev) > 0).map(ev => ev.name);
            return (
              <div style={{ marginTop: 20, background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 8, overflow: 'hidden' }}>
                {/* Unified Summary & Report card */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 16px', borderBottom: '1px solid var(--fl-border2)' }}>
                  <FileDown size={13} style={{ color: 'var(--fl-accent)' }} />
                  <span style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-dim)' }}>
                    {t('casedetail.synthesis_report')}
                  </span>
                  <span style={{ flex: 1 }} />
                  <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-subtle)' }}>
                    {parsedCount}/{evidence.length} {t('casedetail.collections_parsed')}
                  </span>
                </div>

                <div style={{ padding: '14px 16px' }}>
                  <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'baseline', gap: 16, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                    {[
                      [t('casedetail.analyzed_collections'), parsedCount, 'var(--fl-ok)'],
                      [t('casedetail.total_records'), totalRecords.toLocaleString(), 'var(--fl-accent)'],
                      [t('casedetail.iocs_detected'), caseIOCs.length, caseIOCs.length > 0 ? 'var(--fl-danger)' : 'var(--fl-subtle)'],
                    ].map(([label, value, color], i) => (
                      <div key={label} style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
                        {i > 0 && <span style={{ color: 'var(--fl-subtle)', marginRight: 10 }}>·</span>}
                        <span style={{ fontSize: 15, fontWeight: 700, color, fontFeatureSettings: '"tnum"' }}>{value}</span>
                        <span style={{ fontSize: 10.5, color: 'var(--fl-muted)' }}>{label}</span>
                      </div>
                    ))}
                  </div>
                  {parsedEvNames.length > 0 && (
                    <div style={{ marginTop: 12 }}>
                      <div style={{ fontSize: 10, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', marginBottom: 6 }}>{t('casedetail.included_collections')}</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                        {parsedEvNames.map(name => (
                          <span key={name} style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '2px 7px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-ok) 7%, transparent)', color: 'var(--fl-ok)', border: '1px solid color-mix(in srgb, var(--fl-ok) 15%, transparent)' }}>
                            ✓ {name}
                          </span>
                        ))}
                        {evidence.filter(ev => !parsedEvNames.includes(ev.name)).map(ev => (
                          <span key={ev.id} style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '2px 7px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-border) 9%, transparent)', color: 'var(--fl-muted)', border: '1px solid var(--fl-border)' }}>
                            ○ {ev.name}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <div style={{ borderTop: '1px solid var(--fl-border2)', margin: '14px 0' }} />

                  {parsedCount === 0 && (
                    <div style={{ fontSize: 12, color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '0 0 10px', textAlign: 'center', fontStyle: 'italic' }}>
                      {t('casedetail.parse_first')}
                    </div>
                  )}

                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  <div style={{
                    flex: 1, display: 'flex', alignItems: 'center', gap: 6,
                    padding: '5px 10px', borderRadius: 6,
                    background: selectedTemplate ? 'color-mix(in srgb, var(--fl-accent) 6%, transparent)' : 'var(--fl-bg)',
                    border: `1px solid ${selectedTemplate ? 'color-mix(in srgb, var(--fl-accent) 21%, transparent)' : 'var(--fl-card)'}`,
                  }}>
                    <FileDown size={11} style={{ color: selectedTemplate ? 'var(--fl-accent)' : 'var(--fl-muted)', flexShrink: 0 }} />
                    <span style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: selectedTemplate ? 'var(--fl-dim)' : 'var(--fl-muted)', flex: 1 }}>
                      {selectedTemplate ? selectedTemplate.name : t('casedetail.standard_report_all_sections')}
                    </span>
                    {selectedTemplate && (
                      <button onClick={() => setSelectedTemplate(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', padding: 0 }}>
                        <X size={10} />
                      </button>
                    )}
                  </div>
                  <button
                    onClick={() => setShowComposer(v => !v)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 5,
                      padding: '5px 10px', borderRadius: 6, fontSize: 11,
                      fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer',
                      background: showComposer ? 'color-mix(in srgb, var(--fl-accent) 12%, transparent)' : 'var(--fl-card)',
                      border: `1px solid ${showComposer ? 'color-mix(in srgb, var(--fl-accent) 30%, transparent)' : 'var(--fl-card)'}`,
                      color: showComposer ? 'var(--fl-accent)' : 'var(--fl-dim)',
                    }}
                  >
                    <Pencil size={11} /> {t('casedetail.compose')}
                  </button>
                  <button
                    onClick={() => setShowTemplateModal(true)}
                    style={{
                      padding: '5px 10px', borderRadius: 6, fontSize: 11,
                      fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer',
                      background: 'var(--fl-card)', border: '1px solid var(--fl-card)', color: 'var(--fl-dim)',
                    }}
                  >
                    Templates
                  </button>
                </div>

                {showComposer && !selectedTemplate && (
                  <div style={{ marginBottom: 12, padding: '12px 14px', borderRadius: 8, background: 'var(--fl-bg)', border: '1px solid var(--fl-border2)' }}>
                    <div style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-subtle)', marginBottom: 8 }}>{t('casedetail.sections_to_include')}</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 12 }}>
                      {[['mitre', 'MITRE ATT&CK'], ['killchain', t('casedetail.report_section_killchain')], ['findings', t('casedetail.report_section_detections')], ['iocs', 'IOCs'], ['timeline', t('casedetail.report_section_timeline')], ['evidence', t('casedetail.report_section_evidence')]].map(([key, label]) => {
                        const on = reportGroups.has(key);
                        return (
                          <button key={key}
                            onClick={() => setReportGroups(prev => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n; })}
                            style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '4px 10px', borderRadius: 6, cursor: 'pointer', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                              background: on ? 'color-mix(in srgb, var(--fl-accent) 10%, transparent)' : 'transparent',
                              border: `1px solid ${on ? 'color-mix(in srgb, var(--fl-accent) 30%, transparent)' : 'var(--fl-border)'}`,
                              color: on ? 'var(--fl-accent)' : 'var(--fl-muted)' }}>
                            <span style={{ width: 14, height: 14, borderRadius: 4, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
                              border: `1.5px solid ${on ? 'var(--fl-accent)' : 'var(--fl-border3)'}`, background: on ? 'var(--fl-accent)' : 'transparent' }}>
                              {on && <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="4"><polyline points="20 6 9 17 4 12" /></svg>}
                            </span>
                            {label}
                          </button>
                        );
                      })}
                    </div>
                    <div style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-subtle)', marginBottom: 6 }}>{t('casedetail.analyst_note_optional')}</div>
                    <textarea value={reportNote} onChange={e => setReportNote(e.target.value)}
                      placeholder={t('casedetail.analyst_note_ph')} rows={3}
                      style={{ width: '100%', boxSizing: 'border-box', resize: 'vertical', background: 'var(--fl-panel)', color: 'var(--fl-text)', border: '1px solid var(--fl-border)', borderRadius: 6, padding: '8px 10px', fontSize: 12, fontFamily: 'var(--f-ui, Inter, sans-serif)', outline: 'none', lineHeight: 1.5 }} />
                    <div style={{ fontSize: 9.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-subtle)', marginTop: 6 }}>
                      {t('casedetail.executive_summary_included')}{reportGroups.size === 0 ? <span style={{ color: 'var(--fl-warn)' }}>{' '}{t('casedetail.no_optional_section')}</span> : ''}
                    </div>

                    <div style={{ borderTop: '1px solid var(--fl-border2)', margin: '14px 0 12px' }} />
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                      <button onClick={() => setAiEnabled(v => !v)} style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
                        <span style={{ width: 14, height: 14, borderRadius: 4, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
                          border: `1.5px solid ${aiEnabled ? 'var(--fl-accent)' : 'var(--fl-border3)'}`, background: aiEnabled ? 'var(--fl-accent)' : 'transparent' }}>
                          {aiEnabled && <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="4"><polyline points="20 6 9 17 4 12" /></svg>}
                        </span>
                        <span style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: aiEnabled ? 'var(--fl-text)' : 'var(--fl-muted)' }}>{t('casedetail.enrich_with_ai')}</span>
                      </button>
                      {aiEnabled && (
                        <button onClick={generateAiDraft} disabled={aiLoading || parsedCount === 0}
                          title={t('casedetail.ai_draft_title')}
                          style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 11px', borderRadius: 6, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: aiLoading ? 'wait' : 'pointer',
                            background: 'color-mix(in srgb, var(--fl-accent) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 30%, transparent)', color: 'var(--fl-accent)' }}>
                          {aiLoading ? <Loader2 size={11} style={{ animation: 'fl-spin 0.9s linear infinite' }} /> : <Sparkles size={11} />}
                          {aiDraft ? t('casedetail.regenerate_draft') : t('casedetail.generate_ai_draft')}
                        </button>
                      )}
                      {aiError && <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-danger)' }}>{aiError}</span>}
                    </div>
                    {aiEnabled && !aiDraft && !aiLoading && (
                      <div style={{ fontSize: 9.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-subtle)', marginTop: 6 }}>
                        {t('casedetail.ai_auto_generate_hint')}
                      </div>
                    )}
                    {aiEnabled && aiDraft && (
                      <div style={{ marginTop: 12 }}>
                        <ReportAiEditor value={aiDraft} loading={aiLoading}
                          onChange={(k, v) => setAiDraft(prev => ({ ...(prev || {}), [k]: v }))}
                          onRegenerate={generateAiDraft} />
                      </div>
                    )}
                  </div>
                )}
                {showComposer && selectedTemplate && (
                  <div style={{ marginBottom: 12, padding: '10px 12px', borderRadius: 8, background: 'color-mix(in srgb, var(--fl-warn) 6%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-warn) 20%, transparent)', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-warn)' }}>
                    {t('casedetail.template_selected_hint')}
                  </div>
                )}

                <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginTop: 14 }}>
                  <button
                    onClick={generateReport}
                    disabled={generating || parsedCount === 0}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 6,
                      padding: '8px 16px', borderRadius: 7, fontSize: 12,
                      fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 600, cursor: parsedCount === 0 ? 'not-allowed' : 'pointer',
                      background: parsedCount === 0 ? 'var(--fl-card)' : 'var(--fl-accent)',
                      border: `1px solid ${parsedCount === 0 ? 'var(--fl-border)' : 'var(--fl-accent)'}`,
                      color: parsedCount === 0 ? 'var(--fl-muted)' : '#fff',
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
                        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 600, cursor: 'pointer',
                        background: 'color-mix(in srgb, var(--fl-ok) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-ok) 21%, transparent)', color: 'var(--fl-ok)',
                      }}>
                      <Download size={13} /> {t('casedetail.download_pdf')}
                    </button>
                  )}
                </div>
                {reportDone && (
                  <div style={{ marginTop: 10, padding: '8px 12px', borderRadius: 7, background: 'color-mix(in srgb, var(--fl-ok) 3%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-ok) 15%, transparent)', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-ok)', display: 'flex', alignItems: 'center', gap: 6 }}>
                    {t('casedetail.report_done', { n: parsedCount, records: totalRecords.toLocaleString(), iocs: caseIOCs.length })}
                  </div>
                )}
                </div>
              </div>
            );
          })()}

          {!collectionId && <RdpCacheGallery caseId={id} />}

        </div>
      )}

      </div>

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
          <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: 'var(--fl-danger)', marginBottom: 14, letterSpacing: '0.04em' }}>
            {hardDeleteResult ? t('casedetail.db_verification') : t('casedetail.admin_irreversible_action')}
          </div>

          {!hardDeleting && !hardDeleteResult && (
            <>
              <div style={{ marginBottom: 16, padding: '10px 14px', borderRadius: 8, background: 'rgba(218,54,51,0.06)', border: '1px solid rgba(218,54,51,0.18)', fontSize: 12, color: 'var(--fl-muted)', lineHeight: 1.7 }}>
                {t('casedetail.hard_delete_intro', { caseNumber: caseData?.case_number })}{' '}
                (<code style={{ color: 'var(--fl-danger)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>DoD 5220.22-M</code>), {t('casedetail.hard_delete_scope')}<br />
                <span style={{ color: 'var(--fl-warn)', fontSize: 11 }}>{t('casedetail.audit_record_kept')}</span>
              </div>
              <div style={{ marginBottom: 6, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)' }}>
                {t('casedetail.type_case_number_confirm_prefix')} <code style={{ color: 'var(--fl-danger)', letterSpacing: '0.05em' }}>{caseData?.case_number}</code> {t('casedetail.type_case_number_confirm_suffix')}
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
              <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 13, color: 'var(--fl-muted)' }}>{t('casedetail.secure_delete_running')}</div>
              <div style={{ fontSize: 11, color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>DoD 5220.22-M · cascade delete · audit log</div>
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
                  <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12, fontWeight: 700, color: hardDeleteResult.ok ? 'var(--fl-ok)' : 'var(--fl-danger)' }}>
                    {hardDeleteResult.ok ? t('casedetail.hard_delete_success') : t('casedetail.hard_delete_failed')}
                  </span>
                </div>

                {hardDeleteResult.ok && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginLeft: 26 }}>
                    <div style={{ fontSize: 12, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-ok)' }}>
                      {t(hardDeleteResult.files_destroyed === 1 ? 'casedetail.file_destroyed' : 'casedetail.files_destroyed', { count: hardDeleteResult.files_destroyed })}
                    </div>
                    <div style={{ fontSize: 12, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: hardDeleteResult.verified ? 'var(--fl-ok)' : 'var(--fl-danger)' }}>
                      {hardDeleteResult.verified
                        ? t('casedetail.db_absence_confirmed')
                        : t('casedetail.db_still_accessible')}
                    </div>
                    {hardDeleteResult.files_errors?.length > 0 && (
                      <div style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-warn)' }}>
                        {t('casedetail.files_not_overwritten', { count: hardDeleteResult.files_errors.length, files: hardDeleteResult.files_errors.join(', ') })}
                      </div>
                    )}
                  </div>
                )}

                {!hardDeleteResult.ok && (
                  <div style={{ marginLeft: 26, fontSize: 12, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-danger)' }}>
                    {hardDeleteResult.error}
                  </div>
                )}
              </div>

              <div style={{ padding: '8px 12px', borderRadius: 6, background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)' }}>
                {t('casedetail.gdpr_audit_kept')}
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
        open={Boolean(statusModal) && Boolean(c)}
        title={t('casedetail.status_modal_title')}
        onClose={() => setStatusModal(null)}
        size="sm"
      >
        <Modal.Body>
          <div style={{ fontSize: 12, color: 'var(--fl-dim)', marginBottom: 16, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
            {c?.case_number} · {c?.title}
          </div>

          {statusModal === '_pick' ? (
            <>
              <div style={{ fontSize: 12, color: 'var(--fl-muted)', marginBottom: 12 }}>
                {t('casedetail.current_status')} <span style={{ color: SM[c?.status]?.c, fontWeight: 600 }}>{SM[c?.status]?.l}</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {Object.entries(SM).filter(([k]) => k !== c?.status).map(([key, { l, c: col }]) => (
                  <button key={key} onClick={() => setStatusModal(key)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 10, padding: '11px 14px',
                      background: `color-mix(in srgb, ${col} 6%, transparent)`, border: `1px solid color-mix(in srgb, ${col} 19%, transparent)`, borderRadius: 8,
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
                    {t('casedetail.close_case_confirm_prefix')} <strong style={{ color: 'var(--fl-danger)' }}>{t('casedetail.close_permanently')}</strong> {t('casedetail.close_case_confirm_suffix')}<br />
                    <span style={{ fontSize: 11, color: 'var(--fl-dim)' }}>{t('casedetail.status_reversible_hint')}</span>
                  </>
                ) : statusModal === 'pending' ? (
                  <>{t('casedetail.pending_case_prefix')} <strong style={{ color: 'var(--fl-warn)' }}>{t('casedetail.pending')}</strong> — {t('casedetail.pending_case_suffix')}</>
                ) : (
                  <>{t('casedetail.reopen_case_prefix')} <strong style={{ color: 'var(--fl-accent)' }}>{t('casedetail.in_progress')}</strong>.</>
                )}
              </div>
              <div style={{ fontSize: 12, color: 'var(--fl-muted)', marginBottom: 4 }}>
                {t('casedetail.new_status')} <span style={{ color: SM[statusModal]?.c, fontWeight: 700 }}>{SM[statusModal]?.l}</span>
                {user && <span style={{ color: 'var(--fl-border)' }}> · {t('casedetail.by_user', { user: user.full_name || user.username })}</span>}
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
        accentColor="var(--fl-gold)"
      >
        <Modal.Body>
          {triageRunning && (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '32px 0', gap: 14 }}>
              <Spinner size={28} color="var(--fl-gold)" />
              <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 13, color: 'var(--fl-dim)' }}>
                {t('casedetail.triage_running')}
              </div>
              <div style={{ fontSize: 11, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
                {t('casedetail.triage_sql_hint')}
              </div>
            </div>
          )}
          {!triageRunning && triageData && (
            <div>
              {triageData.case_indicators && (
                <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
                  {[
                    ['YARA', triageData.case_indicators.yara_matches, 'var(--fl-danger)'],
                    ['Sigma', triageData.case_indicators.sigma_matches, 'var(--fl-warn)'],
                    ['Threat Intel', triageData.case_indicators.threat_intel_matches, 'var(--fl-purple)'],
                    [t('casedetail.malicious_iocs'), triageData.case_indicators.malicious_iocs, 'var(--fl-gold)'],
                  ].map(([label, val, color]) => val > 0 ? (
                    <span key={label} style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '3px 10px',
                      borderRadius: 4, background: `color-mix(in srgb, ${color} 9%, transparent)`, color, border: `1px solid color-mix(in srgb, ${color} 19%, transparent)` }}>
                      {val} {label}
                    </span>
                  ) : null)}
                </div>
              )}

              {triageData.scores?.length === 0 && (
                <div style={{ padding: '24px', textAlign: 'center', color: 'var(--fl-muted)',
                  fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, borderRadius: 8,
                  background: 'var(--fl-bg)', border: '1px solid var(--fl-border)' }}>
                  {t('casedetail.no_collection_timeline')}<br />
                  {t('casedetail.import_parse_before_triage')}
                </div>
              )}
              {triageData.scores?.length > 0 && (
                <div style={{ borderRadius: 8, border: '1px solid var(--fl-border)', background: 'var(--fl-bg)', overflow: 'hidden' }}>
                  {triageData.scores.map(m => {
                    const riskKey = (m.risk_level || '').normalize('NFD').replace(/\p{Diacritic}/gu, '').toUpperCase();
                    const riskColors = { CRITIQUE: 'var(--fl-danger)', ELEVE: 'var(--fl-warn)', MOYEN: 'var(--fl-gold)', FAIBLE: 'var(--fl-ok)' };
                    const color = riskColors[riskKey] || 'var(--fl-dim)';
                    const breakdown = m.breakdown || {};
                    return (
                      <div key={m.hostname} style={{ padding: '10px 14px', borderBottom: '1px solid #1c2a3a' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                          <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12, color: 'var(--fl-text)', flex: 1 }}>{m.hostname}</span>
                          <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: 'var(--fl-muted)' }}>{m.event_count?.toLocaleString()} {t('casedetail.event_abbr')}</span>
                          <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 14, fontWeight: 700, color, width: 30, textAlign: 'right' }}>{m.score}</span>
                          <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 6px', borderRadius: 3,
                            background: `color-mix(in srgb, ${color} 9%, transparent)`, color, border: `1px solid color-mix(in srgb, ${color} 21%, transparent)`, minWidth: 55, textAlign: 'center' }}>
                            {m.risk_level}
                          </span>
                        </div>
                        <div style={{ height: 4, borderRadius: 2, background: '#1c2a3a', overflow: 'hidden', marginBottom: 6 }}>
                          <div style={{ height: '100%', width: `${Math.min(m.score, 100)}%`, background: color, borderRadius: 2 }} />
                        </div>
                        {Object.keys(breakdown).length > 0 && (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                            {Object.entries(breakdown).map(([rule, pts]) => (
                              <span key={rule} style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 5px',
                                borderRadius: 3, background: '#1c2a3a', color: 'var(--fl-dim)', border: '1px solid var(--fl-border)' }}>
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
                <div style={{ marginTop: 10, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)', textAlign: 'right' }}>
                  {t('casedetail.computed_on', { date: fmtLocal(triageData.computed_at) })}
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
            style={{ color: 'var(--fl-gold)', borderColor: 'rgba(200,157,29,0.30)', background: 'rgba(200,157,29,0.08)' }}>
            {triageRunning ? t('casedetail.triage_running') : t('common.refresh')}
          </Button>
        </Modal.Footer>
      </Modal>

      <Modal
        open={legalHoldModal === 'enable'}
        title={t('casedetail.legal_enable_title')}
        onClose={() => !legalHoldSaving && setLegalHoldModal(false)}
        size="sm"
        accentColor="var(--fl-danger)"
      >
        <Modal.Body>
          <div style={{ marginBottom: 14, padding: '10px 14px', borderRadius: 8,
            background: 'rgba(218,54,51,0.06)', border: '1px solid rgba(218,54,51,0.18)',
            fontSize: 12, color: 'var(--fl-muted)', lineHeight: 1.7 }}>
            {t('casedetail.legal_enable_body_prefix')} <strong style={{ color: 'var(--fl-text)' }}>{c?.case_number}</strong> {t('casedetail.legal_enable_body_suffix')}
          </div>
          <label className="fl-label">{t('casedetail.reason_optional')}</label>
          <input
            value={legalHoldReason}
            onChange={e => setLegalHoldReason(e.target.value)}
            placeholder={t('casedetail.legal_reason_ph')}
            className="fl-input w-full"
            autoFocus
          />
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" size="sm" disabled={legalHoldSaving}
            onClick={() => { setLegalHoldModal(false); setLegalHoldReason(''); }}>
            {t('common.cancel')}
          </Button>
          <Button variant="danger" size="sm" icon={Lock} loading={legalHoldSaving}
            onClick={enableLegalHold}>
            {t('casedetail.legal_enable_title')}
          </Button>
        </Modal.Footer>
      </Modal>

      <Modal
        open={legalHoldModal === 'disable'}
        title={t('casedetail.legal_disable_title')}
        onClose={() => !legalHoldSaving && setLegalHoldModal(false)}
        size="sm"
        accentColor="var(--fl-warn)"
      >
        <Modal.Body>
          <div style={{ marginBottom: 14, padding: '10px 14px', borderRadius: 8,
            background: 'rgba(217,124,32,0.06)', border: '1px solid rgba(217,124,32,0.18)',
            fontSize: 12, color: 'var(--fl-muted)', lineHeight: 1.7 }}>
            {t('casedetail.legal_disable_body_prefix')}{' '}
            <strong style={{ color: 'var(--fl-text)' }}>{c?.case_number}</strong> ?<br />
            <span style={{ fontSize: 11, color: 'var(--fl-dim)' }}>
              {t('casedetail.legal_disable_body_hint')}
            </span>
          </div>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" size="sm" disabled={legalHoldSaving}
            onClick={() => setLegalHoldModal(false)}>
            {t('common.cancel')}
          </Button>
          <Button variant="ghost" size="sm" loading={legalHoldSaving}
            onClick={disableLegalHold}
            style={{ color: 'var(--fl-warn)', borderColor: 'rgba(217,124,32,0.30)', background: 'rgba(217,124,32,0.08)' }}>
            {t('casedetail.legal_disable_title')}
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
