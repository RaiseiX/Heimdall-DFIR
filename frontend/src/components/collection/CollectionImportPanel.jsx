import { useState, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useSocket } from '../../hooks/useSocket';
import { Upload, CheckCircle2, Loader2, Package, Cpu, Shield, ChevronRight, AlertTriangle, X, Terminal, Network, Lock, Clock, HardDrive, Server, Copy } from 'lucide-react';
import { collectionAPI } from '../../utils/api';
import { zipSync } from 'fflate';
import ParsingMonitor from './ParsingMonitor';

const ARTIFACT_EXTS = new Set(['.evtx', '.pf', '.lnk', '.dat', '.hve', '.db', '.sqlite', '.mdb', '.automaticDestinations-ms', '.pcap', '.pcapng', '.cap']);

// Traverse a FileSystemEntry recursively, resolving all File objects
async function collectEntries(entry, prefix = '') {
  if (entry.isFile) {
    return new Promise((resolve) => {
      entry.file(f => resolve([{ file: f, path: prefix + f.name }]), () => resolve([]));
    });
  }
  if (entry.isDirectory) {
    const reader = entry.createReader();
    const all = [];
    // readEntries returns max 100 at a time — must loop
    while (true) {
      const batch = await new Promise((resolve) => reader.readEntries(resolve, () => resolve([])));
      if (!batch.length) break;
      for (const child of batch) {
        const sub = await collectEntries(child, prefix + entry.name + '/');
        all.push(...sub);
      }
    }
    return all;
  }
  return [];
}

async function buildZipFromItems(dataTransferItems) {
  const allFiles = [];
  for (const item of dataTransferItems) {
    const entry = item.webkitGetAsEntry?.();
    if (entry) {
      const collected = await collectEntries(entry);
      allFiles.push(...collected);
    }
  }
  if (allFiles.length === 0) return null;

  const fileMap = {};
  await Promise.all(allFiles.map(({ file, path }) =>
    file.arrayBuffer().then(buf => { fileMap[path] = new Uint8Array(buf); })
  ));
  const zipped = zipSync(fileMap, { level: 0 }); // level 0 = store, fast
  return new File([zipped], 'artifacts.zip', { type: 'application/zip' });
}

const ARTIFACTS = {
  evtx:      { name: 'Event Logs (EVTX)', color: 'var(--fl-artifact-evtx)',      parser: 'EvtxECmd',       platform: 'windows' },
  prefetch:  { name: 'Prefetch',          color: 'var(--fl-artifact-prefetch)',  parser: 'PECmd',           platform: 'windows' },
  mft:       { name: '$MFT',              color: 'var(--fl-artifact-mft)',       parser: 'MFTECmd',         platform: 'windows' },
  usn:       { name: '$J (USN Journal)',  color: 'var(--fl-artifact-mft)',       parser: 'MFTECmd',         platform: 'windows' },
  indx:      { name: '$I30 (INDX)',       color: 'var(--fl-artifact-mft)',       parser: 'MFTECmd',         platform: 'windows' },
  lnk:       { name: 'LNK Shortcuts',     color: 'var(--fl-artifact-lnk)',       parser: 'LECmd',           platform: 'windows' },
  registry:  { name: 'Registry Hives',    color: 'var(--fl-artifact-registry)',  parser: 'RECmd',           platform: 'windows' },
  userassist:{ name: 'UserAssist',        color: 'var(--fl-artifact-registry)',  parser: 'dissect.regf',    platform: 'windows' },
  netprofile:{ name: 'Network Profiles',  color: 'var(--fl-artifact-registry)',  parser: 'dissect.regf',    platform: 'windows', labelKey: 'collection.import.artifacts.netprofile' },
  usb:       { name: 'USB History',       color: 'var(--fl-artifact-recycle)',   parser: 'setupapi.dev.log',platform: 'windows', labelKey: 'collection.import.artifacts.usb' },
  schtasks:  { name: 'Scheduled Tasks',   color: 'var(--fl-artifact-registry)',  parser: 'XML',             platform: 'windows', labelKey: 'collection.import.artifacts.schtasks' },
  pwsh:      { name: 'PowerShell History',color: 'var(--fl-artifact-evtx)',      parser: 'PSReadLine',      platform: 'windows' },
  dns:       { name: 'DNS / hosts',       color: 'var(--fl-artifact-srum)',      parser: 'text',            platform: 'windows' },
  webcache:  { name: 'WebCache (IE/Edge)', color: 'var(--fl-artifact-sqle)',      parser: 'dissect.esedb',   platform: 'windows' },
  pcap:      { name: 'Network Capture (PCAP)', color: 'var(--fl-ok)',             parser: 'tshark',          platform: 'windows', labelKey: 'collection.import.artifacts.pcap' },
  wmi:       { name: 'WMI Persistence', color: 'var(--fl-artifact-registry)',  parser: 'dissect.cim',     platform: 'windows', labelKey: 'collection.import.artifacts.wmi' },
  rdpcache:  { name: 'RDP Bitmap Cache', color: 'var(--fl-artifact-lnk)',       parser: 'bmc-tools',       platform: 'windows' },
  amcache:   { name: 'Amcache',           color: 'var(--fl-artifact-amcache)',   parser: 'AmcacheParser',   platform: 'windows' },
  shellbags: { name: 'Shellbags',         color: 'var(--fl-artifact-shellbags)', parser: 'SBECmd',          platform: 'windows' },
  jumplist:  { name: 'Jump Lists',        color: 'var(--fl-artifact-jumplist)',  parser: 'JLECmd',          platform: 'windows' },
  srum:      { name: 'SRUM',              color: 'var(--fl-artifact-srum)',      parser: 'SrumECmd',        platform: 'windows' },
  recycle:   { name: 'Recycle Bin',       color: 'var(--fl-artifact-recycle)',   parser: 'RBCmd',           platform: 'windows' },
  sum:       { name: 'Browser SQLite',    color: 'var(--fl-artifact-sqle)',      parser: 'SQLECmd',         platform: 'windows' },
  sqle:      { name: 'SQLite DBs',        color: 'var(--fl-artifact-sqle)',      parser: 'SQLECmd',         platform: 'windows' },
  wxtcmd:    { name: 'WER / WxTCmd',      color: 'var(--fl-artifact-wer)',       parser: 'WxTCmd',          platform: 'windows' },
  appcompat: { name: 'AppCompat Cache',   color: 'var(--fl-artifact-appcompat)', parser: 'AppCompatParser', platform: 'windows' },
  bits:      { name: 'BITS Jobs',         color: 'var(--fl-artifact-bits)',      parser: 'BitsParser',      platform: 'windows' },
  catscale:  { name: 'CatScale Linux IR', color: 'var(--fl-artifact-catscale)',  parser: 'CatScale',        platform: 'linux'   },
  auditd:    { name: 'Linux Auditd',      color: 'var(--fl-artifact-catscale)',  parser: 'parse_auditd.py', platform: 'linux',   labelKey: 'collection.import.artifacts.auditd' },
  syslog:    { name: 'Linux Syslog',      color: 'var(--fl-artifact-catscale)',  parser: 'parse_syslog.py', platform: 'linux',   labelKey: 'collection.import.artifacts.syslog' },
  bash_history: { name: 'Bash/Zsh History', color: 'var(--fl-artifact-evtx)',   parser: 'parse_bash_history.py', platform: 'linux', labelKey: 'collection.import.artifacts.bash_history' },
  unified_log: { name: 'macOS Unified Log', color: 'var(--fl-artifact-amcache)', parser: 'parse_unified_log.py', platform: 'macos', labelKey: 'collection.import.artifacts.unified_log' },
};

const PIPELINE_STEPS = [
  { key: 'upload',   label: 'Upload' },
  { key: 'extract',  label: 'Extraction' },
  { key: 'detect',   labelKey: 'collection.import.steps.detect' },
  { key: 'parse',    label: 'Parsing' },
  { key: 'hayabusa', label: 'Hayabusa' },
  { key: 'timeline', label: 'Timeline' },
];

const CATSCALE_STEPS = {
  auth_logs:    { label: 'auth.log / secure / syslog',      icon: Lock },
  logon_history:{ labelKey: 'collection.import.catscale_steps.logon_history', icon: Server },
  processes:    { labelKey: 'collection.import.catscale_steps.processes', icon: Cpu },
  network:      { labelKey: 'collection.import.catscale_steps.network', icon: Network },
  history:      { labelKey: 'collection.import.catscale_steps.history', icon: Terminal },
  persistence:  { labelKey: 'collection.import.catscale_steps.persistence', icon: Clock },
  filesystem:   { label: 'Timeline filesystem',              icon: HardDrive },
};

function parseCatScaleArtifact(raw) {
  const m = /^(\w+):(.+?)\s*\((\d+)\)$/.exec(raw.trim());
  if (!m) return { type: raw, label: raw, count: 0 };
  return { type: m[1], label: m[2], count: parseInt(m[3], 10) };
}

const CATSCALE_TYPE_COLORS = {
  auth:         'var(--fl-danger)',
  failed_logon: 'var(--fl-warn)',
  logon:        'var(--fl-gold)',
  process:      'var(--fl-accent)',
  network:      'var(--fl-ok)',
  history:      'var(--fl-accent)',
  cron:         'var(--fl-purple)',
  systemd:      'var(--fl-purple)',
  fstimeline:   'var(--fl-muted)',
};

export default function CollectionImportPanel({ caseId, caseObj, onDone }) {
  const { t, i18n } = useTranslation();
  const { socket, socketId } = useSocket();
  const fileRef = useRef(null);
  const logRef = useRef(null);

  const [step,            setStep]            = useState('idle');
  const [progress,        setProgress]        = useState(0);
  const [detected,        setDetected]        = useState(null);
  const [selected,        setSelected]        = useState([]);
  const [results,         setResults]         = useState(null);
  const [hayabusaResults, setHayabusaResults] = useState(null);
  const [fileHashes,      setFileHashes]      = useState(null);
  const [error,           setError]           = useState('');
  const [fileName,        setFileName]        = useState('');
  const [collDir,         setCollDir]         = useState('');
  const [pipelineLog,     setPipelineLog]     = useState([]);
  const [dragging,        setDragging]        = useState(false);
  const [copiedHash,      setCopiedHash]      = useState(null);
  const [catscaleDetail,  setCatscaleDetail]  = useState(null);
  const [catscaleStep,    setCatscaleStep]    = useState(null);
  const [parserStates,    setParserStates]    = useState({}); // key -> { status, records }
  const doneCountRef = useRef(0);   // parsers finished (parallel-safe progress)
  const totalRef     = useRef(0);   // total parsers in this run
  const locale = i18n.language === 'fr' ? 'fr-FR' : 'en-US';
  const artifactLabel = (type) => {
    const artifact = ARTIFACTS[type];
    return artifact?.labelKey ? t(artifact.labelKey) : artifact?.name || type;
  };
  const catscaleStepLabel = (key) => {
    const stepMeta = CATSCALE_STEPS[key];
    return stepMeta?.labelKey ? t(stepMeta.labelKey) : stepMeta?.label || key;
  };

  // Auto-scroll the pipeline journal to the latest line.
  useEffect(() => { if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight; }, [pipelineLog.length]);

  const keyFromEventName = (name) => {
    if (!name) return null;
    const n = String(name).toLowerCase();
    return Object.keys(ARTIFACTS).find(k =>
      n.includes(k) ||
      n.includes(String(artifactLabel(k)).toLowerCase()) ||
      n.includes(String(ARTIFACTS[k].parser).toLowerCase())
    ) || null;
  };

  useEffect(() => {
    if (!socket) return;
    function handleProgress(data) {
      if (data.type === 'start') {
        setProgress(0);
        doneCountRef.current = 0;
        totalRef.current = data.total || 0;
      } else if (data.type === 'artifact_start') {
        // Don't derive % from data.current — with parallel parsing it's a start index,
        // not a completion count. Progress advances only on artifact_done below.
        addLog('→ ' + data.name + '…');
        const _k = keyFromEventName(data.name);
        if (_k) setParserStates(p => ({ ...p, [_k]: { ...(p[_k] || {}), status: 'parsing' } }));
      } else if (data.type === 'artifact_done') {
        doneCountRef.current += 1;
        const t = totalRef.current || data.total || 1;
        setProgress(Math.min(99, Math.round((doneCountRef.current / t) * 100)));
        if (data.status === 'success' && data.records > 0)
          addLog(t('collection.import.log.artifact_success', { name: data.name, count: data.records.toLocaleString(locale) }));
        else if (data.status === 'skipped')
          addLog(t('collection.import.log.artifact_skipped', { name: data.name }));
        else if (data.status === 'error')
          addLog(t('collection.import.log.artifact_error', { name: data.name }));
        const _kd = keyFromEventName(data.name);
        if (_kd) setParserStates(p => ({ ...p, [_kd]: {
          status: data.status === 'success' ? 'done' : data.status === 'skipped' ? 'skipped' : 'error',
          records: data.records ?? p[_kd]?.records,
        } }));
      } else if (data.type === 'catscale_step') {
        const info = CATSCALE_STEPS[data.step];
        setCatscaleStep(data.step);
        if (info) addLog(t('collection.import.log.catscale_step', { label: catscaleStepLabel(data.step) }));
      } else if (data.type === 'saving') {
        setProgress(p => Math.max(p, 99));
        addLog(t('collection.import.log.saving'));
      }
    }
    socket.on('collection:progress', handleProgress);
    return () => socket.off('collection:progress', handleProgress);
  }, [socket, t, locale]);

  const addLog = (msg) => setPipelineLog(prev => [...prev, { time: new Date().toLocaleTimeString(locale), msg }]);

  const handleFile = async (file) => {
    if (!file || !caseId) return;
    setFileName(file.name);
    setError('');
    setPipelineLog([]);
    setHayabusaResults(null);
    setResults(null);

    if (!socket) { setError(t('collection.import.errors.socket_required')); return; }

    const formData = new FormData();
    formData.append('collection', file);
    formData.append('socketId', socket.id || '');

    try {
      setStep('uploading');
      setProgress(0);
      addLog(t('collection.import.log.uploading_file', { name: file.name, size: (file.size / 1024 / 1024).toFixed(1) }));

      const importRes = await collectionAPI.import(caseId, formData, (e) => {
        if (e.total) setProgress(Math.round((e.loaded / e.total) * 50));
      });

      const dir = importRes.data?.collection_dir || '';
      setCollDir(dir);
      addLog(t('collection.import.log.upload_done'));
      setStep('extracting');
      setProgress(55);

      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          socket.off('collection:import:done', onDone_);
          socket.off('collection:import:error', onError_);
          reject(new Error(t('collection.import.errors.extraction_timeout')));
        }, 20 * 60 * 1000);

        function onDone_(data) {
          clearTimeout(timer);
          socket.off('collection:import:done', onDone_);
          socket.off('collection:import:error', onError_);

          setStep('detecting');
          setProgress(58);
          addLog(t('collection.import.log.detecting_artifacts'));

          const detectedArtifacts = data?.detected_artifacts || null;
          if (data?.collection_dir) setCollDir(data.collection_dir);
          if (data?.hashes) setFileHashes(data.hashes);

          if (detectedArtifacts && Object.keys(detectedArtifacts).length > 0) {
            const normalized = {};
            for (const [k, v] of Object.entries(detectedArtifacts)) {
              normalized[k] = {
                n: v.count || v.n || 0,
                sz: v.size || v.sz || '?',
                ok: (v.count || v.n || 0) > 0,
                platform: v.platform || null,
              };
            }
            setDetected(normalized);
            setSelected(Object.keys(normalized).filter(k => normalized[k].ok));
            const isCatScale = 'catscale' in normalized;
            addLog(isCatScale
              ? t('collection.import.log.catscale_detected', { count: normalized.catscale.n })
              : t('collection.import.log.windows_detected', { count: Object.keys(normalized).length }));
          } else {
            addLog(t('collection.import.log.no_artifacts_detected'));
            setDetected({});
            setSelected([]);
          }

          setStep('detected');
          setProgress(60);
          resolve();
        }

        function onError_(data) {
          clearTimeout(timer);
          socket.off('collection:import:done', onDone_);
          socket.off('collection:import:error', onError_);
          reject(new Error(data?.details || data?.error || t('collection.import.errors.extraction')));
        }

        socket.on('collection:import:done', onDone_);
        socket.on('collection:import:error', onError_);
      });
    } catch (err) {
      const rawErr = err.response?.data?.error;
      const msg = (typeof rawErr === 'string' ? rawErr : rawErr?.message) || err.response?.data?.message || err.message || t('collection.import.errors.import');
      setError(msg);
      addLog(t('collection.import.log.fatal_error', { error: msg }));
      setStep('idle');
    }
  };

  const isCatScaleCollection = detected && 'catscale' in detected;

  const startParsing = async () => {
    if (!caseId || selected.length === 0) return;
    setParserStates(Object.fromEntries(selected.map(k => [k, { status: 'queued' }])));
    try {
      setStep('parsing');
      setProgress(0);
      const parseTypes = isCatScaleCollection ? ['catscale'] : selected;
      const hasEvtx = !isCatScaleCollection && parseTypes.includes('evtx');

      addLog(isCatScaleCollection
        ? t('collection.import.log.start_catscale_parse')
        : t('collection.import.log.start_parse', { count: parseTypes.length }));
      if (!isCatScaleCollection)
        addLog(t('collection.import.log.parsers', { parsers: parseTypes.map(t => ARTIFACTS[t]?.parser || t).join(', ') }));

      try {
        await collectionAPI.parse(caseId, { collection_dir: collDir, artifact_types: isCatScaleCollection ? 'all' : parseTypes, socketId });
      } catch (e) {
        const errMsg = (e.response?.data?.error || e.message || t('common.unknown'))
          + (e.response?.data?.details ? ' — ' + e.response.data.details : '');
        addLog(t('collection.import.log.parse_api_error', { error: errMsg }));
        setError(errMsg);
        setStep('idle');
        return;
      }

      const doneData = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          socket.off('collection:parse:done', onParseDone);
          socket.off('collection:parse:error', onParseError);
          reject(new Error(t('collection.import.errors.parsing_timeout')));
        }, 2 * 60 * 60 * 1000);

        function onParseDone(data) {
          clearTimeout(timer);
          socket.off('collection:parse:done', onParseDone);
          socket.off('collection:parse:error', onParseError);
          resolve(data);
        }
        function onParseError(data) {
          clearTimeout(timer);
          socket.off('collection:parse:done', onParseDone);
          socket.off('collection:parse:error', onParseError);
          reject(new Error(data?.details || data?.error || t('collection.import.errors.parsing')));
        }

        socket.on('collection:parse:done', onParseDone);
        socket.on('collection:parse:error', onParseError);
      });

      const perResults = doneData?.results || {};
      let totalOk = 0, totalSkip = 0, totalErr = 0;
      for (const r of Object.values(perResults)) {
        if (r.status === 'success') totalOk++;
        else if (r.status === 'skipped') totalSkip++;
        else if (r.status === 'error') {
          totalErr++;
          if (r.tool_output) addLog('    stdout: ' + r.tool_output);
        }
      }

      const total = doneData?.total_records || 0;
      addLog(t('collection.import.log.parsing_done', {
        count: total.toLocaleString(locale),
        ok: totalOk,
        skipped: totalSkip,
        errors: totalErr,
      }));
      setResults({ total, types: parseTypes });
      if (isCatScaleCollection && perResults.catscale) {
        setCatscaleDetail({
          hostname: perResults.catscale.hostname || 'linux-host',
          os_info: perResults.catscale.os_info || '',
          artifacts: perResults.catscale.artifacts || [],
          events: perResults.catscale.events || total,
        });
      }
      setProgress(hasEvtx ? 84 : 90);

      if (hasEvtx) {
        setStep('hayabusa');
        setProgress(80);
        addLog(t('collection.import.log.start_hayabusa'));
        try {
          const hayRes = await collectionAPI.runHayabusa(caseId);
          setHayabusaResults(hayRes.data);
          addLog(t('collection.import.log.hayabusa_done', { count: hayRes.data.total || hayRes.data.detections?.length || 0 }));
        } catch (e) {
          addLog(t('collection.import.log.hayabusa_error', { error: e.response?.data?.error || e.message || t('collection.import.errors.unavailable') }));
        }
      }

      setStep('done');
      setProgress(100);
      addLog(t('collection.import.log.pipeline_done'));
      onDone?.();
    } catch (err) {
      setError(err.message || t('collection.import.errors.parsing'));
      addLog(t('collection.import.log.fatal_error', { error: err.message }));
      setStep('idle');
    }
  };

  const reset = () => {
    setStep('idle'); setDetected(null); setResults(null);
    setHayabusaResults(null); setPipelineLog([]); setFileName('');
    setFileHashes(null); setError(''); setCatscaleDetail(null); setCatscaleStep(null);
  };

  const toggle = (t) => setSelected(p => p.includes(t) ? p.filter(x => x !== t) : [...p, t]);
  const isProcessing = ['uploading', 'extracting', 'detecting', 'parsing', 'hayabusa'].includes(step);

  const currentStepIdx = PIPELINE_STEPS.findIndex(s =>
    (step === 'uploading' && s.key === 'upload') || (step === 'extracting' && s.key === 'extract') ||
    (step === 'detecting' && s.key === 'detect') || (step === 'parsing' && s.key === 'parse') ||
    (step === 'hayabusa' && s.key === 'hayabusa') || (step === 'done' && s.key === 'timeline')
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

      {step === 'idle' && (
        <div
          className="rounded-xl cursor-pointer transition-all"
          style={{
            border: `2px dashed ${dragging ? 'var(--fl-accent)' : 'var(--fl-border2)'}`,
            background: dragging ? 'color-mix(in srgb, var(--fl-accent) 6%, transparent)' : 'var(--fl-bg)',
            padding: '48px 24px',
          }}
          onClick={() => fileRef.current?.click()}
          onDragOver={e => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={async e => {
            e.preventDefault();
            setDragging(false);
            const items = [...(e.dataTransfer.items || [])];
            const files = [...(e.dataTransfer.files || [])];

            // Check if any item is a directory
            const hasDirectory = items.some(it => it.webkitGetAsEntry?.()?.isDirectory);
            // Check if multiple artifact files dropped
            const allArtifacts = files.length > 1 && files.every(f => {
              const ext = '.' + f.name.split('.').pop().toLowerCase();
              return ARTIFACT_EXTS.has(ext);
            });

            if (hasDirectory || allArtifacts) {
              setStep('uploading');
              setProgress(0);
              addLog(t('collection.import.log.creating_zip_from_files'));
              const zipFile = await buildZipFromItems(items.length ? items : files.map(f => ({ webkitGetAsEntry: () => ({ isFile: true, isDirectory: false, file: cb => cb(f), name: f.name }) })));
              if (!zipFile) { setError(t('collection.import.errors.no_file_to_archive')); setStep('idle'); return; }
              addLog(t('collection.import.log.zip_created_uploading', { size: (zipFile.size / 1024 / 1024).toFixed(1) }));
              setStep('idle');
              handleFile(zipFile);
            } else {
              handleFile(files[0]);
            }
          }}
        >
          <div className="text-center">
            <div style={{ width: 64, height: 64, borderRadius: '50%', margin: '0 auto 16px', display: 'flex', alignItems: 'center', justifyContent: 'center',
              background: dragging ? 'color-mix(in srgb, var(--fl-accent) 12%, transparent)' : 'var(--fl-card)',
              border: `1px solid ${dragging ? 'color-mix(in srgb, var(--fl-accent) 30%, transparent)' : 'var(--fl-border)'}`, transition: 'all 0.2s' }}>
              <Package size={28} style={{ color: dragging ? 'var(--fl-accent)' : 'var(--fl-muted)', transition: 'color 0.2s' }} />
            </div>
            <p className="text-base font-semibold mb-1" style={{ color: 'var(--fl-text)' }}>
              {t('collection.import.drop_title')}
            </p>
            <p className="text-sm mb-3" style={{ color: 'var(--fl-dim)' }}>{t('collection.import.drop_subtitle')}</p>
            {caseObj && (
              <p className="text-xs mb-3" style={{ color: 'var(--fl-dim)' }}>
                {t('collection.import.target_case')} <strong style={{ color: 'var(--fl-accent)' }}>{caseObj.case_number}</strong>
              </p>
            )}
            <div style={{ display: 'flex', justifyContent: 'center', gap: 12, marginBottom: 10 }}>
              <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '2px 8px', borderRadius: 3, background: 'color-mix(in srgb, var(--fl-accent) 9%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 19%, transparent)' }}>
                Windows — KAPE · Velociraptor · Magnet · CyLR
              </span>
              <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '2px 8px', borderRadius: 3, background: 'color-mix(in srgb, var(--fl-ok) 9%, transparent)', color: 'var(--fl-ok)', border: '1px solid color-mix(in srgb, var(--fl-ok) 19%, transparent)' }}>
                Linux — CatScale
              </span>
            </div>
            <p className="text-xs font-mono" style={{ color: 'var(--fl-muted)' }}>{t('collection.import.accepted_formats')}</p>
          </div>
          <input ref={fileRef} type="file" accept=".zip,.tar,.gz,.7z,.evtx,.pf,.lnk,.dat,.hve,.db,.sqlite,.pcap,.pcapng,.cap" multiple className="hidden"
            onChange={async e => {
              const files = [...e.target.files];
              if (files.length === 0) return;
              const allArtifacts = files.length > 1 && files.every(f => {
                const ext = '.' + f.name.split('.').pop().toLowerCase();
                return ARTIFACT_EXTS.has(ext);
              });
              if (allArtifacts) {
                addLog(t('collection.import.log.creating_zip_from_selection'));
                const zipFile = await buildZipFromItems(files.map(f => ({ webkitGetAsEntry: () => ({ isFile: true, isDirectory: false, file: cb => cb(f), name: f.name }) })));
                if (zipFile) { addLog(t('collection.import.log.zip_created', { size: (zipFile.size / 1024 / 1024).toFixed(1) })); handleFile(zipFile); }
              } else {
                handleFile(files[0]);
              }
            }}
          />
        </div>
      )}

      {step !== 'idle' && step !== 'done' && fileName && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px', borderRadius: 6, background: 'var(--fl-card)', border: '1px solid var(--fl-border)' }}>
          <Upload size={12} style={{ color: 'var(--fl-accent)' }} />
          <span style={{ fontSize: 12, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)', flex: 1 }}>{fileName}</span>
        </div>
      )}

      {isProcessing && (
        <div className="fl-card p-4">
          <div style={{ display: 'flex', alignItems: 'flex-start', marginBottom: 20 }}>
            {PIPELINE_STEPS.map((ps, i) => {
              const isDone = i < currentStepIdx;
              const isActive = i === currentStepIdx;
              const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
              return (
                <div key={ps.key} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', position: 'relative', minWidth: 0 }}>
                  {/* connector line to the next node (flowing gradient on the active step) */}
                  {i < PIPELINE_STEPS.length - 1 && (
                    <div className={isActive ? 'fl-flow' : ''} style={{ position: 'absolute', top: 13, left: '50%', width: '100%', height: 2, zIndex: 0, transition: 'background 0.4s',
                      background: isDone ? 'var(--fl-ok)'
                        : isActive ? 'linear-gradient(90deg, color-mix(in srgb, var(--fl-accent) 20%, var(--fl-border2)), var(--fl-accent), color-mix(in srgb, var(--fl-accent) 20%, var(--fl-border2)))'
                        : 'var(--fl-border2)' }} />
                  )}
                  <div style={{ position: 'relative', zIndex: 1, width: 26, height: 26, borderRadius: '50%',
                    display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: MONO, fontSize: 11, fontWeight: 700,
                    background: isDone ? 'var(--fl-ok)' : isActive ? 'var(--fl-accent)' : 'var(--fl-panel)',
                    color: (isDone || isActive) ? '#fff' : 'var(--fl-muted)',
                    border: (isDone || isActive) ? 'none' : '1px solid var(--fl-border)',
                    boxShadow: isActive ? '0 0 0 4px color-mix(in srgb, var(--fl-accent) 16%, transparent)' : 'none',
                    transition: 'all 0.3s' }}>
                    {isDone ? '✓' : i + 1}
                  </div>
                  <span style={{ marginTop: 8, fontSize: 10.5, fontFamily: MONO, textAlign: 'center', letterSpacing: '0.02em',
                    color: isActive ? 'var(--fl-accent)' : isDone ? 'var(--fl-ok)' : 'var(--fl-muted)', fontWeight: isActive ? 700 : 400, transition: 'color 0.3s' }}>
                    {ps.labelKey ? t(ps.labelKey) : ps.label}
                  </span>
                </div>
              );
            })}
          </div>
          <div className="flex justify-between items-center mb-2">
            <span className="text-sm font-semibold flex items-center gap-2" style={{ color: 'var(--fl-text)' }}>
              <Loader2 size={14} className="animate-spin" style={{ color: 'var(--fl-accent)' }} />
              {step === 'uploading'  && t('collection.import.status.uploading')}
              {step === 'extracting' && t('collection.import.status.extracting')}
              {step === 'detecting'  && t('collection.import.status.detecting')}
              {step === 'parsing'    && isCatScaleCollection && catscaleStep
                ? <span>{t('collection.import.status.parsing_linux')} <span style={{ color: 'var(--fl-ok)' }}>{catscaleStepLabel(catscaleStep)}</span></span>
                : step === 'parsing' && t('collection.import.status.parsing')}
              {step === 'hayabusa'   && t('collection.import.status.hayabusa')}
            </span>
            <span className="font-mono text-sm font-bold" style={{ color: 'var(--fl-accent)' }}>{progress}%</span>
          </div>
          <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--fl-panel)' }}>
            <div className="h-full rounded-full transition-all duration-500"
              style={{ width: `${progress}%`, background: 'linear-gradient(90deg, var(--fl-accent), var(--fl-purple))' }} />
          </div>
        </div>
      )}

      {fileHashes && (fileHashes.md5 || fileHashes.sha256) && (
        <div className="fl-card p-4">
          <div className="flex items-center gap-2 mb-3 flex-wrap">
            <p className="text-xs font-mono uppercase tracking-widest" style={{ color: 'var(--fl-dim)', margin: 0 }}>
              {t('collection.import.integrity_title', { fileName })}
            </p>
            <span style={{ flex: 1 }} />
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 9.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
              padding: '2px 9px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-ok) 10%, transparent)',
              color: 'var(--fl-ok)', border: '1px solid color-mix(in srgb, var(--fl-ok) 25%, transparent)' }}>
              <CheckCircle2 size={11} /> {t('collection.import.integrity_verified', { date: new Date().toLocaleString(locale, { hour12: false }) })}
            </span>
          </div>
          <div className="space-y-1.5">
            {[['MD5', fileHashes.md5, 'var(--fl-muted)'], ['SHA-1', fileHashes.sha1, 'var(--fl-gold)'], ['SHA-256', fileHashes.sha256, 'var(--fl-accent)']].map(([label, value, color]) => value && (
              <div key={label} className="flex items-center gap-3 rounded-md px-3 py-2" style={{ background: 'var(--fl-bg)', border: '1px solid var(--fl-border2)' }}>
                <span className="font-mono flex-shrink-0" style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: '0.06em', padding: '2px 7px', borderRadius: 4, background: `color-mix(in srgb, ${color} 10%, transparent)`, color, border: `1px solid color-mix(in srgb, ${color} 22%, transparent)`, minWidth: 56, textAlign: 'center' }}>{label}</span>
                <span className="font-mono text-xs flex-1 break-all" style={{ color: 'var(--fl-dim)' }}>{value}</span>
                <button onClick={() => { navigator.clipboard.writeText(value); setCopiedHash(label); setTimeout(() => setCopiedHash(c => c === label ? null : c), 1400); }}
                  className="flex-shrink-0 inline-flex items-center gap-1 text-xs px-2 py-1 rounded font-mono"
                  style={{ background: 'transparent', color: copiedHash === label ? 'var(--fl-ok)' : 'var(--fl-muted)', border: `1px solid ${copiedHash === label ? 'color-mix(in srgb, var(--fl-ok) 35%, transparent)' : 'var(--fl-border)'}`, transition: 'all 0.15s' }}>
                  {copiedHash === label ? <><CheckCircle2 size={11} /> {t('collection.import.copied')}</> : <><Copy size={11} /> {t('common.copy').toLowerCase()}</>}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {step === 'detected' && detected && Object.keys(detected).length === 0 && (
        <div className="fl-card p-5 text-center">
          <AlertTriangle size={28} style={{ color: 'var(--fl-gold)', margin: '0 auto 8px' }} />
          <p className="text-sm font-mono" style={{ color: 'var(--fl-dim)' }}>{t('collection.import.no_artifact_title')}</p>
          <p className="text-xs mt-1" style={{ color: 'var(--fl-dim)' }}>{t('collection.import.no_artifact_hint')}</p>
        </div>
      )}

      {step === 'detected' && detected && Object.keys(detected).length > 0 && (
        <div className="fl-card p-4">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <p className="text-xs font-mono uppercase tracking-widest" style={{ color: 'var(--fl-dim)' }}>{t('collection.import.detected_artifacts')}</p>
              {isCatScaleCollection ? (
                <span className="text-xs font-mono px-2 py-0.5 rounded" style={{ background: 'color-mix(in srgb, var(--fl-ok) 9%, transparent)', color: 'var(--fl-ok)', border: '1px solid color-mix(in srgb, var(--fl-ok) 19%, transparent)' }}>Linux / CatScale</span>
              ) : (
                <span className="text-xs font-mono px-2 py-0.5 rounded" style={{ background: 'color-mix(in srgb, var(--fl-accent) 9%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 19%, transparent)' }}>Windows</span>
              )}
            </div>
            {!isCatScaleCollection && (
              <button onClick={() => setSelected(Object.keys(detected).filter(k => detected[k].ok !== false))} className="fl-btn fl-btn-ghost fl-btn-sm">
                {t('collection.import.select_all')}
              </button>
            )}
          </div>

          {isCatScaleCollection ? (
            <div style={{ background: 'var(--fl-bg)', border: '1px solid color-mix(in srgb, var(--fl-ok) 19%, transparent)', borderRadius: 8, padding: '14px 16px', marginBottom: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                <Terminal size={14} style={{ color: 'var(--fl-ok)' }} />
                <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--fl-ok)' }}>{t('collection.import.catscale_archive')}</span>
                <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)', marginLeft: 'auto', fontFeatureSettings: '"tnum"' }}>
                  {t('collection.import.file_count', { count: (detected.catscale?.n || 0).toLocaleString(locale) })}{detected.catscale?.sz && detected.catscale.sz !== '?' ? ` · ${detected.catscale.sz}` : ''}
                </span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6 }}>
                {Object.entries(CATSCALE_STEPS).map(([key, { icon: Icon }]) => (
                  <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '5px 10px', borderRadius: 5, background: 'var(--fl-panel)', border: '1px solid var(--fl-panel)' }}>
                    <Icon size={11} style={{ color: 'var(--fl-ok)', flexShrink: 0 }} />
                    <span style={{ fontSize: 11, color: 'var(--fl-dim)' }}>{catscaleStepLabel(key)}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-3 gap-2 mb-4">
              {Object.entries(detected).map(([type, info]) => {
                const sel = selected.includes(type);
                const art = ARTIFACTS[type];
                const color = art?.color || 'var(--fl-dim)';
                const disabled = info.ok === false;
                const n = info.n || 0;
                return (
                  <div key={type} onClick={() => !disabled && toggle(type)}
                    className="flex items-center gap-3 rounded-lg transition-all"
                    style={{ cursor: disabled ? 'default' : 'pointer', padding: '11px 13px',
                      background: sel ? 'color-mix(in srgb, var(--fl-accent) 7%, transparent)' : 'var(--fl-bg)',
                      border: `1px solid ${sel ? 'color-mix(in srgb, var(--fl-accent) 38%, transparent)' : 'var(--fl-border2)'}`,
                      opacity: disabled ? 0.4 : 1 }}
                    onMouseEnter={e => { if (!disabled && !sel) { e.currentTarget.style.borderColor = 'var(--fl-border3)'; e.currentTarget.style.background = 'var(--fl-card)'; } }}
                    onMouseLeave={e => { if (!disabled && !sel) { e.currentTarget.style.borderColor = 'var(--fl-border2)'; e.currentTarget.style.background = 'var(--fl-bg)'; } }}>
                    {/* Uniform accent checkbox — selection reads as one signal, not 16 rainbow colors */}
                    <div className="flex-shrink-0 flex items-center justify-center"
                      style={{ width: 16, height: 16, borderRadius: 4,
                        border: `1.5px solid ${sel ? 'var(--fl-accent)' : 'var(--fl-border3)'}`,
                        background: sel ? 'var(--fl-accent)' : 'transparent', transition: 'all 0.15s' }}>
                      {sel && <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="4"><polyline points="20 6 9 17 4 12" /></svg>}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2" style={{ marginBottom: 2 }}>
                        {/* Square category dot — the only place the artifact color reads as signal */}
                        <span style={{ width: 7, height: 7, borderRadius: 2, flexShrink: 0, background: color, display: 'inline-block' }} />
                        <span className="text-sm font-semibold truncate" style={{ color: 'var(--fl-text)' }}>{artifactLabel(type)}</span>
                        {type === 'evtx' && (
                          <span className="flex-shrink-0" style={{ fontSize: 8.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, letterSpacing: '0.04em', textTransform: 'uppercase', padding: '1px 5px', borderRadius: 3, background: 'color-mix(in srgb, var(--fl-accent) 12%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 24%, transparent)' }}>Hayabusa</span>
                        )}
                      </div>
                      <div className="text-xs font-mono" style={{ color: 'var(--fl-muted)', fontFeatureSettings: '"tnum"' }}>
                        {t('collection.import.file_count', { count: n.toLocaleString(locale) })}{info.sz && info.sz !== '?' ? ` · ${info.sz}` : ''}
                      </div>
                    </div>
                    {disabled && <span className="flex-shrink-0" style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--fl-danger)' }}>{t('collection.import.absent')}</span>}
                  </div>
                );
              })}
            </div>
          )}

          <div className="flex justify-between items-center">
            <div className="flex items-center gap-3">
              {isCatScaleCollection ? (
                <span className="text-sm" style={{ color: 'var(--fl-ok)' }}>{t('collection.import.linux_parsers')}</span>
              ) : (
                <>
                  <span className="text-sm" style={{ color: 'var(--fl-dim)' }}><strong style={{ color: 'var(--fl-text)' }}>{selected.length}</strong> {t('collection.import.selected_count_suffix')}</span>
                  {selected.includes('evtx') && (
                    <span className="fl-badge" style={{ background: 'color-mix(in srgb, var(--fl-accent) 7%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 15%, transparent)' }}>
                      <Shield size={10} className="inline mr-1" />{t('collection.import.hayabusa_included')}
                    </span>
                  )}
                </>
              )}
            </div>
            <button onClick={startParsing} disabled={!selected.length && !isCatScaleCollection}
              className="fl-btn fl-btn-primary"
              style={{ opacity: (selected.length || isCatScaleCollection) ? 1 : 0.5 }}>
              <Cpu size={14} /> {isCatScaleCollection ? t('collection.import.analyze_linux') : t('collection.import.start_pipeline')}
            </button>
          </div>
        </div>
      )}

      {step === 'done' && (
        <div className="fl-card p-5">
          <div className="flex items-center gap-3 mb-4">
            <div style={{ width: 34, height: 34, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
              background: 'color-mix(in srgb, var(--fl-ok) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-ok) 30%, transparent)' }}>
              <CheckCircle2 size={18} style={{ color: 'var(--fl-ok)' }} />
            </div>
            <div>
              <div className="text-base font-semibold" style={{ color: 'var(--fl-text)' }}>{t('collection.import.analysis_done')}</div>
              {results && <div style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)', marginTop: 2 }}>
                <span style={{ color: 'var(--fl-ok)', fontWeight: 700 }}>{(results.total || 0).toLocaleString(locale)}</span> {t('collection.import.events_label')} · {t('collection.import.artifact_type_count', { count: results.types?.length || 0 })}
              </div>}
            </div>
            {catscaleDetail && (
              <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-ok)' }}>
                <Server size={11} />
                {catscaleDetail.hostname}
                {catscaleDetail.os_info && <span style={{ color: 'var(--fl-dim)' }}>— {catscaleDetail.os_info}</span>}
              </span>
            )}
          </div>

          {catscaleDetail ? (
            <div className="mb-4">
              <p className="text-xs font-mono mb-3" style={{ color: 'var(--fl-dim)' }}>
                {t('collection.import.events_imported', { count: catscaleDetail.events.toLocaleString(locale) })}
              </p>
              {catscaleDetail.artifacts.length > 0 && (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 4 }}>
                  {catscaleDetail.artifacts.map((raw, i) => {
                    const { type, label, count } = parseCatScaleArtifact(raw);
                    const color = CATSCALE_TYPE_COLORS[type] || 'var(--fl-muted)';
                    return (
                      <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 10px', borderRadius: 5, background: 'var(--fl-bg)', border: `1px solid color-mix(in srgb, ${color} 13%, transparent)` }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: color, flexShrink: 0 }} />
                        <span style={{ fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</span>
                        <span style={{ fontSize: 11, fontWeight: 700, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color, flexShrink: 0 }}>{count.toLocaleString(locale)}</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          ) : results && (
            <div className="mb-4">
              <div className="flex flex-wrap gap-2 mb-2">
                {results.types.map(t => {
                  const art = ARTIFACTS[t];
                  return (
                    <span key={t} className="fl-badge" style={{ background: `color-mix(in srgb, ${art?.color} 8%, transparent)`, color: art?.color, border: `1px solid color-mix(in srgb, ${art?.color} 16%, transparent)` }}>
                      {art?.parser || t}
                    </span>
                  );
                })}
              </div>
              <p className="text-sm" style={{ color: 'var(--fl-dim)' }}>{t('collection.import.records_imported', { count: results.total.toLocaleString(locale) })}</p>
            </div>
          )}

          {hayabusaResults && (
            <div className="mb-4 rounded-lg p-3 flex items-center gap-4" style={{ background: 'var(--fl-bg)', border: '1px solid var(--fl-border)' }}>
              <Shield size={16} style={{ color: 'var(--fl-danger)' }} />
              <span className="text-xs font-mono" style={{ color: 'var(--fl-dim)' }}>Hayabusa</span>
              {['critical', 'high', 'medium', 'low'].map(l => {
                const colors = { critical: 'var(--fl-danger)', high: 'var(--fl-warn)', medium: 'var(--fl-gold)', low: 'var(--fl-ok)' };
                return <span key={l} className="text-xs font-mono font-bold" style={{ color: colors[l] }}>{hayabusaResults.stats?.[l] || 0} {l}</span>;
              })}
            </div>
          )}
          <button onClick={reset} className="fl-btn fl-btn-secondary">{t('collection.import.new_collection')}</button>
        </div>
      )}

      {error && (
        <div className="p-3 rounded-lg text-sm flex items-center gap-2" style={{ background: 'rgba(218,54,51,0.08)', border: '1px solid rgba(218,54,51,0.2)', color: 'var(--fl-danger)' }}>
          <AlertTriangle size={14} /> {error}
          <button onClick={() => setError('')} className="ml-auto"><X size={14} /></button>
        </div>
      )}

      {pipelineLog.length > 0 && (
        <details>
          <summary style={{ cursor: 'pointer', fontSize: 10.5, fontFamily: 'var(--f-mono, monospace)', color: 'var(--fl-muted)', padding: '4px 0' }}>
            {t('collection.pm_details')}
          </summary>
          <div className="rounded-xl border" style={{ background: 'var(--fl-bg)', borderColor: 'var(--fl-border2)', overflow: 'hidden' }}>
            <div className="px-4 py-2 flex items-center gap-2" style={{ borderBottom: '1px solid var(--fl-border2)' }}>
              <Terminal size={12} style={{ color: 'var(--fl-muted)' }} />
              <span className="text-xs font-mono uppercase" style={{ letterSpacing: '0.1em', color: 'var(--fl-muted)' }}>{t('collection.import.pipeline_log')}</span>
              <span style={{ flex: 1 }} />
              <span className="text-xs font-mono" style={{ color: 'var(--fl-subtle)', fontFeatureSettings: '"tnum"' }}>{t('collection.import.entry_count', { count: pipelineLog.length })}</span>
            </div>
            <div ref={logRef} className="p-4 space-y-0.5 font-mono text-xs overflow-y-auto" style={{ maxHeight: 220, lineHeight: 1.6, scrollBehavior: 'smooth' }}>
              {pipelineLog.map((log, i) => {
                const isErr = log.msg.includes('✗');
                const isOk = log.msg.includes('✓');
                const isStep = log.msg.trimStart().startsWith('→');
                const color = isErr ? 'var(--fl-danger)' : isOk ? 'var(--fl-ok)' : isStep ? 'var(--fl-accent)' : 'var(--fl-dim)';
                return (
                  <div key={i} className="fl-log-in">
                    <span style={{ color: 'var(--fl-subtle)' }}>[{log.time}]</span>{' '}
                    <span style={{ color }}>{log.msg}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </details>
      )}
    </div>
  );
}
