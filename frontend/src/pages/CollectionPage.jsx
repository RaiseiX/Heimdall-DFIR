import { useState, useEffect, useRef } from 'react';
import { useSocket } from '../hooks/useSocket';
import { Upload, CheckCircle2, Loader2, Package, Cpu, Shield, FolderOpen, ChevronRight, AlertTriangle, X } from 'lucide-react';
import { collectionAPI, casesAPI } from '../utils/api';

const ARTIFACTS = {

  evtx:      { name: 'Event Logs (EVTX)', color: 'var(--fl-accent)', parser: 'EvtxECmd',      platform: 'windows' },
  prefetch:  { name: 'Prefetch',          color: 'var(--fl-ok)', parser: 'PECmd',          platform: 'windows' },
  mft:       { name: '$MFT',              color: 'var(--fl-purple)', parser: 'MFTECmd',        platform: 'windows' },
  lnk:       { name: 'LNK Shortcuts',     color: 'var(--fl-warn)', parser: 'LECmd',          platform: 'windows' },
  registry:  { name: 'Registry Hives',    color: 'var(--fl-pink)', parser: 'RECmd',          platform: 'windows' },
  amcache:   { name: 'Amcache',           color: 'var(--fl-gold)', parser: 'AmcacheParser',  platform: 'windows' },
  shellbags: { name: 'Shellbags',         color: 'var(--fl-purple)', parser: 'SBECmd',         platform: 'windows' },
  jumplist:  { name: 'Jump Lists',        color: 'var(--fl-accent)', parser: 'JLECmd',         platform: 'windows' },
  srum:      { name: 'SRUM',              color: 'var(--fl-danger)', parser: 'SrumECmd',       platform: 'windows' },
  recycle:   { name: 'Recycle Bin',       color: 'var(--fl-ok)', parser: 'RBCmd',          platform: 'windows' },
  sqle:      { name: 'Browser SQLite',    color: 'var(--fl-purple)', parser: 'SQLECmd',        platform: 'windows' },
  wer:       { name: 'WER Reports',       color: 'var(--fl-pink)', parser: 'WerParser',      platform: 'windows' },

  catscale:  { name: 'CatScale Linux IR', color: 'var(--fl-ok)', parser: 'CatScale',       platform: 'linux' },
};

const PIPELINE_STEPS = [
  { key: 'upload', label: 'Upload' },
  { key: 'extract', label: 'Extraction' },
  { key: 'detect', label: 'Detection' },
  { key: 'parse', label: 'Parsing' },
  { key: 'hayabusa', label: 'Hayabusa' },
  { key: 'timeline', label: 'Timeline' },
];

export default function CollectionPage() {
  const { socket, socketId } = useSocket();
  const fileRef = useRef(null);
  const [cases, setCases] = useState([]);
  const [selectedCase, setSelectedCase] = useState('');
  const [loadingCases, setLoadingCases] = useState(true);
  const [step, setStep] = useState('idle');
  const [progress, setProgress] = useState(0);
  const [detected, setDetected] = useState(null);
  const [selected, setSelected] = useState([]);
  const [results, setResults] = useState(null);
  const [hayabusaResults, setHayabusaResults] = useState(null);
  const [fileHashes, setFileHashes] = useState(null);
  const [error, setError] = useState('');
  const [fileName, setFileName] = useState('');
  const [collDir, setCollDir] = useState('');
  const [pipelineLog, setPipelineLog] = useState([]);
  const [dragging, setDragging] = useState(false);

  useEffect(() => {
    setLoadingCases(true);
    casesAPI.list({}).then(({ data }) => {
      const c = data.cases || (Array.isArray(data) ? data : []);
      setCases(c);
      if (c.length > 0) setSelectedCase(c[0].id);
      setLoadingCases(false);
    }).catch(() => setLoadingCases(false));
  }, []);

  useEffect(() => {
    if (!socket) return;
    function handleProgress(data) {
      if (data.type === 'start') {
        setProgress(0);
      } else if (data.type === 'artifact_start') {
        const pct = data.total > 0 ? Math.round(((data.current - 1) / data.total) * 80) : 0;
        setProgress(pct);
        addLog('→ ' + data.name + '…');
      } else if (data.type === 'artifact_done') {
        const pct = data.total > 0 ? Math.round((data.current / data.total) * 80) : 0;
        setProgress(pct);
        if (data.status === 'success' && data.records > 0)
          addLog('  ✓ ' + data.name + ': ' + data.records.toLocaleString() + ' records');
        else if (data.status === 'skipped')
          addLog('  – ' + data.name + ': skipped');
        else if (data.status === 'error')
          addLog('  ✗ ' + data.name + ': error');
      } else if (data.type === 'saving') {
        setProgress(82);
        addLog('Saving to database…');
      }
    }
    socket.on('collection:progress', handleProgress);
    return () => socket.off('collection:progress', handleProgress);
  }, [socket]);

  const addLog = (msg) => setPipelineLog(prev => [...prev, { time: new Date().toLocaleTimeString('en-US'), msg }]);

  const handleFile = async (file) => {
    if (!file || !selectedCase) return;
    setFileName(file.name);
    setError('');
    setPipelineLog([]);
    setHayabusaResults(null);
    setResults(null);

    if (!socket) {
      setError('Socket connection required — reload the page');
      return;
    }

    const formData = new FormData();
    formData.append('collection', file);

    formData.append('socketId', socket.id || '');

    try {
      setStep('uploading');
      setProgress(0);
      addLog('Uploading ' + file.name + ' (' + (file.size / 1024 / 1024).toFixed(1) + ' MB)...');

      const importRes = await collectionAPI.import(selectedCase, formData, (e) => {
        if (e.total) setProgress(Math.round((e.loaded / e.total) * 50));
      });

      const dir = importRes.data?.collection_dir || '';
      setCollDir(dir);
      addLog('Upload complete — extraction in progress...');
      setStep('extracting');
      setProgress(55);

      await new Promise((resolve, reject) => {

        const timer = setTimeout(() => {
          socket.off('collection:import:done', onDone);
          socket.off('collection:import:error', onError);
          reject(new Error('Timeout extraction (> 20 min)'));
        }, 20 * 60 * 1000);

        function onDone(data) {
          clearTimeout(timer);
          socket.off('collection:import:done', onDone);
          socket.off('collection:import:error', onError);

          setStep('detecting');
          setProgress(58);
          addLog('Detecting forensic artifacts...');

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
            addLog(
              isCatScale
                ? `Linux collection detected — CatScale (${normalized.catscale.n} files)`
                : `${Object.keys(normalized).length} Windows artifact type(s) detected`
            );
          } else {
            addLog('No artifacts detected in the archive');
            setDetected({});
            setSelected([]);
          }

          setStep('detected');
          setProgress(60);
          resolve();
        }

        function onError(data) {
          clearTimeout(timer);
          socket.off('collection:import:done', onDone);
          socket.off('collection:import:error', onError);
          reject(new Error(data?.details || data?.error || 'Extraction error'));
        }

        socket.on('collection:import:done', onDone);
        socket.on('collection:import:error', onError);
      });
    } catch (err) {
      const rawErr = err.response?.data?.error;
      const msg = (typeof rawErr === 'string' ? rawErr : rawErr?.message) || err.response?.data?.message || err.message || 'Import error';
      setError(msg);
      addLog('ERROR: ' + msg);
      setStep('idle');
    }
  };

  const isCatScaleCollection = detected && 'catscale' in detected;

  const startParsing = async () => {
    if (!selectedCase || selected.length === 0) return;
    try {
      setStep('parsing');
      setProgress(0);
      const parseTypes = isCatScaleCollection ? ['catscale'] : selected;
      const hasEvtx = !isCatScaleCollection && parseTypes.includes('evtx');

      addLog(isCatScaleCollection
        ? 'Starting CatScale Linux IR parsing…'
        : 'Starting parsing — ' + parseTypes.length + ' type(s)...');
      if (!isCatScaleCollection)
        addLog('Parsers: ' + parseTypes.map(t => ARTIFACTS[t]?.parser || t).join(', '));

      try {
        await collectionAPI.parse(selectedCase, { collection_dir: collDir, artifact_types: isCatScaleCollection ? 'all' : parseTypes, socketId });
      } catch (e) {
        const errMsg = (e.response?.data?.error || e.message || 'inconnu')
          + (e.response?.data?.details ? ' — ' + e.response.data.details : '');
        addLog('✗ Parse API error: ' + errMsg);
        setError(errMsg);
        setStep('idle');
        return;
      }

      const doneData = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          socket.off('collection:parse:done', onDone);
          socket.off('collection:parse:error', onError);
          reject(new Error('Timeout parsing (> 2h)'));
        }, 2 * 60 * 60 * 1000);

        function onDone(data) {
          clearTimeout(timer);
          socket.off('collection:parse:done', onDone);
          socket.off('collection:parse:error', onError);
          resolve(data);
        }

        function onError(data) {
          clearTimeout(timer);
          socket.off('collection:parse:done', onDone);
          socket.off('collection:parse:error', onError);
          reject(new Error(data?.details || data?.error || 'Parsing error'));
        }

        socket.on('collection:parse:done', onDone);
        socket.on('collection:parse:error', onError);
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
      addLog('✓ Parsing complete: ' + total.toLocaleString() + ' records — ' + totalOk + ' OK / ' + totalSkip + ' skipped / ' + totalErr + ' error(s)');
      setResults({ total, types: parseTypes });
      setProgress(hasEvtx ? 84 : 90);

      if (hasEvtx) {
        setStep('hayabusa');
        setProgress(80);
        addLog('Running Hayabusa on EVTX...');
        try {
          const hayRes = await collectionAPI.runHayabusa(selectedCase);
          setHayabusaResults(hayRes.data);
          addLog('Hayabusa: ' + (hayRes.data.total || hayRes.data.detections?.length || 0) + ' detections');
        } catch (e) {
          addLog('  ✗ Hayabusa: ' + (e.response?.data?.error || e.message || 'unavailable'));
        }
      }

      setStep('done');
      setProgress(100);
      addLog('Pipeline complete!');
    } catch (err) {
      setError(err.message || 'Parsing error');
      addLog('✗ ERROR: ' + err.message);
      setStep('idle');
    }
  };

  const toggle = (t) => setSelected(p => p.includes(t) ? p.filter(x => x !== t) : [...p, t]);
  const isProcessing = ['uploading', 'extracting', 'detecting', 'parsing', 'hayabusa'].includes(step);
  const caseObj = cases.find(c => String(c.id) === String(selectedCase));
  const PC = { critical: 'var(--fl-danger)', high: 'var(--fl-warn)', medium: 'var(--fl-gold)', low: 'var(--fl-ok)' };

  const currentStepIdx = PIPELINE_STEPS.findIndex(s =>
    (step === 'uploading' && s.key === 'upload') || (step === 'extracting' && s.key === 'extract') ||
    (step === 'detecting' && s.key === 'detect') || (step === 'parsing' && s.key === 'parse') ||
    (step === 'hayabusa' && s.key === 'hayabusa') || (step === 'done' && s.key === 'timeline')
  );

  return (
    <div className="p-6">
      
      <div className="fl-header">
        <div>
          <h1 className="fl-header-title">Import Forensic Collection</h1>
          <p className="fl-header-sub">Windows: Magnet RESPONSE · KAPE · Velociraptor · CyLR — Zimmerman parsing + Hayabusa &nbsp;|&nbsp; Linux: CatScale (WithSecure)</p>
        </div>
        {step !== 'idle' && step !== 'done' && (
          <span className="text-xs font-mono px-2 py-1 rounded" style={{ background: 'color-mix(in srgb, var(--fl-accent) 8%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 15%, transparent)' }}>
            {fileName}
          </span>
        )}
      </div>

      <div className="fl-card p-4 mb-4">
        <label className="fl-label">
          <FolderOpen size={12} className="inline mr-1" /> Target case
        </label>
        {loadingCases ? (
          <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--fl-dim)' }}>
            <Loader2 size={14} className="animate-spin" /> Loading…
          </div>
        ) : cases.length === 0 ? (
          <div className="text-sm" style={{ color: 'var(--fl-danger)' }}>No case available. Create one from the Cases page.</div>
        ) : (
          <>
            <select
              value={selectedCase}
              onChange={e => setSelectedCase(e.target.value)}
              className="fl-select w-full"
              style={{ fontFamily: 'JetBrains Mono, monospace' }}
            >
              {cases.map(c => (
                <option key={c.id} value={c.id}>
                  {c.case_number} — {c.title} [{(c.priority || '').toUpperCase()}]
                </option>
              ))}
            </select>
            {caseObj?.description && (
              <p className="text-xs mt-2" style={{ color: 'var(--fl-dim)' }}>{caseObj.description.substring(0, 120)}</p>
            )}
          </>
        )}
      </div>

      {step === 'idle' && selectedCase && (
        <div
          className="rounded-xl cursor-pointer transition-all"
          style={{
            border: `2px dashed ${dragging ? 'var(--fl-accent)' : 'var(--fl-border)'}`,
            background: dragging ? 'rgba(77,130,192,0.04)' : 'transparent',
            padding: 48,
          }}
          onClick={() => fileRef.current?.click()}
          onDragOver={e => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={e => { e.preventDefault(); setDragging(false); handleFile(e.dataTransfer.files[0]); }}
        >
          <div className="text-center">
            <Package size={48} style={{ color: dragging ? 'var(--fl-accent)' : 'var(--fl-border)', margin: '0 auto 16px', transition: 'color 0.2s' }} />
            <p className="text-base font-semibold mb-2" style={{ color: 'var(--fl-text)' }}>
              Drop your collection archive here
            </p>
            <p className="text-sm mb-1" style={{ color: 'var(--fl-dim)' }}>or click to select</p>
            <p className="text-xs mb-4" style={{ color: 'var(--fl-dim)' }}>
              Target case: <strong style={{ color: 'var(--fl-accent)' }}>{caseObj?.case_number}</strong>
            </p>
            <p className="text-xs font-mono" style={{ color: 'var(--fl-muted)' }}>.zip · .tar.gz · .7z — Unlimited size</p>
          </div>
          <input ref={fileRef} type="file" accept=".zip,.tar,.gz,.7z" className="hidden" onChange={e => handleFile(e.target.files[0])} />
        </div>
      )}

      {isProcessing && (
        <div className="fl-card p-5">
          
          <div className="flex items-center gap-2 mb-5">
            {PIPELINE_STEPS.map((ps, i) => {
              const isDone = i < currentStepIdx;
              const isActive = i === currentStepIdx;
              return (
                <div key={ps.key} className="flex items-center gap-2">
                  <div className="flex items-center gap-1.5">
                    <div
                      className="w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold font-mono flex-shrink-0"
                      style={{
                        background: isDone ? 'var(--fl-ok)' : isActive ? 'var(--fl-accent)' : 'var(--fl-panel)',
                        color: isDone || isActive ? '#ffffff' : 'var(--fl-muted)',
                        transition: 'all 0.3s',
                      }}
                    >
                      {isDone ? '✓' : i + 1}
                    </div>
                    <span
                      className="text-xs font-mono hidden sm:inline"
                      style={{ color: isActive ? 'var(--fl-accent)' : isDone ? 'var(--fl-ok)' : 'var(--fl-muted)', fontWeight: isActive ? 700 : 400 }}
                    >
                      {ps.label}
                    </span>
                  </div>
                  {i < PIPELINE_STEPS.length - 1 && (
                    <ChevronRight size={12} style={{ color: 'var(--fl-border)', flexShrink: 0 }} />
                  )}
                </div>
              );
            })}
          </div>

          <div className="flex justify-between items-center mb-2">
            <span className="text-sm font-semibold flex items-center gap-2" style={{ color: 'var(--fl-text)' }}>
              <Loader2 size={15} className="animate-spin" style={{ color: 'var(--fl-accent)' }} />
              {step === 'uploading' && 'Uploading…'}
              {step === 'extracting' && 'Extracting archive…'}
              {step === 'detecting' && 'Detecting artifacts…'}
              {step === 'parsing' && 'Analyzing artifacts…'}
              {step === 'hayabusa' && 'Hayabusa analysis (EVTX)…'}
            </span>
            <span className="font-mono text-sm font-bold" style={{ color: 'var(--fl-accent)' }}>{progress}%</span>
          </div>
          <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--fl-panel)' }}>
            <div
              className="h-full rounded-full transition-all duration-500"
              style={{ width: `${progress}%`, background: 'linear-gradient(90deg, var(--fl-accent), var(--fl-purple))' }}
            />
          </div>
        </div>
      )}

      {fileHashes && (fileHashes.md5 || fileHashes.sha256) && (
        <div className="fl-card p-4 mb-4">
          <p className="text-xs font-mono uppercase tracking-widest mb-3" style={{ color: 'var(--fl-dim)' }}>
            File integrity — {fileName}
          </p>
          <div className="space-y-1.5">
            {[['MD5', fileHashes.md5, 'var(--fl-dim)'], ['SHA-1', fileHashes.sha1, 'var(--fl-gold)'], ['SHA-256', fileHashes.sha256, 'var(--fl-accent)']].map(([label, value, color]) => value && (
              <div key={label} className="flex items-center gap-3 rounded px-3 py-2" style={{ background: 'var(--fl-bg)', border: '1px solid var(--fl-card)' }}>
                <span className="font-mono text-xs flex-shrink-0 w-14" style={{ color: 'var(--fl-muted)' }}>{label}</span>
                <span className="font-mono text-xs flex-1 break-all" style={{ color }}>{value}</span>
                <button onClick={() => navigator.clipboard.writeText(value)}
                  className="flex-shrink-0 text-xs px-2 py-0.5 rounded font-mono"
                  style={{ background: 'var(--fl-card)', color: 'var(--fl-muted)', border: '1px solid var(--fl-border)' }}>
                  copy
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {step === 'detected' && detected && Object.keys(detected).length === 0 && (
        <div className="fl-card p-5 text-center">
          <AlertTriangle size={28} style={{ color: 'var(--fl-gold)', margin: '0 auto 8px' }} />
          <p className="text-sm font-mono" style={{ color: 'var(--fl-dim)' }}>No recognized artifact in this archive.</p>
          <p className="text-xs mt-1" style={{ color: 'var(--fl-dim)' }}>Verify that the archive is a KAPE, Magnet RESPONSE, CatScale, Velociraptor, or CyLR export.</p>
        </div>
      )}

      {step === 'detected' && detected && Object.keys(detected).length > 0 && (
        <div className="fl-card p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <p className="text-xs font-mono uppercase tracking-widest" style={{ color: 'var(--fl-dim)' }}>
                Detected artifacts
              </p>
              {isCatScaleCollection ? (
                <span className="text-xs font-mono px-2 py-0.5 rounded" style={{ background: 'color-mix(in srgb, var(--fl-ok) 9%, transparent)', color: 'var(--fl-ok)', border: '1px solid color-mix(in srgb, var(--fl-ok) 19%, transparent)' }}>
                  🐧 Linux / CatScale
                </span>
              ) : (
                <span className="text-xs font-mono px-2 py-0.5 rounded" style={{ background: 'color-mix(in srgb, var(--fl-accent) 9%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 19%, transparent)' }}>
                  🪟 Windows
                </span>
              )}
            </div>
            {!isCatScaleCollection && (
              <button
                onClick={() => setSelected(Object.keys(detected).filter(k => detected[k].ok !== false))}
                className="fl-btn fl-btn-ghost fl-btn-sm"
              >
                Select all
              </button>
            )}
          </div>
          <div className="grid grid-cols-3 gap-2 mb-5">
            {Object.entries(detected).map(([type, info]) => {
              const sel = selected.includes(type);
              const art = ARTIFACTS[type];
              const color = art?.color || 'var(--fl-dim)';
              const disabled = info.ok === false;
              return (
                <div
                  key={type}
                  onClick={() => !disabled && toggle(type)}
                  className="flex items-center gap-3 p-3 rounded-lg transition-all"
                  style={{
                    cursor: disabled ? 'default' : 'pointer',
                    background: sel ? `color-mix(in srgb, ${color} 5%, transparent)` : 'var(--fl-bg)',
                    border: `1px solid ${sel ? color + '40' : 'var(--fl-border)'}`,
                    opacity: disabled ? 0.45 : 1,
                  }}
                >
                  <div
                    className="w-4 h-4 rounded flex-shrink-0 flex items-center justify-center"
                    style={{ border: `2px solid ${sel ? color : 'var(--fl-card)'}`, background: sel ? color : 'transparent' }}
                  >
                    {sel && <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="4"><polyline points="20 6 9 17 4 12" /></svg>}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-semibold flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: color }} />
                      <span className="truncate">{art?.name || type}</span>
                    </div>
                    <div className="text-xs mt-0.5" style={{ color: 'var(--fl-dim)' }}>
                      {info.n || 0} fichier{(info.n || 0) > 1 ? 's' : ''} · {info.sz || '?'}
                      {type === 'evtx' && <span className="ml-1.5 font-mono" style={{ color: 'var(--fl-accent)' }}>+ Hayabusa</span>}
                    </div>
                  </div>
                  {disabled && (
                    <span className="text-xs font-mono" style={{ color: 'var(--fl-danger)', flexShrink: 0 }}>Absent</span>
                  )}
                </div>
              );
            })}
          </div>

          <div className="flex justify-between items-center">
            <div className="flex items-center gap-3">
              {isCatScaleCollection ? (
                <span className="text-sm" style={{ color: 'var(--fl-ok)' }}>
                  Linux parsers: auth.log, wtmp, processes, network, bash_history, cron, systemd…
                </span>
              ) : (
                <>
                  <span className="text-sm" style={{ color: 'var(--fl-dim)' }}>
                    <strong style={{ color: 'var(--fl-text)' }}>{selected.length}</strong> selected
                  </span>
                  {selected.includes('evtx') && (
                    <span className="fl-badge" style={{ background: 'color-mix(in srgb, var(--fl-accent) 7%, transparent)', color: 'var(--fl-accent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 15%, transparent)' }}>
                      <Shield size={10} className="inline mr-1" />Hayabusa included
                    </span>
                  )}
                </>
              )}
            </div>
            <button
              onClick={startParsing}
              disabled={!selected.length && !isCatScaleCollection}
              className="fl-btn fl-btn-primary"
              style={{ opacity: (selected.length || isCatScaleCollection) ? 1 : 0.5 }}
            >
              <Cpu size={14} /> {isCatScaleCollection ? 'Analyze (Linux)' : 'Run pipeline'}
            </button>
          </div>
        </div>
      )}

      
      {step === 'done' && (
        <div className="fl-card p-5">
          <div className="flex items-center gap-3 mb-4">
            <CheckCircle2 size={20} style={{ color: 'var(--fl-ok)' }} />
            <span className="text-base font-bold" style={{ color: 'var(--fl-ok)' }}>
              Pipeline complete — {caseObj?.case_number}
            </span>
          </div>

          {results && (
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
              <p className="text-sm" style={{ color: 'var(--fl-dim)' }}>
                {results.total.toLocaleString()} imported records
              </p>
            </div>
          )}

          {hayabusaResults && (
            <div className="mb-4 rounded-lg p-3 flex items-center gap-4" style={{ background: 'var(--fl-bg)', border: '1px solid var(--fl-border)' }}>
              <Shield size={16} style={{ color: 'var(--fl-danger)' }} />
              <span className="text-xs font-mono" style={{ color: 'var(--fl-dim)' }}>Hayabusa</span>
              {['critical', 'high', 'medium', 'low'].map(l => {
                const colors = { critical: 'var(--fl-danger)', high: 'var(--fl-warn)', medium: 'var(--fl-gold)', low: 'var(--fl-ok)' };
                return (
                  <span key={l} className="text-xs font-mono font-bold" style={{ color: colors[l] }}>
                    {hayabusaResults.stats?.[l] || 0} {l}
                  </span>
                );
              })}
            </div>
          )}

          <div className="flex gap-3">
            <a href={'/cases/' + selectedCase} className="fl-btn fl-btn-primary">
              View case
            </a>
            <button
              onClick={() => { setStep('idle'); setDetected(null); setResults(null); setHayabusaResults(null); setPipelineLog([]); setFileName(''); }}
              className="fl-btn fl-btn-secondary"
            >
              New collection
            </button>
          </div>
        </div>
      )}

      
      {error && (
        <div className="mt-4 p-3 rounded-lg text-sm flex items-center gap-2" style={{ background: 'rgba(218,54,51,0.08)', border: '1px solid rgba(218,54,51,0.2)', color: 'var(--fl-danger)' }}>
          <AlertTriangle size={14} /> {error}
          <button onClick={() => setError('')} className="ml-auto" style={{ color: 'var(--fl-danger)' }}><X size={14} /></button>
        </div>
      )}

      
      {pipelineLog.length > 0 && (
        <div className="mt-4 rounded-xl border" style={{ background: 'var(--fl-bg)', borderColor: 'var(--fl-border)' }}>
          <div className="px-4 py-2 border-b flex items-center justify-between" style={{ borderColor: 'var(--fl-border)' }}>
            <span className="text-xs font-mono uppercase tracking-widest" style={{ color: 'var(--fl-muted)' }}>Journal pipeline</span>
            <span className="text-xs font-mono" style={{ color: 'var(--fl-muted)' }}>{pipelineLog.length} entries</span>
          </div>
          <div className="p-4 space-y-0.5 font-mono text-xs overflow-y-auto" style={{ maxHeight: 200 }}>
            {pipelineLog.map((log, i) => (
              <div key={i} style={{ color: log.msg.startsWith('ERREUR') || log.msg.includes('✗') ? 'var(--fl-danger)' : log.msg.includes('✓') ? 'var(--fl-ok)' : 'var(--fl-dim)' }}>
                <span style={{ color: 'var(--fl-border)' }}>[{log.time}]</span> {log.msg}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
