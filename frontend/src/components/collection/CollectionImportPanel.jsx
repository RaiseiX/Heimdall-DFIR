import { useState, useEffect, useRef } from 'react';
import { useSocket } from '../../hooks/useSocket';
import { Upload, CheckCircle2, Loader2, Package, Cpu, Shield, ChevronRight, AlertTriangle, X } from 'lucide-react';
import { collectionAPI } from '../../utils/api';

const ARTIFACTS = {
  evtx:      { name: 'Event Logs (EVTX)', color: 'var(--fl-artifact-evtx)',      parser: 'EvtxECmd',      platform: 'windows' },
  prefetch:  { name: 'Prefetch',          color: 'var(--fl-artifact-prefetch)',   parser: 'PECmd',          platform: 'windows' },
  mft:       { name: '$MFT',              color: 'var(--fl-artifact-mft)',        parser: 'MFTECmd',        platform: 'windows' },
  lnk:       { name: 'LNK Shortcuts',     color: 'var(--fl-artifact-lnk)',        parser: 'LECmd',          platform: 'windows' },
  registry:  { name: 'Registry Hives',    color: 'var(--fl-artifact-registry)',   parser: 'RECmd',          platform: 'windows' },
  amcache:   { name: 'Amcache',           color: 'var(--fl-artifact-amcache)',    parser: 'AmcacheParser',  platform: 'windows' },
  shellbags: { name: 'Shellbags',         color: 'var(--fl-artifact-shellbags)',  parser: 'SBECmd',         platform: 'windows' },
  jumplist:  { name: 'Jump Lists',        color: 'var(--fl-artifact-jumplist)',   parser: 'JLECmd',         platform: 'windows' },
  srum:      { name: 'SRUM',              color: 'var(--fl-artifact-srum)',       parser: 'SrumECmd',       platform: 'windows' },
  recycle:   { name: 'Recycle Bin',       color: 'var(--fl-artifact-recycle)',    parser: 'RBCmd',          platform: 'windows' },
  sqle:      { name: 'Browser SQLite',    color: 'var(--fl-artifact-sqle)',       parser: 'SQLECmd',        platform: 'windows' },
  wer:       { name: 'WER Reports',       color: 'var(--fl-artifact-wer)',        parser: 'WerParser',      platform: 'windows' },
  catscale:  { name: 'CatScale Linux IR', color: 'var(--fl-artifact-catscale)',   parser: 'CatScale',       platform: 'linux' },
};

const PIPELINE_STEPS = [
  { key: 'upload',   label: 'Upload' },
  { key: 'extract',  label: 'Extraction' },
  { key: 'detect',   label: 'Détection' },
  { key: 'parse',    label: 'Parsing' },
  { key: 'hayabusa', label: 'Hayabusa' },
  { key: 'timeline', label: 'Timeline' },
];

export default function CollectionImportPanel({ caseId, caseObj, onDone }) {
  const { socket, socketId } = useSocket();
  const fileRef = useRef(null);

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
          addLog('  ✓ ' + data.name + ': ' + data.records.toLocaleString() + ' enregistrements');
        else if (data.status === 'skipped')
          addLog('  – ' + data.name + ': ignoré');
        else if (data.status === 'error')
          addLog('  ✗ ' + data.name + ': erreur');
      } else if (data.type === 'saving') {
        setProgress(82);
        addLog('Enregistrement en base de données…');
      }
    }
    socket.on('collection:progress', handleProgress);
    return () => socket.off('collection:progress', handleProgress);
  }, [socket]);

  const addLog = (msg) => setPipelineLog(prev => [...prev, { time: new Date().toLocaleTimeString('fr-FR'), msg }]);

  const handleFile = async (file) => {
    if (!file || !caseId) return;
    setFileName(file.name);
    setError('');
    setPipelineLog([]);
    setHayabusaResults(null);
    setResults(null);

    if (!socket) { setError('Connexion socket requise — rechargez la page'); return; }

    const formData = new FormData();
    formData.append('collection', file);
    formData.append('socketId', socket.id || '');

    try {
      setStep('uploading');
      setProgress(0);
      addLog('Upload de ' + file.name + ' (' + (file.size / 1024 / 1024).toFixed(1) + ' MB)...');

      const importRes = await collectionAPI.import(caseId, formData, (e) => {
        if (e.total) setProgress(Math.round((e.loaded / e.total) * 50));
      });

      const dir = importRes.data?.collection_dir || '';
      setCollDir(dir);
      addLog('Upload terminé — extraction en cours...');
      setStep('extracting');
      setProgress(55);

      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          socket.off('collection:import:done', onDone_);
          socket.off('collection:import:error', onError_);
          reject(new Error('Timeout extraction (> 20 min)'));
        }, 20 * 60 * 1000);

        function onDone_(data) {
          clearTimeout(timer);
          socket.off('collection:import:done', onDone_);
          socket.off('collection:import:error', onError_);

          setStep('detecting');
          setProgress(58);
          addLog('Détection des artefacts forensiques...');

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
              ? `Collecte Linux détectée — CatScale (${normalized.catscale.n} fichiers)`
              : `${Object.keys(normalized).length} type(s) d'artefacts Windows détectés`);
          } else {
            addLog('Aucun artefact détecté dans l\'archive');
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
          reject(new Error(data?.details || data?.error || 'Erreur extraction'));
        }

        socket.on('collection:import:done', onDone_);
        socket.on('collection:import:error', onError_);
      });
    } catch (err) {
      const rawErr = err.response?.data?.error;
      const msg = (typeof rawErr === 'string' ? rawErr : rawErr?.message) || err.response?.data?.message || err.message || 'Erreur import';
      setError(msg);
      addLog('ERREUR: ' + msg);
      setStep('idle');
    }
  };

  const isCatScaleCollection = detected && 'catscale' in detected;

  const startParsing = async () => {
    if (!caseId || selected.length === 0) return;
    try {
      setStep('parsing');
      setProgress(0);
      const parseTypes = isCatScaleCollection ? ['catscale'] : selected;
      const hasEvtx = !isCatScaleCollection && parseTypes.includes('evtx');

      addLog(isCatScaleCollection
        ? 'Lancement parsing CatScale Linux IR…'
        : 'Lancement du parsing — ' + parseTypes.length + ' type(s)...');
      if (!isCatScaleCollection)
        addLog('Parsers: ' + parseTypes.map(t => ARTIFACTS[t]?.parser || t).join(', '));

      try {
        await collectionAPI.parse(caseId, { collection_dir: collDir, artifact_types: isCatScaleCollection ? 'all' : parseTypes, socketId });
      } catch (e) {
        const errMsg = (e.response?.data?.error || e.message || 'inconnu')
          + (e.response?.data?.details ? ' — ' + e.response.data.details : '');
        addLog('✗ Erreur API parse: ' + errMsg);
        setError(errMsg);
        setStep('idle');
        return;
      }

      const doneData = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          socket.off('collection:parse:done', onParseDone);
          socket.off('collection:parse:error', onParseError);
          reject(new Error('Timeout parsing (> 2h)'));
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
          reject(new Error(data?.details || data?.error || 'Erreur parsing'));
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
      addLog('✓ Parsing terminé: ' + total.toLocaleString() + ' enregistrements — ' + totalOk + ' OK / ' + totalSkip + ' ignorés / ' + totalErr + ' erreur(s)');
      setResults({ total, types: parseTypes });
      setProgress(hasEvtx ? 84 : 90);

      if (hasEvtx) {
        setStep('hayabusa');
        setProgress(80);
        addLog('Lancement Hayabusa sur les EVTX...');
        try {
          const hayRes = await collectionAPI.runHayabusa(caseId);
          setHayabusaResults(hayRes.data);
          addLog('Hayabusa: ' + (hayRes.data.total || hayRes.data.detections?.length || 0) + ' détections');
        } catch (e) {
          addLog('  ✗ Hayabusa: ' + (e.response?.data?.error || e.message || 'non disponible'));
        }
      }

      setStep('done');
      setProgress(100);
      addLog('Pipeline terminé !');
      onDone?.();
    } catch (err) {
      setError(err.message || 'Erreur parsing');
      addLog('✗ ERREUR: ' + err.message);
      setStep('idle');
    }
  };

  const reset = () => {
    setStep('idle'); setDetected(null); setResults(null);
    setHayabusaResults(null); setPipelineLog([]); setFileName('');
    setFileHashes(null); setError('');
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
            border: `2px dashed ${dragging ? '#4d82c0' : '#30363d'}`,
            background: dragging ? 'rgba(77,130,192,0.05)' : '#0d1117',
            padding: '40px 24px',
          }}
          onClick={() => fileRef.current?.click()}
          onDragOver={e => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={e => { e.preventDefault(); setDragging(false); handleFile(e.dataTransfer.files[0]); }}
        >
          <div className="text-center">
            <Package size={44} style={{ color: dragging ? '#4d82c0' : '#30363d', margin: '0 auto 14px', transition: 'color 0.2s' }} />
            <p className="text-base font-semibold mb-1" style={{ color: '#e6edf3' }}>
              Glissez votre archive de collecte ici
            </p>
            <p className="text-sm mb-1" style={{ color: '#7d8590' }}>ou cliquez pour sélectionner</p>
            {caseObj && (
              <p className="text-xs mb-3" style={{ color: '#7d8590' }}>
                Dossier cible : <strong style={{ color: '#4d82c0' }}>{caseObj.case_number}</strong>
              </p>
            )}
            <p className="text-xs font-mono" style={{ color: '#484f58' }}>.zip · .tar.gz · .7z — Taille illimitée</p>
          </div>
          <input ref={fileRef} type="file" accept=".zip,.tar,.gz,.7z" className="hidden" onChange={e => handleFile(e.target.files[0])} />
        </div>
      )}

      {step !== 'idle' && step !== 'done' && fileName && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px', borderRadius: 6, background: '#1c2333', border: '1px solid #30363d' }}>
          <Upload size={12} style={{ color: '#4d82c0' }} />
          <span style={{ fontSize: 12, fontFamily: 'monospace', color: '#8b949e', flex: 1 }}>{fileName}</span>
        </div>
      )}

      {isProcessing && (
        <div className="fl-card p-4">
          <div className="flex items-center gap-2 mb-4 flex-wrap">
            {PIPELINE_STEPS.map((ps, i) => {
              const isDone = i < currentStepIdx;
              const isActive = i === currentStepIdx;
              return (
                <div key={ps.key} className="flex items-center gap-1.5">
                  <div
                    className="w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold font-mono flex-shrink-0"
                    style={{ background: isDone ? '#3fb950' : isActive ? '#4d82c0' : '#21262d', color: isDone || isActive ? '#fff' : '#484f58', transition: 'all 0.3s' }}
                  >
                    {isDone ? '✓' : i + 1}
                  </div>
                  <span className="text-xs font-mono hidden sm:inline"
                    style={{ color: isActive ? '#4d82c0' : isDone ? '#3fb950' : '#484f58', fontWeight: isActive ? 700 : 400 }}>
                    {ps.label}
                  </span>
                  {i < PIPELINE_STEPS.length - 1 && <ChevronRight size={11} style={{ color: '#30363d' }} />}
                </div>
              );
            })}
          </div>
          <div className="flex justify-between items-center mb-2">
            <span className="text-sm font-semibold flex items-center gap-2" style={{ color: '#e6edf3' }}>
              <Loader2 size={14} className="animate-spin" style={{ color: '#4d82c0' }} />
              {step === 'uploading'  && 'Upload en cours…'}
              {step === 'extracting' && 'Extraction de l\'archive…'}
              {step === 'detecting'  && 'Détection des artefacts…'}
              {step === 'parsing'    && 'Analyse des artefacts…'}
              {step === 'hayabusa'   && 'Analyse Hayabusa (EVTX)…'}
            </span>
            <span className="font-mono text-sm font-bold" style={{ color: '#4d82c0' }}>{progress}%</span>
          </div>
          <div className="h-1.5 rounded-full overflow-hidden" style={{ background: '#21262d' }}>
            <div className="h-full rounded-full transition-all duration-500"
              style={{ width: `${progress}%`, background: 'linear-gradient(90deg, #4d82c0, #8b72d6)' }} />
          </div>
        </div>
      )}

      {fileHashes && (fileHashes.md5 || fileHashes.sha256) && (
        <div className="fl-card p-4">
          <p className="text-xs font-mono uppercase tracking-widest mb-3" style={{ color: '#7d8590' }}>
            Intégrité — {fileName}
          </p>
          <div className="space-y-1.5">
            {[['MD5', fileHashes.md5, '#7d8590'], ['SHA-1', fileHashes.sha1, '#c89d1d'], ['SHA-256', fileHashes.sha256, '#4d82c0']].map(([label, value, color]) => value && (
              <div key={label} className="flex items-center gap-3 rounded px-3 py-2" style={{ background: '#0d1117', border: '1px solid #1e2a3a' }}>
                <span className="font-mono text-xs flex-shrink-0 w-14" style={{ color: '#484f58' }}>{label}</span>
                <span className="font-mono text-xs flex-1 break-all" style={{ color }}>{value}</span>
                <button onClick={() => navigator.clipboard.writeText(value)}
                  className="flex-shrink-0 text-xs px-2 py-0.5 rounded font-mono"
                  style={{ background: '#1e2a3a', color: '#484f58', border: '1px solid #30363d' }}>
                  copier
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {step === 'detected' && detected && Object.keys(detected).length === 0 && (
        <div className="fl-card p-5 text-center">
          <AlertTriangle size={28} style={{ color: '#c89d1d', margin: '0 auto 8px' }} />
          <p className="text-sm font-mono" style={{ color: '#c9d1d9' }}>Aucun artefact reconnu dans cette archive.</p>
          <p className="text-xs mt-1" style={{ color: '#7d8590' }}>Vérifiez que l'archive est bien un export KAPE, Magnet RESPONSE, CatScale, Velociraptor ou CyLR.</p>
        </div>
      )}

      {step === 'detected' && detected && Object.keys(detected).length > 0 && (
        <div className="fl-card p-4">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <p className="text-xs font-mono uppercase tracking-widest" style={{ color: '#7d8590' }}>Artefacts détectés</p>
              {isCatScaleCollection ? (
                <span className="text-xs font-mono px-2 py-0.5 rounded" style={{ background: '#22c55e18', color: '#22c55e', border: '1px solid #22c55e30' }}>Linux / CatScale</span>
              ) : (
                <span className="text-xs font-mono px-2 py-0.5 rounded" style={{ background: '#4d82c018', color: '#4d82c0', border: '1px solid #4d82c030' }}>Windows</span>
              )}
            </div>
            {!isCatScaleCollection && (
              <button onClick={() => setSelected(Object.keys(detected).filter(k => detected[k].ok !== false))} className="fl-btn fl-btn-ghost fl-btn-sm">
                Tout sélectionner
              </button>
            )}
          </div>

          <div className="grid grid-cols-3 gap-2 mb-4">
            {Object.entries(detected).map(([type, info]) => {
              const sel = selected.includes(type);
              const art = ARTIFACTS[type];
              const color = art?.color || '#7d8590';
              const disabled = info.ok === false;
              return (
                <div key={type} onClick={() => !disabled && toggle(type)}
                  className="flex items-center gap-3 p-3 rounded-lg transition-all"
                  style={{ cursor: disabled ? 'default' : 'pointer', background: sel ? `${color}0c` : '#0d1117', border: `1px solid ${sel ? color + '40' : '#30363d'}`, opacity: disabled ? 0.45 : 1 }}>
                  <div className="w-4 h-4 rounded flex-shrink-0 flex items-center justify-center"
                    style={{ border: `2px solid ${sel ? color : '#334155'}`, background: sel ? color : 'transparent' }}>
                    {sel && <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="4"><polyline points="20 6 9 17 4 12" /></svg>}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-semibold flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: color }} />
                      <span className="truncate">{art?.name || type}</span>
                    </div>
                    <div className="text-xs mt-0.5" style={{ color: '#7d8590' }}>
                      {info.n || 0} fichier{(info.n || 0) > 1 ? 's' : ''} · {info.sz || '?'}
                      {type === 'evtx' && <span className="ml-1.5 font-mono" style={{ color: '#4d82c0' }}>+ Hayabusa</span>}
                    </div>
                  </div>
                  {disabled && <span className="text-xs font-mono" style={{ color: '#da3633', flexShrink: 0 }}>Absent</span>}
                </div>
              );
            })}
          </div>

          <div className="flex justify-between items-center">
            <div className="flex items-center gap-3">
              {isCatScaleCollection ? (
                <span className="text-sm" style={{ color: '#22c55e' }}>Parseurs Linux : auth.log, wtmp, processus, réseau, bash_history, cron, systemd…</span>
              ) : (
                <>
                  <span className="text-sm" style={{ color: '#7d8590' }}><strong style={{ color: '#e6edf3' }}>{selected.length}</strong> sélectionné(s)</span>
                  {selected.includes('evtx') && (
                    <span className="fl-badge" style={{ background: '#4d82c012', color: '#4d82c0', border: '1px solid #4d82c025' }}>
                      <Shield size={10} className="inline mr-1" />Hayabusa inclus
                    </span>
                  )}
                </>
              )}
            </div>
            <button onClick={startParsing} disabled={!selected.length && !isCatScaleCollection}
              className="fl-btn fl-btn-primary"
              style={{ opacity: (selected.length || isCatScaleCollection) ? 1 : 0.5 }}>
              <Cpu size={14} /> {isCatScaleCollection ? 'Analyser (Linux)' : 'Lancer le pipeline'}
            </button>
          </div>
        </div>
      )}

      {step === 'done' && (
        <div className="fl-card p-5" style={{ borderLeft: '3px solid #3fb950' }}>
          <div className="flex items-center gap-3 mb-4">
            <CheckCircle2 size={20} style={{ color: '#3fb950' }} />
            <span className="text-base font-bold" style={{ color: '#3fb950' }}>Pipeline terminé</span>
          </div>
          {results && (
            <div className="mb-4">
              <div className="flex flex-wrap gap-2 mb-2">
                {results.types.map(t => {
                  const art = ARTIFACTS[t];
                  return (
                    <span key={t} className="fl-badge" style={{ background: `${art?.color}14`, color: art?.color, border: `1px solid ${art?.color}28` }}>
                      {art?.parser || t}
                    </span>
                  );
                })}
              </div>
              <p className="text-sm" style={{ color: '#7d8590' }}>{results.total.toLocaleString()} enregistrements importés</p>
            </div>
          )}
          {hayabusaResults && (
            <div className="mb-4 rounded-lg p-3 flex items-center gap-4" style={{ background: '#0d1117', border: '1px solid #30363d' }}>
              <Shield size={16} style={{ color: '#da3633' }} />
              <span className="text-xs font-mono" style={{ color: '#7d8590' }}>Hayabusa</span>
              {['critical', 'high', 'medium', 'low'].map(l => {
                const colors = { critical: '#da3633', high: '#d97c20', medium: '#c89d1d', low: '#3fb950' };
                return <span key={l} className="text-xs font-mono font-bold" style={{ color: colors[l] }}>{hayabusaResults.stats?.[l] || 0} {l}</span>;
              })}
            </div>
          )}
          <button onClick={reset} className="fl-btn fl-btn-secondary">Nouvelle collecte</button>
        </div>
      )}

      {error && (
        <div className="p-3 rounded-lg text-sm flex items-center gap-2" style={{ background: 'rgba(218,54,51,0.08)', border: '1px solid rgba(218,54,51,0.2)', color: '#da3633' }}>
          <AlertTriangle size={14} /> {error}
          <button onClick={() => setError('')} className="ml-auto"><X size={14} /></button>
        </div>
      )}

      {pipelineLog.length > 0 && (
        <div className="rounded-xl border" style={{ background: '#0d1117', borderColor: '#30363d' }}>
          <div className="px-4 py-2 border-b flex items-center justify-between" style={{ borderColor: '#30363d' }}>
            <span className="text-xs font-mono uppercase tracking-widest" style={{ color: '#484f58' }}>Journal pipeline</span>
            <span className="text-xs font-mono" style={{ color: '#484f58' }}>{pipelineLog.length} entrées</span>
          </div>
          <div className="p-4 space-y-0.5 font-mono text-xs overflow-y-auto" style={{ maxHeight: 200 }}>
            {pipelineLog.map((log, i) => (
              <div key={i} style={{ color: log.msg.startsWith('ERREUR') || log.msg.includes('✗') ? '#da3633' : log.msg.includes('✓') ? '#3fb950' : '#7d8590' }}>
                <span style={{ color: '#30363d' }}>[{log.time}]</span> {log.msg}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
