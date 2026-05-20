import React, { useState, useRef, useCallback } from 'react';
import { Upload, Cpu, X, AlertCircle, CheckCircle2, FileArchive, Plus, Trash2 } from 'lucide-react';
import api from '../../utils/api';

const OS_OPTIONS = [
  { value: 'windows', label: 'Windows' },
  { value: 'linux',   label: 'Linux' },
  { value: 'mac',     label: 'macOS' },
];
const ADDITIONAL_ACCEPT = '.vmsn,.vmss,.pdb,.json,.xz,.zip,.gz,.isf,.lzma,.dwarf,.sym,.symbols';

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export default function MemoryUploadPanel({ caseId, onDone, onClose }) {
  const [file,            setFile]            = useState(null);
  const [additionalFiles, setAdditionalFiles] = useState([]);
  const [dumpOs,          setDumpOs]          = useState('windows');
  const [status,          setStatus]          = useState('idle');
  const [progress,        setProgress]        = useState(0);
  const [statusMsg,       setStatusMsg]       = useState('');
  const [error,           setError]           = useState(null);

  const xhrRef      = useRef(null);
  const dropRef     = useRef(null);
  const addInputRef = useRef(null);
  const fileRef     = useRef(null);
  const dumpOsRef   = useRef('windows');

  const guessOs = useCallback((name) => {
    if (/linux/i.test(name))          return 'linux';
    if (/mac|osx|darwin/i.test(name)) return 'mac';
    return 'windows';
  }, []);

  const handleFile = useCallback((f) => {
    if (!f) return;
    const os = guessOs(f.name);
    fileRef.current   = f;
    dumpOsRef.current = os;
    setFile(f);
    setDumpOs(os);
    setError(null);
    setStatus('idle');
    setProgress(0);
  }, [guessOs]);

  // Pas de ref pour additionalFiles — on lit directement le state via la closure de startUpload
  const handleAdditionalFiles = useCallback((files) => {
    // Snapshot du FileList AVANT le setState (le FileList est live et vidé par e.target.value='')
    const snapshot = Array.from(files || []);
    setAdditionalFiles(prev => {
      const ex = new Set(prev.map(f => f.name));
      return [...prev, ...snapshot.filter(f => !ex.has(f.name))];
    });
  }, []);

  const removeAdditional = useCallback((name) => {
    setAdditionalFiles(prev => prev.filter(f => f.name !== name));
  }, []);

  const handleOsChange = useCallback((value) => {
    dumpOsRef.current = value;
    setDumpOs(value);
  }, []);

  const clearAll = useCallback(() => {
    fileRef.current   = null;
    dumpOsRef.current = 'windows';
    setFile(null);
    setAdditionalFiles([]);
    setDumpOs('windows');
  }, []);

  // startUpload reçoit additionalFiles en argument pour éviter le stale closure
  const startUpload = useCallback(async (currentAdditionalFiles) => {
    const currentFile = fileRef.current;
    if (!currentFile) return;

    setError(null);
    setStatus('uploading');
    setProgress(0);
    setStatusMsg('Vérification de la session…');

    try {
      const rt = localStorage.getItem('heimdall_refresh_token');
      if (rt) {
        const { data } = await api.post('/auth/refresh', { refreshToken: rt });
        localStorage.setItem('heimdall_token', data.token);
        if (data.refreshToken) localStorage.setItem('heimdall_refresh_token', data.refreshToken);
      }
    } catch {
      setStatus('error');
      setError('Session expirée — veuillez vous reconnecter.');
      return;
    }

    const os        = dumpOsRef.current;
    const totalSize = currentFile.size + currentAdditionalFiles.reduce((s, f) => s + f.size, 0);

    const formData = new FormData();
    formData.append('dump_os', os);
    formData.append('evidence_type', 'memory');
    formData.append('file', currentFile, currentFile.name);
    for (const extra of currentAdditionalFiles) {
      formData.append('additionalFiles', extra, extra.name);
    }

    setStatusMsg(`Envoi streaming (${formatBytes(totalSize)})…`);

    await new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhrRef.current = xhr;

      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) {
          setProgress(Math.round((e.loaded / e.total) * 95));
          setStatusMsg(`Envoi ${formatBytes(e.loaded)} / ${formatBytes(e.total)}…`);
        }
      };

      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) resolve();
        else {
          try { reject(new Error(JSON.parse(xhr.responseText)?.error || `HTTP ${xhr.status}`)); }
          catch { reject(new Error(`HTTP ${xhr.status}`)); }
        }
      };
      xhr.onerror = () => reject(new Error('Erreur réseau'));
      xhr.onabort = () => reject(new Error('_aborted_'));

      const token = localStorage.getItem('heimdall_token') || localStorage.getItem('token');
      xhr.open('POST', `/api/evidence/${caseId}/upload-stream`);
      if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`);
      xhr.send(formData);
    }).then(() => {
      setProgress(100);
      setStatus('done');
      setStatusMsg('Upload terminé — Analyse Volatility 3 lancée dans VolWeb…');
      onDone?.();
    }).catch((err) => {
      if (err.message === '_aborted_') {
        setStatus('idle'); setStatusMsg(''); setProgress(0);
      } else {
        setStatus('error'); setError(err.message);
      }
    });
  }, [caseId, onDone]);

  const cancel    = useCallback(() => xhrRef.current?.abort(), []);
  const isRunning = status === 'uploading';

  const btn = (extra = {}) => ({
    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7,
    padding: '9px 20px', borderRadius: 7, cursor: 'pointer',
    fontSize: 12, fontFamily: 'monospace', fontWeight: 700,
    background: 'rgba(139,114,214,0.15)', color: 'var(--fl-purple)',
    border: '1px solid rgba(139,114,214,0.35)', ...extra,
  });

  return (
    <div style={{ background: 'var(--fl-bg)', border: '1px solid var(--fl-card)', borderRadius: 10, padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: 16 }}>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, fontFamily: 'monospace', fontWeight: 700, color: 'var(--fl-purple)' }}>
          <Cpu size={14} /> Upload Dump Mémoire (RAM)
        </span>
        {onClose && <button onClick={onClose} style={{ color: 'var(--fl-subtle)', background: 'none', border: 'none', cursor: 'pointer' }}><X size={14} /></button>}
      </div>

      <div style={{ display: 'inline-flex', alignItems: 'center', gap: 5, alignSelf: 'flex-start', fontSize: 9, fontFamily: 'monospace', padding: '2px 8px', borderRadius: 4, background: 'rgba(34,197,94,0.08)', color: '#22c55e', border: '1px solid rgba(34,197,94,0.20)' }}>
        ⚡ Streaming backend → MinIO (aucun stockage disque)
      </div>

      {!file && status === 'idle' && (
        <div ref={dropRef}
          style={{ border: '2px dashed var(--fl-card)', borderRadius: 8, padding: '28px 20px', textAlign: 'center', cursor: 'pointer', background: '#0a0f1a' }}
          onDrop={(e) => { e.preventDefault(); dropRef.current?.classList.remove('dragover'); handleFile(e.dataTransfer.files?.[0]); }}
          onDragOver={e => { e.preventDefault(); dropRef.current?.classList.add('dragover'); }}
          onDragLeave={() => dropRef.current?.classList.remove('dragover')}
          onClick={() => document.getElementById(`mem-file-input-${caseId}`)?.click()}
        >
          <input id={`mem-file-input-${caseId}`} type="file" accept=".raw,.mem,.vmem,.dmp,.lime,.bin" style={{ display: 'none' }} onChange={e => handleFile(e.target.files?.[0])} />
          <Upload size={28} style={{ color: 'var(--fl-subtle)', marginBottom: 8 }} />
          <div style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--fl-dim)' }}>Glisser-déposer un dump RAM ou cliquer</div>
          <div style={{ fontSize: 10, color: 'var(--fl-subtle)', marginTop: 4 }}>.raw · .mem · .vmem · .dmp · .lime · .bin</div>
        </div>
      )}

      {file && status === 'idle' && (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, fontFamily: 'monospace', color: 'var(--fl-text)' }}>
            <FileArchive size={14} style={{ color: 'var(--fl-purple)' }} />
            <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{file.name}</span>
            <span style={{ color: 'var(--fl-dim)', flexShrink: 0 }}>{formatBytes(file.size)}</span>
            <button onClick={clearAll} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-subtle)' }}><X size={12} /></button>
          </div>

          <div style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 12, fontFamily: 'monospace', color: 'var(--fl-dim)' }}>
            <span>OS :</span>
            {OS_OPTIONS.map(o => (
              <button key={o.value} onClick={() => handleOsChange(o.value)} style={{ padding: '4px 12px', borderRadius: 5, fontSize: 11, fontFamily: 'monospace', cursor: 'pointer', background: dumpOs === o.value ? 'rgba(139,114,214,0.2)' : 'transparent', color: dumpOs === o.value ? 'var(--fl-purple)' : 'var(--fl-dim)', border: `1px solid ${dumpOs === o.value ? 'rgba(139,114,214,0.5)' : 'var(--fl-card)'}` }}>{o.label}</button>
            ))}
          </div>

          <div style={{ border: '1px solid var(--fl-card)', borderRadius: 8, padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-dim)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Plus size={11} /> Fichiers additionnels
              <span style={{ color: 'var(--fl-subtle)', fontSize: 10 }}>— symbols (.pdb, .json.xz, .isf), snapshot (.vmsn, .vmss)…</span>
            </div>
            {additionalFiles.map(f => (
              <div key={f.name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(255,255,255,0.04)', borderRadius: 5, padding: '4px 8px', fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-text)' }}>
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{f.name}</span>
                <span style={{ color: 'var(--fl-dim)', marginLeft: 8, flexShrink: 0 }}>{formatBytes(f.size)}</span>
                <button onClick={() => removeAdditional(f.name)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-subtle)', marginLeft: 6 }}><Trash2 size={11} /></button>
              </div>
            ))}
            <input ref={addInputRef} type="file" accept={ADDITIONAL_ACCEPT} multiple style={{ display: 'none' }} onChange={e => { handleAdditionalFiles(e.target.files); setTimeout(() => { e.target.value = ''; }, 0); }} />
            <button style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-accent)', background: 'none', border: '1px dashed rgba(99,179,237,0.3)', borderRadius: 5, padding: '4px 10px', cursor: 'pointer' }} onClick={() => addInputRef.current?.click()}>
              <Plus size={11} /> Ajouter un fichier
            </button>
          </div>
        </>
      )}

      {(isRunning || status === 'done' || status === 'error') && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div style={{ background: 'var(--fl-card)', borderRadius: 4, height: 6, overflow: 'hidden' }}>
            <div style={{ height: '100%', borderRadius: 4, transition: 'width 0.3s ease', width: `${progress}%`, background: status === 'done' ? '#22c55e' : status === 'error' ? 'var(--fl-danger)' : 'linear-gradient(90deg, var(--fl-accent), #8b72d6)' }} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-dim)' }}>
            <span>{statusMsg}</span><span>{progress}%</span>
          </div>
        </div>
      )}

      {error && <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-danger)' }}><AlertCircle size={13} /> {error}</div>}
      {status === 'done' && <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontFamily: 'monospace', color: '#22c55e' }}><CheckCircle2 size={13} /> Dump uploadé — analyse Volatility 3 lancée dans VolWeb</div>}

      {status === 'idle' && file && (
        <button style={btn()} onClick={() => startUpload(additionalFiles)}>
          <Upload size={13} /> Lancer l'upload
          {additionalFiles.length > 0 && <span style={{ opacity: 0.7, fontWeight: 400 }}>({1 + additionalFiles.length} fichiers)</span>}
        </button>
      )}
      {isRunning && <button onClick={cancel} style={btn({ color: 'var(--fl-danger)', borderColor: 'rgba(239,68,68,0.35)', background: 'rgba(239,68,68,0.08)' })}><X size={13} /> Annuler</button>}
      {status === 'done' && onClose && <button style={btn({ color: '#22c55e', borderColor: 'rgba(34,197,94,0.35)', background: 'rgba(34,197,94,0.08)' })} onClick={onClose}><CheckCircle2 size={13} /> Fermer</button>}
    </div>
  );
}