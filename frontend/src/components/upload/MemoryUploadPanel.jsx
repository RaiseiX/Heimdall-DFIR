
import React, { useState, useRef, useCallback } from 'react';
import { Upload, Cpu, X, AlertCircle, CheckCircle2, Loader2, FileArchive, Plus, Trash2 } from 'lucide-react';
import api from '../../utils/api';

const DEFAULT_CHUNK_SIZE = 50 * 1024 * 1024;
const OS_OPTIONS = [
  { value: 'windows', label: 'Windows' },
  { value: 'linux',   label: 'Linux' },
  { value: 'mac',     label: 'macOS' },
];

const ADDITIONAL_ACCEPT = '.vmsn,.vmss,.pdb,.json,.xz,.zip,.gz,.isf,.lzma,.dwarf,.sym,.symbols';

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function resumeKey(caseId, filename, fileSize) {
  return `mem_upload:${caseId}:${filename}:${fileSize}`;
}

export default function MemoryUploadPanel({ caseId, onDone, onClose }) {
  const [file,            setFile]            = useState(null);
  const [additionalFiles, setAdditionalFiles] = useState([]);
  const [dumpOs,          setDumpOs]          = useState('windows');
  const [status,          setStatus]          = useState('idle');
  const [progress,        setProgress]        = useState(0);
  const [statusMsg,       setStatusMsg]       = useState('');
  const [error,           setError]           = useState(null);
  const [resumeInfo,      setResumeInfo]      = useState(null);
  const abortRef    = useRef(false);
  const dropRef     = useRef(null);
  const addInputRef = useRef(null);

  const guessOs = useCallback((filename) => {
    if (/linux/i.test(filename))          return 'linux';
    if (/mac|osx|darwin/i.test(filename)) return 'mac';
    return 'windows';
  }, []);

  const handleFile = useCallback((f) => {
    if (!f) return;
    setFile(f);
    setDumpOs(guessOs(f.name));
    setError(null);
    setStatus('idle');
    setProgress(0);
    setResumeInfo(null);

    const key = resumeKey(caseId, f.name, f.size);
    const savedId = localStorage.getItem(key);
    if (savedId) {
      api.get(`/volweb/memory/${caseId}/status/${savedId}`)
        .then(res => {
          const d = res.data;
          if (d.status === 'uploading' && d.received_chunks_set.length < d.total_chunks) {
            setResumeInfo({
              uploadId:    d.upload_id,
              receivedSet: new Set(d.received_chunks_set),
              totalChunks: d.total_chunks,
              chunkSize:   d.chunk_size || DEFAULT_CHUNK_SIZE,
            });
          } else {
            localStorage.removeItem(key);
          }
        })
        .catch(() => localStorage.removeItem(key));
    }
  }, [caseId, guessOs]);

  const handleAdditionalFiles = useCallback((files) => {
    const arr = Array.from(files);
    setAdditionalFiles(prev => {
      const existing = new Set(prev.map(f => f.name));
      const newFiles = arr.filter(f => !existing.has(f.name));
      return [...prev, ...newFiles];
    });
  }, []);

  const removeAdditional = useCallback((name) => {
    setAdditionalFiles(prev => prev.filter(f => f.name !== name));
  }, []);

  const onDrop = useCallback((e) => {
    e.preventDefault();
    dropRef.current?.classList.remove('dragover');
    handleFile(e.dataTransfer.files?.[0]);
  }, [handleFile]);

  const onDragOver  = useCallback((e) => { e.preventDefault(); dropRef.current?.classList.add('dragover'); }, []);
  const onDragLeave = useCallback(() => { dropRef.current?.classList.remove('dragover'); }, []);

  const startUpload = useCallback(async (isResume = false) => {
    if (!file) return;
    abortRef.current = false;
    setError(null);

    setStatus('uploading');
    setStatusMsg('Vérification de la session…');
    try {
      const refreshToken = localStorage.getItem('heimdall_refresh_token');
      if (refreshToken) {
        const { data } = await api.post('/auth/refresh', { refreshToken });
        localStorage.setItem('heimdall_token', data.token);
        if (data.refreshToken) localStorage.setItem('heimdall_refresh_token', data.refreshToken);
      }
    } catch {
      setStatus('error');
      setError("Session expirée — veuillez vous reconnecter avant de lancer l'upload.");
      return;
    }

    try {
      // Construction du FormData avec le dump + fichiers additionnels
      const formData = new FormData();
      formData.append('file', file, file.name);
      formData.append('dump_os', dumpOs);
      formData.append('evidence_type', 'memory');
      for (const extra of additionalFiles) {
        formData.append('additionalFiles', extra, extra.name);
      }

      setStatusMsg(`Envoi du dump (${formatBytes(file.size)})${additionalFiles.length ? ` + ${additionalFiles.length} fichier(s) additionnel(s)` : ''}…`);

      // Upload avec progression via XMLHttpRequest pour avoir la progression
      await new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        const token = localStorage.getItem('heimdall_token') || localStorage.getItem('token');

        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) {
            const pct = Math.round((e.loaded / e.total) * 90);
            setProgress(pct);
            setStatusMsg(`Envoi ${formatBytes(e.loaded)} / ${formatBytes(e.total)}…`);
          }
        };

        xhr.onload = () => {
          if (xhr.status >= 200 && xhr.status < 300) resolve(JSON.parse(xhr.responseText));
          else {
            try { reject(new Error(JSON.parse(xhr.responseText)?.error || `HTTP ${xhr.status}`)); }
            catch { reject(new Error(`HTTP ${xhr.status}`)); }
          }
        };
        xhr.onerror  = () => reject(new Error('Erreur réseau'));
        xhr.onabort  = () => reject(new Error('Upload annulé'));

        xhr.open('POST', `/api/evidence/${caseId}/upload`);
        if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`);
        xhr.send(formData);

        // Stocker la ref pour annulation
        abortRef.current = false;
        const origAbort = abortRef;
        const checkAbort = setInterval(() => {
          if (origAbort.current) { xhr.abort(); clearInterval(checkAbort); }
        }, 200);
        xhr.onloadend = () => clearInterval(checkAbort);
      });

      setProgress(100);
      setStatus('done');
      setStatusMsg('Upload terminé. Analyse Volatility 3 en cours dans VolWeb…');
      onDone?.();

    } catch (err) {
      if (abortRef.current) {
        setStatus('idle');
        setStatusMsg('');
      } else {
        setStatus('error');
        setError(err.message || 'Erreur upload');
      }
    }
  }, [file, dumpOs, additionalFiles, caseId, onDone]);

  const cancel = () => { abortRef.current = true; };

  const s = {
    panel: {
      background: 'var(--fl-bg)', border: '1px solid var(--fl-card)', borderRadius: 10,
      padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: 16,
    },
    header: { display: 'flex', alignItems: 'center', justifyContent: 'space-between' },
    title: {
      display: 'flex', alignItems: 'center', gap: 8,
      fontSize: 13, fontFamily: 'monospace', fontWeight: 700, color: 'var(--fl-purple)',
    },
    dropzone: {
      border: '2px dashed var(--fl-card)', borderRadius: 8, padding: '28px 20px',
      textAlign: 'center', cursor: 'pointer', transition: 'border-color 0.2s',
      background: '#0a0f1a',
    },
    osRow: {
      display: 'flex', gap: 8, alignItems: 'center',
      fontSize: 12, fontFamily: 'monospace', color: 'var(--fl-dim)',
    },
    osBtnBase: {
      padding: '4px 12px', borderRadius: 5, fontSize: 11, fontFamily: 'monospace',
      cursor: 'pointer', border: '1px solid var(--fl-card)', transition: 'all 0.15s',
    },
    progressBar:  { background: 'var(--fl-card)', borderRadius: 4, height: 6, overflow: 'hidden' },
    progressFill: (pct) => ({
      height: '100%', borderRadius: 4, transition: 'width 0.3s ease', width: `${pct}%`,
      background: status === 'done' ? '#22c55e'
        : status === 'error' ? 'var(--fl-danger)'
        : 'linear-gradient(90deg, var(--fl-accent), #8b72d6)',
    }),
    uploadBtn: {
      display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7,
      padding: '9px 20px', borderRadius: 7, cursor: 'pointer',
      fontSize: 12, fontFamily: 'monospace', fontWeight: 700,
      background: 'rgba(139,114,214,0.15)', color: 'var(--fl-purple)',
      border: '1px solid rgba(139,114,214,0.35)', transition: 'all 0.15s',
    },
    addSection: {
      border: '1px solid var(--fl-card)', borderRadius: 8, padding: '12px 14px',
      display: 'flex', flexDirection: 'column', gap: 8,
    },
    addTitle: {
      fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-dim)',
      display: 'flex', alignItems: 'center', gap: 6,
    },
    fileChip: {
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      background: 'rgba(255,255,255,0.04)', borderRadius: 5, padding: '4px 8px',
      fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-text)',
    },
    addBtn: {
      display: 'flex', alignItems: 'center', gap: 5,
      fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-accent)',
      background: 'none', border: '1px dashed rgba(99,179,237,0.3)', borderRadius: 5,
      padding: '4px 10px', cursor: 'pointer',
    },
  };

  const isRunning = status === 'uploading' || status === 'hashing';

  return (
    <div style={s.panel}>
      {/* Header */}
      <div style={s.header}>
        <span style={s.title}><Cpu size={14} /> Upload Dump Mémoire (RAM)</span>
        {onClose && (
          <button onClick={onClose} style={{ color: 'var(--fl-subtle)', background: 'none', border: 'none', cursor: 'pointer' }}>
            <X size={14} />
          </button>
        )}
      </div>

      {/* Dropzone dump principal */}
      {!file && status === 'idle' && (
        <div
          ref={dropRef}
          style={s.dropzone}
          onDrop={onDrop}
          onDragOver={onDragOver}
          onDragLeave={onDragLeave}
          onClick={() => document.getElementById(`mem-file-input-${caseId}`)?.click()}
        >
          <input
            id={`mem-file-input-${caseId}`}
            type="file"
            accept=".raw,.mem,.vmem,.dmp,.lime,.bin"
            style={{ display: 'none' }}
            onChange={e => handleFile(e.target.files?.[0])}
          />
          <Upload size={28} style={{ color: 'var(--fl-subtle)', marginBottom: 8 }} />
          <div style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--fl-dim)' }}>
            Glisser-déposer un dump RAM ou cliquer pour sélectionner
          </div>
          <div style={{ fontSize: 10, color: 'var(--fl-subtle)', marginTop: 4 }}>
            .raw · .mem · .vmem · .dmp · .lime · .bin
          </div>
        </div>
      )}

      {/* Fichier sélectionné */}
      {file && status === 'idle' && (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, fontFamily: 'monospace', color: 'var(--fl-text)' }}>
            <FileArchive size={14} style={{ color: 'var(--fl-purple)' }} />
            <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{file.name}</span>
            <span style={{ color: 'var(--fl-dim)', flexShrink: 0 }}>{formatBytes(file.size)}</span>
            <button onClick={() => { setFile(null); setAdditionalFiles([]); }} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-subtle)' }}>
              <X size={12} />
            </button>
          </div>

          {/* Sélection OS */}
          <div style={s.osRow}>
            <span>OS :</span>
            {OS_OPTIONS.map(o => (
              <button
                key={o.value}
                onClick={() => setDumpOs(o.value)}
                style={{
                  ...s.osBtnBase,
                  background:   dumpOs === o.value ? 'rgba(139,114,214,0.2)' : 'transparent',
                  color:        dumpOs === o.value ? 'var(--fl-purple)' : 'var(--fl-dim)',
                  borderColor:  dumpOs === o.value ? 'rgba(139,114,214,0.5)' : 'var(--fl-card)',
                }}
              >
                {o.label}
              </button>
            ))}
          </div>

          {/* Fichiers additionnels */}
          <div style={s.addSection}>
            <div style={s.addTitle}>
              <Plus size={11} />
              Fichiers additionnels
              <span style={{ color: 'var(--fl-subtle)', fontSize: 10 }}>
                — symbols (.pdb, .json.xz, .isf), snapshot (.vmsn, .vmss), etc.
              </span>
            </div>

            {additionalFiles.map(f => (
              <div key={f.name} style={s.fileChip}>
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{f.name}</span>
                <span style={{ color: 'var(--fl-dim)', marginLeft: 8, flexShrink: 0 }}>{formatBytes(f.size)}</span>
                <button
                  onClick={() => removeAdditional(f.name)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-subtle)', marginLeft: 6 }}
                >
                  <Trash2 size={11} />
                </button>
              </div>
            ))}

            <input
              ref={addInputRef}
              type="file"
              accept={ADDITIONAL_ACCEPT}
              multiple
              style={{ display: 'none' }}
              onChange={e => { handleAdditionalFiles(e.target.files); e.target.value = ''; }}
            />
            <button style={s.addBtn} onClick={() => addInputRef.current?.click()}>
              <Plus size={11} /> Ajouter un fichier
            </button>
          </div>
        </>
      )}

      {/* Progression */}
      {(isRunning || status === 'done' || status === 'error') && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div style={s.progressBar}>
            <div style={s.progressFill(progress)} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-dim)' }}>
            <span>{statusMsg}</span>
            <span>{progress}%</span>
          </div>
        </div>
      )}

      {/* Erreur */}
      {error && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-danger)' }}>
          <AlertCircle size={13} />
          {error}
        </div>
      )}

      {/* Succès */}
      {status === 'done' && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontFamily: 'monospace', color: '#22c55e' }}>
          <CheckCircle2 size={13} />
          Dump uploadé — analyse Volatility 3 lancée dans VolWeb
        </div>
      )}

      {/* Actions */}
      {status === 'idle' && file && (
        <button style={s.uploadBtn} onClick={() => startUpload(false)}>
          <Upload size={13} />
          Lancer l'upload
          {additionalFiles.length > 0 && (
            <span style={{ opacity: 0.7, fontWeight: 400 }}>
              ({1 + additionalFiles.length} fichier{additionalFiles.length > 0 ? 's' : ''})
            </span>
          )}
        </button>
      )}

      {isRunning && (
        <button onClick={cancel} style={{ ...s.uploadBtn, color: 'var(--fl-danger)', borderColor: 'rgba(239,68,68,0.35)', background: 'rgba(239,68,68,0.08)' }}>
          <X size={13} /> Annuler
        </button>
      )}

      {status === 'done' && onClose && (
        <button style={{ ...s.uploadBtn, color: '#22c55e', borderColor: 'rgba(34,197,94,0.35)', background: 'rgba(34,197,94,0.08)' }} onClick={onClose}>
          <CheckCircle2 size={13} /> Fermer
        </button>
      )}
    </div>
  );
}