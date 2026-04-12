
import React, { useState, useRef, useCallback, useEffect } from 'react';
import { Upload, Cpu, X, AlertCircle, CheckCircle2, Loader2, FileArchive, RotateCw } from 'lucide-react';
import api from '../../utils/api';

const DEFAULT_CHUNK_SIZE = 50 * 1024 * 1024;
const OS_OPTIONS = [
  { value: 'windows', label: 'Windows' },
  { value: 'linux',   label: 'Linux' },
  { value: 'mac',     label: 'macOS' },
];

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
  const [file,       setFile]       = useState(null);
  const [dumpOs,     setDumpOs]     = useState('windows');
  const [status,     setStatus]     = useState('idle');
  const [progress,   setProgress]   = useState(0);
  const [statusMsg,  setStatusMsg]  = useState('');
  const [error,      setError]      = useState(null);
  const [resumeInfo, setResumeInfo] = useState(null);
  const abortRef   = useRef(false);
  const dropRef    = useRef(null);

  const guessOs = useCallback((filename) => {
    if (/linux/i.test(filename))         return 'linux';
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
        .catch(() => {
          localStorage.removeItem(key);
        });
    }
  }, [caseId, guessOs]);

  const onDrop = useCallback((e) => {
    e.preventDefault();
    dropRef.current?.classList.remove('dragover');
    handleFile(e.dataTransfer.files?.[0]);
  }, [handleFile]);

  const onDragOver = useCallback((e) => {
    e.preventDefault();
    dropRef.current?.classList.add('dragover');
  }, []);

  const onDragLeave = useCallback(() => {
    dropRef.current?.classList.remove('dragover');
  }, []);

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
      setError('Session expirée — veuillez vous reconnecter avant de lancer l\'upload.');
      return;
    }

    let uploadId, chunkSize, totalChunks;
    const receivedSet = new Set();

    try {
      if (isResume && resumeInfo) {
        uploadId    = resumeInfo.uploadId;
        chunkSize   = resumeInfo.chunkSize;
        totalChunks = resumeInfo.totalChunks;
        resumeInfo.receivedSet.forEach(i => receivedSet.add(i));
        setProgress(Math.round((receivedSet.size / totalChunks) * 90));
        setStatusMsg(`Reprise — ${receivedSet.size}/${totalChunks} chunks déjà reçus`);
      } else {
        chunkSize   = DEFAULT_CHUNK_SIZE;
        totalChunks = Math.ceil(file.size / chunkSize);

        setStatusMsg('Initialisation…');
        setProgress(0);
        const initRes = await api.post(`/volweb/memory/${caseId}/initiate`, {
          filename:     file.name,
          total_size:   file.size,
          total_chunks: totalChunks,
          dump_os:      dumpOs,
        });
        uploadId  = initRes.data.upload_id;
        chunkSize = initRes.data.chunk_size || chunkSize;
        totalChunks = Math.ceil(file.size / chunkSize);

        localStorage.setItem(resumeKey(caseId, file.name, file.size), uploadId);
      }

      const sendChunkWithRetry = async (i, maxAttempts = 4) => {
        const start = i * chunkSize;
        const end   = Math.min(start + chunkSize, file.size);
        for (let attempt = 0; attempt < maxAttempts; attempt++) {
          try {
            await api.post(
              `/volweb/memory/${caseId}/chunk?upload_id=${uploadId}&chunk_index=${i}`,
              file.slice(start, end),
              { headers: { 'Content-Type': 'application/octet-stream' } }
            );
            return;
          } catch (err) {
            if (attempt === maxAttempts - 1) throw err;
            await new Promise(r => setTimeout(r, 1000 * Math.pow(2, attempt)));
          }
        }
      };

      for (let i = 0; i < totalChunks; i++) {
        if (abortRef.current) throw new Error('Upload annulé');
        if (receivedSet.has(i)) continue;

        await sendChunkWithRetry(i);

        receivedSet.add(i);
        const end = Math.min((i + 1) * chunkSize, file.size);
        const pct = Math.round((receivedSet.size / totalChunks) * 90);
        setProgress(pct);
        setStatusMsg(`Envoi ${receivedSet.size}/${totalChunks} — ${formatBytes(end)} / ${formatBytes(file.size)}`);
      }

      setStatus('hashing');
      setProgress(92);
      setStatusMsg('Finalisation et calcul des hashes SHA-256…');

      const completeRes = await api.post(`/volweb/memory/${caseId}/complete`, {
        upload_id: uploadId,
      });

      localStorage.removeItem(resumeKey(caseId, file.name, file.size));

      setProgress(100);
      setStatus('done');
      setStatusMsg('Upload terminé. Analyse Volatility 3 en cours dans VolWeb…');
      onDone?.(completeRes.data);

    } catch (err) {
      if (abortRef.current) {
        setStatus('idle');
        setStatusMsg('');
      } else {
        setStatus('error');
        setError(err.response?.data?.error || err.message || 'Erreur upload');
      }
    }
  }, [file, dumpOs, caseId, onDone, resumeInfo]);

  const cancel = () => { abortRef.current = true; };

  const s = {
    panel: {
      background: 'var(--fl-bg)', border: '1px solid var(--fl-card)', borderRadius: 10,
      padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: 16,
    },
    header: {
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    },
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
    progressBar: {
      background: 'var(--fl-card)', borderRadius: 4, height: 6, overflow: 'hidden',
    },
    progressFill: (pct) => ({
      height: '100%', borderRadius: 4, transition: 'width 0.3s ease',
      width: `${pct}%`,
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
  };

  const isRunning = status === 'uploading' || status === 'hashing';
  const chunkSizeMB = Math.round((resumeInfo?.chunkSize || DEFAULT_CHUNK_SIZE) / 1024 / 1024);

  return (
    <div style={s.panel}>
      <div style={s.header}>
        <span style={s.title}><Cpu size={14} /> Upload Dump Mémoire (RAM)</span>
        {onClose && (
          <button onClick={onClose} style={{ color: 'var(--fl-subtle)', background: 'none', border: 'none', cursor: 'pointer' }}>
            <X size={14} />
          </button>
        )}
      </div>

      {status === 'idle' && !file && (
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
            .raw · .mem · .vmem · .dmp · .lime · jusqu'à 256 GB
          </div>
        </div>
      )}

      {file && status === 'idle' && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', background: '#0a0f1a', borderRadius: 6, border: '1px solid var(--fl-card)' }}>
          <FileArchive size={14} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} />
          <div style={{ flex: 1, overflow: 'hidden' }}>
            <div style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--fl-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {file.name}
            </div>
            <div style={{ fontSize: 10, color: 'var(--fl-dim)', fontFamily: 'monospace' }}>
              {formatBytes(file.size)} · {Math.ceil(file.size / (resumeInfo?.chunkSize || DEFAULT_CHUNK_SIZE))} chunks × {chunkSizeMB} MB
            </div>
          </div>
          <button onClick={() => { setFile(null); setResumeInfo(null); }} style={{ color: 'var(--fl-subtle)', background: 'none', border: 'none', cursor: 'pointer', flexShrink: 0 }}>
            <X size={12} />
          </button>
        </div>
      )}

      {resumeInfo && status === 'idle' && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px',
          background: 'rgba(77,130,192,0.08)', borderRadius: 6,
          border: '1px solid rgba(77,130,192,0.25)', fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-accent)',
        }}>
          <RotateCw size={12} />
          Upload précédent détecté — {resumeInfo.receivedSet.size}/{resumeInfo.totalChunks} chunks reçus ({Math.round((resumeInfo.receivedSet.size / resumeInfo.totalChunks) * 100)}%)
        </div>
      )}

      {file && status === 'idle' && !resumeInfo && (
        <div style={s.osRow}>
          <span>OS cible :</span>
          {OS_OPTIONS.map(opt => (
            <button
              key={opt.value}
              onClick={() => setDumpOs(opt.value)}
              style={{
                ...s.osBtnBase,
                background:  dumpOs === opt.value ? 'rgba(139,114,214,0.15)' : 'transparent',
                color:       dumpOs === opt.value ? 'var(--fl-purple)' : 'var(--fl-dim)',
                borderColor: dumpOs === opt.value ? 'rgba(139,114,214,0.35)' : 'var(--fl-card)',
              }}
            >
              {opt.label}
            </button>
          ))}
        </div>
      )}

      {(isRunning || status === 'done' || status === 'error') && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-dim)' }}>
              {statusMsg}
            </span>
            <span style={{ fontSize: 10, fontFamily: 'monospace', color: status === 'done' ? '#22c55e' : status === 'error' ? 'var(--fl-danger)' : 'var(--fl-purple)' }}>
              {progress}%
            </span>
          </div>
          <div style={s.progressBar}>
            <div style={s.progressFill(progress)} />
          </div>
        </div>
      )}

      {status === 'done' && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontFamily: 'monospace', color: '#22c55e' }}>
          <CheckCircle2 size={13} />
          Upload terminé — Volatility 3 démarre dans VolWeb
        </div>
      )}

      {error && (
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6, fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-danger)', background: 'rgba(218,54,51,0.08)', padding: '8px 12px', borderRadius: 6, border: '1px solid rgba(218,54,51,0.2)' }}>
          <AlertCircle size={13} style={{ flexShrink: 0, marginTop: 1 }} />
          {error}
        </div>
      )}

      <div style={{ display: 'flex', gap: 8 }}>
        {file && status === 'idle' && !resumeInfo && (
          <button style={s.uploadBtn} onClick={() => startUpload(false)}>
            <Upload size={13} /> Démarrer l'upload
          </button>
        )}
        {file && status === 'idle' && resumeInfo && (
          <>
            <button style={s.uploadBtn} onClick={() => startUpload(true)}>
              <RotateCw size={13} /> Reprendre l'upload
            </button>
            <button
              style={{ ...s.uploadBtn, color: 'var(--fl-dim)', borderColor: 'var(--fl-card)', background: 'transparent' }}
              onClick={() => {
                localStorage.removeItem(resumeKey(caseId, file.name, file.size));
                setResumeInfo(null);
              }}
            >
              Recommencer
            </button>
          </>
        )}
        {isRunning && (
          <button
            onClick={cancel}
            style={{ ...s.uploadBtn, color: 'var(--fl-danger)', borderColor: 'rgba(218,54,51,0.35)', background: 'rgba(218,54,51,0.08)' }}
          >
            <X size={13} /> Annuler
          </button>
        )}
        {isRunning && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontFamily: 'monospace', color: 'var(--fl-dim)' }}>
            <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} />
            {status === 'hashing' ? 'Calcul hashes…' : 'Envoi en cours…'}
          </div>
        )}
      </div>
    </div>
  );
}
