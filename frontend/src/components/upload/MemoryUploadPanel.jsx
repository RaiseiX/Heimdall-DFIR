
import React, { useState, useRef, useCallback } from 'react';
import { Upload, Cpu, X, AlertCircle, CheckCircle2, Loader2, FileArchive, Paperclip } from 'lucide-react';
import { useTranslation } from 'react-i18next';

const OS_OPTIONS = [
  { value: 'windows', label: 'Windows' },
  { value: 'linux',   label: 'Linux' },
  { value: 'mac',     label: 'macOS' },
];
const ADDITIONAL_ACCEPT = '.vmsn,.vmss,.pdb,.json,.xz,.zip,.gz,.isf,.lzma,.dwarf,.sym,.symbols';

const ADDITIONAL_ACCEPT = '.vmsn,.vmss,.pdb,.json,.xz,.zip,.gz,.isf,.lzma,.dwarf,.sym,.symbols';

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export default function MemoryUploadPanel({ caseId, onDone, onClose }) {
  const { t } = useTranslation();
  const [file,            setFile]            = useState(null);
  const [additionalFiles, setAdditionalFiles] = useState([]);
  const [dumpOs,          setDumpOs]          = useState('windows');
  const [status,          setStatus]          = useState('idle');
  const [progress,        setProgress]        = useState(0);
  const [statusMsg,       setStatusMsg]       = useState('');
  const [error,           setError]           = useState(null);

  const xhrRef    = useRef(null);
  const dropRef   = useRef(null);
  const addInputRef = useRef(null);

  const guessOs = useCallback((filename) => {
    if (/linux/i.test(filename))          return 'linux';
    if (/mac|osx|darwin/i.test(filename)) return 'mac';
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

  const onDrop = useCallback((e) => {
    e.preventDefault();
    dropRef.current?.classList.remove('dragover');
    handleFile(e.dataTransfer.files?.[0]);
  }, [handleFile]);

  const onDragOver  = useCallback((e) => { e.preventDefault(); dropRef.current?.classList.add('dragover'); }, []);
  const onDragLeave = useCallback(() => { dropRef.current?.classList.remove('dragover'); }, []);

  const startUpload = useCallback(() => {
    if (!file) return;
    setError(null);
    setStatus('uploading');
    setProgress(0);
    setStatusMsg(t('upload.memory_status_uploading'));

    const token = localStorage.getItem('heimdall_token');
    const formData = new FormData();
    formData.append('file', file, file.name);
    formData.append('dump_os', dumpOs);
    formData.append('evidence_type', 'memory');
    for (const extra of additionalFiles) {
      formData.append('additionalFiles', extra, extra.name);
    }

    const xhr = new XMLHttpRequest();
    xhrRef.current = xhr;

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) {
        const pct = Math.round((e.loaded / e.total) * 95);
        setProgress(pct);
        setStatusMsg(t('upload.memory_status_progress', { loaded: formatBytes(e.loaded), total: formatBytes(e.total) }));
      }
    };

    xhr.onload = () => {
      xhrRef.current = null;
      if (xhr.status === 201) {
        setProgress(100);
        setStatus('done');
        setStatusMsg(t('upload.memory_done_msg'));
        try { onDone?.(JSON.parse(xhr.responseText)); } catch { onDone?.(); }
      } else {
        setStatus('error');
        let msg = t('upload.memory_error');
        try { msg = JSON.parse(xhr.responseText)?.error || msg; } catch {}
        setError(msg);
      }
    };

    xhr.onerror = () => {
      xhrRef.current = null;
      setStatus('error');
      setError(t('upload.network_error'));
    };

    xhr.onabort = () => {
      xhrRef.current = null;
      setStatus('idle');
      setStatusMsg('');
    };

    const base = (import.meta.env.VITE_API_URL || '/api').replace(/\/$/, '');
    xhr.open('POST', `${base}/evidence/${caseId}/upload-stream`);
    xhr.setRequestHeader('Authorization', `Bearer ${token}`);
    xhr.send(formData);
  }, [file, dumpOs, additionalFiles, caseId, onDone, t]);

  const cancel = () => { xhrRef.current?.abort(); };

  const removeAdditional = (idx) => setAdditionalFiles(prev => prev.filter((_, i) => i !== idx));

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
      fontSize: 13, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, color: 'var(--fl-purple)',
    },
    dropzone: {
      border: '2px dashed var(--fl-card)', borderRadius: 8, padding: '28px 20px',
      textAlign: 'center', cursor: 'pointer', transition: 'border-color 0.2s',
      background: '#0a0f1a',
    },
    osRow: {
      display: 'flex', gap: 8, alignItems: 'center',
      fontSize: 12, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)',
    },
    osBtnBase: {
      padding: '4px 12px', borderRadius: 5, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
      cursor: 'pointer', border: '1px solid var(--fl-card)', transition: 'all 0.15s',
    },
    progressBar: {
      background: 'var(--fl-card)', borderRadius: 4, height: 6, overflow: 'hidden',
    },
    progressFill: (pct) => ({
      height: '100%', borderRadius: 4, transition: 'width 0.3s ease',
      width: `${pct}%`,
      background: status === 'done' ? 'var(--fl-ok)'
        : status === 'error' ? 'var(--fl-danger)'
        : 'linear-gradient(90deg, var(--fl-accent), var(--fl-purple))',
    }),
    uploadBtn: {
      display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7,
      padding: '9px 20px', borderRadius: 7, cursor: 'pointer',
      fontSize: 12, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700,
      background: 'rgba(139,114,214,0.15)', color: 'var(--fl-purple)',
      border: '1px solid rgba(139,114,214,0.35)', transition: 'all 0.15s',
    },
  };

  const isRunning = status === 'uploading';

  return (
    <div style={s.panel}>
      <div style={s.header}>
        <span style={s.title}><Cpu size={14} /> {t('upload.memory_title')}</span>
        {onClose && (
          <button onClick={onClose} style={{ color: 'var(--fl-subtle)', background: 'none', border: 'none', cursor: 'pointer' }}>
            <X size={14} />
          </button>
        )}
      </div>

      {/* Main file drop zone */}
      {status === 'idle' && !file && (
        <div
          ref={dropRef}
          style={s.dropzone}
          onDrop={onDrop}
          onDragOver={onDragOver}
          onDragLeave={onDragLeave}
          onClick={() => document.getElementById(`mem-file-input-${caseId}`)?.click()}
        >
          <input id={`mem-file-input-${caseId}`} type="file" accept=".raw,.mem,.vmem,.dmp,.lime,.bin" style={{ display: 'none' }} onChange={e => handleFile(e.target.files?.[0])} />
          <Upload size={28} style={{ color: 'var(--fl-subtle)', marginBottom: 8 }} />
          <div style={{ fontSize: 12, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)' }}>
            {t('upload.memory_drop')}
          </div>
          <div style={{ fontSize: 10, color: 'var(--fl-subtle)', marginTop: 4 }}>
            {t('upload.memory_types_hint')}
          </div>
        </div>
      )}

      {/* Selected main file */}
      {file && status === 'idle' && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', background: '#0a0f1a', borderRadius: 6, border: '1px solid var(--fl-card)' }}>
          <FileArchive size={14} style={{ color: 'var(--fl-accent)', flexShrink: 0 }} />
          <div style={{ flex: 1, overflow: 'hidden' }}>
            <div style={{ fontSize: 12, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {file.name}
            </div>
            <div style={{ fontSize: 10, color: 'var(--fl-dim)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>
              {formatBytes(file.size)}
            </div>
          </div>
          <button onClick={() => { setFile(null); setAdditionalFiles([]); }} style={{ color: 'var(--fl-subtle)', background: 'none', border: 'none', cursor: 'pointer', flexShrink: 0 }}>
            <X size={12} />
          </button>
        </div>
      )}

      {/* OS selector */}
      {file && status === 'idle' && (
        <div style={s.osRow}>
          <span>{t('upload.target_os')}</span>
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
          </div>
        </>
      )}

      {/* Additional files (symbols, snapshots…) */}
      {file && status === 'idle' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)' }}>
            <Paperclip size={11} />
            <span>{t('upload.additional_files')}</span>
            <button
              onClick={() => addInputRef.current?.click()}
              style={{ marginLeft: 'auto', padding: '2px 8px', borderRadius: 4, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'transparent', border: '1px solid var(--fl-card)', color: 'var(--fl-dim)', cursor: 'pointer' }}
            >
              {t('upload.add')}
            </button>
            <input
              ref={addInputRef}
              type="file"
              accept={ADDITIONAL_ACCEPT}
              multiple
              style={{ display: 'none' }}
              onChange={e => {
                const picked = Array.from(e.target.files || []);
                setAdditionalFiles(prev => [...prev, ...picked]);
                e.target.value = '';
              }}
            />
          </div>
          {additionalFiles.length > 0 && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {additionalFiles.map((f, idx) => (
                <span key={idx} style={{
                  display: 'inline-flex', alignItems: 'center', gap: 4,
                  fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                  background: 'rgba(139,114,214,0.08)', borderRadius: 4,
                  padding: '2px 6px', border: '1px solid rgba(139,114,214,0.2)',
                  color: 'var(--fl-dim)',
                }}>
                  {f.name} · {formatBytes(f.size)}
                  <button onClick={() => removeAdditional(idx)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-subtle)', padding: 0, lineHeight: 1 }}>
                    <X size={9} />
                  </button>
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Progress */}
      {(isRunning || status === 'done' || status === 'error') && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)' }}>
              {statusMsg}
            </span>
            <span style={{ fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: status === 'done' ? 'var(--fl-ok)' : status === 'error' ? 'var(--fl-danger)' : 'var(--fl-purple)' }}>
              {progress}%
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, fontFamily: 'monospace', color: 'var(--fl-dim)' }}>
            <span>{statusMsg}</span><span>{progress}%</span>
          </div>
        </div>
      )}

      {status === 'done' && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-ok)' }}>
          <CheckCircle2 size={13} />
          {t('upload.memory_done')}
        </div>
      )}

      {error && (
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-danger)', background: 'rgba(218,54,51,0.08)', padding: '8px 12px', borderRadius: 6, border: '1px solid rgba(218,54,51,0.2)' }}>
          <AlertCircle size={13} style={{ flexShrink: 0, marginTop: 1 }} />
          {error}
        </div>
      )}

      <div style={{ display: 'flex', gap: 8 }}>
        {file && status === 'idle' && (
          <button style={s.uploadBtn} onClick={startUpload}>
            <Upload size={13} /> {t('upload.start_upload')}
          </button>
        )}
        {isRunning && (
          <>
            <button
              onClick={cancel}
              style={{ ...s.uploadBtn, color: 'var(--fl-danger)', borderColor: 'rgba(218,54,51,0.35)', background: 'rgba(218,54,51,0.08)' }}
            >
              <X size={13} /> {t('upload.cancel')}
            </button>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-dim)' }}>
              <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} />
              {t('upload.memory_status_uploading')}
            </div>
          </>
        )}
      </div>
    </div>
  );
}