
import { useState, useEffect, useRef, useCallback } from 'react';
import { Sparkles, X, Maximize2, Minimize2, Send, Trash2, Users, Save, AlertCircle, ChevronDown, ChevronRight } from 'lucide-react';
import { useResizable } from '../../hooks/useResizable';
import { useDraggable } from '../../hooks/useDraggable';
import api from '../../utils/api';

const QUICK_ACTIONS = [
  'Résume les alertes critiques',
  'Quels artifacts suggèrent une persistance ?',
  'Technique ATT&CK la plus probable ?',
  'Prochaines étapes d\'investigation ?',
  'Génère un résumé d\'incident',
];

function parseThink(raw) {
  const OPEN = '<think>', CLOSE = '</think>';
  const oIdx = raw.indexOf(OPEN);
  if (oIdx < 0) return { think: '', response: raw, isThinking: false };
  const cIdx = raw.indexOf(CLOSE);
  if (cIdx < 0) return {
    think:      raw.slice(oIdx + OPEN.length),
    response:   raw.slice(0, oIdx).trimEnd(),
    isThinking: true,
  };
  return {
    think:      raw.slice(oIdx + OPEN.length, cIdx),
    response:   (raw.slice(0, oIdx) + raw.slice(cIdx + CLOSE.length)).trimStart(),
    isThinking: false,
  };
}

function LiveThinking({ content, isActive, collapsed, onToggle }) {
  const scrollRef = useRef(null);

  useEffect(() => {
    if (isActive && scrollRef.current)
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [content, isActive]);

  if (!content && !isActive) return null;

  return (
    <div style={{
      marginBottom: 5, borderRadius: 5,
      border: `1px solid ${isActive ? '#1a4a2a' : '#0d2a1a'}`,
      background: 'rgba(2,8,4,0.85)', overflow: 'hidden',
      fontSize: 9, fontFamily: 'monospace',
    }}>
      <div onClick={onToggle} style={{
        display: 'flex', alignItems: 'center', gap: 5,
        padding: '3px 8px', cursor: 'pointer',
        background: 'rgba(2,10,5,0.95)',
        borderBottom: collapsed ? 'none' : '1px solid #0d2a1a',
        userSelect: 'none',
      }}>
        {isActive
          ? <span style={{ color: '#22c55e', fontSize: 8 }}>●</span>
          : <span style={{ color: '#3a8a5a', fontSize: 8 }}>✓</span>}
        <span style={{ color: isActive ? '#22c55e' : '#2a6a3a' }}>
          {isActive ? 'Raisonnement en cours…' : 'Raisonnement terminé'}
        </span>
        <span style={{ marginLeft: 'auto', color: '#0d3a1a', fontSize: 8 }}>
          {collapsed ? '▶' : '▼'}
        </span>
      </div>
      {!collapsed && content && (
        <div ref={scrollRef} style={{
          padding: '5px 8px', maxHeight: 180, overflowY: 'auto',
          color: '#2a7a4a', lineHeight: 1.6,
          whiteSpace: 'pre-wrap', wordBreak: 'break-word',
        }}>
          {content}
          {isActive && <span style={{ color: '#22c55e' }}>▌</span>}
        </div>
      )}
    </div>
  );
}

const MITRE_RE = /\bT\d{4}(?:\.\d{3})?\b/g;

function ThinkingSteps({ steps, collapsed, onToggle }) {
  if (!steps || steps.length === 0) return null;

  const lastStep   = steps[steps.length - 1];
  const isGenerating = lastStep?.status === 'generating';
  const doneCount  = steps.filter(s => s.status === 'done').length;
  const total      = steps.filter(s => s.status !== 'generating').length;

  return (
    <div style={{
      marginBottom: 6,
      borderRadius: 5,
      border: '1px solid #0d2035',
      background: 'rgba(4,10,20,0.7)',
      overflow: 'hidden',
      fontSize: 9,
      fontFamily: 'monospace',
    }}>
      
      <div
        onClick={onToggle}
        style={{
          display: 'flex', alignItems: 'center', gap: 5,
          padding: '4px 8px', cursor: 'pointer',
          background: 'rgba(4,14,28,0.9)',
          borderBottom: collapsed ? 'none' : '1px solid #0d2035',
          userSelect: 'none',
        }}
      >
        {collapsed
          ? <ChevronRight size={9} style={{ color: '#2a5a8a', flexShrink: 0 }} />
          : <ChevronDown  size={9} style={{ color: '#2a5a8a', flexShrink: 0 }} />
        }
        <span style={{ color: '#1a4a6a' }}>
          {isGenerating
            ? <><span style={{ color: 'var(--fl-accent)' }}>🤖</span> Génération en cours…</>
            : `Contexte lu — ${doneCount}/${total} sources`
          }
        </span>
        {!collapsed && (
          <span style={{ marginLeft: 'auto', color: '#0d2a40', fontSize: 8 }}>cliquer pour replier</span>
        )}
      </div>

      {!collapsed && (
        <div style={{ padding: '5px 8px', display: 'flex', flexDirection: 'column', gap: 3 }}>
          {steps.map((step, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              
              {step.status === 'loading' && (
                <span style={{ color: '#3a6a9a', flexShrink: 0 }}>⟳</span>
              )}
              {step.status === 'done' && (
                <span style={{ color: '#22c55e', flexShrink: 0, fontSize: 8 }}>✓</span>
              )}
              {step.status === 'generating' && (
                <span style={{ color: 'var(--fl-accent)', flexShrink: 0, animation: 'blink 1s step-end infinite' }}>▌</span>
              )}

              <span style={{
                color: step.status === 'done'
                  ? '#3a8a5a'
                  : step.status === 'generating'
                    ? 'var(--fl-accent)'
                    : '#2a5a8a',
              }}>
                {step.icon} {step.label}
              </span>

              {step.count !== undefined && (
                <span style={{ color: '#1a4060', marginLeft: 2 }}>
                  [{step.count}]
                </span>
              )}
              {step.detail && (
                <span style={{ color: '#1a5a3a', marginLeft: 2, opacity: 0.85 }}>
                  — {step.detail}
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function MitreTag({ id }) {
  return (
    <span style={{
      display: 'inline-block', fontSize: 8, fontFamily: 'monospace',
      padding: '0 5px', borderRadius: 3, margin: '0 2px',
      background: 'rgba(139,114,214,0.15)', color: 'var(--fl-purple)',
      border: '1px solid rgba(139,114,214,0.3)',
      lineHeight: '16px',
    }}
    title={`MITRE ATT&CK — ${id}`}
    >{id}</span>
  );
}

function MessageContent({ content, hasContext }) {
  if (!content) return null;

  const parts = [];
  let last = 0;
  const re = new RegExp(MITRE_RE.source, 'g');
  let m;

  while ((m = re.exec(content)) !== null) {
    if (m.index > last) parts.push(content.slice(last, m.index));
    parts.push(<MitreTag key={m.index} id={m[0]} />);
    last = m.index + m[0].length;
  }
  if (last < content.length) parts.push(content.slice(last));

  return (
    <div>
      <div style={{
        fontFamily: 'monospace', fontSize: 10.5, lineHeight: 1.7,
        color: 'var(--fl-on-dark)', whiteSpace: 'pre-wrap', wordBreak: 'break-word',
      }}>
        {parts}
      </div>
      {hasContext && (
        <div style={{ marginTop: 6, fontSize: 8, fontFamily: 'monospace', color: '#2a5a8a', display: 'flex', alignItems: 'center', gap: 3 }}>
          <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#22c55e', display: 'inline-block', flexShrink: 0 }} />
          Contexte investigateur actif au moment de cette réponse
        </div>
      )}
    </div>
  );
}

export default function AiCopilotModal({ caseId, caseName, isOpen, onClose, socket }) {
  const { size, isFullscreen, toggleFullscreen, getResizeHandleProps } = useResizable(
    `ai-modal-size-${caseId}`,
    { width: 520, height: 640 }
  );
  const { position, getDragHandleProps } = useDraggable(
    `ai-modal-pos-${caseId}`,
    { x: null, y: null }
  );

  const [tab, setTab]                         = useState('chat');
  const [messages, setMessages]               = useState([]);
  const [streaming, setStreaming]             = useState(false);
  const [input, setInput]                     = useState('');
  const [model, setModel]                     = useState('');
  const [models, setModels]                   = useState([]);
  const [loadingHistory, setLoadingHistory]   = useState(true);
  const [clearConfirm, setClearConfirm]       = useState(false);

  const [freeText, setFreeText]               = useState('');
  const [savedText, setSavedText]             = useState('');
  const [ctxMeta, setCtxMeta]                 = useState({ updatedBy: null, updatedAt: null });
  const [saveStatus, setSaveStatus]           = useState(null);
  const [clearCtxConfirm, setClearCtxConfirm] = useState(false);
  const [rtNotif, setRtNotif]                 = useState(null);

  const [collapsedThinking, setCollapsedThinking] = useState({});
  const [collapsedThink, setCollapsedThink]       = useState({});

  const abortRef       = useRef(null);
  const endRef         = useRef(null);
  const inputRef       = useRef(null);
  const autoSaveTimer  = useRef(null);
  const savedTextRef   = useRef('');

  const hasContext = savedText.trim().length > 0;

  useEffect(() => { savedTextRef.current = savedText; }, [savedText]);

  useEffect(() => {
    if (!isOpen) return;

    api.get('/ai/models').then(r => {
      if (r.data.available && r.data.models?.length) {
        setModels(r.data.models);
        setModel(r.data.models[0]);
      }
    }).catch(() => {});

    setLoadingHistory(true);
    api.get(`/cases/${caseId}/ai/history`)
      .then(r => setMessages(r.data.history || []))
      .catch(() => setMessages([]))
      .finally(() => setLoadingHistory(false));

    api.get(`/cases/${caseId}/ai/context`).then(r => {
      const text = r.data.freeText || '';
      setFreeText(text);
      setSavedText(text);
      setCtxMeta({ updatedBy: r.data.updatedBy, updatedAt: r.data.updatedAt });
    }).catch(() => {});
  }, [isOpen, caseId]);

  useEffect(() => {
    if (!socket || !isOpen) return;
    const handler = (data) => {
      const id = typeof caseId === 'string' ? parseInt(caseId, 10) : caseId;
      if (data.caseId !== id && data.caseId !== String(id)) return;
      setRtNotif({ updatedBy: data.updatedBy, preview: data.preview });
      api.get(`/cases/${caseId}/ai/context`).then(r => {
        const text = r.data.freeText || '';
        setFreeText(text);
        setSavedText(text);
        setCtxMeta({ updatedBy: r.data.updatedBy, updatedAt: r.data.updatedAt });
      }).catch(() => {});
      setTimeout(() => setRtNotif(null), 8000);
    };
    socket.on('ai:context:updated', handler);
    return () => socket.off('ai:context:updated', handler);
  }, [socket, isOpen, caseId]);

  useEffect(() => {
    if (tab === 'chat') endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, tab]);

  useEffect(() => {
    if (isOpen && tab === 'chat') setTimeout(() => inputRef.current?.focus(), 100);
  }, [isOpen, tab]);

  const triggerAutoSave = useCallback((text) => {
    if (autoSaveTimer.current) clearTimeout(autoSaveTimer.current);
    autoSaveTimer.current = setTimeout(async () => {
      if (text === savedTextRef.current) return;
      setSaveStatus('saving');
      try {
        await api.put(`/cases/${caseId}/ai/context`, { freeText: text });
        setSavedText(text);
        setSaveStatus('saved');
        setTimeout(() => setSaveStatus(null), 2000);
      } catch {
        setSaveStatus('error');
      }
    }, 2000);
  }, [caseId]);

  const handleFreeTextChange = (e) => {
    setFreeText(e.target.value);
    triggerAutoSave(e.target.value);
  };

  const saveContextNow = async () => {
    if (autoSaveTimer.current) clearTimeout(autoSaveTimer.current);
    setSaveStatus('saving');
    try {
      await api.put(`/cases/${caseId}/ai/context`, { freeText });
      setSavedText(freeText);
      setSaveStatus('saved');
      setCtxMeta(prev => ({ ...prev, updatedAt: new Date().toISOString() }));
      setTimeout(() => setSaveStatus(null), 2500);
    } catch {
      setSaveStatus('error');
    }
  };

  const clearContext = async () => {
    try {
      await api.delete(`/cases/${caseId}/ai/context`);
      setFreeText('');
      setSavedText('');
      setCtxMeta({ updatedBy: null, updatedAt: null });
      setClearCtxConfirm(false);
    } catch {}
  };

  const send = useCallback(async (text) => {
    const userMsg = (text || input).trim();
    if (!userMsg || streaming) return;
    setInput('');
    setClearConfirm(false);

    const now      = new Date().toISOString();
    const assistId = Date.now() + 1;
    setMessages(prev => [
      ...prev,
      { id: Date.now(),  role: 'user',      content: userMsg, created_at: now },
      { id: assistId,    role: 'assistant', content: '', loading: true, thinkingSteps: [], created_at: now },
    ]);
    setStreaming(true);

    try {
      const controller = new AbortController();
      abortRef.current = controller;

      const token = localStorage.getItem('heimdall_token');
      const res = await fetch(`/api/cases/${caseId}/ai/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ message: userMsg, model: model || undefined }),
        signal: controller.signal,
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const reader  = res.body.getReader();
      const decoder = new TextDecoder();
      let buf       = '';
      let ctxFlag   = false;
      let rawAccum  = '';
      let thinkDone = false;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop() ?? '';

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const data = line.slice(6);
          if (data === '[DONE]') break;
          try {
            const parsed = JSON.parse(data);

            if (parsed.thinking) {
              const step = parsed.thinking;
              setMessages(prev => {
                const arr = [...prev];
                const last = arr[arr.length - 1];
                if (last.role !== 'assistant') return arr;

                const existing = last.thinkingSteps || [];
                const idx = existing.findIndex(s => s.label === step.label);
                let updated;
                if (idx >= 0) {
                  updated = existing.map((s, i) => i === idx ? { ...s, ...step } : s);
                } else {
                  updated = [...existing, step];
                }
                arr[arr.length - 1] = { ...last, thinkingSteps: updated };
                return arr;
              });
              continue;
            }

            const token = parsed.response || '';
            if (token) {
              rawAccum += token;
              const { think, response, isThinking } = parseThink(rawAccum);

              if (!thinkDone && (response || isThinking)) {
                if (response && !isThinking) {
                  thinkDone = true;
                  setCollapsedThinking(prev => ({ ...prev, [assistId]: true }));
                }
              }

              setMessages(prev => {
                const arr = [...prev];
                const last = arr[arr.length - 1];
                if (last.role !== 'assistant') return arr;
                arr[arr.length - 1] = {
                  ...last,
                  content:    response,
                  thinkText:  think,
                  isThinking,
                  loading:    false,
                };
                return arr;
              });
            }

            if (parsed.done && parsed.hasContext) ctxFlag = true;
          } catch (_e) {}
        }
      }

      if (ctxFlag) {
        setMessages(prev => {
          const arr = [...prev];
          arr[arr.length - 1] = { ...arr[arr.length - 1], hasContext: true };
          return arr;
        });
      }

    } catch (e) {
      if (e.name !== 'AbortError') {
        setMessages(prev => {
          const arr = [...prev];
          arr[arr.length - 1] = {
            ...arr[arr.length - 1],
            content: `⚠ ${e.message}`,
            error: true,
            loading: false,
          };
          return arr;
        });
      }
    } finally {
      setStreaming(false);
      abortRef.current = null;
    }
  }, [input, streaming, model, caseId]);

  const clearHistory = async () => {
    await api.delete(`/cases/${caseId}/ai/history`);
    setMessages([]);
    setClearConfirm(false);
  };

  if (!isOpen) return null;

  const modalStyle = isFullscreen
    ? { position: 'fixed', inset: 0, width: '100vw', height: '100vh', borderRadius: 0 }
    : position?.x !== null
      ? { position: 'fixed', left: position.x, top: position.y, width: size.width, height: size.height, borderRadius: 12 }
      : { position: 'fixed', bottom: 24, right: 24, width: size.width, height: size.height, borderRadius: 12 };

  const { style: dragStyle, ...dragHandlers } = !isFullscreen
    ? getDragHandleProps(size.width, size.height)
    : { style: {} };

  const fmtDate = (iso) => iso
    ? new Date(iso).toLocaleString('fr-FR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }) + ' UTC'
    : null;

  return (
    <div style={{
      ...modalStyle,
      zIndex: 9100,
      background: '#080f1a',
      border: '1px solid var(--fl-accent)',
      boxShadow: '0 16px 64px rgba(0,0,0,0.8)',
      display: 'flex', flexDirection: 'column',
      overflow: 'hidden',
    }}>
      
      {!isFullscreen && (
        <>
          <div {...getResizeHandleProps('left')} style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: 5, cursor: 'ew-resize', zIndex: 10 }} />
          <div {...getResizeHandleProps('top')}  style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 5, cursor: 'ns-resize', zIndex: 10 }} />
          <div {...getResizeHandleProps('both')} style={{ position: 'absolute', top: 0, left: 0, width: 12, height: 12, cursor: 'nwse-resize', zIndex: 11 }} />
        </>
      )}

      <div
        {...dragHandlers}
        style={{
          flexShrink: 0, height: 52,
          display: 'flex', alignItems: 'center', gap: 8, padding: '0 12px',
          background: 'linear-gradient(90deg, #06111f, #080f1a)',
          borderBottom: '1px solid var(--fl-bg)',
          ...dragStyle,
        }}
      >
        <Sparkles size={14} style={{ color: '#7abfff', flexShrink: 0 }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 700, color: '#7abfff', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            IA Copilot — {caseName}
          </div>
          {model && <div style={{ fontFamily: 'monospace', fontSize: 8, color: '#2a5a8a' }}>{model}</div>}
        </div>

        <div style={{ display: 'flex', gap: 2 }}>
          {[{ id: 'chat', label: 'Chat' }, { id: 'context', label: 'Contexte' }].map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} style={{
              padding: '3px 10px', borderRadius: 4, fontSize: 9, fontFamily: 'monospace',
              background: tab === t.id ? 'rgba(77,130,192,0.2)' : 'transparent',
              border: `1px solid ${tab === t.id ? 'rgba(77,130,192,0.4)' : 'var(--fl-bg)'}`,
              color: tab === t.id ? '#7abfff' : '#2a5a8a',
              cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
            }}>
              {t.label}
              {t.id === 'chat' && hasContext && (
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', display: 'inline-block' }} title="Contexte actif" />
              )}
            </button>
          ))}
        </div>

        <button onClick={toggleFullscreen} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 3, color: '#2a5a8a' }}>
          {isFullscreen ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
        </button>
        <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 3, color: '#2a5a8a' }}>
          <X size={14} />
        </button>
      </div>

      {tab === 'chat' && (
        <>
          <div style={{ flex: 1, overflowY: 'auto', padding: 12, display: 'flex', flexDirection: 'column', gap: 10 }}>
            {loadingHistory ? (
              <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#2a5a8a', textAlign: 'center', paddingTop: 40 }}>Chargement…</div>
            ) : messages.length === 0 ? (
              <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#2a5a8a', lineHeight: 1.8 }}>
                Analyste IA pour le cas <strong style={{ color: 'var(--fl-accent)' }}>{caseName}</strong>.
                {hasContext && (
                  <div style={{ marginTop: 6, padding: '5px 8px', borderRadius: 4, background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.15)', fontSize: 9, color: '#22c55e' }}>
                    ✓ Contexte investigateur actif
                  </div>
                )}
                <div style={{ marginTop: 8, fontSize: 9 }}>Posez une question ou utilisez les suggestions ci-dessous.</div>
              </div>
            ) : (
              messages.map((msg, i) => (
                <div key={msg.id || i} style={{ alignSelf: msg.role === 'user' ? 'flex-end' : 'flex-start', maxWidth: '92%' }}>
                  {msg.role === 'assistant' && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 3 }}>
                      <div style={{ width: 5, height: 5, borderRadius: '50%', background: '#22c55e' }} />
                      <span style={{ fontFamily: 'monospace', fontSize: 8, color: '#1a5a2a' }}>IA Copilot</span>
                    </div>
                  )}
                  
                  {msg.role === 'assistant' && msg.thinkingSteps?.length > 0 && (
                    <ThinkingSteps
                      steps={msg.thinkingSteps}
                      collapsed={!!collapsedThinking[msg.id]}
                      onToggle={() => setCollapsedThinking(prev => ({ ...prev, [msg.id]: !prev[msg.id] }))}
                    />
                  )}
                  
                  {msg.role === 'assistant' && (msg.thinkText || msg.isThinking) && (
                    <LiveThinking
                      content={msg.thinkText}
                      isActive={!!msg.isThinking}
                      collapsed={!msg.isThinking && !!collapsedThink[msg.id]}
                      onToggle={() => setCollapsedThink(prev => ({ ...prev, [msg.id]: !prev[msg.id] }))}
                    />
                  )}
                  <div style={{
                    padding: '8px 11px',
                    borderRadius: msg.role === 'user' ? '8px 8px 2px 8px' : '2px 8px 8px 8px',
                    background: msg.role === 'user' ? 'rgba(77,130,192,0.15)' : msg.error ? 'rgba(239,68,68,0.06)' : 'rgba(6,17,31,0.95)',
                    border: `1px solid ${msg.role === 'user' ? 'rgba(77,130,192,0.25)' : msg.error ? 'rgba(239,68,68,0.2)' : 'var(--fl-bg)'}`,
                  }}>
                    {msg.role === 'user' ? (
                      <div style={{ fontFamily: 'monospace', fontSize: 10.5, color: '#7abfff', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{msg.content}</div>
                    ) : msg.isThinking ? (
                      <span style={{ fontFamily: 'monospace', fontSize: 9, color: '#1a5a2a' }}>Raisonnement…</span>
                    ) : msg.loading && !msg.thinkingSteps?.length ? (
                      <span style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--fl-accent)', animation: 'blink 1s step-end infinite' }}>▌</span>
                    ) : msg.loading && msg.thinkingSteps?.length > 0 ? (
                      <span style={{ fontFamily: 'monospace', fontSize: 9, color: '#1a4060' }}>Lecture du contexte…</span>
                    ) : msg.error ? (
                      <div style={{ fontFamily: 'monospace', fontSize: 10.5, color: 'var(--fl-danger)', display: 'flex', alignItems: 'center', gap: 4 }}>
                        <AlertCircle size={12} /> {msg.content}
                      </div>
                    ) : (
                      <MessageContent content={msg.content} hasContext={msg.hasContext} />
                    )}
                  </div>
                </div>
              ))
            )}
            <div ref={endRef} />
          </div>

          <div style={{ flexShrink: 0, padding: '6px 12px 0', display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {QUICK_ACTIONS.map((qa, i) => (
              <button key={i} onClick={() => send(qa)} disabled={streaming} style={{
                padding: '3px 8px', fontSize: 8.5, fontFamily: 'monospace',
                background: 'rgba(77,130,192,0.06)', border: '1px solid var(--fl-bg)',
                borderRadius: 4, color: '#3a6a9a', cursor: streaming ? 'not-allowed' : 'pointer',
                whiteSpace: 'nowrap', opacity: streaming ? 0.5 : 1,
              }}>{qa}</button>
            ))}
          </div>

          <div style={{ flexShrink: 0, padding: '8px 10px', borderTop: '1px solid var(--fl-bg)', background: '#060c15', display: 'flex', gap: 6, alignItems: 'flex-end' }}>
            {models.length > 0 && (
              <select value={model} onChange={e => setModel(e.target.value)} style={{ background: '#06111f', border: '1px solid var(--fl-bg)', borderRadius: 4, color: '#3a6a9a', fontSize: 8, fontFamily: 'monospace', padding: '2px 4px', maxWidth: 100, flexShrink: 0, alignSelf: 'center' }}>
                {models.map(m => <option key={m} value={m}>{m}</option>)}
              </select>
            )}
            <textarea
              ref={inputRef}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } }}
              disabled={streaming}
              placeholder="Message… (Entrée = envoyer, Maj+Entrée = saut de ligne)"
              rows={2}
              style={{ flex: 1, background: '#06111f', border: '1px solid var(--fl-bg)', borderRadius: 6, color: 'var(--fl-on-dark)', fontSize: 10.5, fontFamily: 'monospace', padding: '6px 8px', resize: 'none', outline: 'none', lineHeight: 1.5 }}
            />
            {streaming ? (
              <button onClick={() => abortRef.current?.abort()} style={{ padding: '0 10px', borderRadius: 6, alignSelf: 'stretch', background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.25)', color: 'var(--fl-danger)', cursor: 'pointer', fontSize: 14, display: 'flex', alignItems: 'center' }}>⏹</button>
            ) : (
              <button onClick={() => send()} disabled={!input.trim()} style={{ padding: '0 10px', borderRadius: 6, alignSelf: 'stretch', background: input.trim() ? 'rgba(77,130,192,0.2)' : 'transparent', border: `1px solid ${input.trim() ? 'rgba(77,130,192,0.3)' : 'var(--fl-bg)'}`, color: input.trim() ? 'var(--fl-accent)' : 'var(--fl-accent)', cursor: input.trim() ? 'pointer' : 'default', display: 'flex', alignItems: 'center' }}>
                <Send size={13} />
              </button>
            )}
          </div>

          <div style={{ flexShrink: 0, padding: '4px 10px 6px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 8, fontFamily: 'monospace', color: 'var(--fl-muted)' }}>
              {messages.filter(m => m.role === 'user').length} échanges · contexte isolé cas #{caseId}
            </span>
            {messages.length > 0 && !clearConfirm && (
              <button onClick={() => setClearConfirm(true)} style={{ fontSize: 8, fontFamily: 'monospace', color: 'var(--fl-accent)', background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 3 }}>
                <Trash2 size={9} /> Effacer l'historique
              </button>
            )}
            {clearConfirm && (
              <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                <span style={{ fontSize: 8, fontFamily: 'monospace', color: 'var(--fl-warn)' }}>Confirmer ?</span>
                <button onClick={clearHistory} style={{ fontSize: 8, fontFamily: 'monospace', padding: '1px 6px', borderRadius: 3, background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)', color: 'var(--fl-danger)', cursor: 'pointer' }}>Oui</button>
                <button onClick={() => setClearConfirm(false)} style={{ fontSize: 8, fontFamily: 'monospace', padding: '1px 6px', borderRadius: 3, background: 'transparent', border: '1px solid var(--fl-bg)', color: 'var(--fl-subtle)', cursor: 'pointer' }}>Non</button>
              </div>
            )}
          </div>
        </>
      )}

      
      {tab === 'context' && (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: 14, gap: 10 }}>
          <div>
            <div style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 700, color: 'var(--fl-on-dark)', marginBottom: 3 }}>Contexte de l'investigation</div>
            <div style={{ fontFamily: 'monospace', fontSize: 9, color: '#2a5a8a', marginBottom: 6 }}>Ce contexte est injecté dans chaque réponse IA. Il oriente toute l'analyse.</div>
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 4, background: 'rgba(77,130,192,0.08)', border: '1px solid var(--fl-bg)', fontSize: 8, fontFamily: 'monospace', color: '#3a6a9a' }}>
              <Users size={9} /> Partagé entre analystes
            </div>
          </div>

          {rtNotif && (
            <div style={{ padding: '6px 10px', borderRadius: 6, background: 'rgba(77,130,192,0.08)', border: '1px solid rgba(77,130,192,0.2)', fontSize: 9, fontFamily: 'monospace', color: 'var(--fl-accent)' }}>
              ⚡ Contexte mis à jour par <strong>{rtNotif.updatedBy}</strong> — «{rtNotif.preview}»
            </div>
          )}

          <textarea
            value={freeText}
            onChange={handleFreeTextChange}
            maxLength={4000}
            placeholder={`Décris ici ce que tu sais déjà sur cet incident :
• Hypothèse principale (ex: ransomware LockBit)
• Patient zéro identifié (ex: PC-COMPTA-03 / marie.dupont)
• Fenêtre temporelle suspecte (ex: 14-16 mars 2026, 02h-05h)
• Vecteur d'entrée suspecté (ex: phishing reçu le 13/03)
• Périmètre compromis connu (ex: 3 serveurs, 12 postes)
• Objectif de l'attaquant supposé (ex: exfiltration RH)`}
            style={{ flex: 1, background: '#06111f', border: '1px solid var(--fl-card)', borderRadius: 6, color: 'var(--fl-on-dark)', fontSize: 10.5, fontFamily: 'monospace', padding: '10px 12px', resize: 'none', outline: 'none', lineHeight: 1.7, minHeight: 200 }}
          />

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontFamily: 'monospace', fontSize: 9, color: freeText.length > 3800 ? 'var(--fl-warn)' : '#2a5a8a' }}>{freeText.length} / 4000</span>
            {saveStatus === 'saving' && <span style={{ fontFamily: 'monospace', fontSize: 9, color: '#3a6a9a' }}>Sauvegarde…</span>}
            {saveStatus === 'saved'  && <span style={{ fontFamily: 'monospace', fontSize: 9, color: '#22c55e' }}>✓ Sauvegardé</span>}
            {saveStatus === 'error'  && <span style={{ fontFamily: 'monospace', fontSize: 9, color: 'var(--fl-danger)' }}>⚠ Erreur</span>}
          </div>

          {ctxMeta.updatedAt && (
            <div style={{ fontFamily: 'monospace', fontSize: 8, color: 'var(--fl-accent)' }}>
              Dernière modif. : {fmtDate(ctxMeta.updatedAt)}{ctxMeta.updatedBy ? ` par ${ctxMeta.updatedBy}` : ''}
            </div>
          )}

          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', flexShrink: 0 }}>
            {!clearCtxConfirm ? (
              <button onClick={() => setClearCtxConfirm(true)} disabled={!freeText && !savedText} style={{ padding: '5px 12px', borderRadius: 5, fontSize: 9, fontFamily: 'monospace', background: 'transparent', border: '1px solid rgba(239,68,68,0.2)', color: '#ef444450', cursor: (freeText || savedText) ? 'pointer' : 'not-allowed' }}>Effacer</button>
            ) : (
              <div style={{ display: 'flex', gap: 5, alignItems: 'center' }}>
                <span style={{ fontSize: 8, fontFamily: 'monospace', color: 'var(--fl-warn)' }}>Effacer le contexte ?</span>
                <button onClick={clearContext} style={{ padding: '3px 8px', borderRadius: 3, fontSize: 8, fontFamily: 'monospace', background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.25)', color: 'var(--fl-danger)', cursor: 'pointer' }}>Oui</button>
                <button onClick={() => setClearCtxConfirm(false)} style={{ padding: '3px 8px', borderRadius: 3, fontSize: 8, fontFamily: 'monospace', background: 'transparent', border: '1px solid var(--fl-bg)', color: 'var(--fl-subtle)', cursor: 'pointer' }}>Non</button>
              </div>
            )}
            <button onClick={saveContextNow} style={{ padding: '5px 14px', borderRadius: 5, fontSize: 9, fontFamily: 'monospace', background: 'rgba(77,130,192,0.2)', border: '1px solid rgba(77,130,192,0.3)', color: '#7abfff', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 5 }}>
              <Save size={11} /> Sauvegarder
            </button>
          </div>
        </div>
      )}

      <style>{`@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}`}</style>
    </div>
  );
}
