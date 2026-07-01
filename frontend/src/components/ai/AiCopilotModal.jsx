
import { useState, useEffect, useRef, useCallback } from 'react';
import { Sparkles, X, Maximize2, Minimize2, Send, Trash2, Users, Save, AlertCircle, ChevronDown, ChevronRight } from 'lucide-react';
import { useResizable } from '../../hooks/useResizable';
import { useDraggable } from '../../hooks/useDraggable';
import { useDateFormat } from '../../hooks/useDateFormat';
import api from '../../utils/api';

const FULL_ANALYSIS_PROMPT = "Perform a COMPLETE forensic analysis of all evidence and artifacts in this case. Structure: 1) Incident summary (vector, impact, status); 2) Key artifacts per host; 3) IOCs and their meaning; 4) Observed ATT&CK techniques and attack-chain reconstruction; 5) Attack timeline; 6) Prioritized recommendations. Rely only on the case data; do not invent anything.";

const QUICK_ACTIONS = [
  'Summarize the critical alerts',
  'Which artifacts suggest persistence?',
  'Most likely ATT&CK technique?',
  'Next investigation steps?',
  'Generate an incident summary',
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
      fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
    }}>
      <div onClick={onToggle} style={{
        display: 'flex', alignItems: 'center', gap: 5,
        padding: '3px 8px', cursor: 'pointer',
        background: 'rgba(2,10,5,0.95)',
        borderBottom: collapsed ? 'none' : '1px solid #0d2a1a',
        userSelect: 'none',
      }}>
        {isActive
          ? <span style={{ color: 'var(--fl-ok)', fontSize: 8 }}>●</span>
          : <span style={{ color: '#3a8a5a', fontSize: 8 }}>✓</span>}
        <span style={{ color: isActive ? 'var(--fl-ok)' : '#2a6a3a' }}>
          {isActive ? 'Thinking in progress…' : 'Thinking complete'}
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
          {isActive && <span style={{ color: 'var(--fl-ok)' }}>▌</span>}
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
      border: '1px solid #131722',
      background: 'rgba(4,10,20,0.7)',
      overflow: 'hidden',
      fontSize: 9,
      fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
    }}>
      
      <div
        onClick={onToggle}
        style={{
          display: 'flex', alignItems: 'center', gap: 5,
          padding: '4px 8px', cursor: 'pointer',
          background: 'rgba(4,14,28,0.9)',
          borderBottom: collapsed ? 'none' : '1px solid #131722',
          userSelect: 'none',
        }}
      >
        {collapsed
          ? <ChevronRight size={9} style={{ color: 'var(--fl-subtle)', flexShrink: 0 }} />
          : <ChevronDown  size={9} style={{ color: 'var(--fl-subtle)', flexShrink: 0 }} />
        }
        <span style={{ color: '#1a4a6a' }}>
          {isGenerating
            ? <><span style={{ color: 'var(--fl-accent)' }}>🤖</span> Generating…</>
            : `Context read — ${doneCount}/${total} sources`
          }
        </span>
        {!collapsed && (
          <span style={{ marginLeft: 'auto', color: '#131722', fontSize: 8 }}>cliquer pour replier</span>
        )}
      </div>

      {!collapsed && (
        <div style={{ padding: '5px 8px', display: 'flex', flexDirection: 'column', gap: 3 }}>
          {steps.map((step, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              
              {step.status === 'loading' && (
                <span style={{ color: 'var(--fl-muted)', flexShrink: 0 }}>⟳</span>
              )}
              {step.status === 'done' && (
                <span style={{ color: 'var(--fl-ok)', flexShrink: 0, fontSize: 8 }}>✓</span>
              )}
              {step.status === 'generating' && (
                <span style={{ color: 'var(--fl-accent)', flexShrink: 0, animation: 'blink 1s step-end infinite' }}>▌</span>
              )}

              <span style={{
                color: step.status === 'done'
                  ? '#3a8a5a'
                  : step.status === 'generating'
                    ? 'var(--fl-accent)'
                    : 'var(--fl-subtle)',
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
      display: 'inline-block', fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
      padding: '0 5px', borderRadius: 3, margin: '0 2px',
      background: 'color-mix(in srgb, var(--fl-accent) 15%, transparent)', color: 'var(--fl-purple)',
      border: '1px solid color-mix(in srgb, var(--fl-accent) 30%, transparent)',
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
        fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10.5, lineHeight: 1.7,
        color: 'var(--fl-on-dark)', whiteSpace: 'pre-wrap', wordBreak: 'break-word',
      }}>
        {parts}
      </div>
      {hasContext && (
        <div style={{ marginTop: 6, fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-subtle)', display: 'flex', alignItems: 'center', gap: 3 }}>
          <span style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--fl-ok)', display: 'inline-block', flexShrink: 0 }} />
          Investigator context active when this response was generated
        </div>
      )}
    </div>
  );
}

export default function AiCopilotModal({ caseId, caseName, isOpen, onClose, socket }) {
  const { fmtDateTime } = useDateFormat();
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
  const [model, setModel]                     = useState(() => localStorage.getItem('heimdall.ai.activeModel') || '');
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

  const [agentType, setAgentType] = useState('analysis');
  const [feedback, setFeedback]   = useState({});  // msgId → 1 | -1

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
        // Honour the admin's active-model setting if it's installed,
        // otherwise fall back to the first available model.
        const saved = localStorage.getItem('heimdall.ai.activeModel');
        setModel(saved && r.data.models.includes(saved) ? saved : r.data.models[0]);
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
        body: JSON.stringify({ message: userMsg, model: model || undefined, agentType }),
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
        <Sparkles size={14} style={{ color: 'var(--fl-dim)', flexShrink: 0 }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, fontWeight: 700, color: 'var(--fl-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            IA Copilot — {caseName}
          </div>
          {model && <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 8, color: 'var(--fl-subtle)' }}>{model}</div>}
        </div>

        <div style={{ display: 'flex', gap: 2 }}>
          {[{ id: 'chat', label: 'Chat' }, { id: 'context', label: 'Context' }].map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} style={{
              padding: '3px 10px', borderRadius: 4, fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
              background: tab === t.id ? 'color-mix(in srgb, var(--fl-accent) 20%, transparent)' : 'transparent',
              border: `1px solid ${tab === t.id ? 'color-mix(in srgb, var(--fl-accent) 40%, transparent)' : 'var(--fl-bg)'}`,
              color: tab === t.id ? 'var(--fl-dim)' : 'var(--fl-subtle)',
              cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
            }}>
              {t.label}
              {t.id === 'chat' && hasContext && (
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--fl-ok)', display: 'inline-block' }} title="Active context" />
              )}
            </button>
          ))}
        </div>

        <button onClick={toggleFullscreen} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 3, color: 'var(--fl-subtle)' }}>
          {isFullscreen ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
        </button>
        <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 3, color: 'var(--fl-subtle)' }}>
          <X size={14} />
        </button>
      </div>

      {tab === 'chat' && (
        <>
          <div style={{ flex: 1, overflowY: 'auto', padding: 12, display: 'flex', flexDirection: 'column', gap: 10 }}>
            {loadingHistory ? (
            <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: 'var(--fl-subtle)', textAlign: 'center', paddingTop: 40 }}>Loading…</div>
            ) : messages.length === 0 ? (
              <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: 'var(--fl-subtle)', lineHeight: 1.8 }}>
                AI analyst for case <strong style={{ color: 'var(--fl-accent)' }}>{caseName}</strong>.
                {hasContext && (
                  <div style={{ marginTop: 6, padding: '5px 8px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-ok) 6%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-ok) 15%, transparent)', fontSize: 9, color: 'var(--fl-ok)' }}>
                    ✓ Investigator context active
                  </div>
                )}
                <div style={{ marginTop: 8, fontSize: 9 }}>Posez une question ou utilisez les suggestions ci-dessous.</div>
              </div>
            ) : (
              messages.map((msg, i) => (
                <div key={msg.id || i} style={{ alignSelf: msg.role === 'user' ? 'flex-end' : 'flex-start', maxWidth: '92%' }}>
                  {msg.role === 'assistant' && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 3 }}>
                      <div style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--fl-ok)' }} />
                      <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 8, color: '#1a5a2a' }}>AI Copilot</span>
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
                    background: msg.role === 'user' ? 'color-mix(in srgb, var(--fl-accent) 15%, transparent)' : msg.error ? 'color-mix(in srgb, var(--fl-danger) 6%, transparent)' : 'rgba(6,17,31,0.95)',
                    border: `1px solid ${msg.role === 'user' ? 'color-mix(in srgb, var(--fl-accent) 25%, transparent)' : msg.error ? 'color-mix(in srgb, var(--fl-danger) 20%, transparent)' : 'var(--fl-bg)'}`,
                  }}>
                    {msg.role === 'user' ? (
                      <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10.5, color: 'var(--fl-dim)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{msg.content}</div>
                    ) : msg.isThinking ? (
                      <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9, color: '#1a5a2a' }}>Thinking…</span>
                    ) : msg.loading && !msg.thinkingSteps?.length ? (
                      <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12, color: 'var(--fl-accent)', animation: 'blink 1s step-end infinite' }}>▌</span>
                    ) : msg.loading && msg.thinkingSteps?.length > 0 ? (
                      <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9, color: '#1a4060' }}>Reading context…</span>
                    ) : msg.error ? (
                      <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10.5, color: 'var(--fl-danger)', display: 'flex', alignItems: 'center', gap: 4 }}>
                        <AlertCircle size={12} /> {msg.content}
                      </div>
                    ) : (
                      <MessageContent content={msg.content} hasContext={msg.hasContext} />
                    )}
                  </div>

                  {/* Feedback thumbs — only on completed assistant messages */}
                  {msg.role === 'assistant' && !msg.loading && !msg.error && msg.content && (
                    <div style={{ display: 'flex', gap: 4, marginTop: 4, justifyContent: 'flex-end' }}>
                      {[{ r: 1, icon: '👍' }, { r: -1, icon: '👎' }].map(({ r, icon }) => (
                        <button
                          key={r}
                          onClick={() => {
                            const next = feedback[msg.id] === r ? 0 : r;
                            setFeedback(f => ({ ...f, [msg.id]: next }));
                            if (next !== 0) {
                              const token = localStorage.getItem('heimdall_token');
                              fetch(`/api/cases/${caseId}/ai/feedback`, {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
                                body: JSON.stringify({ rating: r, agentType, model, msgRef: msg.created_at }),
                              }).catch(() => {});
                            }
                          }}
                          style={{
                            background: 'none', border: 'none', cursor: 'pointer',
                            fontSize: 11, opacity: feedback[msg.id] === r ? 1 : 0.3,
                            transition: 'opacity 0.15s', padding: '0 2px',
                          }}
                          title={r === 1 ? 'Helpful response' : 'Needs improvement'}
                        >{icon}</button>
                      ))}
                    </div>
                  )}
                </div>
              ))
            )}
            <div ref={endRef} />
          </div>

          <div style={{ flexShrink: 0, padding: '8px 12px 0' }}>
            <button onClick={() => send(FULL_ANALYSIS_PROMPT)} disabled={streaming} title="Complete forensic analysis of all case evidence and artifacts"
              style={{
                width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                padding: '7px 10px', borderRadius: 6, fontSize: 11, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 600,
                background: streaming ? 'var(--fl-bg)' : 'color-mix(in srgb, var(--fl-accent) 14%, transparent)',
                border: '1px solid color-mix(in srgb, var(--fl-accent) 32%, transparent)',
                color: 'var(--fl-accent)', cursor: streaming ? 'not-allowed' : 'pointer', opacity: streaming ? 0.5 : 1,
              }}>
              📊 Analyze all case evidence
            </button>
          </div>

          <div style={{ flexShrink: 0, padding: '6px 12px 0', display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {QUICK_ACTIONS.map((qa, i) => (
              <button key={i} onClick={() => send(qa)} disabled={streaming} style={{
                padding: '3px 8px', fontSize: 8.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                background: 'color-mix(in srgb, var(--fl-accent) 6%, transparent)', border: '1px solid var(--fl-bg)',
                borderRadius: 4, color: 'var(--fl-muted)', cursor: streaming ? 'not-allowed' : 'pointer',
                whiteSpace: 'nowrap', opacity: streaming ? 0.5 : 1,
              }}>{qa}</button>
            ))}
          </div>

          {/* Agent selector */}
          <div style={{ flexShrink: 0, padding: '6px 10px 0', display: 'flex', gap: 4, alignItems: 'center' }}>
            <span style={{ fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)', marginRight: 2 }}>Agent:</span>
            {[
              { id: 'triage',   label: '⚡ Triage',   title: 'Verdict rapide · temp 0.1' },
              { id: 'analysis', label: '🔍 Analysis',  title: 'Deep analysis · temp 0.3' },
              { id: 'narrative',label: '📄 Report',    title: 'Report prose · temp 0.5' },
              { id: 'agentic',  label: '🔧 Agent',      title: 'Query the case (accounts, distributions, searches) · slower' },
            ].map(a => (
              <button
                key={a.id}
                onClick={() => setAgentType(a.id)}
                disabled={streaming}
                title={a.title}
                style={{
                  padding: '2px 7px', fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                  borderRadius: 4, cursor: streaming ? 'not-allowed' : 'pointer',
                  background: agentType === a.id ? 'color-mix(in srgb, var(--fl-accent) 18%, transparent)' : 'color-mix(in srgb, var(--fl-accent) 4%, transparent)',
                  border: `1px solid ${agentType === a.id ? 'color-mix(in srgb, var(--fl-accent) 40%, transparent)' : 'var(--fl-bg)'}`,
                  color: agentType === a.id ? 'var(--fl-accent)' : 'var(--fl-muted)',
                  transition: 'all 0.12s',
                }}
              >{a.label}</button>
            ))}
          </div>

          <div style={{ flexShrink: 0, padding: '8px 10px', borderTop: '1px solid var(--fl-bg)', background: '#0a0c11', display: 'flex', gap: 6, alignItems: 'flex-end' }}>
            {models.length > 0 && (
              <select value={model} onChange={e => setModel(e.target.value)} style={{ background: '#06111f', border: '1px solid var(--fl-bg)', borderRadius: 4, color: 'var(--fl-muted)', fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '2px 4px', maxWidth: 100, flexShrink: 0, alignSelf: 'center' }}>
                {models.map(m => <option key={m} value={m}>{m}</option>)}
              </select>
            )}
            <textarea
              ref={inputRef}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } }}
              disabled={streaming}
              placeholder="Message… (Enter = send, Shift+Enter = new line)"
              rows={2}
              style={{ flex: 1, background: '#06111f', border: '1px solid var(--fl-bg)', borderRadius: 6, color: 'var(--fl-on-dark)', fontSize: 10.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '6px 8px', resize: 'none', outline: 'none', lineHeight: 1.5 }}
            />
            {streaming ? (
              <button onClick={() => abortRef.current?.abort()} style={{ padding: '0 10px', borderRadius: 6, alignSelf: 'stretch', background: 'color-mix(in srgb, var(--fl-danger) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 25%, transparent)', color: 'var(--fl-danger)', cursor: 'pointer', fontSize: 14, display: 'flex', alignItems: 'center' }}>⏹</button>
            ) : (
              <button onClick={() => send()} disabled={!input.trim()} style={{ padding: '0 10px', borderRadius: 6, alignSelf: 'stretch', background: input.trim() ? 'color-mix(in srgb, var(--fl-accent) 20%, transparent)' : 'transparent', border: `1px solid ${input.trim() ? 'color-mix(in srgb, var(--fl-accent) 30%, transparent)' : 'var(--fl-bg)'}`, color: input.trim() ? 'var(--fl-accent)' : 'var(--fl-accent)', cursor: input.trim() ? 'pointer' : 'default', display: 'flex', alignItems: 'center' }}>
                <Send size={13} />
              </button>
            )}
          </div>

          <div style={{ flexShrink: 0, padding: '4px 10px 6px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)' }}>
              {messages.filter(m => m.role === 'user').length} exchanges · isolated context for case #{caseId}
            </span>
            {messages.length > 0 && !clearConfirm && (
              <button onClick={() => setClearConfirm(true)} style={{ fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-accent)', background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 3 }}>
                <Trash2 size={9} /> Clear history
              </button>
            )}
            {clearConfirm && (
              <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                <span style={{ fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-warn)' }}>Confirmer ?</span>
                <button onClick={clearHistory} style={{ fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 6px', borderRadius: 3, background: 'color-mix(in srgb, var(--fl-danger) 10%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 20%, transparent)', color: 'var(--fl-danger)', cursor: 'pointer' }}>Yes</button>
                <button onClick={() => setClearConfirm(false)} style={{ fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '1px 6px', borderRadius: 3, background: 'transparent', border: '1px solid var(--fl-bg)', color: 'var(--fl-subtle)', cursor: 'pointer' }}>No</button>
              </div>
            )}
          </div>
        </>
      )}

      
      {tab === 'context' && (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: 14, gap: 10 }}>
          <div>
            <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12, fontWeight: 700, color: 'var(--fl-on-dark)', marginBottom: 3 }}>Investigation context</div>
            <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9, color: 'var(--fl-subtle)', marginBottom: 6 }}>This context is injected into every AI response. It guides the analysis.</div>
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 4, background: 'color-mix(in srgb, var(--fl-accent) 8%, transparent)', border: '1px solid var(--fl-bg)', fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)' }}>
              <Users size={9} /> Shared between analysts
            </div>
          </div>

          {rtNotif && (
            <div style={{ padding: '6px 10px', borderRadius: 6, background: 'color-mix(in srgb, var(--fl-accent) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 20%, transparent)', fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-accent)' }}>
              ⚡ Context updated by <strong>{rtNotif.updatedBy}</strong> — "{rtNotif.preview}"
            </div>
          )}

          <textarea
            value={freeText}
            onChange={handleFreeTextChange}
            maxLength={4000}
            placeholder={`Describe what you already know about this incident:
• Main hypothesis (e.g. LockBit ransomware)
• Identified patient zero (e.g. PC-ACCOUNTING-03 / marie.dupont)
• Suspicious time window (e.g. Mar 14-16, 2026, 02:00-05:00)
• Suspected entry vector (e.g. phishing received on 03/13)
• Known compromised scope (e.g. 3 servers, 12 workstations)
• Suspected attacker objective (e.g. HR exfiltration)`}
            style={{ flex: 1, background: '#06111f', border: '1px solid var(--fl-card)', borderRadius: 6, color: 'var(--fl-on-dark)', fontSize: 10.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '10px 12px', resize: 'none', outline: 'none', lineHeight: 1.7, minHeight: 200 }}
          />

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9, color: freeText.length > 3800 ? 'var(--fl-warn)' : 'var(--fl-subtle)' }}>{freeText.length} / 4000</span>
            {saveStatus === 'saving' && <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9, color: 'var(--fl-muted)' }}>Saving…</span>}
            {saveStatus === 'saved'  && <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9, color: 'var(--fl-ok)' }}>✓ Saved</span>}
            {saveStatus === 'error'  && <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9, color: 'var(--fl-danger)' }}>⚠ Error</span>}
          </div>

          {ctxMeta.updatedAt && (
            <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 8, color: 'var(--fl-accent)' }}>
              Last modified: {fmtDateTime(ctxMeta.updatedAt)} UTC{ctxMeta.updatedBy ? ` by ${ctxMeta.updatedBy}` : ''}
            </div>
          )}

          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', flexShrink: 0 }}>
            {!clearCtxConfirm ? (
              <button onClick={() => setClearCtxConfirm(true)} disabled={!freeText && !savedText} style={{ padding: '5px 12px', borderRadius: 5, fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'transparent', border: '1px solid color-mix(in srgb, var(--fl-danger) 20%, transparent)', color: 'color-mix(in srgb, var(--fl-danger) 31%, transparent)', cursor: (freeText || savedText) ? 'pointer' : 'not-allowed' }}>Clear</button>
            ) : (
              <div style={{ display: 'flex', gap: 5, alignItems: 'center' }}>
                <span style={{ fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-warn)' }}>Clear context?</span>
                <button onClick={clearContext} style={{ padding: '3px 8px', borderRadius: 3, fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'color-mix(in srgb, var(--fl-danger) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 25%, transparent)', color: 'var(--fl-danger)', cursor: 'pointer' }}>Yes</button>
                <button onClick={() => setClearCtxConfirm(false)} style={{ padding: '3px 8px', borderRadius: 3, fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'transparent', border: '1px solid var(--fl-bg)', color: 'var(--fl-subtle)', cursor: 'pointer' }}>No</button>
              </div>
            )}
            <button onClick={saveContextNow} style={{ padding: '5px 14px', borderRadius: 5, fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'color-mix(in srgb, var(--fl-accent) 20%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 30%, transparent)', color: 'var(--fl-dim)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 5 }}>
              <Save size={11} /> Save
            </button>
          </div>
        </div>
      )}

      <style>{`@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}`}</style>
    </div>
  );
}
