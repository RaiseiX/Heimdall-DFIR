import { useState, useEffect, useRef, useCallback } from 'react';
import { Sparkles, X, Minimize2, Maximize2, Send, RotateCcw, ChevronDown, BookOpen, Copy, Check, RefreshCw } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import i18n from '../i18n/index.js';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';
const UI   = 'var(--f-ui, Inter, sans-serif)';

// Last-resort placeholder only (single, conservative). The real list comes from
// the installed Ollama models + the active model configured in the admin panel.
const MODELS_DFLT = ['qwen2.5:3b'];

function getPromptCategories(t) {
  const categories = i18n.getResourceBundle(i18n.language || 'en', 'translation')?.globalAi?.categories
    || i18n.getResourceBundle('en', 'translation')?.globalAi?.categories
    || {};
  return [
    {
      id: 'artefacts', label: categories.artefacts?.label || '', icon: '🗂',
      prompts: categories.artefacts?.prompts || [],
    },
    {
      id: 'mitre', label: categories.mitre?.label || '', icon: '🎯',
      prompts: categories.mitre?.prompts || [],
    },
    {
      id: 'detection', label: categories.detection?.label || '', icon: '🔍',
      prompts: categories.detection?.prompts || [],
    },
    {
      id: 'report', label: categories.report?.label || '', icon: '📋',
      prompts: categories.report?.prompts || [],
    },
  ];
}

// ─── Lightweight, dependency-free Markdown rendering ─────────────────────────

const INLINE_CODE = { fontFamily: MONO, fontSize: '0.92em', background: 'color-mix(in srgb, var(--fl-accent) 11%, transparent)', color: 'var(--fl-accent)', borderRadius: 3, padding: '0.5px 4px' };
const LINK = { color: 'var(--fl-accent)', textDecoration: 'underline' };

function renderInline(text, kp) {
  const out = [];
  let rest = String(text), k = 0;
  const re = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\*[^*]+\*)|(\[[^\]]+\]\([^)]+\))/;
  while (rest) {
    const m = rest.match(re);
    if (!m) { out.push(rest); break; }
    if (m.index > 0) out.push(rest.slice(0, m.index));
    const tok = m[0];
    if (tok.startsWith('`')) out.push(<code key={`${kp}-${k++}`} style={INLINE_CODE}>{tok.slice(1, -1)}</code>);
    else if (tok.startsWith('**')) out.push(<strong key={`${kp}-${k++}`}>{tok.slice(2, -2)}</strong>);
    else if (tok.startsWith('*')) out.push(<em key={`${kp}-${k++}`}>{tok.slice(1, -1)}</em>);
    else { const mm = tok.match(/\[([^\]]+)\]\(([^)]+)\)/); out.push(<a key={`${kp}-${k++}`} href={mm[2]} target="_blank" rel="noreferrer" style={LINK}>{mm[1]}</a>); }
    rest = rest.slice(m.index + tok.length);
  }
  return out;
}

function CopyBtn({ text, label }) {
  const { t } = useTranslation();
  const [done, setDone] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard?.writeText(text).catch(() => {}); setDone(true); setTimeout(() => setDone(false), 1300); }}
      title={t('common.copy')}
      style={{ display: 'inline-flex', alignItems: 'center', gap: 4, background: 'none', border: 'none', cursor: 'pointer', color: done ? 'var(--fl-ok)' : 'var(--fl-muted)', padding: 2, fontSize: 9, fontFamily: MONO }}>
      {done ? <Check size={11} /> : <Copy size={11} />}{label && <span>{done ? t('globalAi.copied') : label}</span>}
    </button>
  );
}

function CodeBlock({ code, lang }) {
  return (
    <div style={{ margin: '6px 0', borderRadius: 7, overflow: 'hidden', border: '1px solid #2A2D36', background: '#16181D' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 10px', background: '#1B1D24', borderBottom: '1px solid #2A2D36' }}>
        <span style={{ fontFamily: MONO, fontSize: 9, color: '#6B7280', textTransform: 'uppercase', letterSpacing: '0.06em', flex: 1 }}>{lang || 'code'}</span>
        <CopyBtn text={code} />
      </div>
      <pre style={{ margin: 0, padding: '8px 10px', overflowX: 'auto', fontFamily: MONO, fontSize: 10.5, lineHeight: 1.6, color: '#D9DCE3', whiteSpace: 'pre' }}>{code}</pre>
    </div>
  );
}

function MarkdownBody({ text }) {
  const out = [];
  const parts = String(text).split(/(```[\s\S]*?```)/g);
  parts.forEach((part, pi) => {
    if (part.startsWith('```')) {
      const m = part.match(/^```(\w*)\n?([\s\S]*?)```$/);
      out.push(<CodeBlock key={`cb-${pi}`} code={(m ? m[2] : part.slice(3, -3)).replace(/\n$/, '')} lang={m && m[1]} />);
      return;
    }
    const lines = part.split('\n');
    let listBuf = null;
    const flush = () => { if (listBuf) { out.push(<ul key={`ul-${pi}-${out.length}`} style={{ margin: '3px 0', paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 2 }}>{listBuf}</ul>); listBuf = null; } };
    lines.forEach((line, li) => {
      const key = `${pi}-${li}`;
      const h = line.match(/^(#{1,3})\s+(.*)/);
      const li1 = line.match(/^\s*[-*]\s+(.*)/);
      const li2 = line.match(/^\s*\d+\.\s+(.*)/);
      if (h) { flush(); const sz = [13, 12, 11.5][h[1].length - 1]; out.push(<div key={key} style={{ fontFamily: UI, fontWeight: 700, fontSize: sz, color: 'var(--fl-text)', margin: '6px 0 2px' }}>{renderInline(h[2], key)}</div>); }
      else if (li1) { (listBuf ||= []).push(<li key={key} style={{ fontFamily: UI, fontSize: 11.5, lineHeight: 1.55 }}>{renderInline(li1[1], key)}</li>); }
      else if (li2) { (listBuf ||= []).push(<li key={key} style={{ fontFamily: UI, fontSize: 11.5, lineHeight: 1.55 }}>{renderInline(li2[1], key)}</li>); }
      else { flush(); if (line.trim()) out.push(<div key={key} style={{ fontFamily: UI, fontSize: 11.5, lineHeight: 1.6, margin: '2px 0' }}>{renderInline(line, key)}</div>); }
    });
    flush();
  });
  return <>{out}</>;
}

// ─── Welcome screen with prompt category cards ───────────────────────────────

function WelcomeScreen({ onPickCategory, t }) {
  const promptCategories = getPromptCategories(t);
  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', padding: '8px 6px', gap: 14 }}>
      <div style={{ textAlign: 'center' }}>
        <div style={{ width: 38, height: 38, borderRadius: 10, margin: '0 auto 10px', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'color-mix(in srgb, var(--fl-accent) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-accent) 28%, transparent)' }}>
          <Sparkles size={18} style={{ color: 'var(--fl-accent)' }} />
        </div>
        <div style={{ fontFamily: UI, fontWeight: 600, fontSize: 14, color: 'var(--fl-text)' }}>{t('globalAi.title')}</div>
        <div style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-muted)', marginTop: 4 }}>{t('globalAi.subtitle')}</div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
        {promptCategories.map(cat => (
          <button key={cat.id} onClick={() => onPickCategory(cat.id)}
            style={{ textAlign: 'left', padding: '10px 11px', borderRadius: 8, cursor: 'pointer', background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', transition: 'border-color 0.12s, background 0.12s' }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = 'color-mix(in srgb, var(--fl-accent) 35%, transparent)'; e.currentTarget.style.background = 'color-mix(in srgb, var(--fl-accent) 5%, transparent)'; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--fl-border)'; e.currentTarget.style.background = 'var(--fl-bg)'; }}>
            <div style={{ fontSize: 16, marginBottom: 5 }}>{cat.icon}</div>
            <div style={{ fontFamily: UI, fontWeight: 600, fontSize: 11.5, color: 'var(--fl-text)' }}>{cat.label}</div>
            <div style={{ fontFamily: MONO, fontSize: 8.5, color: 'var(--fl-subtle)', marginTop: 2 }}>{t('globalAi.prompt_count', { count: cat.prompts.length })}</div>
          </button>
        ))}
      </div>
    </div>
  );
}

export default function GlobalAiChat() {
  const { t } = useTranslation();
  const promptCategories = getPromptCategories(t);
  const [open, setOpen]           = useState(false);
  const [minimized, setMinimized] = useState(false);
  const [available, setAvailable] = useState(null);
  const [models, setModels]       = useState(MODELS_DFLT);
  const [model, setModel]         = useState(MODELS_DFLT[0]);
  const [messages, setMessages]   = useState([]);
  const [input, setInput]         = useState('');
  const [streaming, setStreaming] = useState(false);
  const [unread, setUnread]       = useState(0);
  const [showPrompts, setShowPrompts] = useState(false);
  const [activeCategory, setActiveCategory] = useState('artefacts');

  const abortRef     = useRef(null);
  const endRef       = useRef(null);
  const inputRef     = useRef(null);
  const promptsRef   = useRef(null);
  const prevLenRef   = useRef(0);

  // Draggable launcher bubble — grab to move (position persisted), click to open.
  const [btnPos, setBtnPos] = useState(() => { try { const s = localStorage.getItem('fl_aichat_btn_pos'); if (s) return JSON.parse(s); } catch (_e) {} return null; });
  const btnDragRef = useRef({ moved: false });
  const startBtnDrag = useCallback((e) => {
    if (e.button !== 0) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const sx = e.clientX, sy = e.clientY, ox = rect.left, oy = rect.top;
    btnDragRef.current = { moved: false };
    let last = null;
    const move = (ev) => {
      const dx = ev.clientX - sx, dy = ev.clientY - sy;
      if (!btnDragRef.current.moved && Math.abs(dx) + Math.abs(dy) > 4) btnDragRef.current.moved = true;
      if (btnDragRef.current.moved) { last = { x: Math.min(Math.max(ox + dx, 4), window.innerWidth - 54), y: Math.min(Math.max(oy + dy, 4), window.innerHeight - 54) }; setBtnPos(last); }
    };
    const up = () => {
      document.removeEventListener('mousemove', move); document.removeEventListener('mouseup', up); document.body.style.userSelect = '';
      if (btnDragRef.current.moved && last) { try { localStorage.setItem('fl_aichat_btn_pos', JSON.stringify(last)); } catch (_e) {} }
    };
    document.body.style.userSelect = 'none';
    document.addEventListener('mousemove', move); document.addEventListener('mouseup', up);
  }, []);

  useEffect(() => {
    const auth = { Authorization: `Bearer ${localStorage.getItem('heimdall_token')}` };
    // Active model lives in system_settings (DB) — reliable even if the Ollama probe times out.
    const getActive = fetch('/api/settings/ai', { headers: auth }).then(r => r.json()).then(d => d?.active_model || null).catch(() => null);
    const getModels = fetch('/api/llm/models', { headers: auth }).then(r => r.json()).catch(() => ({ available: false, models: [] }));
    Promise.all([getActive, getModels]).then(([active, d]) => {
      setAvailable(d.available ?? false);
      const installed = Array.isArray(d.models) ? d.models.filter(Boolean) : [];
      let list = installed;
      if (active && !list.includes(active)) list = [active, ...list];   // surface the configured model first
      if (list.length) {
        setModels(list);
        setModel(active && list.includes(active) ? active : list[0]);
      } else if (active) {
        setModels([active]); setModel(active);
      }
    });
  }, []);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
    if (!open && messages.length > prevLenRef.current && messages[messages.length - 1]?.role === 'assistant') setUnread(u => u + 1);
    prevLenRef.current = messages.length;
  }, [messages, open]);

  useEffect(() => {
    if (open && !minimized) { setTimeout(() => inputRef.current?.focus(), 100); setUnread(0); }
  }, [open, minimized]);

  // Allow any page to open the chat pre-filled with a prompt:
  //   window.dispatchEvent(new CustomEvent('heimdall:ai-open', { detail: { prompt } }))
  useEffect(() => {
    const onOpen = (e) => {
      setOpen(true); setMinimized(false);
      const p = e.detail?.prompt;
      if (p) { setInput(p); setTimeout(() => inputRef.current?.focus(), 150); }
    };
    window.addEventListener('heimdall:ai-open', onOpen);
    return () => window.removeEventListener('heimdall:ai-open', onOpen);
  }, []);

  useEffect(() => {
    function h(e) { if (promptsRef.current && !promptsRef.current.contains(e.target)) setShowPrompts(false); }
    if (showPrompts) { document.addEventListener('mousedown', h); return () => document.removeEventListener('mousedown', h); }
  }, [showPrompts]);

  function buildPrompt(userMsg) {
    const history = messages.slice(-6).map(m => `${m.role === 'user' ? t('globalAi.analyst') : t('globalAi.assistant')}: ${m.content}`).join('\n');
    const context = history ? `${history}\n${t('globalAi.analyst')}: ${userMsg}` : userMsg;
    if (messages.length === 0) return `${t('globalAi.system_prompt')}\n\n${t('globalAi.analyst')}: ${userMsg}`;
    return `${t('globalAi.system_prompt')}\n\n${context}`;
  }

  const send = useCallback(async (text, appendUser = true) => {
    const userMsg = (text || input).trim();
    if (!userMsg || streaming || !available) return;
    setInput('');
    setShowPrompts(false);
    if (appendUser) setMessages(prev => [...prev, { role: 'user', content: userMsg }]);
    setStreaming(true);
    setMessages(prev => [...prev, { role: 'assistant', content: '', loading: true }]);

    try {
      const controller = new AbortController();
      abortRef.current = controller;
      // Case-aware: on a case page, route through the case endpoint (rich context + RAG).
      const cm = window.location.pathname.match(/\/cases\/([0-9a-fA-F-]{36})/);
      const caseId = cm ? cm[1] : null;
      const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${localStorage.getItem('heimdall_token')}` };
      const res = caseId
        ? await fetch(`/api/cases/${caseId}/ai/stream`, { method: 'POST', headers, body: JSON.stringify({ message: userMsg }), signal: controller.signal })
        : await fetch('/api/llm/analyze', { method: 'POST', headers, body: JSON.stringify({ model, prompt: buildPrompt(userMsg), stream: true }), signal: controller.signal });
      if (!res.ok) throw new Error(t('globalAi.http_error', { status: res.status }));
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
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
            const token = JSON.parse(data).response || '';
            if (token) setMessages(prev => { const arr = [...prev]; const last = arr[arr.length - 1]; arr[arr.length - 1] = { role: 'assistant', content: last.content + token }; return arr; });
          } catch {}
        }
      }
    } catch (e) {
      if (e.name !== 'AbortError') setMessages(prev => { const arr = [...prev]; arr[arr.length - 1] = { role: 'assistant', content: `⚠ ${e.message}`, error: true }; return arr; });
    } finally {
      setStreaming(false);
      abortRef.current = null;
    }
  }, [input, streaming, available, model, messages]);

  const regenerate = useCallback(() => {
    if (streaming) return;
    let lastUser = null;
    for (let i = messages.length - 1; i >= 0; i--) { if (messages[i].role === 'user') { lastUser = messages[i].content; break; } }
    if (!lastUser) return;
    setMessages(prev => { const arr = [...prev]; while (arr.length && arr[arr.length - 1].role === 'assistant') arr.pop(); return arr; });
    setTimeout(() => send(lastUser, false), 30);
  }, [messages, streaming, send]);

  const pickCategory = (id) => { setActiveCategory(id); setShowPrompts(true); };

  if (available === false) return null;

  const currentCategory = promptCategories.find(c => c.id === activeCategory) || promptCategories[0];

  return (
    <>
      {!open && (
        <button onMouseDown={startBtnDrag} onClick={() => { if (btnDragRef.current.moved) return; setOpen(true); }} title={`${t('globalAi.launcher_title')} — ${t('globalAi.drag_hint')}`}
          style={{ position: 'fixed', zIndex: 9000, ...(btnPos ? { left: btnPos.x, top: btnPos.y } : { bottom: 24, right: 24 }), width: 46, height: 46, borderRadius: '50%', background: 'var(--fl-panel)', border: '1px solid var(--fl-accent)', boxShadow: 'var(--fl-shadow-md)', cursor: 'grab', display: 'flex', alignItems: 'center', justifyContent: 'center', transition: 'transform 0.15s, box-shadow 0.15s' }}
          onMouseEnter={e => { e.currentTarget.style.transform = 'scale(1.1)'; e.currentTarget.style.boxShadow = 'var(--fl-shadow-lg)'; }}
          onMouseLeave={e => { e.currentTarget.style.transform = 'scale(1)'; e.currentTarget.style.boxShadow = 'var(--fl-shadow-md)'; }}>
          <Sparkles size={18} style={{ color: 'var(--fl-accent)' }} />
          {unread > 0 && (
            <span style={{ position: 'absolute', top: -4, right: -4, background: 'var(--fl-ok)', color: '#fff', borderRadius: '50%', width: 16, height: 16, fontSize: 9, fontFamily: MONO, fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center', border: '2px solid var(--fl-bg)' }}>{unread}</span>
          )}
        </button>
      )}

      {open && (
        <div style={{ position: 'fixed', bottom: 24, right: 24, zIndex: 9000, width: 420, height: minimized ? 48 : 600, background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 12, boxShadow: 'var(--fl-shadow-lg)', display: 'flex', flexDirection: 'column', overflow: 'hidden', transition: 'height 0.2s ease' }}>

          <div style={{ flexShrink: 0, height: 48, display: 'flex', alignItems: 'center', gap: 8, padding: '0 12px', background: 'var(--fl-bg)', borderBottom: minimized ? 'none' : '1px solid var(--fl-border)', cursor: minimized ? 'pointer' : 'default' }}
            onClick={minimized ? () => setMinimized(false) : undefined}>
            <div style={{ width: 22, height: 22, borderRadius: 6, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'color-mix(in srgb, var(--fl-accent) 14%, transparent)', flexShrink: 0 }}>
              <Sparkles size={12} style={{ color: 'var(--fl-accent)' }} />
            </div>
            <span style={{ fontFamily: UI, fontSize: 12, fontWeight: 600, color: 'var(--fl-text)', flex: 1 }}>{t('globalAi.title')}</span>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: available ? 'var(--fl-ok)' : 'var(--fl-muted)' }} title={available ? t('common.online') : t('common.offline')} />
            {!minimized && (
              <>
                <select value={model} onChange={e => setModel(e.target.value)} onClick={e => e.stopPropagation()}
                  style={{ background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', borderRadius: 4, color: 'var(--fl-muted)', fontSize: 8.5, fontFamily: MONO, padding: '2px 4px', maxWidth: 104 }}>
                  {models.map(m => <option key={m} value={m}>{m}</option>)}
                </select>
                {messages.length > 0 && (
                  <button onClick={() => setMessages([])} title={t('globalAi.clear_conversation')} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, color: 'var(--fl-muted)' }}>
                    <RotateCcw size={11} />
                  </button>
                )}
              </>
            )}
            <button onClick={() => setMinimized(v => !v)} title={minimized ? t('globalAi.maximize') : t('globalAi.minimize')} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, color: 'var(--fl-muted)' }}>
              {minimized ? <Maximize2 size={11} /> : <Minimize2 size={11} />}
            </button>
            <button onClick={() => { setOpen(false); setMinimized(false); }} title={t('common.close')} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, color: 'var(--fl-muted)' }}>
              <X size={13} />
            </button>
          </div>

          {!minimized && (
            <>
              <div style={{ flex: 1, overflowY: 'auto', padding: '12px 12px 4px', display: 'flex', flexDirection: 'column', gap: 12 }}>
                {messages.length === 0 ? (
                  <WelcomeScreen onPickCategory={pickCategory} t={t} />
                ) : (
                  messages.map((msg, i) => {
                    const isUser = msg.role === 'user';
                    const isLast = i === messages.length - 1;
                    const showCursor = streaming && isLast && !isUser;
                    return (
                      <div key={i} style={{ display: 'flex', flexDirection: 'column', alignItems: isUser ? 'flex-end' : 'flex-start', maxWidth: '100%' }}>
                        {!isUser && (
                          <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 4 }}>
                            <div style={{ width: 16, height: 16, borderRadius: 5, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'color-mix(in srgb, var(--fl-accent) 14%, transparent)' }}>
                              <Sparkles size={9} style={{ color: 'var(--fl-accent)' }} />
                            </div>
                            <span style={{ fontFamily: MONO, fontSize: 8.5, color: 'var(--fl-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{t('globalAi.title')}</span>
                          </div>
                        )}
                        <div style={{ maxWidth: '92%', padding: isUser ? '7px 11px' : '8px 11px', borderRadius: isUser ? '10px 10px 3px 10px' : '3px 10px 10px 10px', background: isUser ? 'color-mix(in srgb, var(--fl-accent) 14%, transparent)' : msg.error ? 'color-mix(in srgb, var(--fl-danger) 8%, transparent)' : 'var(--fl-card)', border: `1px solid ${isUser ? 'color-mix(in srgb, var(--fl-accent) 24%, transparent)' : msg.error ? 'color-mix(in srgb, var(--fl-danger) 20%, transparent)' : 'var(--fl-border)'}` }}>
                          {isUser ? (
                            <div style={{ fontFamily: UI, fontSize: 11.5, color: 'var(--fl-text)', lineHeight: 1.55, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{msg.content}</div>
                          ) : msg.error ? (
                            <div style={{ fontFamily: MONO, fontSize: 10.5, color: 'var(--fl-danger)', whiteSpace: 'pre-wrap' }}>{msg.content}</div>
                          ) : (
                            <div style={{ wordBreak: 'break-word' }}>
                              {msg.content ? <MarkdownBody text={msg.content} /> : null}
                              {showCursor && <span style={{ animation: 'blink 1s step-end infinite', color: 'var(--fl-accent)', fontFamily: MONO }}>▌</span>}
                            </div>
                          )}
                        </div>
                        {/* message actions */}
                        {!isUser && !msg.error && msg.content && !showCursor && (
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 3, paddingLeft: 2 }}>
                            <CopyBtn text={msg.content} label={t('common.copy')} />
                            {isLast && !streaming && (
                              <button onClick={regenerate} title={t('globalAi.regenerate')} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', padding: 2, fontSize: 9, fontFamily: MONO }}>
                                <RefreshCw size={11} /> {t('globalAi.regenerate')}
                              </button>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })
                )}
                <div ref={endRef} />
              </div>

              {showPrompts && (
                <div ref={promptsRef} style={{ flexShrink: 0, borderTop: '1px solid var(--fl-border)', background: 'var(--fl-bg)', maxHeight: 240, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                  <div style={{ display: 'flex', borderBottom: '1px solid var(--fl-border)', flexShrink: 0 }}>
                    {promptCategories.map(cat => (
                      <button key={cat.id} onClick={() => setActiveCategory(cat.id)}
                        style={{ flex: 1, padding: '6px 2px', fontSize: 8, fontFamily: MONO, background: 'none', border: 'none', cursor: 'pointer', borderBottom: `2px solid ${activeCategory === cat.id ? 'var(--fl-accent)' : 'transparent'}`, color: activeCategory === cat.id ? 'var(--fl-accent)' : 'var(--fl-muted)', transition: 'color 0.1s' }}>
                        {cat.icon} {cat.label}
                      </button>
                    ))}
                  </div>
                  <div style={{ overflowY: 'auto', padding: '4px 0' }}>
                    {currentCategory.prompts.map((p, i) => (
                      <PromptItem key={i} text={p} onSend={() => send(p)} onFill={() => { setInput(p); setShowPrompts(false); setTimeout(() => inputRef.current?.focus(), 50); }} />
                    ))}
                  </div>
                </div>
              )}

              <div style={{ flexShrink: 0, padding: '8px 10px', borderTop: showPrompts ? 'none' : '1px solid var(--fl-border)', background: 'var(--fl-bg)', display: 'flex', gap: 6, alignItems: 'flex-end' }}>
                <button onClick={() => setShowPrompts(v => !v)} title={t('globalAi.prompt_menu_title')}
                  style={{ padding: '6px 8px', borderRadius: 6, flexShrink: 0, background: showPrompts ? 'color-mix(in srgb, var(--fl-accent) 20%, transparent)' : 'color-mix(in srgb, var(--fl-accent) 6%, transparent)', border: `1px solid ${showPrompts ? 'color-mix(in srgb, var(--fl-accent) 38%, transparent)' : 'var(--fl-border)'}`, color: showPrompts ? 'var(--fl-accent)' : 'var(--fl-muted)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4, fontSize: 9, fontFamily: MONO }}>
                  <BookOpen size={11} />
                  <ChevronDown size={9} style={{ transform: showPrompts ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }} />
                </button>
                <textarea ref={inputRef} value={input} onChange={e => setInput(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } }}
                  disabled={streaming || !available} placeholder={t('globalAi.message_ph')} rows={2}
                  style={{ flex: 1, background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', borderRadius: 6, color: 'var(--fl-text)', fontSize: 11, fontFamily: UI, padding: '7px 9px', resize: 'none', outline: 'none', lineHeight: 1.5 }}
                  onFocus={e => { e.currentTarget.style.borderColor = 'color-mix(in srgb, var(--fl-accent) 45%, transparent)'; }}
                  onBlur={e => { e.currentTarget.style.borderColor = 'var(--fl-border)'; }}
                />
                {streaming ? (
                  <button onClick={() => abortRef.current?.abort()} title={t('globalAi.stop')}
                    style={{ padding: '0 11px', borderRadius: 6, alignSelf: 'stretch', background: 'color-mix(in srgb, var(--fl-danger) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--fl-danger) 25%, transparent)', color: 'var(--fl-danger)', cursor: 'pointer', fontSize: 14, display: 'flex', alignItems: 'center' }}>⏹</button>
                ) : (
                  <button onClick={() => send()} disabled={!input.trim() || !available} title={t('globalAi.send_enter')}
                    style={{ padding: '0 11px', borderRadius: 6, alignSelf: 'stretch', background: input.trim() ? 'var(--fl-accent)' : 'transparent', border: `1px solid ${input.trim() ? 'var(--fl-accent)' : 'var(--fl-border)'}`, color: input.trim() ? '#fff' : 'var(--fl-muted)', cursor: input.trim() ? 'pointer' : 'default', display: 'flex', alignItems: 'center' }}>
                    <Send size={13} />
                  </button>
                )}
              </div>

              <div style={{ flexShrink: 0, padding: '3px 10px 6px' }}>
                <span style={{ fontSize: 8, fontFamily: MONO, color: 'var(--fl-subtle)' }}>{t('globalAi.footer_hint')}</span>
              </div>
            </>
          )}
        </div>
      )}

      <style>{`@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }`}</style>
    </>
  );
}

function PromptItem({ text, onSend, onFill }) {
  const [hov, setHov] = useState(false);
  const { t } = useTranslation();
  return (
    <div onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)}
      style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 12px', background: hov ? 'var(--fl-hover-bg)' : 'transparent', cursor: 'pointer' }}>
      <span style={{ fontFamily: MONO, fontSize: 10, color: 'var(--fl-accent)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} onClick={onSend} title={text}>{text}</span>
      <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
        <button onClick={onFill} title={t('globalAi.edit_prompt_title')} style={{ padding: '1px 6px', borderRadius: 3, fontSize: 8, fontFamily: MONO, background: 'transparent', border: '1px solid var(--fl-border)', color: 'var(--fl-muted)', cursor: 'pointer', whiteSpace: 'nowrap' }}>{t('globalAi.edit')}</button>
        <button onClick={onSend} title={t('globalAi.send_direct')} style={{ padding: '1px 6px', borderRadius: 3, fontSize: 8, fontFamily: MONO, background: 'color-mix(in srgb, var(--fl-accent) 12%, transparent)', border: '1px solid var(--fl-border)', color: 'var(--fl-accent)', cursor: 'pointer', whiteSpace: 'nowrap' }}>↵ {t('workbench.send')}</button>
      </div>
    </div>
  );
}
