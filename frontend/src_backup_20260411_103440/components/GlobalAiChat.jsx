import { useState, useEffect, useRef, useCallback } from 'react';
import { Sparkles, X, Minimize2, Maximize2, Send, RotateCcw, ChevronDown, BookOpen } from 'lucide-react';

const MODELS_DFLT = ['qwen2.5:7b', 'qwen2.5:14b', 'deepseek-r1:8b', 'llama3.2:3b', 'mistral:7b'];

const SYSTEM_PROMPT = `Tu es un expert DFIR (Digital Forensics & Incident Response) et analyste cybersécurité senior.
Tu aides l'analyste à comprendre les artefacts forensiques, les techniques d'attaque MITRE ATT&CK, et à interpréter les preuves numériques.
Réponds en français. Sois précis, concis, et actionnable.
Si tu ne sais pas, dis-le clairement plutôt que d'inventer.`;

const PROMPT_CATEGORIES = [
  {
    id: 'artefacts',
    label: 'Artefacts Windows',
    icon: '🗂',
    prompts: [
      'Explique ce que contient le MFT ($MFT) et comment l\'utiliser en forensique.',
      'Qu\'est-ce que les fichiers Prefetch et que peut-on en déduire ?',
      'Quelles informations trouve-t-on dans les fichiers LNK (.lnk) ?',
      'Comment analyser les ruches de registre Windows (SAM, SYSTEM, SOFTWARE) ?',
      'Qu\'est-ce que les Shellbags et comment les utiliser pour retracer la navigation ?',
      'Que contient le journal d\'événements EVTX et quels EventID sont critiques ?',
      'Explique ce qu\'est l\'AMCACHE et comment détecter des exécutables suspects.',
      'Comment exploiter les artefacts SRUM pour reconstituer l\'activité réseau ?',
    ],
  },
  {
    id: 'mitre',
    label: 'MITRE ATT&CK',
    icon: '🎯',
    prompts: [
      'Explique les techniques de persistance (T1547) les plus courantes sur Windows.',
      'Comment détecter du process hollowing (T1055.012) dans les logs ?',
      'Quels artefacts indiquent un mouvement latéral (T1021) via RDP ou SMB ?',
      'Explique le Pass-the-Hash (T1550.002) et les artefacts qu\'il laisse.',
      'Comment identifier une exfiltration de données (T1041) dans les logs réseau ?',
      'Qu\'est-ce que le DLL sideloading (T1574.002) et comment le détecter ?',
      'Explique les techniques d\'élévation de privilèges (T1068) les plus fréquentes.',
      'Comment détecter un Living Off the Land (LOLBins) dans les logs Windows ?',
    ],
  },
  {
    id: 'detection',
    label: 'Détection & Analyse',
    icon: '🔍',
    prompts: [
      'Quels EventID Windows sont les plus importants pour détecter une compromission ?',
      'Comment analyser un dump mémoire avec Volatility pour trouver des malwares ?',
      'Explique comment identifier un ransomware à partir d\'artefacts forensiques.',
      'Quels indicateurs montrent qu\'un compte a été compromis dans les logs AD ?',
      'Comment détecter un mimikatz/LSASS dump (EventID 4656, 4663) ?',
      'Explique comment reconstituer la chronologie d\'un incident avec les timestamps.',
      'Quelles règles YARA permettent de détecter des malwares courants ?',
      'Comment détecter un beacon C2 dans une timeline réseau ?',
    ],
  },
  {
    id: 'rapport',
    label: 'Rapport & Synthèse',
    icon: '📋',
    prompts: [
      'Génère un template de rapport d\'incident forensique.',
      'Quels éléments doit contenir un résumé exécutif d\'incident cyber ?',
      'Comment documenter la chaîne de custody (chain of custody) pour les preuves ?',
      'Explique le format STIX/TAXII pour le partage d\'IOCs.',
      'Que doit-on inclure dans une note de triage pour un analyste NOC/SOC ?',
      'Comment rédiger un timeline d\'attaque pour un RSSI non-technique ?',
    ],
  },
];

export default function GlobalAiChat() {
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
  const [activeCategory, setActiveCategory] = useState(PROMPT_CATEGORIES[0].id);

  const abortRef     = useRef(null);
  const endRef       = useRef(null);
  const inputRef     = useRef(null);
  const promptsRef   = useRef(null);

  useEffect(() => {
    fetch('/api/llm/models', {
      headers: { Authorization: `Bearer ${localStorage.getItem('heimdall_token')}` },
    })
      .then(r => r.json())
      .then(d => {
        setAvailable(d.available ?? false);
        if (d.models?.length) { setModels(d.models); setModel(d.models[0]); }
      })
      .catch(() => setAvailable(false));
  }, []);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
    if (!open && messages.length > 0 && messages[messages.length - 1].role === 'assistant') {
      setUnread(u => u + 1);
    }
  }, [messages]);

  useEffect(() => {
    if (open && !minimized) {
      setTimeout(() => inputRef.current?.focus(), 100);
      setUnread(0);
    }
  }, [open, minimized]);

  useEffect(() => {
    function h(e) {
      if (promptsRef.current && !promptsRef.current.contains(e.target)) setShowPrompts(false);
    }
    if (showPrompts) {
      document.addEventListener('mousedown', h);
      return () => document.removeEventListener('mousedown', h);
    }
  }, [showPrompts]);

  function buildPrompt(userMsg) {
    const history = messages.slice(-6).map(m =>
      `${m.role === 'user' ? 'Analyste' : 'IA'}: ${m.content}`
    ).join('\n');
    const context = history ? `${history}\nAnalyste: ${userMsg}` : userMsg;
    if (messages.length === 0) return `${SYSTEM_PROMPT}\n\nAnalyste: ${userMsg}`;
    return `${SYSTEM_PROMPT}\n\n${context}`;
  }

  const send = useCallback(async (text) => {
    const userMsg = (text || input).trim();
    if (!userMsg || streaming || !available) return;
    setInput('');
    setShowPrompts(false);
    setMessages(prev => [...prev, { role: 'user', content: userMsg }]);
    setStreaming(true);
    setMessages(prev => [...prev, { role: 'assistant', content: '', loading: true }]);

    try {
      const controller = new AbortController();
      abortRef.current = controller;

      const res = await fetch('/api/llm/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('heimdall_token')}`,
        },
        body: JSON.stringify({ model, prompt: buildPrompt(userMsg), stream: true }),
        signal: controller.signal,
      });

      if (!res.ok) throw new Error(`Erreur HTTP ${res.status}`);

      const reader  = res.body.getReader();
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
            if (token) {
              setMessages(prev => {
                const arr = [...prev];
                const last = arr[arr.length - 1];
                arr[arr.length - 1] = { role: 'assistant', content: last.content + token };
                return arr;
              });
            }
          } catch {}
        }
      }
    } catch (e) {
      if (e.name !== 'AbortError') {
        setMessages(prev => {
          const arr = [...prev];
          arr[arr.length - 1] = { role: 'assistant', content: `⚠ ${e.message}`, error: true };
          return arr;
        });
      }
    } finally {
      setStreaming(false);
      abortRef.current = null;
    }
  }, [input, streaming, available, model, messages]);

  if (available === false) return null;

  const currentCategory = PROMPT_CATEGORIES.find(c => c.id === activeCategory) || PROMPT_CATEGORIES[0];

  return (
    <>
      {!open && (
        <button
          onClick={() => setOpen(true)}
          title="Chat IA — Ollama local"
          style={{
            position: 'fixed', bottom: 24, right: 24, zIndex: 9000,
            width: 46, height: 46, borderRadius: '50%',
            background: 'var(--fl-panel)',
            border: '1px solid var(--fl-accent)',
            boxShadow: '0 4px 20px rgba(77,130,192,0.35)',
            cursor: 'pointer',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            transition: 'transform 0.15s, box-shadow 0.15s',
          }}
          onMouseEnter={e => { e.currentTarget.style.transform = 'scale(1.1)'; e.currentTarget.style.boxShadow = '0 6px 24px rgba(77,130,192,0.5)'; }}
          onMouseLeave={e => { e.currentTarget.style.transform = 'scale(1)'; e.currentTarget.style.boxShadow = '0 4px 20px rgba(77,130,192,0.35)'; }}
        >
          <Sparkles size={18} style={{ color: 'var(--fl-accent)' }} />
          {unread > 0 && (
            <span style={{
              position: 'absolute', top: -4, right: -4,
              background: '#22c55e', color: '#fff',
              borderRadius: '50%', width: 16, height: 16,
              fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              border: '2px solid var(--fl-bg)',
            }}>{unread}</span>
          )}
        </button>
      )}

      {open && (
        <div style={{
          position: 'fixed', bottom: 24, right: 24, zIndex: 9000,
          width: 400,
          height: minimized ? 48 : 560,
          background: 'var(--fl-panel)',
          border: '1px solid var(--fl-border)',
          borderRadius: 12,
          boxShadow: '0 12px 48px rgba(0,0,0,0.4), 0 0 0 1px rgba(77,130,192,0.1)',
          display: 'flex', flexDirection: 'column',
          overflow: 'hidden',
          transition: 'height 0.2s ease',
        }}>

          <div style={{
            flexShrink: 0, height: 48,
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '0 12px',
            background: 'var(--fl-bg)',
            borderBottom: minimized ? 'none' : '1px solid var(--fl-border)',
            cursor: minimized ? 'pointer' : 'default',
          }} onClick={minimized ? () => setMinimized(false) : undefined}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: available ? '#22c55e' : '#6b7280', boxShadow: available ? '0 0 6px #22c55e' : 'none' }} />
            <span style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 700, color: 'var(--fl-accent)', flex: 1 }}>
              IA Forensique
            </span>
            {!minimized && (
              <>
                <select value={model} onChange={e => setModel(e.target.value)} onClick={e => e.stopPropagation()}
                  style={{ background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', borderRadius: 4, color: 'var(--fl-muted)', fontSize: 8, fontFamily: 'monospace', padding: '1px 3px', maxWidth: 110 }}>
                  {models.map(m => <option key={m} value={m}>{m}</option>)}
                </select>
                {messages.length > 0 && (
                  <button onClick={() => setMessages([])} title="Effacer la conversation"
                    style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, color: 'var(--fl-muted)' }}>
                    <RotateCcw size={11} />
                  </button>
                )}
              </>
            )}
            <button onClick={() => setMinimized(v => !v)} title={minimized ? 'Agrandir' : 'Réduire'}
              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, color: 'var(--fl-muted)' }}>
              {minimized ? <Maximize2 size={11} /> : <Minimize2 size={11} />}
            </button>
            <button onClick={() => { setOpen(false); setMinimized(false); }} title="Fermer"
              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, color: 'var(--fl-muted)' }}>
              <X size={13} />
            </button>
          </div>

          {!minimized && (
            <>
              <div style={{ flex: 1, overflowY: 'auto', padding: '12px 12px 4px', display: 'flex', flexDirection: 'column', gap: 10 }}>
                {messages.length === 0 && (
                  <div style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-muted)', lineHeight: 1.6 }}>
                    Posez une question ou sélectionnez un prompt dans le menu <strong style={{ color: 'var(--fl-accent)' }}>📋 Prompts</strong>.
                  </div>
                )}

                {messages.map((msg, i) => (
                  <div key={i} style={{ alignSelf: msg.role === 'user' ? 'flex-end' : 'flex-start', maxWidth: '90%' }}>
                    {msg.role === 'assistant' && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 3 }}>
                        <div style={{ width: 5, height: 5, borderRadius: '50%', background: '#22c55e' }} />
                        <span style={{ fontFamily: 'monospace', fontSize: 8, color: 'var(--fl-ok)' }}>IA Forensique</span>
                      </div>
                    )}
                    <div style={{
                      padding: '7px 10px',
                      borderRadius: msg.role === 'user' ? '8px 8px 2px 8px' : '2px 8px 8px 8px',
                      background: msg.role === 'user' ? 'rgba(77,130,192,0.15)' : msg.error ? 'rgba(239,68,68,0.08)' : 'var(--fl-card)',
                      border: `1px solid ${msg.role === 'user' ? 'rgba(77,130,192,0.25)' : msg.error ? 'rgba(239,68,68,0.2)' : 'var(--fl-border)'}`,
                    }}>
                      <div style={{
                        fontFamily: 'monospace', fontSize: 10.5,
                        color: msg.role === 'user' ? 'var(--fl-accent)' : msg.error ? '#ef4444' : 'var(--fl-text)',
                        lineHeight: 1.7, whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                      }}>
                        {msg.content || (streaming && i === messages.length - 1
                          ? <span style={{ animation: 'blink 1s step-end infinite' }}>▌</span>
                          : '')}
                      </div>
                    </div>
                  </div>
                ))}
                <div ref={endRef} />
              </div>

              {showPrompts && (
                <div ref={promptsRef} style={{
                  flexShrink: 0,
                  borderTop: '1px solid var(--fl-border)',
                  background: 'var(--fl-bg)',
                  maxHeight: 240,
                  display: 'flex',
                  flexDirection: 'column',
                  overflow: 'hidden',
                }}>
                  <div style={{ display: 'flex', borderBottom: '1px solid var(--fl-border)', flexShrink: 0 }}>
                    {PROMPT_CATEGORIES.map(cat => (
                      <button key={cat.id} onClick={() => setActiveCategory(cat.id)}
                        style={{
                          flex: 1, padding: '5px 2px', fontSize: 8, fontFamily: 'monospace',
                          background: 'none', border: 'none', cursor: 'pointer',
                          borderBottom: `2px solid ${activeCategory === cat.id ? 'var(--fl-accent)' : 'transparent'}`,
                          color: activeCategory === cat.id ? 'var(--fl-accent)' : 'var(--fl-muted)',
                          transition: 'color 0.1s',
                        }}>
                        {cat.icon} {cat.label}
                      </button>
                    ))}
                  </div>
                  <div style={{ overflowY: 'auto', padding: '4px 0' }}>
                    {currentCategory.prompts.map((p, i) => (
                      <PromptItem key={i} text={p}
                        onSend={() => send(p)}
                        onFill={() => { setInput(p); setShowPrompts(false); setTimeout(() => inputRef.current?.focus(), 50); }}
                      />
                    ))}
                  </div>
                </div>
              )}

              <div style={{
                flexShrink: 0, padding: '8px 10px',
                borderTop: showPrompts ? 'none' : '1px solid var(--fl-border)',
                background: 'var(--fl-bg)',
                display: 'flex', gap: 6, alignItems: 'flex-end',
              }}>
                <button
                  onClick={() => setShowPrompts(v => !v)}
                  title="Prompts pré-construits"
                  style={{
                    padding: '6px 8px', borderRadius: 6, flexShrink: 0,
                    background: showPrompts ? 'rgba(77,130,192,0.2)' : 'rgba(77,130,192,0.06)',
                    border: `1px solid ${showPrompts ? '#4d82c060' : 'var(--fl-border)'}`,
                    color: showPrompts ? 'var(--fl-accent)' : 'var(--fl-muted)',
                    cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
                    fontSize: 9, fontFamily: 'monospace',
                  }}>
                  <BookOpen size={11} />
                  <ChevronDown size={9} style={{ transform: showPrompts ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }} />
                </button>

                <textarea
                  ref={inputRef}
                  value={input}
                  onChange={e => setInput(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
                  }}
                  disabled={streaming || !available}
                  placeholder="Message… (Entrée pour envoyer)"
                  rows={2}
                  style={{
                    flex: 1, background: 'var(--fl-input-bg)', border: '1px solid var(--fl-border)', borderRadius: 6,
                    color: 'var(--fl-text)', fontSize: 10.5, fontFamily: 'monospace',
                    padding: '6px 8px', resize: 'none', outline: 'none', lineHeight: 1.5,
                  }}
                />
                {streaming ? (
                  <button onClick={() => abortRef.current?.abort()} title="Arrêter"
                    style={{
                      padding: '0 10px', borderRadius: 6, alignSelf: 'stretch',
                      background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.25)',
                      color: '#ef4444', cursor: 'pointer', fontSize: 14,
                      display: 'flex', alignItems: 'center',
                    }}>⏹</button>
                ) : (
                  <button onClick={() => send()} disabled={!input.trim() || !available} title="Envoyer (Entrée)"
                    style={{
                      padding: '0 10px', borderRadius: 6, alignSelf: 'stretch',
                      background: input.trim() ? 'rgba(77,130,192,0.2)' : 'transparent',
                      border: `1px solid ${input.trim() ? 'rgba(77,130,192,0.3)' : 'var(--fl-border)'}`,
                      color: input.trim() ? 'var(--fl-accent)' : 'var(--fl-muted)',
                      cursor: input.trim() ? 'pointer' : 'default',
                      display: 'flex', alignItems: 'center',
                    }}>
                    <Send size={13} />
                  </button>
                )}
              </div>

              <div style={{ flexShrink: 0, padding: '3px 10px 5px' }}>
                <span style={{ fontSize: 8, fontFamily: 'monospace', color: 'var(--fl-border)' }}>
                  Shift+Entrée = saut de ligne · données restent en local
                </span>
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
  return (
    <div
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: 'flex', alignItems: 'center', gap: 6,
        padding: '5px 12px',
        background: hov ? 'var(--fl-hover-bg)' : 'transparent',
        cursor: 'pointer',
      }}>
      <span
        style={{
          fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-accent)',
          flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}
        onClick={onSend}
        title={text}
      >
        {text}
      </span>
      <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
        <button onClick={onFill}
          title="Mettre dans la zone de texte pour éditer"
          style={{
            padding: '1px 6px', borderRadius: 3, fontSize: 8, fontFamily: 'monospace',
            background: 'transparent', border: '1px solid var(--fl-border)',
            color: 'var(--fl-muted)', cursor: 'pointer', whiteSpace: 'nowrap',
          }}>
          Éditer
        </button>
        <button onClick={onSend}
          title="Envoyer directement"
          style={{
            padding: '1px 6px', borderRadius: 3, fontSize: 8, fontFamily: 'monospace',
            background: 'rgba(77,130,192,0.12)', border: '1px solid var(--fl-border)',
            color: 'var(--fl-accent)', cursor: 'pointer', whiteSpace: 'nowrap',
          }}>
          ↵ Envoyer
        </button>
      </div>
    </div>
  );
}
