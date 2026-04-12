
import { useState, useRef, useEffect } from 'react';

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
          ? <span style={{ color: '#22c55e', fontSize: 8, animation: 'blink 1s step-end infinite' }}>●</span>
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
          {isActive && <span style={{ color: '#22c55e', animation: 'blink 1s step-end infinite' }}>▌</span>}
        </div>
      )}
    </div>
  );
}

const DEFAULT_MODELS = ['qwen2.5:7b', 'qwen2.5:14b', 'deepseek-r1:8b', 'llama3.2:3b', 'mistral:7b'];
const SYSTEM_PROMPT = `Tu es un analyste forensique senior en DFIR (Digital Forensics and Incident Response).
Tu analyses des événements de timeline forensique (Windows artifacts: EVTX, MFT, Prefetch, Registry, etc.).
Réponds en français. Sois concis et précis. Identifie les comportements suspects, les IOCs, et les techniques MITRE ATT&CK.`;

const ARTIFACT_ICONS = {
  evtx:        '📋', winevt: '📋', event: '📋',
  prefetch:    '⚡', pf: '⚡',
  mft:         '🗂️', usnjrnl: '🗂️', '$mft': '🗂️',
  registry:    '🔑', reg: '🔑', amcache: '🔑',
  lnk:         '🔗', shellbag: '🔗',
  hayabusa:    '🚨', sigma: '🚨',
  srum:        '📊', timeline: '📊',
  network:     '🌐', dns: '🌐',
  memory:      '💾', vol: '💾',
};

function artifactIcon(type) {
  const t = (type || '').toLowerCase();
  for (const [key, icon] of Object.entries(ARTIFACT_ICONS)) {
    if (t.includes(key)) return icon;
  }
  return '🔍';
}

function ThinkingSteps({ steps, collapsed, onToggle }) {
  if (!steps || steps.length === 0) return null;

  const lastStep     = steps[steps.length - 1];
  const isGenerating = lastStep?.status === 'generating';
  const doneCount    = steps.filter(s => s.status === 'done').length;
  const total        = steps.filter(s => s.status !== 'generating').length;

  return (
    <div style={{
      marginBottom: 6,
      borderRadius: 5,
      border: '1px solid #0d2035',
      background: 'rgba(4,10,20,0.8)',
      overflow: 'hidden',
      fontSize: 9,
      fontFamily: 'monospace',
    }}>
      
      <div
        onClick={onToggle}
        style={{
          display: 'flex', alignItems: 'center', gap: 5,
          padding: '4px 8px', cursor: 'pointer',
          background: 'rgba(4,14,28,0.95)',
          borderBottom: collapsed ? 'none' : '1px solid #0d2035',
          userSelect: 'none',
        }}
      >
        <span style={{ color: '#2a5a8a', flexShrink: 0 }}>{collapsed ? '▶' : '▼'}</span>
        <span style={{ color: '#1a4a6a' }}>
          {isGenerating
            ? <><span style={{ color: '#4d82c0' }}>🤖</span> Génération en cours…</>
            : `Contexte lu — ${doneCount}/${total} sources`}
        </span>
        {!collapsed && (
          <span style={{ marginLeft: 'auto', color: '#0d2a40', fontSize: 8 }}>cliquer pour replier</span>
        )}
      </div>

      {!collapsed && (
        <div style={{ padding: '5px 8px', display: 'flex', flexDirection: 'column', gap: 3 }}>
          {steps.map((step, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{
                flexShrink: 0, fontSize: 8,
                color: step.status === 'done' ? '#22c55e'
                  : step.status === 'generating' ? '#4d82c0'
                  : '#3a6a9a',
              }}>
                {step.status === 'done' ? '✓'
                  : step.status === 'generating' ? '▌'
                  : '⟳'}
              </span>
              <span style={{
                color: step.status === 'done' ? '#3a8a5a'
                  : step.status === 'generating' ? '#4d82c0'
                  : '#2a5a8a',
              }}>
                {step.icon} {step.label}
              </span>
              {step.count !== undefined && (
                <span style={{ color: '#1a4060' }}>[{step.count}]</span>
              )}
              {step.detail && (
                <span style={{ color: '#1a5a3a', opacity: 0.85 }}>— {step.detail}</span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function AiAnalystPanel({ records, caseId, totalEvents = 0 }) {
  const [model, setModel]             = useState(DEFAULT_MODELS[0]);
  const [prompt, setPrompt]           = useState('');
  const [messages, setMessages]       = useState([]);
  const [streaming, setStreaming]     = useState(false);
  const [available, setAvailable]     = useState(null);
  const [models, setModels]           = useState(DEFAULT_MODELS);
  const [collapsedMap, setCollapsedMap]   = useState({});
  const [collapsedThink, setCollapsedThink] = useState({});
  const abortRef      = useRef(null);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    fetch('/api/llm/models', {
      headers: { Authorization: `Bearer ${localStorage.getItem('heimdall_token')}` },
    })
      .then(r => r.json())
      .then(d => {
        setAvailable(d.available ?? false);
        if (d.models?.length) setModels(d.models);
      })
      .catch(() => setAvailable(false));
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  function buildThinkingSteps() {
    const recs = records || [];

    const byType = {};
    for (const r of recs) {
      const t = (r.artifact_type || 'inconnu').toLowerCase();
      byType[t] = (byType[t] || 0) + 1;
    }

    const steps = [];

    steps.push({
      icon: '📅',
      label: 'Super Timeline',
      status: 'done',
      count: totalEvents || recs.length,
      detail: `${recs.length} chargés · analyse intelligente`,
    });

    for (const [type, count] of Object.entries(byType).sort((a, b) => b[1] - a[1])) {
      steps.push({ icon: artifactIcon(type), label: type, status: 'done', count });
    }

    const hosts = new Set(recs.map(r => r.host_name).filter(Boolean));
    const users = new Set(recs.map(r => r.user_name).filter(Boolean));
    if (hosts.size > 0)
      steps.push({ icon: '🖥️', label: 'Machines', status: 'done', count: hosts.size, detail: [...hosts].slice(0, 3).join(', ') + (hosts.size > 3 ? '…' : '') });
    if (users.size > 0)
      steps.push({ icon: '👤', label: 'Utilisateurs', status: 'done', count: users.size, detail: [...users].slice(0, 3).join(', ') + (users.size > 3 ? '…' : '') });

    const mitreSet = new Set(
      recs.map(r => r.mitre_technique || r.mitre_technique_id).filter(Boolean)
    );
    if (mitreSet.size > 0)
      steps.push({ icon: '🛡️', label: 'Techniques MITRE ATT&CK', status: 'done', count: mitreSet.size, detail: [...mitreSet].slice(0, 4).join(', ') + (mitreSet.size > 4 ? '…' : '') });

    steps.push({ icon: '🤖', label: "Génération de l'analyse", status: 'generating' });

    return steps;
  }

  function buildContext() {
    const recs = records || [];
    const n    = recs.length;

    const byType  = {};
    const byLevel = {};
    const hosts   = new Set();
    const users   = new Set();
    const procs   = new Set();
    const mitres  = new Set();
    let   earliest = null, latest = null;

    for (const r of recs) {
      const t = (r.artifact_type || 'inconnu').toLowerCase();
      byType[t]  = (byType[t]  || 0) + 1;
      const lv   = (r.level || 'info').toLowerCase();
      byLevel[lv] = (byLevel[lv] || 0) + 1;
      if (r.host_name)    hosts.add(r.host_name);
      if (r.user_name)    users.add(r.user_name);
      if (r.process_name) procs.add(r.process_name);
      const m = r.mitre_technique || r.mitre_technique_id;
      if (m) mitres.add(m);
      if (r.timestamp) {
        if (!earliest || r.timestamp < earliest) earliest = r.timestamp;
        if (!latest   || r.timestamp > latest)   latest   = r.timestamp;
      }
    }

    const statsBlock = [
      `ÉVÉNEMENTS : ${totalEvents ? `${totalEvents.toLocaleString()} au total dans la base` : `${n} chargés`}${totalEvents && totalEvents > n ? ` (${n} analysés ici — appliquer des filtres pour affiner)` : ''}`,
      `FENÊTRE TEMPORELLE : ${earliest || '?'} → ${latest || '?'}`,
      `PAR TYPE : ${Object.entries(byType).sort((a,b) => b[1]-a[1]).map(([t,c]) => `${t}(${c})`).join(', ')}`,
      `PAR NIVEAU : ${Object.entries(byLevel).sort((a,b) => b[1]-a[1]).map(([l,c]) => `${l}(${c})`).join(', ')}`,
      `MACHINES (${hosts.size}) : ${[...hosts].slice(0, 10).join(', ')}${hosts.size > 10 ? '…' : ''}`,
      `UTILISATEURS (${users.size}) : ${[...users].slice(0, 10).join(', ')}${users.size > 10 ? '…' : ''}`,
      `PROCESSUS UNIQUES (${procs.size}) : ${[...procs].slice(0, 15).join(', ')}${procs.size > 15 ? '…' : ''}`,
      `TECHNIQUES MITRE (${mitres.size}) : ${[...mitres].join(', ')}`,
    ].join('\n');

    const LEVEL_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const topEvents = [...recs]
      .filter(r => ['critical','high'].includes((r.level || '').toLowerCase()))
      .sort((a, b) => (LEVEL_ORDER[a.level?.toLowerCase()] ?? 9) - (LEVEL_ORDER[b.level?.toLowerCase()] ?? 9))
      .slice(0, 30)
      .map(r => ({
        ts:     r.timestamp,
        type:   r.artifact_type,
        level:  r.level,
        host:   r.host_name,
        user:   r.user_name,
        proc:   r.process_name,
        mitre:  r.mitre_technique || r.mitre_technique_id,
        desc:   (r.description || '').substring(0, 150),
      }));

    const byTypeSample = {};
    for (const r of recs) {
      const t = (r.artifact_type || 'inconnu').toLowerCase();
      if (!byTypeSample[t]) byTypeSample[t] = [];
      if (byTypeSample[t].length < 3) {
        byTypeSample[t].push({
          ts:   r.timestamp,
          host: r.host_name,
          user: r.user_name,
          desc: (r.description || '').substring(0, 100),
        });
      }
    }

    return [
      `=== STATISTIQUES GLOBALES ===\n${statsBlock}`,
      topEvents.length
        ? `\n=== TOP ${topEvents.length} ÉVÉNEMENTS CRITIQUES/HIGH ===\n${JSON.stringify(topEvents, null, 1)}`
        : '\n(Aucun événement critique ou high dans les records chargés)',
      `\n=== EXEMPLES PAR TYPE D'ARTIFACT ===\n${JSON.stringify(byTypeSample, null, 1)}`,
    ].join('\n');
  }

  async function runThinkingAnimation(msgId, steps) {
    const allButLast = steps.slice(0, -1);
    const last       = steps[steps.length - 1];

    for (const step of allButLast) {

      setMessages(prev => {
        const arr = [...prev];
        const msg = arr.find(m => m.id === msgId);
        if (!msg) return arr;
        const existing = msg.thinkingSteps || [];
        const updated  = [...existing, { ...step, status: 'loading' }];
        return arr.map(m => m.id === msgId ? { ...m, thinkingSteps: updated } : m);
      });

      const delay = Math.min(800, Math.max(120, (step.count || 10) / 5));
      await new Promise(r => setTimeout(r, delay));

      setMessages(prev => {
        const arr = [...prev];
        return arr.map(m => {
          if (m.id !== msgId) return m;
          const updated = (m.thinkingSteps || []).map(s =>
            s.label === step.label ? { ...s, status: 'done' } : s
          );
          return { ...m, thinkingSteps: updated };
        });
      });
    }

    setMessages(prev => prev.map(m => {
      if (m.id !== msgId) return m;
      const updated = [...(m.thinkingSteps || []), last];
      return { ...m, thinkingSteps: updated };
    }));
  }

  async function sendMessage() {
    if (!prompt.trim() || streaming || !available) return;
    const userMsg = prompt.trim();
    setPrompt('');
    const currentMessages = messages;
    const msgId = Date.now();

    setMessages(prev => [
      ...prev,
      { role: 'user', content: userMsg },
      { role: 'assistant', content: '', id: msgId, thinkingSteps: [], loading: true },
    ]);
    setStreaming(true);

    const steps = buildThinkingSteps();
    runThinkingAnimation(msgId, steps);

    const context = buildContext();
    const history = currentMessages.map(m =>
      `${m.role === 'user' ? 'Analyste' : 'IA'}: ${m.content}`
    ).join('\n\n');
    const fullPrompt = currentMessages.length === 0
      ? `${SYSTEM_PROMPT}\n\n${context}\n\nQuestion: ${userMsg}`
      : `${SYSTEM_PROMPT}\n\n${context}\n\nHistorique de la conversation:\n${history}\n\nAnalyste: ${userMsg}`;

    try {
      const controller = new AbortController();
      abortRef.current = controller;

      const res = await fetch('/api/llm/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('heimdall_token')}`,
        },
        body: JSON.stringify({ model, prompt: fullPrompt, stream: true }),
        signal: controller.signal,
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const reader  = res.body.getReader();
      const decoder = new TextDecoder();
      let sseBuffer = '';
      let rawAccum  = '';
      let thinkDone = false;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        sseBuffer += decoder.decode(value, { stream: true });
        const lines = sseBuffer.split('\n');
        sseBuffer = lines.pop() ?? '';

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const data = line.slice(6);
          if (data === '[DONE]') break;
          try {
            const j = JSON.parse(data);
            const token = j.response || j.token || '';
            if (!token) continue;

            rawAccum += token;
            const { think, response, isThinking } = parseThink(rawAccum);

            if (response && !thinkDone && !isThinking) {
              thinkDone = true;
              setCollapsedMap(prev => ({ ...prev, [msgId]: true }));
            }

            setMessages(prev => prev.map(m => m.id !== msgId ? m : {
              ...m,
              content:    response,
              thinkText:  think,
              isThinking,
              loading:    false,
            }));
          } catch (_e) {}
        }
      }
    } catch (e) {
      if (e.name !== 'AbortError') {
        setMessages(prev => prev.map(m => m.id !== msgId ? m : {
          ...m, content: `Erreur: ${e.message}`, loading: false,
        }));
      }
    } finally {
      setStreaming(false);
      abortRef.current = null;
    }
  }

  if (available === null) return (
    <div style={{ padding: 16, fontFamily: 'monospace', fontSize: 10, color: '#2a5a8a' }}>
      Vérification disponibilité Ollama…
    </div>
  );

  if (!available) return (
    <div style={{ padding: '16px 20px' }}>
      <div style={{ fontFamily: 'monospace', fontSize: 11, color: '#2a5a8a', marginBottom: 8 }}>
        IA Locale (Ollama) — non disponible
      </div>
      <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#1a3a5c', lineHeight: 1.6 }}>
        Pour activer : démarrez le service Docker avec le profil <code style={{ color: '#4d82c0' }}>ai</code>
        <br />
        <code style={{ color: '#4d82c0' }}>docker compose --profile ai up -d</code>
        <br />
        Puis configurez <code style={{ color: '#4d82c0' }}>OLLAMA_URL</code> dans le backend.
      </div>
    </div>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: '#04080f' }}>
      
      <div style={{ flexShrink: 0, padding: '6px 12px', borderBottom: '1px solid #0d1f30', display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#22c55e', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          ⚡ IA Locale
        </span>
        <select value={model} onChange={e => setModel(e.target.value)}
          style={{ background: '#0a1520', border: '1px solid #0d1f30', borderRadius: 4, color: '#7abfff', fontSize: 9, fontFamily: 'monospace', padding: '1px 4px' }}>
          {models.map(m => <option key={m} value={m}>{m}</option>)}
        </select>
        {messages.length > 0 && (
          <button onClick={() => { setMessages([]); setCollapsedMap({}); }}
            style={{ marginLeft: 'auto', fontSize: 9, fontFamily: 'monospace', color: '#2a5a8a', background: 'none', border: 'none', cursor: 'pointer' }}>
            ✕ Effacer
          </button>
        )}
      </div>

      <div style={{ flex: 1, overflow: 'auto', padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 10 }}>
        {messages.length === 0 && (
          <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#1a3a5c', lineHeight: 1.7 }}>
            Posez une question sur les <strong style={{ color: '#2a5a8a' }}>{records?.length ?? 0} événements</strong> chargés.
            <br />
            <span style={{ fontSize: 9, color: '#0d1f30' }}>Modèle: {model} · CPU uniquement</span>
            <br /><br />
            Exemples :
            <br />• Quels sont les processus les plus suspects ?
            <br />• Y a-t-il des signes de persistence ?
            <br />• Résume la chronologie des événements critiques.
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={msg.id || i} style={{
            maxWidth: '92%',
            alignSelf: msg.role === 'user' ? 'flex-end' : 'flex-start',
          }}>
            
            {msg.role === 'assistant' && msg.thinkingSteps?.length > 0 && (
              <ThinkingSteps
                steps={msg.thinkingSteps}
                collapsed={!!collapsedMap[msg.id]}
                onToggle={() => setCollapsedMap(prev => ({ ...prev, [msg.id]: !prev[msg.id] }))}
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
              background: msg.role === 'user' ? 'rgba(77,130,192,0.15)' : 'rgba(6,17,31,0.8)',
              border: `1px solid ${msg.role === 'user' ? 'rgba(77,130,192,0.3)' : '#0d1f30'}`,
              borderRadius: msg.role === 'user' ? '8px 8px 2px 8px' : '2px 8px 8px 8px',
              padding: '7px 10px',
            }}>
              <div style={{
                fontFamily: 'monospace', fontSize: 10,
                color: msg.role === 'user' ? '#7abfff' : '#c0cce0',
                lineHeight: 1.65, whiteSpace: 'pre-wrap',
              }}>
                {msg.content
                  ? msg.content
                  : msg.isThinking
                    ? <span style={{ color: '#1a5a2a', fontSize: 9 }}>Raisonnement…</span>
                    : msg.loading
                      ? <span style={{ color: '#1a4060', fontSize: 9 }}>Lecture des artifacts…</span>
                      : streaming && i === messages.length - 1
                        ? '▌'
                        : ''}
              </div>
            </div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      <div style={{ flexShrink: 0, padding: '8px 12px', borderTop: '1px solid #0d1f30', display: 'flex', gap: 6 }}>
        <textarea
          value={prompt}
          onChange={e => setPrompt(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } }}
          placeholder="Question (Entrée pour envoyer, Shift+Entrée saut de ligne)…"
          rows={2}
          disabled={streaming}
          style={{
            flex: 1, background: '#06111f', border: '1px solid #0d1f30', borderRadius: 5,
            color: '#c0cce0', fontSize: 10, fontFamily: 'monospace', padding: '6px 8px',
            resize: 'none', outline: 'none',
          }}
        />
        {streaming ? (
          <button onClick={() => abortRef.current?.abort()}
            style={{ padding: '6px 10px', borderRadius: 5, background: 'rgba(239,68,68,0.15)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.3)', cursor: 'pointer', fontSize: 10, fontFamily: 'monospace' }}>
            ⏹
          </button>
        ) : (
          <button onClick={sendMessage} disabled={!prompt.trim()}
            style={{ padding: '6px 10px', borderRadius: 5, background: prompt.trim() ? 'rgba(77,130,192,0.2)' : 'transparent', color: prompt.trim() ? '#4d82c0' : '#1a3a5c', border: '1px solid #0d1f30', cursor: prompt.trim() ? 'pointer' : 'default', fontSize: 10, fontFamily: 'monospace' }}>
            ↵
          </button>
        )}
      </div>
    </div>
  );
}
