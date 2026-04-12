import { useState, useEffect, useRef, useCallback } from 'react';
import { usePreferences } from '../../utils/preferences';
import {
  MessageSquare, X, Send, Loader2, Trash2, Bell,
  ChevronDown, Search, Pin, PinOff, Reply, Volume2, VolumeX,
  MoreHorizontal, Bot, Maximize2, Minimize2,
} from 'lucide-react';
import api from '../../utils/api';
import { useDraggable } from '../../hooks/useDraggable';

const PANEL_WIDTH = 380;

function fmtTime(ts) {
  return new Date(ts).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
}
function fmtDate(ts) {
  return new Date(ts).toLocaleDateString('fr-FR', { day: '2-digit', month: 'short' });
}
function hashCode(s) {
  return Math.abs([...s].reduce((h, c) => Math.imul(31, h) + c.charCodeAt(0) | 0, 0));
}
const AVATAR_COLORS = ['#4d82c0', '#8b5cf6', '#22c55e', '#f97316', '#e11d48', '#06b6d4'];
function avatarColor(u) { return AVATAR_COLORS[hashCode(u || '') % AVATAR_COLORS.length]; }
function initials(n) { return (n || '?').slice(0, 2).toUpperCase(); }

function playPing() {
  try {
    const ctx = new AudioContext();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain); gain.connect(ctx.destination);
    osc.frequency.value = 880;
    gain.gain.setValueAtTime(0.25, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.4);
    osc.start(); osc.stop(ctx.currentTime + 0.4);
  } catch (_e) {}
}

const QUICK_EMOJIS = ['👍', '✅', '🔴', '⚠️', '🔍', '💡', '🚨', '😂'];
const EMOJI_GRID = [
  '😀','😂','🤔','😅','😎','🤯','😤','🥳',
  '👍','👎','👋','🙌','👀','🤞','✌️','💪',
  '🔍','🚨','✅','⚠️','🔴','🟡','🟢','💡',
  '🛡️','🔐','💻','🌐','⚡','🔒','🧬','📋',
  '🐛','🚀','🎯','🔥','💀','☠️','🕵️','🔑',
];

const IOC_RE = /(@\w+)|(\b[a-fA-F0-9]{64}\b)|(\b[a-fA-F0-9]{40}\b)|(\b[a-fA-F0-9]{32}\b)|(\b(?:\d{1,3}\.){3}\d{1,3}\b)/g;

const IOC_STYLE = {
  mention: { color: '#4d82c0', fontWeight: 700, background: '#4d82c018', borderRadius: 3, padding: '0 3px' },
  sha256:  { color: '#da3633', fontFamily: 'monospace', fontSize: 11, background: '#da363318', borderRadius: 3, padding: '0 3px', cursor: 'help' },
  sha1:    { color: '#c89d1d', fontFamily: 'monospace', fontSize: 11, background: '#c89d1d18', borderRadius: 3, padding: '0 3px', cursor: 'help' },
  md5:     { color: '#8b5cf6', fontFamily: 'monospace', fontSize: 11, background: '#8b5cf618', borderRadius: 3, padding: '0 3px', cursor: 'help' },
  ipv4:    { color: '#f0883e', fontFamily: 'monospace', fontSize: 12, background: '#f0883e18', borderRadius: 3, padding: '0 3px' },
};

function renderContent(text) {
  const segments = [];
  let last = 0;
  const re = new RegExp(IOC_RE.source, 'g');
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) segments.push({ t: 'text', v: text.slice(last, m.index) });
    const [full, mention, sha256, sha1, md5, ipv4] = m;
    if (mention) segments.push({ t: 'mention', v: full });
    else if (sha256) segments.push({ t: 'sha256', v: full });
    else if (sha1)   segments.push({ t: 'sha1',   v: full });
    else if (md5)    segments.push({ t: 'md5',    v: full });
    else if (ipv4)   segments.push({ t: 'ipv4',   v: full });
    last = m.index + full.length;
  }
  if (last < text.length) segments.push({ t: 'text', v: text.slice(last) });

  return segments.map((seg, i) => {
    if (seg.t === 'text') return <span key={i}>{seg.v}</span>;
    const style = IOC_STYLE[seg.t] || {};
    const display = (seg.t === 'sha256' || seg.t === 'sha1')
      ? seg.v.slice(0, 8) + '…'
      : seg.v;
    return (
      <span key={i} style={style} title={seg.t !== 'mention' ? `${seg.t.toUpperCase()}: ${seg.v}` : undefined}>
        {display}
      </span>
    );
  });
}

function buildReactMap(reactions = []) {
  const m = new Map();
  for (const r of reactions) {
    if (!m.has(r.emoji)) m.set(r.emoji, new Set());
    m.get(r.emoji).add(r.user_id);
  }
  return m;
}

const GLOBAL_STYLE = `
@keyframes fl-bounce {
  0%,80%,100%{transform:translateY(0);opacity:.4}
  40%{transform:translateY(-4px);opacity:1}
}
@keyframes fl-fadein {
  from{opacity:0;transform:translateY(4px)}
  to{opacity:1;transform:translateY(0)}
}
`;

function PinBanner({ pinned, onUnpin, onScrollTo, canPin }) {
  if (!pinned) return null;
  return (
    <div style={{
      background: '#1a2535', borderBottom: '1px solid #2d4a5e',
      padding: '5px 12px', display: 'flex', alignItems: 'center', gap: 8,
      flexShrink: 0,
    }}>
      <Pin size={11} color="#4d82c0" />
      <button
        onClick={onScrollTo}
        style={{ flex: 1, background: 'none', border: 'none', cursor: 'pointer',
          textAlign: 'left', fontSize: 11, color: '#8aa0bc', padding: 0,
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
        title="Aller au message épinglé"
      >
        <span style={{ color: '#7d8590', marginRight: 5 }}>
          {pinned.username} :
        </span>
        {pinned.content}
      </button>
      {canPin && (
        <button onClick={onUnpin} title="Désépingler"
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#4d5460', padding: 0 }}>
          <PinOff size={11} />
        </button>
      )}
    </div>
  );
}

function ReplyBar({ replyTo, onClear }) {
  if (!replyTo) return null;
  return (
    <div style={{
      margin: '0 10px 4px',
      padding: '5px 10px', background: '#1a2535',
      borderLeft: '3px solid #4d82c0', borderRadius: 4,
      display: 'flex', alignItems: 'center', gap: 8,
    }}>
      <Reply size={10} color="#4d82c0" />
      <div style={{ flex: 1, minWidth: 0 }}>
        <span style={{ fontSize: 10, color: '#4d82c0', fontWeight: 700 }}>
          {replyTo.full_name || replyTo.username}
        </span>
        <span style={{ fontSize: 11, color: '#7d8590', marginLeft: 6,
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'inline-block', maxWidth: 200, verticalAlign: 'bottom' }}>
          {replyTo.content}
        </span>
      </div>
      <button onClick={onClear}
        style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#4d5460', padding: 0 }}>
        <X size={12} />
      </button>
    </div>
  );
}

function MentionDropdown({ users, onSelect, onlineIds = new Set() }) {
  if (!users.length) return null;
  return (
    <div style={{
      position: 'absolute', bottom: '100%', left: 0, right: 0,
      background: '#0d1117', border: '1px solid #4d82c080', borderRadius: 8,
      marginBottom: 6, overflow: 'hidden', zIndex: 30,
      animation: 'fl-fadein 0.1s ease',
      boxShadow: '0 -4px 16px rgba(0,0,0,0.6)',
    }}>
      <div style={{ padding: '4px 10px 3px', fontSize: 10, color: '#4d82c0', fontWeight: 600, borderBottom: '1px solid #21262d' }}>
        Mentionner un analyste
      </div>
      {users.map(u => {
        const online = onlineIds.has(u.id);
        return (
          <button
            key={u.id}
            onMouseDown={e => { e.preventDefault(); onSelect(u); }}
            style={{
              width: '100%', display: 'flex', alignItems: 'center', gap: 9,
              padding: '7px 12px', background: 'none', border: 'none',
              cursor: 'pointer', textAlign: 'left',
            }}
            onMouseEnter={e => e.currentTarget.style.background = '#1c2333'}
            onMouseLeave={e => e.currentTarget.style.background = 'none'}
          >
            
            <div style={{ position: 'relative', flexShrink: 0 }}>
              <div style={{
                width: 26, height: 26, borderRadius: '50%',
                background: avatarColor(u.username),
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 10, fontWeight: 700, color: '#fff',
              }}>
                {initials(u.full_name || u.username)}
              </div>
              <div style={{
                position: 'absolute', bottom: 0, right: 0,
                width: 8, height: 8, borderRadius: '50%',
                background: online ? '#3fb950' : '#4d5460',
                border: '1.5px solid #0d1117',
              }} />
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: '#e6edf3' }}>
                @{u.username}
              </div>
              {u.full_name && (
                <div style={{ fontSize: 10, color: '#8b949e', marginTop: 1 }}>
                  {u.full_name}{online ? ' · en ligne' : ''}
                </div>
              )}
            </div>
            <span style={{
              fontSize: 9, padding: '1px 5px', borderRadius: 3,
              background: u.role === 'admin' ? '#8b5cf620' : '#4d82c015',
              color: u.role === 'admin' ? '#8b5cf6' : '#4d82c0',
              border: `1px solid ${u.role === 'admin' ? '#8b5cf630' : '#4d82c025'}`,
              flexShrink: 0,
            }}>{u.role}</span>
          </button>
        );
      })}
    </div>
  );
}

function DaySep({ date }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, margin: '12px 0' }}>
      <div style={{ flex: 1, height: 1, background: '#21262d' }} />
      <span style={{ fontSize: 10, color: '#4d5460' }}>{date}</span>
      <div style={{ flex: 1, height: 1, background: '#21262d' }} />
    </div>
  );
}

function Bubble({ msg, currentUserId, onDelete, onReact, onPin, onReply,
                   hideHeader, reactionMap, onScrollTo, canPin, searchQuery, ownColor }) {
  const isOwn = msg.author_id === currentUserId;
  const username = msg.username || msg.full_name || '?';
  const [showActions, setShowActions] = useState(false);
  const [showTimestamp, setShowTimestamp] = useState(false);
  const [showEmojiBar, setShowEmojiBar] = useState(false);
  const hideTimerRef = useRef(null);

  const enter = () => { clearTimeout(hideTimerRef.current); setShowActions(true); setShowEmojiBar(true); };
  const leave = () => { hideTimerRef.current = setTimeout(() => { setShowActions(false); setShowEmojiBar(false); }, 150); };
  const keepOpen = () => clearTimeout(hideTimerRef.current);

  if (msg.is_ping) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', margin: '6px 0' }}>
        <div style={{
          background: '#21303f', border: '1px solid #2d4a5e',
          borderRadius: 8, padding: '4px 10px',
          fontSize: 11, color: '#7d8590', fontStyle: 'italic',
          maxWidth: '90%', textAlign: 'center',
        }}>
          {msg.content}
        </div>
      </div>
    );
  }

  const content = msg.content || '';
  const displayContent = searchQuery
    ? content
    : content;

  return (
    <div
      id={`msg-${msg.id}`}
      style={{
        display: 'flex', flexDirection: isOwn ? 'row-reverse' : 'row',
        alignItems: 'flex-end', gap: 6,
        marginBottom: hideHeader ? 2 : 8,
        animation: 'fl-fadein 0.15s ease',
      }}
      onMouseEnter={enter}
      onMouseLeave={leave}
    >
      
      {!isOwn && (
        <div style={{
          width: 28, height: 28, borderRadius: '50%', flexShrink: 0,
          background: hideHeader ? 'transparent' : avatarColor(username),
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 10, fontWeight: 700, color: '#fff', alignSelf: 'flex-end',
        }}>
          {!hideHeader && initials(username)}
        </div>
      )}

      <div style={{ maxWidth: '78%', display: 'flex', flexDirection: 'column',
        alignItems: isOwn ? 'flex-end' : 'flex-start', position: 'relative' }}>

        {!isOwn && !hideHeader && (
          <div style={{ fontSize: 12, color: '#7d8590', marginBottom: 2 }}>
            {msg.full_name || msg.username}
          </div>
        )}

        {msg.pinned && (
          <div style={{ fontSize: 9, color: '#4d82c0', display: 'flex', alignItems: 'center', gap: 3, marginBottom: 2 }}>
            <Pin size={9} /> épinglé par {msg.pinned_by_username || '?'}
          </div>
        )}

        {msg.reply_to && (
          <button
            onClick={() => onScrollTo(msg.reply_to.id)}
            style={{
              display: 'block', width: '100%', background: '#1a2535',
              border: 'none', borderLeft: '2px solid #4d82c060',
              borderRadius: 4, padding: '3px 8px', marginBottom: 3,
              cursor: 'pointer', textAlign: isOwn ? 'right' : 'left',
            }}
          >
            <div style={{ fontSize: 10, color: '#4d82c0', fontWeight: 600 }}>
              {msg.reply_to.full_name || msg.reply_to.username}
            </div>
            <div style={{ fontSize: 11, color: '#7d8590',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 200 }}>
              {msg.reply_to.content}
            </div>
          </button>
        )}

        {showEmojiBar && (
          <div
            onMouseEnter={keepOpen}
            onMouseLeave={leave}
            style={{
              position: 'absolute', top: -32,
              ...(isOwn ? { right: 0 } : { left: 34 }),
              background: '#161b22', border: '1px solid #30363d',
              borderRadius: 20, padding: '3px 6px',
              display: 'flex', gap: 2, zIndex: 20,
              animation: 'fl-fadein 0.1s ease',
            }}
          >
            {QUICK_EMOJIS.map(e => (
              <button key={e} onClick={() => onReact(msg.id, e)}
                style={{ width: 22, height: 22, background: 'transparent', border: 'none',
                  cursor: 'pointer', fontSize: 14, display: 'flex', alignItems: 'center',
                  justifyContent: 'center', borderRadius: '50%' }}
                onMouseEnter={ev => ev.currentTarget.style.background = '#21303f'}
                onMouseLeave={ev => ev.currentTarget.style.background = 'transparent'}
              >{e}</button>
            ))}
            
            <div style={{ width: 1, background: '#30363d', margin: '2px 2px' }} />
            
            <button onClick={() => { onReply(msg); setShowEmojiBar(false); }}
              style={{ width: 22, height: 22, background: 'transparent', border: 'none',
                cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center',
                borderRadius: '50%', color: '#7d8590' }}
              title="Répondre"
              onMouseEnter={ev => ev.currentTarget.style.background = '#21303f'}
              onMouseLeave={ev => ev.currentTarget.style.background = 'transparent'}
            ><Reply size={12} /></button>
            
            {canPin && (
              <button onClick={() => { onPin(msg.id); setShowEmojiBar(false); }}
                style={{ width: 22, height: 22, background: 'transparent', border: 'none',
                  cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  borderRadius: '50%', color: msg.pinned ? '#4d82c0' : '#7d8590' }}
                title={msg.pinned ? 'Désépingler' : 'Épingler'}
                onMouseEnter={ev => ev.currentTarget.style.background = '#21303f'}
                onMouseLeave={ev => ev.currentTarget.style.background = 'transparent'}
              ><Pin size={12} /></button>
            )}
            
            {isOwn && (
              <button onClick={() => onDelete(msg.id)}
                style={{ width: 22, height: 22, background: 'transparent', border: 'none',
                  cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  borderRadius: '50%', color: '#7d8590' }}
                title="Supprimer"
                onMouseEnter={ev => ev.currentTarget.style.background = '#21303f'}
                onMouseLeave={ev => ev.currentTarget.style.background = 'transparent'}
              ><Trash2 size={11} /></button>
            )}
          </div>
        )}

        <div
          onMouseEnter={() => setShowTimestamp(true)}
          onMouseLeave={() => setShowTimestamp(false)}
          style={{
            background: msg.pinned ? '#1a2535' : (isOwn ? (ownColor || '#1c6ef2') : '#21303f'),
            borderRadius: isOwn ? '18px 18px 4px 18px' : '18px 18px 18px 4px',
            padding: '8px 12px', fontSize: 15,
            color: isOwn ? '#fff' : '#e6edf3',
            lineHeight: 1.5, wordBreak: 'break-word', whiteSpace: 'pre-wrap',
            border: msg.pinned ? '1px solid #2d4a5e' : 'none',
            position: 'relative',
          }}
        >
          {renderContent(displayContent)}
          
          {showTimestamp && (
            <span style={{
              position: 'absolute', bottom: -16,
              ...(isOwn ? { right: 4 } : { left: 4 }),
              fontSize: 9, color: '#4d5460', whiteSpace: 'nowrap',
              background: '#0d1117', padding: '1px 4px', borderRadius: 3,
              pointerEvents: 'none',
            }}>
              {fmtTime(msg.created_at)}
            </span>
          )}
        </div>

        {reactionMap && reactionMap.size > 0 && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, marginTop: 5,
            justifyContent: isOwn ? 'flex-end' : 'flex-start' }}>
            {[...reactionMap.entries()].map(([emoji, users]) => (
              <button key={emoji} onClick={() => onReact(msg.id, emoji)}
                title={[...users].join(', ')}
                style={{
                  fontSize: 12, padding: '2px 6px', borderRadius: 12, cursor: 'pointer',
                  background: users.has(currentUserId) ? '#1c6ef225' : '#21303f',
                  border: `1px solid ${users.has(currentUserId) ? '#1c6ef260' : '#30363d'}`,
                  color: '#e6edf3', display: 'flex', alignItems: 'center', gap: 3,
                  transition: 'all 0.1s',
                }}>
                {emoji} <span style={{ fontSize: 10, color: '#7d8590' }}>{users.size}</span>
              </button>
            ))}
          </div>
        )}
      </div>

      {isOwn && <div style={{ width: 28, flexShrink: 0 }} />}
    </div>
  );
}

export default function CaseChatPanel({ caseId, socket, currentUser, presenceUsers = [], hidden = false }) {
  const { prefs } = usePreferences();
  const [open, setOpen]     = useState(false);
  const [messages, setMsgs] = useState([]);
  const [hasMore, setHasMore] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [loading, setLoading]   = useState(false);
  const [input, setInput]       = useState('');
  const [draft, setDraft]       = useState(null);
  const [unread, setUnread]     = useState(0);
  const [isAtBottom, setIsAtBottom] = useState(true);
  const [pinned, setPinned]     = useState(null);
  const [replyTo, setReplyTo]   = useState(null);
  const [showSearch, setShowSearch] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [showEmojiPicker, setShowEmojiPicker] = useState(false);
  const [mentionDropdown, setMentionDropdown] = useState({ show: false, users: [], start: 0 });
  const [allUsers, setAllUsers] = useState([]);
  const [pinging, setPinging]   = useState(false);
  const [pingDone, setPingDone] = useState(false);
  const [pingingUser, setPingingUser] = useState(null);
  const [soundEnabled, setSoundEnabled] = useState(
    () => localStorage.getItem('fl_chat_sound') !== '0'
  );
  const [panelHeight, setPanelHeight] = useState(
    () => parseInt(localStorage.getItem('fl_chat_height') || '500')
  );
  const { position: panelPos, getDragHandleProps } = useDraggable('fl_chat_pos');
  const [fullscreen, setFullscreen] = useState(false);

  const [chatMode, setChatMode]       = useState('team');
  const [aiMessages, setAiMessages]   = useState([]);
  const [aiInput, setAiInput]         = useState('');
  const [aiStreaming, setAiStreaming]  = useState(false);
  const aiEndRef                      = useRef(null);

  const [reactionsMap, setReactionsMap] = useState(new Map());

  const bottomRef     = useRef(null);
  const msgsElRef     = useRef(null);
  const textareaRef   = useRef(null);
  const emojiPickerRef = useRef(null);
  const typingDebRef  = useRef(null);
  const dragRef       = useRef({ active: false, startY: 0, startH: 0 });
  const pendingDragY  = useRef(null);
  const rafRef        = useRef(null);

  const userId = currentUser?.id ?? (() => {
    try { return JSON.parse(localStorage.getItem('heimdall_user'))?.id; }
    catch { return null; }
  })();

  const onDragStart = (e) => {
    dragRef.current = { active: true, startY: e.clientY, startH: panelHeight };
    document.addEventListener('mousemove', onDrag);
    document.addEventListener('mouseup', onDragEnd);
    e.preventDefault();
  };
  const onDrag = useCallback((e) => {
    if (!dragRef.current.active) return;
    pendingDragY.current = e.clientY;
    if (rafRef.current) return;
    rafRef.current = requestAnimationFrame(() => {
      rafRef.current = null;
      const diff = dragRef.current.startY - pendingDragY.current;
      const h = Math.max(300, Math.min(window.innerHeight * 0.85, dragRef.current.startH + diff));
      setPanelHeight(h);
    });
  }, []);
  const onDragEnd = useCallback(() => {
    dragRef.current.active = false;
    document.removeEventListener('mousemove', onDrag);
    document.removeEventListener('mouseup', onDragEnd);
    if (rafRef.current) { cancelAnimationFrame(rafRef.current); rafRef.current = null; }
    setPanelHeight(h => { localStorage.setItem('fl_chat_height', h); return h; });
  }, [onDrag]);

  useEffect(() => () => {
    document.removeEventListener('mousemove', onDrag);
    document.removeEventListener('mouseup', onDragEnd);
    if (rafRef.current) cancelAnimationFrame(rafRef.current);
  }, [onDrag, onDragEnd]);

  useEffect(() => {
    api.get('/users').then(r => setAllUsers(r.data || [])).catch(() => {});
  }, []);

  const mergeReactions = useCallback((msgId, reactions) => {
    setReactionsMap(prev => {
      const next = new Map(prev);
      next.set(msgId, buildReactMap(reactions));
      return next;
    });
  }, []);

  const toggleReactionLocal = useCallback((msgId, emoji, uid, added) => {
    setReactionsMap(prev => {
      const next = new Map(prev);
      if (!next.has(msgId)) next.set(msgId, new Map());
      const em = new Map(next.get(msgId));
      if (!em.has(emoji)) em.set(emoji, new Set());
      const us = new Set(em.get(emoji));
      if (added) us.add(uid); else { us.delete(uid); if (!us.size) em.delete(emoji); }
      em.set(emoji, us);
      next.set(msgId, em);
      return next;
    });
  }, []);

  useEffect(() => {
    if (!open || !caseId) return;
    setLoading(true);
    Promise.all([
      api.get(`/chat/${caseId}/history?limit=50`),
      api.get(`/chat/${caseId}/pinned`),
    ]).then(([histRes, pinnedRes]) => {
      const { messages: msgs, has_more } = histRes.data;
      setMsgs(msgs);
      setHasMore(has_more);
      setUnread(0);
      setIsAtBottom(true);

      const rm = new Map();
      for (const m of msgs) {
        if (m.reactions?.length) rm.set(m.id, buildReactMap(m.reactions));
      }
      setReactionsMap(rm);
      setPinned(pinnedRes.data || null);
    }).catch(() => {}).finally(() => setLoading(false));
  }, [open, caseId]);

  const loadMore = useCallback(async () => {
    if (!hasMore || loadingMore || !messages.length) return;
    const oldest = messages[0];
    setLoadingMore(true);
    try {
      const res = await api.get(`/chat/${caseId}/history?limit=50&before_id=${oldest.id}`);
      const { messages: older, has_more } = res.data;
      setHasMore(has_more);

      const el = msgsElRef.current;
      const prevScrollHeight = el?.scrollHeight || 0;
      setMsgs(prev => [...older, ...prev]);

      requestAnimationFrame(() => {
        if (el) el.scrollTop = el.scrollHeight - prevScrollHeight;
      });

      const rm = new Map();
      for (const m of older) {
        if (m.reactions?.length) rm.set(m.id, buildReactMap(m.reactions));
      }
      setReactionsMap(prev => new Map([...rm, ...prev]));
    } catch (_e) {}
    setLoadingMore(false);
  }, [hasMore, loadingMore, messages, caseId]);

  useEffect(() => {
    if (!socket) return;
    const handler = (msg) => {
      if (msg.case_id !== caseId) return;
      setMsgs(prev => [...prev, msg]);
      if (!open) setUnread(n => n + 1);
    };
    socket.on('chat:message', handler);
    return () => socket.off('chat:message', handler);
  }, [socket, caseId, open]);

  useEffect(() => {
    if (!socket) return;
    const handler = ({ messageId, emoji, userId: uid, added }) => {
      if (uid === userId) return;
      toggleReactionLocal(messageId, emoji, uid, added !== false);
    };
    socket.on('chat:react', handler);
    return () => socket.off('chat:react', handler);
  }, [socket, userId, toggleReactionLocal]);

  useEffect(() => {
    if (!socket) return;
    const handler = async ({ case_id, pinned: nowPinned }) => {
      if (case_id !== caseId) return;
      if (nowPinned) {
        const res = await api.get(`/chat/${caseId}/pinned`).catch(() => null);
        setPinned(res?.data || null);
      } else {
        setPinned(null);
      }

      setMsgs(prev => prev.map(m =>
        nowPinned ? { ...m, pinned: m.id === nowPinned } : { ...m, pinned: false }
      ));
    };
    socket.on('chat:pin', handler);
    return () => socket.off('chat:pin', handler);
  }, [socket, caseId]);

  useEffect(() => {
    if (!socket) return;
    const handler = (data) => {
      if (data.case_id !== caseId) return;
      if (!open) setUnread(n => n + 1);
      if (soundEnabled) playPing();
      setMsgs(prev => [...prev, {
        id: `ping-${Date.now()}`, case_id: caseId, is_ping: true,
        content: `🔔 Ping de ${data.from_full_name || data.from_user} : ${data.message}`,
        created_at: data.sent_at || new Date().toISOString(),
        author_id: null, username: data.from_user, reactions: [],
      }]);
    };
    socket.on('case:ping', handler);
    return () => socket.off('case:ping', handler);
  }, [socket, caseId, open, soundEnabled]);

  useEffect(() => {
    if (!socket) return;
    const handler = (data) => {
      if (data.case_id !== caseId) return;
      if (soundEnabled) playPing();
    };
    socket.on('chat:mention', handler);
    return () => socket.off('chat:mention', handler);
  }, [socket, caseId, soundEnabled]);

  useEffect(() => {
    if (!open || !isAtBottom) return;
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, open]);

  const handleScroll = (e) => {
    const el = e.currentTarget;
    setIsAtBottom(el.scrollHeight - el.scrollTop - el.clientHeight < 60);
  };

  const [othersTyping, setOthersTyping] = useState([]);
  useEffect(() => {
    if (!socket) return;
    const handler = ({ userId: uid, username }) => {
      if (uid === userId) return;
      setOthersTyping(prev => prev.find(u => u.userId === uid) ? prev : [...prev, { userId: uid, username }]);
      setTimeout(() => setOthersTyping(prev => prev.filter(u => u.userId !== uid)), 3000);
    };
    socket.on('chat:typing', handler);
    return () => socket.off('chat:typing', handler);
  }, [socket, userId]);

  const emitTyping = useCallback(() => {
    if (!socket || typingDebRef.current) return;
    socket.emit('chat:typing', { caseId, userId, username: currentUser?.username });
    typingDebRef.current = setTimeout(() => { typingDebRef.current = null; }, 2000);
  }, [socket, caseId, userId, currentUser]);

  const send = useCallback(() => {
    const text = (draft != null ? draft : input).trim();
    if (!text || !socket) return;
    socket.emit('chat:send', { caseId, content: text, reply_to_id: replyTo?.id || null });
    setInput('');
    setDraft(null);
    setReplyTo(null);
    setIsAtBottom(true);
    setTimeout(() => bottomRef.current?.scrollIntoView({ behavior: 'smooth' }), 50);
  }, [input, draft, socket, caseId, replyTo]);

  const handleReact = useCallback(async (messageId, emoji) => {

    const currentlyHas = reactionsMap.get(messageId)?.get(emoji)?.has(userId);
    const added = !currentlyHas;
    toggleReactionLocal(messageId, emoji, userId, added);

    try {
      await api.post(`/chat/${caseId}/${messageId}/react`, { emoji });
    } catch (_e) {
      toggleReactionLocal(messageId, emoji, userId, !added);
      return;
    }

    if (socket) socket.emit('chat:react', { caseId, messageId, emoji, userId, added });
  }, [reactionsMap, userId, socket, caseId, toggleReactionLocal]);

  const handlePin = useCallback(async (messageId) => {
    try {
      const res = await api.post(`/chat/${caseId}/${messageId}/pin`);
      if (res.data.pinned) {
        const pr = await api.get(`/chat/${caseId}/pinned`);
        setPinned(pr.data || null);
      } else {
        setPinned(null);
      }
      setMsgs(prev => prev.map(m => ({ ...m, pinned: res.data.pinned && m.id === messageId })));
    } catch (_e) {}
  }, [caseId]);

  useEffect(() => {
    if (!showEmojiPicker) return;
    const handler = (e) => {
      if (emojiPickerRef.current && !emojiPickerRef.current.contains(e.target)) {
        setShowEmojiPicker(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [showEmojiPicker]);

  const insertEmoji = useCallback((emoji) => {
    const el = textareaRef.current;
    const start = el?.selectionStart ?? input.length;
    const end   = el?.selectionEnd   ?? input.length;
    const val   = draft != null ? draft : input;
    const next  = val.slice(0, start) + emoji + val.slice(end);
    draft != null ? setDraft(next) : setInput(next);
    setShowEmojiPicker(false);
    requestAnimationFrame(() => {
      el?.focus();
      el?.setSelectionRange(start + emoji.length, start + emoji.length);
    });
  }, [input, draft]);

  const handleInputChange = useCallback((e) => {
    const val = e.target.value;
    setInput(val);
    emitTyping();

    const cursor = e.target.selectionStart;
    const before = val.slice(0, cursor);
    const mMatch = before.match(/@(\w*)$/);
    if (mMatch) {
      const q = mMatch[1].toLowerCase();

      const pool = allUsers.length > 0 ? allUsers : presenceUsers;
      const filtered = pool.filter(u =>
        u.id !== userId &&
        (u.username.toLowerCase().includes(q) || (u.full_name || '').toLowerCase().includes(q))
      ).slice(0, 8);
      if (filtered.length) {
        setMentionDropdown({ show: true, users: filtered, start: cursor - mMatch[0].length });
        return;
      }
    }
    setMentionDropdown({ show: false, users: [], start: 0 });
  }, [emitTyping, allUsers, presenceUsers, userId]);

  const insertMention = useCallback((user) => {
    const el = textareaRef.current;
    const { start } = mentionDropdown;
    const after = input.slice(el?.selectionStart ?? input.length);
    const next = input.slice(0, start) + '@' + user.username + ' ' + after;
    setInput(next);
    setMentionDropdown({ show: false, users: [], start: 0 });
    requestAnimationFrame(() => {
      el?.focus();
      const pos = start + user.username.length + 2;
      el?.setSelectionRange(pos, pos);
    });
  }, [input, mentionDropdown]);

  const deleteMsg = useCallback(async (id) => {
    try {
      await api.delete(`/chat/${caseId}/${id}`);
      setMsgs(prev => prev.filter(m => m.id !== id));
    } catch (_e) {}
  }, [caseId]);

  const sendPing = useCallback(async (targetUserId = null) => {
    if (pinging) return;
    setPinging(true);
    if (targetUserId) setPingingUser(targetUserId);
    try {
      const body = { message: 'Ping !' };
      if (targetUserId) body.target_user_id = targetUserId;
      await api.post(`/chat/${caseId}/ping`, body);
      setPingDone(true);
      if (soundEnabled) playPing();
      setTimeout(() => { setPingDone(false); setPingingUser(null); }, 2500);
    } catch (_e) {}
    setPinging(false);
  }, [caseId, pinging, soundEnabled]);

  useEffect(() => {
    const handler = (e) => {
      const { timestamp, artifact_type, description } = e.detail || {};
      const ts = timestamp
        ? new Date(timestamp).toISOString().slice(0, 19).replace('T', ' ')
        : '';
      setDraft(`🔗 [${artifact_type || '?'}] ${ts}\n${description || ''}`);
      setOpen(true);
      setTimeout(() => textareaRef.current?.focus(), 80);
    };
    window.addEventListener('forensic:shareToChat', handler);
    return () => window.removeEventListener('forensic:shareToChat', handler);
  }, []);

  const scrollToMsg = useCallback((msgId) => {
    const el = document.getElementById(`msg-${msgId}`);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      el.style.outline = '2px solid #4d82c060';
      setTimeout(() => { el.style.outline = 'none'; }, 1500);
    }
  }, []);

  const filtered = searchQuery
    ? messages.filter(m => (m.content || '').toLowerCase().includes(searchQuery.toLowerCase()))
    : messages;

  const items = [];
  let lastDay = null;
  for (let i = 0; i < filtered.length; i++) {
    const msg = filtered[i];
    const day = fmtDate(msg.created_at);
    if (day !== lastDay) { items.push({ type: 'sep', day }); lastDay = day; }
    const prev = filtered[i - 1];
    const hideHeader = !msg.is_ping && prev && !prev.is_ping &&
      prev.author_id === msg.author_id &&
      new Date(msg.created_at) - new Date(prev.created_at) < 2 * 60 * 1000;
    items.push({ type: 'msg', msg, hideHeader: !!hideHeader });
  }

  const activeInput = draft != null ? draft : input;
  const canSend = !!activeInput.trim();

  const sendAI = useCallback(async () => {
    const msg = aiInput.trim();
    if (!msg || aiStreaming) return;
    setAiInput('');
    const now = new Date().toISOString();
    setAiMessages(prev => [
      ...prev,
      { role: 'user',      content: msg, created_at: now },
      { role: 'assistant', content: '', loading: true, created_at: now },
    ]);
    setAiStreaming(true);
    try {
      const token = localStorage.getItem('heimdall_token');
      const res = await fetch(`/api/cases/${caseId}/ai/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ message: msg }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
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
            const parsed = JSON.parse(data);
            if (parsed.response) {
              setAiMessages(prev => {
                const arr = [...prev];
                arr[arr.length - 1] = { ...arr[arr.length - 1], content: arr[arr.length - 1].content + parsed.response, loading: false };
                return arr;
              });
            }
          } catch (_e) {}
        }
      }
    } catch {
      setAiMessages(prev => {
        const arr = [...prev];
        arr[arr.length - 1] = { ...arr[arr.length - 1], content: 'Erreur de connexion IA.', loading: false };
        return arr;
      });
    } finally {
      setAiStreaming(false);
      setTimeout(() => aiEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 50);
    }
  }, [aiInput, aiStreaming, caseId]);

  if (hidden) return null;
  return (
    <>
      <style>{GLOBAL_STYLE}</style>

      <button
        onClick={() => { setOpen(o => !o); if (!open) setUnread(0); }}
        title={chatMode === 'ai' ? 'Chat IA' : 'Chat équipe'}
        style={{
          position: 'fixed', bottom: 24, right: 24, zIndex: 1000,
          width: 48, height: 48, borderRadius: '50%',
          background: chatMode === 'ai' ? '#8b5cf6' : '#4d82c0',
          border: 'none', cursor: 'pointer',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: '0 4px 16px rgba(0,0,0,0.4)',
          transition: 'transform 0.15s',
        }}
        onMouseEnter={e => e.currentTarget.style.transform = 'scale(1.08)'}
        onMouseLeave={e => e.currentTarget.style.transform = 'scale(1)'}
      >
        {open ? <X size={20} color="#fff" /> : chatMode === 'ai' ? <Bot size={20} color="#fff" /> : <MessageSquare size={20} color="#fff" />}
        {!open && unread > 0 && (
          <span style={{
            position: 'absolute', top: 0, right: 0,
            background: '#da3633', color: '#fff', borderRadius: '50%',
            width: 18, height: 18, fontSize: 10, fontWeight: 700,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            border: '2px solid #0d1117',
          }}>
            {unread > 9 ? '9+' : unread}
          </span>
        )}
      </button>

      {open && (
        <div style={{
          position: 'fixed',
          ...(!fullscreen && panelPos?.x != null
            ? { left: panelPos.x, top: panelPos.y }
            : { bottom: fullscreen ? 0 : 24, right: fullscreen ? 0 : 24 }),
          ...(fullscreen
            ? { width: '100vw', height: '100vh', border: 'none', borderRadius: 0 }
            : { width: PANEL_WIDTH, height: panelHeight, border: '1px solid #30363d', borderRadius: 12 }),
          zIndex: 999,
          background: '#161b22', boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
          display: 'flex', flexDirection: 'column', overflow: 'hidden',
          animation: 'fl-fadein 0.15s ease',
        }}>

          {!fullscreen && (
            <div
              onMouseDown={onDragStart}
              style={{
                height: 6, cursor: 'ns-resize', flexShrink: 0,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: 'transparent',
              }}
            >
              <div style={{ width: 32, height: 3, borderRadius: 2, background: '#30363d' }} />
            </div>
          )}

          <div style={{
            padding: '6px 12px 8px', display: 'flex', alignItems: 'center', gap: 6,
            borderBottom: '1px solid #21262d', flexShrink: 0,
          }}>
            {chatMode === 'ai' ? <Bot size={13} color="#8b5cf6" /> : <MessageSquare size={13} color="#4d82c0" />}
            <span
              onMouseDown={getDragHandleProps(PANEL_WIDTH, panelHeight).onMouseDown}
              style={{ cursor: 'grab', fontWeight: 600, fontSize: 13, color: chatMode === 'ai' ? '#8b5cf6' : '#c9d1d9', flex: 1, userSelect: 'none' }}
            >
              {chatMode === 'ai' ? 'Chat IA' : 'Chat'}
            </span>

            {presenceUsers.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center' }}>
                {presenceUsers.slice(0, 4).map((u, i) => (
                  <div key={u.id || i} title={u.full_name || u.username} style={{
                    width: 22, height: 22, borderRadius: '50%', flexShrink: 0,
                    background: avatarColor(u.username || ''),
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 9, fontWeight: 700, color: '#fff',
                    border: '2px solid #161b22',
                    marginLeft: i > 0 ? -6 : 0,
                    cursor: 'default',
                  }}>
                    {initials(u.full_name || u.username)}
                  </div>
                ))}
                {presenceUsers.length > 4 && (
                  <div style={{
                    width: 22, height: 22, borderRadius: '50%',
                    background: '#21303f', border: '2px solid #161b22',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 9, color: '#7d8590', marginLeft: -6,
                  }}>+{presenceUsers.length - 4}</div>
                )}
              </div>
            )}

            <button
              onClick={() => sendPing()}
              disabled={pinging}
              title="Pinger tous les analystes du cas"
              style={{
                background: pingDone && !pingingUser ? '#3fb95015' : 'none',
                border: `1px solid ${pingDone && !pingingUser ? '#3fb95030' : '#21262d'}`,
                borderRadius: 4, cursor: pinging ? 'default' : 'pointer',
                padding: '2px 6px', display: 'flex', alignItems: 'center', gap: 3,
                color: pingDone && !pingingUser ? '#3fb950' : '#c89d1d',
                fontSize: 10, fontFamily: 'monospace',
              }}
            >
              <Bell size={10} />
              {pingDone && !pingingUser ? '✓' : 'Ping'}
            </button>

            <button
              onClick={() => setChatMode(m => m === 'team' ? 'ai' : 'team')}
              title={chatMode === 'ai' ? 'Passer au chat équipe' : 'Passer au chat IA'}
              style={{
                background: chatMode === 'ai' ? '#8b5cf618' : 'none',
                border: chatMode === 'ai' ? '1px solid #8b5cf635' : '1px solid transparent',
                borderRadius: 4, cursor: 'pointer',
                color: chatMode === 'ai' ? '#8b5cf6' : '#7d8590',
                padding: '2px 5px', display: 'flex', alignItems: 'center',
              }}
            >
              <Bot size={13} />
            </button>

            <button
              onClick={() => {
                const next = !soundEnabled;
                setSoundEnabled(next);
                localStorage.setItem('fl_chat_sound', next ? '1' : '0');
              }}
              title={soundEnabled ? 'Désactiver les sons' : 'Activer les sons'}
              style={{ background: 'none', border: 'none', cursor: 'pointer',
                color: soundEnabled ? '#4d82c0' : '#4d5460', padding: 0 }}
            >
              {soundEnabled ? <Volume2 size={13} /> : <VolumeX size={13} />}
            </button>

            <button
              onClick={() => { setShowSearch(s => !s); if (showSearch) setSearchQuery(''); }}
              title="Rechercher dans le chat"
              style={{ background: 'none', border: 'none', cursor: 'pointer',
                color: showSearch ? '#4d82c0' : '#7d8590', padding: 0 }}
            >
              <Search size={13} />
            </button>

            <button
              onClick={() => setFullscreen(f => !f)}
              title={fullscreen ? 'Réduire' : 'Plein écran'}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: fullscreen ? '#4d82c0' : '#7d8590', padding: 0 }}
            >
              {fullscreen ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
            </button>

            <button onClick={() => setOpen(false)}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#8b949e', padding: 0 }}>
              <X size={14} />
            </button>
          </div>

          {chatMode === 'ai' && (
            <>
              <div style={{ flex: 1, overflowY: 'auto', padding: '8px 10px 4px', scrollbarWidth: 'thin' }}>
                {aiMessages.length === 0 && (
                  <div style={{ textAlign: 'center', color: '#4d5460', fontSize: 14, marginTop: 40 }}>
                    <Bot size={28} style={{ color: '#8b5cf630', marginBottom: 8 }} />
                    <div>Posez une question à l'IA sur ce cas</div>
                  </div>
                )}
                {aiMessages.map((m, i) => (
                  <div key={i} style={{
                    display: 'flex', flexDirection: 'column',
                    alignItems: m.role === 'user' ? 'flex-end' : 'flex-start',
                    marginBottom: 10,
                  }}>
                    <div style={{
                      maxWidth: '85%', padding: '7px 11px', borderRadius: 10,
                      fontSize: 14, lineHeight: 1.6, fontFamily: 'monospace',
                      background: m.role === 'user' ? '#4d82c018' : '#8b5cf615',
                      color: m.role === 'user' ? '#c9d1d9' : '#c0b0f0',
                      border: `1px solid ${m.role === 'user' ? '#4d82c030' : '#8b5cf630'}`,
                      whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                    }}>
                      {m.loading
                        ? <span style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                            <span style={{ animation: 'fl-bounce 1.4s infinite', animationDelay: '0s', display: 'inline-block', width: 5, height: 5, borderRadius: '50%', background: '#8b5cf6' }} />
                            <span style={{ animation: 'fl-bounce 1.4s infinite', animationDelay: '0.2s', display: 'inline-block', width: 5, height: 5, borderRadius: '50%', background: '#8b5cf6' }} />
                            <span style={{ animation: 'fl-bounce 1.4s infinite', animationDelay: '0.4s', display: 'inline-block', width: 5, height: 5, borderRadius: '50%', background: '#8b5cf6' }} />
                          </span>
                        : m.content}
                    </div>
                  </div>
                ))}
                <div ref={aiEndRef} />
              </div>
              <div style={{ padding: '8px 10px', borderTop: '1px solid #21262d', display: 'flex', gap: 6, alignItems: 'flex-end', flexShrink: 0 }}>
                <textarea
                  value={aiInput}
                  onChange={e => setAiInput(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendAI(); } }}
                  placeholder="Demander à l'IA…"
                  rows={2}
                  style={{
                    flex: 1, resize: 'none', background: '#0d1117', outline: 'none',
                    border: '1px solid #8b5cf630', borderRadius: 8,
                    color: '#c9d1d9', fontSize: 14, padding: '6px 10px', fontFamily: 'inherit',
                  }}
                />
                <button
                  onClick={sendAI}
                  disabled={!aiInput.trim() || aiStreaming}
                  style={{
                    background: aiInput.trim() && !aiStreaming ? '#8b5cf6' : '#21262d',
                    border: 'none', borderRadius: 8, padding: '8px 10px', cursor: 'pointer',
                    display: 'flex', alignItems: 'center', color: '#fff', flexShrink: 0,
                  }}
                >
                  {aiStreaming
                    ? <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} />
                    : <Send size={14} />}
                </button>
              </div>
            </>
          )}

          
          {chatMode === 'team' && <>

          
          {presenceUsers.length > 0 && (
            <div style={{
              padding: '4px 12px', display: 'flex', alignItems: 'center', gap: 8,
              borderBottom: '1px solid #1a2030', flexShrink: 0, flexWrap: 'wrap',
            }}>
              <span style={{ fontSize: 10, color: '#4d5460', fontFamily: 'monospace' }}>En ligne :</span>
              {presenceUsers.filter(u => u.id !== userId).map((u, i) => (
                <button
                  key={u.id || i}
                  onClick={() => sendPing(u.id)}
                  disabled={pinging}
                  title={`Pinger ${u.full_name || u.username}`}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 4,
                    background: pingingUser === u.id && pingDone ? '#3fb95015' : '#1a2535',
                    border: `1px solid ${pingingUser === u.id && pingDone ? '#3fb95030' : '#21262d'}`,
                    borderRadius: 12, padding: '1px 7px 1px 4px',
                    cursor: pinging ? 'default' : 'pointer', fontSize: 10,
                    color: pingingUser === u.id && pingDone ? '#3fb950' : '#c9d1d9',
                  }}
                >
                  <div style={{
                    width: 6, height: 6, borderRadius: '50%',
                    background: '#3fb950', boxShadow: '0 0 4px #3fb95080',
                  }} />
                  {u.username}
                  <Bell size={8} style={{ color: pingingUser === u.id && pingDone ? '#3fb950' : '#c89d1d' }} />
                </button>
              ))}
            </div>
          )}

          
          {showSearch && (
            <div style={{ padding: '6px 12px', borderBottom: '1px solid #1a2030', flexShrink: 0 }}>
              <div style={{ position: 'relative' }}>
                <Search size={12} style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', color: '#4d5460' }} />
                <input
                  autoFocus
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  placeholder="Rechercher…"
                  style={{
                    width: '100%', background: '#0d1117', border: '1px solid #30363d',
                    borderRadius: 6, padding: '4px 8px 4px 26px',
                    color: '#c9d1d9', fontSize: 12, outline: 'none', boxSizing: 'border-box',
                  }}
                />
                {searchQuery && (
                  <span style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)',
                    fontSize: 10, color: '#4d5460' }}>
                    {filtered.length} résultat{filtered.length !== 1 ? 's' : ''}
                  </span>
                )}
              </div>
            </div>
          )}

          
          <PinBanner
            pinned={pinned}
            canPin
            onUnpin={() => pinned && handlePin(pinned.id)}
            onScrollTo={() => pinned && scrollToMsg(pinned.id)}
          />

          
          <div style={{ flex: 1, position: 'relative', minHeight: 0 }}>
            <div
              ref={msgsElRef}
              onScroll={handleScroll}
              style={{ height: '100%', overflowY: 'auto', padding: '8px 10px 4px', scrollbarWidth: 'thin' }}
            >
              
              {hasMore && (
                <div style={{ textAlign: 'center', padding: '4px 0 8px' }}>
                  <button
                    onClick={loadMore}
                    disabled={loadingMore}
                    style={{
                      background: '#21303f', border: '1px solid #30363d', borderRadius: 6,
                      padding: '3px 12px', fontSize: 11, color: '#7d8590', cursor: 'pointer',
                    }}
                  >
                    {loadingMore
                      ? <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} />
                      : 'Charger plus'}
                  </button>
                </div>
              )}

              {loading && (
                <div style={{ display: 'flex', justifyContent: 'center', marginTop: 40 }}>
                  <Loader2 size={20} color="#4d82c0" style={{ animation: 'spin 1s linear infinite' }} />
                </div>
              )}

              {!loading && messages.length === 0 && (
                <div style={{ textAlign: 'center', color: '#4d5460', fontSize: 12, marginTop: 40 }}>
                  Aucun message — commencez la discussion !
                </div>
              )}

              {!loading && searchQuery && filtered.length === 0 && (
                <div style={{ textAlign: 'center', color: '#4d5460', fontSize: 12, marginTop: 20 }}>
                  Aucun résultat pour « {searchQuery} »
                </div>
              )}

              {!loading && items.map((item, i) =>
                item.type === 'sep'
                  ? <DaySep key={`sep-${i}`} date={item.day} />
                  : <Bubble
                      key={item.msg.id}
                      msg={item.msg}
                      currentUserId={userId}
                      onDelete={deleteMsg}
                      onReact={handleReact}
                      onPin={handlePin}
                      onReply={setReplyTo}
                      onScrollTo={scrollToMsg}
                      hideHeader={item.hideHeader}
                      reactionMap={reactionsMap.get(item.msg.id)}
                      canPin
                      searchQuery={searchQuery}
                      ownColor={prefs.chat_color}
                    />
              )}
              <div ref={bottomRef} />
            </div>

            
            {!isAtBottom && (
              <button
                onClick={() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); setIsAtBottom(true); }}
                title="Aller en bas"
                style={{
                  position: 'absolute', bottom: 8, right: 12,
                  width: 28, height: 28, borderRadius: '50%',
                  background: '#21303f', border: '1px solid #30363d',
                  cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  color: '#7d8590', boxShadow: '0 2px 8px rgba(0,0,0,0.4)', zIndex: 10,
                }}
              >
                <ChevronDown size={14} />
                {unread > 0 && (
                  <span style={{
                    position: 'absolute', top: -4, right: -4,
                    background: '#da3633', color: '#fff', borderRadius: '50%',
                    width: 14, height: 14, fontSize: 9, fontWeight: 700,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>{unread}</span>
                )}
              </button>
            )}
          </div>

          
          {othersTyping.length > 0 && (
            <div style={{ padding: '3px 12px', fontSize: 11, color: '#7d8590',
              fontStyle: 'italic', display: 'flex', alignItems: 'center', flexShrink: 0 }}>
              {othersTyping.map(u => u.username).join(', ')} écrit…
              <span style={{ display: 'inline-flex', gap: 2, marginLeft: 6 }}>
                {[0, 1, 2].map(i => (
                  <span key={i} style={{
                    width: 4, height: 4, borderRadius: '50%', background: '#7d8590',
                    display: 'inline-block',
                    animation: `fl-bounce 1.2s ease-in-out ${i * 0.2}s infinite`,
                  }} />
                ))}
              </span>
            </div>
          )}

          
          {draft != null && (
            <div style={{
              margin: '0 10px 4px', padding: '5px 10px',
              background: '#1c2c3c', borderLeft: '3px solid #4d82c0',
              borderRadius: 4, fontSize: 11, color: '#e6edf3',
              whiteSpace: 'pre-wrap', position: 'relative', flexShrink: 0,
            }}>
              {draft}
              <button onClick={() => setDraft(null)}
                style={{ position: 'absolute', top: 4, right: 6, background: 'none',
                  border: 'none', color: '#7d8590', cursor: 'pointer', fontSize: 11 }}>
                ✕
              </button>
            </div>
          )}

          
          <ReplyBar replyTo={replyTo} onClear={() => setReplyTo(null)} />

          
          <div style={{
            padding: '8px 10px', borderTop: '1px solid #21262d',
            display: 'flex', gap: 6, alignItems: 'flex-end', flexShrink: 0,
            position: 'relative',
          }}>
            
            {mentionDropdown.show && (
              <div style={{ position: 'absolute', bottom: '100%', left: 10, right: 50 }}>
                <MentionDropdown
                  users={mentionDropdown.users}
                  onSelect={insertMention}
                  onlineIds={new Set(presenceUsers.map(u => u.id))}
                />
              </div>
            )}

            <textarea
              ref={textareaRef}
              value={activeInput}
              onChange={draft != null
                ? e => setDraft(e.target.value)
                : handleInputChange
              }
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
                if (e.key === 'Escape' && mentionDropdown.show) {
                  setMentionDropdown({ show: false, users: [], start: 0 });
                }
                if (e.key === 'Escape' && replyTo) setReplyTo(null);
              }}
              placeholder={replyTo ? `Répondre à ${replyTo.username}…` : 'Message… (Entrée pour envoyer)'}
              rows={2}
              style={{
                flex: 1, resize: 'none', background: '#0d1117', outline: 'none',
                border: `1px solid ${draft != null ? '#4d82c0' : replyTo ? '#4d82c060' : '#30363d'}`,
                borderRadius: 8, color: '#c9d1d9', fontSize: 14,
                padding: '6px 10px', fontFamily: 'inherit',
              }}
            />

            
            <div ref={emojiPickerRef} style={{ position: 'relative', flexShrink: 0 }}>
              <button
                onClick={() => setShowEmojiPicker(p => !p)}
                title="Insérer un emoji"
                style={{ background: 'none', border: 'none', cursor: 'pointer',
                  fontSize: 16, padding: 2, lineHeight: 1 }}
              >
                😊
              </button>
              {showEmojiPicker && (
                <div style={{
                  position: 'absolute', bottom: 'calc(100% + 4px)', right: 0,
                  width: 228, background: '#161b22', border: '1px solid #30363d',
                  borderRadius: 10, padding: 8,
                  display: 'grid', gridTemplateColumns: 'repeat(8, 1fr)', gap: 2,
                  zIndex: 30,
                }}>
                  {EMOJI_GRID.map(emoji => (
                    <button key={emoji} onClick={() => insertEmoji(emoji)}
                      style={{
                        width: 28, height: 28, fontSize: 16, background: 'transparent',
                        border: 'none', cursor: 'pointer', borderRadius: 4,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = '#21303f'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >{emoji}</button>
                  ))}
                </div>
              )}
            </div>

            
            <button
              onClick={send}
              disabled={!canSend}
              style={{
                background: canSend ? '#4d82c0' : '#21262d',
                border: 'none', borderRadius: 8, padding: '8px 10px',
                cursor: canSend ? 'pointer' : 'default',
                display: 'flex', alignItems: 'center', color: '#fff',
                flexShrink: 0,
              }}
            >
              <Send size={14} />
            </button>
          </div>

          </> /* end chatMode === 'team' */}
        </div>
      )}
    </>
  );
}
