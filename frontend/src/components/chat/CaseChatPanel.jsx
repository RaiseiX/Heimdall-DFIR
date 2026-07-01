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

function fmtTime(ts, locale = 'en') {
  return new Date(ts).toLocaleTimeString(locale?.startsWith('en') ? 'en-GB' : locale, { hour: '2-digit', minute: '2-digit' });
}
function fmtDate(ts, locale = 'en') {
  return new Date(ts).toLocaleDateString(locale?.startsWith('en') ? 'en-GB' : locale, { day: '2-digit', month: 'short' });
}
function hashCode(s) {
  return Math.abs([...s].reduce((h, c) => Math.imul(31, h) + c.charCodeAt(0) | 0, 0));
}
const AVATAR_COLORS = ['var(--fl-accent)', 'var(--fl-accent)', 'var(--fl-ok)', 'var(--fl-warn)', 'var(--fl-danger)', 'var(--fl-purple)'];
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
  mention: { color: 'var(--fl-accent)', fontWeight: 700, background: 'color-mix(in srgb, var(--fl-accent) 9%, transparent)', borderRadius: 3, padding: '0 3px' },
  sha256:  { color: 'var(--fl-danger)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, background: 'color-mix(in srgb, var(--fl-danger) 9%, transparent)', borderRadius: 3, padding: '0 3px', cursor: 'help' },
  sha1:    { color: 'var(--fl-gold)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, background: 'color-mix(in srgb, var(--fl-gold) 9%, transparent)', borderRadius: 3, padding: '0 3px', cursor: 'help' },
  md5:     { color: 'var(--fl-accent)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, background: 'color-mix(in srgb, var(--fl-accent) 9%, transparent)', borderRadius: 3, padding: '0 3px', cursor: 'help' },
  ipv4:    { color: 'var(--fl-warn)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, background: 'color-mix(in srgb, var(--fl-warn) 9%, transparent)', borderRadius: 3, padding: '0 3px', cursor: 'help' },
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
      background: 'var(--fl-sep)', borderBottom: '1px solid var(--fl-border)',
      padding: '5px 12px', display: 'flex', alignItems: 'center', gap: 8,
      flexShrink: 0,
    }}>
      <Pin size={11} color="var(--fl-accent)" />
      <button
        onClick={onScrollTo}
        style={{ flex: 1, background: 'none', border: 'none', cursor: 'pointer',
          textAlign: 'left', fontSize: 11, color: 'var(--fl-dim)', padding: 0,
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
        title="Go to pinned message"
      >
        <span style={{ color: 'var(--fl-dim)', marginRight: 5 }}>
          {pinned.username} :
        </span>
        {pinned.content}
      </button>
      {canPin && (
        <button onClick={onUnpin} title="Unpin"
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', padding: 0 }}>
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
      padding: '5px 10px', background: 'var(--fl-sep)',
      borderLeft: '2px solid var(--fl-border3)', borderRadius: 4,
      display: 'flex', alignItems: 'center', gap: 8,
    }}>
      <Reply size={10} color="var(--fl-accent)" />
      <div style={{ flex: 1, minWidth: 0 }}>
        <span style={{ fontSize: 10, color: 'var(--fl-accent)', fontWeight: 700 }}>
          {replyTo.full_name || replyTo.username}
        </span>
        <span style={{ fontSize: 11, color: 'var(--fl-dim)', marginLeft: 6,
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'inline-block', maxWidth: 200, verticalAlign: 'bottom' }}>
          {replyTo.content}
        </span>
      </div>
      <button onClick={onClear}
        style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', padding: 0 }}>
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
      background: 'var(--fl-bg)', border: '1px solid color-mix(in srgb, var(--fl-accent) 50%, transparent)', borderRadius: 8,
      marginBottom: 6, overflow: 'hidden', zIndex: 30,
      animation: 'fl-fadein 0.1s ease',
      boxShadow: '0 -4px 16px rgba(0,0,0,0.6)',
    }}>
      <div style={{ padding: '4px 10px 3px', fontSize: 10, color: 'var(--fl-accent)', fontWeight: 600, borderBottom: '1px solid var(--fl-border)' }}>
        Mention an analyst
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
            onMouseEnter={e => e.currentTarget.style.background = 'var(--fl-card)'}
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
                background: online ? 'var(--fl-ok)' : 'var(--fl-muted)',
                border: '1.5px solid var(--fl-bg)',
              }} />
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--fl-text)' }}>
                @{u.username}
              </div>
              {u.full_name && (
                <div style={{ fontSize: 10, color: 'var(--fl-dim)', marginTop: 1 }}>
                  {u.full_name}{online ? ' · online' : ''}
                </div>
              )}
            </div>
            <span style={{
              fontSize: 9, padding: '1px 5px', borderRadius: 3,
              background: u.role === 'admin' ? 'color-mix(in srgb, var(--fl-accent) 13%, transparent)' : 'color-mix(in srgb, var(--fl-accent) 8%, transparent)',
              color: u.role === 'admin' ? 'var(--fl-accent)' : 'var(--fl-accent)',
              border: `1px solid ${u.role === 'admin' ? 'color-mix(in srgb, var(--fl-accent) 19%, transparent)' : 'color-mix(in srgb, var(--fl-accent) 15%, transparent)'}`,
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
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, margin: '14px 0 10px' }}>
      <div style={{ flex: 1, height: 1, background: 'var(--fl-border2)' }} />
      <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-muted)', padding: '2px 9px', borderRadius: 10, background: 'var(--fl-bg)', border: '1px solid var(--fl-border2)' }}>{date}</span>
      <div style={{ flex: 1, height: 1, background: 'var(--fl-border2)' }} />
    </div>
  );
}

function Bubble({ msg, currentUserId, onDelete, onReact, onPin, onReply,
                   hideHeader, groupEnd = true, reactionMap, onScrollTo, canPin, searchQuery, ownColor }) {
  const isOwn = msg.author_id === currentUserId;
  const username = msg.username || msg.full_name || '?';
  // Connected-cluster radius: the corner facing an adjacent same-author message is flattened.
  const grpTop = hideHeader ? 4 : 12;   // a message sits above (continuation) → flat top
  const grpBot = groupEnd ? 12 : 4;     // a message follows in the group → flat bottom
  const bubbleRadius = isOwn ? `12px ${grpTop}px ${grpBot}px 12px` : `${grpTop}px 12px 12px ${grpBot}px`;
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
          background: 'var(--fl-panel)', border: '1px solid var(--fl-border)',
          borderRadius: 8, padding: '4px 10px',
          fontSize: 11, color: 'var(--fl-dim)', fontStyle: 'italic',
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
        marginBottom: groupEnd ? 10 : 2,
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
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginBottom: 3 }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--fl-text)' }}>{msg.full_name || msg.username}</span>
            <span style={{ fontSize: 9.5, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{fmtTime(msg.created_at, locale)}</span>
          </div>
        )}

        {msg.pinned && (
          <div style={{ fontSize: 9, color: 'var(--fl-accent)', display: 'flex', alignItems: 'center', gap: 3, marginBottom: 2 }}>
            <Pin size={9} /> pinned by {msg.pinned_by_username || '?'}
          </div>
        )}

        {msg.reply_to && (
          <button
            onClick={() => onScrollTo(msg.reply_to.id)}
            style={{
              display: 'block', width: '100%', background: 'var(--fl-sep)',
              border: 'none', borderLeft: '2px solid color-mix(in srgb, var(--fl-accent) 38%, transparent)',
              borderRadius: 4, padding: '3px 8px', marginBottom: 3,
              cursor: 'pointer', textAlign: isOwn ? 'right' : 'left',
            }}
          >
            <div style={{ fontSize: 10, color: 'var(--fl-accent)', fontWeight: 600 }}>
              {msg.reply_to.full_name || msg.reply_to.username}
            </div>
            <div style={{ fontSize: 11, color: 'var(--fl-dim)',
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
              background: 'var(--fl-panel)', border: '1px solid var(--fl-border)',
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
                onMouseEnter={ev => ev.currentTarget.style.background = 'var(--fl-panel)'}
                onMouseLeave={ev => ev.currentTarget.style.background = 'transparent'}
              >{e}</button>
            ))}
            
            <div style={{ width: 1, background: 'var(--fl-border)', margin: '2px 2px' }} />
            
            <button onClick={() => { onReply(msg); setShowEmojiBar(false); }}
              style={{ width: 22, height: 22, background: 'transparent', border: 'none',
                cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center',
                borderRadius: '50%', color: 'var(--fl-dim)' }}
              title="Reply"
              onMouseEnter={ev => ev.currentTarget.style.background = 'var(--fl-panel)'}
              onMouseLeave={ev => ev.currentTarget.style.background = 'transparent'}
            ><Reply size={12} /></button>
            
            {canPin && (
              <button onClick={() => { onPin(msg.id); setShowEmojiBar(false); }}
                style={{ width: 22, height: 22, background: 'transparent', border: 'none',
                  cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  borderRadius: '50%', color: msg.pinned ? 'var(--fl-accent)' : 'var(--fl-dim)' }}
                title={msg.pinned ? 'Unpin' : 'Pin'}
                onMouseEnter={ev => ev.currentTarget.style.background = 'var(--fl-panel)'}
                onMouseLeave={ev => ev.currentTarget.style.background = 'transparent'}
              ><Pin size={12} /></button>
            )}
            
            {isOwn && (
              <button onClick={() => onDelete(msg.id)}
                style={{ width: 22, height: 22, background: 'transparent', border: 'none',
                  cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  borderRadius: '50%', color: 'var(--fl-dim)' }}
              title="Delete"
                onMouseEnter={ev => ev.currentTarget.style.background = 'var(--fl-panel)'}
                onMouseLeave={ev => ev.currentTarget.style.background = 'transparent'}
              ><Trash2 size={11} /></button>
            )}
          </div>
        )}

        <div
          onMouseEnter={() => setShowTimestamp(true)}
          onMouseLeave={() => setShowTimestamp(false)}
          style={{
            background: msg.pinned ? 'var(--fl-sep)' : (isOwn ? (ownColor || 'var(--fl-accent)') : 'var(--fl-card)'),
            borderRadius: bubbleRadius,
            padding: '7px 11px', fontSize: 13,
            color: isOwn ? '#fff' : 'var(--fl-text)',
            lineHeight: 1.55, wordBreak: 'break-word', whiteSpace: 'pre-wrap',
            border: `1px solid ${msg.pinned ? 'var(--fl-border)' : (isOwn ? 'transparent' : 'var(--fl-border2)')}`,
            position: 'relative',
          }}
        >
          {renderContent(displayContent)}
          
          {showTimestamp && (
            <span style={{
              position: 'absolute', bottom: -16,
              ...(isOwn ? { right: 4 } : { left: 4 }),
              fontSize: 9, color: 'var(--fl-muted)', whiteSpace: 'nowrap',
              background: 'var(--fl-bg)', padding: '1px 4px', borderRadius: 3,
              pointerEvents: 'none',
            }}>
              {fmtTime(msg.created_at, locale)}
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
                  background: users.has(currentUserId) ? 'color-mix(in srgb, var(--fl-accent) 18%, transparent)' : 'var(--fl-panel)',
                  border: `1px solid ${users.has(currentUserId) ? 'color-mix(in srgb, var(--fl-accent) 45%, transparent)' : 'var(--fl-border)'}`,
                  color: 'var(--fl-text)', display: 'flex', alignItems: 'center', gap: 3,
                  transition: 'all 0.1s',
                }}>
                {emoji} <span style={{ fontSize: 10, color: 'var(--fl-dim)' }}>{users.size}</span>
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
  const locale = prefs.language || 'en';
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
  const [emojiPickerPos, setEmojiPickerPos]   = useState({ top: 0, left: 0 });
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

  // Draggable launcher bubble — grab to move (position persisted), click to open.
  const [btnPos, setBtnPos] = useState(() => {
    try { const s = localStorage.getItem('fl_chat_btn_pos'); if (s) return JSON.parse(s); } catch (_e) {}
    return null;
  });
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
      if (btnDragRef.current.moved) {
        last = { x: Math.min(Math.max(ox + dx, 4), window.innerWidth - 56), y: Math.min(Math.max(oy + dy, 4), window.innerHeight - 56) };
        setBtnPos(last);
      }
    };
    const up = () => {
      document.removeEventListener('mousemove', move);
      document.removeEventListener('mouseup', up);
      document.body.style.userSelect = '';
      if (btnDragRef.current.moved && last) { try { localStorage.setItem('fl_chat_btn_pos', JSON.stringify(last)); } catch (_e) {} }
    };
    document.body.style.userSelect = 'none';
    document.addEventListener('mousemove', move);
    document.addEventListener('mouseup', up);
  }, []);

  const [chatMode, setChatMode]       = useState('team');
  const [aiMessages, setAiMessages]   = useState([]);
  const [aiInput, setAiInput]         = useState('');
  const [aiStreaming, setAiStreaming]  = useState(false);
  const aiEndRef                      = useRef(null);

  const [reactionsMap, setReactionsMap] = useState(new Map());

  const bottomRef     = useRef(null);
  const msgsElRef     = useRef(null);
  const textareaRef   = useRef(null);
  const emojiPickerRef    = useRef(null);
  const emojiPickerBtnRef = useRef(null);
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
        content: `🔔 Ping from ${data.from_full_name || data.from_user}: ${data.message}`,
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
      el.style.outline = '2px solid color-mix(in srgb, var(--fl-accent) 38%, transparent)';
      setTimeout(() => { el.style.outline = 'none'; }, 1500);
    }
  }, []);

  const filtered = searchQuery
    ? messages.filter(m => (m.content || '').toLowerCase().includes(searchQuery.toLowerCase()))
    : messages;

  const items = [];
  let lastDay = null;
  const GROUP_MS = 4 * 60 * 1000;   // same-author messages within this window cluster together
  for (let i = 0; i < filtered.length; i++) {
    const msg = filtered[i];
    const day = fmtDate(msg.created_at, locale);
    if (day !== lastDay) { items.push({ type: 'sep', day }); lastDay = day; }
    const prev = filtered[i - 1];
    const next = filtered[i + 1];
    const hideHeader = !msg.is_ping && prev && !prev.is_ping &&
      prev.author_id === msg.author_id &&
      new Date(msg.created_at) - new Date(prev.created_at) < GROUP_MS;
    const groupContinues = !msg.is_ping && next && !next.is_ping &&
      next.author_id === msg.author_id &&
      fmtDate(next.created_at, locale) === day &&
      new Date(next.created_at) - new Date(msg.created_at) < GROUP_MS;
    items.push({ type: 'msg', msg, hideHeader: !!hideHeader, groupEnd: !groupContinues });
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
        arr[arr.length - 1] = { ...arr[arr.length - 1], content: 'AI connection error.', loading: false };
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

      {/* Launcher shows only when the panel is closed — otherwise it overlaps the
          composer / send button (esp. in fullscreen). Closing is done via the header ✕. */}
      {!open && (
      <button
        onMouseDown={startBtnDrag}
        onClick={() => { if (btnDragRef.current.moved) return; setOpen(true); setUnread(0); }}
        title={`${chatMode === 'ai' ? 'AI chat' : 'Team chat'} — drag to move`}
        style={{
          position: 'fixed', zIndex: 1000,
          ...(btnPos ? { left: btnPos.x, top: btnPos.y } : { bottom: 24, right: 24 }),
          width: 48, height: 48, borderRadius: '50%',
          background: 'var(--fl-accent)',
          border: 'none', cursor: 'grab',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: 'var(--fl-shadow-lg)',
          transition: 'transform 0.15s',
        }}
        onMouseEnter={e => e.currentTarget.style.transform = 'scale(1.08)'}
        onMouseLeave={e => e.currentTarget.style.transform = 'scale(1)'}
      >
        {chatMode === 'ai' ? <Bot size={20} color="#fff" /> : <MessageSquare size={20} color="#fff" />}
        {unread > 0 && (
          <span style={{
            position: 'absolute', top: 0, right: 0,
            background: 'var(--fl-danger)', color: '#fff', borderRadius: '50%',
            width: 18, height: 18, fontSize: 10, fontWeight: 700,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            border: '2px solid var(--fl-bg)',
          }}>
            {unread > 9 ? '9+' : unread}
          </span>
        )}
      </button>
      )}

      {open && (
        <div style={{
          position: 'fixed',
          ...(!fullscreen && panelPos?.x != null
            ? { left: panelPos.x, top: panelPos.y }
            : { bottom: fullscreen ? 0 : 24, right: fullscreen ? 0 : 24 }),
          ...(fullscreen
            ? { width: '100vw', height: '100vh', border: 'none', borderRadius: 0 }
            : { width: PANEL_WIDTH, height: panelHeight, border: '1px solid var(--fl-border)', borderRadius: 12 }),
          zIndex: 999,
          background: 'var(--fl-panel)', boxShadow: 'var(--fl-shadow-lg)',
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
              <div style={{ width: 32, height: 3, borderRadius: 2, background: 'var(--fl-border)' }} />
            </div>
          )}

          <div style={{
            padding: '6px 12px 8px', display: 'flex', alignItems: 'center', gap: 6,
            borderBottom: '1px solid var(--fl-border)', flexShrink: 0,
          }}>
            {chatMode === 'ai' ? <Bot size={13} color="var(--fl-accent)" /> : <MessageSquare size={13} color="var(--fl-accent)" />}
            <span
              onMouseDown={getDragHandleProps(PANEL_WIDTH, panelHeight).onMouseDown}
              style={{ cursor: 'grab', fontWeight: 600, fontSize: 13, color: chatMode === 'ai' ? 'var(--fl-accent)' : 'var(--fl-dim)', flex: 1, userSelect: 'none' }}
            >
              {chatMode === 'ai' ? 'AI chat' : 'Chat'}
            </span>

            {presenceUsers.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center' }}>
                {presenceUsers.slice(0, 4).map((u, i) => (
                  <div key={u.id || i} title={u.full_name || u.username} style={{
                    width: 22, height: 22, borderRadius: '50%', flexShrink: 0,
                    background: avatarColor(u.username || ''),
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 9, fontWeight: 700, color: '#fff',
                    border: '2px solid var(--fl-panel)',
                    marginLeft: i > 0 ? -6 : 0,
                    cursor: 'default',
                  }}>
                    {initials(u.full_name || u.username)}
                  </div>
                ))}
                {presenceUsers.length > 4 && (
                  <div style={{
                    width: 22, height: 22, borderRadius: '50%',
                    background: 'var(--fl-panel)', border: '2px solid var(--fl-panel)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 9, color: 'var(--fl-dim)', marginLeft: -6,
                  }}>+{presenceUsers.length - 4}</div>
                )}
              </div>
            )}

            <button
              onClick={() => sendPing()}
              disabled={pinging}
              title="Ping all analysts on the case"
              style={{
                background: pingDone && !pingingUser ? 'color-mix(in srgb, var(--fl-ok) 8%, transparent)' : 'none',
                border: `1px solid ${pingDone && !pingingUser ? 'color-mix(in srgb, var(--fl-ok) 19%, transparent)' : 'var(--fl-panel)'}`,
                borderRadius: 4, cursor: pinging ? 'default' : 'pointer',
                padding: '2px 6px', display: 'flex', alignItems: 'center', gap: 3,
                color: pingDone && !pingingUser ? 'var(--fl-ok)' : 'var(--fl-gold)',
                fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
              }}
            >
              <Bell size={10} />
              {pingDone && !pingingUser ? '✓' : 'Ping'}
            </button>

            <button
              onClick={() => setChatMode(m => m === 'team' ? 'ai' : 'team')}
              title={chatMode === 'ai' ? 'Switch to team chat' : 'Switch to AI chat'}
              style={{
                background: chatMode === 'ai' ? 'color-mix(in srgb, var(--fl-accent) 9%, transparent)' : 'none',
                border: chatMode === 'ai' ? '1px solid color-mix(in srgb, var(--fl-accent) 21%, transparent)' : '1px solid transparent',
                borderRadius: 4, cursor: 'pointer',
                color: chatMode === 'ai' ? 'var(--fl-accent)' : 'var(--fl-dim)',
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
              title={soundEnabled ? 'Disable sounds' : 'Enable sounds'}
              style={{ background: 'none', border: 'none', cursor: 'pointer',
                color: soundEnabled ? 'var(--fl-accent)' : 'var(--fl-muted)', padding: 0 }}
            >
              {soundEnabled ? <Volume2 size={13} /> : <VolumeX size={13} />}
            </button>

            <button
              onClick={() => { setShowSearch(s => !s); if (showSearch) setSearchQuery(''); }}
              title="Search in chat"
              style={{ background: 'none', border: 'none', cursor: 'pointer',
                color: showSearch ? 'var(--fl-accent)' : 'var(--fl-dim)', padding: 0 }}
            >
              <Search size={13} />
            </button>

            <button
              onClick={() => setFullscreen(f => !f)}
              title={fullscreen ? 'Minimize' : 'Fullscreen'}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: fullscreen ? 'var(--fl-accent)' : 'var(--fl-dim)', padding: 0 }}
            >
              {fullscreen ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
            </button>

            <button onClick={() => setOpen(false)}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-dim)', padding: 0 }}>
              <X size={14} />
            </button>
          </div>

          {chatMode === 'ai' && (
            <>
              <div style={{ flex: 1, overflowY: 'auto', padding: '8px 10px 4px', scrollbarWidth: 'thin' }}>
                {aiMessages.length === 0 && (
                  <div style={{ textAlign: 'center', color: 'var(--fl-muted)', fontSize: 14, marginTop: 40 }}>
                    <Bot size={28} style={{ color: 'color-mix(in srgb, var(--fl-accent) 19%, transparent)', marginBottom: 8 }} />
                    <div>Ask the AI a question about this case</div>
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
                      fontSize: 13, lineHeight: 1.6, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                      background: m.role === 'user' ? 'color-mix(in srgb, var(--fl-accent) 9%, transparent)' : 'color-mix(in srgb, var(--fl-accent) 8%, transparent)',
                      color: m.role === 'user' ? 'var(--fl-dim)' : 'var(--fl-text)',
                      border: `1px solid ${m.role === 'user' ? 'color-mix(in srgb, var(--fl-accent) 19%, transparent)' : 'color-mix(in srgb, var(--fl-accent) 19%, transparent)'}`,
                      whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                    }}>
                      {m.loading
                        ? <span style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                            <span style={{ animation: 'fl-bounce 1.4s infinite', animationDelay: '0s', display: 'inline-block', width: 5, height: 5, borderRadius: '50%', background: 'var(--fl-accent)' }} />
                            <span style={{ animation: 'fl-bounce 1.4s infinite', animationDelay: '0.2s', display: 'inline-block', width: 5, height: 5, borderRadius: '50%', background: 'var(--fl-accent)' }} />
                            <span style={{ animation: 'fl-bounce 1.4s infinite', animationDelay: '0.4s', display: 'inline-block', width: 5, height: 5, borderRadius: '50%', background: 'var(--fl-accent)' }} />
                          </span>
                        : m.content}
                    </div>
                  </div>
                ))}
                <div ref={aiEndRef} />
              </div>
              <div style={{ padding: '8px 10px', borderTop: '1px solid var(--fl-border)', display: 'flex', gap: 6, alignItems: 'flex-end', flexShrink: 0 }}>
                <textarea
                  value={aiInput}
                  onChange={e => setAiInput(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendAI(); } }}
                  placeholder="Ask the AI…"
                  rows={2}
                  style={{
                    flex: 1, resize: 'none', background: 'var(--fl-bg)', outline: 'none',
                    border: '1px solid color-mix(in srgb, var(--fl-accent) 19%, transparent)', borderRadius: 8,
                    color: 'var(--fl-text)', fontSize: 13, padding: '7px 10px', fontFamily: 'var(--f-ui, Inter, sans-serif)',
                  }}
                />
                <button
                  onClick={sendAI}
                  disabled={!aiInput.trim() || aiStreaming}
                  style={{
                    background: aiInput.trim() && !aiStreaming ? 'var(--fl-accent)' : 'var(--fl-panel)',
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
              borderBottom: '1px solid var(--fl-border)', flexShrink: 0, flexWrap: 'wrap',
            }}>
              <span style={{ fontSize: 10, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>Online:</span>
              {presenceUsers.filter(u => u.id !== userId).map((u, i) => (
                <button
                  key={u.id || i}
                  onClick={() => sendPing(u.id)}
                  disabled={pinging}
                  title={`Ping ${u.full_name || u.username}`}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 4,
                    background: pingingUser === u.id && pingDone ? 'color-mix(in srgb, var(--fl-ok) 8%, transparent)' : 'var(--fl-sep)',
                    border: `1px solid ${pingingUser === u.id && pingDone ? 'color-mix(in srgb, var(--fl-ok) 19%, transparent)' : 'var(--fl-panel)'}`,
                    borderRadius: 12, padding: '1px 7px 1px 4px',
                    cursor: pinging ? 'default' : 'pointer', fontSize: 10,
                    color: pingingUser === u.id && pingDone ? 'var(--fl-ok)' : 'var(--fl-dim)',
                  }}
                >
                  <div style={{
                    width: 6, height: 6, borderRadius: '50%',
                    background: 'var(--fl-ok)',
                  }} />
                  {u.username}
                  <Bell size={8} style={{ color: pingingUser === u.id && pingDone ? 'var(--fl-ok)' : 'var(--fl-gold)' }} />
                </button>
              ))}
            </div>
          )}

          
          {showSearch && (
            <div style={{ padding: '6px 12px', borderBottom: '1px solid var(--fl-border)', flexShrink: 0 }}>
              <div style={{ position: 'relative' }}>
                <Search size={12} style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', color: 'var(--fl-muted)' }} />
                <input
                  autoFocus
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  placeholder="Search…"
                  style={{
                    width: '100%', background: 'var(--fl-bg)', border: '1px solid var(--fl-border)',
                    borderRadius: 6, padding: '4px 8px 4px 26px',
                    color: 'var(--fl-dim)', fontSize: 12, outline: 'none', boxSizing: 'border-box',
                  }}
                />
                {searchQuery && (
                  <span style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)',
                    fontSize: 10, color: 'var(--fl-muted)' }}>
                    {filtered.length} result{filtered.length !== 1 ? 's' : ''}
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
                      background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 6,
                      padding: '3px 12px', fontSize: 11, color: 'var(--fl-dim)', cursor: 'pointer',
                    }}
                  >
                    {loadingMore
                      ? <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} />
                      : 'Load more'}
                  </button>
                </div>
              )}

              {loading && (
                <div style={{ display: 'flex', justifyContent: 'center', marginTop: 40 }}>
                  <Loader2 size={20} color="var(--fl-accent)" style={{ animation: 'spin 1s linear infinite' }} />
                </div>
              )}

              {!loading && messages.length === 0 && (
                <div style={{ textAlign: 'center', color: 'var(--fl-muted)', fontSize: 12, marginTop: 40 }}>
                  No messages - start the conversation!
                </div>
              )}

              {!loading && searchQuery && filtered.length === 0 && (
                <div style={{ textAlign: 'center', color: 'var(--fl-muted)', fontSize: 12, marginTop: 20 }}>
                  No results for “{searchQuery}”
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
                      groupEnd={item.groupEnd}
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
                title="Jump to bottom"
                style={{
                  position: 'absolute', bottom: 8, right: 12,
                  width: 28, height: 28, borderRadius: '50%',
                  background: 'var(--fl-panel)', border: '1px solid var(--fl-border)',
                  cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  color: 'var(--fl-dim)', boxShadow: '0 2px 8px rgba(0,0,0,0.4)', zIndex: 10,
                }}
              >
                <ChevronDown size={14} />
                {unread > 0 && (
                  <span style={{
                    position: 'absolute', top: -4, right: -4,
                    background: 'var(--fl-danger)', color: '#fff', borderRadius: '50%',
                    width: 14, height: 14, fontSize: 9, fontWeight: 700,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>{unread}</span>
                )}
              </button>
            )}
          </div>

          
          {othersTyping.length > 0 && (
            <div style={{ padding: '3px 12px', fontSize: 11, color: 'var(--fl-dim)',
              fontStyle: 'italic', display: 'flex', alignItems: 'center', flexShrink: 0 }}>
              {othersTyping.map(u => u.username).join(', ')} typing…
              <span style={{ display: 'inline-flex', gap: 2, marginLeft: 6 }}>
                {[0, 1, 2].map(i => (
                  <span key={i} style={{
                    width: 4, height: 4, borderRadius: '50%', background: 'var(--fl-dim)',
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
              background: 'var(--fl-card)', borderLeft: '2px solid var(--fl-border3)',
              borderRadius: 4, fontSize: 11, color: 'var(--fl-text)',
              whiteSpace: 'pre-wrap', position: 'relative', flexShrink: 0,
            }}>
              {draft}
              <button onClick={() => setDraft(null)}
                style={{ position: 'absolute', top: 4, right: 6, background: 'none',
                  border: 'none', color: 'var(--fl-dim)', cursor: 'pointer', fontSize: 11 }}>
                ✕
              </button>
            </div>
          )}

          
          <ReplyBar replyTo={replyTo} onClear={() => setReplyTo(null)} />

          
          <div style={{
            padding: '8px 10px', borderTop: '1px solid var(--fl-border)',
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
              placeholder={replyTo ? `Reply to ${replyTo.username}…` : 'Message… (Enter to send)'}
              rows={2}
              style={{
                flex: 1, resize: 'none', background: 'var(--fl-bg)', outline: 'none',
                border: `1px solid ${draft != null ? 'var(--fl-accent)' : replyTo ? 'color-mix(in srgb, var(--fl-accent) 38%, transparent)' : 'var(--fl-border)'}`,
                borderRadius: 8, color: 'var(--fl-text)', fontSize: 13,
                padding: '7px 10px', fontFamily: 'var(--f-ui, Inter, sans-serif)', lineHeight: 1.5,
              }}
            />

            
            <div style={{ position: 'relative', flexShrink: 0 }}>
              <button
                ref={emojiPickerBtnRef}
                onClick={() => {
                  if (!showEmojiPicker) {
                    const rect = emojiPickerBtnRef.current?.getBoundingClientRect();
                    if (rect) {
                      const pickerW = 244;
                      const left = Math.max(4, Math.min(rect.right - pickerW, window.innerWidth - pickerW - 4));
                      setEmojiPickerPos({ top: rect.top - 4, left });
                    }
                  }
                  setShowEmojiPicker(p => !p);
                }}
                title="Insert emoji"
                style={{ background: 'none', border: 'none', cursor: 'pointer',
                  fontSize: 16, padding: 2, lineHeight: 1 }}
              >
                😊
              </button>
            </div>
            {showEmojiPicker && (
              <div
                ref={emojiPickerRef}
                style={{
                  position: 'fixed',
                  top: emojiPickerPos.top,
                  left: emojiPickerPos.left,
                  transform: 'translateY(-100%)',
                  width: 244, background: 'var(--fl-panel)', border: '1px solid var(--fl-border)',
                  borderRadius: 10, padding: 8,
                  display: 'grid', gridTemplateColumns: 'repeat(8, 1fr)', gap: 2,
                  zIndex: 9999,
                  boxShadow: '0 4px 24px rgba(0,0,0,0.4)',
                }}>
                {EMOJI_GRID.map(emoji => (
                  <button key={emoji} onClick={() => insertEmoji(emoji)}
                    style={{
                      width: 28, height: 28, fontSize: 16, background: 'transparent',
                      border: 'none', cursor: 'pointer', borderRadius: 4,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }}
                    onMouseEnter={e => e.currentTarget.style.background = 'var(--fl-hover-bg)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >{emoji}</button>
                ))}
              </div>
            )}

            
            <button
              onClick={send}
              disabled={!canSend}
              style={{
                background: canSend ? 'var(--fl-accent)' : 'var(--fl-panel)',
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
