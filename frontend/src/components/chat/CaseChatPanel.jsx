import { useState, useEffect, useRef, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { usePreferences } from '../../utils/preferences';
import {
  MessageSquare, X, Send, Loader2, Trash2, Bell,
  ChevronDown, Search, Pin, PinOff, Reply, Volume2, VolumeX,
  MoreHorizontal, Bot, Maximize2, Minimize2, Copy, Check,
} from 'lucide-react';
import api from '../../utils/api';
import { useDraggable } from '../../hooks/useDraggable';
import { playPing } from './chatSound';
import {
  isUuid, formatTimeUtc, formatLocalTitle, dayKeyUtc, formatDayUtc, tokenizeContent,
  buildReactMap, reactionTitle, mergeMessages, applyPinEvent, bannerAfterPinEvent,
  serverErrorKey, copyText, shareDraft, iocLabel,
} from './chatUtils';
import { signalerChatMonte } from '../pingToast';

const PANEL_WIDTH = 380;
const SEND_ACK_TIMEOUT_MS = 8000;
const PING_DEFAULT = 'Ping !';

function hashCode(s) {
  return Math.abs([...s].reduce((h, c) => Math.imul(31, h) + c.charCodeAt(0) | 0, 0));
}
const AVATAR_COLORS = ['var(--fl-accent)', 'var(--fl-accent)', 'var(--fl-ok)', 'var(--fl-warn)', 'var(--fl-danger)', 'var(--fl-purple)'];
function avatarColor(u) { return AVATAR_COLORS[hashCode(u || '') % AVATAR_COLORS.length]; }
function initials(n) { return (n || '?').slice(0, 2).toUpperCase(); }

const QUICK_EMOJIS = ['👍', '✅', '🔴', '⚠️', '🔍', '💡', '🚨', '😂'];
const EMOJI_GRID = [
  '😀','😂','🤔','😅','😎','🤯','😤','🥳',
  '👍','👎','👋','🙌','👀','🤞','✌️','💪',
  '🔍','🚨','✅','⚠️','🔴','🟡','🟢','💡',
  '🛡️','🔐','💻','🌐','⚡','🔒','🧬','📋',
  '🐛','🚀','🎯','🔥','💀','☠️','🕵️','🔑',
];

function HashChip({ type, value, onCopyFailed }) {
  const { t } = useTranslation();
  const [state, setState] = useState('idle');
  const timerRef = useRef(null);
  useEffect(() => () => clearTimeout(timerRef.current), []);
  const algo = iocLabel(type);
  const onCopy = async () => {
    const ok = await copyText(value);
    clearTimeout(timerRef.current);
    if (!ok) {
      setState('idle');
      if (onCopyFailed) onCopyFailed();
      return;
    }
    setState('ok');
    timerRef.current = setTimeout(() => setState('idle'), 2000);
  };
  return (
    <span>
      <span className={`fl-chat-ioc fl-chat-ioc--${type} fl-chat-hash`} title={algo}>{value}</span>
      <button type="button" className="fl-chat-copy" aria-label={t('chat.copy_hash', { algo })} title={t('chat.copy_hash', { algo })} onClick={onCopy}>
        {state === 'ok' ? <Check size={11} /> : <Copy size={11} />}
      </button>
      <span role="status" className="fl-chat-copy-status sr-only">
        {state === 'ok' ? t('chat.copied') : ''}
      </span>
    </span>
  );
}

function renderContent(text, onCopyFailed) {
  return tokenizeContent(text).map((seg, i) => {
    if (seg.t === 'text') return <span key={i}>{seg.v}</span>;
    if (seg.t === 'mention') return <span key={i} className="fl-chat-ioc fl-chat-ioc--mention">{seg.v}</span>;
    if (seg.t === 'ipv4') {
      return <span key={i} className="fl-chat-ioc fl-chat-ioc--ipv4" title={iocLabel('ipv4')}>{seg.v}</span>;
    }
    return <HashChip key={i} type={seg.t} value={seg.v} onCopyFailed={onCopyFailed} />;
  });
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
.fl-chat-ioc{border-radius:3px;padding:0 3px;color:var(--ioc);background:color-mix(in srgb,var(--ioc) 9%,transparent)}
.fl-chat-ioc--mention{--ioc:var(--fl-accent);font-weight:700}
.fl-chat-ioc--sha256{--ioc:var(--fl-danger)}
.fl-chat-ioc--sha1{--ioc:var(--fl-gold)}
.fl-chat-ioc--md5{--ioc:var(--fl-accent)}
.fl-chat-ioc--ipv4{--ioc:var(--fl-warn)}
.fl-chat-ioc--sha256,.fl-chat-ioc--sha1,.fl-chat-ioc--md5,.fl-chat-ioc--ipv4{font-family:var(--f-mono,"JetBrains Mono",monospace);font-size:var(--fs-base);cursor:help}
.fl-chat-hash{overflow-wrap:anywhere;word-break:break-all}
.fl-chat-copy{position:relative;display:inline-flex;align-items:center;justify-content:center;background:none;border:none;cursor:pointer;color:inherit;padding:0 3px;vertical-align:middle}
.fl-chat-copy::after{content:"";position:absolute;left:50%;top:50%;width:var(--sp-7);height:var(--sp-7);transform:translate(-50%,-50%)}
.fl-chat-copy:focus-visible{outline:2px solid currentColor;outline-offset:2px}
.fl-chat-time{font-size:var(--fs-base);color:var(--fl-dim);font-family:var(--f-mono,"JetBrains Mono",monospace)}
.fl-chat-time-hover{position:absolute;bottom:-16px;z-index:5;opacity:0;font-size:var(--fs-base);color:var(--fl-dim);font-family:var(--f-mono,"JetBrains Mono",monospace);white-space:nowrap;background:var(--fl-bg);padding:1px 4px;border-radius:3px;pointer-events:none}
.fl-chat-bubble:hover .fl-chat-time-hover,.fl-chat-row:focus-within .fl-chat-time-hover{opacity:1}
.fl-chat-bubble:focus-visible{outline:2px solid var(--fl-text);outline-offset:2px}
.fl-chat-time-hover--own{right:4px}
.fl-chat-time-hover--other{left:4px}
.fl-chat-offscreen{position:fixed;left:-9999px;top:0}
.fl-chat-notice{margin:0 10px 4px;padding:6px 10px;border:1px solid color-mix(in srgb,var(--fl-danger) 40%,var(--fl-border));border-radius:4px;color:var(--fl-text);font-size:var(--fs-md);display:flex;align-items:flex-start;gap:8px;flex-shrink:0}
.fl-chat-notice-text{flex:1;min-width:0;overflow-wrap:anywhere}
.fl-chat-notice-close{display:inline-flex;align-items:center;justify-content:center;min-width:var(--sp-7);min-height:var(--sp-7);background:none;border:none;cursor:pointer;color:var(--fl-dim);padding:0;flex-shrink:0}
.fl-chat-notice-close:focus-visible{outline:2px solid currentColor;outline-offset:-2px}
.fl-chat-error{display:flex;flex-direction:column;align-items:center;gap:8px;margin:24px 12px 0;color:var(--fl-text);font-size:var(--fs-md);text-align:center}
.fl-chat-loading{display:flex;justify-content:center;align-items:center;gap:var(--sp-4);margin-top:40px;color:var(--fl-dim);font-size:var(--fs-md)}
.fl-chat-badge{position:absolute;display:flex;align-items:center;justify-content:center;box-sizing:border-box;min-width:16px;height:16px;padding:0 var(--sp-2);border-radius:8px;background:var(--fl-danger);color:var(--fl-bg);font-size:var(--fs-base);font-weight:700;line-height:1}
.fl-chat-badge--launcher{top:0;right:0;min-width:20px;height:20px;border:2px solid var(--fl-bg)}
.fl-chat-badge--jump{top:-6px;right:-6px}
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
    <div className="fl-chat-daysep" style={{ display: 'flex', alignItems: 'center', gap: 10, margin: '14px 0 10px' }}>
      <div style={{ flex: 1, height: 1, background: 'var(--fl-border2)' }} />
      <span style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)', padding: '2px 9px', borderRadius: 10, background: 'var(--fl-bg)', border: '1px solid var(--fl-border2)' }}>{date}</span>
      <div style={{ flex: 1, height: 1, background: 'var(--fl-border2)' }} />
    </div>
  );
}

function Bubble({ msg, currentUserId, onDelete, onReact, onPin, onReply,
                   hideHeader, groupEnd = true, reactionMap, onScrollTo, canPin, searchQuery, ownColor, locale = 'en', onCopyFailed }) {
  const { t } = useTranslation();
  const isOwn = msg.author_id === currentUserId;
  const username = msg.username || msg.full_name || '?';
  const grpTop = hideHeader ? 4 : 12;
  const grpBot = groupEnd ? 12 : 4;
  const bubbleRadius = isOwn ? `12px ${grpTop}px ${grpBot}px 12px` : `${grpTop}px 12px 12px ${grpBot}px`;
  const [showActions, setShowActions] = useState(false);
  const [showEmojiBar, setShowEmojiBar] = useState(false);
  const hideTimerRef = useRef(null);
  useEffect(() => () => clearTimeout(hideTimerRef.current), []);

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
          {msg.ping
            ? (msg.ping.message && msg.ping.message.trim() !== PING_DEFAULT
              ? t('chat.ping_with_message', { who: msg.ping.who, message: msg.ping.message })
              : t('chat.ping_from', { who: msg.ping.who }))
            : msg.content}
        </div>
      </div>
    );
  }

  const content = msg.content || '';
  const displayContent = searchQuery
    ? content
    : content;
  const localLabel = t('chat.local_time', { time: formatLocalTitle(msg.created_at, locale) });
  const hasHoverTime = isOwn || !!hideHeader;

  return (
    <div
      id={`msg-${msg.id}`}
      className="fl-chat-row"
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
            <time className="fl-chat-time" dateTime={msg.created_at}>{formatTimeUtc(msg.created_at)}</time>
            <span className="sr-only">{localLabel}</span>
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
          className="fl-chat-bubble"
          tabIndex={hasHoverTime ? 0 : undefined}
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
          {renderContent(displayContent, onCopyFailed)}
          
          {hasHoverTime && (
            <span className={`fl-chat-time-hover fl-chat-time-hover--${isOwn ? 'own' : 'other'}`}>
              <time dateTime={msg.created_at}>{formatTimeUtc(msg.created_at)}</time>
              <span className="sr-only">{localLabel}</span>
            </span>
          )}
        </div>

        {reactionMap && reactionMap.size > 0 && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, marginTop: 5,
            justifyContent: isOwn ? 'flex-end' : 'flex-start' }}>
            {[...reactionMap.entries()].map(([emoji, users]) => (
              <button key={emoji} onClick={() => onReact(msg.id, emoji)}
                title={reactionTitle(users)}
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
  const { t } = useTranslation();
  const { prefs } = usePreferences();
  const locale = prefs.language || 'en';
  const [open, setOpen]     = useState(false);
  const [messages, setMsgs] = useState([]);
  const [hasMore, setHasMore] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [loading, setLoading]   = useState(false);
  const [loadError, setLoadError] = useState(false);
  const [notice, setNotice]     = useState(null);
  const [sending, setSending]   = useState(false);
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
  const aiInputRef    = useRef(null);
  const timedOutTextRef = useRef(null);
  const loadHistoryRef = useRef(() => {});
  const anchorRafRef  = useRef(null);
  const emojiPickerRef    = useRef(null);
  const emojiPickerBtnRef = useRef(null);
  const typingThrottleRef = useRef(false);
  const timersRef     = useRef(new Map());
  const mountedRef    = useRef(true);
  const openRef       = useRef(false);
  const isAtBottomRef = useRef(true);
  const messagesRef   = useRef([]);
  const pinnedRef     = useRef(null);
  const allUsersRef   = useRef([]);
  const presenceRef   = useRef([]);
  const usersStateRef = useRef('idle');
  const loadSeqRef    = useRef(0);
  const resyncSeqRef  = useRef(0);
  const loadMoreSeqRef = useRef(0);
  const pinnedSeqRef  = useRef(0);
  const caseIdRef     = useRef(caseId);
  caseIdRef.current = caseId;
  const pingSeqRef    = useRef(0);
  const highlightRef  = useRef(null);
  const scrollRafRef  = useRef(null);
  const sendRef       = useRef(() => {});
  const loadMoreRef   = useRef(() => {});
  const resyncRef     = useRef(() => {});
  const soundRef      = useRef(true);
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
    mountedRef.current = true;
    const timers = timersRef.current;
    return () => {
      mountedRef.current = false;
      for (const timerId of timers.values()) clearTimeout(timerId);
      timers.clear();
      if (scrollRafRef.current) cancelAnimationFrame(scrollRafRef.current);
      if (anchorRafRef.current) cancelAnimationFrame(anchorRafRef.current);
    };
  }, []);

  useEffect(() => {
    if (hidden) return undefined;
    return signalerChatMonte(caseId);
  }, [caseId, hidden]);

  openRef.current = open;
  messagesRef.current = messages;
  pinnedRef.current = pinned;
  allUsersRef.current = allUsers;
  presenceRef.current = presenceUsers;
  soundRef.current = soundEnabled;

  const setTimer = useCallback((name, fn, ms) => {
    const timers = timersRef.current;
    clearTimeout(timers.get(name));
    timers.set(name, setTimeout(() => { timers.delete(name); fn(); }, ms));
  }, []);

  const clearTimer = useCallback((name) => {
    clearTimeout(timersRef.current.get(name));
    timersRef.current.delete(name);
  }, []);

  const clearNotice = useCallback((...kinds) => {
    setNotice(n => (n && (kinds.length === 0 || kinds.includes(n.kind)) ? null : n));
  }, []);

  const showNotice = useCallback((text, action = null, kind = 'general') => {
    setNotice({ text, action, kind });
  }, []);

  const focusComposer = useCallback(() => {
    const el = chatMode === 'ai' ? aiInputRef.current : textareaRef.current;
    if (el) el.focus();
  }, [chatMode]);

  const notifyCopyFailed = useCallback(() => {
    showNotice(t('chat.copy_failed'), null, 'copy');
  }, [showNotice, t]);

  const captureAnchor = useCallback(() => {
    const el = msgsElRef.current;
    if (!el || isAtBottomRef.current) return null;
    const base = el.getBoundingClientRect().top;
    const node = [...el.querySelectorAll('[id^="msg-"]')].find(n => n.getBoundingClientRect().bottom > base);
    return node ? { id: node.id, offset: node.getBoundingClientRect().top - base } : null;
  }, []);

  const restoreAnchor = useCallback((anchor) => {
    if (!anchor) return;
    if (anchorRafRef.current) cancelAnimationFrame(anchorRafRef.current);
    anchorRafRef.current = requestAnimationFrame(() => {
      anchorRafRef.current = null;
      const el = msgsElRef.current;
      const node = document.getElementById(anchor.id);
      if (!el || !node) return;
      el.scrollTop += (node.getBoundingClientRect().top - el.getBoundingClientRect().top) - anchor.offset;
    });
  }, []);

  const updateBottom = useCallback((atBottom) => {
    isAtBottomRef.current = atBottom;
    setIsAtBottom(atBottom);
    if (atBottom) setUnread(0);
  }, []);

  const loadUsers = useCallback(async () => {
    try {
      const r = await api.get('/users');
      setAllUsers(r.data || []);
      usersStateRef.current = 'ok';
      return true;
    } catch (_e) {
      usersStateRef.current = 'failed';
      return false;
    }
  }, []);

  useEffect(() => { loadUsers(); }, [loadUsers]);

  const nameOf = useCallback((uid) => {
    if (uid === userId) return currentUser?.full_name || currentUser?.username || t('chat.unknown_user');
    const u = allUsersRef.current.find(x => x.id === uid) || presenceRef.current.find(x => x.id === uid);
    return u ? (u.full_name || u.username || t('chat.unknown_user')) : t('chat.unknown_user');
  }, [userId, currentUser, t]);

  const toggleReactionLocal = useCallback((msgId, emoji, uid, added, label) => {
    setReactionsMap(prev => {
      const next = new Map(prev);
      if (!next.has(msgId)) next.set(msgId, new Map());
      const em = new Map(next.get(msgId));
      const us = new Map(em.get(emoji) || []);
      if (added) us.set(uid, label); else us.delete(uid);
      if (us.size) em.set(emoji, us); else em.delete(emoji);
      next.set(msgId, em);
      return next;
    });
  }, []);

  const applyReactions = useCallback((list, replace) => {
    setReactionsMap(prev => {
      const next = new Map(prev);
      for (const m of list) {
        if (m.reactions?.length) next.set(m.id, buildReactMap(m.reactions, nameOf));
        else if (replace) next.delete(m.id);
      }
      return next;
    });
  }, [nameOf]);

  const removeLocal = useCallback((messageId) => {
    setMsgs(prev => prev.filter(m => m.id !== messageId));
    setReactionsMap(prev => {
      if (!prev.has(messageId)) return prev;
      const next = new Map(prev);
      next.delete(messageId);
      return next;
    });
    setPinned(p => (p && p.id === messageId ? null : p));
    setReplyTo(r => (r && r.id === messageId ? null : r));
  }, []);

  const refreshPinned = useCallback(async (fallbackMessages) => {
    const seq = ++pinnedSeqRef.current;
    const stale = () => seq !== pinnedSeqRef.current || caseIdRef.current !== caseId;
    try {
      const res = await api.get(`/chat/${caseId}/pinned`);
      if (stale()) return;
      setPinned(res.data || null);
    } catch (_e) {
      if (stale()) return;
      const p = (fallbackMessages || []).find(m => m.pinned);
      setPinned(p ? bannerAfterPinEvent(null, [p], { message_id: p.id, pinned: true, pinned_by: p.pinned_by_username }).banner : null);
    }
  }, [caseId]);

  useEffect(() => {
    resyncSeqRef.current += 1;
    loadSeqRef.current += 1;
    loadMoreSeqRef.current += 1;
    pinnedSeqRef.current += 1;
    setLoadingMore(false);
    setMsgs([]);
    setPinned(null);
    setReactionsMap(new Map());
    setHasMore(false);
    setReplyTo(null);
    setUnread(0);
    setLoadError(false);
  }, [caseId]);

  const loadHistory = useCallback(async (options) => {
    if (!caseId) return;
    const keepReading = options?.keepReading === true;
    const seq = ++loadSeqRef.current;
    if (!keepReading) setLoading(true);
    setLoadError(false);
    const pinnedReq = api.get(`/chat/${caseId}/pinned`)
      .then(r => ({ ok: true, data: r.data || null }))
      .catch(() => ({ ok: false }));
    try {
      const histRes = await api.get(`/chat/${caseId}/history?limit=50`);
      const pinnedRes = await pinnedReq;
      if (seq !== loadSeqRef.current) return;
      const { messages: msgs, has_more } = histRes.data;
      if (keepReading) {
        setMsgs(prev => mergeMessages(prev, msgs, { dropMissingInWindow: true }));
        setHasMore(h => h || has_more);
        applyReactions(msgs, true);
      } else {
        setMsgs(msgs);
        setHasMore(has_more);
        updateBottom(true);
        const rm = new Map();
        for (const m of msgs) {
          if (m.reactions?.length) rm.set(m.id, buildReactMap(m.reactions, nameOf));
        }
        setReactionsMap(rm);
      }
      clearNotice('history', 'loadmore', 'resync');
      if (pinnedRes.ok) {
        setPinned(pinnedRes.data);
      } else {
        const p = msgs.find(m => m.pinned);
        setPinned(p ? bannerAfterPinEvent(null, [p], { message_id: p.id, pinned: true, pinned_by: p.pinned_by_username }).banner : null);
      }
    } catch (_e) {
      if (seq === loadSeqRef.current) {
        if (messagesRef.current.some(x => !x.is_ping)) {
          showNotice(t('chat.history_stale'), { label: t('chat.retry'), run: () => loadHistoryRef.current() }, 'history');
        } else {
          setLoadError(true);
        }
      }
    } finally {
      if (seq === loadSeqRef.current) setLoading(false);
    }
  }, [caseId, nameOf, updateBottom, applyReactions, clearNotice, showNotice, t]);

  loadHistoryRef.current = loadHistory;

  useEffect(() => {
    if (!open || !caseId) return undefined;
    loadHistory();
    return () => { loadSeqRef.current += 1; };
  }, [open, caseId, loadHistory]);

  const loadMore = useCallback(async () => {
    if (!hasMore || loadingMore) return;
    const seq = ++loadMoreSeqRef.current;
    const stale = () => seq !== loadMoreSeqRef.current || caseIdRef.current !== caseId;
    setLoadingMore(true);
    try {
      let candidates = messagesRef.current.filter(m => !m.is_ping && isUuid(m.id));
      let attempts = 0;
      let removed = 0;
      while (candidates.length && attempts < 5) {
        const cursor = candidates[0];
        attempts += 1;
        let res;
        try {
          res = await api.get(`/chat/${caseId}/history?limit=50&before_id=${cursor.id}`);
        } catch (err) {
          if (stale()) return;
          if (err?.response?.status === 404) {
            removeLocal(cursor.id);
            removed += 1;
            candidates = candidates.slice(1);
            continue;
          }
          throw err;
        }
        if (stale()) return;
        const { messages: older, has_more } = res.data;
        setHasMore(has_more);
        const el = msgsElRef.current;
        const prevScrollHeight = el?.scrollHeight || 0;
        setMsgs(prev => mergeMessages(prev, older));
        scrollRafRef.current = requestAnimationFrame(() => {
          scrollRafRef.current = null;
          if (el) el.scrollTop = el.scrollHeight - prevScrollHeight;
        });
        applyReactions(older, false);
        clearNotice('loadmore', 'history', 'resync', 'removed');
        if (removed > 0) showNotice(t('chat.removed_deleted', { count: removed }), null, 'removed');
        return;
      }
      if (stale()) return;
      await loadHistory({ keepReading: candidates.length > 0 });
      if (removed > 0 && !stale()) showNotice(t('chat.removed_deleted', { count: removed }), null, 'removed');
    } catch (_e) {
      if (!stale()) showNotice(t('chat.err_load_more'), { label: t('chat.retry'), run: () => loadMoreRef.current() }, 'loadmore');
    } finally {
      if (seq === loadMoreSeqRef.current) setLoadingMore(false);
    }
  }, [hasMore, loadingMore, caseId, removeLocal, applyReactions, loadHistory, clearNotice, showNotice, t]);

  loadMoreRef.current = loadMore;

  const resync = useCallback(async () => {
    const seq = ++resyncSeqRef.current;
    const stale = () => seq !== resyncSeqRef.current || caseIdRef.current !== caseId;
    const known = messagesRef.current.filter(m => !m.is_ping && isUuid(m.id));
    const lastKnown = known.length ? known[known.length - 1] : null;
    try {
      let collected = [];
      let before = null;
      let complete = false;
      let hasMoreBefore = false;
      for (let page = 0; page < 5; page += 1) {
        const res = await api.get(`/chat/${caseId}/history?limit=100${before ? `&before_id=${before}` : ''}`);
        const batch = res.data.messages || [];
        collected = [...batch, ...collected];
        hasMoreBefore = !!res.data.has_more;
        if (!hasMoreBefore || !batch.length) { complete = true; break; }
        if (!lastKnown || new Date(batch[0].created_at) <= new Date(lastKnown.created_at)) { complete = true; break; }
        before = batch[0].id;
      }
      if (stale()) return;
      clearNotice('resync', 'history', 'loadmore');
      if (complete) {
        setMsgs(prev => mergeMessages(prev, collected, { dropMissingInWindow: true }));
      } else {
        const anchor = captureAnchor();
        setMsgs(prev => mergeMessages(prev.filter(x => x.is_ping), collected));
        setHasMore(true);
        restoreAnchor(anchor);
        showNotice(t('chat.resync_partial'), null, 'resync');
      }
      applyReactions(collected, true);
      refreshPinned(collected);
    } catch (_e) {
      if (!stale()) showNotice(t('chat.err_resync'), { label: t('chat.retry'), run: () => resyncRef.current() }, 'resync');
    }
  }, [caseId, applyReactions, refreshPinned, clearNotice, captureAnchor, restoreAnchor, showNotice, t]);

  resyncRef.current = resync;

  useEffect(() => {
    if (!socket) return undefined;
    const handler = () => { if (openRef.current) resyncRef.current(); };
    socket.on('connect', handler);
    return () => socket.off('connect', handler);
  }, [socket]);

  useEffect(() => {
    if (!socket) return undefined;
    const handler = (msg) => {
      if (msg.case_id !== caseId) return;
      setMsgs(prev => mergeMessages(prev, [msg]));
      const pending = timedOutTextRef.current;
      if (pending && msg.author_id === userId && String(msg.content || '').trim() === pending) {
        timedOutTextRef.current = null;
        setInput(cur => (cur.trim() === pending ? '' : cur));
        setDraft(cur => (cur != null && cur.trim() === pending ? null : cur));
        setReplyTo(null);
        clearNotice('send');
      }
      if (msg.author_id !== userId && (!openRef.current || !isAtBottomRef.current)) setUnread(n => n + 1);
    };
    socket.on('chat:message', handler);
    return () => socket.off('chat:message', handler);
  }, [socket, caseId, userId, clearNotice]);

  useEffect(() => {
    if (!socket) return undefined;
    const handler = (data) => {
      if (data?.case_id !== caseId) return;
      removeLocal(data.message_id);
    };
    socket.on('chat:deleted', handler);
    return () => socket.off('chat:deleted', handler);
  }, [socket, caseId, removeLocal]);

  useEffect(() => {
    if (!socket) return undefined;
    const handler = ({ caseId: cid, messageId, emoji, userId: uid, added }) => {
      if (uid === userId) return;
      if (cid && cid !== caseId) return;
      toggleReactionLocal(messageId, emoji, uid, added !== false, nameOf(uid));
    };
    socket.on('chat:react', handler);
    return () => socket.off('chat:react', handler);
  }, [socket, caseId, userId, toggleReactionLocal, nameOf]);

  const applyPin = useCallback(async (ev) => {
    const { banner, refetch } = bannerAfterPinEvent(pinnedRef.current, messagesRef.current, ev);
    setMsgs(prev => applyPinEvent(prev, ev));
    if (refetch) await refreshPinned(null);
    else setPinned(banner);
  }, [refreshPinned]);

  useEffect(() => {
    if (!socket) return undefined;
    const handler = async (ev) => {
      if (ev?.case_id !== caseId) return;
      await applyPin(ev);
    };
    socket.on('chat:pin', handler);
    return () => socket.off('chat:pin', handler);
  }, [socket, caseId, applyPin]);

  useEffect(() => {
    if (!socket) return undefined;
    const handler = (data) => {
      if (data.case_id !== caseId) return;
      if (!openRef.current || !isAtBottomRef.current) setUnread(n => n + 1);
      if (soundEnabled) playPing();
      pingSeqRef.current += 1;
      const row = {
        id: `ping-${pingSeqRef.current}`, case_id: caseId, is_ping: true,
        ping: { who: data.from_full_name || data.from_user, message: data.message },
        content: '',
        created_at: data.sent_at || new Date().toISOString(),
        author_id: null, username: data.from_user, reactions: [],
      };
      setMsgs(prev => mergeMessages(prev, [row]));
    };
    socket.on('case:ping', handler);
    return () => socket.off('case:ping', handler);
  }, [socket, caseId, soundEnabled]);

  useEffect(() => {
    if (!socket) return undefined;
    const handler = (data) => {
      if (data.case_id !== caseId) return;
      if (soundEnabled) playPing();
    };
    socket.on('chat:mention', handler);
    return () => socket.off('chat:mention', handler);
  }, [socket, caseId, soundEnabled]);

  useEffect(() => {
    if (!socket) return undefined;
    const onError = (e) => showNotice(t(serverErrorKey(e)), null, 'socket');
    const onDenied = (e) => {
      if (e?.caseId && e.caseId !== caseId) return;
      showNotice(t('chat.err_forbidden'), null, 'socket');
    };
    socket.on('chat:error', onError);
    socket.on('case:join:denied', onDenied);
    return () => {
      socket.off('chat:error', onError);
      socket.off('case:join:denied', onDenied);
    };
  }, [socket, caseId, showNotice, t]);

  useEffect(() => {
    if (!open || !isAtBottom) return;
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, open]);

  const handleScroll = (e) => {
    const el = e.currentTarget;
    updateBottom(el.scrollHeight - el.scrollTop - el.clientHeight < 60);
  };

  const [othersTyping, setOthersTyping] = useState([]);
  useEffect(() => {
    if (!socket) return undefined;
    const handler = ({ userId: uid, username }) => {
      if (uid === userId) return;
      setOthersTyping(prev => prev.find(u => u.userId === uid) ? prev : [...prev, { userId: uid, username }]);
      setTimer(`typing:${uid}`, () => setOthersTyping(prev => prev.filter(u => u.userId !== uid)), 3000);
    };
    socket.on('chat:typing', handler);
    return () => socket.off('chat:typing', handler);
  }, [socket, userId, setTimer]);

  const emitTyping = useCallback(() => {
    if (!socket || typingThrottleRef.current) return;
    socket.emit('chat:typing', { caseId, userId, username: currentUser?.username });
    typingThrottleRef.current = true;
    setTimer('typingThrottle', () => { typingThrottleRef.current = false; }, 2000);
  }, [socket, caseId, userId, currentUser, setTimer]);

  const send = useCallback(() => {
    const text = (draft != null ? draft : input).trim();
    if (!text || !socket || sending) return;
    clearNotice();
    timedOutTextRef.current = null;
    const resendAction = { label: t('chat.resend'), run: () => sendRef.current() };
    if (socket.connected === false) {
      showNotice(t('chat.err_offline'), resendAction, 'send');
      return;
    }
    setSending(true);
    let settled = false;
    setTimer('send', () => {
      if (settled) return;
      settled = true;
      setSending(false);
      timedOutTextRef.current = text;
      showNotice(t('chat.send_timeout', { seconds: SEND_ACK_TIMEOUT_MS / 1000 }), resendAction, 'send');
    }, SEND_ACK_TIMEOUT_MS);
    socket.emit('chat:send', { caseId, content: text, reply_to_id: replyTo?.id || null }, (res) => {
      if (settled || !mountedRef.current) return;
      settled = true;
      clearTimer('send');
      setSending(false);
      if (res && res.ok) {
        setInput(cur => (cur.trim() === text ? '' : cur));
        setDraft(cur => (cur != null && cur.trim() === text ? null : cur));
        setReplyTo(null);
        updateBottom(true);
        setTimer('scrollSend', () => bottomRef.current?.scrollIntoView({ behavior: 'smooth' }), 50);
      } else {
        showNotice([t('chat.send_failed'), t(serverErrorKey(res)), t('chat.text_kept')].join(' '), resendAction, 'send');
      }
    });
  }, [input, draft, socket, caseId, replyTo, sending, t, clearNotice, showNotice, setTimer, clearTimer, updateBottom]);

  sendRef.current = send;

  const handleReact = useCallback(async (messageId, emoji) => {
    const currentlyHas = reactionsMap.get(messageId)?.get(emoji)?.has(userId);
    const added = !currentlyHas;
    clearNotice('react');
    const label = nameOf(userId);
    toggleReactionLocal(messageId, emoji, userId, added, label);

    try {
      await api.post(`/chat/${caseId}/${messageId}/react`, { emoji });
    } catch (_e) {
      toggleReactionLocal(messageId, emoji, userId, !added, label);
      showNotice(t('chat.err_react'), null, 'react');
      return;
    }

    if (socket) socket.emit('chat:react', { caseId, messageId, emoji, userId, added });
  }, [reactionsMap, userId, socket, caseId, toggleReactionLocal, nameOf, clearNotice, showNotice, t]);

  const handlePin = useCallback(async (messageId) => {
    clearNotice('pin');
    try {
      const res = await api.post(`/chat/${caseId}/${messageId}/pin`);
      await applyPin({ message_id: messageId, pinned: !!res.data.pinned, pinned_by: currentUser?.username, case_id: caseId });
    } catch (_e) {
      showNotice(t('chat.err_pin'), null, 'pin');
    }
  }, [caseId, currentUser, applyPin, clearNotice, showNotice, t]);

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
    clearNotice('send');
    emitTyping();

    const cursor = e.target.selectionStart;
    const before = val.slice(0, cursor);
    const mMatch = before.match(/(?<!\w)@(\w*)$/);
    if (mMatch) {
      const q = mMatch[1].toLowerCase();

      if (q === '' && usersStateRef.current === 'failed') {
        loadUsers().then(ok => { if (!ok && mountedRef.current) showNotice(t('chat.err_users'), null, 'users'); });
      }
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
  }, [emitTyping, clearNotice, allUsers, presenceUsers, userId, loadUsers, showNotice, t]);

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
    clearNotice('delete');
    try {
      await api.delete(`/chat/${caseId}/${id}`);
      removeLocal(id);
    } catch (_e) {
      showNotice(t('chat.err_delete'), null, 'delete');
    }
  }, [caseId, removeLocal, clearNotice, showNotice, t]);

  const sendPing = useCallback(async (targetUserId = null) => {
    if (pinging) return;
    clearNotice('ping');
    setPinging(true);
    if (targetUserId) setPingingUser(targetUserId);
    try {
      const body = { message: PING_DEFAULT };
      if (targetUserId) body.target_user_id = targetUserId;
      await api.post(`/chat/${caseId}/ping`, body);
      setPingDone(true);
      setTimer('pingDone', () => { setPingDone(false); setPingingUser(null); }, 2500);
    } catch (_e) {
      setPingingUser(null);
      showNotice(t('chat.err_ping'), null, 'ping');
    }
    setPinging(false);
  }, [caseId, pinging, setTimer, clearNotice, showNotice, t]);

  useEffect(() => {
    const handler = (e) => {
      setDraft(shareDraft(e.detail || {}));
      setOpen(true);
      setTimer('focusDraft', () => textareaRef.current?.focus(), 80);
    };
    window.addEventListener('forensic:shareToChat', handler);
    return () => window.removeEventListener('forensic:shareToChat', handler);
  }, [setTimer]);

  const scrollToMsg = useCallback((msgId) => {
    const el = document.getElementById(`msg-${msgId}`);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      if (highlightRef.current && highlightRef.current !== el) highlightRef.current.style.outline = 'none';
      highlightRef.current = el;
      el.style.outline = '2px solid color-mix(in srgb, var(--fl-accent) 38%, transparent)';
      setTimer('highlight', () => { el.style.outline = 'none'; }, 1500);
    }
  }, [setTimer]);

  const filtered = searchQuery
    ? messages.filter(m => (m.content || '').toLowerCase().includes(searchQuery.toLowerCase()))
    : messages;

  const items = [];
  let lastDay = null;
  const GROUP_MS = 4 * 60 * 1000;
  for (let i = 0; i < filtered.length; i++) {
    const msg = filtered[i];
    const day = dayKeyUtc(msg.created_at);
    if (day !== lastDay) { items.push({ type: 'sep', day: `${formatDayUtc(msg.created_at, locale)} UTC`, key: day }); lastDay = day; }
    const prev = filtered[i - 1];
    const next = filtered[i + 1];
    const hideHeader = !msg.is_ping && prev && !prev.is_ping &&
      prev.author_id === msg.author_id &&
      new Date(msg.created_at) - new Date(prev.created_at) < GROUP_MS;
    const groupContinues = !msg.is_ping && next && !next.is_ping &&
      next.author_id === msg.author_id &&
      dayKeyUtc(next.created_at) === day &&
      new Date(next.created_at) - new Date(msg.created_at) < GROUP_MS;
    items.push({ type: 'msg', msg, hideHeader: !!hideHeader, groupEnd: !groupContinues });
  }

  const activeInput = draft != null ? draft : input;
  const canSend = !!activeInput.trim() && !sending && !!socket;

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

  const jumpLabel = unread > 0 ? t('chat.jump_to_bottom_unread', { count: unread }) : t('chat.jump_to_bottom');

  const noticeBar = notice && (
    <div className="fl-chat-notice" role="alert">
      <span className="fl-chat-notice-text">{notice.text}</span>
      {notice.action && (
        <button type="button" className="fl-btn fl-btn-secondary fl-btn-xs" onClick={() => { notice.action.run(); focusComposer(); }}>
          {notice.action.label}
        </button>
      )}
      <button type="button" className="fl-chat-notice-close" aria-label={t('chat.dismiss')} title={t('chat.dismiss')} onClick={() => { clearNotice(); focusComposer(); }}>
        <X size={12} />
      </button>
    </div>
  );

  if (hidden) return null;
  return (
    <>
      <style>{GLOBAL_STYLE}</style>

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
          <span className="fl-chat-badge fl-chat-badge--launcher">
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
              {noticeBar}
              <div style={{ padding: '8px 10px', borderTop: '1px solid var(--fl-border)', display: 'flex', gap: 6, alignItems: 'flex-end', flexShrink: 0 }}>
                <textarea
                  ref={aiInputRef}
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
              data-testid="chat-scroll"
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
                      : t('chat.load_more')}
                  </button>
                </div>
              )}

              {loading && (
                <div className="fl-chat-loading" role="status">
                  <Loader2 size={20} color="var(--fl-accent)" style={{ animation: 'spin 1s linear infinite' }} />
                  <span>{t('chat.loading')}</span>
                </div>
              )}

              {!loading && loadError && (
                <div className="fl-chat-error" role="alert" data-testid="chat-history-error">
                  <span>{t('chat.history_error')}</span>
                  <button type="button" className="fl-btn fl-btn-secondary fl-btn-xs" onClick={loadHistory}>
                    {t('chat.retry')}
                  </button>
                </div>
              )}

              {!loading && !loadError && messages.length === 0 && (
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
                  ? <DaySep key={`sep-${item.key}-${i}`} date={item.day} />
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
                      locale={locale}
                      onCopyFailed={notifyCopyFailed}
                    />
              )}
              <div ref={bottomRef} />
            </div>

            
            {!isAtBottom && (
              <button
                data-testid="chat-jump"
                aria-label={jumpLabel}
                onClick={() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); updateBottom(true); }}
                title={jumpLabel}
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
                  <span data-testid="chat-jump-count" className="fl-chat-badge fl-chat-badge--jump" aria-hidden="true">
                    {unread > 99 ? '99+' : unread}
                  </span>
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
              <button onClick={() => { setDraft(null); clearNotice('send'); }}
                style={{ position: 'absolute', top: 4, right: 6, background: 'none',
                  border: 'none', color: 'var(--fl-dim)', cursor: 'pointer', fontSize: 11 }}>
                ✕
              </button>
            </div>
          )}

          {noticeBar}

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
                ? e => { setDraft(e.target.value); clearNotice('send'); }
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
              aria-label={t(sending ? 'chat.sending' : 'chat.send')}
              style={{
                background: canSend ? 'var(--fl-accent)' : 'var(--fl-panel)',
                border: 'none', borderRadius: 8, padding: '8px 10px',
                cursor: canSend ? 'pointer' : 'default',
                display: 'flex', alignItems: 'center', color: '#fff',
                flexShrink: 0,
              }}
            >
              {sending ? <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> : <Send size={14} />}
            </button>
          </div>

          </>}
        </div>
      )}
    </>
  );
}
