import { useState, useEffect, useCallback } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { LayoutDashboard, FolderOpen, Search, Users, LogOut, ChevronLeft, ChevronRight, Crosshair, Settings, BookOpen, Sun, Moon, Globe, Brain, CalendarDays, MessageSquarePlus, MessageSquare, X, Send, Terminal, Activity, Library, ListChecks, SlidersHorizontal, Inbox } from 'lucide-react';
import Modal from './ui/Modal';
import HeimdallLogo from './ui/HeimdallLogo';
import { useTheme } from '../utils/theme';
import { usePreferences } from '../utils/preferences';
import { casesAPI, triageAPI } from '../utils/api';
import FeedbackMyRequests from './FeedbackMyRequests';
import { useSocket } from '../hooks/useSocket';
import { useToast } from './ui/Toast';
import CommandPalette from './ui/CommandPalette';
import GlobalAiChat from './GlobalAiChat';
import apiClient from '../utils/api';
import { useTranslation } from 'react-i18next';

export default function Layout({ user, onLogout, onTourStart, children }) {
  const [collapsed, setCollapsed] = useState(false);
  const [cmdOpen, setCmdOpen] = useState(false);
  const [urgentCount, setUrgentCount] = useState(0);
  const [triageOpen, setTriageOpen] = useState(0);
  const [zebra, setZebra] = useState(() => localStorage.getItem('fl_zebra') === '1');
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const [myRequestsOpen, setMyRequestsOpen] = useState(false);
  const [fbForm, setFbForm] = useState({ type: 'bug', title: '', description: '' });
  const [fbSending, setFbSending] = useState(false);
  const { prefs, updatePref } = usePreferences();
  const { t } = useTranslation();
  const location = useLocation();
  const navigate = useNavigate();
  const T = useTheme();

  useEffect(() => {
    document.body.classList.toggle('fl-zebra', zebra);
    localStorage.setItem('fl_zebra', zebra ? '1' : '0');
  }, [zebra]);
  const { socket } = useSocket();
  const { toast } = useToast();

  useEffect(() => {
    if (!socket) return;
    const handler = (notif) => {
      if (notif.status === 'done')
        toast.success(notif.message, 6000);
      else
        toast.error(notif.message, 8000);
    };
    socket.on('notification:job_done', handler);
    return () => socket.off('notification:job_done', handler);
  }, [socket, toast]);

  useEffect(() => {
    if (!socket) return;
    const handler = (data) => {
      const who = data.from_full_name || data.from_user || '?';
      const msg = data.target_user_id
        ? t('layout.ping_no_case', { who })
        : t('layout.ping_on_case', { who });
      toast.info(msg, 4000);
    };
    socket.on('case:ping', handler);
    return () => socket.off('case:ping', handler);
  }, [socket, toast]);

  useEffect(() => {
    function fetchDeadlines() {
      casesAPI.deadlines()
        .then(r => {
          const urgent = (r.data.deadlines || []).filter(d => d.hours_remaining < 48);
          setUrgentCount(urgent.length);
        })
        .catch(() => {});
      triageAPI.alertStats()
        .then(r => setTriageOpen(r.data?.open || 0))
        .catch(() => {});
    }
    fetchDeadlines();
    const interval = setInterval(fetchDeadlines, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    function onKey(e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        setCmdOpen(o => !o);
      }
    }
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  const navItems = [
    { path: '/',                    label: t('nav.dashboard'),    icon: LayoutDashboard },
    { path: '/triage',              label: t('nav.triage'),       icon: Inbox, badge: triageOpen > 0 ? triageOpen : null },
    { path: '/cases',               label: t('nav.cases'),        icon: FolderOpen },
    // IOCs are admin-managed. Threat Hunting now lives inside each collection (evidence tab);
    // rules are configured from the Settings panel.
    ...(user.role === 'admin' ? [
      { path: '/iocs',              label: t('nav.iocs'),         icon: Crosshair },
    ] : []),
    { path: '/collection-agent',    label: t('nav.collection'),   icon: Terminal },
    { path: '/documentation',       label: t('nav.documentation'), icon: Library },
    { path: '/calendar',            label: t('nav.calendar'),     icon: CalendarDays, badge: urgentCount > 0 ? urgentCount : null },
    { path: '/settings',           label: t('nav.settings'),     icon: SlidersHorizontal },
    ...(user.role === 'admin' ? [{ path: '/admin', label: t('nav.operations'), icon: Activity }] : []),
  ];

  const isActive = (path) => location.pathname === path || (path !== '/' && location.pathname.startsWith(path));

  const sendFeedback = useCallback(async () => {
    if (!fbForm.description.trim()) return;
    setFbSending(true);
    try {
      await apiClient.post('/feedback', { ...fbForm, page_url: window.location.href });
      toast.success(t('common.success'));
      setFeedbackOpen(false);
      setFbForm({ type: 'bug', title: '', description: '' });
    } catch {
      toast.error(t('common.error'));
    } finally {
      setFbSending(false);
    }
  }, [fbForm, toast]);

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: T.bg }}>
      <aside
        className="flex flex-col flex-shrink-0 transition-all duration-300"
        style={{ width: collapsed ? 56 : 220, background: T.panel, borderRight: `1px solid ${T.border}` }}
      >
        
        <div className="flex items-center gap-2.5 px-4 py-4" style={{ borderBottom: `1px solid ${T.border}`, minHeight: 54 }}>
          <HeimdallLogo size={22} id="sidebar" />
          {!collapsed && (
            <span style={{
              fontFamily: 'var(--f-display, "Space Grotesk", "Inter", sans-serif)',
              fontSize: 13,
              fontWeight: 500,
              letterSpacing: '0.18em',
              color: 'var(--fl-text)',
            }}>
              HEIMDALL
            </span>
          )}
        </div>

        <nav className="flex-1 py-3 px-2 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const active = !item.external && isActive(item.path);
            const sharedStyle = {
              background: active ? 'color-mix(in srgb, var(--fl-accent) 10%, transparent)' : 'transparent',
              color: active ? 'var(--fl-text)' : 'var(--fl-muted)',
              paddingLeft: collapsed ? 0 : 12,
              paddingRight: collapsed ? 0 : 12,
              justifyContent: collapsed ? 'center' : 'flex-start',
              fontFamily: 'var(--f-ui, "Inter", sans-serif)',
              fontSize: 12.5,
              fontWeight: active ? 500 : 400,
              letterSpacing: '-0.005em',
              transition: 'background 0.12s ease, color 0.12s ease',
            };
            const sharedClass = "flex items-center gap-3 py-2 rounded-lg";
            const onEnter = (e) => { if (!active) { e.currentTarget.style.background = 'var(--fl-card)'; e.currentTarget.style.color = 'var(--fl-dim)'; } };
            const onLeave = (e) => { if (!active) { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--fl-muted)'; } };
            // Active = accent icon (the signal) + tinted pill — no colored side-bar (charter).
            const iconStyle = { flexShrink: 0, color: active ? 'var(--fl-accent)' : 'currentColor', transition: 'color 0.12s ease' };
            if (item.external) {
              return (
                <a
                  key={item.path}
                  href={item.path}
                  target="_blank"
                  rel="noopener noreferrer"
                  title={collapsed ? item.label : undefined}
                  className={sharedClass}
                  style={sharedStyle}
                  data-tour={item.path}
                  onMouseEnter={onEnter}
                  onMouseLeave={onLeave}
                >
                  <item.icon size={16} style={iconStyle} />
                  {!collapsed && <span>{item.label}</span>}
                </a>
              );
            }
            return (
              <Link
                key={item.path}
                to={item.path}
                title={collapsed ? item.label : undefined}
                className={sharedClass}
                style={sharedStyle}
                data-tour={item.path}
                onMouseEnter={onEnter}
                onMouseLeave={onLeave}
              >
                <div className="relative" style={{ flexShrink: 0, display: 'flex' }}>
                  <item.icon size={16} style={iconStyle} />
                  {item.badge && (
                    <span className="absolute -top-1.5 -right-1.5 min-w-4 h-4 flex items-center justify-center rounded-full text-white font-bold"
                      style={{ background: 'var(--fl-danger)', fontSize: 9, lineHeight: 1, padding: '0 3px' }}>
                      {item.badge}
                    </span>
                  )}
                </div>
                {!collapsed && (
                  <span className="flex-1 flex items-center justify-between">
                    {item.label}
                    {item.badge && (
                      <span className="ml-1 min-w-5 h-5 flex items-center justify-center rounded-full text-white font-bold"
                        style={{ background: 'var(--fl-danger)', fontSize: 10, padding: '0 4px' }}>
                        {item.badge}
                      </span>
                    )}
                  </span>
                )}
              </Link>
            );
          })}
        </nav>

        <div style={{ padding: '6px 10px' }}>
          <button
            onClick={() => setCmdOpen(true)}
            title={t('ui.command_bar')}
            style={{
              width: '100%', display: 'flex', alignItems: 'center', gap: 8,
              padding: collapsed ? '6px' : '6px 10px',
              justifyContent: collapsed ? 'center' : 'flex-start',
              background: `color-mix(in srgb, ${T.accent} 6%, transparent)`, border: `1px solid color-mix(in srgb, ${T.accent} 15%, transparent)`,
              borderRadius: 6, cursor: 'pointer', color: 'var(--fl-dim)',
              transition: 'all 0.15s',
            }}
          >
            <Search size={13} style={{ flexShrink: 0, color: 'var(--fl-accent)' }} />
            {!collapsed && (
              <>
                <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, flex: 1, textAlign: 'left', color: 'var(--fl-dim)' }}>{t('nav.search')}</span>
                <kbd style={{ fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', color: 'var(--fl-muted)',
                  background: 'var(--fl-bg)', border: '1px solid var(--fl-border)', borderRadius: 3, padding: '1px 4px' }}>
                  ⌃K
                </kbd>
              </>
            )}
          </button>
        </div>

        <div style={{ borderTop: '1px solid var(--fl-border)' }}>

          {/* ── Mode / UTC / theme ── */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: collapsed ? '6px 8px' : '6px 10px' }}>
            {!collapsed && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, color: 'var(--fl-muted)' }}>
                  {T.mode === 'dark' ? t('dark_mode') : t('light_mode')}
                </span>
                <button
                  onClick={() => updatePref('timezone', prefs.timezone === 'utc' ? 'local' : 'utc')}
                  title={prefs.timezone === 'utc' ? 'UTC → local' : 'Local → UTC'}
                  style={{
                    fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700,
                    padding: '1px 5px', borderRadius: 3, border: 'none', cursor: 'pointer',
                    background: prefs.timezone === 'utc' ? 'color-mix(in srgb, var(--fl-accent) 18%, transparent)' : 'color-mix(in srgb, var(--fl-gold) 15%, transparent)',
                    color: prefs.timezone === 'utc' ? 'var(--fl-accent)' : 'var(--fl-gold)',
                  }}>
                  {prefs.timezone === 'utc' ? 'UTC' : 'LOCAL'}
                </button>
              </div>
            )}
            {collapsed && (
              <button
                onClick={() => updatePref('timezone', prefs.timezone === 'utc' ? 'local' : 'utc')}
                title={prefs.timezone === 'utc' ? 'UTC' : 'Local'}
                style={{
                  fontSize: 8, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700,
                  padding: '2px 4px', borderRadius: 3, border: 'none', cursor: 'pointer',
                  background: prefs.timezone === 'utc' ? 'color-mix(in srgb, var(--fl-accent) 18%, transparent)' : 'color-mix(in srgb, var(--fl-gold) 15%, transparent)',
                  color: prefs.timezone === 'utc' ? 'var(--fl-accent)' : 'var(--fl-gold)',
                  margin: '0 auto',
                }}>
                {prefs.timezone === 'utc' ? 'UTC' : 'LCL'}
              </button>
            )}
            <button onClick={T.toggle} title={t('ui.toggle_theme')}
              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 5, borderRadius: 4, color: 'var(--fl-dim)', display: 'flex', alignItems: 'center' }}>
              {T.mode === 'dark' ? <Sun size={13} /> : <Moon size={13} />}
            </button>
          </div>

          {/* ── Zebra / feedback / tour ── */}
          {!collapsed && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 2, padding: '2px 8px 4px' }}>
              <button onClick={() => setZebra(z => !z)} title="Zebra-striping"
                style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 5, padding: '4px 8px', borderRadius: 3, border: 'none', cursor: 'pointer', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10, background: zebra ? 'color-mix(in srgb, var(--fl-accent) 10%, transparent)' : 'transparent', color: zebra ? 'var(--fl-accent)' : 'var(--fl-dim)' }}>
                ≡ Zebra
              </button>
              {[
                { icon: MessageSquarePlus, fn: () => setFeedbackOpen(true),   title: t('ui.report_bug') },
                { icon: MessageSquare,    fn: () => setMyRequestsOpen(true),  title: t('ui.my_requests') },
                ...(onTourStart ? [{ icon: BookOpen, fn: onTourStart, title: t('ui.tour') }] : []),
              ].map(({ icon: Ico, fn, title: t2 }) => (
                <button key={t2} onClick={fn} title={t2}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 5, borderRadius: 3, color: 'var(--fl-dim)', display: 'flex', alignItems: 'center' }}>
                  <Ico size={12} />
                </button>
              ))}
            </div>
          )}

          {/* ── User profile ── */}
          {!collapsed && (
            <button onClick={() => navigate('/settings')}
              style={{ display: 'flex', alignItems: 'center', gap: 9, width: '100%', padding: '6px 12px 8px', background: 'none', border: 'none', cursor: 'pointer', textAlign: 'left' }}>
              <div style={{
                width: 28, height: 28, borderRadius: '50%', flexShrink: 0,
                background: `linear-gradient(135deg, ${prefs.chat_color}, color-mix(in srgb, ${prefs.chat_color} 60%, #0a0c11))`,
                border: '1px solid color-mix(in srgb, var(--fl-text) 12%, transparent)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                fontWeight: 600, fontSize: 10, color: '#fff',
                letterSpacing: '0.02em',
              }}>
                {(prefs.display_name || user.full_name || '?').split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase()}
              </div>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontFamily: 'var(--f-ui, "Inter", sans-serif)', fontSize: 12, fontWeight: 500, color: 'var(--fl-text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {prefs.display_name || user.full_name}
                </div>
                <div style={{ fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9.5, color: 'var(--fl-muted)', letterSpacing: '0.06em' }}>{user.role.toUpperCase()}</div>
              </div>
            </button>
          )}
          {collapsed && (
            <button onClick={() => navigate('/settings')} title={t('ui.my_profile')}
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: '100%', padding: '6px 0 8px', background: 'none', border: 'none', cursor: 'pointer' }}>
              <div style={{ width: 26, height: 26, borderRadius: '50%', background: prefs.chat_color, display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, fontSize: 10, color: '#fff' }}>
                {(prefs.display_name || user.full_name || '?').split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase()}
              </div>
            </button>
          )}

          {/* ── Logout ── */}
          <div style={{ padding: '2px 8px 8px' }}>
            <button onClick={onLogout} title={collapsed ? 'Logout' : undefined}
              style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%', padding: collapsed ? '6px' : '6px 10px', justifyContent: collapsed ? 'center' : 'flex-start', background: 'none', border: 'none', cursor: 'pointer', borderRadius: 3, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11, color: 'var(--fl-danger)', transition: 'background 0.12s' }}
              onMouseEnter={e => e.currentTarget.style.background = 'color-mix(in srgb, var(--fl-danger) 8%, transparent)'}
              onMouseLeave={e => e.currentTarget.style.background = 'none'}>
              <LogOut size={13} style={{ flexShrink: 0 }} />
              {!collapsed && t('logout')}
            </button>
          </div>
        </div>

        <button onClick={() => setCollapsed(!collapsed)}
          style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '8px', borderTop: '1px solid var(--fl-border)', background: 'none', cursor: 'pointer', color: 'var(--fl-subtle)', width: '100%' }}>
          {collapsed ? <ChevronRight size={13} /> : <ChevronLeft size={13} />}
        </button>
      </aside>

      <main className="flex-1 overflow-y-auto overflow-x-hidden" style={{ background: T.bg }}>
        {children}
      </main>

      {myRequestsOpen && <FeedbackMyRequests onClose={() => setMyRequestsOpen(false)} />}

      <Modal
        open={feedbackOpen}
        title={<span style={{ display: 'flex', alignItems: 'center', gap: 7 }}><MessageSquarePlus size={14} style={{ color: T.accent }} /> Feedback</span>}
        onClose={() => setFeedbackOpen(false)}
        size="sm"
      >
        <Modal.Body style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <select value={fbForm.type} onChange={e => setFbForm(f => ({ ...f, type: e.target.value }))}
            style={{ padding: '5px 8px', borderRadius: 5, fontSize: 12, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'var(--fl-card)', color: 'var(--fl-text)', border: '1px solid var(--fl-border)' }}>
            <option value="bug">🐛 Bug</option>
            <option value="suggestion">💡 Suggestion</option>
            <option value="autre">📝 {t('ui.feedback_type_other')}</option>
          </select>

          <input
            placeholder={t('ui.feedback_title_ph')}
            value={fbForm.title}
            onChange={e => setFbForm(f => ({ ...f, title: e.target.value }))}
            style={{ padding: '6px 10px', borderRadius: 5, fontSize: 12, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'var(--fl-card)', color: 'var(--fl-text)', border: '1px solid var(--fl-border)', outline: 'none' }}
          />

          <textarea
            placeholder={t('ui.feedback_description_ph')}
            value={fbForm.description}
            onChange={e => setFbForm(f => ({ ...f, description: e.target.value }))}
            rows={5}
            style={{ padding: '8px 10px', borderRadius: 5, fontSize: 12, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', background: 'var(--fl-card)', color: 'var(--fl-text)', border: '1px solid var(--fl-border)', resize: 'vertical', outline: 'none' }}
          />

        </Modal.Body>
        <Modal.Footer>
          <button
            onClick={sendFeedback}
            disabled={fbSending || !fbForm.description.trim()}
            style={{
              padding: '8px 16px', borderRadius: 6, fontSize: 12, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 600,
              background: fbForm.description.trim() ? T.accent : 'var(--fl-border)',
              color: '#fff', border: 'none', cursor: fbForm.description.trim() ? 'pointer' : 'not-allowed',
              display: 'flex', alignItems: 'center', gap: 6, justifyContent: 'center',
            }}>
            <Send size={12} /> {fbSending ? t('ui.sending') : t('workbench.send')}
          </button>
        </Modal.Footer>
      </Modal>

      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} />
      
      {!location.pathname.startsWith('/cases/') && <GlobalAiChat />}
    </div>
  );
}
