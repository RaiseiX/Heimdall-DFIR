import { useState, useEffect, useCallback } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { LayoutDashboard, FolderOpen, Search, Users, LogOut, ChevronLeft, ChevronRight, Crosshair, Settings, BookOpen, Sun, Moon, Globe, Brain, CalendarDays, MessageSquarePlus, MessageSquare, X, Send, Terminal, Activity, Library } from 'lucide-react';
import Modal from './ui/Modal';
import HeimdallLogo from './ui/HeimdallLogo';
import { useTheme } from '../utils/theme';
import { usePreferences } from '../utils/preferences';
import { casesAPI } from '../utils/api';
import FeedbackMyRequests from './FeedbackMyRequests';
import { useSocket } from '../hooks/useSocket';
import { useToast } from './ui/Toast';
import CommandPalette from './ui/CommandPalette';
import UserProfileModal from './ui/UserProfileModal';
import GlobalAiChat from './GlobalAiChat';
import apiClient from '../utils/api';
import { useTranslation } from 'react-i18next';

export default function Layout({ user, onLogout, onTourStart, children }) {
  const [collapsed, setCollapsed] = useState(false);
  const [cmdOpen, setCmdOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [urgentCount, setUrgentCount] = useState(0);
  const [zebra, setZebra] = useState(() => localStorage.getItem('fl_zebra') === '1');
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const [myRequestsOpen, setMyRequestsOpen] = useState(false);
  const [fbForm, setFbForm] = useState({ type: 'bug', title: '', description: '' });
  const [fbSending, setFbSending] = useState(false);
  const { prefs, updatePref } = usePreferences();
  const { t } = useTranslation();
  const location = useLocation();
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
        .catch(() =>  });
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
    { path: '/cases',               label: t('nav.cases'),        icon: FolderOpen },
    { path: '/iocs',                label: t('nav.iocs'),         icon: Crosshair },
      { path: '/threat-hunt',         label: t('nav.threat_hunt'),  icon: Search },
    { path: '/threat-intel',        label: t('nav.threat_intel'), icon: Globe },
    { path: '/collection-agent',    label: t('nav.collection'),   icon: Terminal },
    { path: '/documentation',       label: 'Documentation',       icon: Library },
    { path: '/calendar',            label: t('nav.calendar'),     icon: CalendarDays, badge: urgentCount > 0 ? urgentCount : null },
    { path: 'http://localhost:8888', label: t('nav.volweb'),      icon: Brain, external: true },
    ...(user.role === 'admin' ? [{ path: '/admin', label: t('nav.admin'), icon: Settings }] : []),
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
          <HeimdallLogo size={20} style={{ color: T.accent, flexShrink: 0 }} id="sidebar" />
          {!collapsed && (
            <span className="font-mono font-semibold text-sm tracking-widest" style={{ color: T.text }}>
              HEIMDALL<span style={{ color: T.accent }}> DFIR</span>
            </span>
          )}
        </div>

        <nav className="flex-1 py-3 px-2 space-y-0.5 overflow-y-auto">
          {navItems.map((item) => {
            const active = !item.external && isActive(item.path);
            const sharedStyle = {
              background: active ? `${T.accent}14` : 'transparent',
              color: active ? T.accent : T.dim,
              borderLeft: active ? `2px solid ${T.accent}` : '2px solid transparent',
              paddingLeft: active ? 10 : 12,
              paddingRight: 12,
            };
            const sharedClass = "flex items-center gap-3 py-2 rounded-md text-sm font-medium transition-colors";
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
                >
                  <item.icon size={16} style={{ flexShrink: 0 }} />
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
              >
                <div className="relative" style={{ flexShrink: 0 }}>
                  <item.icon size={16} />
                  {item.badge && (
                    <span className="absolute -top-1.5 -right-1.5 min-w-4 h-4 flex items-center justify-center rounded-full text-white font-bold"
                      style={{ background: '#ef4444', fontSize: 9, lineHeight: 1, padding: '0 3px' }}>
                      {item.badge}
                    </span>
                  )}
                </div>
                {!collapsed && (
                  <span className="flex-1 flex items-center justify-between">
                    {item.label}
                    {item.badge && (
                      <span className="ml-1 min-w-5 h-5 flex items-center justify-center rounded-full text-white font-bold"
                        style={{ background: '#ef4444', fontSize: 10, padding: '0 4px' }}>
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
            title="Barre de commande (Ctrl+K)"
            style={{
              width: '100%', display: 'flex', alignItems: 'center', gap: 8,
              padding: collapsed ? '6px' : '6px 10px',
              justifyContent: collapsed ? 'center' : 'flex-start',
              background: `${T.accent}0f`, border: `1px solid ${T.accent}26`,
              borderRadius: 6, cursor: 'pointer', color: '#7d8590',
              transition: 'all 0.15s',
            }}
          >
            <Search size={13} style={{ flexShrink: 0, color: '#4d82c0' }} />
            {!collapsed && (
              <>
                <span style={{ fontFamily: 'monospace', fontSize: 10, flex: 1, textAlign: 'left', color: '#7d8590' }}>Rechercher…</span>
                <kbd style={{ fontSize: 9, fontFamily: 'monospace', color: '#484f58',
                  background: '#0d1117', border: '1px solid #30363d', borderRadius: 3, padding: '1px 4px' }}>
                  ⌃K
                </kbd>
              </>
            )}
          </button>
        </div>

        <div style={{ borderTop: `1px solid ${T.border}` }}>
          
          <div className="flex items-center justify-between px-3 py-2">
            {!collapsed && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span className="text-xs" style={{ color: T.muted }}>
                  {T.mode === 'dark' ? t('dark_mode') : t('light_mode')}
                </span>
                
                <button
                  onClick={() => updatePref('timezone', prefs.timezone === 'utc' ? 'local' : 'utc')}
                  title={prefs.timezone === 'utc' ? 'Affichage en UTC — cliquer pour passer en heure locale' : 'Affichage en heure locale — cliquer pour passer en UTC'}
                  style={{
                    fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
                    padding: '1px 5px', borderRadius: 3, border: 'none', cursor: 'pointer',
                    background: prefs.timezone === 'utc' ? `${T.accent}2e` : `${T.gold}26`,
                    color: prefs.timezone === 'utc' ? T.accent : T.gold,
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
                  fontSize: 8, fontFamily: 'monospace', fontWeight: 700,
                  padding: '2px 4px', borderRadius: 3, border: 'none', cursor: 'pointer',
                  background: prefs.timezone === 'utc' ? `${T.accent}2e` : `${T.gold}26`,
                  color: prefs.timezone === 'utc' ? T.accent : T.gold,
                  margin: '0 auto',
                }}>
                {prefs.timezone === 'utc' ? 'UTC' : 'LCL'}
              </button>
            )}
            <button
              onClick={T.toggle}
              title="Basculer thème"
              className="p-1.5 rounded-md transition-colors"
              style={{ color: T.dim, marginLeft: collapsed ? 0 : 0 }}
            >
              {T.mode === 'dark' ? <Sun size={13} /> : <Moon size={13} />}
            </button>
          </div>

          {!collapsed && (
            <div className="px-2 pb-1 flex items-center gap-1">
              <button
                onClick={() => setZebra(z => !z)}
                title="Alterner les lignes des tableaux (zebra-striping)"
                className="flex-1 px-3 py-1.5 rounded-md text-xs font-mono flex items-center gap-2 transition-colors"
                style={{ color: zebra ? T.accent : T.dim, background: zebra ? `color-mix(in srgb, ${T.accent} 10%, transparent)` : 'transparent' }}>
                ≡ Zebra
              </button>
              <button onClick={() => setFeedbackOpen(true)}
                title="Signaler un bug / faire une suggestion"
                className="px-2 py-1.5 rounded-md text-xs font-mono flex items-center transition-colors"
                style={{ color: T.dim }}>
                <MessageSquarePlus size={12} />
              </button>
              <button onClick={() => setMyRequestsOpen(true)}
                title="Voir mes demandes"
                className="px-2 py-1.5 rounded-md text-xs font-mono flex items-center transition-colors"
                style={{ color: T.dim }}>
                <MessageSquare size={12} />
              </button>
              {onTourStart && (
                <button onClick={onTourStart}
                  className="px-2 py-1.5 rounded-md text-xs font-mono flex items-center transition-colors"
                  style={{ color: T.dim }}>
                  <BookOpen size={12} />
                </button>
              )}
            </div>
          )}

          {!collapsed && (
            <button
              onClick={() => setProfileOpen(true)}
              style={{
                display: 'flex', alignItems: 'center', gap: 8,
                width: '100%', padding: '6px 16px 8px',
                background: 'none', border: 'none', cursor: 'pointer',
                textAlign: 'left',
              }}>
              
              <div style={{
                width: 26, height: 26, borderRadius: '50%', flexShrink: 0,
                background: prefs.chat_color,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontFamily: 'monospace', fontWeight: 700, fontSize: 10, color: '#fff',
              }}>
                {(prefs.display_name || user.full_name || '?')
                  .split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase()}
              </div>
              <div>
                <div className="text-sm font-medium" style={{ color: T.text }}>
                  {prefs.display_name || user.full_name}
                </div>
                <div className="text-xs font-mono" style={{ color: T.muted }}>{user.role.toUpperCase()}</div>
              </div>
            </button>
          )}
          {collapsed && (
            <button
              onClick={() => setProfileOpen(true)}
              title="Mon profil"
              style={{
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                width: '100%', padding: '6px 0 8px',
                background: 'none', border: 'none', cursor: 'pointer',
              }}>
              <div style={{
                width: 26, height: 26, borderRadius: '50%',
                background: prefs.chat_color,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontFamily: 'monospace', fontWeight: 700, fontSize: 10, color: '#fff',
              }}>
                {(prefs.display_name || user.full_name || '?')
                  .split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase()}
              </div>
            </button>
          )}

          <div className="px-2 pb-2">
            <button
              onClick={onLogout}
              title={collapsed ? 'Déconnexion' : undefined}
              className="flex items-center gap-2 w-full px-3 py-2 rounded-md text-sm transition-colors"
              style={{ color: T.danger }}
            >
              <LogOut size={15} style={{ flexShrink: 0 }} />
              {!collapsed && t('logout')}
            </button>
          </div>
        </div>

        <button
          onClick={() => setCollapsed(!collapsed)}
          className="flex items-center justify-center py-2.5 transition-colors"
          style={{ borderTop: `1px solid ${T.border}`, color: T.muted }}
        >
          {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
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
            style={{ padding: '5px 8px', borderRadius: 5, fontSize: 12, fontFamily: 'monospace', background: 'var(--fl-card)', color: 'var(--fl-text)', border: '1px solid var(--fl-border)' }}>
            <option value="bug">🐛 Bug</option>
            <option value="suggestion">💡 Suggestion</option>
            <option value="autre">📝 Autre</option>
          </select>

          <input
            placeholder="Titre (optionnel)"
            value={fbForm.title}
            onChange={e => setFbForm(f => ({ ...f, title: e.target.value }))}
            style={{ padding: '6px 10px', borderRadius: 5, fontSize: 12, fontFamily: 'monospace', background: 'var(--fl-card)', color: 'var(--fl-text)', border: '1px solid var(--fl-border)', outline: 'none' }}
          />

          <textarea
            placeholder="Description du problème ou de la suggestion…"
            value={fbForm.description}
            onChange={e => setFbForm(f => ({ ...f, description: e.target.value }))}
            rows={5}
            style={{ padding: '8px 10px', borderRadius: 5, fontSize: 12, fontFamily: 'monospace', background: 'var(--fl-card)', color: 'var(--fl-text)', border: '1px solid var(--fl-border)', resize: 'vertical', outline: 'none' }}
          />

        </Modal.Body>
        <Modal.Footer>
          <button
            onClick={sendFeedback}
            disabled={fbSending || !fbForm.description.trim()}
            style={{
              padding: '8px 16px', borderRadius: 6, fontSize: 12, fontFamily: 'monospace', fontWeight: 600,
              background: fbForm.description.trim() ? T.accent : 'var(--fl-border)',
              color: '#fff', border: 'none', cursor: fbForm.description.trim() ? 'pointer' : 'not-allowed',
              display: 'flex', alignItems: 'center', gap: 6, justifyContent: 'center',
            }}>
            <Send size={12} /> {fbSending ? 'Envoi…' : 'Envoyer'}
          </button>
        </Modal.Footer>
      </Modal>

      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} />
      {profileOpen && <UserProfileModal user={user} onClose={() => setProfileOpen(false)} />}
      
      {!location.pathname.startsWith('/cases/') && <GlobalAiChat />}
    </div>
  );
}
