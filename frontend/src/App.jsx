import { useState, useEffect } from 'react';
import { Routes, Route, Navigate, useNavigate, useParams } from 'react-router-dom';
import { ThemeProvider } from './utils/theme';
import { ToastProvider } from './components/ui/Toast';
import { PreferencesProvider, usePreferences } from './utils/preferences';
import { authAPI, settingsAPI } from './utils/api';
import i18n from './i18n/index.js';
import { I18nextProvider } from 'react-i18next';
import Layout from './components/Layout';
import GuidedTour from './components/GuidedTour';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import CasesPage from './pages/CasesPage';
import TriagePage from './pages/TriagePage';
import SettingsPage from './pages/SettingsPage';
import CaseDetailPage from './pages/CaseDetailPage';
import CaseShell from './pages/CaseShell';
import CollectionPage from './pages/CollectionPage';
import CollectionLayout from './pages/CollectionLayout';
import SuperTimelinePage from './pages/SuperTimelinePage';
import ParserLogsPage from './pages/ParserLogsPage';
import IOCsPage from './pages/IOCsPage';
import ThreatHuntPage from './pages/ThreatHuntPage';
import ThreatIntelPage from './pages/ThreatIntelPage';
import CaseIntelligencePage from './pages/CaseIntelligencePage';
import GlobalNetworkMapPage from './pages/GlobalNetworkMapPage';
import AdminPage from './pages/AdminPage';
import ParsedDataPage from './pages/ParsedDataPage';
import CalendarPage from './pages/CalendarPage';
import CollectionAgentPage from './pages/CollectionAgentPage';
import DocumentationPage from './pages/DocumentationPage';

function NetworkMapRedirect() {
  const { caseId } = useParams();
  return <Navigate to={`/cases/${caseId}/graph?view=network`} replace />;
}

function AppInner() {
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem('heimdall_user');
    return saved ? JSON.parse(saved) : null;
  });
  const [showTour, setShowTour] = useState(false);
  const navigate = useNavigate();
  const { loadFromBackend } = usePreferences();

  useEffect(() => {
    if (user && !localStorage.getItem('heimdall_tour_done')) {
      setTimeout(() => setShowTour(true), 800);
    }
    if (user) {
      authAPI.me().then(r => {
        if (r.data?.preferences) loadFromBackend(r.data.preferences);
      }).catch(() => {});
    }
  }, [user]);

  const login = (userData, token, refreshToken) => {
    localStorage.setItem('heimdall_token', token);
    localStorage.setItem('heimdall_user', JSON.stringify(userData));
    if (refreshToken) localStorage.setItem('heimdall_refresh_token', refreshToken);
    if (userData.preferences) loadFromBackend(userData.preferences);
    setUser(userData);
    navigate('/');
  };

  const logout = async () => {
    try {
      const rt = localStorage.getItem('heimdall_refresh_token');
      if (rt) await authAPI.logout(rt).catch(() => {});
    } catch {}
    localStorage.removeItem('heimdall_token');
    localStorage.removeItem('heimdall_refresh_token');
    localStorage.removeItem('heimdall_user');
    setUser(null);
    navigate('/login');
  };

  const closeTour = () => {
    setShowTour(false);
    localStorage.setItem('heimdall_tour_done', '1');
  };

  // Auto-logout on inactivity, driven by the admin security policy (0 = disabled).
  useEffect(() => {
    if (!user) return;
    let timer = null;
    let cancelled = false;
    let cleanup = null;
    settingsAPI.getSecurityClient().then(r => {
      const mins = Number(r.data?.inactivityTimeoutMin) || 0;
      if (cancelled || mins <= 0) return;
      const ms = mins * 60_000;
      const reset = () => { if (timer) clearTimeout(timer); timer = setTimeout(() => logout(), ms); };
      const events = ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart'];
      events.forEach(e => window.addEventListener(e, reset, { passive: true }));
      reset();
      cleanup = () => { events.forEach(e => window.removeEventListener(e, reset)); if (timer) clearTimeout(timer); };
    }).catch(() => {});
    return () => { cancelled = true; if (cleanup) cleanup(); else if (timer) clearTimeout(timer); };
  }, [user]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <ThemeProvider>
      <ToastProvider>
        {!user ? (
          <LoginPage onLogin={login} />
        ) : (
          <>
            {showTour && <GuidedTour onClose={closeTour} />}
            <Layout user={user} onLogout={logout} onTourStart={() => setShowTour(true)}>
              <Routes>
                <Route path="/" element={<DashboardPage />} />
                <Route path="/cases" element={<CasesPage user={user} />} />
                <Route path="/triage" element={<TriagePage />} />
                <Route path="/settings" element={<SettingsPage />} />
                <Route path="/cases/:id" element={<CaseShell user={user} />}>
                  <Route index element={<Navigate to="evidence" replace />} />
                  <Route path="graph" element={<CaseIntelligencePage />} />
                  <Route path="collections/:collectionId" element={<CollectionLayout />}>
                    <Route index element={<Navigate to="evidence" replace />} />
                    <Route path="timeline" element={<SuperTimelinePage />} />
                    <Route path="logs" element={<ParserLogsPage />} />
                    <Route path=":tab" element={<CaseDetailPage user={user} />} />
                  </Route>
                  <Route path="global-map" element={<GlobalNetworkMapPage />} />
                  <Route path=":tab" element={<CaseDetailPage user={user} />} />
                </Route>
                <Route path="/collection" element={<CollectionPage />} />
                <Route path="/super-timeline" element={<SuperTimelinePage />} />
                <Route path="/parsed-data" element={<ParsedDataPage />} />
                {/* IOCs & Threat Hunting are admin-only; analysts hunt within a case. */}
                <Route path="/iocs" element={user.role === 'admin' ? <IOCsPage /> : <Navigate to="/" replace />} />
                <Route path="/threat-hunt" element={user.role === 'admin' ? <Navigate to="/threat-hunt/yara-rules" replace /> : <Navigate to="/" replace />} />
                <Route path="/threat-hunt/:tab" element={user.role === 'admin' ? <ThreatHuntPage /> : <Navigate to="/" replace />} />
                <Route path="/threat-intel" element={<Navigate to="/threat-intel/feeds" replace />} />
                <Route path="/threat-intel/:tab" element={<ThreatIntelPage />} />
                <Route path="/network/:caseId" element={<NetworkMapRedirect />} />
                <Route path="/calendar" element={<CalendarPage />} />
                <Route path="/collection-agent" element={<CollectionAgentPage />} />
                <Route path="/documentation" element={<DocumentationPage />} />
                {user.role === 'admin' && <Route path="/admin" element={<Navigate to="/admin/health" replace />} />}
                {/* Account/Audit/RGPD/SLA were moved to Settings — redirect legacy /admin URLs. */}
                {user.role === 'admin' && <Route path="/admin/users" element={<Navigate to="/settings" replace />} />}
                {user.role === 'admin' && <Route path="/admin/audit" element={<Navigate to="/settings" replace />} />}
                {user.role === 'admin' && <Route path="/admin/rgpd" element={<Navigate to="/settings" replace />} />}
                {user.role === 'admin' && <Route path="/admin/settings" element={<Navigate to="/settings" replace />} />}
                {user.role === 'admin' && <Route path="/admin/:tab" element={<AdminPage />} />}
                <Route path="*" element={<Navigate to="/" />} />
              </Routes>
            </Layout>
          </>
        )}
      </ToastProvider>
    </ThemeProvider>
  );
}

export default function App() {
  return (
    <I18nextProvider i18n={i18n}>
      <PreferencesProvider>
        <AppInner />
      </PreferencesProvider>
    </I18nextProvider>
  );
}
