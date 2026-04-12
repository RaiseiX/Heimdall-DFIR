import { useState, useEffect } from 'react';
import { Routes, Route, Navigate, useNavigate, useParams } from 'react-router-dom';
import { ThemeProvider } from './utils/theme';
import { ToastProvider } from './components/ui/Toast';
import { PreferencesProvider, usePreferences } from './utils/preferences';
import { authAPI } from './utils/api';
import i18n from './i18n/index.js';
import { I18nextProvider } from 'react-i18next';
import Layout from './components/Layout';
import GuidedTour from './components/GuidedTour';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import CasesPage from './pages/CasesPage';
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

function NetworkMapRedirect() {
  const { caseId } = useParams();
  return <Navigate to={`/cases/${caseId}/graph?view=network`} replace />;
}
import AdminPage from './pages/AdminPage';
import ParsedDataPage from './pages/ParsedDataPage';
import CalendarPage from './pages/CalendarPage';
import CollectionAgentPage from './pages/CollectionAgentPage';
import DocumentationPage from './pages/DocumentationPage';

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
                <Route path="/cases/:id" element={<CaseShell user={user} />}>
                  <Route index element={<Navigate to="evidence" replace />} />
                  <Route path="graph" element={<CaseIntelligencePage />} />
                  <Route path="collections/:collectionId" element={<CollectionLayout />}>
                    <Route index element={<Navigate to="evidence" replace />} />
                    <Route path="timeline" element={<SuperTimelinePage />} />
                    <Route path="logs" element={<ParserLogsPage />} />
                    <Route path=":tab" element={<CaseDetailPage user={user} />} />
                  </Route>
                  <Route path=":tab" element={<CaseDetailPage user={user} />} />
                </Route>
                <Route path="/collection" element={<CollectionPage />} />
                <Route path="/super-timeline" element={<SuperTimelinePage />} />
                <Route path="/parsed-data" element={<ParsedDataPage />} />
                <Route path="/iocs" element={<IOCsPage />} />
                <Route path="/threat-hunt" element={<Navigate to="/threat-hunt/yara-rules" replace />} />
                <Route path="/threat-hunt/:tab" element={<ThreatHuntPage />} />
                <Route path="/threat-intel" element={<Navigate to="/threat-intel/feeds" replace />} />
                <Route path="/threat-intel/:tab" element={<ThreatIntelPage />} />
                <Route path="/network/:caseId" element={<NetworkMapRedirect />} />
                <Route path="/calendar" element={<CalendarPage />} />
                <Route path="/collection-agent" element={<CollectionAgentPage />} />
                <Route path="/documentation" element={<DocumentationPage />} />
                {user.role === 'admin' && <Route path="/admin" element={<Navigate to="/admin/users" replace />} />}
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
