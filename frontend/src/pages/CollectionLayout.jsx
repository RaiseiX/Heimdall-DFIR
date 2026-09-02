import { useState, useEffect } from 'react';
import { useParams, NavLink, Outlet, useOutletContext, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  FolderOpen, Clock, Crosshair, AlertTriangle, Network,
  Shield, ScrollText, FileText, Activity, FlaskConical, ChevronLeft,
  Brain, ExternalLink, ListChecks,
} from 'lucide-react';
import UiIcon from '../components/ui/Icon';
import { evidenceAPI } from '../utils/api';
import CaseIntelligencePage from './CaseIntelligencePage';
import HayabusaPage from './HayabusaPage';
import CyberChefPage from './CyberChefPage';
import CollectionThreatHuntTab from '../components/collection/CollectionThreatHuntTab';
import CollectionOverview from '../components/collection/CollectionOverview';
import { resolveCollectionPane } from './collectionPane';

export default function CollectionLayout() {
  const { t } = useTranslation();
  const { id, collectionId, tab: collectionTab } = useParams();
  const pane = resolveCollectionPane(collectionTab);
  const shellCtx = useOutletContext() || {};
  const navigate = useNavigate();
  const [collName, setCollName] = useState('');

  const base = `/cases/${id}/collections/${collectionId}`;
  const volwebUrl = `${window.location.protocol}//${window.location.hostname}:8888`;

  useEffect(() => {
    if (!id || !collectionId) return;
    evidenceAPI.list(id)
      .then(r => { const ev = (r.data || []).find(e => e.id === collectionId); if (ev) setCollName(ev.name || ''); })
      .catch(() => {});
  }, [id, collectionId]);

  const tabSt = (isActive, accent = 'var(--fl-accent)') => ({
    display: 'flex', alignItems: 'center', gap: 6,
    padding: '0 11px', height: 27, alignSelf: 'center',
    fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10.5,
    fontWeight: isActive ? 600 : 400,
    outline: 'none', cursor: 'pointer', borderRadius: 7,
    background: isActive ? `color-mix(in srgb, ${accent} 14%, transparent)` : 'transparent',
    border: `1px solid ${isActive ? `color-mix(in srgb, ${accent} 28%, transparent)` : 'transparent'}`,
    color: isActive ? accent : 'var(--fl-dim)',
    transition: 'all 0.12s',
    flexShrink: 0,
    whiteSpace: 'nowrap',
    textDecoration: 'none',
  });
  const tabHoverIn  = e => { if (e.currentTarget.getAttribute('aria-current') !== 'page') { e.currentTarget.style.background = 'var(--fl-card)'; e.currentTarget.style.color = 'var(--fl-dim)'; } };
  const tabHoverOut = e => { if (e.currentTarget.getAttribute('aria-current') !== 'page') { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--fl-subtle)'; } };

  const TABS = [
    { id: 'evidence',   label: 'Evidence',    icon: FolderOpen },
    { id: 'iocs',       label: 'IOCs',        icon: Crosshair },
    { id: 'detections', label: 'Detections',   icon: AlertTriangle },
    { id: 'network',    label: 'Network',      icon: Network },
    { id: 'mitre',      label: 'MITRE',       icon: Shield },
    { id: 'audit',      label: 'Audit',       icon: ScrollText },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>

      <div style={{
        position: 'sticky', top: 36, zIndex: 101,
        display: 'flex', alignItems: 'center',
        height: 36, padding: '0 10px',
        background: 'var(--fl-bg)',
        borderBottom: '1px solid var(--fl-border)',
        flexShrink: 0,
        overflowX: 'auto',
        scrollbarWidth: 'none',
        gap: 2,
      }}>

        <button onClick={() => navigate(`/cases/${id}/evidence`)} title="Back to case evidence"
          style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-muted)', padding: '0 6px', height: '100%', flexShrink: 0 }}
          onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-dim)'; }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; }}>
          <ChevronLeft size={13} />
        </button>
        <span style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '0 8px', flexShrink: 0, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 9.5, color: 'var(--fl-dim)', whiteSpace: 'nowrap', maxWidth: 420, overflow: 'hidden', textOverflow: 'ellipsis' }} title={collName || 'Collection'}>
          <UiIcon name="case" size={11} style={{ color: 'var(--fl-purple)', flexShrink: 0 }} />
          {collName || 'Collection'}
        </span>
        <span style={{ width: 1, height: 16, background: 'var(--fl-border)', flexShrink: 0, margin: '0 6px' }} />

        {TABS.map(({ id: tid, label, icon: Icon }) => (
          <NavLink
            key={tid}
            to={`${base}/${tid}`}
            style={({ isActive }) => tabSt(isActive)}
            onMouseEnter={tabHoverIn} onMouseLeave={tabHoverOut}
          >
            <Icon size={12} />
            {label}
          </NavLink>
        ))}

        <span style={{ width: 1, height: 16, background: 'var(--fl-border)', flexShrink: 0, margin: '0 4px' }} />

        <NavLink
          to={`${base}/timeline`}
          style={({ isActive }) => tabSt(isActive, 'var(--fl-ok)')}
          onMouseEnter={tabHoverIn} onMouseLeave={tabHoverOut}
        >
          <Clock size={12} />
          Super Timeline
        </NavLink>

        <NavLink
          to={`${base}/logs`}
          style={({ isActive }) => tabSt(isActive)}
          onMouseEnter={tabHoverIn} onMouseLeave={tabHoverOut}
        >
          <FileText size={12} />
          Logs
        </NavLink>

        <NavLink
          to={`${base}/coverage`}
          style={({ isActive }) => tabSt(isActive)}
          onMouseEnter={tabHoverIn} onMouseLeave={tabHoverOut}
        >
          <ListChecks size={12} />
          {t('coverage.tab')}
        </NavLink>

        <span style={{ width: 1, height: 16, background: 'var(--fl-border)', flexShrink: 0, margin: '0 4px' }} />

        <NavLink
          to={`${base}/hayabusa`}
          style={({ isActive }) => tabSt(isActive, 'var(--fl-danger)')}
          onMouseEnter={tabHoverIn} onMouseLeave={tabHoverOut}
        >
          <Activity size={12} />
          Hayabusa
        </NavLink>

        <NavLink
          to={`${base}/cyberchef`}
          style={({ isActive }) => tabSt(isActive)}
          onMouseEnter={tabHoverIn} onMouseLeave={tabHoverOut}
        >
          <FlaskConical size={12} />
          CyberChef
        </NavLink>

        <NavLink
          to={`${base}/threathunt`}
          style={({ isActive }) => tabSt(isActive)}
          onMouseEnter={tabHoverIn} onMouseLeave={tabHoverOut}
        >
          <Crosshair size={12} />
          Threat Hunting
        </NavLink>

        <a
          href={volwebUrl}
          target="_blank"
          rel="noopener noreferrer"
          title="Open VolWeb (Volatility 3 memory analysis) in a new tab"
          style={tabSt(false)}
          onMouseEnter={tabHoverIn} onMouseLeave={tabHoverOut}
        >
          <Brain size={12} />
          VolWeb
          <ExternalLink size={8} style={{ opacity: 0.6 }} />
        </a>
      </div>

      <div key={collectionTab || 'outlet'} style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, animation: 'fl-fade 120ms var(--ease, ease)' }}>
        {pane === 'overview' ? (
          <CollectionOverview caseId={id} collectionId={collectionId} collName={collName} />
        ) : pane === 'network' ? (
          <CaseIntelligencePage collectionId={collectionId} />
        ) : pane === 'hayabusa' ? (
          <HayabusaPage />
        ) : pane === 'cyberchef' ? (
          <CyberChefPage />
        ) : pane === 'threathunt' ? (
          <CollectionThreatHuntTab caseId={id} collectionId={collectionId} collName={collName} />
        ) : (
          <Outlet context={{
            ...shellCtx,
            caseId: id,
            collectionId,
            insideCollectionLayout: true,
          }} />
        )}
      </div>

    </div>
  );
}
