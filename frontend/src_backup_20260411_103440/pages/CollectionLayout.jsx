import { useParams, NavLink, Outlet, useOutletContext } from 'react-router-dom';
import {
  FolderOpen, Clock, Crosshair, AlertTriangle, Network,
  Shield, ScrollText, FileText, Activity, FlaskConical,
} from 'lucide-react';
import CaseIntelligencePage from './CaseIntelligencePage';
import HayabusaPage from './HayabusaPage';
import CyberChefPage from './CyberChefPage';

export default function CollectionLayout() {
  const { id, collectionId, tab: collectionTab = 'evidence' } = useParams();
  const shellCtx = useOutletContext() || {};

  const base = `/cases/${id}/collections/${collectionId}`;

  const tabSt = (isActive) => ({
    display: 'flex', alignItems: 'center', gap: 4,
    padding: '0 8px', height: '100%',
    fontFamily: 'monospace', fontSize: 9,
    background: 'none', border: 'none', outline: 'none', cursor: 'pointer',
    borderBottom: `2px solid ${isActive ? '#4d82c0' : 'transparent'}`,
    color: isActive ? '#b0ccec' : '#3d5070',
    transition: 'color 0.1s',
    marginBottom: -1,
    flexShrink: 0,
    whiteSpace: 'nowrap',
    textDecoration: 'none',
  });

  const TABS = [
    { id: 'evidence',   label: 'Preuves',     icon: FolderOpen },
    { id: 'iocs',       label: 'IOCs',        icon: Crosshair },
    { id: 'detections', label: 'Détections',  icon: AlertTriangle },
    { id: 'network',    label: 'Réseau',      icon: Network },
    { id: 'mitre',      label: 'MITRE',       icon: Shield },
    { id: 'audit',      label: 'Audit',       icon: ScrollText },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>

      <div style={{
        position: 'sticky', top: 36, zIndex: 101,
        display: 'flex', alignItems: 'center',
        height: 36, padding: '0 10px',
        background: '#07101f',
        borderBottom: '1px solid #1a2540',
        borderLeft: '3px solid #1e3a5f',
        flexShrink: 0,
        overflowX: 'auto',
        scrollbarWidth: 'none',
        gap: 0,
      }}>

        {TABS.map(({ id: tid, label, icon: Icon }) => (
          <NavLink
            key={tid}
            to={`${base}/${tid}`}
            style={({ isActive }) => tabSt(isActive)}
          >
            <Icon size={9} />
            {label}
          </NavLink>
        ))}

        <span style={{ width: 1, height: 16, background: '#1a2540', flexShrink: 0, margin: '0 4px' }} />

        <NavLink
          to={`${base}/timeline`}
          style={({ isActive }) => ({
            ...tabSt(false),
            color: isActive ? '#22c55e' : '#2d5040',
            borderBottom: `2px solid ${isActive ? '#22c55e' : 'transparent'}`,
          })}
        >
          <Clock size={9} />
          Super Timeline
        </NavLink>

        <NavLink
          to={`${base}/logs`}
          style={({ isActive }) => tabSt(isActive)}
        >
          <FileText size={9} />
          Logs
        </NavLink>

        <span style={{ width: 1, height: 16, background: '#1a2540', flexShrink: 0, margin: '0 4px' }} />

        <NavLink
          to={`${base}/hayabusa`}
          style={({ isActive }) => ({
            ...tabSt(false),
            color: isActive ? '#f87171' : '#3d5070',
            borderBottom: `2px solid ${isActive ? '#da3633' : 'transparent'}`,
          })}
        >
          <Activity size={9} />
          Hayabusa
        </NavLink>

        <NavLink
          to={`${base}/cyberchef`}
          style={({ isActive }) => tabSt(isActive)}
        >
          <FlaskConical size={9} />
          CyberChef
        </NavLink>
      </div>

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
        {collectionTab === 'network' ? (
          <CaseIntelligencePage collectionId={collectionId} />
        ) : collectionTab === 'hayabusa' ? (
          <HayabusaPage />
        ) : collectionTab === 'cyberchef' ? (
          <CyberChefPage />
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
