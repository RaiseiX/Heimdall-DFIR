import { useState, useEffect, Fragment } from 'react';
import { useParams, NavLink, Outlet, useOutletContext } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ExternalLink } from 'lucide-react';
import { evidenceAPI } from '../utils/api';
import CaseIntelligencePage from './CaseIntelligencePage';
import HayabusaPage from './HayabusaPage';
import CyberChefPage from './CyberChefPage';
import CollectionThreatHuntTab from '../components/collection/CollectionThreatHuntTab';
import CollectionOverview from '../components/collection/CollectionOverview';
import { resolveCollectionPane } from './collectionPane';
import { COLLECTION_TAB_GROUPS, EXTERNAL_TABS } from './collectionTabs';

const FS_TAB = 10.5;

const BAR_STYLE = {
  position: 'sticky', top: 36, zIndex: 101,
  display: 'flex', alignItems: 'center',
  height: 36, padding: '0 12px', gap: 18,
  background: 'var(--fl-bg)',
  borderBottom: '1px solid var(--fl-border)',
  flexShrink: 0, overflowX: 'auto', scrollbarWidth: 'none',
};
const GROUP_SEP_STYLE = { width: 1, height: 13, background: 'var(--fl-border2)', alignSelf: 'center', flexShrink: 0 };
const EXT_ICON_STYLE = { opacity: 0.55, alignSelf: 'center' };

export default function CollectionLayout() {
  const { t } = useTranslation();
  const { id, collectionId, tab: collectionTab } = useParams();
  const pane = resolveCollectionPane(collectionTab);
  const shellCtx = useOutletContext() || {};
  const setCollectionName = shellCtx.setCollectionName;
  const [collName, setCollName] = useState('');

  useEffect(() => {
    setCollectionName?.(collName);
    return () => setCollectionName?.('');
  }, [collName, setCollectionName]);

  const base = `/cases/${id}/collections/${collectionId}`;
  const volwebUrl = `${window.location.protocol}//${window.location.hostname}:8888`;

  useEffect(() => {
    if (!id || !collectionId) return;
    evidenceAPI.list(id)
      .then(r => { const ev = (r.data || []).find(e => e.id === collectionId); if (ev) setCollName(ev.name || ''); })
      .catch(() => {});
  }, [id, collectionId]);

  const tabSt = (isActive) => ({
    display: 'inline-flex', alignItems: 'baseline', gap: 4,
    padding: '0 0 3px', alignSelf: 'center',
    fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: FS_TAB,
    fontWeight: isActive ? 600 : 400,
    background: 'none', border: 'none', outline: 'none', cursor: 'pointer',
    borderBottom: `1px solid ${isActive ? 'var(--fl-accent)' : 'transparent'}`,
    color: isActive ? 'var(--fl-text)' : 'var(--fl-muted)',
    textDecoration: 'none', whiteSpace: 'nowrap', flexShrink: 0,
    transition: 'color 0.12s, border-color 0.12s',
  });
  const tabHoverIn  = e => { if (e.currentTarget.getAttribute('aria-current') !== 'page') e.currentTarget.style.color = 'var(--fl-dim)'; };
  const tabHoverOut = e => { if (e.currentTarget.getAttribute('aria-current') !== 'page') e.currentTarget.style.color = 'var(--fl-muted)'; };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>

      <div style={BAR_STYLE}>
        {COLLECTION_TAB_GROUPS.map((groupe, gi) => (
          <Fragment key={groupe.id}>
            {gi > 0 && <span style={GROUP_SEP_STYLE} />}
            {groupe.tabs.map(({ id: tid, label }) => (
              EXTERNAL_TABS.has(tid) ? (
                <a key={tid} href={volwebUrl} target="_blank" rel="noopener noreferrer"
                  title={t('collection.tabs.volweb_hint')}
                  style={tabSt(false)}
                  onMouseEnter={tabHoverIn} onMouseLeave={tabHoverOut}>
                  {label}
                  <ExternalLink size={8} style={EXT_ICON_STYLE} />
                </a>
              ) : (
                <NavLink key={tid} to={`${base}/${tid}`}
                  style={({ isActive }) => tabSt(isActive)}
                  onMouseEnter={tabHoverIn} onMouseLeave={tabHoverOut}>
                  {label}
                </NavLink>
              )
            ))}
          </Fragment>
        ))}

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
