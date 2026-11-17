import { useState, useEffect } from 'react';
import { useParams, Outlet, useOutletContext } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { evidenceAPI } from '../utils/api';
import CaseIntelligencePage from './CaseIntelligencePage';
import HayabusaPage from './HayabusaPage';
import CyberChefPage from './CyberChefPage';
import CollectionThreatHuntTab from '../components/collection/CollectionThreatHuntTab';
import CollectionOverview from '../components/collection/CollectionOverview';
import CollectionProcessesTab from '../components/processes/CollectionProcessesTab';
import AuthGraphPanel from '../components/network/AuthGraphPanel';
import ErrorBoundary from '../components/ErrorBoundary';
import { resolveCollectionPane } from './collectionPane';
import CollectionTabsBar from './CollectionTabsBar';

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


  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>

      <CollectionTabsBar base={base} volwebUrl={volwebUrl} actifId={collectionTab} />

      <div key={collectionTab || 'outlet'} style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, animation: 'fl-fade 120ms var(--ease, ease)' }}>
        <ErrorBoundary
          libelles={{
            titre:  t('errors.render_title'),
            detail: t('errors.render_detail'),
            action: t('errors.render_retry'),
          }}>
        {pane === 'overview' ? (
          <CollectionOverview caseId={id} collectionId={collectionId} collName={collName} />
        ) : pane === 'network' ? (
          <CaseIntelligencePage collectionId={collectionId} />
        ) : pane === 'auth' ? (
          <AuthGraphPanel caseId={id} collectionId={collectionId} />
        ) : pane === 'hayabusa' ? (
          <HayabusaPage caseId={id} collectionId={collectionId} />
        ) : pane === 'processes' ? (
          <CollectionProcessesTab caseId={id} collectionId={collectionId} />
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
        </ErrorBoundary>
      </div>

    </div>
  );
}
