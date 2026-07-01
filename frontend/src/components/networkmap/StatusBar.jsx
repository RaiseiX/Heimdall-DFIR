// frontend/src/components/networkmap/StatusBar.jsx
import { useTranslation } from 'react-i18next';

export default function StatusBar({ graphData, zoom, selectedNode }) {
  const { t } = useTranslation();
  const nodes = (graphData?.nodes || []).length;
  const edges = (graphData?.edges || []).length;
  const ioc   = (graphData?.nodes || []).filter(n => n.is_suspicious).length;

  return (
    <div style={{ height: 22, background: 'var(--fl-bg)', borderTop: '1px solid var(--fl-card)', display: 'flex', alignItems: 'center', padding: '0 12px', gap: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 7, color: 'var(--fl-muted)', flexShrink: 0 }}>
      <span>{t('networkMap.nodes', { count: nodes })}</span>
      <span style={{ color: 'var(--fl-raised)' }}>·</span>
      <span>{t('networkMap.edges', { count: edges })}</span>
      {ioc > 0 && <><span style={{ color: 'var(--fl-raised)' }}>·</span><span style={{ color: 'var(--fl-danger)' }}>{ioc} IOC</span></>}
      {selectedNode && <><span style={{ color: 'var(--fl-raised)' }}>·</span><span style={{ color: 'var(--fl-purple)' }}>{t('networkMap.selected', { node: selectedNode })}</span></>}
      <span style={{ flex: 1 }} />
      <span>Cytoscape.js</span>
      {zoom && <><span style={{ color: 'var(--fl-raised)' }}>·</span><span>{t('networkMap.zoom', { zoom: zoom.toFixed(2) })}</span></>}
    </div>
  );
}
