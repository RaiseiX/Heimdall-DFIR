import { useTranslation } from 'react-i18next';

export default function StatusBar({ graphData, zoom, selectedNode }) {
  const { t } = useTranslation();
  const nodes = (graphData?.nodes || []).length;
  const edges = (graphData?.edges || []).length;
  const ioc   = (graphData?.nodes || []).filter(n => n.is_suspicious).length;

  const id = graphData?.identity || {};
  const discardedOccurrences = id.discarded_occurrences || 0;
  const folded  = id.machines_folded || 0;
  const noLink  = (id.machines_without_link || []).length;
  const discardedDetail = (id.discarded || [])
    .map(d => `${d.count} × ${d.id} — ${d.reason}`)
    .join('\n');

  const sep = <span style={{ color: 'var(--fl-raised)' }}>·</span>;

  return (
    <div style={{ height: 26, background: 'var(--fl-bg)', borderTop: '1px solid var(--fl-card)', display: 'flex', alignItems: 'center', padding: '0 12px', gap: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 12, color: 'var(--fl-muted)', flexShrink: 0 }}>
      <span>{t('networkMap.nodes', { count: nodes })}</span>
      {sep}
      <span>{t('networkMap.edges', { count: edges })}</span>
      {ioc > 0 && <>{sep}<span style={{ color: 'var(--fl-danger)' }}>{ioc} IOC</span></>}

      {folded > 0 && <>{sep}
        <span title={t('networkMap.folded_hint')}>{t('networkMap.folded', { count: folded })}</span>
      </>}

      {discardedOccurrences > 0 && <>{sep}
        <span title={discardedDetail} style={{ textDecoration: 'underline dotted' }}>
          {t('networkMap.discarded', { count: discardedOccurrences })}
        </span>
      </>}

      {noLink > 0 && <>{sep}
        <span title={(id.machines_without_link || []).join(', ')}>
          {t('networkMap.no_link', { count: noLink })}
        </span>
      </>}

      {id.coverage_unavailable && <>{sep}
        <span style={{ color: 'var(--fl-warn)' }} title={id.coverage_unavailable}>
          {t('networkMap.coverage_unavailable')}
        </span>
      </>}

      {selectedNode && <>{sep}<span style={{ color: 'var(--fl-purple)' }}>{t('networkMap.selected', { node: selectedNode })}</span></>}
      <span style={{ flex: 1 }} />
      <span>Cytoscape.js</span>
      {zoom && <>{sep}<span>{t('networkMap.zoom', { zoom: zoom.toFixed(2) })}</span></>}
    </div>
  );
}
