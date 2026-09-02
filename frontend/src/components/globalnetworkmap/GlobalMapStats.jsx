
import { useTranslation } from 'react-i18next';
import { declaredZoneEntries } from '../networkmap/utils/zoneDeclaration';
import { formatCount } from '../../utils/formatCount';

const stat = { fontFamily: 'var(--f-mono)', fontSize: 11, color: 'var(--fl-muted)', whiteSpace: 'nowrap' };
const strong = { color: 'var(--fl-text)', fontWeight: 600 };

export default function GlobalMapStats({ counts, loading = false }) {
  const { t } = useTranslation();

  if (loading || !counts) {
    return <span style={stat}>{t('networkMap.loading_global')}</span>;
  }

  const c = counts;
  const partial = !c.complete;
  const inferred = c.zonesInferred || {};
  const declared = c.zonesDeclared || {};
  const inferredTotal = (inferred.internal || 0) + (inferred.external || 0);

  return (
    <>
      <span style={stat}>
        <b style={strong}>{formatCount(c.drawnNodes)}</b> {t('networkMap.band.nodes')}
        {partial && <span> {t('networkMap.band.of', { total: formatCount(c.totalNodes) })}</span>}
      </span>
      <span style={stat}>
        <b style={strong}>{formatCount(c.drawnEdges)}</b> {t('networkMap.band.edges')}
        {partial && <span> {t('networkMap.band.of', { total: formatCount(c.totalEdges) })}</span>}
      </span>

      {inferredTotal > 0 && (
        <span style={stat}>
          {inferred.internal > 0 && (
            <><b style={strong}>{formatCount(inferred.internal)}</b> {t('networkMap.band.zone_internal', { count: inferred.internal })}</>
          )}
          {inferred.internal > 0 && inferred.external > 0 && <span style={{ color: 'var(--fl-subtle)' }}> · </span>}
          {inferred.external > 0 && (
            <><b style={strong}>{formatCount(inferred.external)}</b> {t('networkMap.band.zone_external', { count: inferred.external })}</>
          )}
          {' '}{t('networkMap.band.zones_inferred', { count: inferredTotal })}
        </span>
      )}
      {declaredZoneEntries(declared).map(({ zone, count, key }) => (
        <span key={zone} style={{ ...stat, color: 'var(--fl-warn)' }}>
          <b style={{ color: 'var(--fl-warn)', fontWeight: 600 }}>{formatCount(count)}</b>
          {' '}{t(key, { count })}
        </span>
      ))}

      <span style={stat}>{t('networkMap.evidences', { count: c.evidences })}</span>

      {c.correlated > 0 && (
        <span style={stat}>{t('networkMap.correlated', { count: c.correlated })}</span>
      )}

      {c.machinesFolded > 0 && (
        <span style={stat}>{t('networkMap.folded', { count: c.machinesFolded })}</span>
      )}
      {c.discardedOccurrences > 0 && (
        <span
          style={{ ...stat, color: 'var(--fl-gold)', cursor: 'help' }}
          title={c.discarded.map(d => `${d.count} × ${d.id} — ${d.reason}`).join('\n')}
        >
          {t('networkMap.discarded', { count: c.discardedOccurrences })}
        </span>
      )}

      {c.coverageUnavailable
        ? <span style={{ ...stat, color: 'var(--fl-gold)' }}>{t('networkMap.coverage_unavailable')}</span>
        : c.withoutLink > 0 && (
          <span style={{ ...stat, cursor: 'help' }} title={c.withoutLinkNames.join('\n')}>
            {t('networkMap.no_link', { count: c.withoutLink })}
          </span>
        )}

      {c.urlsUnattributed > 0 && (
        <span style={{ ...stat, color: 'var(--fl-gold)' }}>
          {t('networkMap.band.urls_unattributed', { count: c.urlsUnattributed })}
        </span>
      )}
      {c.connectionsUnattributed > 0 && (
        <span style={{ ...stat, color: 'var(--fl-gold)' }}>
          {t('networkMap.band.connections_unattributed', { count: c.connectionsUnattributed })}
        </span>
      )}

      {c.truncated && (
        <span style={{ ...stat, color: 'var(--fl-gold)' }}>{t('networkMap.graph_truncated')}</span>
      )}
    </>
  );
}
