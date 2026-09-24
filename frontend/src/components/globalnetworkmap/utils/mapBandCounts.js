
import { countZones } from '../../networkmap/utils/zoneDeclaration';

const int = (v) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
};

export function mapBandCounts({ rawData, elements, folded, declarations } = {}) {
  const nodes = rawData?.nodes || [];
  const edges = rawData?.edges || [];
  const els = elements || [];
  const identity = rawData?.identity || {};
  const f = folded?.folded || {};

  const drawn = els.filter(el => el?.data?.source == null && el?.data?.nodeType !== 'cluster');
  const drawnNodes = drawn.length;
  const drawnEdges = els.filter(el => el?.data?.source != null).length;

  const zones = countZones(
    drawn.map(el => ({ id: el.data?.id, type: el.data?._raw?.type })),
    declarations,
  );

  return {
    drawnNodes,
    drawnEdges,
    zonesInferred: zones.inferred,
    zonesDeclared: zones.declared,
    totalNodes: nodes.length,
    totalEdges: edges.length,
    complete: drawnNodes === nodes.length && drawnEdges === edges.length,

    evidences: (rawData?.evidence_sources || []).length,
    correlated: nodes.filter(n => (n?.evidence_ids || []).length >= 2).length,
    truncated: Boolean(rawData?.truncated),

    foldedUrls: int(f.urls),
    foldedHosts: int(f.hosts),
    unfoldable: int(f.unfoldable),

    machinesFolded: int(identity.machines_folded),
    discardedOccurrences: int(identity.discarded_occurrences),
    discarded: identity.discarded || [],
    withoutLink: (identity.machines_without_link || []).length,
    withoutLinkNames: identity.machines_without_link || [],
    urlsUnattributed: int(identity.urls_unattributed),
    connectionsUnattributed: int(identity.connections_unattributed),
    coverageUnavailable: identity.coverage_unavailable ?? null,
  };
}
