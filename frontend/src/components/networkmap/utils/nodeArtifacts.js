// Pure helper: derive the IOC / finding / timeline payloads for a selected
// network-map node. No I/O. Consumed by InvestigationDrawer's actions.

const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9a-fA-F:]+:[0-9a-fA-F:]+$/;

export function buildNodeArtifacts(nodeData) {
  const indicator = String(nodeData?.label || nodeData?.id || '').trim();
  const iocType = (IPV4.test(indicator) || IPV6.test(indicator)) ? 'ip' : 'domain';

  const beacon = Number(nodeData?.beacon_score) || 0;
  const dga = Number(nodeData?.dga_score) || 0;
  const suspicious = !!nodeData?.is_suspicious;

  let severity = 5;
  if (suspicious) severity = Math.max(severity, 7);
  if (beacon > 70) severity = Math.max(severity, 8);
  if (dga > 60) severity = Math.max(severity, 7);

  const parts = [];
  if (suspicious) parts.push('IOC');
  if (beacon > 0) parts.push(`beacon ${beacon}%`);
  if (dga > 0) parts.push(`DGA ${dga}`);
  if (nodeData?.geo?.country) parts.push(`external (${nodeData.geo.country})`);
  const context = 'Network map' + (parts.length ? ' — ' + parts.join(', ') : '');

  return {
    indicator,
    iocType,
    severity,
    context,
    timelineQuery: indicator,
    valid: indicator.length > 0,
  };
}
