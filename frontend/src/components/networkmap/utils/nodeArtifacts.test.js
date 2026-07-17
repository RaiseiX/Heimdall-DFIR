import { describe, it, expect } from 'vitest';
import { buildNodeArtifacts } from './nodeArtifacts';

describe('buildNodeArtifacts', () => {
  it('classifies an IPv4 node as an ip indicator', () => {
    const a = buildNodeArtifacts({ id: '185.220.101.47', label: '185.220.101.47' });
    expect(a.iocType).toBe('ip');
    expect(a.indicator).toBe('185.220.101.47');
    expect(a.valid).toBe(true);
    expect(a.timelineQuery).toBe('185.220.101.47');
  });
  it('classifies a hostname/domain node as a domain indicator', () => {
    const a = buildNodeArtifacts({ id: 'n1', label: 'evil.example.net' });
    expect(a.iocType).toBe('domain');
    expect(a.indicator).toBe('evil.example.net');
  });
  it('classifies an IPv6 node as an ip indicator', () => {
    expect(buildNodeArtifacts({ label: 'fe80::1ff:fe23:4567:890a' }).iocType).toBe('ip');
  });
  it('escalates severity from risk signals (max wins)', () => {
    expect(buildNodeArtifacts({ label: 'x', beacon_score: 85 }).severity).toBe(8);
    expect(buildNodeArtifacts({ label: 'x', dga_score: 70 }).severity).toBe(7);
    expect(buildNodeArtifacts({ label: 'x', is_suspicious: true }).severity).toBe(7);
    expect(buildNodeArtifacts({ label: 'x', is_suspicious: true, beacon_score: 85 }).severity).toBe(8);
    expect(buildNodeArtifacts({ label: 'x' }).severity).toBe(5);
  });
  it('builds a human context string from present signals', () => {
    const a = buildNodeArtifacts({ label: '1.2.3.4', is_suspicious: true, beacon_score: 85, dga_score: 70, geo: { country: 'US' } });
    expect(a.context).toBe('Network map — IOC, beacon 85%, DGA 70, external (US)');
  });
  it('has a bare context when no signals are present', () => {
    expect(buildNodeArtifacts({ label: '1.2.3.4' }).context).toBe('Network map');
  });
  it('marks a node with no identifier invalid', () => {
    expect(buildNodeArtifacts({}).valid).toBe(false);
    expect(buildNodeArtifacts({ label: '   ' }).valid).toBe(false);
  });
});
