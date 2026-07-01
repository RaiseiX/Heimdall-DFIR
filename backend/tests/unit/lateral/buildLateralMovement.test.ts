import { buildLateralMovement, RawLateralRow } from '../../../src/services/lateralMovementService';

const row = (o: Partial<RawLateralRow>): RawLateralRow => ({
  src: 'A', dst: 'B', username: 'u', event_id: '4624', logon_type: '3',
  artifact_type: 'evtx', event_count: 1, first_seen: '2026-01-01T00:00:00Z',
  last_seen: '2026-01-01T00:00:00Z', ...o,
});

describe('buildLateralMovement', () => {
  test('produit une réponse rétrocompatible + chains + score', () => {
    const res = buildLateralMovement({
      rows: [row({ src: 'A', dst: 'B', first_seen: '2026-01-01T00:00:00Z' }),
             row({ src: 'B', dst: 'C', first_seen: '2026-01-01T01:00:00Z' })],
      observations: [{ identifiers: ['10.0.0.5', 'A'] }],
      indicators: [],
      iocHosts: new Set(),
    });
    expect(res).toHaveProperty('nodes');
    expect(res).toHaveProperty('edges');
    expect(res).toHaveProperty('total_events');
    expect(res).toHaveProperty('indicators');
    expect(res).toHaveProperty('chains');
    expect(res.chains.some((c) => c.path.join('>') === 'A>B>C')).toBe(true);
    expect(res.nodes.every((n) => typeof n.score === 'number')).toBe(true);
  });

  test('résout l identité : 10.0.0.5 et A comptent comme un seul nœud', () => {
    const res = buildLateralMovement({
      rows: [row({ src: '10.0.0.5', dst: 'B' }), row({ src: 'A', dst: 'B' })],
      observations: [{ identifiers: ['10.0.0.5', 'A'] }],
      indicators: [], iocHosts: new Set(),
    });
    expect(res.nodes.filter((n) => n.id === 'A').length).toBe(1);
  });
});
