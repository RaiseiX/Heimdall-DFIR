import { buildLateralGraph, RawLateralRow } from '../../../src/services/lateralMovementService';

const row = (o: Partial<RawLateralRow>): RawLateralRow => ({
  src: 'A', dst: 'B', username: 'admin', event_id: '4624', logon_type: '3',
  artifact_type: 'evtx', event_count: 1, first_seen: '2026-01-01T00:00:00Z',
  last_seen: '2026-01-01T00:00:00Z', ...o,
});

describe('buildLateralGraph', () => {
  test('agrège nœuds avec as_source / as_target', () => {
    const { nodes } = buildLateralGraph([row({ src: 'A', dst: 'B', event_count: 2 })], (id) => id);
    const a = nodes.find((n) => n.id === 'A')!;
    const b = nodes.find((n) => n.id === 'B')!;
    expect(a.as_source).toBe(2);
    expect(b.as_target).toBe(2);
  });

  test('applique la résolution d identité (IP et hostname -> un seul nœud)', () => {
    const resolve = (id: string) => (id === '10.0.0.5' ? 'WS01' : id);
    const { nodes } = buildLateralGraph(
      [row({ src: '10.0.0.5', dst: 'B' }), row({ src: 'WS01', dst: 'B' })],
      resolve,
    );
    expect(nodes.filter((n) => n.id === 'WS01').length).toBe(1);
    expect(nodes.find((n) => n.id === 'WS01')!.as_source).toBe(2);
  });

  test('fusionne les arêtes même source->target et collecte event_ids/usernames', () => {
    const { edges } = buildLateralGraph(
      [row({ event_id: '4624', username: 'a' }), row({ event_id: '4648', username: 'b' })],
      (id) => id,
    );
    expect(edges.length).toBe(1);
    expect(edges[0].count).toBe(2);
    expect(edges[0].event_ids.sort()).toEqual(['4624', '4648']);
    expect(edges[0].usernames.sort()).toEqual(['a', 'b']);
  });
});

describe('buildLateralGraph — origin', () => {
  test('arête EVTX seule => origin evtx', () => {
    const { edges } = buildLateralGraph([row({ artifact_type: 'evtx' })], (id) => id);
    expect(edges[0].origin).toBe('evtx');
  });
  test('arête réseau seule => origin network', () => {
    const { edges } = buildLateralGraph(
      [row({ artifact_type: 'network', event_id: 'NET:SMB', logon_type: null })],
      (id) => id,
    );
    expect(edges[0].origin).toBe('network');
  });
  test('même couple vu dans les deux sources => origin both', () => {
    const { edges } = buildLateralGraph(
      [row({ artifact_type: 'evtx' }), row({ artifact_type: 'network', event_id: 'NET:SMB' })],
      (id) => id,
    );
    expect(edges).toHaveLength(1);
    expect(edges[0].origin).toBe('both');
  });
});
