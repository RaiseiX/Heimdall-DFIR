// Set required env vars before any module is loaded
process.env.JWT_SECRET = 'test-secret-for-unit-tests';

// Mock heavy dependencies so network.js loads without DB/auth side effects
jest.mock('../../../src/config/database', () => ({
  pool: { query: jest.fn().mockResolvedValue({ rows: [] }) },
}));
jest.mock('../../../src/middleware/auth', () => ({
  authenticate: jest.fn(),
  requireRole: jest.fn(() => jest.fn()),
}));
jest.mock('../../../src/config/logger', () => ({
  default: { info: jest.fn(), error: jest.fn(), warn: jest.fn(), debug: jest.fn() },
}));

const { mergeGlobalGraph } = require('../../../src/routes/network');

const EV_A = { id: 'ev-a', name: 'Evidence Alpha' };
const EV_B = { id: 'ev-b', name: 'Evidence Bravo' };

function makeResult(nodes: any[], edges: any[], truncated = false) {
  return { nodes, edges, evidence_sources: [], truncated };
}

describe('mergeGlobalGraph', () => {
  test('returns empty graph when all results are empty', () => {
    const result = mergeGlobalGraph(
      [makeResult([], []), makeResult([], [])],
      [EV_A, EV_B]
    );
    expect(result.nodes).toHaveLength(0);
    expect(result.edges).toHaveLength(0);
    expect(result.evidence_sources).toEqual([
      { id: 'ev-a', name: 'Evidence Alpha' },
      { id: 'ev-b', name: 'Evidence Bravo' },
    ]);
  });

  test('single evidence — node has evidence_ids with that evidence', () => {
    const result = mergeGlobalGraph(
      [makeResult([{ id: '10.0.0.1', type: 'internal', is_suspicious: false, connection_count: 3, total_bytes: 0 }], [])],
      [EV_A]
    );
    expect(result.nodes).toHaveLength(1);
    expect(result.nodes[0].evidence_ids).toEqual(['ev-a']);
  });

  test('same node in two evidences — correlated, counts summed', () => {
    const nodeA = { id: '8.8.8.8', type: 'external', is_suspicious: false, connection_count: 2, total_bytes: 100 };
    const nodeB = { id: '8.8.8.8', type: 'external', is_suspicious: false, connection_count: 5, total_bytes: 200 };
    const result = mergeGlobalGraph(
      [makeResult([nodeA], []), makeResult([nodeB], [])],
      [EV_A, EV_B]
    );
    expect(result.nodes).toHaveLength(1);
    const n = result.nodes[0];
    expect(n.evidence_ids).toEqual(['ev-a', 'ev-b']);
    expect(n.connection_count).toBe(7);
    expect(n.total_bytes).toBe(300);
  });

  test('suspicious flag is OR-ed across evidences', () => {
    const safe = { id: 'evil.ru', type: 'domain', is_suspicious: false, connection_count: 1, total_bytes: 0 };
    const bad  = { id: 'evil.ru', type: 'domain', is_suspicious: true,  connection_count: 1, total_bytes: 0 };
    const result = mergeGlobalGraph(
      [makeResult([safe], []), makeResult([bad], [])],
      [EV_A, EV_B]
    );
    expect(result.nodes[0].is_suspicious).toBe(true);
  });

  test('different nodes in different evidences — each has one evidence_id', () => {
    const result = mergeGlobalGraph(
      [
        makeResult([{ id: '10.0.0.1', type: 'internal', is_suspicious: false, connection_count: 1, total_bytes: 0 }], []),
        makeResult([{ id: '10.0.0.2', type: 'internal', is_suspicious: false, connection_count: 1, total_bytes: 0 }], []),
      ],
      [EV_A, EV_B]
    );
    expect(result.nodes).toHaveLength(2);
    expect(result.nodes.find((n: any) => n.id === '10.0.0.1')!.evidence_ids).toEqual(['ev-a']);
    expect(result.nodes.find((n: any) => n.id === '10.0.0.2')!.evidence_ids).toEqual(['ev-b']);
  });

  test('edges are merged by src||dst||port||proto key', () => {
    const edge = { source: '10.0.0.1', target: '8.8.8.8', connection_count: 2, total_bytes: 100, has_suspicious: false, ports: ['53'], protocols: ['UDP'] };
    const result = mergeGlobalGraph(
      [makeResult([], [edge]), makeResult([], [{ ...edge, connection_count: 3, total_bytes: 50 }])],
      [EV_A, EV_B]
    );
    expect(result.edges).toHaveLength(1);
    const e = result.edges[0];
    expect(e.connection_count).toBe(5);
    expect(e.total_bytes).toBe(150);
    expect(e.evidence_ids).toEqual(['ev-a', 'ev-b']);
  });

  test('truncated is true if any evidence result was truncated', () => {
    const result = mergeGlobalGraph(
      [makeResult([], [], false), makeResult([], [], true)],
      [EV_A, EV_B]
    );
    expect(result.truncated).toBe(true);
  });

  test('truncated is false when no evidence was truncated', () => {
    const result = mergeGlobalGraph(
      [makeResult([], [], false), makeResult([], [], false)],
      [EV_A, EV_B]
    );
    expect(result.truncated).toBe(false);
  });

  test('dga_score is the max across evidences', () => {
    const low  = { id: 'rand0m.xyz', type: 'domain', is_suspicious: false, connection_count: 1, total_bytes: 0, dga_score: 20 };
    const high = { id: 'rand0m.xyz', type: 'domain', is_suspicious: false, connection_count: 1, total_bytes: 0, dga_score: 75 };
    const result = mergeGlobalGraph(
      [makeResult([low], []), makeResult([high], [])],
      [EV_A, EV_B]
    );
    expect(result.nodes[0].dga_score).toBe(75);
  });

  test('evidence_sources uses name || original_filename || id fallback', () => {
    const evA = { id: 'uuid-a', name: 'Named Evidence' };
    const evB = { id: 'uuid-b', name: null, original_filename: 'dump.raw' };
    const evC = { id: 'uuid-c', name: null, original_filename: null };
    const result = mergeGlobalGraph(
      [makeResult([], []), makeResult([], []), makeResult([], [])],
      [evA, evB, evC]
    );
    expect(result.evidence_sources).toEqual([
      { id: 'uuid-a', name: 'Named Evidence' },
      { id: 'uuid-b', name: 'dump.raw' },
      { id: 'uuid-c', name: 'uuid-c' },
    ]);
  });
});
