import { analyzeChains, LateralEdge } from '../../../src/services/lateralMovementService';

const edge = (source: string, target: string, ts: string): LateralEdge => ({
  source, target, count: 1, event_ids: ['4624'], usernames: ['u'], logon_types: ['3'],
  first_seen: ts, last_seen: ts,
});

describe('analyzeChains', () => {
  test('reconstruit A->B->C ordonné dans le temps', () => {
    const chains = analyzeChains([
      edge('A', 'B', '2026-01-01T00:00:00Z'),
      edge('B', 'C', '2026-01-01T01:00:00Z'),
    ]);
    const abc = chains.find((c) => c.path.join('>') === 'A>B>C');
    expect(abc).toBeTruthy();
    expect(abc!.entryPoint).toBe('A');
  });

  test('ne chaîne pas au-delà de la fenêtre Δt', () => {
    const chains = analyzeChains(
      [edge('A', 'B', '2026-01-01T00:00:00Z'), edge('B', 'C', '2026-01-03T00:00:00Z')],
      { windowMs: 24 * 60 * 60 * 1000 },
    );
    expect(chains.some((c) => c.path.join('>') === 'A>B>C')).toBe(false);
  });

  test('ne chaîne pas un saut antérieur dans le temps (B->C avant A->B)', () => {
    const chains = analyzeChains([
      edge('A', 'B', '2026-01-01T02:00:00Z'),
      edge('B', 'C', '2026-01-01T00:00:00Z'),
    ]);
    expect(chains.some((c) => c.path.join('>') === 'A>B>C')).toBe(false);
  });

  test('entryPoint = nœud jamais cible', () => {
    const chains = analyzeChains([edge('A', 'B', '2026-01-01T00:00:00Z')]);
    expect(chains[0].entryPoint).toBe('A');
  });

  test('ne boucle pas à l infini sur un cycle (chemins simples)', () => {
    const chains = analyzeChains([
      edge('A', 'B', '2026-01-01T00:00:00Z'),
      edge('B', 'C', '2026-01-01T01:00:00Z'),
      edge('C', 'B', '2026-01-01T02:00:00Z'),
    ]);
    expect(Array.isArray(chains)).toBe(true);
    for (const c of chains) expect(new Set(c.path).size).toBe(c.path.length); // aucun nœud répété
  });

  test('cycle pur sans point d entrée -> aucune chaîne, pas de crash', () => {
    const chains = analyzeChains([
      edge('A', 'B', '2026-01-01T00:00:00Z'),
      edge('B', 'A', '2026-01-01T01:00:00Z'),
    ]);
    expect(chains).toEqual([]);
  });

  test('entrée vide -> []', () => {
    expect(analyzeChains([])).toEqual([]);
  });

  test('respecte le plafond maxChains', () => {
    // hub E vers 5 cibles, chacune vers une feuille -> bornable
    const many: LateralEdge[] = [];
    for (let i = 0; i < 5; i++) {
      many.push(edge('E', `H${i}`, '2026-01-01T00:00:00Z'));
      many.push(edge(`H${i}`, `L${i}`, '2026-01-01T01:00:00Z'));
    }
    const chains = analyzeChains(many, { maxChains: 2 });
    expect(chains.length).toBeLessThanOrEqual(2);
  });
});
