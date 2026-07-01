// backend/tests/unit/investigation/killChain.test.js
const { TACTICS, weightedCoverage, blindSpots, causalChains } = require('../../../src/services/killChain');

describe('killChain', () => {
  test('TACTICS contient les 14 tactiques ordonnées', () => {
    expect(TACTICS).toHaveLength(14);
    expect(TACTICS[0]).toBe('Reconnaissance');
    expect(TACTICS[13]).toBe('Impact');
  });

  test('weightedCoverage pondère par confiance', () => {
    const r = weightedCoverage([
      { mitre_tactic: 'Execution', confidence: 'high' },
      { mitre_tactic: 'Persistence', confidence: 'low' },
    ]);
    expect(r.covered).toBe(2);
    expect(r.total).toBe(14);
    expect(r.score).toBeCloseTo(1.3 / 14, 5);
  });

  test('confiance absente compte comme low', () => {
    const r = weightedCoverage([{ mitre_tactic: 'Execution' }]);
    expect(r.score).toBeCloseTo(0.3 / 14, 5);
  });

  test('blindSpots liste les tactiques sans finding', () => {
    const gaps = blindSpots([{ mitre_tactic: 'Execution' }]);
    expect(gaps).toContain('Reconnaissance');
    expect(gaps).not.toContain('Execution');
    expect(gaps).toHaveLength(13);
  });
});

describe('causalChains', () => {
  test('suit links_to depuis les racines', () => {
    const chains = causalChains([
      { id: 'a', links_to: 'b' },
      { id: 'b', links_to: 'c' },
      { id: 'c', links_to: null },
    ]);
    expect(chains).toEqual([['a', 'b', 'c']]);
  });

  test('gère les cycles sans boucle infinie', () => {
    const chains = causalChains([
      { id: 'a', links_to: 'b' },
      { id: 'b', links_to: 'a' },
    ]);
    expect(chains.length).toBeGreaterThan(0);
    expect(chains[0].length).toBeLessThanOrEqual(2);
  });
});

const { navigatorLayer } = require('../../../src/services/killChain');

test('navigatorLayer produit un layer ATT&CK valide', () => {
  const layer = navigatorLayer(
    [{ mitre_technique: 'T1059', mitre_tactic: 'Execution', confidence: 'high' }],
    'CASE-001',
  );
  expect(layer.domain).toBe('enterprise-attack');
  expect(layer.techniques[0].techniqueID).toBe('T1059');
  expect(layer.techniques[0].score).toBe(100);
});
