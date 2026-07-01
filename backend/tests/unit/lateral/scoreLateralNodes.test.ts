import {
  scoreLateralNodes, selectSignalAwareEdges, LateralNode, LateralEdge, LateralChain, LateralIndicator,
} from '../../../src/services/lateralMovementService';

const node = (o: Partial<LateralNode>): LateralNode => ({ id: 'X', total_events: 0, as_source: 0, as_target: 0, ...o });
const edge = (source: string, target: string, count: number, logon_types: string[] = ['3']): LateralEdge => ({
  source, target, count, event_ids: ['4624'], usernames: ['u'], logon_types,
  first_seen: '2026-01-01T00:00:00Z', last_seen: '2026-01-01T00:00:00Z',
});

describe('scoreLateralNodes', () => {
  test('un pivot source structurel obtient un score et un facteur', () => {
    const n = node({ id: 'A', total_events: 10, as_source: 9, as_target: 1 });
    const scored = scoreLateralNodes([n], [edge('A', 'B', 9)], [], [], new Set());
    const a = scored.find((x) => x.id === 'A')!;
    expect(a.score).toBeGreaterThan(0);
    expect(a.factors!.length).toBeGreaterThan(0);
  });

  test('présence d un outil de pivot (indicator) augmente le score et ajoute un facteur', () => {
    const n = node({ id: 'A', total_events: 4, as_source: 2, as_target: 2 });
    const indicators: LateralIndicator[] = [{ host_name: 'A', description: 'PsExec service', mitre_technique_id: 'T1021.002' }];
    const withTool = scoreLateralNodes([n], [edge('A', 'B', 2)], indicators, [], new Set());
    const without = scoreLateralNodes([n], [edge('A', 'B', 2)], [], [], new Set());
    expect(withTool[0].score!).toBeGreaterThan(without[0].score!);
    expect(withTool[0].factors!.join(' ')).toMatch(/pivot|outil|tool/i);
  });

  test('recouvrement IOC ajoute un facteur', () => {
    const n = node({ id: 'A', total_events: 4, as_source: 2, as_target: 2 });
    const scored = scoreLateralNodes([n], [edge('A', 'B', 2)], [], [], new Set(['A']));
    expect(scored[0].factors!.join(' ')).toMatch(/ioc/i);
  });
});

describe('selectSignalAwareEdges', () => {
  test('conserve toujours les arêtes à fort signal même rares, sous le plafond', () => {
    const many = Array.from({ length: 10 }, (_, i) => edge(`H${i}`, 'T', 100));
    const rareCritical = edge('RARE', 'T', 1);
    const kept = selectSignalAwareEdges([...many, rareCritical], new Set(['RARE']), 5);
    expect(kept.length).toBe(5);
    expect(kept.some((e) => e.source === 'RARE')).toBe(true);
  });

  test('arêtes high-signal au-delà du cap : garde les plus fréquentes', () => {
    const sig = [edge('S', 'T', 1), edge('S', 'U', 50), edge('S', 'V', 10)];
    const kept = selectSignalAwareEdges(sig, new Set(['S']), 2);
    expect(kept.length).toBe(2);
    expect(kept.map((e) => e.count).sort((a, b) => b - a)).toEqual([50, 10]);
  });
});

describe('scoreLateralNodes — locking tests', () => {
  test('score plafonné à 100', () => {
    const n = node({ id: 'A', total_events: 100, as_source: 99, as_target: 1 });
    const indicators: LateralIndicator[] = [{ host_name: 'A', description: 'PsExec', mitre_technique_id: 'T1021.002' }];
    const chains: LateralChain[] = [{ path: ['Z', 'A', 'Y'], timestamps: ['t', 't'], entryPoint: 'Z' }];
    const scored = scoreLateralNodes([n], [edge('A', 'B', 99, ['10'])], indicators, chains, new Set(['A']));
    expect(scored[0].score!).toBeLessThanOrEqual(100);
    expect(scored[0].score).toBe(100);
  });

  test('logon interactif détecté même si le type est stocké en nombre', () => {
    const n = node({ id: 'A', total_events: 4, as_source: 2, as_target: 2 });
    const e = { ...edge('A', 'B', 2), logon_types: [10 as unknown as string] };
    const scored = scoreLateralNodes([n], [e], [], [], new Set());
    expect(scored[0].factors!.join(' ')).toMatch(/interactif|RDP/i);
  });

  test('description générique contenant "lateral" ne déclenche pas le facteur outil de pivot', () => {
    const n = node({ id: 'A', total_events: 4, as_source: 2, as_target: 2 });
    const indicators: LateralIndicator[] = [{ host_name: 'A', description: 'Bilateral authentication attempt', mitre_technique_id: null }];
    const scored = scoreLateralNodes([n], [edge('A', 'B', 2)], indicators, [], new Set());
    expect(scored[0].factors!.join(' ')).not.toMatch(/Outil de pivot/i);
  });
});
