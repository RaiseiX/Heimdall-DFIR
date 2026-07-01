import { resolveIdentities } from '../../../src/services/lateralMovementService';

const isIp = (s: string) => /^[0-9a-f.:]+$/i.test(s);

describe('resolveIdentities', () => {
  test('unit une IP et un hostname vus dans le même event', () => {
    const map = resolveIdentities([{ identifiers: ['10.0.0.5', 'WS01'] }]);
    expect(map.get('10.0.0.5')).toBe(map.get('WS01'));
  });

  test('canonique = hostname plutôt que IP', () => {
    const map = resolveIdentities([{ identifiers: ['10.0.0.5', 'WS01'] }]);
    expect(map.get('10.0.0.5')).toBe('WS01');
    expect(isIp(map.get('WS01')!)).toBe(false);
  });

  test('borne NAT : une IP seule dans des events séparés ne fusionne pas deux hosts', () => {
    const map = resolveIdentities([
      { identifiers: ['10.0.0.5', 'WS01'] },
      { identifiers: ['10.0.0.5', 'WS02'] },
    ]);
    expect(map.get('WS01')).not.toBe(map.get('WS02'));
  });

  test('identifiant isolé reste son propre hostId', () => {
    const map = resolveIdentities([{ identifiers: ['WS09'] }]);
    expect(map.get('WS09')).toBe('WS09');
  });

  test('un hostname tout-hexadécimal (ex. DC01) n est pas classé comme IP', () => {
    const map = resolveIdentities([{ identifiers: ['10.0.0.5', 'DC01'] }]);
    expect(map.get('10.0.0.5')).toBe('DC01');
  });

  test('tableau d observations vide -> map vide', () => {
    expect(resolveIdentities([]).size).toBe(0);
  });

  test('observation composée uniquement d IPs : canonique = IP alphabétiquement première', () => {
    const map = resolveIdentities([{ identifiers: ['10.0.0.2', '10.0.0.1'] }]);
    expect(map.get('10.0.0.1')).toBe(map.get('10.0.0.2'));
  });
});
