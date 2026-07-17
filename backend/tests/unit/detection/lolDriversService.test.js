const { matchDrivers } = require('../../../src/services/lolDriversService');

// Fixture index shaped like getDriverIndex()'s return value: { sha: Set<hex>, names: Map<filename, meta> }
const KNOWN_SHA1 = 'a'.repeat(40); // synthetic but valid-looking 40-hex-char SHA1
function fixtureIndex() {
  return {
    sha: new Set([KNOWN_SHA1]),
    names: new Map([['evil.sys', { category: 'vulnerable driver', mitre: 'T1068' }]]),
  };
}

describe('matchDrivers — amcache source (characterization, existing behavior)', () => {
  test('matches on DriverId hash', () => {
    const rows = [{ timestamp: 't1', artifact_type: 'amcache', host_name: 'H1', raw: { DriverId: KNOWN_SHA1, DriverName: 'evil.sys' } }];
    const out = matchDrivers(rows, fixtureIndex());
    expect(out.length).toBe(1);
    expect(out[0].confidence).toBe('high');
    expect(out[0].mitre).toBe('T1068');
  });

  test('benign amcache row (unknown hash/name) does not match', () => {
    const rows = [{ timestamp: 't1', artifact_type: 'amcache', host_name: 'H1', raw: { DriverId: 'b'.repeat(40), DriverName: 'benign.sys' } }];
    const out = matchDrivers(rows, fixtureIndex());
    expect(out.length).toBe(0);
  });
});

describe('matchDrivers — Sysmon EID 6 runtime driver-load source (H6)', () => {
  test('matches a driver load with a known-bad SHA1 in Hashes + ImageLoaded path', () => {
    const rows = [{
      timestamp: 't2', artifact_type: 'sysmon', host_name: 'H2',
      raw: { EventID: '6', ImageLoaded: 'C:\\Windows\\evil.sys', Hashes: `SHA1=${KNOWN_SHA1}` },
    }];
    const out = matchDrivers(rows, fixtureIndex());
    expect(out.length).toBe(1);
    expect(out[0].confidence).toBe('high');
  });

  test('benign driver load (unknown hash, unknown name) does not match', () => {
    const rows = [{
      timestamp: 't2', artifact_type: 'sysmon', host_name: 'H2',
      raw: { EventID: '6', ImageLoaded: 'C:\\Windows\\benign.sys', Hashes: `SHA1=${'c'.repeat(40)}` },
    }];
    const out = matchDrivers(rows, fixtureIndex());
    expect(out.length).toBe(0);
  });
});
