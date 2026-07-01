import { networkEventId, isPrivateIp } from '../../../src/services/lateralMovementService';
import { mapNetworkRowsToLateral, NetworkConnRow } from '../../../src/services/lateralMovementService';

describe('networkEventId', () => {
  test('mappe les ports latéraux vers NET:<proto>', () => {
    expect(networkEventId(445)).toBe('NET:SMB');
    expect(networkEventId(3389)).toBe('NET:RDP');
    expect(networkEventId(22)).toBe('NET:SSH');
    expect(networkEventId(5985)).toBe('NET:WINRM');
    expect(networkEventId(5900)).toBe('NET:VNC');
  });
  test('renvoie null pour un port non latéral', () => {
    expect(networkEventId(80)).toBeNull();
    expect(networkEventId(53)).toBeNull();
  });
});

describe('isPrivateIp', () => {
  test('reconnaît les plages privées IPv4', () => {
    expect(isPrivateIp('10.0.0.5')).toBe(true);
    expect(isPrivateIp('192.168.1.10')).toBe(true);
    expect(isPrivateIp('172.16.0.1')).toBe(true);
    expect(isPrivateIp('172.31.255.1')).toBe(true);
  });
  test('rejette les IP publiques et 172.32+', () => {
    expect(isPrivateIp('8.8.8.8')).toBe(false);
    expect(isPrivateIp('172.32.0.1')).toBe(false);
    expect(isPrivateIp('')).toBe(false);
  });
  test('reconnaît les privées IPv6 (ULA / link-local / loopback)', () => {
    expect(isPrivateIp('::1')).toBe(true);
    expect(isPrivateIp('fc00::1')).toBe(true);
    expect(isPrivateIp('fe80::abcd')).toBe(true);
    expect(isPrivateIp('2001:4860:4860::8888')).toBe(false);
  });
});

const nrow = (o: Partial<NetworkConnRow>): NetworkConnRow => ({
  src_ip: '10.0.0.1', dst_ip: '10.0.0.2', dst_port: 445, protocol: 'tcp',
  packet_count: 12, first_seen: '2026-01-01T00:00:00Z', last_seen: '2026-01-01T00:05:00Z', ...o,
});

describe('mapNetworkRowsToLateral', () => {
  test('mappe une connexion SMB interne en RawLateralRow réseau', () => {
    const [r] = mapNetworkRowsToLateral([nrow({})]);
    expect(r.src).toBe('10.0.0.1');
    expect(r.dst).toBe('10.0.0.2');
    expect(r.username).toBe('?');
    expect(r.logon_type).toBeNull();
    expect(r.artifact_type).toBe('network');
    expect(r.event_id).toBe('NET:SMB');
    expect(r.event_count).toBe(12);
  });
  test('event_count retombe à 1 si packet_count nul/absent', () => {
    const [r] = mapNetworkRowsToLateral([nrow({ packet_count: null })]);
    expect(r.event_count).toBe(1);
  });
  test('exclut les connexions avec une extrémité externe', () => {
    expect(mapNetworkRowsToLateral([nrow({ dst_ip: '8.8.8.8' })])).toHaveLength(0);
    expect(mapNetworkRowsToLateral([nrow({ src_ip: '93.184.216.34' })])).toHaveLength(0);
  });
  test('exclut les ports non latéraux et src===dst', () => {
    expect(mapNetworkRowsToLateral([nrow({ dst_port: 80 })])).toHaveLength(0);
    expect(mapNetworkRowsToLateral([nrow({ dst_ip: '10.0.0.1' })])).toHaveLength(0);
  });
});
