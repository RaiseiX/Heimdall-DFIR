import { isPrivateIP, validateExternalUrl } from '../../../src/utils/networkUtils';

const dnsPromises = require('dns').promises as typeof import('dns').promises;

describe('isPrivateIP', () => {
  test.each([
    ['127.0.0.1',       true,  'loopback'],
    ['127.255.255.255', true,  'loopback range end'],
    ['10.0.0.1',        true,  'RFC 1918 /8'],
    ['10.255.255.255',  true,  'RFC 1918 /8 end'],
    ['172.16.0.1',      true,  'RFC 1918 /12'],
    ['172.31.255.255',  true,  'RFC 1918 /12 end'],
    ['192.168.1.1',     true,  'RFC 1918 /16'],
    ['192.168.255.255', true,  'RFC 1918 /16 end'],
    ['169.254.169.254', true,  'AWS metadata / link-local'],
    ['169.254.0.1',     true,  'link-local start'],
    ['100.64.0.1',      true,  'CGNAT RFC 6598'],
    ['0.0.0.1',         true,  'reserved 0/8'],
    ['224.0.0.1',       true,  'multicast'],
    ['255.255.255.255', true,  'broadcast'],
    ['8.8.8.8',         false, 'Google DNS — public'],
    ['1.1.1.1',         false, 'Cloudflare DNS — public'],
    ['203.0.112.1',     false, 'just outside TEST-NET-3'],
    ['172.15.255.255',  false, 'just before RFC 1918 /12'],
    ['172.32.0.0',      false, 'just after RFC 1918 /12'],
  ])('isPrivateIP("%s") === %s (%s)', (ip, expected) => {
    expect(isPrivateIP(ip)).toBe(expected);
  });

  test('IPv6 loopback ::1 is private', () => {
    expect(isPrivateIP('::1')).toBe(true);
  });

  test('IPv6 link-local fe80::1 is private', () => {
    expect(isPrivateIP('fe80::1')).toBe(true);
  });

  test('unknown format is blocked', () => {
    expect(isPrivateIP('not-an-ip')).toBe(true);
  });
});

describe('validateExternalUrl', () => {
  const realEnv = process.env.NODE_ENV;
  afterEach(() => {
    process.env.NODE_ENV = realEnv;
    jest.restoreAllMocks();
  });

  test('rejects non-http(s) schemes', async () => {
    await expect(validateExternalUrl('ftp://example.com')).rejects.toThrow("not allowed");
  });

  test('rejects invalid URL', async () => {
    await expect(validateExternalUrl('not a url')).rejects.toThrow("Invalid URL");
  });

  test('rejects direct private IPv4 address', async () => {
    await expect(validateExternalUrl('http://192.168.1.1/api')).rejects.toThrow("SSRF blocked");
  });

  test('rejects direct loopback IP', async () => {
    await expect(validateExternalUrl('http://127.0.0.1:8080')).rejects.toThrow("SSRF blocked");
  });

  test('rejects 169.254.169.254 (AWS metadata)', async () => {
    await expect(validateExternalUrl('http://169.254.169.254/latest/meta-data')).rejects.toThrow("SSRF blocked");
  });

  test('rejects HTTP in production', async () => {
    process.env.NODE_ENV = 'production';
    jest.spyOn(dnsPromises, 'lookup').mockResolvedValueOnce([{ address: '8.8.8.8', family: 4 }] as any);
    await expect(validateExternalUrl('http://example.com')).rejects.toThrow("HTTPS is required");
  });

  test('accepts HTTPS with public resolved IP', async () => {
    jest.spyOn(dnsPromises, 'lookup').mockResolvedValueOnce([{ address: '8.8.8.8', family: 4 }] as any);
    await expect(validateExternalUrl('https://example.com')).resolves.toBeUndefined();
  });

  test('rejects when hostname resolves to private IP', async () => {
    jest.spyOn(dnsPromises, 'lookup').mockResolvedValueOnce([{ address: '10.0.0.1', family: 4 }] as any);
    await expect(validateExternalUrl('https://internal.corp')).rejects.toThrow("SSRF blocked");
  });

  test('rejects when any resolved IP is private (all: true)', async () => {
    jest.spyOn(dnsPromises, 'lookup').mockResolvedValueOnce([
      { address: '8.8.8.8',  family: 4 },
      { address: '10.0.0.1', family: 4 },
    ] as any);
    await expect(validateExternalUrl('https://tricky.corp')).rejects.toThrow("SSRF blocked");
  });

  test('rejects if DNS lookup fails', async () => {
    jest.spyOn(dnsPromises, 'lookup').mockRejectedValueOnce(new Error('ENOTFOUND'));
    await expect(validateExternalUrl('https://nonexistent.invalid')).rejects.toThrow("DNS resolution failed");
  });
});
