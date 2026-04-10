
const dnsPromises = require('dns').promises as typeof import('dns').promises;
import net from 'net';

const PRIVATE_RANGES: Array<[number, number]> = [
  [ipToInt('0.0.0.0'),       ipToInt('0.255.255.255')],
  [ipToInt('10.0.0.0'),      ipToInt('10.255.255.255')],
  [ipToInt('100.64.0.0'),    ipToInt('100.127.255.255')],
  [ipToInt('127.0.0.0'),     ipToInt('127.255.255.255')],
  [ipToInt('169.254.0.0'),   ipToInt('169.254.255.255')],
  [ipToInt('172.16.0.0'),    ipToInt('172.31.255.255')],
  [ipToInt('192.0.0.0'),     ipToInt('192.0.0.255')],
  [ipToInt('192.168.0.0'),   ipToInt('192.168.255.255')],
  [ipToInt('198.18.0.0'),    ipToInt('198.19.255.255')],
  [ipToInt('198.51.100.0'),  ipToInt('198.51.100.255')],
  [ipToInt('203.0.113.0'),   ipToInt('203.0.113.255')],
  [ipToInt('224.0.0.0'),     ipToInt('239.255.255.255')],
  [ipToInt('240.0.0.0'),     ipToInt('255.255.255.255')],
];

function ipToInt(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

export function isPrivateIP(address: string): boolean {

  if (net.isIPv6(address)) {
    const lower = address.toLowerCase();
    return (
      lower === '::1'           ||
      lower.startsWith('fe80:') ||
      lower.startsWith('fc')    ||
      lower.startsWith('fd')    ||
      lower === '::'
    );
  }

  if (!net.isIPv4(address)) return true;

  const n = ipToInt(address);
  return PRIVATE_RANGES.some(([lo, hi]) => n >= lo && n <= hi);
}

export async function validateExternalUrl(url: string): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid URL: ${url}`);
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`URL scheme '${parsed.protocol}' not allowed — use http or https`);
  }

  if (process.env.NODE_ENV === 'production' && parsed.protocol !== 'https:') {
    throw new Error('HTTPS is required in production');
  }

  if (net.isIP(parsed.hostname)) {
    if (isPrivateIP(parsed.hostname)) {
      throw new Error(`SSRF blocked: ${parsed.hostname} is a private/reserved address`);
    }
    return;
  }

  let addresses: Array<{ address: string; family: number }>;
  try {
    addresses = await dnsPromises.lookup(parsed.hostname, { all: true }) as unknown as Array<{ address: string; family: number }>;
  } catch (err: any) {
    throw new Error(`DNS resolution failed for '${parsed.hostname}': ${err.message}`);
  }

  if (!addresses.length) {
    throw new Error(`DNS resolved no addresses for '${parsed.hostname}'`);
  }

  for (const { address } of addresses) {
    if (isPrivateIP(address)) {
      throw new Error(
        `SSRF blocked: '${parsed.hostname}' resolves to private/reserved address ${address}`,
      );
    }
  }
}
