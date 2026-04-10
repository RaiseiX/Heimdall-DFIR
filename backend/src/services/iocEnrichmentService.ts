import axios from 'axios';
import logger from '../config/logger';
import { getRedis } from '../config/redis';

const CACHE_TTL = 86400;

const VT_SUPPORTED = ['ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256'];

export interface VTResult {
  malicious: number;
  total: number;
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  country?: string;
  asn?: string;
  owner?: string;
}

export interface AbuseResult {
  score: number;
  reports: number;
  country?: string;
  isp?: string;
  domain?: string;
}

export interface ShodanResult {
  ports: number[];
  hostnames: string[];
  org?: string;
  country_name?: string;
  vulns: string[];
}

export interface GeoResult {
  country: string;
  country_code: string;
  city?: string;
  region?: string;
  org?: string;
  asn?: string;
  lat?: number;
  lon?: number;
  is_hosting?: boolean;
  is_proxy?: boolean;
  is_tor?: boolean;
}

export interface EnrichmentResult {
  virustotal?: VTResult | null;
  abuseipdb?: AbuseResult | null;
  shodan?: ShodanResult | null;
  shodan_ports?: number[];
  shodan_org?: string;
  shodan_vulns?: string[];
  geo?: GeoResult | null;
  geo_country_code?: string;
  geo_country?: string;
  geo_city?: string;
  geo_org?: string;
  enriched_at: string;
  from_cache?: boolean;
}

async function getCached(key: string): Promise<EnrichmentResult | null> {
  try {
    const redis = getRedis();
    if (!redis) return null;
    const raw = await redis.get(key);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

async function setCached(key: string, data: EnrichmentResult): Promise<void> {
  try {
    const redis = getRedis();
    if (!redis) return;
    await (redis as any).set(key, JSON.stringify(data), { EX: CACHE_TTL });
  } catch {

  }
}

async function enrichVirusTotal(value: string, iocType: string): Promise<VTResult | null> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return null;

  let url: string;
  if (iocType === 'ip') {
    url = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(value)}`;
  } else if (iocType === 'domain') {
    url = `https:
  } else if (['hash_md5', 'hash_sha1', 'hash_sha256'].includes(iocType)) {
    url = `https:
  } else if (iocType === 'url') {
    const b64 = Buffer.from(value)
      .toString('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\
    url = `https:
  } else {
    return null;
  }

  try {
    const resp = await axios.get(url, {
      headers: { 'x-apikey': apiKey },
      timeout: 15000,
    });

    const stats = (resp.data?.data?.attributes?.last_analysis_stats as Record<string, number>) || {};
    const malicious: number = stats.malicious || 0;
    const suspicious: number = stats.suspicious || 0;
    const total: number = Object.values(stats).reduce((a, b) => a + b, 0);

    let verdict: VTResult['verdict'] = 'unknown';
    if (malicious > 0) verdict = 'malicious';
    else if (suspicious > 0) verdict = 'suspicious';
    else if (total > 0) verdict = 'clean';

    const attrs = resp.data?.data?.attributes || {};
    return {
      malicious,
      total,
      verdict,
      country: attrs.country || undefined,
      asn: attrs.asn ? String(attrs.asn) : undefined,
      owner: attrs.as_owner || attrs.registrar || undefined,
    };
  } catch (err: any) {
    if (err.response?.status === 404) return { malicious: 0, total: 0, verdict: 'unknown' };
    logger.error('[VT] enrichment error:', err.message);
    return null;
  }
}

async function enrichAbuseIPDB(ip: string): Promise<AbuseResult | null> {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) return null;

  try {
    const resp = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      params: { ipAddress: ip, maxAgeInDays: 90 },
      headers: { Key: apiKey, Accept: 'application/json' },
      timeout: 15000,
    });

    const d = resp.data?.data || {};
    return {
      score: d.abuseConfidenceScore ?? 0,
      reports: d.totalReports ?? 0,
      country: d.countryCode || undefined,
      isp: d.isp || undefined,
      domain: d.domain || undefined,
    };
  } catch (err: any) {
    logger.error('[AbuseIPDB] enrichment error:', err.message);
    return null;
  }
}

async function enrichShodan(ip: string): Promise<ShodanResult | null> {
  const apiKey = process.env.SHODAN_API_KEY;
  if (!apiKey) return null;

  const cacheKey = `shodan:${ip}`;
  try {
    const redis = getRedis();
    if (redis) {
      const raw = await redis.get(cacheKey);
      if (raw) return JSON.parse(raw) as ShodanResult;
    }
  } catch {
  }

  try {
    const resp = await axios.get(
      `https:
      { params: { key: apiKey }, timeout: 15000 }
    );

    const d = resp.data || {};
    const result: ShodanResult = {
      ports:        Array.isArray(d.ports)     ? d.ports     : [],
      hostnames:    Array.isArray(d.hostnames) ? d.hostnames : [],
      org:          d.org          || undefined,
      country_name: d.country_name || undefined,
      vulns:        d.vulns ? Object.keys(d.vulns) : [],
    };

    try {
      const redis = getRedis();
      if (redis) {
        await (redis as any).set(cacheKey, JSON.stringify(result), { EX: CACHE_TTL });
      }
    } catch {

    }

    return result;
  } catch (err: any) {
    if (err.response?.status === 404) {
      return { ports: [], hostnames: [], vulns: [] };
    }
    logger.error('[Shodan] enrichment error:', err.message);
    return null;
  }
}

async function enrichGeoIP(ip: string): Promise<GeoResult | null> {

  if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|localhost)/i.test(ip)) return null;

  const cacheKey = `geo:${ip}`;
  try {
    const redis = getRedis();
    if (redis) {
      const raw = await redis.get(cacheKey);
      if (raw) return JSON.parse(raw) as GeoResult;
    }
  } catch {

  }

  try {
    const resp = await axios.get(
      `http:
      {
        params: { fields: 'status,country,countryCode,regionName,city,lat,lon,isp,org,as,proxy,hosting,query' },
        timeout: 5000,
      }
    );
    if (resp.data?.status !== 'success') return null;
    const d = resp.data;
    const result: GeoResult = {
      country: d.country || '',
      country_code: d.countryCode || '',
      city: d.city || undefined,
      region: d.regionName || undefined,
      org: d.org || d.isp || undefined,
      asn: d.as || undefined,
      lat: d.lat,
      lon: d.lon,
      is_hosting: d.hosting,
      is_proxy: d.proxy,
    };

    try {
      const redis = getRedis();
      if (redis) {
        await (redis as any).set(cacheKey, JSON.stringify(result), { EX: CACHE_TTL });
      }
    } catch {

    }

    return result;
  } catch {
    return null;
  }
}

export async function enrichIOC(value: string, iocType: string): Promise<EnrichmentResult> {
  const cacheKey = `enrich:${iocType}:${value.toLowerCase()}`;
  const cached = await getCached(cacheKey);
  if (cached) return { ...cached, from_cache: true };

  const result: EnrichmentResult = { enriched_at: new Date().toISOString() };

  if (VT_SUPPORTED.includes(iocType)) {
    result.virustotal = await enrichVirusTotal(value, iocType);
  }
  if (iocType === 'ip') {
    result.abuseipdb = await enrichAbuseIPDB(value);
    result.shodan = await enrichShodan(value);
    if (result.shodan) {
      result.shodan_ports = result.shodan.ports;
      result.shodan_org   = result.shodan.org;
      result.shodan_vulns = result.shodan.vulns;
    }
    const geo = await enrichGeoIP(value);
    result.geo = geo;
    if (geo) {
      result.geo_country_code = geo.country_code;
      result.geo_country      = geo.country;
      result.geo_city         = geo.city;
      result.geo_org          = geo.org;
    }
  }

  await setCached(cacheKey, result);
  return result;
}

export function vtVerdictToColumns(vt: VTResult | null | undefined) {
  if (!vt) return { vt_malicious: null, vt_total: null, vt_verdict: null };
  return { vt_malicious: vt.malicious, vt_total: vt.total, vt_verdict: vt.verdict };
}
