import axios from 'axios';
import logger from '../config/logger';
import { getRedis } from '../config/redis';
// @ts-ignore — CommonJS helper (env first, then system_settings)
import { getIntegrationKey } from './integrationKeys';

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

export interface GreyNoiseResult {
  noise: boolean;          // mass-scanner background noise
  riot: boolean;           // known benign service (RIOT)
  classification: string;  // 'benign' | 'malicious' | 'unknown'
  name?: string;
  link?: string;
}
export interface UrlhausResult {
  query_status: string;    // 'ok' | 'no_results'
  threat?: string;
  url_status?: string;     // 'online' | 'offline'
  tags?: string[];
}
export interface MalwareBazaarResult {
  query_status: string;    // 'ok' | 'hash_not_found'
  file_name?: string;
  file_type?: string;
  signature?: string;      // malware family
  tags?: string[];
}
export interface HibpResult {
  pwned: boolean;
  breach_count: number;
  breaches?: string[];
}

export interface EnrichmentResult {
  greynoise?: GreyNoiseResult | null;
  urlhaus?: UrlhausResult | null;
  malwarebazaar?: MalwareBazaarResult | null;
  hibp?: HibpResult | null;
  noise?: boolean;          // true → likely internet background noise / benign (de-prioritise)
  noise_reason?: string;
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
  const apiKey = process.env.VIRUSTOTAL_API_KEY || await getIntegrationKey('virustotal');
  if (!apiKey) return null;

  let url: string;
  if (iocType === 'ip') {
    url = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(value)}`;
  } else if (iocType === 'domain') {
    url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(value)}`;
  } else if (['hash_md5', 'hash_sha1', 'hash_sha256'].includes(iocType)) {
    url = `https://www.virustotal.com/api/v3/files/${value}`;
  } else if (iocType === 'url') {
    const b64 = Buffer.from(value)
      .toString('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
    url = `https://www.virustotal.com/api/v3/urls/${b64}`;
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
  const apiKey = process.env.ABUSEIPDB_API_KEY || await getIntegrationKey('abuseipdb');
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
  const apiKey = process.env.SHODAN_API_KEY || await getIntegrationKey('shodan');
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
      `https://api.shodan.io/shodan/host/${ip}`,
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
      `http://ip-api.com/json/${ip}`,
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

// ── Noise-reduction / reputation sources ─────────────────────────────────

// GreyNoise Community API — is this IP just internet background noise?
async function enrichGreyNoise(ip: string): Promise<GreyNoiseResult | null> {
  const apiKey = process.env.GREYNOISE_API_KEY || await getIntegrationKey('greynoise');
  if (!apiKey) return null;
  try {
    const resp = await axios.get(`https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`, {
      headers: { key: apiKey, Accept: 'application/json' }, timeout: 10_000,
    });
    const d = resp.data || {};
    return {
      noise:          !!d.noise,
      riot:           !!d.riot,
      classification: d.classification || 'unknown',
      name:           d.name,
      link:           d.link,
    };
  } catch (err: any) {
    if (err.response?.status === 404) return { noise: false, riot: false, classification: 'unknown' };
    logger.warn('[enrich] greynoise error', { error: err.message });
    return null;
  }
}

// abuse.ch URLhaus — is this URL a known malware/payload URL?
async function enrichUrlhaus(url: string): Promise<UrlhausResult | null> {
  const apiKey = process.env.URLHAUS_API_KEY || await getIntegrationKey('urlhaus');
  if (!apiKey) return null;
  try {
    const body = new URLSearchParams({ url });
    const resp = await axios.post('https://urlhaus-api.abuse.ch/v1/url/', body, {
      headers: { 'Auth-Key': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10_000,
    });
    const d = resp.data || {};
    return {
      query_status: d.query_status || 'unknown',
      threat:       d.threat,
      url_status:   d.url_status,
      tags:         Array.isArray(d.tags) ? d.tags : undefined,
    };
  } catch (err: any) {
    logger.warn('[enrich] urlhaus error', { error: err.message });
    return null;
  }
}

// abuse.ch MalwareBazaar — is this hash a known malware sample?
async function enrichMalwareBazaar(hash: string): Promise<MalwareBazaarResult | null> {
  const apiKey = process.env.MALWAREBAZAAR_API_KEY || await getIntegrationKey('malwarebazaar');
  if (!apiKey) return null;
  try {
    const body = new URLSearchParams({ query: 'get_info', hash });
    const resp = await axios.post('https://mb-api.abuse.ch/api/v1/', body, {
      headers: { 'Auth-Key': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10_000,
    });
    const d = resp.data || {};
    const info = Array.isArray(d.data) && d.data.length ? d.data[0] : {};
    return {
      query_status: d.query_status || 'unknown',
      file_name:    info.file_name,
      file_type:    info.file_type,
      signature:    info.signature,
      tags:         Array.isArray(info.tags) ? info.tags : undefined,
    };
  } catch (err: any) {
    logger.warn('[enrich] malwarebazaar error', { error: err.message });
    return null;
  }
}

// Have I Been Pwned — is this email in known breaches?
async function enrichHibp(email: string): Promise<HibpResult | null> {
  const apiKey = process.env.HIBP_API_KEY || await getIntegrationKey('hibp');
  if (!apiKey) return null;
  try {
    const resp = await axios.get(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=true`,
      { headers: { 'hibp-api-key': apiKey, 'user-agent': 'Heimdall-DFIR' }, timeout: 10_000 },
    );
    const breaches = (resp.data || []).map((b: any) => b.Name).filter(Boolean);
    return { pwned: breaches.length > 0, breach_count: breaches.length, breaches };
  } catch (err: any) {
    if (err.response?.status === 404) return { pwned: false, breach_count: 0, breaches: [] };
    logger.warn('[enrich] hibp error', { error: err.message });
    return null;
  }
}

/**
 * Derive a noise verdict from enrichment: true → likely benign internet noise,
 * so automation can de-prioritise (lower severity) the related triage alert.
 * Returns { noise, reason }.
 */
export function assessNoise(r: EnrichmentResult): { noise: boolean; reason?: string } {
  if (r.greynoise?.riot) return { noise: true, reason: `GreyNoise RIOT: ${r.greynoise.name || 'known benign service'}` };
  if (r.greynoise && r.greynoise.noise && r.greynoise.classification === 'benign') {
    return { noise: true, reason: 'GreyNoise: benign background scanner' };
  }
  return { noise: false };
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
    result.greynoise = await enrichGreyNoise(value);
  }
  if (iocType === 'url' || iocType === 'domain') {
    result.urlhaus = await enrichUrlhaus(value);
  }
  if (['md5', 'sha1', 'sha256', 'hash'].includes(iocType)) {
    result.malwarebazaar = await enrichMalwareBazaar(value);
  }
  if (iocType === 'email') {
    result.hibp = await enrichHibp(value);
  }

  // Noise verdict — de-prioritise triage alerts for benign background traffic.
  const { noise, reason } = assessNoise(result);
  if (noise) { result.noise = true; result.noise_reason = reason; }

  await setCached(cacheKey, result);
  return result;
}

export function vtVerdictToColumns(vt: VTResult | null | undefined) {
  if (!vt) return { vt_malicious: null, vt_total: null, vt_verdict: null };
  return { vt_malicious: vt.malicious, vt_total: vt.total, vt_verdict: vt.verdict };
}
