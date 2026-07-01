import axios from 'axios';
import https from 'https';
import logger from '../config/logger';
import { validateExternalUrl } from '../utils/networkUtils';
import { indexToES, type ParsedIndicator } from './taxiiService';

export interface MispInstance {
  id:          string;
  name:        string;
  url:         string;       // base API URL, e.g. https://misp.local
  api_key:     string;       // MISP automation key (sent as Authorization header)
  verify_ssl?: boolean;      // false → accept self-signed certs
}

// MISP attribute type → Heimdall ioc_type. Composite types (value1|value2) keep value1.
const TYPE_MAP: Record<string, string> = {
  'ip-src': 'ip', 'ip-dst': 'ip', 'ip-src|port': 'ip', 'ip-dst|port': 'ip',
  'domain': 'domain', 'domain|ip': 'domain', 'hostname': 'domain', 'hostname|port': 'domain',
  'url': 'url', 'uri': 'url', 'link': 'url',
  'md5': 'hash', 'sha1': 'hash', 'sha256': 'hash', 'sha512': 'hash', 'imphash': 'hash', 'ssdeep': 'hash',
  'filename|md5': 'hash', 'filename|sha1': 'hash', 'filename|sha256': 'hash',
  'email': 'email', 'email-src': 'email', 'email-dst': 'email',
};

function client(inst: MispInstance) {
  return axios.create({
    baseURL: inst.url.replace(/\/+$/, ''),
    headers: {
      Authorization:  inst.api_key,
      Accept:         'application/json',
      'Content-Type': 'application/json',
    },
    timeout:   45_000,
    httpsAgent: inst.verify_ssl === false ? new https.Agent({ rejectUnauthorized: false }) : undefined,
  });
}

/** Lightweight reachability/credential check via MISP /servers/getVersion. */
export async function testMispConnection(inst: MispInstance): Promise<{ ok: boolean; version?: string }> {
  await validateExternalUrl(inst.url);
  try {
    const res = await client(inst).get('/servers/getVersion');
    return { ok: true, version: res.data?.version };
  } catch (err: any) {
    logger.warn('[MISP] connection test failed', { name: inst.name, error: err.message });
    return { ok: false };
  }
}

/**
 * Pull exportable attributes (to_ids = true) from a MISP instance and index them
 * into the shared Threat-Intel Elasticsearch index, alongside TAXII indicators.
 * Returns the number of indicators indexed.
 */
export async function syncMispInstance(inst: MispInstance, opts: { limit?: number } = {}): Promise<number> {
  await validateExternalUrl(inst.url);
  const limit = opts.limit ?? 5000;

  const res = await client(inst).post('/attributes/restSearch', {
    returnFormat:     'json',
    limit,
    page:             1,
    to_ids:           true,
    deleted:          false,
    includeEventTags: true,
  });

  const attrs: any[] = res.data?.response?.Attribute ?? [];
  const indicators: ParsedIndicator[] = [];

  for (const a of attrs) {
    const iocType = TYPE_MAP[a.type];
    if (!iocType) continue;
    const rawVal = String(a.value || '').split('|')[0].trim();
    if (!rawVal) continue;
    const ts = a.timestamp
      ? new Date(parseInt(a.timestamp, 10) * 1000).toISOString()
      : new Date().toISOString();

    indicators.push({
      stix_id:           `misp--${inst.id}--${a.uuid || a.id}`,
      stix_type:         'indicator',
      name:              a.comment || `${a.category} / ${a.type}`,
      description:       a.comment || '',
      ioc_value:         rawVal,
      ioc_type:          iocType,
      indicator_pattern: null,
      labels:            Array.isArray(a.Tag) ? a.Tag.map((t: any) => t.name).filter(Boolean) : [],
      confidence:        a.to_ids ? 80 : null,
      source_name:       `MISP · ${inst.name}`,
      valid_from:        null,
      created:           ts,
      modified:          ts,
    });
  }

  const count = await indexToES(indicators);
  logger.info('[MISP] synced instance', { name: inst.name, attributes: attrs.length, indexed: count });
  return count;
}
