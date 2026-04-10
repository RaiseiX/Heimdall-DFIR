
import axios, { AxiosRequestConfig } from 'axios';
import { Client } from '@elastic/elasticsearch';
import type { Pool } from 'pg';
import { validateExternalUrl } from '../utils/networkUtils';
import logger from '../config/logger';

const ES_URL = process.env.ELASTICSEARCH_URL || 'http://elasticsearch:9200';
let _esClient: Client | null = null;
function getClient(): Client {
  if (!_esClient) _esClient = new Client({ node: ES_URL, requestTimeout: 30_000 });
  return _esClient;
}

const THREAT_INTEL_INDEX = 'threat_intel';

export interface TaxiiFeed {
  id:             string;
  name:           string;
  url:            string;
  api_root?:      string;
  collection_id?: string;
  auth_type:      'none' | 'bearer' | 'basic';
  auth_value?:    string;
  is_active:      boolean;
  last_fetched?:  string;
  indicator_count: number;
}

interface StixObject {
  id:                string;
  type:              string;
  name?:             string;
  description?:      string;
  pattern?:          string;
  pattern_type?:     string;
  labels?:           string[];
  confidence?:       number;
  valid_from?:       string;
  created:           string;
  modified:          string;
  external_references?: Array<{ source_name: string; external_id?: string }>;
}

export interface ParsedIndicator {
  stix_id:           string;
  stix_type:         string;
  name:              string;
  description:       string;
  ioc_value:         string | null;
  ioc_type:          string | null;
  indicator_pattern: string | null;
  labels:            string[];
  confidence:        number | null;
  source_name:       string;
  valid_from:        string | null;
  created:           string;
  modified:          string;
}

export async function ensureThreatIntelIndex(): Promise<void> {
  const client = getClient();
  try {
    const exists = await client.indices.exists({ index: THREAT_INTEL_INDEX });
    if (exists) return;
    await client.indices.create({
      index: THREAT_INTEL_INDEX,
      body: {
        settings: {
          number_of_shards:   1,
          number_of_replicas: 0,
          refresh_interval:   '5s',
        },
        mappings: {
          properties: {
            stix_id:           { type: 'keyword' },
            stix_type:         { type: 'keyword' },
            name:              { type: 'text', fields: { keyword: { type: 'keyword', ignore_above: 256 } } },
            description:       { type: 'text' },
            ioc_value:         { type: 'keyword' },
            ioc_type:          { type: 'keyword' },
            indicator_pattern: { type: 'text' },
            labels:            { type: 'keyword' },
            confidence:        { type: 'integer' },
            source_name:       { type: 'keyword' },
            valid_from:        { type: 'date' },
            created:           { type: 'date' },
            modified:          { type: 'date' },
          },
        },
      },
    } as any);
    logger.info('[ThreatIntel] Created Elasticsearch index threat_intel');
  } catch (err: any) {

    if (!String(err.message).includes('already exists')) {
      logger.warn('[ThreatIntel] ensureThreatIntelIndex warn', { error: err.message });
    }
  }
}

ensureThreatIntelIndex().catch(e => logger.warn('[ThreatIntel] index init failed', { error: e.message }));

function buildAxiosConfig(authType: string, authValue?: string): AxiosRequestConfig {
  const headers: Record<string, string> = {
    Accept: 'application/taxii+json;version=2.1',
  };
  if (authType === 'bearer' && authValue) {
    headers['Authorization'] = `Bearer ${authValue}`;
  } else if (authType === 'basic' && authValue) {
    headers['Authorization'] = `Basic ${Buffer.from(authValue).toString('base64')}`;
  }
  return { headers, timeout: 30_000 };
}

export async function discoverServer(
  url: string,
  authType: string,
  authValue?: string,
): Promise<{ title: string; api_roots: string[]; description?: string }> {
  await validateExternalUrl(url);

  const discoveryUrl = url.replace(/\/$/, '') + '/taxii2/';
  const cfg = buildAxiosConfig(authType, authValue);
  const res = await axios.get(discoveryUrl, cfg);
  const data = res.data;
  return {
    title:       data.title || 'Unknown',
    api_roots:   data.api_roots || [],
    description: data.description,
  };
}

export async function fetchCollections(
  feed: Pick<TaxiiFeed, 'url' | 'api_root' | 'auth_type' | 'auth_value'>,
): Promise<Array<{ id: string; title: string; description?: string }>> {
  await validateExternalUrl(feed.api_root || feed.url);
  const base = (feed.api_root || feed.url.replace(/\/$/, '') + '/stix').replace(/\/$/, '');
  const cfg = buildAxiosConfig(feed.auth_type, feed.auth_value);
  const res = await axios.get(`${base}/collections/`, cfg);
  return (res.data?.collections || []).map((c: any) => ({
    id:          c.id,
    title:       c.title || c.id,
    description: c.description,
  }));
}

export async function fetchObjects(
  feed: TaxiiFeed,
  options: { limit?: number; added_after?: string } = {},
): Promise<StixObject[]> {
  await validateExternalUrl(feed.api_root || feed.url);
  const base = (feed.api_root || feed.url.replace(/\/$/, '') + '/stix').replace(/\/$/, '');
  const collId = feed.collection_id || 'default';
  const cfg = buildAxiosConfig(feed.auth_type, feed.auth_value);

  const params: Record<string, string | number> = { limit: options.limit ?? 1000 };
  if (options.added_after) params['added_after'] = options.added_after;

  const url = `${base}/collections/${collId}/objects/`;
  const res = await axios.get(url, { ...cfg, params });
  const data = res.data;

  if (Array.isArray(data?.objects)) return data.objects;
  if (Array.isArray(data))          return data;
  return [];
}

const PATTERN_REGEXES: Array<{ re: RegExp; ioc_type: string }> = [
  { re: /\[ipv4-addr:value\s*=\s*'([^']+)'/i,           ioc_type: 'ipv4'    },
  { re: /\[ipv6-addr:value\s*=\s*'([^']+)'/i,           ioc_type: 'ipv6'    },
  { re: /\[domain-name:value\s*=\s*'([^']+)'/i,         ioc_type: 'domain'  },
  { re: /\[url:value\s*=\s*'([^']+)'/i,                 ioc_type: 'url'     },
  { re: /\[email-addr:value\s*=\s*'([^']+)'/i,          ioc_type: 'email'   },
  { re: /file:hashes\.'MD5'\s*=\s*'([^']+)'/i,          ioc_type: 'md5'     },
  { re: /file:hashes\.'SHA-1'\s*=\s*'([^']+)'/i,        ioc_type: 'sha1'    },
  { re: /file:hashes\.'SHA-256'\s*=\s*'([^']+)'/i,      ioc_type: 'sha256'  },
];

function extractIoc(pattern: string): { ioc_value: string; ioc_type: string } | null {
  for (const { re, ioc_type } of PATTERN_REGEXES) {
    const m = pattern.match(re);
    if (m) return { ioc_value: m[1], ioc_type };
  }
  return null;
}

export function parseStixBundle(
  objects:    StixObject[],
  sourceName: string,
): ParsedIndicator[] {
  const supported = new Set(['indicator', 'malware', 'attack-pattern']);
  return objects
    .filter(o => supported.has(o.type))
    .map(o => {
      const ioc = o.pattern ? extractIoc(o.pattern) : null;
      return {
        stix_id:           o.id,
        stix_type:         o.type,
        name:              o.name || o.id,
        description:       o.description || '',
        ioc_value:         ioc?.ioc_value ?? null,
        ioc_type:          ioc?.ioc_type  ?? null,
        indicator_pattern: o.pattern || null,
        labels:            o.labels || [],
        confidence:        o.confidence ?? null,
        source_name:       sourceName,
        valid_from:        o.valid_from || null,
        created:           o.created,
        modified:          o.modified,
      };
    });
}

export async function indexToES(indicators: ParsedIndicator[]): Promise<number> {
  if (!indicators.length) return 0;

  await ensureThreatIntelIndex();
  const client = getClient();

  const operations: unknown[] = [];
  for (const ind of indicators) {

    operations.push({ index: { _index: THREAT_INTEL_INDEX, _id: ind.stix_id } });
    operations.push(ind);
  }

  const response = await client.bulk({ operations } as any);
  if (response.errors) {
    const firstErr = (response.items as any[]).find(i => i.index?.error);
    logger.warn('[ThreatIntel] bulk partial error', { error: JSON.stringify(firstErr?.index?.error ?? {}).substring(0, 200) });
  }
  return indicators.length;
}

export interface IndicatorSearchParams {
  q?:           string;
  ioc_type?:    string;
  source_name?: string;
  stix_type?:   string;
  page?:        number;
  limit?:       number;
}

export async function searchIndicators(params: IndicatorSearchParams) {
  const client  = getClient();
  const pg      = Math.max(1, params.page  ?? 1);
  const lim     = Math.min(500, Math.max(1, params.limit ?? 50));
  const offset  = (pg - 1) * lim;

  const filters: unknown[] = [];
  const must:    unknown[] = [];

  if (params.ioc_type)    filters.push({ term: { ioc_type:    params.ioc_type    } });
  if (params.source_name) filters.push({ term: { source_name: params.source_name } });
  if (params.stix_type)   filters.push({ term: { stix_type:   params.stix_type   } });
  if (params.q?.trim()) {
    must.push({
      multi_match: {
        query:    params.q.trim(),
        fields:   ['name', 'description', 'ioc_value', 'indicator_pattern'],
        operator: 'and',
        type:     'best_fields',
      },
    });
  }

  try {
    const result = await client.search({
      index: THREAT_INTEL_INDEX,
      from:  offset,
      size:  lim,
      query: { bool: { filter: filters, must } },
      sort:  [{ modified: { order: 'desc' } }] as any,
    } as any);

    const total = typeof result.hits.total === 'number'
      ? result.hits.total
      : ((result.hits.total as any)?.value ?? 0);

    return {
      records:     (result.hits.hits as any[]).map(h => h._source),
      total,
      page:        pg,
      limit:       lim,
      total_pages: Math.ceil(total / lim),
    };
  } catch {
    return { records: [], total: 0, page: pg, limit: lim, total_pages: 0 };
  }
}

export async function getStats() {
  const client = getClient();
  try {
    const result = await client.search({
      index: THREAT_INTEL_INDEX,
      size:  0,
      aggs:  {
        by_type:   { terms: { field: 'stix_type',   size: 10 } },
        by_ioc:    { terms: { field: 'ioc_type',    size: 10 } },
        by_source: { terms: { field: 'source_name', size: 20 } },
      },
    } as any);
    const aggs = result.aggregations as any;
    const total = typeof result.hits.total === 'number'
      ? result.hits.total
      : ((result.hits.total as any)?.value ?? 0);
    return {
      total,
      by_type:   aggs?.by_type?.buckets   ?? [],
      by_ioc:    aggs?.by_ioc?.buckets    ?? [],
      by_source: aggs?.by_source?.buckets ?? [],
    };
  } catch {
    return { total: 0, by_type: [], by_ioc: [], by_source: [] };
  }
}

const IOC_FIELDS: Record<string, string> = {

  IpAddress:          'ipv4',
  SourceAddress:      'ipv4',
  DestinationAddress: 'ipv4',
  'Source Address':   'ipv4',
  'Dest Address':     'ipv4',
  RemoteAddress:      'ipv4',
  LocalAddress:       'ipv4',

  Hostname:           'domain',
  Domain:             'domain',
  RemoteHostname:     'domain',

  URL:                'url',
  Uri:                'url',
  RequestUri:         'url',

  MD5:                'md5',
  'MD5Hash':          'md5',
  'File MD5':         'md5',
  SHA256:             'sha256',
  'SHA-256':          'sha256',
  'File SHA256':      'sha256',
  Hash:               'sha256',
  Hashes:             'sha256',
};

export async function correlateCase(caseId: string, pool: Pool): Promise<number> {
  const client = getClient();

  try {
    const exists = await client.indices.exists({ index: THREAT_INTEL_INDEX });
    if (!exists) return 0;
    const countRes = await client.count({ index: THREAT_INTEL_INDEX });
    if ((countRes as any).count === 0) return 0;
  } catch {
    return 0;
  }

  const BATCH = 500;
  let offset  = 0;
  let totalMatches = 0;

  while (true) {
    const { rows } = await pool.query<{ raw: Record<string, string> }>(
      `SELECT raw FROM collection_timeline WHERE case_id = $1 LIMIT $2 OFFSET $3`,
      [caseId, BATCH, offset],
    );
    if (!rows.length) break;
    offset += rows.length;

    const iocMap = new Map<string, string>();
    for (const row of rows) {
      if (!row.raw || typeof row.raw !== 'object') continue;
      for (const [field, iocType] of Object.entries(IOC_FIELDS)) {
        const val = row.raw[field];
        if (val && typeof val === 'string' && val.trim() && val !== '-') {

          const cleaned = val.split(/[,\s;|]+/)[0].trim();
          if (cleaned) iocMap.set(cleaned, iocType);
        }
      }
    }

    if (!iocMap.size) continue;

    const iocValues = Array.from(iocMap.keys());
    let esResults: any[] = [];
    try {
      const res = await client.search({
        index: THREAT_INTEL_INDEX,
        size:  1000,
        query: { terms: { ioc_value: iocValues } },
        _source: ['stix_id', 'name', 'ioc_value', 'ioc_type', 'source_name'],
      } as any);
      esResults = (res.hits.hits as any[]).map(h => h._source);
    } catch {
      continue;
    }

    if (!esResults.length) continue;

    for (const match of esResults) {
      try {
        await pool.query(
          `INSERT INTO threat_correlations (case_id, ioc_value, ioc_type, stix_id, indicator_name, source_name)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (case_id, ioc_value, stix_id) DO NOTHING`,
          [caseId, match.ioc_value, match.ioc_type, match.stix_id, match.name, match.source_name],
        );
        totalMatches++;
      } catch {

      }
    }

    if (rows.length < BATCH) break;
  }

  return totalMatches;
}

export function correlateCaseAsync(caseId: string, pool: Pool): void {
  correlateCase(caseId, pool).then(n => {
    if (n > 0) logger.info('[ThreatIntel] IOC matches found', { caseId, count: n });
  }).catch(err => {
    logger.warn('[ThreatIntel] correlateCase error', { caseId, error: err.message });
  });
}
