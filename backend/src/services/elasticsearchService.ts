
import { Client } from '@elastic/elasticsearch';
import logger from '../config/logger';
import { splitSearchTerms } from '../utils/textFilter';

const ES_URL = process.env.ELASTICSEARCH_URL || 'http://elasticsearch:9200';

let _client: Client | null = null;
function getClient(): Client {
  if (!_client) {
    _client = new Client({ node: ES_URL, requestTimeout: 30_000 });
  }
  return _client;
}

function indexFor(caseId: string): string {
  return `forensiclab-${caseId}`;
}

const FORENSIC_MAPPING = {
  properties: {
    case_id:          { type: 'keyword' },
    result_id:        { type: 'keyword' },
    evidence_id:      { type: 'keyword' },
    artifact_type:    { type: 'keyword' },
    artifact_name:    { type: 'keyword' },
    timestamp: {
      type:   'date',
      format: 'strict_date_optional_time||epoch_millis',
    },
    description: {
      type:     'text',
      analyzer: 'standard',
      fields: {

        keyword: { type: 'keyword', ignore_above: 512 },
      },
    },
    details: {
      type:     'text',
      analyzer: 'standard',
    },
    source: {
      type:         'keyword',
      ignore_above: 256,
    },
    raw: {

      type:    'object',
      enabled: false,
    },

    mitre_technique_id:   { type: 'keyword' },
    mitre_technique_name: { type: 'keyword' },
    mitre_tactic:         { type: 'keyword' },
    // Searchable text fields mirror the PG free-text search columns
    // (description/source/host/user/tool/path/ext/process/tags…). Each keeps a
    // `.keyword` sub-field so the terms aggregations (type/host/user pills) and
    // exact filters keep working on the raw value.
    host_name: {
      type:     'text',
      analyzer: 'standard',
      fields:   { keyword: { type: 'keyword', ignore_above: 256 } },
    },
    user_name: {
      type:     'text',
      analyzer: 'standard',
      fields:   { keyword: { type: 'keyword', ignore_above: 256 } },
    },
    process_name: {
      type:     'text',
      analyzer: 'standard',
      fields:   { keyword: { type: 'keyword', ignore_above: 512 } },
    },
    tool: {
      type:     'text',
      analyzer: 'standard',
      fields:   { keyword: { type: 'keyword', ignore_above: 256 } },
    },
    path: {
      type:     'text',
      analyzer: 'standard',
      fields:   { keyword: { type: 'keyword', ignore_above: 512 } },
    },
    event_id: { type: 'keyword' },
    ext:      { type: 'keyword', ignore_above: 64 },
    tags:     { type: 'keyword' },
    // Analyzed copy of tags for free-text search: PG matches tags::text with
    // case-insensitive ILIKE ("PowerShell Remoting" is found by "powershell"),
    // which a keyword field cannot do. Standard analyzer lowercases and
    // tokenizes, closing that gap for the multi-column search.
    tags_text: { type: 'text', analyzer: 'standard' },
    // Concatenation of every searchable column (description, host, user, tool,
    // path, tags… — see buildSearchText) analyzed with a FIXED trigram tokenizer.
    // PG free-text search is ILIKE '%term%' (case-insensitive substring); the
    // standard analyzer only matches whole tokens. Fixed 3-grams keep the index
    // small (≈1 term per char, vs N× with 2..15-gram ranges) while a
    // `match_phrase` over consecutive grams gives true substring semantics.
    search_text: { type: 'text', analyzer: 'trigram_analyzer' },
    sha1:     { type: 'keyword', ignore_above: 128 },
  },
} as const;

const INDEX_SETTINGS = {
  number_of_shards:   1,
  number_of_replicas: 0,
  refresh_interval:   '10s',
  max_result_window:  2_147_483_647,
  analysis: {
    analyzer: {
      trigram_analyzer: {
        tokenizer: 'trigram_tokenizer',
        filter:    ['lowercase'],
      },
    },
    tokenizer: {
      // Fixed 3-grams (not a range): the count of grams per token stays ≈ the
      // token length instead of (max-min+1)×length. token_chars letter+digit+
      // punctuation keeps paths like C:\Windows searchable as a substring.
      trigram_tokenizer: {
        type:        'ngram',
        min_gram:    3,
        max_gram:    3,
        token_chars: ['letter', 'digit', 'punctuation'],
      },
    },
  },
} as const;

async function withRetry<T>(fn: () => Promise<T>, maxRetries = 5, baseDelayMs = 2000): Promise<T> {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err: any) {
      if (attempt === maxRetries) throw err;
      const delay = baseDelayMs * Math.pow(2, attempt - 1);
      logger.warn(`[ES] attempt ${attempt}/${maxRetries} failed: ${err.message}. Retrying in ${delay}ms…`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  throw new Error('withRetry exhausted');
}

export async function initElasticsearch(): Promise<void> {
  await withRetry(() =>
    getClient().cluster.health({ wait_for_status: 'yellow', timeout: '10s' } as any)
  );
  logger.info('[ES] cluster ready');
}

export async function isAvailable(): Promise<boolean> {
  try {
    const health = await getClient().cluster.health({ timeout: '3s' } as any);
    return (health as any).status !== 'red';
  } catch {
    return false;
  }
}

export async function indexExists(caseId: string): Promise<boolean> {
  try {
    return Boolean(await getClient().indices.exists({ index: indexFor(caseId) }));
  } catch {
    return false;
  }
}

export async function ensureIndex(caseId: string): Promise<void> {
  const client = getClient();
  const index  = indexFor(caseId);
  const exists = await withRetry(() => client.indices.exists({ index }));
  if (!exists) {
    await withRetry(async () => {
      try {
        await client.indices.create({
          index,
          mappings: FORENSIC_MAPPING as any,
          settings: INDEX_SETTINGS as any,
        });
      } catch (err: any) {

        if (err?.body?.error?.type === 'resource_already_exists_exception' ||
            err?.meta?.body?.error?.type === 'resource_already_exists_exception') {
          return;
        }
        throw err;
      }
    });
    logger.info(`[ES] index created: ${index}`);
  } else {

    try {
      await client.indices.putSettings({
        index,
        settings: { index: { max_result_window: INDEX_SETTINGS.max_result_window } } as any,
      });
    } catch (_e) {}
  }
}

export async function countDocuments(caseId: string): Promise<number> {
  const client = getClient();
  const index  = indexFor(caseId);
  try {
    const res = await client.count({ index });
    return typeof res.count === 'number' ? res.count : 0;
  } catch (e: any) {
    logger.warn(`[ES] countDocuments warning (${caseId}): ${String(e.message).substring(0, 100)}`);
    return 0;
  }
}

export async function clearCaseIndex(caseId: string): Promise<void> {
  const client = getClient();
  const index  = indexFor(caseId);

  try {
    const exists = await client.indices.exists({ index });
    if (exists) {
      await client.indices.delete({ index });
      logger.info(`[ES] clearCaseIndex: deleted ${index}`);
    }
  } catch (e: any) {
    logger.warn(`[ES] clearCaseIndex delete warning (${caseId}): ${String(e.message).substring(0, 100)}`);
  }

  try {
    await client.indices.create({
      index,
      mappings: FORENSIC_MAPPING as any,
      settings: INDEX_SETTINGS as any,
    });
    logger.info(`[ES] clearCaseIndex: recreated ${index}`);
  } catch (e: any) {
    logger.warn(`[ES] clearCaseIndex create warning (${caseId}): ${String(e.message).substring(0, 100)}`);
  }
}

export async function deleteIndex(caseId: string): Promise<void> {
  try {
    const client = getClient();
    const index  = indexFor(caseId);
    const exists = await client.indices.exists({ index });
    if (exists) {
      await client.indices.delete({ index });
      logger.info(`[ES] deleteIndex: ${index}`);
    }
  } catch (e: any) {
    logger.warn(`[ES] deleteIndex warning (${caseId}): ${String(e.message).substring(0, 100)}`);
  }
}

export async function deleteByResultId(caseId: string, resultId: string): Promise<void> {
  try {
    const client = getClient();
    const index  = indexFor(caseId);
    const exists = await client.indices.exists({ index });
    if (!exists) return;
    await client.deleteByQuery({
      index,
      body: { query: { term: { result_id: resultId } } },
      refresh: true,
    });
    logger.info(`[ES] deleteByResultId: cleared result_id=${resultId} from ${index}`);
  } catch (e: any) {
    logger.warn(`[ES] deleteByResultId warning (${caseId}/${resultId}): ${String(e.message).substring(0, 100)}`);
  }
}

// Targeted cleanup for a partial re-parse: remove only the documents of the
// artifact types being re-run on one evidence, leaving other types untouched.
// deleteByResultId is too coarse here — it would drop every type tied to the
// result row, and the untouched types must stay searchable in ES.
export async function deleteByEvidenceAndTypes(caseId: string, evidenceId: string, artifactTypes: string[]): Promise<void> {
  if (!artifactTypes || artifactTypes.length === 0) return;
  try {
    const client = getClient();
    const index  = indexFor(caseId);
    const exists = await client.indices.exists({ index });
    if (!exists) return;
    await client.deleteByQuery({
      index,
      body: {
        query: {
          bool: {
            must: [
              { term: { evidence_id: evidenceId } },
              { terms: { artifact_type: artifactTypes } },
            ],
          },
        },
      },
      refresh: true,
    });
    logger.info(`[ES] deleteByEvidenceAndTypes: cleared ${artifactTypes.join(',')} for evidence ${evidenceId}`);
  } catch (e: any) {
    logger.warn(`[ES] deleteByEvidenceAndTypes warning (${caseId}/${evidenceId}): ${String(e.message).substring(0, 100)}`);
  }
}

export interface TimelineRecord {
  timestamp:     string;
  artifact_type: string;
  artifact_name: string;
  description:   string;
  source:        string;
  raw:           Record<string, unknown>;

  result_id?:    string | null;

  id?:                    number | null;
  mitre_technique_id?:   string | null;
  mitre_technique_name?: string | null;
  mitre_tactic?:         string | null;
  host_name?:            string | null;
  user_name?:            string | null;
  process_name?:         string | null;
  tool?:                 string | null;
  event_id?:             number | string | null;
  path?:                 string | null;
  ext?:                  string | null;
  tags?:                 string[] | null;
  sha1?:                 string | null;
  timestamp_kind?:       string | null;
  file_size?:            number | string | null;
  src_ip?:               string | null;
  dst_ip?:               string | null;
  detections?:           unknown[] | null;

  evidence_id?:          string | null;
  dedupe_hash?:          string | null;
}

// Columns mirrored from utils/textFilter.ts SEARCH_COLS (PG's free-text search).
// Separator is a control char — not letter/digit/punctuation — so the ngram
// tokenizer never builds a gram that bridges two columns (no false positives
// across column boundaries, matching PG's per-column ILIKE).
const SEARCH_COL_SEP = '\u0001';

function buildSearchText(rec: TimelineRecord): string | null {
  const parts = [
    rec.description,
    rec.source,
    rec.artifact_type,
    rec.event_id != null ? String(rec.event_id) : null,
    rec.host_name,
    rec.user_name,
    rec.tool,
    rec.details,
    rec.path,
    rec.ext,
    rec.process_name,
    Array.isArray(rec.tags) ? rec.tags.join(' ') : rec.tags,
  ];
  const joined = parts
    .filter(p => p != null && String(p).length > 0)
    .map(p => String(p))
    .join(SEARCH_COL_SEP);
  return joined.length ? joined : null;
}

export async function bulkIndex(
  caseId:     string,
  records:    TimelineRecord[],
  resultId?:  string,
  evidenceId?: string,
): Promise<void> {
  if (!records.length) return;

  const client = getClient();
  const index  = indexFor(caseId);

  await ensureIndex(caseId);

  const operations: unknown[] = [];
  for (const rec of records) {
    // Use the stable dedupe_hash as the document _id so ES mirrors the PG
    // unique (case_id, dedupe_hash) index: a duplicate row (same hive from a
    // VSS copy, re-index of an already-present event) overwrites instead of
    // adding a second document, keeping search counts identical to the DB.
    operations.push({ index: { _index: index, ...(rec.dedupe_hash ? { _id: rec.dedupe_hash } : {}) } });
    operations.push({
      case_id:       caseId,
      result_id:     resultId   ?? rec.result_id ?? null,
      evidence_id:   evidenceId ?? rec.evidence_id ?? null,
      timestamp:     rec.timestamp,
      artifact_type: rec.artifact_type,
      artifact_name: rec.artifact_name,
      description:   rec.description,
      details:       rec.details ?? null,
      source:        rec.source,
      raw:           rec.raw,
      mitre_technique_id:   rec.mitre_technique_id   ?? null,
      mitre_technique_name: rec.mitre_technique_name ?? null,
      mitre_tactic:         rec.mitre_tactic         ?? null,
      id:           rec.id           ?? null,
      host_name:    rec.host_name    ?? null,
      user_name:    rec.user_name    ?? null,
      process_name: rec.process_name ?? null,
      tool:         rec.tool         ?? null,
      event_id:     rec.event_id     ?? null,
      path:         rec.path         ?? null,
      ext:          rec.ext          ?? null,
      tags:         rec.tags         ?? null,
      tags_text:    rec.tags         ?? null,
      search_text:  buildSearchText(rec),
      sha1:         rec.sha1         ?? null,
      timestamp_kind: rec.timestamp_kind ?? null,
      file_size:    rec.file_size    ?? null,
      src_ip:       rec.src_ip       ?? null,
      dst_ip:       rec.dst_ip       ?? null,
      detections:   rec.detections   ?? null,
    });
  }

  const response = await client.bulk({ operations } as any);

  if (response.errors) {

    const firstErr = (response.items as any[]).find(i => i.index?.error);
    logger.warn(
      `[ES] bulkIndex partial error (${caseId}): ${JSON.stringify(firstErr?.index?.error ?? {}).substring(0, 200)}`,
    );
  }
}

export interface SearchParams {
  page?:           number;
  limit?:          number;
  sort_dir?:       string;
  sort_col?:       string;

  sort_multi?:     string;
  artifact_types?: string;
  search?:         string;
  start_time?:     string;
  end_time?:       string;
  result_id?:      string;
  evidence_id?:    string;
  evidence_ids?:   string[];
  // Skip the filter-context terms aggs (types/hosts/users). The artifact
  // browser pays for them yet only uses records/total/columns; on a big
  // filtered set the aggs dominate the latency (observed 2.9s vs 150ms).
  skipAggs?:       boolean;
}

export interface SearchResult {
  records:                  unknown[];
  total:                    number;
  page:                     number;
  limit:                    number;
  total_pages:              number;
  artifact_types_available: string[];
  artifact_types_counts?:   Record<string, number>;
  hosts_available?:         string[];
  users_available?:         string[];
}

// Free-text search now runs on the single `search_text` field (see
// buildSearchText) which mirrors the SEARCH_COLS list in utils/textFilter.ts.

const ES_SORT_FIELDS: Record<string, string> = {
  timestamp:     'timestamp',
  artifact_type: 'artifact_type',
  artifact_name: 'artifact_name',
  source:        'source',
  description:   'description.keyword',
};

function buildEsSortArray(
  params: SearchParams,
  tiebreaker: '_seq_no' | '_shard_doc' = '_seq_no',
): Array<Record<string, unknown>> {
  const sortArr: Array<Record<string, unknown>> = [];

  if (params.sort_multi) {
    for (const part of params.sort_multi.split(',')) {
      const [rawField, rawDir] = part.trim().split(':');
      const esField = ES_SORT_FIELDS[rawField ?? ''];
      if (!esField) continue;
      const dir = rawDir === 'asc' ? 'asc' : 'desc';
      sortArr.push({ [esField]: { order: dir } });
    }
  }

  if (sortArr.length === 0) {
    const direction = params.sort_dir === 'desc' ? 'desc' : 'asc';
    const sortField = ES_SORT_FIELDS[params.sort_col ?? 'timestamp'] ?? 'timestamp';
    sortArr.push({ [sortField]: { order: direction } });
  }

  sortArr.push({ [tiebreaker]: { order: 'asc' } });
  return sortArr;
}

export async function searchTimeline(
  caseId: string,
  params: SearchParams,
): Promise<SearchResult> {
  const pg        = Math.max(1, params.page  ?? 1);
  const lim       = Math.max(1, params.limit ?? 200);
  const offset    = (pg - 1) * lim;

  const filters: unknown[] = [];
  const mustClauses: unknown[] = [];

  if (params.artifact_types) {
    const types = params.artifact_types.split(',').filter(Boolean);
    if (types.length === 1) {
      filters.push({ term: { artifact_type: types[0] } });
    } else if (types.length > 1) {
      filters.push({ terms: { artifact_type: types } });
    }
  }

  if (params.start_time || params.end_time) {
    const range: Record<string, string> = {};
    if (params.start_time) range['gte'] = params.start_time;
    if (params.end_time)   range['lte'] = params.end_time;
    filters.push({ range: { timestamp: range } });
  }

  if (params.result_id) {
    filters.push({ term: { result_id: params.result_id } });
  }

  if (params.evidence_id) {
    filters.push({ term: { evidence_id: params.evidence_id } });
  }

  if (params.search?.trim()) {
    // PG free-text search is ILIKE '%term%' (case-insensitive substring) across
    // SEARCH_COLS. `search_text` is indexed with a fixed trigram analyzer, so a
    // `match_phrase` over the term's consecutive 3-grams == substring match in
    // any column. Terms shorter than 3 chars have no gram and are skipped (a
    // pathological 1-2 char ILIKE would match half the table anyway).
    for (const term of splitSearchTerms(params.search.trim())) {
      if (term.length >= 3) {
        mustClauses.push({ match_phrase: { search_text: { query: term } } });
      }
    }
  }

  const query = {
    bool: {
      filter: filters,
      must:   mustClauses,
    },
  };

  const filtersForTypeAgg: unknown[] = [];
  if (params.start_time || params.end_time) {
    const range: Record<string, string> = {};
    if (params.start_time) range['gte'] = params.start_time;
    if (params.end_time)   range['lte'] = params.end_time;
    filtersForTypeAgg.push({ range: { timestamp: range } });
  }
  if (params.result_id)  filtersForTypeAgg.push({ term: { result_id: params.result_id } });
  if (params.evidence_id) filtersForTypeAgg.push({ term: { evidence_id: params.evidence_id } });
  if (params.evidence_ids?.length) filtersForTypeAgg.push({ terms: { evidence_id: params.evidence_ids } });
  if (mustClauses.length) {

    filtersForTypeAgg.push(...mustClauses.map(m => ({ bool: { must: m } })));
  }

  const result = await getClient().search({
    index:            indexFor(caseId),
    from:             offset,
    size:             lim,
    query,
    sort:             buildEsSortArray(params, '_seq_no') as any,

    track_total_hits: true,
    ...(params.skipAggs ? {} : { aggs: {

      artifact_types_ctx: {
        filter: { bool: { filter: filtersForTypeAgg } },
        aggs: {
          types: { terms: { field: 'artifact_type', size: 50 } },
        },
      },
      hosts_ctx: {
        filter: { bool: { filter: filtersForTypeAgg } },
        aggs: {
          hosts: { terms: { field: 'host_name.keyword', size: 100 } },
        },
      },
      users_ctx: {
        filter: { bool: { filter: filtersForTypeAgg } },
        aggs: {
          users: { terms: { field: 'user_name.keyword', size: 100 } },
        },
      },
    } }),
    _source: ['id', 'timestamp', 'artifact_type', 'artifact_name', 'description', 'details', 'source', 'raw',
               'mitre_technique_id', 'mitre_technique_name', 'mitre_tactic',
               'host_name', 'user_name', 'process_name', 'tool', 'event_id', 'path', 'ext', 'tags',
               'sha1', 'timestamp_kind', 'file_size', 'src_ip', 'dst_ip', 'detections'],
  } as any);

  const total = typeof result.hits.total === 'number'
    ? result.hits.total
    : ((result.hits.total as any)?.value ?? 0);

  const records = (result.hits.hits as any[]).map(h => h._source);

  const buckets: Array<{ key: string; doc_count?: number }> =
    ((result.aggregations?.artifact_types_ctx as any)?.types?.buckets ?? []);
  const hostBuckets: Array<{ key: string }> =
    ((result.aggregations?.hosts_ctx as any)?.hosts?.buckets ?? []);
  const userBuckets: Array<{ key: string }> =
    ((result.aggregations?.users_ctx as any)?.users?.buckets ?? []);

  return {
    records,
    total,
    page:                     pg,
    limit:                    lim,
    total_pages:              Math.ceil(total / lim),
    artifact_types_available: buckets.map(b => b.key),
    artifact_types_counts:    Object.fromEntries(buckets.map(b => [b.key, b.doc_count ?? 0])),
    hosts_available:          hostBuckets.map(b => b.key),
    users_available:          userBuckets.map(b => b.key),
  };
}

export async function openPIT(caseId: string, keepAlive = '5m'): Promise<string> {
  const response = await getClient().openPointInTime({
    index: indexFor(caseId),
    keep_alive: keepAlive,
  } as any);
  return (response as any).id;
}

export async function closePIT(pitId: string): Promise<void> {
  try {
    await getClient().closePointInTime({ body: { id: pitId } } as any);
  } catch (e: any) {
    logger.warn(`[ES] closePIT warning: ${String(e.message).substring(0, 100)}`);
  }
}

export interface PitSearchParams extends SearchParams {
  pit_id?:      string;
  search_after?: unknown[];
  keep_alive?:  string;
}

export async function searchTimelineWithPIT(
  caseId: string,
  params: PitSearchParams,
): Promise<SearchResult & { next_search_after?: unknown[]; pit_id?: string }> {

  if (!params.pit_id) {
    return searchTimeline(caseId, params);
  }

  const lim       = Math.max(1, Math.min(params.limit ?? 200, 2000));

  const filters: unknown[] = [];
  const mustClauses: unknown[] = [];

  filters.push({ term: { case_id: caseId } });

  if (params.artifact_types) {
    const types = params.artifact_types.split(',').filter(Boolean);
    if (types.length === 1) filters.push({ term: { artifact_type: types[0] } });
    else if (types.length > 1) filters.push({ terms: { artifact_type: types } });
  }

  if (params.start_time || params.end_time) {
    const range: Record<string, string> = {};
    if (params.start_time) range['gte'] = params.start_time;
    if (params.end_time)   range['lte'] = params.end_time;
    filters.push({ range: { timestamp: range } });
  }

  if (params.result_id)  filters.push({ term: { result_id:  params.result_id } });
  if (params.evidence_id) filters.push({ term: { evidence_id: params.evidence_id } });

  if (params.search?.trim()) {
    for (const term of splitSearchTerms(params.search.trim())) {
      if (term.length >= 3) {
        mustClauses.push({ match_phrase: { search_text: { query: term } } });
      }
    }
  }

  const query = { bool: { filter: filters, must: mustClauses } };

  const body: Record<string, unknown> = {
    size: lim,
    query,

    sort: buildEsSortArray(params, '_shard_doc'),
    pit: {
      id:         params.pit_id,
      keep_alive: params.keep_alive ?? '5m',
    },
    track_total_hits: true,
    aggs: {
      artifact_types: { terms: { field: 'artifact_type', size: 30 } },
    },
    _source: [
      'timestamp', 'artifact_type', 'artifact_name', 'description', 'details', 'source', 'raw',
      'mitre_technique_id', 'mitre_technique_name', 'mitre_tactic',
      'host_name', 'user_name', 'process_name',
    ],
  };

  if (params.search_after?.length) {
    body.search_after = params.search_after;
  }

  const result = await getClient().search(body as any);

  const hits  = result.hits.hits as any[];
  const total = typeof result.hits.total === 'number'
    ? result.hits.total
    : ((result.hits.total as any)?.value ?? 0);

  const records = hits.map(h => h._source);

  const next_search_after: unknown[] | undefined =
    hits.length > 0 ? hits[hits.length - 1].sort : undefined;

  const returned_pit_id: string | undefined = (result as any).pit_id ?? params.pit_id;

  const buckets: Array<{ key: string }> =
    ((result.aggregations?.artifact_types as any)?.buckets ?? []);
  const artifact_types_available = buckets.map(b => b.key);

  return {
    records,
    total,
    page:                     1,
    limit:                    lim,
    total_pages:              Math.ceil(total / lim),
    artifact_types_available,
    next_search_after,
    pit_id:                   returned_pit_id,
  };
}

export async function rawSearch(caseId: string, body: Record<string, unknown>): Promise<any> {
  return getClient().search({
    index: indexFor(caseId),
    ...body,
  } as any);
}
