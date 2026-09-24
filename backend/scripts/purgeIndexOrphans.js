const { Client } = require('@elastic/elasticsearch');
const { pool } = require('../src/config/database');
const { withCaseDeletion } = require('../src/services/caseDeletion');
const { auditLog } = require('../src/middleware/auth');
const { purgerOrphelins } = require('../src/services/indexOrphelins');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DELAI_SUPPRESSION_MS = 60 * 60 * 1000;

async function main() {
  const [caseId, drapeau] = process.argv.slice(2);
  if (!UUID.test(caseId || '')) throw new Error('usage : node scripts/purgeIndexOrphans.js <case_id> [--appliquer]');
  const appliquer = drapeau === '--appliquer';
  const es = new Client({ node: process.env.ELASTICSEARCH_URL, requestTimeout: DELAI_SUPPRESSION_MS });
  const index = `forensiclab-${caseId}`;

  const resultat = await purgerOrphelins({
    caseId,
    appliquer,
    compterParResultat: async () => {
      const r = await es.search({
        index, size: 0, track_total_hits: true,
        aggs: { r: { terms: { field: 'result_id', size: 10000 } }, sans: { missing: { field: 'result_id' } } },
      });
      return {
        par_resultat: r.aggregations.r.buckets.map(b => ({ result_id: String(b.key), docs: b.doc_count })),
        sans_resultat: r.aggregations.sans.doc_count,
      };
    },
    idsConnus: async () => {
      const { rows } = await pool.query('SELECT id FROM parser_results WHERE case_id = $1', [caseId]);
      return new Set(rows.map(r => String(r.id)));
    },
    verrou: (id, travail) => withCaseDeletion(pool, id, travail),
    supprimer: async (id, resultId) => {
      const r = await es.deleteByQuery({
        index, query: { term: { result_id: resultId } },
        conflicts: 'proceed', refresh: true, wait_for_completion: true, slices: 'auto',
      });
      if (Array.isArray(r.failures) && r.failures.length) throw new Error(`${r.failures.length} échec(s) ES`);
    },
    journaliser: details => auditLog(null, 'purge_index_orphans', 'case', caseId, details, 'script'),
  });

  console.log(JSON.stringify(resultat, null, 1));
}

main()
  .catch(e => { console.error(e.message); process.exitCode = 1; })
  .finally(() => pool.end());
