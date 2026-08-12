// One-time (idempotent) re-parse of every sigma_rules.content to populate
// level / mitre_techniques / upstream_status — Task 4 of docs/superpowers/
// plans/2026-08-07-sigma-platform-scoping-and-honest-counts.md.
//
// WHY a script and not a SQL migration: db/migrations/20260810000000_sigma_
// rule_metadata.sql only adds the three columns (schema, no data). Populating
// them from stored YAML needs the same YAML-aware extraction sigmaService.ts
// already uses at import/update time (js-yaml via parseRule) — a plain SQL
// migration would have to re-implement that as regexes over raw text, at
// real risk of silently drifting from the extractor. Same house pattern as
// scripts/seedDfiq.js.
//
// Idempotent: re-parses `content` fresh every run and only issues an UPDATE
// when a value actually differs (IS DISTINCT FROM, which treats NULL/NULL
// and array/array equality correctly) — running it twice against an
// already-backfilled table updates zero rows the second time.
//
// It invents nothing: a rule whose YAML declares no `level:` gets level =
// NULL (never a default), same for upstream_status; a rule with no
// attack.t#### tags gets mitre_techniques = '{}' (empty, not NULL — "found
// none" is a real, non-fabricated answer here, unlike level/status where a
// missing field is genuinely unknown).
//
// Run inside the backend container so DB_HOST/DB_PASSWORD etc. resolve the
// same way the app does:
//   docker compose exec backend node scripts/backfillSigmaMetadata.js

// ts-jest already transforms .ts files inside the Jest sandbox (see
// jest.config.ts) — registering ts-node again there would double-hook the
// require('.ts') extension. Only needed when this script (or the module
// requiring sigmaService.ts below) runs standalone via plain `node`.
if (!process.env.JEST_WORKER_ID) {
  require('ts-node').register({
    transpileOnly: true,
    compilerOptions: {
      module: 'commonjs',
      esModuleInterop: true,
      allowSyntheticDefaultImports: true,
      resolveJsonModule: true,
    },
  });
}

const { parseRule } = require('../src/services/sigmaService');

async function runBackfill(pool) {
  const { rows } = await pool.query('SELECT id, content FROM sigma_rules');

  let updated = 0;
  let unchanged = 0;
  let invalid = 0;

  for (const row of rows) {
    const parsed = parseRule(row.content);
    if (!parsed.valid) { invalid++; continue; }

    const level           = parsed.level ?? null;
    const mitreTechniques = parsed.mitreTechniques ?? [];
    const upstreamStatus  = parsed.upstreamStatus ?? null;

    const result = await pool.query(
      `UPDATE sigma_rules
          SET level = $2, mitre_techniques = $3, upstream_status = $4
        WHERE id = $1
          AND (level IS DISTINCT FROM $2
               OR mitre_techniques IS DISTINCT FROM $3
               OR upstream_status IS DISTINCT FROM $4)`,
      [row.id, level, mitreTechniques, upstreamStatus],
    );
    if (result.rowCount > 0) updated++; else unchanged++;
  }

  return { scanned: rows.length, updated, unchanged, invalid };
}

async function main() {
  // eslint-disable-next-line global-require
  const { pool } = require('../src/config/database');
  const stats = await runBackfill(pool);
  // eslint-disable-next-line no-console
  console.log('[sigma:backfill-metadata]', stats);
  await pool.end();
}

module.exports = { runBackfill };

if (require.main === module) {
  main().catch((e) => {
    // eslint-disable-next-line no-console
    console.error('[sigma:backfill-metadata] failed', e);
    process.exit(1);
  });
}
