
import express, { Response, NextFunction } from 'express';
import type { Server as IOServer } from 'socket.io';
import type { Pool } from 'pg';
import type { AuthRequest } from '../types/index';
import { getAvailableTools } from '../services/parserService';
import { parserQueue } from '../config/queue';
import { parserRateLimiter } from '../middleware/rateLimiter';

const { authenticate } = require('../middleware/auth');
const { caseAccessParam } = require('../middleware/caseAccess');
const router = express.Router();
router.use(authenticate);
router.param('caseId', caseAccessParam);

function getPool(res: Response): Pool {
  return res.app.locals.pool as Pool;
}
function getIO(res: Response): IOServer {
  return res.app.locals.io as IOServer;
}

// Collapses per-status row counts into a flat { status: count } map.
// Deliberately keeps every ingestion_files status distinct — no green-washing
// (empty/degraded/quarantined/skipped_duplicate must never be folded into a success count).
function rollupCounts(rows: Array<{ status: string; n: number }>): Record<string, number> {
  return Object.fromEntries(rows.map(r => [r.status, r.n]));
}

router.get('/available', (req: AuthRequest, res: Response) => {
  res.json(getAvailableTools());
});

router.post('/run', parserRateLimiter, async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const { parser, evidenceId, caseId, socketId, extraArgs } = req.body;

    if (!parser || !evidenceId || !caseId || !socketId) {
      return res.status(400).json({
        error: 'Champs requis: parser, evidenceId, caseId, socketId',
      });
    }

    const tools = getAvailableTools();
    if (!tools[parser]) {
      return res.status(400).json({ error: `Parseur inconnu: ${parser}` });
    }
    if (!tools[parser].available) {
      return res.status(409).json({
        error: `Outil ${tools[parser].name} non installé`,
        hint: `Déposez ${tools[parser].dll} dans ${process.env.ZIMMERMAN_TOOLS_DIR || '/app/zimmerman-tools'}`,
      });
    }

    const io = getIO(res);

    const sockets = await io.fetchSockets();
    const targetSocket = sockets.find((s) => s.id === socketId);
    if (!targetSocket) {
      return res.status(400).json({
        error: `Socket ${socketId} non connecté. Reconnectez-vous.`,
      });
    }

    const job = await parserQueue.add('parse' as any, {
      parser,
      evidenceId,
      caseId,
      userId: req.user.id,
      socketId,
      extraArgs: extraArgs || {},
    });

    res.json({
      message: `${tools[parser].name} mis en queue…`,
      jobId:    job.id,
      socketId,
      parser,
    });
  } catch (err) {
    next(err);
  }
});

// Honest per-status rollup for one evidence's ingestion_files rows (all 11 states —
// received/extracting/classified/queued/parsing/parsed/empty/degraded/error/quarantined/skipped_duplicate).
router.get('/status/:caseId/:evidenceId', async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const pool = getPool(res);
    const { caseId, evidenceId } = req.params;
    const result = await pool.query(
      `SELECT status, COUNT(*)::int n
       FROM ingestion_files
       WHERE evidence_id = $1
         AND case_id = $2
       GROUP BY status`,
      [evidenceId, caseId]
    );
    res.json({ evidence_id: evidenceId, counts: rollupCounts(result.rows) });
  } catch (err) {
    next(err);
  }
});

// The coverage ledger, file by file.
//
// `/status/:caseId/:evidenceId` above answers "how many of each status"; this one
// answers "which file, and why". That distinction is the point: an analyst who
// asks "did we miss anything" needs the 5 unsupported paths, not the number 5.
//
// The ledger holds one row per collected file and one per expanded archive member,
// so its total is the only checkable statement about completeness — row counts in
// the timeline rise with every parser improvement and prove nothing.
router.get('/coverage/:caseId', async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const pool = getPool(res);
    const { caseId } = req.params;
    const { status, search, evidence_id: evidenceId } = req.query;
    // Floored as well as capped. Math.min alone let `?limit=-3` through as
    // `LIMIT -3`, which Postgres rejects outright ("LIMIT must not be negative"),
    // so a malformed page request reached the analyst as a bare 500 instead of a
    // short page. The offset line below already floors; these two only looked symmetric.
    const limit = Math.min(Math.max(Number(req.query.limit) || 200, 1), 1000);
    const offset = Math.max(Number(req.query.offset) || 0, 0);

    const where: string[] = ['case_id = $1'];
    const params: unknown[] = [caseId];
    if (status) { params.push(String(status).split(',')); where.push(`status = ANY($${params.length})`); }
    if (evidenceId) { params.push(evidenceId); where.push(`evidence_id = $${params.length}`); }
    if (search) { params.push(`%${String(search)}%`); where.push(`relative_path ILIKE $${params.length}`); }
    const clause = where.join(' AND ');

    // Counts describe the perimeter under examination, never the filtered page.
    //
    // `status` and `search` are reading filters: they change what the analyst is
    // looking *through*, not what was collected, so they must stay out of this query.
    // A filter that shrank the totals would answer "did we miss anything?" with a
    // number that depends on what the analyst happened to type.
    //
    // `evidence_id` is different in kind — it selects *which collection* is under
    // examination, so it does belong here. Left out, a header claiming the case's
    // 531 files above a list of one evidence's files would overstate that evidence's
    // coverage: the mirror image of the failure this ledger exists to prevent.
    const scope: string[] = ['case_id = $1'];
    const scopeParams: unknown[] = [caseId];
    if (evidenceId) { scopeParams.push(evidenceId); scope.push(`evidence_id = $${scopeParams.length}`); }
    const counts = await pool.query(
      `SELECT status, COUNT(*)::int n
         FROM ingestion_files
        WHERE ${scope.join(' AND ')}
        GROUP BY status`,
      scopeParams,
    );
    // Ordered by path, tie-broken by id. relative_path carries no unique constraint,
    // and two collections in one case both hold System_Info/deb-packages.txt: ordering
    // on the path alone leaves equal keys in an order Postgres may vary between
    // queries, so a paginated walk can show one row twice and another never. A ledger
    // that answers "did we miss anything" cannot itself drop rows while paging. The
    // timeline route carries the same tie-breaker, for the same reason.
    const page = await pool.query(
      `SELECT relative_path, status, status_detail, file_size, sha256, evidence_id
         FROM ingestion_files
        WHERE ${clause}
        ORDER BY relative_path, id
        LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, limit, offset],
    );
    const filtered = await pool.query(
      `SELECT COUNT(*)::int n FROM ingestion_files WHERE ${clause}`, params,
    );

    const byStatus = rollupCounts(counts.rows);
    res.json({
      case_id: caseId,
      // What `counts` and `total` are counted over, stated rather than inferred:
      // the screen must be able to label "531 files" as the case's or this
      // evidence's without re-deriving it from which query parameters it sent.
      counts_scope: evidenceId ? 'evidence' : 'case',
      counts: byStatus,
      total: Object.values(byStatus).reduce((a, b) => a + b, 0),
      filtered_total: filtered.rows[0]?.n ?? 0,
      limit,
      offset,
      files: page.rows,
    });
  } catch (err) {
    next(err);
  }
});

router.get('/results/:caseId', async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const pool = getPool(res);
    const result = await pool.query(
      `SELECT pr.id, pr.parser_name, pr.record_count, pr.created_at,
              pr.evidence_id,
              COALESCE(
                e.name,
                regexp_replace(pr.input_file, '.*/([^/]+)/?$', '\\1')
              ) AS evidence_name,
              u.full_name AS parsed_by
       FROM parser_results pr
       LEFT JOIN evidence e ON pr.evidence_id = e.id
       LEFT JOIN users u ON pr.created_by = u.id
       WHERE pr.case_id = $1
         AND pr.parser_name != 'MagnetRESPONSE_Import'
       ORDER BY pr.created_at DESC`,
      [req.params.caseId]
    );
    res.json(result.rows);
  } catch (err) {
    next(err);
  }
});

router.get('/result/:resultId/types', async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const pool = getPool(res);
    // Counted from the rows that were actually written, not from output_data.
    //
    // The previous query exploded `output_data` as a JSON array. It is an object
    // — keys `parse_results`, `total_records`, `artifact_types` — so the CASE
    // fell through to '[]' and every collection reported zero artifact types
    // while showing its real record count beside it. Measured on a CatScale
    // collection of 335,666 events across 10 types (2026-08-13).
    //
    // `output_data.artifact_types` is not the answer either: it lists the types
    // *requested* of the parser, which for a Linux collection is the whole
    // Windows roster. Only collection_timeline knows what came out.
    const result = await pool.query(
      `SELECT artifact_type, COUNT(*)::int AS count
         FROM collection_timeline
        WHERE result_id = $1
          AND artifact_type <> ''
        GROUP BY 1
        ORDER BY 2 DESC`,
      [req.params.resultId]
    );
    res.json({ types: result.rows });
  } catch (err) {
    next(err);
  }
});

router.get('/result/:resultId/data', async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const pool = getPool(res);
    const page = Math.max(1, parseInt(req.query['page'] as string || '1', 10));
    const pageSize = Math.min(500, Math.max(1, parseInt(req.query['pageSize'] as string || '100', 10)));
    const offset = (page - 1) * pageSize;
    const artifactType = (req.query['artifactType'] as string) || null;

    const result = await pool.query(
      `WITH source AS (
         SELECT
           CASE
             WHEN jsonb_typeof(output_data) = 'array'         THEN output_data
             WHEN output_data ? 'unified_timeline'             THEN output_data->'unified_timeline'
             WHEN output_data ? 'hayabusa_timeline'            THEN output_data->'hayabusa_timeline'
             ELSE '[]'::jsonb
           END AS arr,
           (output_data ? 'unified_timeline') AS is_unified,
           parser_name,
           record_count
         FROM parser_results WHERE id = $1
       ),
       elems AS (
         SELECT elem FROM source, jsonb_array_elements(arr) AS elem
         WHERE NOT source.is_unified
            OR $4::text IS NULL
            OR elem->>'artifact_type' = $4
       )
       SELECT
         (SELECT parser_name  FROM source) AS parser_name,
         (SELECT record_count FROM source) AS record_count,
         (SELECT COUNT(*)::int FROM elems) AS total,
         (SELECT jsonb_agg(e)
          FROM (SELECT elem AS e FROM elems LIMIT $2 OFFSET $3) s) AS records`,
      [req.params.resultId, pageSize, offset, artifactType]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Résultat non trouvé' });
    }

    const row = result.rows[0];
    res.json({
      id: req.params.resultId,
      parserName: row.parser_name,
      total: parseInt(row.total, 10) || 0,
      page,
      pageSize,
      records: row.records || [],
    });
  } catch (err) {
    next(err);
  }
});

router.get('/result/:resultId/export/csv', async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const pool = getPool(res);
    const result = await pool.query(
      `SELECT pr.parser_name, pr.output_data, pr.record_count, pr.created_at,
              COALESCE(e.name, regexp_replace(pr.input_file, '.*/([^/]+)/?$', '\\1')) AS evidence_name
       FROM parser_results pr
       LEFT JOIN evidence e ON pr.evidence_id = e.id
       WHERE pr.id = $1`,
      [req.params.resultId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Résultat non trouvé' });
    }

    const { parser_name, output_data, created_at } = result.rows[0];

    let records: Record<string, unknown>[] = [];
    if (Array.isArray(output_data)) {
      records = output_data;
    } else if (output_data && typeof output_data === 'object') {
      if (Array.isArray((output_data as any).unified_timeline)) {
        records = (output_data as any).unified_timeline;
      } else if (Array.isArray((output_data as any).hayabusa_timeline)) {
        records = (output_data as any).hayabusa_timeline;
      }
    }

    if (records.length === 0) {
      return res.status(204).end();
    }

    const firstRaw = records[0];
    const first: Record<string, unknown> = (firstRaw && typeof (firstRaw as any).raw === 'object' && (firstRaw as any).raw !== null && !Array.isArray((firstRaw as any).raw))
      ? { ...firstRaw, ...(firstRaw as any).raw, raw: undefined }
      : { ...firstRaw };
    delete first.raw;

    const headers = Object.keys(first);

    const escape = (v: unknown): string => {
      const s = v === null || v === undefined ? '' : String(typeof v === 'object' ? JSON.stringify(v) : v);
      if (s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r')) {
        return '"' + s.replace(/"/g, '""') + '"';
      }
      return s;
    };

    const ts = new Date(created_at).toISOString().slice(0, 10).replace(/-/g, '');
    const safeName = parser_name.replace(/[^a-zA-Z0-9_-]/g, '_');
    const filename = `parser-${safeName}-${ts}.csv`;

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    res.write('\uFEFF');
    res.write(headers.map(escape).join(',') + '\r\n');

    for (const rec of records) {
      const flat: Record<string, unknown> = (rec && typeof (rec as any).raw === 'object' && (rec as any).raw !== null && !Array.isArray((rec as any).raw))
        ? { ...rec, ...(rec as any).raw, raw: undefined }
        : { ...rec };
      delete flat.raw;
      res.write(headers.map(h => escape(flat[h])).join(',') + '\r\n');
    }

    res.end();
  } catch (err) {
    next(err);
  }
});

router.delete('/results/:resultId', async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const pool = getPool(res);
    const { resultId } = req.params;

    const deleted = await pool.query(
      `DELETE FROM parser_results WHERE id = $1 RETURNING id, parser_name, record_count`,
      [resultId]
    );

    if (deleted.rowCount === 0) {
      return res.status(404).json({ error: 'Résultat introuvable' });
    }

    const row = deleted.rows[0];
    res.json({
      success: true,
      deleted_id: row.id,
      parser_name: row.parser_name,
      records_removed: row.record_count,
    });
  } catch (err) {
    next(err);
  }
});

(router as any).rollupCounts = rollupCounts;

export = router;
