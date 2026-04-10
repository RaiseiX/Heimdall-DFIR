
import express, { Response, NextFunction } from 'express';
import type { Server as IOServer } from 'socket.io';
import type { Pool } from 'pg';
import type { AuthRequest } from '../types/index';
import { getAvailableTools } from '../services/parserService';
import { parserQueue } from '../config/queue';
import { parserRateLimiter } from '../middleware/rateLimiter';

const router = express.Router();

function getPool(res: Response): Pool {
  return res.app.locals.pool as Pool;
}
function getIO(res: Response): IOServer {
  return res.app.locals.io as IOServer;
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

    const job = await parserQueue.add('parse', {
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
    const result = await pool.query(
      `SELECT elem->>'artifact_type' AS artifact_type,
              COUNT(*)::int           AS count
       FROM parser_results,
            jsonb_array_elements(
              CASE
                WHEN output_data ? 'unified_timeline' THEN output_data->'unified_timeline'
                WHEN jsonb_typeof(output_data) = 'array' THEN output_data
                ELSE '[]'::jsonb
              END
            ) AS elem
       WHERE id = $1
         AND elem->>'artifact_type' IS NOT NULL
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

export = router;
