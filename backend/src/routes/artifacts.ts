
import express from 'express';
import xss from 'xss';
import type { Pool } from 'pg';
import { authenticate, requireRole } from '../middleware/auth';
import type { AuthRequest } from '../types/index';

const router = express.Router();

function ensureTable(pool: Pool) {
  pool.query(`
    CREATE TABLE IF NOT EXISTS artifact_notes (
      id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      case_id      UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
      artifact_ref VARCHAR(128) NOT NULL,
      note         TEXT NOT NULL,
      author_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at   TIMESTAMPTZ DEFAULT NOW(),
      updated_at   TIMESTAMPTZ DEFAULT NOW()
    )
  `).then(() =>
    pool.query(`CREATE INDEX IF NOT EXISTS idx_artifact_notes_case_ref ON artifact_notes(case_id, artifact_ref)`)
  ).catch(() => {});
}

function pool(req: express.Request): Pool {
  const p = (req as any).app.locals.pool as Pool;
  ensureTable(p);
  return p;
}

function sanitize(raw: unknown): string {
  return xss(String(raw ?? '').trim(), { whiteList: {} });
}

router.get('/:caseId/refs-with-notes', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const result = await pool(req).query(
      `SELECT DISTINCT artifact_ref FROM artifact_notes WHERE case_id = $1`,
      [caseId],
    );
    res.json({ refs: result.rows.map((r: any) => r.artifact_ref) });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/:caseId/:ref/notes', authenticate, async (req, res) => {
  try {
    const { caseId, ref } = req.params;
    const result = await pool(req).query(
      `SELECT n.id, n.note, n.created_at, n.updated_at,
              u.full_name AS author_name, u.username AS author_username, n.author_id
         FROM artifact_notes n
         JOIN users u ON u.id = n.author_id
        WHERE n.case_id = $1 AND n.artifact_ref = $2
        ORDER BY n.created_at ASC`,
      [caseId, ref],
    );
    res.json({ notes: result.rows });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/:caseId/:ref/notes', authenticate, (requireRole as any)('analyst', 'admin'), async (req: express.Request, res: express.Response) => {
  try {
    const { caseId, ref } = req.params;
    const userId = (req as AuthRequest).user?.id;
    const safeNote = sanitize(req.body?.note);
    if (!safeNote) return res.status(400).json({ error: 'Note vide' });

    const result = await pool(req).query(
      `INSERT INTO artifact_notes (case_id, artifact_ref, note, author_id)
       VALUES ($1, $2, $3, $4)
       RETURNING id, note, created_at, updated_at`,
      [caseId, ref, safeNote, userId],
    );
    res.status(201).json({ note: result.rows[0] });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.put('/:caseId/:ref/notes/:noteId', authenticate, async (req: express.Request, res: express.Response) => {
  try {
    const { caseId, ref, noteId } = req.params;
    const user = (req as AuthRequest).user;
    const safeNote = sanitize(req.body?.note);
    if (!safeNote) return res.status(400).json({ error: 'Note vide' });

    const result = await pool(req).query(
      user?.role === 'admin'
        ? `UPDATE artifact_notes SET note = $1, updated_at = NOW()
            WHERE id = $2 AND case_id = $3
            RETURNING id, note, created_at, updated_at`
        : `UPDATE artifact_notes SET note = $1, updated_at = NOW()
            WHERE id = $2 AND case_id = $3 AND author_id = $4
            RETURNING id, note, created_at, updated_at`,
      user?.role === 'admin'
        ? [safeNote, noteId, caseId]
        : [safeNote, noteId, caseId, user?.id],
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Note introuvable ou non autorisée' });
    res.json({ note: result.rows[0] });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

router.delete('/:caseId/:ref/notes/:noteId', authenticate, async (req: express.Request, res: express.Response) => {
  try {
    const { caseId, noteId } = req.params;
    const user = (req as AuthRequest).user;

    const result = await pool(req).query(
      user?.role === 'admin'
        ? `DELETE FROM artifact_notes WHERE id = $1 AND case_id = $2 RETURNING id`
        : `DELETE FROM artifact_notes WHERE id = $1 AND case_id = $2 AND author_id = $3 RETURNING id`,
      user?.role === 'admin'
        ? [noteId, caseId]
        : [noteId, caseId, user?.id],
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Note introuvable ou non autorisée' });
    res.json({ deleted: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

export = router;
