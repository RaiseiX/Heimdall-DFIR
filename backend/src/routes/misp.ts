import express from 'express';
import logger from '../config/logger';
import type { Pool } from 'pg';
import { authenticate, requireRole } from '../middleware/auth';
import type { AuthRequest } from '../types/index';
import { syncMispInstance, testMispConnection, type MispInstance } from '../services/mispService';

const router = express.Router();

async function ensureTables(pool: Pool): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS misp_instances (
      id              UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
      name            VARCHAR(200) NOT NULL,
      url             TEXT NOT NULL,
      api_key         TEXT NOT NULL,
      verify_ssl      BOOLEAN DEFAULT true,
      is_active       BOOLEAN DEFAULT true,
      last_synced     TIMESTAMPTZ,
      indicator_count INTEGER DEFAULT 0,
      created_at      TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

let _tablesReady = false;
function initTables(pool: Pool): void {
  if (_tablesReady) return;
  _tablesReady = true;
  ensureTables(pool).catch(e => logger.error('[MISP] ensureTables error:', e.message));
}

router.use((req, res, next) => {
  initTables(res.app.locals.pool as Pool);
  next();
});

// api_key is never returned to the client.
const PUBLIC_COLS =
  `id, name, url, verify_ssl, is_active, last_synced, indicator_count, created_at`;

router.get('/instances', authenticate as any, async (_req, res) => {
  const pool: Pool = res.app.locals.pool;
  try {
    const { rows } = await pool.query(
      `SELECT ${PUBLIC_COLS}, (api_key IS NOT NULL AND api_key <> '') AS has_key
       FROM misp_instances ORDER BY created_at DESC`,
    );
    res.json(rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/instances', authenticate as any, (requireRole as any)('admin'), async (req: AuthRequest, res: any) => {
  const pool: Pool = res.app.locals.pool;
  const { name, url, api_key, verify_ssl = true } = req.body;

  if (!name || !url || !api_key) return res.status(400).json({ error: 'name, url et api_key sont requis' });
  try { new URL(url); } catch { return res.status(400).json({ error: 'URL invalide' }); }

  try {
    const { rows } = await pool.query(
      `INSERT INTO misp_instances (name, url, api_key, verify_ssl)
       VALUES ($1, $2, $3, $4) RETURNING ${PUBLIC_COLS}`,
      [name, url, api_key, verify_ssl !== false],
    );
    res.status(201).json(rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/instances/:id', authenticate as any, (requireRole as any)('admin'), async (req: AuthRequest, res: any) => {
  const pool: Pool = res.app.locals.pool;
  try {
    const { rowCount } = await pool.query(`DELETE FROM misp_instances WHERE id = $1`, [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Instance MISP non trouvée' });
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

async function loadInstance(pool: Pool, id: string): Promise<MispInstance | null> {
  const { rows } = await pool.query(
    `SELECT id, name, url, api_key, verify_ssl FROM misp_instances WHERE id = $1`, [id],
  );
  return rows.length ? (rows[0] as MispInstance) : null;
}

router.post('/instances/:id/test', authenticate as any, (requireRole as any)('admin'), async (req: AuthRequest, res: any) => {
  const pool: Pool = res.app.locals.pool;
  try {
    const inst = await loadInstance(pool, req.params.id);
    if (!inst) return res.status(404).json({ error: 'Instance MISP non trouvée' });
    res.json(await testMispConnection(inst));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/instances/:id/sync', authenticate as any, (requireRole as any)('admin', 'analyst'), async (req: AuthRequest, res: any) => {
  const pool: Pool = res.app.locals.pool;
  try {
    const inst = await loadInstance(pool, req.params.id);
    if (!inst) return res.status(404).json({ error: 'Instance MISP non trouvée' });

    const count = await syncMispInstance(inst, { limit: 5000 });
    await pool.query(
      `UPDATE misp_instances SET last_synced = NOW(), indicator_count = indicator_count + $1 WHERE id = $2`,
      [count, inst.id],
    );
    res.json({ success: true, indexed: count, message: `${count} indicateur(s) MISP indexé(s)` });
  } catch (err: any) {
    res.status(500).json({ error: `Erreur MISP : ${err.message}` });
  }
});

export = router;
