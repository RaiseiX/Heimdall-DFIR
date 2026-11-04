
import express from 'express';
import type { Pool } from 'pg';
import { authenticate, requireRole } from '../middleware/auth';
import type { AuthRequest } from '../types/index';
import {
  discoverServer,
  fetchObjects,
  parseStixBundle,
  indexToES,
  searchIndicators,
  getStats,
  correlateCase,
} from '../services/taxiiService';

const { caseAccessParam } = require('../middleware/caseAccess');
const router = express.Router();
router.use(authenticate);
router.param('caseId', caseAccessParam);

function maskFeed(feed: Record<string, unknown>) {
  return { ...feed, auth_value: feed.auth_value ? '***' : null };
}

router.get('/feeds', authenticate as any, async (req, res) => {
  const pool: Pool = res.app.locals.pool;
  try {
    const { rows } = await pool.query(
      `SELECT id, name, url, api_root, collection_id, auth_type,
              is_active, last_fetched, indicator_count, created_at
       FROM taxii_feeds ORDER BY created_at DESC`,
    );
    res.json(rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/feeds', authenticate as any, (requireRole as any)('admin'), async (req: AuthRequest, res: any) => {
  const pool: Pool = res.app.locals.pool;
  const { name, url, api_root, collection_id, auth_type = 'none', auth_value } = req.body;

  if (!name || !url) return res.status(400).json({ error: 'name et url sont requis' });

  try {
    new URL(url);
  } catch {
    return res.status(400).json({ error: 'URL invalide' });
  }

  try {
    const { rows } = await pool.query(
      `INSERT INTO taxii_feeds (name, url, api_root, collection_id, auth_type, auth_value)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, name, url, api_root, collection_id, auth_type, is_active, last_fetched, indicator_count, created_at`,
      [name, url, api_root || null, collection_id || null, auth_type, auth_value || null],
    );
    res.status(201).json(maskFeed(rows[0]));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/feeds/:id', authenticate as any, (requireRole as any)('admin'), async (req: AuthRequest, res: any) => {
  const pool: Pool = res.app.locals.pool;
  try {
    const { rowCount } = await pool.query(`DELETE FROM taxii_feeds WHERE id = $1`, [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Feed non trouvé' });
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/feeds/:id/fetch', authenticate as any, (requireRole as any)('admin'), async (req: AuthRequest, res: any) => {
  const pool: Pool = res.app.locals.pool;

  let feed: Record<string, any>;
  try {
    const { rows } = await pool.query(`SELECT * FROM taxii_feeds WHERE id = $1`, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Feed non trouvé' });
    feed = rows[0];
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }

  try {

    const objects = await fetchObjects(feed as any, { limit: 2000 });
    const indicators = parseStixBundle(objects, feed.name);
    const count = await indexToES(indicators);

    await pool.query(
      `UPDATE taxii_feeds SET last_fetched = NOW(), indicator_count = indicator_count + $1 WHERE id = $2`,
      [count, feed.id],
    );

    res.json({
      success:   true,
      fetched:   objects.length,
      indexed:   count,
      message:   `${count} indicateur(s) indexé(s) dans Elasticsearch`,
    });
  } catch (err: any) {
    res.status(500).json({ error: `Erreur TAXII : ${err.message}` });
  }
});

router.get('/indicators', authenticate as any, async (req, res) => {
  try {
    const result = await searchIndicators({
      q:           req.query.q as string,
      ioc_type:    req.query.ioc_type as string,
      source_name: req.query.source_name as string,
      stix_type:   req.query.stix_type as string,
      page:        req.query.page ? parseInt(req.query.page as string, 10) : 1,
      limit:       req.query.limit ? parseInt(req.query.limit as string, 10) : 50,
    });
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/stats', authenticate as any, async (_req, res) => {
  try {
    res.json(await getStats());
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/correlate/:caseId', authenticate as any, (requireRole as any)('admin', 'analyst'), async (req: AuthRequest, res: any) => {
  const pool: Pool = res.app.locals.pool;
  try {
    const matches = await correlateCase(req.params.caseId, pool);
    res.json({ success: true, matches, message: `${matches} correspondance(s) trouvée(s)` });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/correlations/:caseId', authenticate as any, async (req, res) => {
  const pool: Pool = res.app.locals.pool;
  try {
    const { rows } = await pool.query(
      `SELECT id, ioc_value, ioc_type, stix_id, indicator_name, source_name, matched_at
       FROM threat_correlations WHERE case_id = $1
       ORDER BY matched_at DESC LIMIT 500`,
      [req.params.caseId],
    );
    res.json(rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export = router;
