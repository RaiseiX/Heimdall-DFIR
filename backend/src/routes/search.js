const express = require('express');
const { pool } = require('../config/database');
const { authenticate } = require('../middleware/auth');

const logger = require('../config/logger').default;
const router = express.Router();

router.get('/', authenticate, async (req, res) => {
  try {
    const { q, type } = req.query;
    if (!q || q.length < 2) return res.status(400).json({ error: 'Recherche trop courte (min 2 caractères)' });

    const results = { cases: [], evidence: [], iocs: [], network: [], timeline: [] };
    const pattern = `%${q}%`;

    if (!type || type === 'cases') {
      const casesResult = await pool.query(
        `SELECT id, case_number, title, status, priority FROM cases
         WHERE title ILIKE $1 OR case_number ILIKE $1 OR description ILIKE $1 LIMIT 20`, [pattern]
      );
      results.cases = casesResult.rows;
    }

    if (!type || type === 'evidence') {
      const evidenceResult = await pool.query(
        `SELECT e.id, e.name, e.evidence_type, e.hash_sha256, e.case_id, c.case_number
         FROM evidence e JOIN cases c ON e.case_id = c.id
         WHERE e.name ILIKE $1 OR e.hash_sha256 ILIKE $1 OR e.hash_md5 ILIKE $1 OR e.notes ILIKE $1 LIMIT 20`, [pattern]
      );
      results.evidence = evidenceResult.rows;
    }

    if (!type || type === 'iocs') {
      const iocResult = await pool.query(
        `SELECT i.*, c.case_number, c.title as case_title
         FROM iocs i JOIN cases c ON i.case_id = c.id
         WHERE i.value ILIKE $1 OR i.description ILIKE $1 OR $2 = ANY(i.tags)
         ORDER BY i.severity DESC LIMIT 50`, [pattern, q.toLowerCase()]
      );
      results.iocs = iocResult.rows;
    }

    if (!type || type === 'network') {
      const networkResult = await pool.query(
        `SELECT nc.*, c.case_number FROM network_connections nc JOIN cases c ON nc.case_id = c.id
         WHERE nc.src_ip ILIKE $1 OR nc.dst_ip ILIKE $1 OR nc.notes ILIKE $1 LIMIT 20`, [pattern]
      );
      results.network = networkResult.rows;
    }

    if (!type || type === 'timeline') {
      const timelineResult = await pool.query(
        `SELECT te.*, c.case_number FROM timeline_events te JOIN cases c ON te.case_id = c.id
         WHERE te.title ILIKE $1 OR te.description ILIKE $1 OR te.source ILIKE $1 LIMIT 20`, [pattern]
      );
      results.timeline = timelineResult.rows;
    }

    const totalResults = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);
    res.json({ query: q, total: totalResults, results });
  } catch (err) {
    logger.error('Search error:', err);
    res.status(500).json({ error: 'Erreur recherche' });
  }
});

module.exports = router;
