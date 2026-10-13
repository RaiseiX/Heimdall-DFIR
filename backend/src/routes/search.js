const express = require('express');
const { pool } = require('../config/database');
const { authenticate } = require('../middleware/auth');
const { caseListFilter } = require('../middleware/caseAccess');

const logger = require('../config/logger').default;
const router = express.Router();

router.get('/', authenticate, async (req, res) => {
  try {
    const { q, type } = req.query;
    if (!q || q.length < 2) return res.status(400).json({ error: 'Recherche trop courte (min 2 caractères)' });

    const results = { cases: [], evidence: [], iocs: [], network: [], timeline: [] };
    const pattern = `%${q}%`;

    if (!type || type === 'cases') {
      const acc = caseListFilter(req.user, 'c', 2);
      const casesResult = await pool.query(
        `SELECT c.id, c.case_number, c.title, c.status, c.priority FROM cases c
         WHERE (c.title ILIKE $1 OR c.case_number ILIKE $1 OR c.description ILIKE $1)${acc.sql} LIMIT 20`, [pattern, ...acc.params]
      );
      results.cases = casesResult.rows;
    }

    if (!type || type === 'evidence') {
      const acc = caseListFilter(req.user, 'c', 2);
      const evidenceResult = await pool.query(
        `SELECT e.id, e.name, e.evidence_type, e.hash_sha256, e.case_id, c.case_number
         FROM evidence e JOIN cases c ON e.case_id = c.id
         WHERE (e.name ILIKE $1 OR e.hash_sha256 ILIKE $1 OR e.hash_md5 ILIKE $1 OR e.notes ILIKE $1)${acc.sql} LIMIT 20`, [pattern, ...acc.params]
      );
      results.evidence = evidenceResult.rows;
    }

    if (!type || type === 'iocs') {
      const acc = caseListFilter(req.user, 'c', 3);
      const iocResult = await pool.query(
        `SELECT i.*, c.case_number, c.title as case_title
         FROM iocs i JOIN cases c ON i.case_id = c.id
         WHERE (i.value ILIKE $1 OR i.description ILIKE $1 OR $2 = ANY(i.tags))${acc.sql}
         ORDER BY i.severity DESC LIMIT 50`, [pattern, q.toLowerCase(), ...acc.params]
      );
      results.iocs = iocResult.rows;
    }

    if (!type || type === 'network') {
      const acc = caseListFilter(req.user, 'c', 2);
      const networkResult = await pool.query(
        `SELECT nc.*, c.case_number FROM network_connections nc JOIN cases c ON nc.case_id = c.id
         WHERE (nc.src_ip ILIKE $1 OR nc.dst_ip ILIKE $1 OR nc.notes ILIKE $1)${acc.sql} LIMIT 20`, [pattern, ...acc.params]
      );
      results.network = networkResult.rows;
    }

    if (!type || type === 'timeline') {
      const acc = caseListFilter(req.user, 'c', 2);
      const timelineResult = await pool.query(
        `SELECT te.*, c.case_number FROM timeline_events te JOIN cases c ON te.case_id = c.id
         WHERE (te.title ILIKE $1 OR te.description ILIKE $1 OR te.source ILIKE $1)${acc.sql} LIMIT 20`, [pattern, ...acc.params]
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
