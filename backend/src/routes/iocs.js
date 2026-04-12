const express = require('express');
const { pool } = require('../config/database');
const { authenticate, auditLog } = require('../middleware/auth');
const { enrichIOC, vtVerdictToColumns } = require('../services/iocEnrichmentService');

const logger = require('../config/logger').default;
const router = express.Router();

router.get('/:caseId', authenticate, async (req, res) => {
  try {
    const { type, malicious, search } = req.query;
    let query = 'SELECT * FROM iocs WHERE case_id = $1';
    const params = [req.params.caseId];
    let idx = 2;

    if (type) { query += ` AND ioc_type = $${idx++}`; params.push(type); }
    if (malicious !== undefined) { query += ` AND is_malicious = $${idx++}`; params.push(malicious === 'true'); }
    if (search) {
      query += ` AND (value ILIKE $${idx} OR description ILIKE $${idx})`;
      params.push(`%${search}%`);
      idx++;
    }

    query += ' ORDER BY severity DESC, created_at DESC';
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/:caseId', authenticate, async (req, res) => {
  try {
    const { ioc_type, value, description, severity, is_malicious, source, first_seen, last_seen, tags } = req.body;
    const result = await pool.query(
      `INSERT INTO iocs (case_id, ioc_type, value, description, severity, is_malicious, source, first_seen, last_seen, tags, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
      [req.params.caseId, ioc_type, value, description, severity || 5, is_malicious, source, first_seen, last_seen, tags || [], req.user.id]
    );
    await auditLog(req.user.id, 'create_ioc', 'ioc', result.rows[0].id, { ioc_type, value }, req.ip);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/top-shared', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         i.value       AS ioc_value,
         i.ioc_type,
         COUNT(DISTINCT i.case_id) AS case_count,
         COUNT(*)                  AS total_occurrences,
         BOOL_OR(i.is_malicious)   AS any_malicious,
         MAX(i.severity)           AS max_severity,
         MAX(i.created_at)         AS last_seen
       FROM iocs i
       WHERE i.value IS NOT NULL AND i.value != ''
       GROUP BY i.value, i.ioc_type
       HAVING COUNT(DISTINCT i.case_id) > 1
       ORDER BY case_count DESC, total_occurrences DESC
       LIMIT 10`,
    );
    res.json(result.rows);
  } catch (err) {
    logger.error('[iocs] top-shared:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/quick-enrich', authenticate, async (req, res) => {
  const { value, type } = req.query;
  if (!value) return res.status(400).json({ error: 'value required' });
  try {
    const enrichment = await enrichIOC(value, type || 'ip');
    res.json({ value, type: type || 'ip', enrichment, from_cache: enrichment.from_cache || false });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/search/global', authenticate, async (req, res) => {
  try {
    const { q, type } = req.query;

    let query = `
      SELECT i.*, c.case_number, c.title as case_title
      FROM iocs i
      JOIN cases c ON i.case_id = c.id
    `;
    const params = [];
    let idx = 1;
    const conditions = [];

    if (q) {
      conditions.push(`(i.value ILIKE $${idx} OR i.description ILIKE $${idx} OR $${idx + 1} = ANY(i.tags))`);
      params.push(`%${q}%`, q.toLowerCase());
      idx += 2;
    }
    if (type) {
      conditions.push(`i.ioc_type = $${idx++}`);
      params.push(type);
    }
    if (conditions.length) query += ' WHERE ' + conditions.join(' AND ');
    query += ' ORDER BY i.severity DESC, i.created_at DESC LIMIT 500';

    const result = await pool.query(query, params);
    res.json({ query: q || '', total: result.rows.length, results: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Erreur recherche IOC' });
  }
});

router.post('/:id/enrich', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const iocRes = await pool.query('SELECT id, value, ioc_type FROM iocs WHERE id = $1', [id]);
    if (!iocRes.rows.length) return res.status(404).json({ error: 'IOC non trouvé' });

    const { value, ioc_type } = iocRes.rows[0];
    const enrichment = await enrichIOC(value, ioc_type);
    const vtCols = vtVerdictToColumns(enrichment.virustotal);

    await pool.query(
      `UPDATE iocs SET
        vt_malicious    = $1,
        vt_total        = $2,
        vt_verdict      = $3,
        abuseipdb_score = $4,
        enriched_at     = NOW(),
        enrichment_data = $5
       WHERE id = $6`,
      [
        vtCols.vt_malicious,
        vtCols.vt_total,
        vtCols.vt_verdict,
        enrichment.abuseipdb?.score ?? null,
        JSON.stringify(enrichment),
        id,
      ]
    );

    res.json({ success: true, from_cache: enrichment.from_cache || false, enrichment });
  } catch (err) {
    logger.error('[enrich]', err);
    res.status(500).json({ error: 'Erreur enrichissement' });
  }
});

router.post('/enrich-case/:caseId', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const iocRes = await pool.query(
      'SELECT id, value, ioc_type FROM iocs WHERE case_id = $1 ORDER BY severity DESC',
      [caseId]
    );

    res.json({ started: true, total: iocRes.rows.length });

    (async () => {
      for (const ioc of iocRes.rows) {
        try {
          const enrichment = await enrichIOC(ioc.value, ioc.ioc_type);
          const vtCols = vtVerdictToColumns(enrichment.virustotal);
          await pool.query(
            `UPDATE iocs SET vt_malicious=$1, vt_total=$2, vt_verdict=$3,
              abuseipdb_score=$4, enriched_at=NOW(), enrichment_data=$5 WHERE id=$6`,
            [vtCols.vt_malicious, vtCols.vt_total, vtCols.vt_verdict,
             enrichment.abuseipdb?.score ?? null, JSON.stringify(enrichment), ioc.id]
          );
          if (!enrichment.from_cache) {
            await new Promise(r => setTimeout(r, 300));
          }
        } catch (_e) {}
      }
    })();
  } catch (err) {
    res.status(500).json({ error: 'Erreur enrichissement batch' });
  }
});

router.get('/export-stix/:caseId', authenticate, async (req, res) => {
  try {
    const { caseId } = req.params;
    const crypto = require('crypto');

    const caseRes = await pool.query('SELECT case_number, title FROM cases WHERE id = $1', [caseId]);
    if (caseRes.rows.length === 0) return res.status(404).json({ error: 'Cas non trouvé' });
    const caseData = caseRes.rows[0];

    const iocRes = await pool.query(
      'SELECT * FROM iocs WHERE case_id = $1 ORDER BY severity DESC',
      [caseId]
    );

    const now = new Date().toISOString();

    function iocToStixPattern(ioc) {
      const v = ioc.value.replace(/'/g, "\\'");
      switch ((ioc.ioc_type || '').toLowerCase()) {
        case 'ip':
        case 'ipv4':     return `[ipv4-addr:value = '${v}']`;
        case 'ipv6':     return `[ipv6-addr:value = '${v}']`;
        case 'domain':   return `[domain-name:value = '${v}']`;
        case 'url':      return `[url:value = '${v}']`;
        case 'md5':      return `[file:hashes.MD5 = '${v}']`;
        case 'sha1':     return `[file:hashes.'SHA-1' = '${v}']`;
        case 'sha256':   return `[file:hashes.'SHA-256' = '${v}']`;
        case 'email':    return `[email-addr:value = '${v}']`;
        case 'filename': return `[file:name = '${v}']`;
        default:         return `[artifact:url = '${v}']`;
      }
    }

    const objects = iocRes.rows.map(ioc => ({
      type: 'indicator',
      spec_version: '2.1',
      id: `indicator--${crypto.randomUUID()}`,
      created:      ioc.created_at ? new Date(ioc.created_at).toISOString() : now,
      modified:     now,
      name:         `${(ioc.ioc_type || '').toUpperCase()}: ${ioc.value}`,
      description:  ioc.description || '',
      pattern:      iocToStixPattern(ioc),
      pattern_type: 'stix',
      valid_from:   ioc.first_seen ? new Date(ioc.first_seen).toISOString() : now,
      labels:       [ioc.ioc_type, ...(Array.isArray(ioc.tags) ? ioc.tags : []), ...(ioc.is_malicious ? ['malicious-activity'] : [])].filter(Boolean),
      confidence:   Math.round((ioc.severity || 5) * 10),
      external_references: [{
        source_name: 'ForensicLab',
        description: `Cas ${caseData.case_number} — ${caseData.title}`,
      }],
    }));

    const bundle = { type: 'bundle', id: `bundle--${crypto.randomUUID()}`, objects };

    const filename = `stix-${caseData.case_number}-${Date.now()}.json`;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.json(bundle);

    await auditLog(req.user.id, 'export_stix', 'case', caseId,
      { case_number: caseData.case_number, ioc_count: objects.length }, req.ip);
  } catch (err) {
    logger.error('[export stix]', err);
    if (!res.headersSent) res.status(500).json({ error: 'Erreur export STIX' });
  }
});

router.get('/internal-intel', authenticate, async (req, res) => {
  const { query, type, limit = '50' } = req.query;
  try {
    const esClient = req.app.locals.esClient;
    if (!esClient) return res.json({ hits: [], total: 0 });

    const must = [];
    if (query) must.push({ multi_match: { query, fields: ['value', 'notes', 'tags'] } });
    if (type) must.push({ term: { ioc_type: type } });

    const result = await esClient.search({
      index: 'threat_intel_internal',
      size: Math.min(parseInt(limit, 10) || 50, 200),
      body: {
        query: must.length > 0 ? { bool: { must } } : { match_all: {} },
        sort: [{ last_confirmed: { order: 'desc' } }],
      },
    });

    const hits = (result.hits?.hits || []).map(h => ({ id: h._id, ...h._source }));
    res.json({ hits, total: result.hits?.total?.value || hits.length });
  } catch (err) {
    if (err.message?.includes('index_not_found')) return res.json({ hits: [], total: 0 });
    logger.error('[internal-intel] error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/cross-case', authenticate, async (req, res) => {
  try {
    const { value } = req.query;
    if (!value?.trim()) return res.status(400).json({ error: 'Paramètre value requis' });
    const result = await pool.query(
      `SELECT DISTINCT c.id, c.case_number, c.title, c.status, c.priority,
              i.ioc_type, i.value AS ioc_value, i.created_at AS ioc_created_at
         FROM iocs i
         JOIN cases c ON i.case_id = c.id
        WHERE i.value ILIKE $1
        ORDER BY i.created_at DESC
        LIMIT 50`,
      [`%${value.trim()}%`]
    );
    res.json(result.rows);
  } catch (err) {
    logger.error('[iocs] cross-case:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/:id/confirm', authenticate, async (req, res) => {
  const { id } = req.params;
  const { confidence = 'confirmed', notes = '' } = req.body;

  try {
    const iocRes = await pool.query(
      `UPDATE iocs SET is_malicious = true, notes = COALESCE($2, notes), updated_at = NOW()
       WHERE id = $1 RETURNING *`,
      [id, notes || null]
    );
    if (iocRes.rows.length === 0) return res.status(404).json({ error: 'IOC not found' });
    const ioc = iocRes.rows[0];

    try {
      const esClient = req.app.locals.esClient;
      if (esClient) {
        await esClient.index({
          index: 'threat_intel_internal',
          id: ioc.id,
          document: {
            ioc_type: ioc.ioc_type,
            value: ioc.value,
            confidence,
            tags: [],
            source: 'analyst_confirmed',
            case_id: ioc.case_id,
            notes: notes || '',
            first_seen: ioc.created_at,
            last_confirmed: new Date().toISOString(),
          },
          refresh: true,
        });
      }
    } catch (esErr) {
      logger.warn('[IOC confirm] ES index failed (non-critical):', esErr.message);
    }

    try {
      await pool.query(
        `INSERT INTO audit_logs (user_id, action, resource_type, resource_id, details)
         VALUES ($1, 'confirm_ioc', 'ioc', $2, $3)`,
        [req.user.id, id, JSON.stringify({ value: ioc.value, type: ioc.ioc_type, confidence })]
      );
    } catch {}

    res.json({ ok: true, ioc });
  } catch (err) {
    logger.error('[IOC confirm] error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/:caseId/import-stix', authenticate, async (req, res) => {
  const { caseId } = req.params;
  const { bundles } = req.body;

  if (!Array.isArray(bundles) || bundles.length === 0) {
    return res.status(400).json({ error: 'bundles[] requis' });
  }

  function parsePattern(pattern) {
    if (!pattern || typeof pattern !== 'string') return null;

    const rules = [
      { re: /\[ipv4-addr:value\s*=\s*'([^']+)'\]/i,                   type: 'ip' },
      { re: /\[ipv6-addr:value\s*=\s*'([^']+)'\]/i,                   type: 'ip' },
      { re: /\[domain-name:value\s*=\s*'([^']+)'\]/i,                  type: 'domain' },
      { re: /\[url:value\s*=\s*'([^']+)'\]/i,                          type: 'url' },
      { re: /\[file:hashes\.'MD5'\s*=\s*'([^']+)'\]/i,                 type: 'hash_md5' },
      { re: /\[file:hashes\.'SHA-1'\s*=\s*'([^']+)'\]/i,               type: 'hash_sha1' },
      { re: /\[file:hashes\.'SHA-256'\s*=\s*'([^']+)'\]/i,             type: 'hash_sha256' },
      { re: /\[file:name\s*=\s*'([^']+)'\]/i,                          type: 'filename' },
      { re: /\[windows-registry-key:key\s*=\s*'([^']+)'\]/i,           type: 'registry_key' },
      { re: /\[mutex:name\s*=\s*'([^']+)'\]/i,                         type: 'mutex' },
      { re: /\[email-addr:value\s*=\s*'([^']+)'\]/i,                   type: 'email' },
      { re: /\[network-traffic:dst_ref\.type\s*=\s*'[^']*'[^\]]*value\s*=\s*'([^']+)'\]/i, type: 'ip' },
    ];

    for (const { re, type } of rules) {
      const m = pattern.match(re);
      if (m) return { ioc_type: type, value: m[1] };
    }
    return null;
  }

  function confidenceToSeverity(confidence) {
    if (confidence == null) return 5;
    return Math.max(1, Math.min(10, Math.round(confidence / 10)));
  }

  const toInsert = [];
  let skipped = 0;

  for (const bundle of bundles) {
    const objects = Array.isArray(bundle.objects) ? bundle.objects : [];
    for (const obj of objects) {
      if (obj.type !== 'indicator') continue;
      const parsed = parsePattern(obj.pattern);
      if (!parsed) { skipped++; continue; }

      const labels = Array.isArray(obj.labels) ? obj.labels : [];
      const isMalicious = labels.some(l =>
        ['malicious-activity', 'malware', 'apt', 'threat-actor'].includes(l.toLowerCase())
      );
      const tags = [
        ...labels,
        ...(obj.indicator_types || []),
      ].filter(Boolean);

      toInsert.push({
        ...parsed,
        description: obj.description || obj.name || '',
        severity: confidenceToSeverity(obj.confidence),
        is_malicious: isMalicious,
        source: obj.created_by_ref ? `OpenCTI (${obj.created_by_ref})` : 'OpenCTI',
        first_seen: obj.valid_from || null,
        last_seen: obj.valid_until || null,
        tags: tags.slice(0, 10),
        stix_id: obj.id || null,
      });
    }
  }

  if (toInsert.length === 0) {
    return res.json({ created: 0, skipped, errors: 0,
      message: 'Aucun indicateur STIX trouvé dans les bundles fournis.' });
  }

  let created = 0;
  let errors  = 0;

  for (const ioc of toInsert) {
    try {
      await pool.query(
        `INSERT INTO iocs (case_id, ioc_type, value, description, severity, is_malicious,
                           source, first_seen, last_seen, tags, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
         ON CONFLICT DO NOTHING`,
        [caseId, ioc.ioc_type, ioc.value, ioc.description, ioc.severity,
         ioc.is_malicious, ioc.source, ioc.first_seen, ioc.last_seen,
         ioc.tags, req.user.id]
      );
      created++;
    } catch {
      errors++;
    }
  }

  await auditLog(req.user.id, 'import_stix', 'iocs', caseId,
    { created, skipped, bundles_count: bundles.length }, req.ip).catch(() => {});

  res.json({ created, skipped, errors,
    message: `${created} IOC(s) importé(s), ${skipped} ignoré(s), ${errors} erreur(s).` });
});

router.get('/:value/cross-cases', authenticate, async (req, res) => {
  try {
    const { value } = req.params;
    const result = await pool.query(
      `SELECT c.id, c.case_number, c.title, c.status, c.priority,
              i.ioc_type, i.value AS ioc_value,
              i.severity, i.is_malicious, i.created_at AS ioc_created_at
       FROM iocs i
       JOIN cases c ON i.case_id = c.id
       WHERE i.value = $1
       ORDER BY c.created_at DESC
       LIMIT 100`,
      [value],
    );
    res.json({
      ioc_value:  value,
      case_count: result.rows.length,
      cases:      result.rows,
    });
  } catch (err) {
    logger.error('[iocs] cross-cases:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;
