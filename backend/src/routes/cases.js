const express = require('express');
const crypto = require('crypto');
const { pool } = require('../config/database');
const { authenticate, requireRole, auditLog } = require('../middleware/auth');
const { hardDeleteCase } = require('../services/hardDeleteService');
const { getRiskScore } = require('../services/riskScoreService');
const logger = require('../config/logger').default;
const { computeTriageScores, saveTriageScores, getTriageScores } = require('../services/triageScoreService');

const router = express.Router();

router.get('/', authenticate, async (req, res) => {
  try {
    const { status, priority, search, page = 1, limit = 50 } = req.query;
    let query = `
      SELECT c.*, u.full_name as investigator_name,
        (SELECT COUNT(*) FROM evidence WHERE case_id = c.id) as evidence_count,
        (SELECT COUNT(*) FROM iocs WHERE case_id = c.id) as ioc_count,
        (SELECT array_agg(t.name) FROM case_tags ct JOIN tags t ON ct.tag_id = t.id WHERE ct.case_id = c.id) as tags
      FROM cases c
      LEFT JOIN users u ON c.investigator_id = u.id
      WHERE 1=1
    `;
    const params = [];
    let idx = 1;

    if (status) { query += ` AND c.status = $${idx++}`; params.push(status); }
    if (priority) { query += ` AND c.priority = $${idx++}`; params.push(priority); }
    if (search) {
      query += ` AND (c.title ILIKE $${idx} OR c.case_number ILIKE $${idx} OR c.description ILIKE $${idx})`;
      params.push(`%${search}%`);
      idx++;
    }

    query += ` ORDER BY c.created_at DESC LIMIT $${idx++} OFFSET $${idx++}`;
    params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));

    const result = await pool.query(query, params);

    const countResult = await pool.query('SELECT COUNT(*) FROM cases');

    res.json({
      cases: result.rows,
      total: parseInt(countResult.rows[0].count),
      page: parseInt(page),
      limit: parseInt(limit)
    });
  } catch (err) {
    logger.error('Cases fetch error:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/stats/dashboard', authenticate, async (req, res) => {
  try {
    const [stats, evidenceStats, iocStats, recentActivity, dailyActivity, artifactStats] = await Promise.all([
      pool.query(`
        SELECT
          COUNT(*) FILTER (WHERE status = 'active') as active_cases,
          COUNT(*) FILTER (WHERE status = 'pending') as pending_cases,
          COUNT(*) FILTER (WHERE status = 'closed') as closed_cases,
          COUNT(*) FILTER (WHERE priority = 'critical') as critical_cases,
          COUNT(*) as total_cases
        FROM cases
      `),
      pool.query(`
        SELECT COUNT(*) as total_evidence,
          COUNT(*) FILTER (WHERE is_highlighted) as highlighted_evidence,
          COALESCE(SUM(file_size), 0) as total_size
        FROM evidence
      `),
      pool.query(`
        SELECT COUNT(*) as total_iocs,
          COUNT(*) FILTER (WHERE is_malicious = true) as malicious_iocs,
          COUNT(DISTINCT ioc_type::text) as ioc_types
        FROM iocs
      `),
      pool.query(`
        SELECT al.action, al.entity_type, al.details, al.created_at, u.full_name
        FROM audit_log al
        LEFT JOIN users u ON al.user_id = u.id
        ORDER BY al.created_at DESC LIMIT 10
      `),
      pool.query(`
        WITH days AS (
          SELECT generate_series(
            current_date - interval '6 days',
            current_date,
            interval '1 day'
          )::date AS day
        )
        SELECT
          days.day,
          to_char(days.day, 'Dy') AS label,
          COALESCE(ev.cnt, 0) AS events,
          COALESCE(ioc.cnt, 0) AS iocs
        FROM days
        LEFT JOIN (
          SELECT DATE(created_at) AS d, COUNT(*) AS cnt FROM audit_log
          WHERE created_at >= current_date - interval '6 days'
          GROUP BY d
        ) ev ON ev.d = days.day
        LEFT JOIN (
          SELECT DATE(created_at) AS d, COUNT(*) AS cnt FROM iocs
          WHERE created_at >= current_date - interval '6 days'
          GROUP BY d
        ) ioc ON ioc.d = days.day
        ORDER BY days.day
      `).catch(() => ({ rows: [] })),
      pool.query(`
        SELECT
          COUNT(DISTINCT artifact_type) AS artifact_types,
          SUM(cnt) AS total_lines,
          json_agg(
            json_build_object('type', artifact_type, 'lines', cnt)
            ORDER BY cnt DESC
          ) AS breakdown
        FROM (
          SELECT artifact_type, COUNT(*) AS cnt
          FROM collection_timeline
          GROUP BY artifact_type
        ) t
      `).catch(() => ({ rows: [{ artifact_types: 0, total_lines: 0, breakdown: [] }] })),
    ]);

    res.json({
      cases: stats.rows[0],
      evidence: evidenceStats.rows[0],
      iocs: iocStats.rows[0],
      recent_activity: recentActivity.rows,
      daily_activity: dailyActivity.rows,
      artifacts: artifactStats.rows[0] || { artifact_types: 0, total_lines: 0, breakdown: [] },
    });
  } catch (err) {
    logger.error('Dashboard stats error:', err.message, err.detail || '');
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/leaderboard', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        u.id,
        u.full_name,
        u.username,
        COALESCE((
          SELECT COUNT(*)::int FROM case_playbook_steps cps
          WHERE cps.completed_by = u.id AND cps.completed = TRUE
            AND cps.completed_at >= NOW() - INTERVAL '7 days'
        ), 0) AS steps_this_week,
        COALESCE((
          SELECT COUNT(*)::int FROM cases c
          WHERE c.investigator_id = u.id AND c.status = 'active'
        ), 0) AS active_cases,
        COALESCE((
          SELECT COUNT(*)::int FROM case_playbook_steps cps
          WHERE cps.completed_by = u.id AND cps.completed = TRUE
        ), 0) AS total_done
      FROM users u
      WHERE u.is_active = TRUE
      ORDER BY steps_this_week DESC, total_done DESC
      LIMIT 8
    `);
    res.json({ leaderboard: result.rows });
  } catch (err) {
    logger.error('Leaderboard error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/deadlines', authenticate, async (req, res) => {
  const SQL = `
    SELECT c.id, c.title, c.case_number, c.status, c.priority, c.report_deadline,
      u.full_name as investigator_name,
      EXTRACT(EPOCH FROM (c.report_deadline - NOW())) / 3600 AS hours_remaining
    FROM cases c
    LEFT JOIN users u ON c.investigator_id = u.id
    WHERE c.report_deadline IS NOT NULL
      AND c.report_deadline >= NOW()
      AND c.report_deadline <= NOW() + interval '60 days'
      AND c.status != 'closed'
    ORDER BY c.report_deadline ASC
  `;

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const result = await pool.query(SQL);
      return res.json({ deadlines: result.rows });
    } catch (err) {
      const isConnErr = /timeout|connection terminated|ECONNRESET/i.test(err.message);
      if (attempt === 0 && isConnErr) continue;
      logger.error('Deadlines fetch error:', err.message);
      return res.status(500).json({ error: 'Erreur serveur' });
    }
  }
});

router.get('/:id', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.*, u.full_name as investigator_name,
        (SELECT array_agg(t.name) FROM case_tags ct JOIN tags t ON ct.tag_id = t.id WHERE ct.case_id = c.id) as tags
      FROM cases c
      LEFT JOIN users u ON c.investigator_id = u.id
      WHERE c.id = $1
    `, [req.params.id]);

    if (result.rows.length === 0) return res.status(404).json({ error: 'Cas non trouvé' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/', authenticate, async (req, res) => {
  try {
    const { title, description, priority, investigator_id, tags, report_deadline } = req.body;

    if (!title || !title.trim()) {
      return res.status(400).json({ error: 'Le titre est requis' });
    }

    const countResult = await pool.query("SELECT COUNT(*) FROM cases WHERE case_number LIKE 'CASE-2026-%'");
    const num = parseInt(countResult.rows[0].count) + 1;
    const case_number = `CASE-2026-${String(num).padStart(3, '0')}`;

    const validInvestigator = investigator_id && investigator_id.match(/^[0-9a-f-]{36}$/i) ? investigator_id : null;

    const deadline = report_deadline ? new Date(report_deadline) : null;
    if (deadline && isNaN(deadline.getTime())) {
      return res.status(400).json({ error: 'Date d\'échéance invalide' });
    }

    const result = await pool.query(
      `INSERT INTO cases (case_number, title, description, priority, investigator_id, created_by, report_deadline)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [case_number, title.trim(), description || '', priority || 'medium', validInvestigator, req.user.id, deadline || null]
    );

    if (tags && Array.isArray(tags) && tags.length > 0) {
      for (const tagName of tags) {
        if (!tagName || !tagName.trim()) continue;
        let tagResult = await pool.query('SELECT id FROM tags WHERE name = $1', [tagName.trim()]);
        if (tagResult.rows.length === 0) {
          tagResult = await pool.query('INSERT INTO tags (name) VALUES ($1) RETURNING id', [tagName.trim()]);
        }
        await pool.query('INSERT INTO case_tags (case_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [result.rows[0].id, tagResult.rows[0].id]);
      }
    }

    await auditLog(req.user.id, 'create_case', 'case', result.rows[0].id, { case_number, title }, req.ip);
    req.app.locals.io?.emit('dashboard:update');
    res.status(201).json(result.rows[0]);
  } catch (err) {
    logger.error('Case create error:', err.message, err.detail || '');
    res.status(500).json({ error: 'Erreur création du cas: ' + err.message });
  }
});

router.put('/:id', authenticate, async (req, res) => {
  try {
    const { title, description, status, priority, investigator_id, report_deadline } = req.body;
    const hasDeadline = 'report_deadline' in req.body;
    const deadline = hasDeadline ? (report_deadline ? new Date(report_deadline) : null) : undefined;
    const params = [title, description, status, priority, investigator_id, req.params.id];
    const deadlineClause = hasDeadline ? ', report_deadline = $7' : '';
    if (hasDeadline) params.push(deadline);
    const result = await pool.query(
      `UPDATE cases SET title = COALESCE($1, title), description = COALESCE($2, description),
       status = COALESCE($3, status), priority = COALESCE($4, priority),
       investigator_id = COALESCE($5, investigator_id), updated_at = NOW(),
       closed_at = CASE WHEN $3 = 'closed' THEN NOW() ELSE closed_at END
       ${deadlineClause}
       WHERE id = $6 RETURNING *`,
      params
    );

    if (result.rows.length === 0) return res.status(404).json({ error: 'Cas non trouvé' });
    await auditLog(req.user.id, 'update_case', 'case', req.params.id, req.body, req.ip);
    req.app.locals.io?.emit('dashboard:update');
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/:id/audit', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const offset = parseInt(req.query.offset) || 0;

    const params = [id];

    const baseWhere = `
      (
        (al.entity_type = 'case'       AND al.entity_id = $1)
        OR (al.entity_type = 'evidence'  AND al.entity_id IN (
              SELECT id FROM evidence WHERE case_id = $1))
        OR (al.entity_type = 'ioc'       AND al.entity_id IN (
              SELECT id FROM iocs      WHERE case_id = $1))
        OR (al.entity_type = 'report'    AND al.entity_id IN (
              SELECT id FROM reports   WHERE case_id = $1))
        OR (al.entity_type = 'collection' AND al.entity_id IN (
              SELECT id FROM parser_results WHERE case_id = $1))
      )`;

    const filters = [];

    if (req.query.action) {
      params.push(req.query.action);
      filters.push(`al.action = $${params.length}`);
    }
    if (req.query.user_id) {
      params.push(req.query.user_id);
      filters.push(`al.user_id = $${params.length}`);
    }
    if (req.query.username) {
      params.push(`%${req.query.username}%`);
      filters.push(`u.username ILIKE $${params.length}`);
    }
    if (req.query.date_from) {
      params.push(req.query.date_from);
      filters.push(`al.created_at >= $${params.length}`);
    }
    if (req.query.date_to) {
      params.push(req.query.date_to);
      filters.push(`al.created_at <= $${params.length}`);
    }

    const extraFilters = filters.length > 0 ? ' AND ' + filters.join(' AND ') : '';
    const where = `WHERE ${baseWhere}${extraFilters}`;

    const countResult = await pool.query(
      `SELECT COUNT(*) FROM audit_log al ${where}`, params
    );
    const total = parseInt(countResult.rows[0].count);

    const queryParams = [...params, limit, offset];

    const result = await pool.query(`
      SELECT
        al.id,
        al.action,
        al.entity_type,
        al.entity_id,
        al.details,
        al.created_at,
        al.ip_address,
        u.full_name  AS user_name,
        u.username
      FROM audit_log al
      LEFT JOIN users u ON al.user_id = u.id
      ${where}
      ORDER BY al.created_at DESC
      LIMIT $${queryParams.length - 1} OFFSET $${queryParams.length}
    `, queryParams);

    res.json({ total, rows: result.rows });
  } catch (err) {
    logger.error('Audit fetch error:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/:id/lateral-movement', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(`
      WITH events AS (
        SELECT
          NULLIF(TRIM(COALESCE(
            NULLIF(raw->>'WorkstationName', ''),
            NULLIF(raw->>'SourceHostname', ''),
            NULLIF(raw->>'IpAddress', ''),
            NULLIF(raw->>'SourceIp', '')
          )), '-') AS src,
          NULLIF(TRIM(COALESCE(
            NULLIF(raw->>'ComputerName', ''),
            NULLIF(raw->>'Computer', ''),
            NULLIF(raw->>'DestinationHostname', ''),
            NULLIF(raw->>'DestinationIp', '')
          )), '-') AS dst,
          COALESCE(NULLIF(TRIM(raw->>'TargetUserName'), ''), NULLIF(TRIM(raw->>'SubjectUserName'), ''), '?') AS username,
          COALESCE(raw->>'EventID', raw->>'EventId', '?') AS event_id,
          COALESCE(raw->>'LogonType', '') AS logon_type,
          timestamp
        FROM collection_timeline
        WHERE case_id = $1
          AND (
            raw->>'EventID'  IN ('4624','4648','4768','4769','4776','3')
            OR raw->>'EventId' IN ('4624','4648','4768','4769','4776','3')
          )
      )
      SELECT
        src, dst, username, event_id, logon_type,
        COUNT(*)::int          AS event_count,
        MIN(timestamp)         AS first_seen,
        MAX(timestamp)         AS last_seen
      FROM events
      WHERE src IS NOT NULL
        AND dst IS NOT NULL
        AND src <> dst
        AND src NOT IN ('127.0.0.1','::1','0.0.0.0')
        AND dst NOT IN ('127.0.0.1','::1','0.0.0.0')
      GROUP BY src, dst, username, event_id, logon_type
      ORDER BY event_count DESC
      LIMIT 500
    `, [id]);

    const rows = result.rows;

    const nodeMap = new Map();
    const addNode = (id) => {
      if (!nodeMap.has(id)) nodeMap.set(id, { id, total_events: 0, as_source: 0, as_target: 0 });
    };

    rows.forEach(r => {
      addNode(r.src); addNode(r.dst);
      nodeMap.get(r.src).total_events += r.event_count;
      nodeMap.get(r.src).as_source    += r.event_count;
      nodeMap.get(r.dst).total_events += r.event_count;
      nodeMap.get(r.dst).as_target    += r.event_count;
    });

    const edgeMap = new Map();
    rows.forEach(r => {
      const key = `${r.src}|||${r.dst}`;
      if (!edgeMap.has(key)) {
        edgeMap.set(key, { source: r.src, target: r.dst, count: 0, event_ids: new Set(), usernames: new Set(), first_seen: r.first_seen, last_seen: r.last_seen });
      }
      const e = edgeMap.get(key);
      e.count      += r.event_count;
      e.event_ids.add(r.event_id);
      if (r.username && r.username !== '?') e.usernames.add(r.username);
      if (r.first_seen < e.first_seen) e.first_seen = r.first_seen;
      if (r.last_seen  > e.last_seen)  e.last_seen  = r.last_seen;
    });

    const edges = [...edgeMap.values()].map(e => ({
      ...e,
      event_ids: [...e.event_ids],
      usernames: [...e.usernames],
    }));

    res.json({
      nodes: [...nodeMap.values()],
      edges,
      total_events: rows.reduce((s, r) => s + r.event_count, 0),
    });
  } catch (err) {
    logger.error('[lateral-movement]', err);
    res.status(500).json({ error: 'Erreur construction graphe: ' + err.message });
  }
});

router.post('/:id/triage', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const caseRes = await pool.query('SELECT id FROM cases WHERE id = $1', [id]);
    if (!caseRes.rows.length) return res.status(404).json({ error: 'Cas non trouvé' });

    const result = await computeTriageScores(pool, id);
    await saveTriageScores(pool, id, result);
    await auditLog(req.user.id, 'triage_compute', 'case', id, { machines: result.machines.length }, req.ip);

    res.json(result);
  } catch (err) {
    logger.error('[triage]', err);
    res.status(500).json({ error: 'Erreur calcul du triage: ' + err.message });
  }
});

router.get('/:id/triage', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    const [stored, caseIndicators] = await Promise.all([
      getTriageScores(pool, id),
      Promise.all([
        pool.query('SELECT COUNT(*) as cnt FROM yara_scan_results WHERE case_id = $1', [id]),
        pool.query('SELECT COALESCE(SUM(match_count),0) as total FROM sigma_hunt_results WHERE case_id = $1', [id]),
        pool.query('SELECT COUNT(*) as cnt FROM threat_correlations WHERE case_id = $1', [id]),
        pool.query('SELECT COUNT(*) as cnt FROM iocs WHERE case_id = $1 AND is_malicious = true', [id]),
      ]),
    ]);

    res.json({
      scores: stored.scores,
      computed_at: stored.computed_at,
      case_indicators: {
        yara_matches:         parseInt(caseIndicators[0].rows[0]?.cnt || '0'),
        sigma_matches:        parseInt(caseIndicators[1].rows[0]?.total || '0'),
        threat_intel_matches: parseInt(caseIndicators[2].rows[0]?.cnt || '0'),
        malicious_iocs:       parseInt(caseIndicators[3].rows[0]?.cnt || '0'),
      },
    });
  } catch (err) {
    logger.error('[triage get]', err);
    res.status(500).json({ error: 'Erreur récupération du triage' });
  }
});

router.get('/:id/detections/timestomping', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const threshold = parseInt(req.query.threshold_days || '0', 10);

    const result = await pool.query(
      `SELECT
         raw->>'FileName'            AS filename,
         raw->>'ParentPath'          AS parent_path,
         raw->>'Extension'           AS extension,
         raw->>'Created0x10'         AS sia_created,
         raw->>'Created0x30'         AS fn_created,
         raw->>'LastModified0x10'    AS sia_modified,
         raw->>'LastModified0x30'    AS fn_modified,
         raw->>'InUse'               AS in_use,
         raw->>'IsDirectory'         AS is_dir,
         timestamp                   AS indexed_at
       FROM collection_timeline
       WHERE case_id = $1
         AND artifact_type = 'mft'
         AND raw->>'Created0x10' IS NOT NULL
         AND raw->>'Created0x30' IS NOT NULL
         AND (
           -- $SIA Created before $FN Created (impossible without timestomping)
           (raw->>'Created0x10')::timestamptz < (raw->>'Created0x30')::timestamptz
           OR
           -- $SIA Modified before $FN Modified
           (raw->>'LastModified0x10' IS NOT NULL AND raw->>'LastModified0x30' IS NOT NULL AND
            (raw->>'LastModified0x10')::timestamptz < (raw->>'LastModified0x30')::timestamptz)
         )
       ORDER BY ABS(EXTRACT(EPOCH FROM (
         (raw->>'Created0x10')::timestamptz - (raw->>'Created0x30')::timestamptz
       ))) DESC
       LIMIT 500`,
      [id]
    );

    const items = result.rows
      .map(r => {
        const siaCreated = r.sia_created ? new Date(r.sia_created) : null;
        const fnCreated  = r.fn_created  ? new Date(r.fn_created)  : null;
        const diffMs     = siaCreated && fnCreated ? Math.abs(fnCreated - siaCreated) : 0;
        const diffDays   = diffMs / 86400000;
        if (threshold > 0 && diffDays < threshold) return null;
        return {
          filename:    r.filename    || '',
          parent_path: r.parent_path || '',
          extension:   r.extension   || '',
          sia_created: r.sia_created,
          fn_created:  r.fn_created,
          sia_modified: r.sia_modified,
          fn_modified:  r.fn_modified,
          diff_days:   Math.round(diffDays * 10) / 10,
          severity:    diffDays > 365 ? 'CRITIQUE' : diffDays > 30 ? 'ÉLEVÉ' : diffDays > 1 ? 'MOYEN' : 'FAIBLE',
          in_use:      r.in_use === '1' || r.in_use?.toLowerCase() === 'true',
        };
      })
      .filter(Boolean);

    res.json({ items, total: items.length, mft_records_analyzed: result.rowCount });
  } catch (err) {
    logger.error('[timestomping]', err);
    res.status(500).json({ error: 'Erreur détection timestomping: ' + err.message });
  }
});

router.get('/:id/detections/double-ext', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    const DANGEROUS_EXT = ['exe','bat','cmd','scr','vbs','js','ps1','hta','com','pif','lnk','dll','msi','reg','jar','wsf'];

    const DECOY_EXT = ['pdf','doc','docx','xls','xlsx','ppt','pptx','txt','jpg','jpeg','png','gif','bmp','mp3','mp4','avi','zip','rar'];

    const result = await pool.query(
      `SELECT
         timestamp,
         artifact_type,
         description,
         source,
         COALESCE(raw->>'FileName', raw->>'Name', raw->>'ExecutableName',
                  raw->>'AppId', raw->>'TargetFilenameLastPart', '') AS filename
       FROM collection_timeline
       WHERE case_id = $1
         AND artifact_type IN ('mft','lnk','prefetch','amcache','appcompat','recycle','shellbags','jumplist')
       ORDER BY timestamp ASC`,
      [id]
    );

    const doubleExtPattern = new RegExp(
      `\\.(${DECOY_EXT.join('|')})\\.(?:${DANGEROUS_EXT.join('|')})$`,
      'i'
    );

    const LEGITIMATE_SUFFIXES = [
      /\.d\.ts$/i,
      /\.spec\.(js|ts)$/i,
      /\.test\.(js|ts)$/i,
      /\.min\.js$/i,
      /\.config\.(js|ts)$/i,
      /\.user\.js$/i,
      /\.bundle\.js$/i,
      /\.chunk\.js$/i,
      /\.worker\.js$/i,
      /\.setup\.(js|ts)$/i,
    ];

    const matches = result.rows
      .map(r => {
        const fname = (r.filename || '').trim();
        if (!fname || !doubleExtPattern.test(fname)) return null;
        const parts = fname.toLowerCase().split('.');
        const dangerExt = parts[parts.length - 1];
        const decoyExt  = parts[parts.length - 2];

        if (decoyExt === 'txt' && dangerExt === 'js') return null;
        return {
          filename:    fname,
          decoy_ext:   decoyExt,
          danger_ext:  dangerExt,
          artifact_type: r.artifact_type,
          source:      r.source,
          description: r.description,
          timestamp:   r.timestamp,
          severity:    'CRITIQUE',
        };
      })
      .filter(Boolean);

    const items = matches.filter(item => {
      const filename = item.filename || '';
      return !LEGITIMATE_SUFFIXES.some(re => re.test(filename));
    });

    res.json({ items, total: items.length, records_scanned: result.rowCount });
  } catch (err) {
    logger.error('[double-ext]', err);
    res.status(500).json({ error: 'Erreur détection double extension: ' + err.message });
  }
});

router.get('/:id/detections/beaconing', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const minConnections = parseInt(req.query.min_connections || '5', 10);

    const result = await pool.query(
      `SELECT
         timestamp,
         COALESCE(
           raw->>'DestinationIp', raw->>'DestIP', raw->>'IpAddress',
           raw->>'TargetAddress', raw->>'IPAddress', raw->>'ip_address'
         ) AS dest_ip,
         COALESCE(raw->>'DestinationPort', raw->>'DestPort', raw->>'Port') AS dest_port,
         COALESCE(raw->>'Image', raw->>'ProcessName', raw->>'process_name') AS process_name,
         host_name,
         artifact_type
       FROM collection_timeline
       WHERE case_id = $1
         AND artifact_type IN ('evtx', 'hayabusa')
         AND (
           raw->>'DestinationIp' IS NOT NULL OR raw->>'DestIP' IS NOT NULL
           OR raw->>'IpAddress'  IS NOT NULL OR raw->>'TargetAddress' IS NOT NULL
         )
         AND timestamp IS NOT NULL
       ORDER BY timestamp ASC`,
      [id]
    );

    const ipGroups = {};
    for (const row of result.rows) {
      const ip = (row.dest_ip || '').trim();
      if (!ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('169.254')) continue;

      if (!ipGroups[ip]) ipGroups[ip] = [];
      ipGroups[ip].push({ ts: new Date(row.timestamp), port: row.dest_port, process: row.process_name, host: row.host_name });
    }

    const items = [];
    for (const [ip, conns] of Object.entries(ipGroups)) {
      if (conns.length < minConnections) continue;
      conns.sort((a, b) => a.ts - b.ts);

      const intervals = [];
      for (let i = 1; i < conns.length; i++) {
        intervals.push(conns[i].ts - conns[i - 1].ts);
      }
      if (intervals.length < minConnections - 1) continue;

      const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const variance    = intervals.reduce((s, v) => s + Math.pow(v - avgInterval, 2), 0) / intervals.length;
      const stdDev      = Math.sqrt(variance);

      const cv = avgInterval > 0 ? stdDev / avgInterval : 1;

      const beaconScore = Math.round(Math.max(0, Math.min(100, (1 - cv) * 100)));
      if (beaconScore < 40) continue;

      const avgSec = Math.round(avgInterval / 1000);
      items.push({
        dest_ip:          ip,
        connection_count: conns.length,
        avg_interval_sec: avgSec,
        avg_interval_label: avgSec >= 3600 ? `${Math.round(avgSec / 3600)}h` : avgSec >= 60 ? `${Math.round(avgSec / 60)}m` : `${avgSec}s`,
        cv:               Math.round(cv * 100) / 100,
        beacon_score:     beaconScore,
        first_seen:       conns[0].ts,
        last_seen:        conns[conns.length - 1].ts,
        dest_port:        conns[0].port || null,
        process_name:     conns[0].process || null,
        host_name:        conns[0].host    || null,
        severity:         beaconScore >= 80 ? 'CRITIQUE' : beaconScore >= 60 ? 'ÉLEVÉ' : 'MOYEN',
      });
    }

    items.sort((a, b) => b.beacon_score - a.beacon_score);
    res.json({ items, total: items.length, network_events_analyzed: result.rowCount });
  } catch (err) {
    logger.error('[beaconing]', err);
    res.status(500).json({ error: 'Erreur détection beaconing: ' + err.message });
  }
});

router.get('/:id/detections/persistence', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    const VECTORS = [
      {
        id: 'registry_runkeys',
        label: 'Registry Run Keys / Autostart',
        mitre: 'T1547.001',
        severity: 'ÉLEVÉ',
        query: `
          SELECT timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type = 'registry'
            AND (
              source  ILIKE '%\\CurrentVersion\\Run%'
              OR source  ILIKE '%\\CurrentVersion\\RunOnce%'
              OR source  ILIKE '%\\CurrentVersion\\RunServices%'
              OR description ILIKE '%\\Run%'
              OR description ILIKE '%\\RunOnce%'
            )
          ORDER BY timestamp
          LIMIT 200`,
      },
      {
        id: 'lnk_startup',
        label: 'Raccourcis LNK — Dossier Startup',
        mitre: 'T1547.009',
        severity: 'MOYEN',
        query: `
          SELECT timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type = 'lnk'
            AND (
              source ILIKE '%\\Startup%'
              OR source ILIKE '%\\Start Menu%'
              OR description ILIKE '%startup%'
            )
            AND NOT (
              raw->>'TargetPath' ILIKE 'C:\\Windows\\System32%'
              OR raw->>'TargetPath' ILIKE 'C:\\Windows\\SysWOW64%'
              OR raw->>'TargetPath' ILIKE 'C:\\Program Files%'
              OR raw->>'TargetPath' ILIKE 'C:\\Program Files (x86)%'
              OR raw->>'TargetPath' ILIKE 'C:\\ProgramData\\Microsoft%'
              OR raw->>'TargetPath' ILIKE '%\\AppData\\Local\\Microsoft\\Teams%'
              OR raw->>'TargetPath' ILIKE '%\\AppData\\Local\\Programs\\Microsoft VS Code%'
            )
          ORDER BY timestamp
          LIMIT 200`,
      },
      {
        id: 'bits_jobs',
        label: 'BITS Jobs',
        mitre: 'T1197',
        severity: 'ÉLEVÉ',
        query: `
          SELECT timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type = 'bits'
          ORDER BY timestamp
          LIMIT 200`,
      },
      {
        id: 'hayabusa_persistence',
        label: 'Hayabusa — Persistance (Sigma)',
        mitre: 'T1543 / T1053',
        severity: 'CRITIQUE',
        query: `
          SELECT timestamp, artifact_type, description, source, host_name, raw,
                 raw->>'level'     AS hay_level,
                 raw->>'rule_file' AS rule_file
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type = 'hayabusa'
            AND (
              raw->>'mitre_tactics' ILIKE '%Persistence%'
              OR raw->>'tactic'     ILIKE '%Persistence%'
              OR description ILIKE '%service install%'
              OR description ILIKE '%scheduled task%'
              OR description ILIKE '%autorun%'
              OR description ILIKE '%run key%'
              OR description ILIKE '%winlogon%'
              OR description ILIKE '%appinit%'
              OR description ILIKE '%image file execution%'
            )
          ORDER BY
            CASE raw->>'level'
              WHEN 'critical' THEN 1 WHEN 'high' THEN 2
              WHEN 'medium'   THEN 3 ELSE 4
            END,
            timestamp
          LIMIT 200`,
      },
    ];

    const populated = [];
    for (const v of VECTORS) {
      const r = await pool.query(v.query, [id]);
      if (r.rows.length > 0) {
        populated.push({ id: v.id, label: v.label, mitre: v.mitre, severity: v.severity, count: r.rows.length, items: r.rows });
      }
    }

    const total = populated.reduce((s, v) => s + v.count, 0);
    res.json({ vectors: populated, total });
  } catch (err) {
    logger.error('[persistence]', err);
    res.status(500).json({ error: 'Erreur détection persistance: ' + err.message });
  }
});

router.get('/:id/detections/sysmon-behavior', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    const VECTORS = [
      {
        id: 'lsass_access',
        label: 'Accès LSASS (credential dumping) — EventID 10',
        mitre: 'T1003.001',
        severity: 'CRITIQUE',
        query: `
          SELECT timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type IN ('evtx', 'sysmon', 'hayabusa')
            AND (
              (raw->>'EventID' = '10' AND raw->>'TargetImage' ILIKE '%lsass%')
              OR description ILIKE '%lsass%credential%'
              OR description ILIKE '%mimikatz%'
              OR description ILIKE '%sekurlsa%'
            )
          ORDER BY timestamp LIMIT 200`,
      },
      {
        id: 'remote_thread',
        label: 'CreateRemoteThread (injection de processus) — EventID 8',
        mitre: 'T1055',
        severity: 'CRITIQUE',
        query: `
          SELECT timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type IN ('evtx', 'sysmon', 'hayabusa')
            AND (
              raw->>'EventID' = '8'
              OR description ILIKE '%CreateRemoteThread%'
              OR description ILIKE '%remote thread%'
            )
          ORDER BY timestamp LIMIT 200`,
      },
      {
        id: 'exec_from_temp',
        label: 'Exécution depuis %TEMP% / %AppData% — EventID 1',
        mitre: 'T1059',
        severity: 'ÉLEVÉ',
        query: `
          SELECT timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type IN ('evtx', 'sysmon', 'prefetch', 'hayabusa')
            AND (
              (raw->>'EventID' = '1' AND (
                raw->>'Image'          ILIKE '%\\Temp\\%'
                OR raw->>'Image'       ILIKE '%\\AppData\\Local\\Temp%'
                OR raw->>'Image'       ILIKE '%\\AppData\\Roaming%'
                OR raw->>'CommandLine' ILIKE '%\\Temp\\%.exe%'
              ))
              OR description ILIKE '%\\Temp\\%.exe%'
              OR description ILIKE '%\\AppData\\%.exe%'
            )
          ORDER BY timestamp LIMIT 200`,
      },
      {
        id: 'unsigned_dll',
        label: 'Chargement DLL non signée — EventID 7',
        mitre: 'T1574.002',
        severity: 'ÉLEVÉ',
        query: `
          SELECT timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type IN ('evtx', 'sysmon')
            AND raw->>'EventID' = '7'
            AND (
              raw->>'Signed' = 'false'
              OR raw->>'SignatureStatus' ILIKE '%error%'
              OR raw->>'SignatureStatus' ILIKE '%invalid%'
            )
          ORDER BY timestamp LIMIT 200`,
      },
      {
        id: 'suspicious_network',
        label: 'Connexions réseau suspectes — EventID 3',
        mitre: 'T1071',
        severity: 'MOYEN',
        query: `
          SELECT timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type IN ('evtx', 'sysmon')
            AND raw->>'EventID' = '3'
            AND (
              raw->>'DestinationPort' IN ('4444','1234','31337','8080','8443','9001')
              OR (raw->>'Image' ILIKE '%powershell%' AND raw->>'DestinationIsIpv6' = 'false')
              OR (raw->>'Image' ILIKE '%wscript%')
              OR (raw->>'Image' ILIKE '%mshta%')
            )
          ORDER BY timestamp LIMIT 200`,
      },
      {
        id: 'process_tampering',
        label: 'Altération de processus (Process Herpaderping/Hollowing) — EventID 25',
        mitre: 'T1055.012',
        severity: 'CRITIQUE',
        query: `
          SELECT timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type IN ('evtx', 'sysmon')
            AND (
              raw->>'EventID' = '25'
              OR description ILIKE '%process hollowing%'
              OR description ILIKE '%process herpaderping%'
              OR description ILIKE '%process doppelgänging%'
            )
          ORDER BY timestamp LIMIT 200`,
      },
      {
        id: 'suspicious_file_create',
        label: 'Fichiers créés dans emplacements suspects — EventID 11',
        mitre: 'T1074',
        severity: 'MOYEN',
        query: `
          SELECT timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type IN ('evtx', 'sysmon')
            AND raw->>'EventID' = '11'
            AND (
              raw->>'TargetFilename' ILIKE '%\\Temp\\%'
              OR raw->>'TargetFilename' ILIKE '%\\System32\\%'
              OR raw->>'TargetFilename' ILIKE '%\\SysWOW64\\%'
              OR raw->>'TargetFilename' ~ '\\.(exe|dll|bat|ps1|vbs|hta|scr|com)$'
            )
          ORDER BY timestamp LIMIT 200`,
      },
    ];

    const populated = [];
    for (const v of VECTORS) {
      const r = await pool.query(v.query, [id]);
      if (r.rows.length > 0) {
        populated.push({ id: v.id, label: v.label, mitre: v.mitre, severity: v.severity, count: r.rows.length, items: r.rows });
      }
    }

    const total = populated.reduce((s, v) => s + v.count, 0);
    res.json({ vectors: populated, total });
  } catch (err) {
    logger.error('[sysmon-behavior]', err);
    res.status(500).json({ error: 'Erreur détection comportementale Sysmon: ' + err.message });
  }
});

router.post('/:id/legal-hold', authenticate, requireRole('admin'), async (req, res) => {
  const { reason } = req.body;
  try {
    const caseRes = await pool.query('SELECT * FROM cases WHERE id = $1', [req.params.id]);
    if (caseRes.rows.length === 0) return res.status(404).json({ error: 'Cas introuvable' });
    const c = caseRes.rows[0];
    if (c.legal_hold) return res.status(409).json({ error: 'Legal hold déjà actif sur ce cas' });

    await pool.query(
      'UPDATE cases SET legal_hold = TRUE, legal_hold_at = NOW(), legal_hold_by = $1 WHERE id = $2',
      [req.user.id, req.params.id]
    );

    await auditLog(req.user.id, 'legal_hold_enable', 'case', req.params.id,
      { reason: reason || null }, req.ip);

    res.json({ message: 'Legal Hold activé', case_id: req.params.id });
  } catch (err) {
    logger.error('[legal-hold]', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.delete('/:id/legal-hold', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const caseRes = await pool.query('SELECT legal_hold FROM cases WHERE id = $1', [req.params.id]);
    if (caseRes.rows.length === 0) return res.status(404).json({ error: 'Cas introuvable' });
    if (!caseRes.rows[0].legal_hold) return res.status(409).json({ error: 'Aucun legal hold actif' });

    await pool.query(
      'UPDATE cases SET legal_hold = FALSE, legal_hold_at = NULL, legal_hold_by = NULL WHERE id = $1',
      [req.params.id]
    );

    await auditLog(req.user.id, 'legal_hold_disable', 'case', req.params.id, {}, req.ip);
    res.json({ message: 'Legal Hold désactivé' });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.get('/:id/legal-hold/manifest', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const id = req.params.id;
    const [caseRes, evidRes, iocRes, mitreRes, bookmarkRes, parserRes] = await Promise.all([
      pool.query(
        `SELECT c.*, u.username AS held_by_name, u2.username AS investigator_name
         FROM cases c
         LEFT JOIN users u  ON u.id  = c.legal_hold_by
         LEFT JOIN users u2 ON u2.id = c.investigator_id
         WHERE c.id = $1`, [id]),
      pool.query(
        `SELECT e.id, e.name, e.original_filename, e.evidence_type, e.file_size,
                e.hash_md5, e.hash_sha1, e.hash_sha256, e.scan_status, e.created_at,
                u.username AS added_by_name
         FROM evidence e LEFT JOIN users u ON u.id = e.added_by
         WHERE e.case_id = $1 ORDER BY e.created_at`, [id]),
      pool.query(
        `SELECT i.ioc_type, i.value, i.description, i.is_malicious, i.vt_verdict,
                i.enriched_at, u.username AS added_by_name
         FROM iocs i LEFT JOIN users u ON u.id = i.added_by
         WHERE i.case_id = $1 ORDER BY i.ioc_type, i.value`, [id]),
      pool.query(
        `SELECT m.technique_id, m.technique_name, m.tactic, m.sub_technique_name,
                m.confidence, m.notes, u.username AS added_by_name
         FROM case_mitre_techniques m LEFT JOIN users u ON u.id = m.created_by
         WHERE m.case_id = $1 ORDER BY m.tactic, m.technique_id`, [id]),
      pool.query(
        `SELECT b.title, b.mitre_technique, b.mitre_tactic, b.description,
                b.event_timestamp, b.color, u.username AS author_name
         FROM timeline_bookmarks b LEFT JOIN users u ON u.id = b.author_id
         WHERE b.case_id = $1 ORDER BY b.event_timestamp ASC NULLS LAST`, [id]),
      pool.query(
        `SELECT pr.parser_type, pr.status, pr.record_count, pr.created_at,
                e.name AS evidence_name
         FROM parser_results pr LEFT JOIN evidence e ON e.id = pr.evidence_id
         WHERE pr.case_id = $1 ORDER BY pr.created_at`, [id]),
    ]);

    if (caseRes.rows.length === 0) return res.status(404).json({ error: 'Cas introuvable' });
    const c = caseRes.rows[0];

    const manifest = {
      format: 'ForensicLab Legal Hold Manifest v1',
      generated_at: new Date().toISOString(),
      case: {
        id: c.id,
        case_number: c.case_number,
        title: c.title,
        status: c.status,
        priority: c.priority,
        description: c.description,
        report_deadline: c.report_deadline,
        investigator: c.investigator_name,
      },
      legal_hold: {
        enabled: c.legal_hold,
        enabled_at: c.legal_hold_at,
        enabled_by: c.held_by_name,
      },
      evidence: evidRes.rows,
      iocs: iocRes.rows,
      mitre_techniques: mitreRes.rows,
      attack_chain_bookmarks: bookmarkRes.rows,
      parser_results: parserRes.rows,
      summary: {
        evidence_count: evidRes.rows.length,
        ioc_count: iocRes.rows.length,
        mitre_technique_count: mitreRes.rows.length,
        bookmark_count: bookmarkRes.rows.length,
        parser_count: parserRes.rows.length,
      },
    };

    const body = JSON.stringify(manifest, null, 2);
    const hmac = crypto.createHmac('sha256', process.env.JWT_SECRET || '')
                       .update(body).digest('hex');
    manifest.manifest_hmac = hmac;

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="legal-hold-manifest-${c.case_number}.json"`);
    res.send(JSON.stringify(manifest, null, 2));
  } catch (err) {
    logger.error('[manifest]', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

function pseudoIP(ip, ipMap) {
  if (!ip || typeof ip !== 'string') return ip;
  if (!ipMap.has(ip)) {
    const idx = ipMap.size + 1;
    ipMap.set(ip, `10.ANON.${Math.floor((idx - 1) / 254) + 1}.${((idx - 1) % 254) + 1}`);
  }
  return ipMap.get(ip);
}

function pseudoName(name, nameMap, prefix) {
  if (!name || typeof name !== 'string' || !name.trim()) return name;
  const key = name.trim().toLowerCase();
  if (!nameMap.has(key)) {
    nameMap.set(key, `${prefix}_${nameMap.size + 1}`);
  }
  return nameMap.get(key);
}

function anonymizeRaw(raw, ipMap, userMap, hostMap) {
  if (!raw || typeof raw !== 'object') return raw;
  const result = { ...raw };

  for (const field of ['RemoteHost','RemoteAddress','DstIP','dst_ip','DestinationIp','id.resp_h','SourceIP','src_ip','ip']) {
    if (result[field]) result[field] = pseudoIP(result[field], ipMap);
  }

  for (const field of ['User','Username','UserName','SubjectUserName','TargetUserName','email','Email']) {
    if (result[field]) result[field] = pseudoName(result[field], userMap, 'USER');
  }

  for (const field of ['Computer','Hostname','hostname','host','WorkstationName']) {
    if (result[field]) result[field] = pseudoName(result[field], hostMap, 'HOST');
  }

  return result;
}

router.get('/:id/export/anonymized', authenticate, async (req, res) => {
  const { id } = req.params;

  try {
    const [caseRes, eventsRes, iocsRes] = await Promise.all([
      pool.query(`SELECT id, case_number, title, status, created_at FROM cases WHERE id = $1`, [id]),
      pool.query(`SELECT id, timestamp, artifact_type, source, description, raw FROM collection_timeline WHERE case_id = $1 ORDER BY timestamp LIMIT 500`, [id]),
      pool.query(`SELECT id, ioc_type, value, is_malicious, tags FROM iocs WHERE case_id = $1`, [id]),
    ]);

    if (caseRes.rows.length === 0) return res.status(404).json({ error: 'Cas introuvable' });
    const caseInfo = caseRes.rows[0];

    const ipMap = new Map();
    const userMap = new Map();
    const hostMap = new Map();

    const anonymizedIOCs = iocsRes.rows.map(ioc => {
      const val = ioc.ioc_type === 'ip' ? pseudoIP(ioc.value, ipMap) : ioc.value;
      return { type: ioc.ioc_type, value: val, is_malicious: ioc.is_malicious, tags: ioc.tags };
    });

    const anonymizedEvents = eventsRes.rows.map(ev => ({
      timestamp: ev.timestamp,
      artifact_type: ev.artifact_type,
      source: ev.source,
      description: ev.description?.replace(/\b(\d{1,3}\.){3}\d{1,3}\b/g, ip => pseudoIP(ip, ipMap)) || ev.description,
      raw: anonymizeRaw(ev.raw, ipMap, userMap, hostMap),
    }));

    const pseudonymMap = {
      hosts: Object.fromEntries([...hostMap.entries()].map(([real, pseudo]) => [real, pseudo])),
      users: Object.fromEntries([...userMap.entries()].map(([real, pseudo]) => [real, pseudo])),
      ips: Object.fromEntries([...ipMap.entries()].map(([real, pseudo]) => [real, pseudo])),
    };

    const exportData = {
      case: {
        id: caseInfo.id,
        title: 'Données anonymisées RGPD',
        case_number: `ANON-${caseInfo.case_number || id.slice(0, 8)}`,
        status: caseInfo.status,
        original_created: caseInfo.created_at,
      },
      events: anonymizedEvents,
      iocs: anonymizedIOCs,
      pseudonym_map: pseudonymMap,
      exported_at: new Date().toISOString(),
      format_version: '1.0',
      anonymization: true,
      rgpd_notice: 'Ce fichier a été anonymisé conformément au RGPD. Les données personnelles ont été pseudonymisées.',
    };

    const filename = `forensiclab-anonymized-${caseInfo.case_number || id.slice(0,8)}-${new Date().toISOString().slice(0,10)}.json`;
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/json');
    res.json(exportData);

    pool.query(`INSERT INTO audit_logs (user_id, action, resource_type, resource_id) VALUES ($1, 'export_anonymized', 'case', $2)`,
      [req.user.id, id]).catch(() => {});
  } catch (err) {
    logger.error('[export-anonymized] error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.delete('/:id/hard-delete', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const result = await hardDeleteCase(pool, req.params.id, req.user.id, req.ip);
    req.app.locals.io?.emit('dashboard:update');
    res.json({
      message: `Cas ${result.caseNumber} détruit de manière permanente.`,
      files_destroyed: result.filesDestroyed,
      files_errors: result.filesErrors,
    });
  } catch (err) {
    if (err.status === 404) return res.status(404).json({ error: 'Cas introuvable' });
    logger.error('Hard delete error:', err);
    res.status(500).json({ error: 'Erreur lors de la destruction définitive: ' + err.message });
  }
});

router.get('/:id/risk-score', authenticate, async (req, res) => {
  try {
    const result = await getRiskScore(pool, req.params.id);
    res.json(result);
  } catch (err) {
    logger.error('[risk-score]', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
