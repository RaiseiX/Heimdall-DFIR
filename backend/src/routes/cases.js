const express = require('express');
const crypto = require('crypto');
const { pool } = require('../config/database');
const { authenticate, requireRole, auditLog } = require('../middleware/auth');
const { hardDeleteCase } = require('../services/hardDeleteService');
const { getRiskScore } = require('../services/riskScoreService');
const logger = require('../config/logger').default;
const { computeTriageScores, saveTriageScores, getTriageScores } = require('../services/triageScoreService');
const { getExceptions, applyExceptions, applyExceptionsGrouped } = require('../services/detectionExceptions');
const { getDriverIndex, getHijackIndex, matchDrivers, matchHijack } = require('../services/lolDriversService');
const { buildLateralMovement, mapNetworkRowsToLateral } = require('../services/lateralMovementService');
const { SYSMON_BEHAVIOR_VECTORS, TIMESTOMP_QUERY, EXEC_ANOMALY_VECTORS, WMI_PERSISTENCE_VECTORS } = require('../services/detectionVectors');

const router = express.Router();

const { caseAccessParam, caseListFilter, canAccessCase, ELEVATED } = require('../middleware/caseAccess');
// Enforce case-level access on every route carrying :id (the case id). The cases
// list (no :id) and global routes (e.g. /detections/exceptions/:exId) are unaffected.
// NB: param callbacks run before route-level middleware, so authenticate must be
// applied at router level first — otherwise req.user is undefined in the param.
router.use(authenticate);
router.param('id', caseAccessParam);

// ── Case assignment (RBAC) ───────────────────────────────────────────────────
// Users that can be assigned to a case (analysts + team leads).
router.get('/assignable-users', authenticate, requireRole('admin', 'team_lead'), async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, full_name, username, role FROM users WHERE role IN ('analyst','team_lead','admin') AND is_active IS NOT FALSE ORDER BY full_name NULLS LAST, username`);
    res.json({ users: r.rows });
  } catch (e) { logger.error('assignable-users:', e.message); res.status(500).json({ error: 'Erreur serveur' }); }
});

// Assignees of a case (anyone with access to the case can view them).
router.get('/:id/assignees', authenticate, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT u.id, u.full_name, u.username, u.role, ca.assigned_at
         FROM case_assignees ca JOIN users u ON u.id = ca.user_id
        WHERE ca.case_id = $1 ORDER BY ca.assigned_at`, [req.params.id]);
    res.json({ assignees: r.rows });
  } catch (e) { logger.error('get assignees:', e.message); res.status(500).json({ error: 'Erreur serveur' }); }
});

router.post('/:id/assignees', authenticate, requireRole('admin', 'team_lead'), async (req, res) => {
  try {
    const { user_id } = req.body;
    if (!user_id) return res.status(400).json({ error: 'user_id requis' });
    await pool.query(
      `INSERT INTO case_assignees (case_id, user_id, assigned_by) VALUES ($1, $2, $3)
       ON CONFLICT (case_id, user_id) DO NOTHING`, [req.params.id, user_id, req.user.id]);
    await auditLog(req.user.id, 'update_case', 'case', req.params.id, { action: 'assign', user_id }, req.ip);
    res.json({ ok: true });
  } catch (e) { logger.error('add assignee:', e.message); res.status(500).json({ error: 'Erreur serveur' }); }
});

router.delete('/:id/assignees/:userId', authenticate, requireRole('admin', 'team_lead'), async (req, res) => {
  try {
    await pool.query('DELETE FROM case_assignees WHERE case_id = $1 AND user_id = $2', [req.params.id, req.params.userId]);
    await auditLog(req.user.id, 'update_case', 'case', req.params.id, { action: 'unassign', user_id: req.params.userId }, req.ip);
    res.json({ ok: true });
  } catch (e) { logger.error('remove assignee:', e.message); res.status(500).json({ error: 'Erreur serveur' }); }
});

// ── Detection false-positive suppression (tuning loop) ───────────────────────
// Confidence (true-positive likelihood) — distinct from severity (impact if true).
const CONF_FROM_SEV = { 'CRITIQUE': 'high', 'ÉLEVÉ': 'high', 'MOYEN': 'medium', 'FAIBLE': 'low' };
const vecConf = (v) => v.confidence || CONF_FROM_SEV[v.severity] || 'medium';
const DETECTION_TYPES = ['timestomping', 'double-ext', 'beaconing', 'persistence', 'sysmon-behavior',
  'lolbins', 'masquerading', 'powershell-abuse', 'wmi-persistence', 'defender-tampering',
  'anti-forensic', 'execution-anomaly', 'attack-techniques', 'vuln-drivers'];

router.get('/:id/detections/exceptions', authenticate, async (req, res) => {
  try { res.json({ exceptions: await getExceptions(req.params.id) }); }
  catch (err) { logger.error('[detections.exceptions GET]', err); res.status(500).json({ error: 'Erreur serveur' }); }
});

router.post('/:id/detections/exceptions', authenticate, async (req, res) => {
  try {
    const value = String(req.body?.match_value || '').trim();
    if (!value) return res.status(400).json({ error: 'match_value requis' });
    const dtype = DETECTION_TYPES.includes(req.body?.detection_type) ? req.body.detection_type : null;
    const scope = req.body?.scope === 'global' ? null : req.params.id;   // null = global
    const reason = String(req.body?.reason || '').slice(0, 500) || null;
    const r = await pool.query(
      `INSERT INTO detection_exceptions (case_id, detection_type, match_value, reason, created_by)
       VALUES ($1, $2, $3, $4, $5) RETURNING id, case_id, detection_type, match_value, reason, created_at`,
      [scope, dtype, value, reason, req.user.id]
    );
    await auditLog(req.user.id, 'create_ioc', 'case', req.params.id,
      { action: 'detection_exception', detection_type: dtype, scope: scope ? 'case' : 'global' }, req.ip);
    res.status(201).json(r.rows[0]);
  } catch (err) { logger.error('[detections.exceptions POST]', err); res.status(500).json({ error: 'Erreur serveur' }); }
});

router.delete('/:id/detections/exceptions/:exId', authenticate, async (req, res) => {
  try { await pool.query('DELETE FROM detection_exceptions WHERE id = $1', [req.params.exId]); res.json({ ok: true }); }
  catch (err) { logger.error('[detections.exceptions DELETE]', err); res.status(500).json({ error: 'Erreur serveur' }); }
});

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

    // RBAC: analysts only see their own/assigned cases (elevated roles see all).
    const acc = caseListFilter(req.user, 'c', idx);
    if (acc.sql) { query += acc.sql; params.push(...acc.params); idx += acc.params.length; }

    query += ` ORDER BY c.created_at DESC LIMIT $${idx++} OFFSET $${idx++}`;
    params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));

    const result = await pool.query(query, params);

    const accCount = caseListFilter(req.user, 'c', 1);
    const countResult = await pool.query(
      `SELECT COUNT(*) FROM cases c WHERE 1=1${accCount.sql}`, accCount.params);

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
    const [stats, evidenceStats, iocStats, recentActivity, dailyActivity, artifactStats, findingsSev, scanHealth, parsedEv] = await Promise.all([
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
      // Findings by severity — aggregate over persisted threat-engine detections (JSONB array per row)
      pool.query(`
        SELECT lower(COALESCE(d->>'severity','')) AS sev, COUNT(*)::int AS cnt
        FROM collection_timeline ct
        CROSS JOIN LATERAL jsonb_array_elements(ct.detections) AS d
        WHERE ct.detections IS NOT NULL AND jsonb_typeof(ct.detections) = 'array'
        GROUP BY lower(COALESCE(d->>'severity',''))
      `).catch(() => ({ rows: [] })),
      // Scan health — evidence scan_status distribution
      pool.query(`
        SELECT COALESCE(NULLIF(scan_status, ''), 'pending') AS st, COUNT(*)::int AS cnt
        FROM evidence
        GROUP BY COALESCE(NULLIF(scan_status, ''), 'pending')
      `).catch(() => ({ rows: [] })),
      // Parse coverage — evidence that produced at least one timeline row
      pool.query(`
        SELECT COUNT(DISTINCT evidence_id)::int AS parsed
        FROM collection_timeline WHERE evidence_id IS NOT NULL
      `).catch(() => ({ rows: [{ parsed: 0 }] })),
    ]);

    // ── Findings by severity (greyware folds into low) ──────────────────────
    const findings_by_severity = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const row of findingsSev.rows) {
      const s = row.sev;
      if (s === 'critical')                 findings_by_severity.critical += row.cnt;
      else if (s === 'high')                findings_by_severity.high    += row.cnt;
      else if (s === 'medium')              findings_by_severity.medium  += row.cnt;
      else if (s === 'low' || s === 'greyware') findings_by_severity.low += row.cnt;
    }

    // ── Scan health (known buckets + total + parsed coverage) ───────────────
    const scan_health = { pending: 0, clean: 0, quarantined: 0, error: 0, other: 0, total: 0, parsed: parsedEv.rows[0]?.parsed || 0 };
    for (const row of scanHealth.rows) {
      const st = String(row.st || '').toLowerCase();
      scan_health.total += row.cnt;
      if (st in scan_health && st !== 'total' && st !== 'parsed' && st !== 'other') scan_health[st] += row.cnt;
      else scan_health.other += row.cnt;
    }

    res.json({
      cases: stats.rows[0],
      evidence: evidenceStats.rows[0],
      iocs: iocStats.rows[0],
      recent_activity: recentActivity.rows,
      daily_activity: dailyActivity.rows,
      artifacts: artifactStats.rows[0] || { artifact_types: 0, total_lines: 0, breakdown: [] },
      findings_by_severity,
      scan_health,
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

    const year = new Date().getFullYear();
    const maxResult = await pool.query(
      `SELECT COALESCE(MAX(CAST(SUBSTRING(case_number FROM $1) AS INTEGER)), 0) AS max_num
       FROM cases WHERE case_number ~ $2`,
      [`CASE-${year}-([0-9]+)$`, `^CASE-${year}-[0-9]+$`]
    );
    const num = maxResult.rows[0].max_num + 1;
    const case_number = `CASE-${year}-${String(num).padStart(3, '0')}`;

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

    // EvtxECmd stores source in RemoteHost as "hostname (IP)" — extract hostname part.
    // Hayabusa stores source in AllFieldInfo.WorkstationName / AllFieldInfo.IpAddress.
    // Both legacy field names (WorkstationName, IpAddress at root) and new nested paths
    // are checked so the query works regardless of which parser produced the record.
    const [result, indicators, netConns] = await Promise.all([
      pool.query(`
        WITH raw_events AS (
          SELECT
            -- Source extraction: EvtxECmd uses RemoteHost "HOST (IP)"; Hayabusa uses AllFieldInfo
            NULLIF(TRIM(COALESCE(
              -- EvtxECmd RemoteHost: "HOSTNAME (IP)" → extract hostname before " ("
              CASE
                WHEN raw->>'RemoteHost' ~ '^[^-].+ \\(.+\\)$'
                THEN NULLIF(TRIM(SPLIT_PART(raw->>'RemoteHost', ' (', 1)), '-')
              END,
              -- EvtxECmd RemoteHost IP-only fallback: extract from "(IP)"
              CASE
                WHEN raw->>'RemoteHost' ~ '\\([0-9a-f.:]+\\)'
                THEN NULLIF(REGEXP_REPLACE(raw->>'RemoteHost', '^.*\\(([^)]+)\\).*$', '\\1'), '-')
              END,
              -- Hayabusa AllFieldInfo nested fields
              NULLIF(raw->'AllFieldInfo'->>'WorkstationName', ''),
              NULLIF(raw->'AllFieldInfo'->>'IpAddress', ''),
              NULLIF(raw->'AllFieldInfo'->>'SourceAddress', ''),
              -- Legacy flat fields (some older parsers / Sysmon)
              NULLIF(raw->>'WorkstationName', ''),
              NULLIF(raw->>'SourceHostname', ''),
              NULLIF(raw->>'IpAddress', ''),
              NULLIF(raw->>'SourceIp', '')
            )), '-') AS src,

            -- Destination: EvtxECmd uses Computer; Hayabusa also uses Computer at root
            NULLIF(TRIM(COALESCE(
              NULLIF(raw->>'Computer', ''),
              NULLIF(raw->>'ComputerName', ''),
              NULLIF(raw->'AllFieldInfo'->>'DestinationHostname', ''),
              NULLIF(raw->>'DestinationHostname', ''),
              NULLIF(raw->>'DestinationIp', '')
            )), '-') AS dst,

            COALESCE(
              NULLIF(TRIM(raw->'AllFieldInfo'->>'TargetUserName'), ''),
              NULLIF(TRIM(raw->>'TargetUserName'), ''),
              NULLIF(TRIM(raw->'AllFieldInfo'->>'SubjectUserName'), ''),
              NULLIF(TRIM(raw->>'SubjectUserName'), ''), '?'
            ) AS username,

            COALESCE(raw->>'EventID', raw->>'EventId', event_id::text, '?') AS event_id,

            COALESCE(
              raw->'AllFieldInfo'->>'LogonType',
              raw->>'LogonType',
              raw->>'PayloadData2'
            ) AS logon_type,

            artifact_type,
            timestamp
          FROM collection_timeline
          WHERE case_id = $1
            AND (
              event_id IN (4624, 4625, 4648, 4768, 4769, 4776, 4771)
              OR raw->>'EventID' IN ('4624','4625','4648','4768','4769','4776','4771','3')
              OR raw->>'EventId' IN ('4624','4625','4648','4768','4769','4776','4771','3')
            )
        )
        SELECT
          src, dst, username, event_id, logon_type, artifact_type,
          COUNT(*)::int  AS event_count,
          MIN(timestamp) AS first_seen,
          MAX(timestamp) AS last_seen
        FROM raw_events
        WHERE src IS NOT NULL
          AND dst IS NOT NULL
          AND src <> dst
          AND src  NOT IN ('127.0.0.1','::1','0.0.0.0','-')
          AND dst  NOT IN ('127.0.0.1','::1','0.0.0.0','-')
          AND src  NOT ILIKE '%localhost%'
          AND dst  NOT ILIKE '%localhost%'
        GROUP BY src, dst, username, event_id, logon_type, artifact_type
        ORDER BY event_count DESC
        LIMIT 2000
      `, [id]),

      // Lateral movement indicators: non-network artifacts that reveal RDP/remote tool usage
      pool.query(`
        SELECT artifact_type, description, mitre_tactic, mitre_technique_id, timestamp, host_name
        FROM collection_timeline
        WHERE case_id = $1
          AND (
            -- RDP client execution (mstsc.exe in MFT/amcache/prefetch)
            description ILIKE '%mstsc%'
            OR description ILIKE '%rdpclip%'
            OR description ILIKE '%tscon%'
            -- Registry: RDP enabled / terminal server config
            OR (artifact_type = 'registry' AND (
              description ILIKE '%RDP%'
              OR description ILIKE '%Terminal Server%'
              OR raw->>'KeyPath' ILIKE '%TerminalServer%'
              OR raw->>'KeyPath' ILIKE '%Terminal Server%'
            ))
            -- Hayabusa lateral movement tactics
            OR mitre_tactic ILIKE '%lateral%'
            OR mitre_technique_id IN ('T1021.001','T1021.002','T1021.003','T1021.004',
                                       'T1021.006','T1047','T1550.002','T1550.003',
                                       'T1563.002','T1570')
            -- Hayabusa detection names for lateral movement
            OR (artifact_type = 'hayabusa' AND (
              artifact_name ILIKE '%RDP%'
              OR artifact_name ILIKE '%PsExec%'
              OR artifact_name ILIKE '%WMI%Remote%'
              OR artifact_name ILIKE '%Pass-the%'
              OR artifact_name ILIKE '%Lateral%'
              OR artifact_name ILIKE '%Remote Service%'
            ))
          )
        ORDER BY timestamp
        LIMIT 200
      `, [id]),

      pool.query(`
        SELECT src_ip, dst_ip, dst_port, protocol, packet_count, first_seen, last_seen
        FROM network_connections
        WHERE case_id = $1
          AND dst_port IN (445,139,135,3389,5985,5986,22,5900)
          AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
        ORDER BY packet_count DESC NULLS LAST
        LIMIT 5000
      `, [id]),
    ]);

    const networkRows = mapNetworkRowsToLateral(
      netConns.rows.map((r) => ({
        src_ip: r.src_ip, dst_ip: r.dst_ip, dst_port: Number(r.dst_port),
        protocol: r.protocol, packet_count: r.packet_count == null ? null : Number(r.packet_count),
        first_seen: r.first_seen, last_seen: r.last_seen,
      })),
    );
    const rows = [...result.rows, ...networkRows];

    // IOC hosts for overlap scoring (ioc_type enum has 'ip','domain' — there is no 'hostname')
    let iocHosts = new Set();
    try {
      const iocRes = await pool.query(
        `SELECT DISTINCT value FROM iocs WHERE case_id = $1 AND ioc_type IN ('ip','domain')`, [id]
      );
      iocHosts = new Set(iocRes.rows.map(r => r.value));
    } catch (e) {
      logger.warn('[lateral-movement] ioc lookup failed, continuing without IOC overlap: ' + e.message);
    }

    // Identity observations: group the MULTIPLE representations of the SAME host (IP + hostname).
    // CRITICAL: never put a source host and a destination host in the same observation — they are
    // different machines. The aggregated `rows` only expose one coalesced identifier per side, so we
    // have no second representation to link here. Pass NO cross-identity observations (resolver is a
    // safe no-op: each id maps to itself). Feeding real IP+hostname pairs is a follow-up that requires
    // the raw_events SELECT to emit both forms per host.
    const observations = [];

    const result2 = buildLateralMovement({
      rows,
      observations,
      indicators: indicators.rows,
      iocHosts,
    });
    res.json(result2);
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
      TIMESTOMP_QUERY,
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
          id:          r.id,
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

    const _exc = await getExceptions(req.params.id);
    const _items = applyExceptions(items, _exc, 'timestomping');
    res.json({ items: _items, total: _items.length, mft_records_analyzed: result.rowCount, suppressed: items.length - _items.length });
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
         id,
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
          id:          r.id,
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

    const _exc = await getExceptions(req.params.id);
    const _items = applyExceptions(items, _exc, 'double-ext');
    res.json({ items: _items, total: _items.length, records_scanned: result.rowCount, suppressed: items.length - _items.length });
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

      // NOTE (H8): coefficient-of-variation regularity is defeated by jittered beacons —
      // modern C2 randomizes intervals (± jitter %), inflating the CV and lowering the score.
      // A robust follow-up would use a jitter-tolerant metric (MAD / autocorrelation / FFT);
      // tracked as a roadmap item, not implemented here.
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
    const _exc = await getExceptions(req.params.id);
    const _items = applyExceptions(items, _exc, 'beaconing');
    res.json({ items: _items, total: _items.length, network_events_analyzed: result.rowCount, suppressed: items.length - _items.length,
      limitation: 'Score CV : les beacons jitterisés (intervalles randomisés) peuvent échapper. Métrique robuste (MAD/autocorrélation) = suivi roadmap.' });
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
          SELECT id, timestamp, artifact_type, description, source, host_name, raw
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
          SELECT id, timestamp, artifact_type, description, source, host_name, raw
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
          SELECT id, timestamp, artifact_type, description, source, host_name, raw
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
          SELECT id, timestamp, artifact_type, description, source, host_name, raw,
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
      {
        id: 'wmi_subscription',
        label: 'Persistance WMI (Event Subscription)',
        mitre: 'T1546.003',
        severity: 'CRITIQUE',
        query: `
          SELECT id, timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type IN ('evtx','sysmon','hayabusa')
            AND (
              raw->>'EventID' IN ('19','20','21')
              OR description ILIKE '%CommandLineEventConsumer%'
              OR description ILIKE '%ActiveScriptEventConsumer%'
              OR description ILIKE '%__EventFilter%'
              OR description ILIKE '%WmiEventConsumer%'
            )
          ORDER BY timestamp
          LIMIT 200`,
      },
      {
        id: 'scheduled_tasks',
        label: 'Tâches planifiées suspectes',
        mitre: 'T1053.005',
        severity: 'ÉLEVÉ',
        query: `
          SELECT id, timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND (
              (artifact_type = 'registry' AND source ILIKE '%TaskCache%Tasks%')
              OR (artifact_type IN ('evtx','sysmon','hayabusa') AND raw->>'EventID' IN ('4698','4702'))
            )
            AND (
              description ILIKE '%temp%'       OR description ILIKE '%appdata%'
              OR description ILIKE '%powershell%' OR description ILIKE '%cmd.exe%'
              OR description ILIKE '%mshta%'     OR description ILIKE '%rundll32%'
              OR description ILIKE '%programdata%' OR description ILIKE '%users%public%'
            )
          ORDER BY timestamp
          LIMIT 200`,
      },
      {
        id: 'service_install',
        label: 'Services — chemin/commande suspects',
        mitre: 'T1543.003',
        severity: 'ÉLEVÉ',
        query: `
          SELECT id, timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type = 'registry'
            AND source ILIKE '%Services%'
            AND (
              description ILIKE '%temp%'    OR description ILIKE '%appdata%'
              OR description ILIKE '%powershell%' OR description ILIKE '%cmd.exe /c%'
              OR description ILIKE '%programdata%' OR description ILIKE '%users%'
            )
            AND description NOT ILIKE '%system32%'
            AND description NOT ILIKE '%program files%'
          ORDER BY timestamp
          LIMIT 200`,
      },
      {
        id: 'winlogon_hijack',
        label: 'Winlogon (Shell / Userinit / Notify)',
        mitre: 'T1547.004',
        severity: 'ÉLEVÉ',
        query: `
          SELECT id, timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type = 'registry'
            AND source ILIKE '%Winlogon%'
            AND (description ILIKE '%Userinit%' OR description ILIKE '%Shell%' OR description ILIKE '%Notify%')
            AND description NOT ILIKE '%explorer.exe%'
            AND description NOT ILIKE '%userinit.exe%'
          ORDER BY timestamp
          LIMIT 200`,
      },
      {
        id: 'ifeo_debugger',
        label: 'IFEO Debugger (détournement d\'exécution)',
        mitre: 'T1546.012',
        severity: 'ÉLEVÉ',
        query: `
          SELECT id, timestamp, artifact_type, description, source, host_name, raw
          FROM collection_timeline
          WHERE case_id = $1
            AND artifact_type = 'registry'
            AND source ILIKE '%Image File Execution Options%'
            AND description ILIKE '%Debugger%'
          ORDER BY timestamp
          LIMIT 200`,
      },
    ];

    const populated = [];
    for (const v of VECTORS) {
      const r = await pool.query(v.query, [id]);
      if (r.rows.length > 0) {
        populated.push({ id: v.id, label: v.label, mitre: v.mitre, severity: v.severity, confidence: vecConf(v), count: r.rows.length, items: r.rows });
      }
    }

    const total = populated.reduce((s, v) => s + v.count, 0);
    const _exc = await getExceptions(req.params.id);
    const _g = applyExceptionsGrouped(populated, _exc, 'persistence');
    res.json({ vectors: _g.vectors, total: _g.total, suppressed: total - _g.total });
  } catch (err) {
    logger.error('[persistence]', err);
    res.status(500).json({ error: 'Erreur détection persistance: ' + err.message });
  }
});

router.get('/:id/detections/sysmon-behavior', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    const VECTORS = SYSMON_BEHAVIOR_VECTORS;

    const populated = [];
    for (const v of VECTORS) {
      const r = await pool.query(v.query, [id]);
      if (r.rows.length > 0) {
        populated.push({ id: v.id, label: v.label, mitre: v.mitre, severity: v.severity, confidence: vecConf(v), count: r.rows.length, items: r.rows });
      }
    }

    const total = populated.reduce((s, v) => s + v.count, 0);
    const _exc = await getExceptions(req.params.id);
    const _g = applyExceptionsGrouped(populated, _exc, 'sysmon-behavior');
    res.json({ vectors: _g.vectors, total: _g.total, suppressed: total - _g.total });
  } catch (err) {
    logger.error('[sysmon-behavior]', err);
    res.status(500).json({ error: 'Erreur détection comportementale Sysmon: ' + err.message });
  }
});

// Generic grouped detection runner — shared by anti-forensic & execution-anomaly.
async function runGroupedDetection(req, res, type, VECTORS, label) {
  try {
    const { id } = req.params;
    const populated = [];
    for (const v of VECTORS) {
      try {
        const r = await pool.query(v.query, [id]);
        if (r.rows.length) populated.push({ id: v.id, label: v.label, mitre: v.mitre, severity: v.severity, confidence: vecConf(v), count: r.rows.length, items: r.rows });
      } catch (e) { logger.warn(`[${type}:${v.id}]`, e.message); }
    }
    const total = populated.reduce((s, v) => s + v.count, 0);
    const _exc = await getExceptions(id);
    const _g = applyExceptionsGrouped(populated, _exc, type);
    res.json({ vectors: _g.vectors, total: _g.total, suppressed: total - _g.total });
  } catch (err) {
    logger.error(`[${type}]`, err);
    res.status(500).json({ error: `Erreur détection ${label}: ` + err.message });
  }
}

router.get('/:id/detections/anti-forensic', authenticate, async (req, res) => {
  const VECTORS = [
    { id: 'log_cleared', label: 'Journaux d\'événements effacés', mitre: 'T1070.001', severity: 'CRITIQUE', query: `
      SELECT timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND artifact_type IN ('evtx','sysmon','hayabusa') AND (
        raw->>'EventID' IN ('1102','104')
        OR description ILIKE '%audit log was cleared%' OR description ILIKE '%event log was cleared%'
        OR raw->>'CommandLine' ILIKE '%wevtutil%cl%' OR raw->>'CommandLine' ILIKE '%clear-eventlog%'
      ) ORDER BY timestamp LIMIT 200` },
    { id: 'shadowcopy_delete', label: 'Suppression de Volume Shadow Copies', mitre: 'T1490', severity: 'CRITIQUE', query: `
      SELECT timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND (
        raw->>'CommandLine' ILIKE '%shadowcopy%delete%' OR raw->>'CommandLine' ILIKE '%vssadmin%delete%shadows%'
        OR raw->>'CommandLine' ILIKE '%wmic%shadowcopy%delete%' OR description ILIKE '%delete shadows%'
        OR raw->>'CommandLine' ILIKE '%resize shadowstorage%'
      ) ORDER BY timestamp LIMIT 200` },
    { id: 'usn_journal_delete', label: 'Suppression du journal USN', mitre: 'T1070', severity: 'CRITIQUE', query: `
      SELECT timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND (
        raw->>'CommandLine' ILIKE '%fsutil%usn%deletejournal%' OR description ILIKE '%deletejournal%'
      ) ORDER BY timestamp LIMIT 200` },
    { id: 'secure_wipe', label: 'Effacement sécurisé / wiping', mitre: 'T1070.004', severity: 'ÉLEVÉ', query: `
      SELECT timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND (
        raw->>'CommandLine' ILIKE '%cipher%/w%' OR lower(raw->>'Image') LIKE '%sdelete%'
        OR raw->>'CommandLine' ILIKE '%sdelete%' OR raw->>'CommandLine' ILIKE '%format%/p:%'
      ) ORDER BY timestamp LIMIT 200` },
    { id: 'edr_tampering', label: 'Altération Sysmon / EDR', mitre: 'T1562.001', severity: 'ÉLEVÉ', query: `
      SELECT timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND (
        raw->>'CommandLine' ILIKE '%sysmon%-u%' OR description ILIKE '%sysmon%uninstall%'
        OR (description ILIKE '%sysmon%' AND raw->>'EventID' IN ('4','5') AND description ILIKE '%stop%')
      ) ORDER BY timestamp LIMIT 200` },
    { id: 'defender_tampering', label: 'Désactivation de Microsoft Defender', mitre: 'T1562.001', severity: 'ÉLEVÉ', query: `
      SELECT timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND (
        raw->>'CommandLine' ILIKE '%set-mppreference%disable%' OR raw->>'CommandLine' ILIKE '%add-mppreference%exclusion%'
        OR description ILIKE '%disableantispyware%' OR raw->>'CommandLine' ILIKE '%mpcmdrun%removedefinitions%'
        OR description ILIKE '%real-time protection%disabled%'
      ) ORDER BY timestamp LIMIT 200` },
    { id: 'prefetch_disabled', label: 'Prefetch désactivé', mitre: 'T1562', severity: 'MOYEN', query: `
      SELECT timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND artifact_type='registry' AND source ILIKE '%PrefetchParameters%'
        AND description ILIKE '%EnablePrefetcher%' AND (description ILIKE '%=0%' OR raw->>'value'='0')
      ORDER BY timestamp LIMIT 200` },
  ];
  return runGroupedDetection(req, res, 'anti-forensic', VECTORS, 'anti-forensique');
});

router.get('/:id/detections/execution-anomaly', authenticate, async (req, res) => {
  const VECTORS = EXEC_ANOMALY_VECTORS;
  return runGroupedDetection(req, res, 'execution-anomaly', VECTORS, 'anomalies d\'exécution');
});

router.get('/:id/detections/wmi-persistence', authenticate, (req, res) =>
  runGroupedDetection(req, res, 'wmi-persistence', WMI_PERSISTENCE_VECTORS, 'WMI persistence'));

router.get('/:id/detections/attack-techniques', authenticate, async (req, res) => {
  const VECTORS = [
    { id: 'lsass_dump', label: 'Dump LSASS / vol de credentials', mitre: 'T1003.001', severity: 'CRITIQUE', query: `
      SELECT id, timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND (
        raw->>'CommandLine' ILIKE '%comsvcs.dll%minidump%' OR raw->>'CommandLine' ILIKE '%procdump%lsass%'
        OR raw->>'CommandLine' ILIKE '%rundll32%comsvcs%' OR (raw->>'EventID'='10' AND raw->>'TargetImage' ILIKE '%lsass%')
        OR description ILIKE '%lsass%dump%' OR description ILIKE '%mimikatz%' OR description ILIKE '%sekurlsa%' OR raw->>'CommandLine' ILIKE '%lsadump%'
      ) ORDER BY timestamp LIMIT 200` },
    { id: 'dcsync', label: 'DCSync (réplication AD)', mitre: 'T1003.006', severity: 'CRITIQUE', query: `
      SELECT id, timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND raw->>'EventID'='4662' AND description ILIKE '%replicating directory changes%'
      ORDER BY timestamp LIMIT 200` },
    { id: 'kerberoasting', label: 'Kerberoasting (TGS RC4)', mitre: 'T1558.003', severity: 'ÉLEVÉ', query: `
      SELECT id, timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND raw->>'EventID'='4769'
        AND (raw->>'TicketEncryptionType' ILIKE '%0x17%' OR description ILIKE '%0x17%' OR description ILIKE '%RC4%')
      ORDER BY timestamp LIMIT 200` },
    { id: 'remote_exec', label: 'Exécution distante (PsExec / WMI / WinRM)', mitre: 'T1021.002 / T1021.006', severity: 'ÉLEVÉ', query: `
      SELECT id, timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND (
        description ILIKE '%psexec%' OR (raw->>'EventID'='7045' AND description ILIKE '%PSEXESVC%')
        OR raw->>'CommandLine' ILIKE '%wmic%/node:%' OR raw->>'CommandLine' ILIKE '%enter-pssession%'
        OR raw->>'CommandLine' ILIKE '%invoke-command%-computername%' OR description ILIKE '%winrm%'
      ) ORDER BY timestamp LIMIT 200` },
    { id: 'rdp_explicit_logon', label: 'Connexion RDP / credentials explicites', mitre: 'T1021.001', severity: 'MOYEN', confidence: 'low', query: `
      SELECT id, timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND (
        (raw->>'EventID'='4624' AND raw->>'LogonType'='10') OR raw->>'EventID'='4648'
      ) ORDER BY timestamp LIMIT 200` },
    { id: 'recon_burst', label: 'Reconnaissance (whoami / net / nltest)', mitre: 'T1087 / T1082', severity: 'MOYEN', confidence: 'low', query: `
      SELECT id, timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
      WHERE case_id=$1 AND (
        raw->>'CommandLine' ILIKE '%whoami /all%' OR raw->>'CommandLine' ILIKE '%net group%domain admins%'
        OR raw->>'CommandLine' ILIKE '%nltest%/dclist%' OR raw->>'CommandLine' ILIKE '%net localgroup administrators%'
        OR raw->>'CommandLine' ILIKE '%nltest%/domain_trusts%'
      ) ORDER BY timestamp LIMIT 200` },
  ];
  return runGroupedDetection(req, res, 'attack-techniques', VECTORS, 'techniques ATT&CK');
});

// LOLDrivers (vulnerable/malicious drivers) + HijackLibs (DLL hijacking) — matched
// in JS against cached threat-intel datasets (too large for SQL IN/ILIKE).
router.get('/:id/detections/vuln-drivers', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    const populated = [];
    let degraded = null;

    // LOLDrivers: Amcache driver inventory carries SHA1 (DriverId) + DriverName.
    try {
      const drvRows = (await pool.query(
        `SELECT timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
         WHERE case_id=$1 AND artifact_type='amcache' AND (raw ? 'DriverName' OR raw ? 'DriverId') LIMIT 20000`, [id])).rows;
      const idx = await getDriverIndex();
      const items = matchDrivers(drvRows, idx);
      if (items.length) populated.push({ id: 'loldrivers', label: 'Driver vulnérable / malveillant (LOLDrivers)', mitre: 'T1068', severity: 'CRITIQUE', confidence: 'high', count: items.length, items });
    } catch (e) { degraded = 'LOLDrivers indisponible (' + e.message + ')'; logger.warn('[vuln-drivers:loldrivers]', e.message); }

    // LOLDrivers runtime: Sysmon EID 6 (Driver Loaded) carries ImageLoaded + Hashes,
    // matched the same way as the Amcache inventory (H6 — BYOVD, T1068).
    try {
      const evtRows = (await pool.query(
        `SELECT timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
         WHERE case_id=$1 AND artifact_type IN ('evtx','sysmon') AND raw->>'EventID'='6' LIMIT 20000`, [id])).rows;
      const idx = await getDriverIndex();
      const items = matchDrivers(evtRows, idx);
      if (items.length) populated.push({ id: 'loldrivers_runtime', label: 'Driver vulnérable chargé (LOLDrivers, EID 6)', mitre: 'T1068', severity: 'CRITIQUE', confidence: 'high', count: items.length, items });
    } catch (e) { logger.warn('[vuln-drivers:runtime]', e.message); }

    // HijackLibs: known-hijackable DLL name found outside its expected location.
    try {
      const dllRows = (await pool.query(
        `SELECT timestamp, artifact_type, description, source, host_name, raw FROM collection_timeline
         WHERE case_id=$1 AND (raw->>'path' ILIKE '%.dll' OR raw->>'FullPath' ILIKE '%.dll' OR description ILIKE '%.dll') LIMIT 20000`, [id])).rows;
      const hidx = await getHijackIndex();
      const items = matchHijack(dllRows, hidx);
      if (items.length) populated.push({ id: 'hijacklibs', label: 'DLL hijacking (HijackLibs)', mitre: 'T1574.001', severity: 'ÉLEVÉ', confidence: 'medium', count: items.length, items });
    } catch (e) { logger.warn('[vuln-drivers:hijacklibs]', e.message); }

    const total = populated.reduce((s, v) => s + v.count, 0);
    const _exc = await getExceptions(id);
    const _g = applyExceptionsGrouped(populated, _exc, 'vuln-drivers');
    res.json({ vectors: _g.vectors, total: _g.total, suppressed: total - _g.total, degraded });
  } catch (err) {
    logger.error('[vuln-drivers]', err);
    res.status(500).json({ error: 'Erreur détection drivers/DLL : ' + err.message });
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

// GET /cases/:id/time — temps analytique cumulé par analyste
router.get('/:id/time', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT
         u.id,
         u.username,
         u.full_name,
         COUNT(s.id)::int          AS session_count,
         COALESCE(SUM(s.duration_s), 0)::int AS total_seconds
       FROM case_sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.case_id = $1 AND s.ended_at IS NOT NULL
       GROUP BY u.id, u.username, u.full_name
       ORDER BY total_seconds DESC`,
      [req.params.id]
    );
    const grand_total = rows.reduce((acc, r) => acc + r.total_seconds, 0);
    res.json({ analysts: rows, grand_total_seconds: grand_total });
  } catch (err) {
    logger.error('[cases/time]', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
