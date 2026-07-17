const express = require('express');
const PDFDocument = require('pdfkit');
const { renderReport, buildDfiqReportData } = require('../services/reportRenderer');
const fs = require('fs');
const path = require('path');
const { pool } = require('../config/database');
const { authenticate, auditLog } = require('../middleware/auth');
const { caseAccessParam } = require('../middleware/caseAccess');

const logger = require('../config/logger').default;
const router = express.Router();
router.use(authenticate);
router.param('caseId', caseAccessParam);

router.get('/templates', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT t.*, u.full_name as created_by_name
      FROM report_templates t LEFT JOIN users u ON u.id = t.created_by
      ORDER BY t.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    logger.error('List templates error:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

router.post('/templates', authenticate, async (req, res) => {
  try {
    const { name, description, config } = req.body;
    if (!name) return res.status(400).json({ error: 'Nom requis' });
    const result = await pool.query(
      `INSERT INTO report_templates (name, description, config, created_by)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [name, description || '', config || {}, req.user.id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    logger.error('Create template error:', err);
    res.status(500).json({ error: 'Erreur création template' });
  }
});

router.put('/templates/:id', authenticate, async (req, res) => {
  try {
    const { name, description, config, is_default } = req.body;
    const result = await pool.query(
      `UPDATE report_templates
       SET name=$1, description=$2, config=$3, is_default=$4, updated_at=NOW()
       WHERE id=$5 RETURNING *`,
      [name, description || '', config || {}, !!is_default, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Template non trouvé' });
    res.json(result.rows[0]);
  } catch (err) {
    logger.error('Update template error:', err);
    res.status(500).json({ error: 'Erreur mise à jour template' });
  }
});

router.delete('/templates/:id', authenticate, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM report_templates WHERE id=$1 RETURNING id', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Template non trouvé' });
    res.json({ deleted: true });
  } catch (err) {
    logger.error('Delete template error:', err);
    res.status(500).json({ error: 'Erreur suppression template' });
  }
});

// Generate the AI narrative ONLY (for the analyst to review/edit in the code editor
// before it's baked into the PDF). Returns { narrative: {field: text, ...} }.
router.post('/:caseId/ai-draft', authenticate, async (req, res) => {
  try {
    const reportAi = require('../services/reportAi');
    if (!reportAi.isAvailable()) return res.status(503).json({ error: "L'IA n'est pas configurée sur cette instance (OLLAMA_URL absent)." });
    const caseId = req.params.caseId;
    const caseResult = await pool.query(
      'SELECT c.*, u.full_name as investigator_name FROM cases c LEFT JOIN users u ON c.investigator_id = u.id WHERE c.id = $1', [caseId]);
    if (caseResult.rows.length === 0) return res.status(404).json({ error: 'Cas non trouvé' });
    const caseData = caseResult.rows[0];

    const [evi, iocs, mitre, hay, sig, yar, tri, bms, pins, anotes] = await Promise.all([
      pool.query('SELECT id, is_highlighted FROM evidence WHERE case_id=$1', [caseId]).catch(() => ({ rows: [] })),
      pool.query('SELECT value, is_malicious FROM iocs WHERE case_id=$1', [caseId]).catch(() => ({ rows: [] })),
      pool.query('SELECT technique_id, tactic FROM case_mitre_techniques WHERE case_id=$1', [caseId]).catch(() => ({ rows: [] })),
      pool.query(`SELECT raw->>'level' AS level, raw->>'rule_title' AS rule_title, description FROM collection_timeline WHERE case_id=$1 AND artifact_type='hayabusa' AND raw->>'level' IN ('critical','high') LIMIT 50`, [caseId]).catch(() => ({ rows: [] })),
      pool.query(`SELECT sr.rule_name, s.severity FROM sigma_hunt_results sr LEFT JOIN sigma_rules s ON s.id=sr.rule_id WHERE sr.case_id=$1 LIMIT 30`, [caseId]).catch(() => ({ rows: [] })),
      pool.query('SELECT rule_name FROM yara_scan_results WHERE case_id=$1 LIMIT 30', [caseId]).catch(() => ({ rows: [] })),
      pool.query('SELECT hostname, risk_level, score FROM triage_scores WHERE case_id=$1 ORDER BY score DESC LIMIT 10', [caseId]).catch(() => ({ rows: [] })),
      pool.query('SELECT title, description, mitre_technique, mitre_tactic FROM timeline_bookmarks WHERE case_id=$1 ORDER BY event_timestamp NULLS LAST LIMIT 25', [caseId]).catch(() => ({ rows: [] })),
      pool.query('SELECT description AS title, note AS description FROM timeline_pins WHERE case_id=$1 LIMIT 20', [caseId]).catch(() => ({ rows: [] })),
      pool.query('SELECT note FROM artifact_notes WHERE case_id=$1 ORDER BY created_at LIMIT 25', [caseId]).catch(() => ({ rows: [] })),
    ]);
    const ctx = reportAi.buildContext(caseData, {
      evidence: evi.rows, iocs: iocs.rows, mitre: mitre.rows, hayabusa: hay.rows,
      sigma: sig.rows, yara: yar.rows, triage: tri.rows,
      bookmarks: bms.rows, pins: pins.rows, notes: anotes.rows,
      analystNote: req.body && req.body.notes,   // free-text note the analyst typed in the composer
    });
    const resolvedModel = await require('../services/aiService').resolveModel(pool).catch(() => undefined);
    const narrative = await reportAi.generateNarrative(ctx, resolvedModel);
    Promise.resolve(auditLog(req.user.id, 'report_ai_draft', 'case', caseId, {}, req.ip)).catch(() => {});
    res.json({ narrative });
  } catch (err) {
    logger.error('[report] ai-draft error:', err.message);
    res.status(500).json({ error: 'Échec de la génération IA : ' + err.message });
  }
});

// Generate a focused markdown narrative from analyst bookmarks only.
// Lighter than ai-draft — no full case context — so it runs fast and stays
// faithful to what the analyst explicitly flagged.
router.post('/:caseId/bookmark-narrative', authenticate, async (req, res) => {
  try {
    const aiRouter = require('../services/aiRouter');
    if (!process.env.OLLAMA_URL) return res.status(503).json({ error: "IA non configurée (OLLAMA_URL absent)." });

    const { caseId } = req.params;
    const [caseRes, bmsRes] = await Promise.all([
      pool.query('SELECT title, case_number, status FROM cases WHERE id = $1', [caseId]),
      pool.query(
        `SELECT title, description, mitre_technique, mitre_tactic, event_timestamp
           FROM timeline_bookmarks WHERE case_id = $1 AND source != 'mitre'
           ORDER BY event_timestamp NULLS LAST LIMIT 30`,
        [caseId],
      ),
    ]);
    if (!caseRes.rows.length) return res.status(404).json({ error: 'Cas non trouvé' });
    if (!bmsRes.rows.length) return res.status(400).json({ error: 'Aucun bookmark trouvé pour ce cas.' });

    const c = caseRes.rows[0];
    const bookmarks = bmsRes.rows;

    const bkmLines = bookmarks.map((b, i) =>
      `${i + 1}. [${b.event_timestamp ? new Date(b.event_timestamp).toISOString().slice(0, 16) : '—'}] ${b.title || '(sans titre)'}` +
      (b.description ? `\n   Note : ${b.description}` : '') +
      (b.mitre_tactic  ? `\n   Tactic : ${b.mitre_tactic}`  : '') +
      (b.mitre_technique ? ` | Technique : ${b.mitre_technique}` : ''),
    ).join('\n\n');

    const sys = [
      'Tu es un analyste DFIR senior. Tu rédiges un narratif d\'investigation concis en markdown, uniquement fondé sur les observations de l\'analyste listées ci-dessous.',
      'RÈGLES IMPÉRATIVES :',
      '- N\'invente aucun fait, IOC, date ou technique absents des données.',
      '- Si une information manque, ne l\'extrapole pas — reste factuel.',
      '- Format : markdown, titres ## pour chaque phase ATT&CK identifiée, liste à puces pour les faits.',
      '- Longueur cible : 150-250 mots.',
      '- Langue : français.',
    ].join('\n');

    const userMsg =
      `Cas : ${c.case_number} — ${c.title} (statut : ${c.status})\n\n` +
      `OBSERVATIONS DE L'ANALYSTE (${bookmarks.length} bookmark(s)) :\n\n${bkmLines}\n\n` +
      `Rédige le narratif d'investigation markdown fondé sur ces observations.`;

    let model;
    try { model = await aiRouter.selectModel('fast'); } catch (_e) { model = process.env.AI_MODEL || 'qwen2.5:7b'; }

    const narrative = await aiRouter.chat({
      model,
      messages: [{ role: 'system', content: sys }, { role: 'user', content: userMsg }],
      thinkingMode: 'no_think',
      temperature: 0.3,
    });

    Promise.resolve(auditLog(req.user.id, 'bookmark_narrative_draft', 'case', caseId, { bookmarks: bookmarks.length }, req.ip)).catch(() => {});
    res.json({ narrative: String(narrative).trim() });
  } catch (err) {
    logger.error('[report] bookmark-narrative error:', err.message);
    res.status(500).json({ error: 'Échec génération narratif : ' + err.message });
  }
});

router.post('/:caseId/generate', authenticate, async (req, res) => {
  try {
    const caseId = req.params.caseId;

    const {
      templateId,
      sections: bodySections,          // ad-hoc section list chosen by the analyst (overrides template)
      notes: analystNotes,             // free-text analyst note(s) to print on top of the report
      organization: bodyOrg,
      classification: bodyClass,
      footer_text: bodyFooter,
      color_accent: bodyAccent,
      use_ai: bodyUseAi,
      ai_narrative: bodyAiNarrative,   // analyst-edited AI narrative (from the code-editor) — used as-is when present
    } = req.body;
    let tplConfig = null;
    if (templateId) {
      const tplResult = await pool.query('SELECT config FROM report_templates WHERE id=$1', [templateId]);
      if (tplResult.rows.length > 0) tplConfig = tplResult.rows[0].config;
    }
    const ALL_SECTIONS = ['summary','evidence','timeline','iocs','mitre','killchain','workflow','triage','yara','threat_intel','bookmarks','hayabusa','sigma','custody','dfiq'];
    // Priority: explicit body selection → saved template → everything.
    const activeSections = new Set(
      (Array.isArray(bodySections) && bodySections.length > 0) ? bodySections
        : (tplConfig?.sections || ALL_SECTIONS)
    );
    const org            = bodyOrg || tplConfig?.organization || 'Heimdall DFIR';
    const classification = bodyClass || tplConfig?.classification || 'CONFIDENTIEL';
    const footerText     = (bodyFooter != null ? bodyFooter : tplConfig?.footer_text) || '';
    const accentColor    = bodyAccent || tplConfig?.color_accent || '#00d4ff';
    // AI enrichment is on by default when an LLM backend is configured (OLLAMA_URL),
    // unless explicitly disabled via the request body or template.
    const useAI          = (bodyUseAi != null ? bodyUseAi : (tplConfig?.use_ai !== false)) && Boolean(process.env.OLLAMA_URL);

    const caseResult = await pool.query(`
      SELECT c.*, u.full_name as investigator_name
      FROM cases c LEFT JOIN users u ON c.investigator_id = u.id
      WHERE c.id = $1
    `, [caseId]);

    if (caseResult.rows.length === 0) return res.status(404).json({ error: 'Cas non trouvé' });
    const caseData = caseResult.rows[0];

    const evidenceResult = await pool.query('SELECT * FROM evidence WHERE case_id = $1 ORDER BY created_at', [caseId]);

    // Analyst-flagged events only (bookmarks + pins + noted rows)
    const bookmarkFlagResult = await pool.query(`
      SELECT b.id,
             b.event_timestamp AS event_time,
             NULL              AS source,
             b.title,
             b.description,
             b.mitre_tactic,
             b.mitre_technique,
             b.color,
             b.significance,
             b.confidence,
             b.links_to,
             u.full_name AS author,
             'bookmark' AS flag_type
      FROM timeline_bookmarks b
      LEFT JOIN users u ON u.id = b.author_id
      WHERE b.case_id = $1
      ORDER BY b.event_timestamp NULLS LAST
    `, [caseId]).catch(() => ({ rows: [] }));

    const pinFlagResult = await pool.query(`
      SELECT p.event_ts   AS event_time,
             p.artifact_type AS source,
             p.description   AS title,
             p.note          AS description,
             p.source        AS host_info,
             u.full_name     AS author,
             'pin' AS flag_type
      FROM timeline_pins p
      LEFT JOIN users u ON u.id = p.author_id
      WHERE p.case_id = $1
      ORDER BY p.event_ts NULLS LAST
    `, [caseId]).catch(() => ({ rows: [] }));

    const notesFlagResult = await pool.query(`
      SELECT n.artifact_ref,
             n.note,
             n.created_at,
             u.full_name AS author
      FROM artifact_notes n
      LEFT JOIN users u ON u.id = n.author_id
      WHERE n.case_id = $1
      ORDER BY n.created_at
    `, [caseId]).catch(() => ({ rows: [] }));

    const stepsResult = await pool.query(
      'SELECT phase, title, status, position FROM investigation_steps WHERE case_id = $1 ORDER BY phase, position, created_at',
      [caseId]
    ).catch(() => ({ rows: [] }));

    const dfiqResult = await pool.query(
      `SELECT s.title AS scenario_title,
              q.text AS question_text,
              a.status,
              a.note,
              q.position AS question_position,
              tb.title AS evidence_title
         FROM case_dfiq cd
         JOIN dfiq_scenarios s ON s.id = cd.scenario_id
         JOIN dfiq_questions q ON q.scenario_id = cd.scenario_id
         JOIN case_dfiq_answers a ON a.case_dfiq_id = cd.id AND a.question_id = q.id AND a.status = 'answered'
         LEFT JOIN case_dfiq_evidence e ON e.case_dfiq_answer_id = a.id
         LEFT JOIN timeline_bookmarks tb ON tb.id = e.bookmark_id
        WHERE cd.case_id = $1
        ORDER BY s.title, q.position`,
      [caseId]
    ).catch(() => ({ rows: [] }));

    const iocResult = await pool.query('SELECT * FROM iocs WHERE case_id = $1 ORDER BY severity DESC', [caseId]);
    const networkResult = await pool.query('SELECT * FROM network_connections WHERE case_id = $1', [caseId]);
    const mitreResult = await pool.query(
      'SELECT * FROM case_mitre_techniques WHERE case_id = $1 ORDER BY tactic, technique_id',
      [caseId]
    ).catch(() => ({ rows: [] }));

    const [yaraResult, correlResult, triageResult, bookmarkResult, hayabusaResult, sigmaResult] = await Promise.all([
      pool.query(
        `SELECT y.rule_name, y.scanned_at, e.name as evidence_name,
                jsonb_array_length(y.matched_strings) as match_count
         FROM yara_scan_results y
         LEFT JOIN evidence e ON e.id = y.evidence_id
         WHERE y.case_id = $1 ORDER BY y.scanned_at DESC LIMIT 200`,
        [caseId]
      ).catch(() => ({ rows: [] })),
      pool.query(
        `SELECT ioc_value, ioc_type, indicator_name, source_name, matched_at
         FROM threat_correlations WHERE case_id = $1 ORDER BY matched_at DESC LIMIT 200`,
        [caseId]
      ).catch(() => ({ rows: [] })),
      pool.query(
        `SELECT hostname, score, risk_level, event_count, computed_at
         FROM triage_scores WHERE case_id = $1 ORDER BY score DESC LIMIT 50`,
        [caseId]
      ).catch(() => ({ rows: [] })),
      pool.query(
        `SELECT b.title, b.mitre_tactic, b.mitre_technique, b.description, b.created_at,
                u.username as author
         FROM timeline_bookmarks b LEFT JOIN users u ON u.id = b.author_id
         WHERE b.case_id = $1 ORDER BY b.mitre_tactic, b.created_at`,
        [caseId]
      ).catch(() => ({ rows: [] })),

      pool.query(
        `SELECT timestamp, description, raw->>'level' AS level, raw->>'rule_title' AS rule_title,
                raw->>'mitre_tactics' AS tactics, host_name
         FROM collection_timeline
         WHERE case_id = $1 AND artifact_type = 'hayabusa'
           AND raw->>'level' IN ('critical', 'high')
         ORDER BY CASE raw->>'level' WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END, timestamp
         LIMIT 200`,
        [caseId]
      ).catch(() => ({ rows: [] })),

      pool.query(
        `SELECT sr.rule_name, sr.matched_at, sr.match_count, sr.sample_events,
                s.description AS rule_description, s.severity
         FROM sigma_hunt_results sr LEFT JOIN sigma_rules s ON s.id = sr.rule_id
         WHERE sr.case_id = $1
         ORDER BY sr.matched_at DESC LIMIT 100`,
        [caseId]
      ).catch(() => ({ rows: [] })),
    ]);

    const reportAi = require('../services/reportAi');
    // An analyst-edited narrative (from the code editor) is authoritative — use it as-is.
    let aiNarrative = reportAi.sanitizeNarrative(bodyAiNarrative);
    if (!aiNarrative && useAI) {
      try {
        const caseCtx = reportAi.buildContext(caseData, {
          evidence: evidenceResult.rows,
          iocs: iocResult.rows,
          mitre: mitreResult.rows,
          hayabusa: hayabusaResult.rows,
          sigma: sigmaResult.rows,
          yara: yaraResult.rows,
          triage: triageResult.rows,
          bookmarks: bookmarkFlagResult.rows,
          pins: pinFlagResult.rows,
          notes: notesFlagResult.rows,
          analystNote: analystNotes,   // free-text note + analyst observations drive the narrative
        });
        const resolvedModel = await require('../services/aiService').resolveModel(pool).catch(() => undefined);
        aiNarrative = await reportAi.generateNarrative(caseCtx, resolvedModel);
        logger.info('[report] AI narrative generated via aiRouter');
      } catch (aiErr) {
        logger.warn('[report] AI narrative generation failed, continuing without AI:', aiErr.message);
      }
    }

    // margin:0 — the renderer manages all layout/pagination manually. A non-zero
    // margin makes pdfkit auto-add pages whenever absolute-positioned content
    // lands below the bottom margin (which exploded the page count and split
    // save/restore pairs).
    const doc = new PDFDocument({ size: 'A4', margin: 0, bufferPages: true, info: {
      Title: `Rapport Forensique - ${caseData.case_number}`,
      Author: req.user.full_name,
      Subject: caseData.title,
      Creator: 'Heimdall DFIR v2.7.0'
    }});

    const filePath = path.join(process.env.UPLOAD_DIR || '/app/uploads', `report-${caseData.case_number}-${Date.now()}.pdf`);
    const stream = fs.createWriteStream(filePath);
    doc.pipe(stream);

    const evidence   = evidenceResult.rows;
    const highlighted = evidence.filter(e => e.is_highlighted);

    renderReport(doc, {
      caseData,
      evidence,
      highlighted,
      iocs: iocResult.rows,
      network: networkResult.rows,
      mitre: mitreResult.rows,
      triage: triageResult.rows,
      yara: yaraResult.rows,
      correl: correlResult.rows,
      hayabusa: hayabusaResult.rows,
      sigma: sigmaResult.rows,
      bookmarks: bookmarkFlagResult.rows,
      pins: pinFlagResult.rows,
      notes: notesFlagResult.rows,
      steps: stepsResult.rows,
      dfiq: buildDfiqReportData(dfiqResult.rows),
      aiNarrative,
      analystNotes,
      activeSections,
      org, classification, footerText, accentColor,
      generatedBy: req.user.full_name,
    });
    doc.end();

    stream.on('finish', async () => {

      const reportResult = await pool.query(
        `INSERT INTO reports (case_id, title, content, generated_by, file_path)
         VALUES ($1, $2, $3, $4, $5) RETURNING *`,
        [caseId, `Rapport - ${caseData.case_number}`, JSON.stringify({
          case: caseData,
          evidence_count: evidence.length,
          highlighted_count: highlighted.length,
          analyst_bookmarks: bookmarkFlagResult.rows.length,
          analyst_pins: pinFlagResult.rows.length,
          analyst_notes: notesFlagResult.rows.length,
          ioc_count: iocResult.rows.length,
          mitre_techniques: mitreResult.rows.length,
        }), req.user.id, filePath]
      );

      await auditLog(req.user.id, 'generate_report', 'report', reportResult.rows[0].id, { case_number: caseData.case_number }, req.ip);

      res.json({
        report: reportResult.rows[0],
        download_url: `/api/reports/download/${reportResult.rows[0].id}`
      });
    });
  } catch (err) {
    logger.error('Report generation error:', err);
    res.status(500).json({ error: 'Erreur génération rapport' });
  }
});

router.get('/download/:id', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM reports WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Rapport non trouvé' });

    const report = result.rows[0];
    if (!fs.existsSync(report.file_path)) {
      return res.status(404).json({ error: 'Fichier PDF non trouvé' });
    }

    await auditLog(req.user.id, 'download_report', 'report', req.params.id,
      { title: report.title, case_id: report.case_id }, req.ip);
    res.download(report.file_path, `${report.title}.pdf`);
  } catch (err) {
    res.status(500).json({ error: 'Erreur téléchargement' });
  }
});

router.get('/:caseId', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT r.*, u.full_name as generated_by_name
      FROM reports r LEFT JOIN users u ON r.generated_by = u.id
      WHERE r.case_id = $1 ORDER BY r.created_at DESC
    `, [req.params.caseId]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;
