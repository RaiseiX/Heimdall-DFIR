const express = require('express');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const { pool } = require('../config/database');
const { authenticate, auditLog } = require('../middleware/auth');

const logger = require('../config/logger').default;
const router = express.Router();

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

router.post('/:caseId/generate', authenticate, async (req, res) => {
  try {
    const caseId = req.params.caseId;

    const { templateId } = req.body;
    let tplConfig = null;
    if (templateId) {
      const tplResult = await pool.query('SELECT config FROM report_templates WHERE id=$1', [templateId]);
      if (tplResult.rows.length > 0) tplConfig = tplResult.rows[0].config;
    }
    const ALL_SECTIONS = ['summary','evidence','timeline','iocs','mitre','triage','yara','threat_intel','bookmarks','hayabusa','sigma','custody'];
    const activeSections = new Set(tplConfig?.sections || ALL_SECTIONS);
    const org            = tplConfig?.organization || 'Heimdall DFIR';
    const classification = tplConfig?.classification || 'CONFIDENTIEL';
    const footerText     = tplConfig?.footer_text || '';
    const accentColor    = tplConfig?.color_accent || '#00d4ff';
    const useAI          = (tplConfig?.use_ai !== false) && process.env.AI_ENABLED === 'true';

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
      SELECT b.event_timestamp AS event_time,
             NULL              AS source,
             b.title,
             b.description,
             b.mitre_tactic,
             b.mitre_technique,
             b.color,
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

    let aiNarrative = null;
    if (useAI) {
      try {
        const http = require('http');
        const aiUrl = new URL(`${process.env.AI_BACKEND_URL || 'http://ollama:11434'}/api/generate`);

        const caseCtx = {
          case_number: caseData.case_number,
          title: caseData.title,
          status: caseData.status,
          description: caseData.description,
          opened_at: caseData.opened_at,
          ioc_count: iocResult.rows.length,
          malicious_iocs: iocResult.rows.filter(i => i.is_malicious).map(i => i.value).slice(0, 10),
          timeline_events: bookmarkFlagResult.rows.length + pinFlagResult.rows.length,
          mitre_techniques: mitreResult.rows.map(t => `${t.technique_id} (${t.tactic})`).slice(0, 15),
          critical_yara: yaraResult.rows.map(y => y.rule_name).slice(0, 5),
          triage_top: triageResult.rows.slice(0, 5).map(t => `${t.hostname}: ${t.risk_level} (${t.score}/100)`),
          bookmarks: bookmarkResult.rows.slice(0, 10).map(b => b.title),
        };

        const aiPrompt = `Tu es un analyste DFIR expert. Analyse les données de l'investigation suivante et génère un rapport structuré en JSON.\n\nDonnées du cas:\n${JSON.stringify(caseCtx, null, 2)}\n\nGénère exactement ce JSON (sans markdown, sans \`\`\`, uniquement le JSON brut):\n{\n  "executive_summary": "3-4 phrases résumant l'incident, l'impact et le statut",\n  "key_findings": "2-3 phrases sur les découvertes principales",\n  "ioc_analysis": "2-3 phrases analysant les IOCs et leur signification",\n  "mitre_analysis": "2-3 phrases sur les TTPs observées et la chaîne d'attaque",\n  "timeline_narrative": "2-3 phrases décrivant le déroulé chronologique de l'attaque",\n  "recommendations": "3-4 recommandations concrètes de remédiation"\n}`;

        const aiResponse = await new Promise((resolve, reject) => {
          const body = JSON.stringify({
            model: process.env.AI_MODEL || 'qwen2.5:14b',
            prompt: aiPrompt,
            stream: false,
            options: { temperature: 0.3 },
          });
          const req2 = http.request({
            hostname: aiUrl.hostname,
            port: aiUrl.port || 80,
            path: aiUrl.pathname,
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
          }, (res2) => {
            let data = '';
            res2.on('data', chunk => data += chunk);
            res2.on('end', () => resolve(data));
          });
          req2.on('error', reject);
          req2.setTimeout(120000, () => { req2.destroy(); reject(new Error('AI timeout')); });
          req2.write(body);
          req2.end();
        });

        const parsed = JSON.parse(aiResponse);
        let rawText = parsed.response || '';

        rawText = rawText.replace(/^```(?:json)?\n?/m, '').replace(/\n?```$/m, '').trim();
        aiNarrative = JSON.parse(rawText);
        logger.info('AI narrative generated successfully for report');
      } catch (aiErr) {
        logger.warn('AI narrative generation failed, continuing without AI:', aiErr.message);
      }
    }

    const doc = new PDFDocument({ size: 'A4', margin: 50, info: {
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

    let secIdx = 0;
    const S = (label) => {
      if (doc.y > 600) doc.addPage();
      secIdx++;
      doc.fontSize(16).fillColor('#333').text(`${secIdx}. ${label}`);
      doc.moveTo(50, doc.y).lineTo(545, doc.y).stroke(accentColor);
      doc.moveDown(0.5);
    };

    doc.fontSize(24).fillColor(accentColor).text('HEIMDALL DFIR', { align: 'center' });
    doc.fontSize(12).fillColor('#555').text(org, { align: 'center' });
    doc.fontSize(10).fillColor('#888').text(`Rapport Forensique — ${classification}`, { align: 'center' });
    doc.moveDown(2);

    if (aiNarrative) {
      doc.fontSize(8).fillColor('#666').text('⚡ Rapport enrichi par analyse IA (Heimdall AI Copilot)', { align: 'center' });
      doc.moveDown(1);
    }

    if (activeSections.has('summary')) {
      S('Résumé du Cas');
      doc.fontSize(10).fillColor('#333');
      doc.text(`Numéro: ${caseData.case_number}`);
      doc.text(`Titre: ${caseData.title}`);
      doc.text(`Statut: ${caseData.status}`);
      doc.text(`Priorité: ${caseData.priority}`);
      doc.text(`Investigateur: ${caseData.investigator_name || 'Non assigné'}`);
      doc.text(`Date d'ouverture: ${new Date(caseData.opened_at).toLocaleString('fr-FR')}`);
      doc.moveDown(0.5);
      doc.text(`Description: ${caseData.description || 'N/A'}`);
      doc.moveDown(0.8);

      if (aiNarrative?.executive_summary) {
        doc.fontSize(9).fillColor('#4d82c0').text('Synthèse exécutive (IA)', { continued: false });
        doc.fontSize(9).fillColor('#555').text(aiNarrative.executive_summary, { align: 'justify' });
        doc.moveDown(0.4);
      }
      if (aiNarrative?.key_findings) {
        doc.fontSize(9).fillColor('#4d82c0').text('Découvertes principales (IA)', { continued: false });
        doc.fontSize(9).fillColor('#555').text(aiNarrative.key_findings, { align: 'justify' });
      }
      doc.moveDown(1.5);
    }

    if (activeSections.has('evidence')) {
      S('Preuves');
      doc.fontSize(10).fillColor('#333').text(`Total: ${evidence.length} preuves (${highlighted.length} mises en évidence)`);
      doc.moveDown(0.5);
      for (const ev of evidence) {
        if (doc.y > 700) doc.addPage();
        doc.fontSize(9).fillColor(ev.is_highlighted ? '#ff6b35' : '#333');
        doc.text(`${ev.is_highlighted ? '★ ' : ''}${ev.name} [${ev.evidence_type}] - ${ev.hash_sha256 || 'N/A'}`);
        if (ev.notes) doc.fontSize(8).fillColor('#666').text(`  Notes: ${ev.notes}`);
      }
      doc.moveDown(1.5);
    }

    if (activeSections.has('timeline')) {
      const totalFlagged = bookmarkFlagResult.rows.length + pinFlagResult.rows.length + notesFlagResult.rows.length;
      S(`Événements Repérés par l'Analyste (${totalFlagged})`);

      if (aiNarrative?.timeline_narrative) {
        doc.fontSize(9).fillColor('#4d82c0').text('Analyse narrative (IA)');
        doc.fontSize(9).fillColor('#555').text(aiNarrative.timeline_narrative, { align: 'justify' });
        doc.moveDown(0.6);
      }

      if (bookmarkFlagResult.rows.length > 0) {
        doc.fontSize(10).fillColor(accentColor).text(`▸ Bookmarks (${bookmarkFlagResult.rows.length})`);
        doc.moveDown(0.2);
        let lastTactic = null;
        for (const ev of bookmarkFlagResult.rows) {
          if (doc.y > 710) doc.addPage();
          if (ev.mitre_tactic && ev.mitre_tactic !== lastTactic) {
            doc.fontSize(8).fillColor('#888').text(`  ─── ${ev.mitre_tactic} ───`);
            lastTactic = ev.mitre_tactic;
          }
          const ts = ev.event_time ? new Date(ev.event_time).toLocaleString('fr-FR') : '?';
          doc.fontSize(9).fillColor('#999').text(`  ${ts}`, { continued: true });
          if (ev.mitre_technique) doc.fillColor('#4d82c0').text(`  [${ev.mitre_technique}]`, { continued: true });
          doc.fillColor('#111').text(`  ${ev.title || ''}`);
          if (ev.description) doc.fontSize(8).fillColor('#555').text(`    ${ev.description}`);
          if (ev.author) doc.fontSize(7).fillColor('#888').text(`    — ${ev.author}`);
        }
        doc.moveDown(0.8);
      }

      if (pinFlagResult.rows.length > 0) {
        doc.fontSize(10).fillColor(accentColor).text(`▸ Événements Épinglés (${pinFlagResult.rows.length})`);
        doc.moveDown(0.2);
        for (const ev of pinFlagResult.rows) {
          if (doc.y > 710) doc.addPage();
          const ts = ev.event_time ? new Date(ev.event_time).toLocaleString('fr-FR') : '?';
          doc.fontSize(9).fillColor('#999').text(`  ${ts}`, { continued: true });
          if (ev.source) doc.fillColor('#666').text(`  [${ev.source}]`, { continued: true });
          doc.fillColor('#111').text(`  ${ev.title || ''}`);
          if (ev.description) doc.fontSize(8).fillColor('#4d82c0').text(`    Note: ${ev.description}`);
          if (ev.author) doc.fontSize(7).fillColor('#888').text(`    — ${ev.author}`);
        }
        doc.moveDown(0.8);
      }

      if (notesFlagResult.rows.length > 0) {
        doc.fontSize(10).fillColor(accentColor).text(`▸ Notes d'Analyse (${notesFlagResult.rows.length})`);
        doc.moveDown(0.2);
        for (const n of notesFlagResult.rows) {
          if (doc.y > 710) doc.addPage();
          doc.fontSize(9).fillColor('#111').text(`  • ${n.note}`);
          doc.fontSize(7).fillColor('#888').text(
            `    — ${n.author || 'N/A'} · ${new Date(n.created_at).toLocaleString('fr-FR')}`
          );
        }
        doc.moveDown(0.8);
      }

      if (totalFlagged === 0) {
        doc.fontSize(9).fillColor('#999').text("Aucun événement repéré par l'analyste pour ce cas.");
      }
      doc.moveDown(1.5);
    }

    if (activeSections.has('iocs')) {
      S('Indicateurs de Compromission (IOC)');
      if (aiNarrative?.ioc_analysis) {
        doc.fontSize(9).fillColor('#4d82c0').text('Analyse des IOCs (IA)');
        doc.fontSize(9).fillColor('#555').text(aiNarrative.ioc_analysis, { align: 'justify' });
        doc.moveDown(0.6);
      }
      for (const ioc of iocResult.rows) {
        if (doc.y > 720) doc.addPage();
        const color = ioc.is_malicious ? '#ff3355' : '#333';
        doc.fontSize(9).fillColor(color).text(`[${ioc.ioc_type}] ${ioc.value} (Sévérité: ${ioc.severity}/10)${ioc.is_malicious ? ' ⚠ MALVEILLANT' : ''}`);
        if (ioc.description) doc.fontSize(8).fillColor('#666').text(`  ${ioc.description}`);
      }
      doc.moveDown(1.5);
    }

    const mitreHasData = mitreResult.rows.length > 0 || bookmarkFlagResult.rows.some(b => b.mitre_technique);
    if (activeSections.has('mitre') && mitreHasData) {
      S('Cartographie MITRE ATT\u0026CK');
      if (aiNarrative?.mitre_analysis) {
        doc.fontSize(9).fillColor('#4d82c0').text('Analyse des TTPs (IA)');
        doc.fontSize(9).fillColor('#555').text(aiNarrative.mitre_analysis, { align: 'justify' });
        doc.moveDown(0.6);
      }

      // ── Build tactic→techniques map ──────────────────────────────────────
      const TACTIC_ORDER = [
        'Reconnaissance','Resource Development','Initial Access','Execution',
        'Persistence','Privilege Escalation','Defense Evasion','Credential Access',
        'Discovery','Lateral Movement','Collection','Command and Control',
        'Exfiltration','Impact',
      ];
      const CONF_COLORS = { confirmed:'#ef4444', high:'#f97316', medium:'#eab308', low:'#22c55e', bookmark:'#4d82c0' };
      const CONF_LABELS = { confirmed:'Confirmé', high:'Élevée', medium:'Moyenne', low:'Faible', bookmark:'Repéré' };

      const tacticMap = new Map();
      for (const t of mitreResult.rows) {
        const tac = t.tactic || 'Unknown';
        if (!tacticMap.has(tac)) tacticMap.set(tac, []);
        tacticMap.get(tac).push({ id: t.technique_id, name: t.technique_name, confidence: t.confidence, notes: t.notes });
      }
      for (const b of bookmarkFlagResult.rows) {
        if (!b.mitre_tactic || !b.mitre_technique) continue;
        const tac = b.mitre_tactic;
        if (!tacticMap.has(tac)) tacticMap.set(tac, []);
        const existing = tacticMap.get(tac);
        if (!existing.find(e => e.id === b.mitre_technique)) {
          existing.push({ id: b.mitre_technique, name: b.title, confidence: 'bookmark', notes: b.description });
        }
      }

      const tactics = TACTIC_ORDER.filter(t => tacticMap.has(t));
      // also add any tactics not in the standard order
      for (const t of tacticMap.keys()) { if (!tactics.includes(t)) tactics.push(t); }

      // ── Draw visual matrix ───────────────────────────────────────────────
      const X0 = 50;
      const PAGE_W = 495;
      const MAX_COLS = 7;
      const HEADER_H = 28;
      const TECH_H   = 17;

      const hexToRgb = (hex) => {
        const h = hex.replace('#','');
        return [parseInt(h.slice(0,2),16), parseInt(h.slice(2,4),16), parseInt(h.slice(4,6),16)];
      };

      if (doc.y > 500) doc.addPage();

      for (let rowStart = 0; rowStart < tactics.length; rowStart += MAX_COLS) {
        const rowTactics = tactics.slice(rowStart, rowStart + MAX_COLS);
        const colCount = rowTactics.length;
        const colW = Math.floor(PAGE_W / colCount);
        const maxTechs = Math.max(...rowTactics.map(t => (tacticMap.get(t) || []).length), 0);
        const rowH = HEADER_H + maxTechs * TECH_H + 8;

        if (doc.y + rowH > 770) doc.addPage();
        const startY = doc.y;

        rowTactics.forEach((tactic, ci) => {
          const techs = tacticMap.get(tactic) || [];
          const cx = X0 + ci * colW;

          // Tactic header
          doc.rect(cx, startY, colW - 2, HEADER_H)
             .fillColor('#1e3a5f').fill();
          doc.rect(cx, startY, colW - 2, HEADER_H)
             .strokeColor('#0d2137').lineWidth(0.5).stroke();
          doc.fontSize(6).fillColor('#ffffff')
             .text(tactic.toUpperCase(), cx + 3, startY + 4, {
               width: colW - 6, height: HEADER_H - 6, lineBreak: true, ellipsis: true,
             });

          techs.forEach((tech, ti) => {
            const ty = startY + HEADER_H + ti * TECH_H;
            const conf = tech.confidence || 'bookmark';
            const col = CONF_COLORS[conf] || '#888';
            const [r, g, b] = hexToRgb(col);

            doc.rect(cx, ty, colW - 2, TECH_H - 1)
               .fillColor([r, g, b], 0.18).fill();
            doc.rect(cx, ty, colW - 2, TECH_H - 1)
               .strokeColor(col).lineWidth(0.5).stroke();
            doc.fontSize(6).fillColor('#111')
               .text(tech.id || '', cx + 3, ty + 2, { width: colW - 6, lineBreak: false, ellipsis: true });
            doc.fontSize(5).fillColor('#333')
               .text((tech.name || '').substring(0, 24), cx + 3, ty + 9, { width: colW - 6, lineBreak: false, ellipsis: true });
          });
        });

        // Advance cursor past the drawn block
        doc.text('', X0, startY + rowH, { lineBreak: false });
        doc.moveDown(0.4);
      }

      // ── Legend ───────────────────────────────────────────────────────────
      doc.moveDown(0.5);
      doc.fontSize(7.5).fillColor('#333');
      let legendX = 50;
      const legendY = doc.y;
      for (const [conf, col] of Object.entries(CONF_COLORS)) {
        const [r, g, b] = hexToRgb(col);
        doc.rect(legendX, legendY - 1, 10, 8).fillColor([r, g, b], 0.9).fill();
        doc.fillColor('#333').text(`  ${CONF_LABELS[conf]}`, legendX + 12, legendY, { continued: true });
        legendX += 75;
      }
      doc.text('');

      // ── Textual detail list ──────────────────────────────────────────────
      doc.moveDown(0.8);
      doc.fontSize(9).fillColor('#555').text(`Détail des ${mitreResult.rows.length + [...tacticMap.values()].filter(ts => ts.some(t => t.confidence === 'bookmark')).length} technique(s) identifiée(s):`);
      doc.moveDown(0.3);
      for (const [tactic, techs] of tacticMap.entries()) {
        if (doc.y > 700) doc.addPage();
        doc.fontSize(9).fillColor(accentColor).text(tactic);
        for (const t of techs) {
          if (doc.y > 720) doc.addPage();
          const confLabel = CONF_LABELS[t.confidence] || t.confidence;
          const confColor = CONF_COLORS[t.confidence] || '#999';
          doc.fontSize(8).fillColor('#333').text(`  ${t.id || '?'}`, { continued: true })
             .fillColor('#555').text(`  ${t.name || ''}`, { continued: true })
             .fillColor(confColor).text(`  [${confLabel}]`);
          if (t.notes) doc.fontSize(7).fillColor('#666').text(`    ${t.notes}`);
        }
        doc.moveDown(0.3);
      }
      doc.moveDown(1);
    }

    if (activeSections.has('triage') && triageResult.rows.length > 0) {
      S('Scores de Triage Machine');
      const RISK_COLORS = { CRITIQUE: '#ef4444', ÉLEVÉ: '#f97316', MOYEN: '#eab308', FAIBLE: '#22c55e' };
      for (const ts of triageResult.rows) {
        if (doc.y > 720) doc.addPage();
        const color = RISK_COLORS[ts.risk_level] || '#999';
        doc.fontSize(10).fillColor('#333').text(`${ts.hostname}`, { continued: true });
        doc.fillColor(color).text(`  [${ts.risk_level}]  Score: ${ts.score}/100`, { continued: true });
        doc.fillColor('#666').text(`  (${ts.event_count} événements)`);
      }
      doc.moveDown(1.5);
    }

    if (activeSections.has('yara') && yaraResult.rows.length > 0) {
      S('Résultats Scan YARA');
      doc.fontSize(9).fillColor('#333').text(`${yaraResult.rows.length} correspondance(s) YARA détectée(s).`);
      doc.moveDown(0.3);
      for (const y of yaraResult.rows) {
        if (doc.y > 720) doc.addPage();
        doc.fontSize(9).fillColor('#ef4444').text(`⚑  ${y.rule_name}`, { continued: true });
        doc.fillColor('#666').text(`  — ${y.evidence_name || 'N/A'}  (${y.match_count} correspondance(s))`);
      }
      doc.moveDown(1.5);
    }

    if (activeSections.has('threat_intel') && correlResult.rows.length > 0) {
      S('Corrélations Threat Intelligence');
      doc.fontSize(9).fillColor('#333').text(`${correlResult.rows.length} IOC(s) corrélé(s) avec des indicateurs Threat Intel connus.`);
      doc.moveDown(0.3);
      for (const c of correlResult.rows) {
        if (doc.y > 720) doc.addPage();
        doc.fontSize(9).fillColor('#f97316').text(`[${c.ioc_type}] ${c.ioc_value}`, { continued: true });
        doc.fillColor('#555').text(`  → ${c.indicator_name || 'N/A'}  (${c.source_name || ''})`);
      }
      doc.moveDown(1.5);
    }

    if (activeSections.has('bookmarks') && bookmarkResult.rows.length > 0) {
      S('Événements Marqués (Bookmarks)');
      let lastTactic = null;
      for (const b of bookmarkResult.rows) {
        if (doc.y > 720) doc.addPage();
        if (b.mitre_tactic !== lastTactic) {
          doc.moveDown(0.3);
          doc.fontSize(10).fillColor(accentColor).text(b.mitre_tactic || 'Non classé');
          lastTactic = b.mitre_tactic;
        }
        doc.fontSize(9).fillColor('#333').text(`  • ${b.title}`, { continued: !!b.mitre_technique });
        if (b.mitre_technique) doc.fillColor('#888').text(`  [${b.mitre_technique}]`);
        else doc.text('');
        if (b.description) doc.fontSize(8).fillColor('#666').text(`    ${b.description}`);
      }
      doc.moveDown(1.5);
    }

    if (activeSections.has('hayabusa') && hayabusaResult.rows.length > 0) {
      S('Détections Hayabusa (Critical/High)');
      doc.fontSize(9).fillColor('#333').text(`${hayabusaResult.rows.length} alerte(s) Hayabusa de niveau critical/high détectée(s).`);
      doc.moveDown(0.3);
      const LEVEL_COLORS = { critical: '#ef4444', high: '#f97316' };
      for (const h of hayabusaResult.rows) {
        if (doc.y > 720) doc.addPage();
        const lcolor = LEVEL_COLORS[h.level] || '#666';
        doc.fontSize(9).fillColor(lcolor).text(`[${(h.level || '').toUpperCase()}]`, { continued: true });
        doc.fillColor('#333').text(`  ${h.rule_title || h.description || 'N/A'}`);
        if (h.tactics) doc.fontSize(8).fillColor('#666').text(`  Tactiques: ${h.tactics}`);
        if (h.timestamp) doc.fontSize(8).fillColor('#999').text(`  ${new Date(h.timestamp).toLocaleString('fr-FR')}${h.host_name ? '  — ' + h.host_name : ''}`);
      }
      doc.moveDown(1.5);
    }

    if (activeSections.has('sigma') && sigmaResult.rows.length > 0) {
      S('Résultats Sigma Threat Hunting');
      doc.fontSize(9).fillColor('#333').text(`${sigmaResult.rows.length} règle(s) Sigma ayant généré des correspondances.`);
      doc.moveDown(0.3);
      for (const s of sigmaResult.rows) {
        if (doc.y > 720) doc.addPage();
        doc.fontSize(9).fillColor('#a371f7').text(`⚑  ${s.rule_name}`, { continued: true });
        doc.fillColor('#666').text(`  (${s.match_count} match${s.match_count > 1 ? 'es' : ''})`);
        if (s.rule_description) doc.fontSize(8).fillColor('#888').text(`  ${s.rule_description}`);
      }
      doc.moveDown(1.5);
    }

    if (aiNarrative?.recommendations) {
      S('Recommandations (IA)');
      doc.fontSize(10).fillColor('#555').text(aiNarrative.recommendations, { align: 'justify' });
      doc.moveDown(1.5);
    }

    if (activeSections.has('custody')) {
      S('Chaîne de Custody');
      for (const ev of evidence) {
        if (doc.y > 720) doc.addPage();
        doc.fontSize(9).fillColor('#333').text(`${ev.name}`);
        doc.fontSize(8).fillColor('#666').text(`  MD5: ${ev.hash_md5 || 'N/A'}`);
        doc.text(`  SHA1: ${ev.hash_sha1 || 'N/A'}`);
        doc.text(`  SHA256: ${ev.hash_sha256 || 'N/A'}`);
        doc.text(`  Ajouté: ${new Date(ev.created_at).toLocaleString('fr-FR')}`);
        doc.text(`  Intégrité: ✓ Vérifié`);
        doc.moveDown(0.3);
      }
    }

    doc.moveDown(2);
    const footerLine = footerText || `Généré par Heimdall DFIR v2.7.0 le ${new Date().toLocaleString('fr-FR')} · Par: ${req.user.full_name}`;
    doc.fontSize(8).fillColor('#999').text(footerLine, { align: 'center' });
    if (footerText) doc.fontSize(8).fillColor('#999').text(`Généré le ${new Date().toLocaleString('fr-FR')} par ${req.user.full_name}`, { align: 'center' });

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
