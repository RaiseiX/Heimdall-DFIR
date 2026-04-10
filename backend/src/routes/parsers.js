const express = require('express');
const { execSync, exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const { parse } = require('csv-parse/sync');
const { pool } = require('../config/database');
const { authenticate, auditLog } = require('../middleware/auth');

const logger = require('../config/logger').default;
const router = express.Router();
const ZIMMERMAN_DIR = process.env.ZIMMERMAN_TOOLS_DIR || '/app/zimmerman-tools';
const TEMP_DIR = '/app/temp';

const ZIMMERMAN_TOOLS = {
  mft: { dll: 'MFTECmd.dll', name: 'MFTECmd', description: 'Parse $MFT (Master File Table)', extensions: ['.mft', '$mft'] },
  prefetch: { dll: 'PECmd.dll', name: 'PECmd', description: 'Parse Windows Prefetch files', extensions: ['.pf'] },
  lnk: { dll: 'LECmd.dll', name: 'LECmd', description: 'Parse Windows LNK (shortcut) files', extensions: ['.lnk'] },
  shellbags: { dll: 'SBECmd.dll', name: 'SBECmd', description: 'Parse Shellbags', extensions: [] },
  amcache: { dll: 'AmcacheParser.dll', name: 'AmcacheParser', description: 'Parse Amcache.hve', extensions: ['.hve'] },
  appcompat: { dll: 'AppCompatCacheParser.dll', name: 'AppCompatCacheParser', description: 'Parse AppCompatCache (ShimCache)', extensions: [] },
  evtx: { dll: 'EvtxECmd.dll', name: 'EvtxECmd', description: 'Parse Windows Event Logs', extensions: ['.evtx'] },
  registry: { dll: 'RECmd.dll', name: 'RECmd', description: 'Parse Windows Registry hives', extensions: ['.dat', '.hve'] },
  jumplist: { dll: 'JLECmd.dll', name: 'JLECmd', description: 'Parse Jump Lists', extensions: ['.automaticDestinations-ms', '.customDestinations-ms'] },
  srum: { dll: 'SrumECmd.dll', name: 'SrumECmd', description: 'Parse SRUM database', extensions: ['.dat'] },
  sum: { dll: 'SumECmd.dll', name: 'SumECmd', description: 'Parse User Access Logging', extensions: [] },
  wxtcmd: { dll: 'WxTCmd.dll', name: 'WxTCmd', description: 'Parse Windows Timeline (ActivitiesCache.db)', extensions: ['.db'] },
};

router.get('/available', authenticate, async (req, res) => {
  const tools = {};
  for (const [key, tool] of Object.entries(ZIMMERMAN_TOOLS)) {
    const dllPath = path.join(ZIMMERMAN_DIR, tool.dll);
    tools[key] = {
      ...tool,
      available: fs.existsSync(dllPath),
      path: dllPath
    };
  }
  res.json(tools);
});

router.post('/run', authenticate, async (req, res) => {
  try {
    const { parser, evidence_id, case_id, options } = req.body;

    if (!ZIMMERMAN_TOOLS[parser]) {
      return res.status(400).json({ error: `Parseur inconnu: ${parser}` });
    }

    const tool = ZIMMERMAN_TOOLS[parser];
    const dllPath = path.join(ZIMMERMAN_DIR, tool.dll);

    if (!fs.existsSync(dllPath)) {
      return res.status(404).json({
        error: `Outil ${tool.name} non trouvé`,
        hint: `Placez ${tool.dll} dans ${ZIMMERMAN_DIR}`
      });
    }

    const evidenceResult = await pool.query('SELECT file_path, name FROM evidence WHERE id = $1', [evidence_id]);
    if (evidenceResult.rows.length === 0) return res.status(404).json({ error: 'Preuve non trouvée' });

    const inputFile = evidenceResult.rows[0].file_path;
    const outputDir = path.join(TEMP_DIR, `parse-${Date.now()}`);
    fs.mkdirSync(outputDir, { recursive: true });

    let cmd = `dotnet "${dllPath}" -f "${inputFile}" --csv "${outputDir}"`;

    if (parser === 'evtx') {
      cmd = `dotnet "${dllPath}" -f "${inputFile}" --csv "${outputDir}" --csvf results.csv`;
    } else if (parser === 'registry') {
      cmd = `dotnet "${dllPath}" -f "${inputFile}" --csv "${outputDir}" --csvf results.csv`;
    }

    try {
      execSync(cmd, { timeout: 300000, maxBuffer: 1024 * 1024 * 100 });
    } catch (execErr) {
      logger.error(`Parser execution error: ${execErr.message}`);

    }

    const csvFiles = fs.readdirSync(outputDir).filter(f => f.endsWith('.csv'));
    let outputData = [];
    let recordCount = 0;

    for (const csvFile of csvFiles) {
      const csvContent = fs.readFileSync(path.join(outputDir, csvFile), 'utf-8');
      try {
        const records = parse(csvContent, { columns: true, skip_empty_lines: true, relax_column_count: true });
        outputData.push({ file: csvFile, records });
        recordCount += records.length;
      } catch (parseErr) {
        logger.error(`CSV parse error for ${csvFile}:`, parseErr.message);
      }
    }

    const result = await pool.query(
      `INSERT INTO parser_results (case_id, evidence_id, parser_name, parser_version, input_file, output_data, record_count, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [case_id, evidence_id, tool.name, '1.0', inputFile, JSON.stringify(outputData), recordCount, req.user.id]
    );

    fs.rmSync(outputDir, { recursive: true, force: true });

    await auditLog(req.user.id, 'run_parser', 'parser', result.rows[0].id, { parser: tool.name, evidence_id, record_count: recordCount }, req.ip);

    res.json({
      id: result.rows[0].id,
      parser: tool.name,
      record_count: recordCount,
      data: outputData
    });
  } catch (err) {
    logger.error('Parser error:', err);
    res.status(500).json({ error: 'Erreur exécution parseur' });
  }
});

router.get('/results/:caseId', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT pr.*, e.name as evidence_name, u.full_name as parsed_by
      FROM parser_results pr
      LEFT JOIN evidence e ON pr.evidence_id = e.id
      LEFT JOIN users u ON pr.created_by = u.id
      WHERE pr.case_id = $1
      ORDER BY pr.created_at DESC
    `, [req.params.caseId]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;
