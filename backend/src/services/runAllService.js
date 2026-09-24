// "Run all" detection orchestrator — runs every engine on a case in the background.
// Shared by the Threat Hunting route (manual launch) and the parsing pipeline
// (auto-launch when parsing finishes). Reuses existing endpoints via internal HTTP
// with a short-lived JWT signed for the requesting user — no scan-logic duplication.
// State is persisted to `hunt_runs` (services/huntRuns) so it survives restarts and
// is shared across API instances; actual work is dispatched via the `hunting-jobs`
// BullMQ queue and executed by the hunting worker (Task 3).
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { JWT_SECRET } = require('../middleware/auth');
const logger = require('../config/logger').default;
const { pool } = require('../config/database');
const { huntingQueue } = require('../config/queue');
const { startHuntRun, updateHuntStep, finishHuntRun, getHuntRun } = require('./huntRuns');

const RUN_ALL_ENGINES = [
  { key: 'yara',              label: 'YARA (preuves)',          method: 'post', path: (c) => `/api/threat-hunting/yara/scan-case/${c}`, timeout: 600000 },
  { key: 'sigma',             label: 'Sigma (logs)',            method: 'post', path: (c) => `/api/threat-hunting/sigma/scan-case/${c}`, timeout: 600000 },
  { key: 'hayabusa',          label: 'Hayabusa',                method: 'post', path: (c) => `/api/collection/${c}/hayabusa`, timeout: 900000 },
  { key: 'persistence',       label: 'Persistance',             method: 'get',  path: (c) => `/api/cases/${c}/detections/persistence` },
  { key: 'sysmon-behavior',   label: 'Sysmon comportemental',   method: 'get',  path: (c) => `/api/cases/${c}/detections/sysmon-behavior` },
  { key: 'anti-forensic',     label: 'Anti-forensique',         method: 'get',  path: (c) => `/api/cases/${c}/detections/anti-forensic` },
  { key: 'execution-anomaly', label: "Anomalies d'exécution",   method: 'get',  path: (c) => `/api/cases/${c}/detections/execution-anomaly` },
  { key: 'attack-techniques', label: 'Techniques ATT&CK',       method: 'get',  path: (c) => `/api/cases/${c}/detections/attack-techniques` },
  { key: 'vuln-drivers',      label: 'LOLDrivers / HijackLibs',  method: 'get', path: (c) => `/api/cases/${c}/detections/vuln-drivers`, timeout: 180000 },
];

function extractCount(d) {
  if (d == null) return 0;
  if (typeof d.total === 'number') return d.total;
  if (typeof d.total_detections === 'number') return d.total_detections;
  if (Array.isArray(d.results)) return d.results.length;
  if (Array.isArray(d.matches)) return d.matches.length;
  if (Array.isArray(d.hunts))   return d.hunts.reduce((s, h) => s + (h.match_count || 0), 0);
  if (typeof d.detections === 'number') return d.detections;
  return 0;
}

const initialSteps = () => RUN_ALL_ENGINES.map(e => ({ key: e.key, label: e.label, status: 'pending', count: null, error: null }));

// Guard + persist + enqueue. Shared by routes (via startRunAll) and workers.
async function triggerHunt(p, caseId, userId, trigger = 'manual', evidenceId = null) {
  const { started, huntRunId } = await startHuntRun(p, caseId, trigger, evidenceId, initialSteps());
  if (!started) return { started: false };
  try {
    await huntingQueue.add('hunt', { caseId, userId, trigger, evidenceId: evidenceId || undefined, huntRunId });
  } catch (err) {
    // Enqueue failed (e.g. Redis blip) after the 'running' row was inserted — release the
    // per-case guard so future auto-hunts aren't blocked forever by an orphaned row.
    await finishHuntRun(p, huntRunId, 'error');
    return { started: false };
  }
  return { started: true, huntRunId };
}

// The actual engine orchestration — runs in the hunting worker (Task 3). Reuses the
// existing endpoints via internal HTTP with a short-lived JWT; no scan-logic duplication.
const NOT_CONNECTED_CODES = new Set(['ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED']);
const RETRY_DELAYS_MS = [10000, 30000, 60000];
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function callEngine(e, base, caseId, sign, pause) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await axios({ method: e.method, url: base + e.path(caseId),
        headers: { Authorization: `Bearer ${sign()}` }, timeout: e.timeout || 120000,
        data: e.method === 'post' ? {} : undefined });
    } catch (err) {
      if (err.response || !NOT_CONNECTED_CODES.has(err.code) || attempt >= RETRY_DELAYS_MS.length) throw err;
      await pause(RETRY_DELAYS_MS[attempt]);
    }
  }
}

async function runAllEngines(p, caseId, userId, huntRunId, { pause = sleep } = {}) {
  const u = (await p.query('SELECT username, role FROM users WHERE id=$1', [userId])).rows[0] || { username: 'system', role: 'admin' };
  const sign = () => jwt.sign({ id: userId, username: u.username, role: u.role || 'admin' }, JWT_SECRET, { expiresIn: '30m' });
  const base = process.env.INTERNAL_API_BASE || 'http://backend:4000';
  for (const e of RUN_ALL_ENGINES) {
    await updateHuntStep(p, huntRunId, e.key, { status: 'running' });
    try {
      const resp = await callEngine(e, base, caseId, sign, pause);
      await updateHuntStep(p, huntRunId, e.key, { status: 'done', count: extractCount(resp.data) });
    } catch (err) {
      await updateHuntStep(p, huntRunId, e.key, { status: 'error', error: err.response?.data?.error || err.message });
    }
  }
  await finishHuntRun(p, huntRunId, 'done');
  logger.info(`[hunt] case ${caseId} done — engines executed`);
}

// Signatures preserved for routes (collection.js:2113, threatHunting.ts).
async function startRunAll(caseId, user, trigger = 'manual') {
  await triggerHunt(pool, caseId, user.id, trigger);
  return getHuntRun(pool, caseId);
}
async function getRunAllJob(caseId) { return getHuntRun(pool, caseId); }

module.exports = { RUN_ALL_ENGINES, runAllEngines, triggerHunt, startRunAll, getRunAllJob };
