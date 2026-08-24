// "Run all" detection orchestrator — runs every engine on a case in the background.
// Shared by the Threat Hunting route (manual launch) and the parsing pipeline
// (auto-launch when parsing finishes). Reuses existing endpoints via internal HTTP
// with a short-lived JWT signed for the requesting user — no scan-logic duplication.
// State is persisted to `hunt_runs` (services/huntRuns) so it survives restarts and
// is shared across API instances; actual work is dispatched via the `hunting-jobs`
// BullMQ queue and executed by the hunting worker (Task 3).
//
// Engine split (2026-08-21): YARA/Sigma operate at case scope (they sweep the
// case's evidence files / logs as a whole), while the detection engines
// (persistence, ATT&CK, ...) and Hayabusa are evidence-scoped — the detections UI
// always passes ?evidence_id=<uuid> and the backend caches per evidence
// (`detection_cache` keyed `section:e<uuid>`). A case-scoped run would fill cache
// keys the page never reads, and a case-wide Hayabusa would re-scan every
// evidence's EVTX. So the detection engines + Hayabusa are run once PER EVIDENCE
// that has timeline rows (evidence_id in body/query) — after a parse the cache is
// warm for the evidence(s) parsed, and opening the detections page is instant.
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { JWT_SECRET } = require('../middleware/auth');
const logger = require('../config/logger').default;
const { pool } = require('../config/database');
const { huntingQueue } = require('../config/queue');
const { startHuntRun, updateHuntStep, finishHuntRun, getHuntRun } = require('./huntRuns');

// Engines that operate over the whole case (files/logs), not one evidence.
const CASE_ENGINES = [
  { key: 'yara',              label: 'YARA (preuves)',          method: 'post', path: (c) => `/api/threat-hunting/yara/scan-case/${c}`, timeout: 600000 },
  { key: 'sigma',             label: 'Sigma (logs)',            method: 'post', path: (c) => `/api/threat-hunting/sigma/scan-case/${c}`, timeout: 600000 },
];

// Evidence-scoped detection engines. Keys MUST match the section names the
// detections UI reads back (`evSection` in routes/cases.js: 'timestomping',
// 'double-ext', 'beaconing', 'persistence', 'sysmon-behavior', 'anti-forensic',
// 'execution-anomaly', 'attack-techniques', 'vuln-drivers') so the refresh=1
// call lands in the exact `detection_cache` row the page will serve.
// `params` mirrors the frontend defaults (timestomping opens at 1 day, beaconing
// at its hard floor) so the pre-warmed payload matches the page's initial load.
const DETECTION_ENGINES = [
  { key: 'persistence',       label: 'Persistance',             method: 'get', path: (c) => `/api/cases/${c}/detections/persistence`, timeout: 300000 },
  { key: 'sysmon-behavior',   label: 'Sysmon comportemental',   method: 'get', path: (c) => `/api/cases/${c}/detections/sysmon-behavior`, timeout: 300000 },
  { key: 'anti-forensic',     label: 'Anti-forensique',         method: 'get', path: (c) => `/api/cases/${c}/detections/anti-forensic`, timeout: 300000 },
  { key: 'execution-anomaly', label: "Anomalies d'exécution",   method: 'get', path: (c) => `/api/cases/${c}/detections/execution-anomaly`, timeout: 300000 },
  { key: 'attack-techniques', label: 'Techniques ATT&CK',       method: 'get', path: (c) => `/api/cases/${c}/detections/attack-techniques`, timeout: 600000 },
  { key: 'vuln-drivers',      label: 'LOLDrivers / HijackLibs', method: 'get', path: (c) => `/api/cases/${c}/detections/vuln-drivers`, timeout: 300000 },
  { key: 'timestomping',      label: 'Timestomping',            method: 'get', path: (c) => `/api/cases/${c}/detections/timestomping`, params: { threshold_days: 1 }, timeout: 300000 },
  { key: 'double-ext',        label: 'Double extension',        method: 'get', path: (c) => `/api/cases/${c}/detections/double-ext`, timeout: 300000 },
  { key: 'beaconing',         label: 'Beaconing C2',            method: 'get', path: (c) => `/api/cases/${c}/detections/beaconing`, timeout: 300000 },
];

// Hayabusa is a full parser run (it wipes and re-inserts its own rows), but in
// the background auto-run it must target only the parsed evidence — a case-wide
// scan would re-process every evidence's EVTX files. It posts { evidence_id }
// and the /hayabusa route scopes both the scan root and the row cleanup to that
// evidence. On a large EVTX set (4961 rules, --enable-all-rules) it can run 30+
// minutes; 2h matches the frontend's timeout.
const HAYABUSA_ENGINE = { key: 'hayabusa', label: 'Hayabusa', method: 'post', path: (c) => `/api/collection/${c}/hayabusa`, timeout: 7200000 };

// Kept for backwards compatibility: the full engine list (case + per-evidence).
const RUN_ALL_ENGINES = [...CASE_ENGINES, ...DETECTION_ENGINES, HAYABUSA_ENGINE];

function extractCount(d) {
  if (d == null) return 0;
  if (typeof d.total === 'number') return d.total;
  if (Array.isArray(d.results)) return d.results.length;
  if (Array.isArray(d.matches)) return d.matches.length;
  if (Array.isArray(d.hunts))   return d.hunts.reduce((s, h) => s + (h.match_count || 0), 0);
  if (typeof d.detections === 'number') return d.detections;
  return 0;
}

// Enumerate the evidences a detection run must cover. When `evidenceId` is given
// (auto-trigger right after that evidence's ingestion), only that evidence is
// warmed — it is the one the analyst just parsed and will open next. Otherwise
// (parse completion in collection.js, manual "Tout lancer") every evidence with
// timeline rows is warmed so the whole case is ready.
async function evidenceIds(p, caseId, evidenceId) {
  try {
    if (evidenceId) {
      const r = await p.query(
        `SELECT DISTINCT evidence_id AS id FROM collection_timeline
          WHERE case_id = $1 AND evidence_id = $2 AND evidence_id IS NOT NULL`,
        [caseId, evidenceId]);
      return r.rows.map(row => row.id);
    }
    const r = await p.query(
      `SELECT DISTINCT evidence_id AS id FROM collection_timeline
        WHERE case_id = $1 AND evidence_id IS NOT NULL`,
      [caseId]);
    return r.rows.map(row => row.id);
  } catch (err) {
    logger.warn('[hunt] evidence enumeration failed:', err.message);
    return [];
  }
}

// Full step list for a run: case engines + one detection step per evidence.
// `updateHuntStep` only patches existing step keys, so this list must contain
// every step the worker will ever mark running/done/error.
async function buildSteps(p, caseId, evidenceId) {
  // Detections + Hayabusa first: they are the fast, index-bounded scans the
  // detections page waits on. YARA/Sigma (case engines) can take 30 min+ and
  // must not delay the cache warm-up.
  const steps = [];
  const ids = await evidenceIds(p, caseId, evidenceId);
  let names = {};
  try {
    const r = await p.query('SELECT id, name FROM evidence WHERE case_id = $1', [caseId]);
    for (const row of r.rows) names[row.id] = row.name;
  } catch (err) { /* labels are best-effort */ }
  for (const id of ids) {
    for (const e of DETECTION_ENGINES) {
      steps.push({
        key: `${e.key}:e${id}`,
        label: `${e.label} · ${names[id] || id.slice(0, 8)}`,
        status: 'pending', count: null, error: null,
      });
    }
    steps.push({
      key: `${HAYABUSA_ENGINE.key}:e${id}`,
      label: `${HAYABUSA_ENGINE.label} · ${names[id] || id.slice(0, 8)}`,
      status: 'pending', count: null, error: null,
    });
  }
  for (const e of CASE_ENGINES) {
    steps.push({ key: e.key, label: e.label, status: 'pending', count: null, error: null });
  }
  return steps;
}

async function enqueueHunt(p, huntRunId, caseId, userId, trigger, evidenceId) {
  try {
    await huntingQueue.add('hunt', { caseId, userId, trigger, evidenceId: evidenceId || undefined, huntRunId });
  } catch (err) {
    // Enqueue failed (e.g. Redis blip) after the 'running' row was inserted — release the
    // per-case guard so future auto-hunts aren't blocked forever by an orphaned row.
    await finishHuntRun(p, huntRunId, 'error');
    throw err;
  }
}

// Guard + persist + enqueue. Shared by routes (via startRunAll) and workers.
async function triggerHunt(p, caseId, userId, trigger = 'manual', evidenceId = null) {
  const steps = await buildSteps(p, caseId, evidenceId);
  const { started, huntRunId } = await startHuntRun(p, caseId, trigger, evidenceId, steps);
  if (!started) {
    // Guard blocked by a 'running' row. A worker crash / backend restart can leave that
    // row frozen forever — the per-case guard then silently swallows every later
    // auto-hunt (incl. Hayabusa), which is exactly how "Hayabusa never launches" shows
    // up in the UI. Reclaim runs whose heartbeat froze (> 30 min, matching
    // reconcileStaleHunts), then retry once.
    try {
      const stale = await p.query(
        `UPDATE hunt_runs SET status='error', finished_at=NOW(), updated_at=NOW()
          WHERE case_id=$1 AND status='running' AND updated_at < NOW() - interval '30 minutes'
          RETURNING id`,
        [caseId]
      );
      if (stale.rowCount > 0) {
        logger.warn(`[hunt] reclaimed ${stale.rowCount} stale 'running' run(s) for case ${caseId} — retrying trigger`);
        const retrySteps = await buildSteps(p, caseId, evidenceId);
        const retry = await startHuntRun(p, caseId, trigger, evidenceId, retrySteps);
        if (retry.started) {
          await enqueueHunt(p, retry.huntRunId, caseId, userId, trigger, evidenceId);
          return { started: true, huntRunId: retry.huntRunId };
        }
      }
    } catch (err) {
      logger.warn('[hunt] stale-reclaim error:', err.message);
    }
    return { started: false };
  }
  await enqueueHunt(p, huntRunId, caseId, userId, trigger, evidenceId);
  return { started: true, huntRunId };
}

// The actual engine orchestration — runs in the hunting worker (Task 3). Reuses the
// existing endpoints via internal HTTP with a short-lived JWT; no scan-logic duplication.
async function runAllEngines(p, caseId, userId, huntRunId, evidenceId = null) {
  const u = (await p.query('SELECT username, role FROM users WHERE id=$1', [userId])).rows[0] || { username: 'system', role: 'admin' };
  const token = jwt.sign({ id: userId, username: u.username, role: u.role || 'admin' }, JWT_SECRET, { expiresIn: '30m' });
  const base = process.env.INTERNAL_API_BASE || 'http://backend:4000';
  // Per-evidence detections + Hayabusa first (fast, index-bounded detections) so
  // the cache is warm before the slow case engines (YARA/Sigma) have finished.
  const ids = await evidenceIds(p, caseId, evidenceId);
  for (const id of ids) {
    for (const e of [...DETECTION_ENGINES, HAYABUSA_ENGINE]) {
      const key = `${e.key}:e${id}`;
      await updateHuntStep(p, huntRunId, key, { status: 'running' });
      try {
        const opts = { method: e.method, url: base + e.path(caseId),
          headers: { Authorization: `Bearer ${token}` }, timeout: e.timeout || 120000 };
        if (e.method === 'post') {
          // Hayabusa: body carries the evidence to scope the scan + cleanup to.
          opts.data = { evidence_id: id };
        } else {
          opts.url += `?${new URLSearchParams({ ...(e.params || {}), refresh: 1, evidence_id: id }).toString()}`;
        }
        const resp = await axios(opts);
        await updateHuntStep(p, huntRunId, key, { status: 'done', count: extractCount(resp.data) });
      } catch (err) {
        // 409 = another Hayabusa run is already in flight for this case (e.g. the
        // frontend started it first). Not a failure — the running instance writes
        // the same rows.
        if (err.response?.status === 409 && e.key === 'hayabusa') {
          await updateHuntStep(p, huntRunId, key, { status: 'done', count: null, error: null });
        } else {
          await updateHuntStep(p, huntRunId, key, { status: 'error', error: err.response?.data?.error || err.message });
        }
      }
    }
  }
  for (const e of CASE_ENGINES) {
    await updateHuntStep(p, huntRunId, e.key, { status: 'running' });
    try {
      const resp = await axios({ method: e.method, url: base + e.path(caseId),
        headers: { Authorization: `Bearer ${token}` }, timeout: e.timeout || 120000,
        data: e.method === 'post' ? {} : undefined });
      await updateHuntStep(p, huntRunId, e.key, { status: 'done', count: extractCount(resp.data) });
    } catch (err) {
      // 409 = another Hayabusa run is already in flight for this case (e.g. the
      // frontend pipeline started it first). That's not a failure — the step is
      // effectively done; the running instance writes the same rows.
      if (err.response?.status === 409 && e.key === 'hayabusa') {
        await updateHuntStep(p, huntRunId, e.key, { status: 'done', count: null, error: null });
      } else {
        await updateHuntStep(p, huntRunId, e.key, { status: 'error', error: err.response?.data?.error || err.message });
      }
    }
  }
  await finishHuntRun(p, huntRunId, 'done');
  logger.info(`[hunt] case ${caseId} done — engines executed`);
}

// Signatures preserved for routes (collection.js:2113, threatHunting.ts).
async function startRunAll(caseId, user, trigger = 'manual', evidenceId = null) {
  await triggerHunt(pool, caseId, user.id, trigger, evidenceId);
  return getHuntRun(pool, caseId);
}
async function getRunAllJob(caseId) { return getHuntRun(pool, caseId); }

module.exports = { RUN_ALL_ENGINES, runAllEngines, triggerHunt, startRunAll, getRunAllJob };
