// "Run all" detection orchestrator — runs every engine on a case in the background.
// Shared by the Threat Hunting route (manual launch) and the parsing pipeline
// (auto-launch when parsing finishes). Reuses existing endpoints via internal HTTP
// with a short-lived JWT signed for the requesting user — no scan-logic duplication.
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { JWT_SECRET } = require('../middleware/auth');
const logger = require('../config/logger').default;

const RUN_ALL_JOBS = new Map(); // caseId -> job

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
  if (Array.isArray(d.results)) return d.results.length;
  if (Array.isArray(d.matches)) return d.matches.length;
  if (Array.isArray(d.hunts))   return d.hunts.reduce((s, h) => s + (h.match_count || 0), 0);
  if (typeof d.detections === 'number') return d.detections;
  return 0;
}

function getRunAllJob(caseId) {
  return RUN_ALL_JOBS.get(caseId) || { caseId, status: 'idle', steps: [] };
}

// Launch all engines in the background. `trigger` = 'manual' | 'auto'.
// Guarded: a case already running is not restarted.
function startRunAll(caseId, user, trigger = 'manual') {
  const existing = RUN_ALL_JOBS.get(caseId);
  if (existing && existing.status === 'running') return existing;

  const token = jwt.sign({ id: user.id, username: user.username, role: user.role || 'admin' }, JWT_SECRET, { expiresIn: '30m' });
  const job = {
    caseId, status: 'running', trigger, startedAt: Date.now(), finishedAt: null,
    steps: RUN_ALL_ENGINES.map(e => ({ key: e.key, label: e.label, status: 'pending', count: null, error: null })),
  };
  RUN_ALL_JOBS.set(caseId, job);

  (async () => {
    const base = `http://localhost:${process.env.PORT || 4000}`;
    for (let i = 0; i < RUN_ALL_ENGINES.length; i++) {
      const e = RUN_ALL_ENGINES[i]; const step = job.steps[i];
      step.status = 'running';
      try {
        const resp = await axios({
          method: e.method, url: base + e.path(caseId),
          headers: { Authorization: `Bearer ${token}` },
          timeout: e.timeout || 120000, data: e.method === 'post' ? {} : undefined,
        });
        step.count = extractCount(resp.data); step.status = 'done';
      } catch (err) {
        step.status = 'error'; step.error = err.response?.data?.error || err.message;
      }
    }
    job.status = 'done'; job.finishedAt = Date.now();
    logger.info(`[run-all] case ${caseId} done (${trigger}) — ${job.steps.reduce((s, st) => s + (st.count || 0), 0)} results`);
  })();

  return job;
}

module.exports = { startRunAll, getRunAllJob };
