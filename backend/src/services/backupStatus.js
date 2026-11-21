const fs = require('fs');
const path = require('path');

const RUN_FILE_RE = /^\d{8}-\d{6}-\d+\.json$/;
const HOUR = 60 * 60 * 1000;

function runsDir() {
  return process.env.BACKUP_RUNS_DIR || '/app/backup-runs';
}

function maxAgeHours() {
  const value = Number(process.env.BACKUP_MAX_AGE_HOURS);
  return Number.isFinite(value) && value > 0 ? value : 48;
}

async function readRuns(dir) {
  let names;
  try {
    names = await fs.promises.readdir(dir);
  } catch (error) {
    if (error && (error.code === 'ENOENT' || error.code === 'ENOTDIR' || error.code === 'EACCES')) return [];
    throw error;
  }
  const runs = [];
  for (const name of names.filter((n) => RUN_FILE_RE.test(n))) {
    try {
      const data = JSON.parse(await fs.promises.readFile(path.join(dir, name), 'utf8'));
      const finished = Date.parse(data.finished_at);
      if (!Number.isFinite(finished) || typeof data.status !== 'string') continue;
      runs.push({ status: data.status, finishedAt: finished, finished_at: data.finished_at });
    } catch (_) {
      continue;
    }
  }
  return runs;
}

async function readBackupStatus({ dir = runsDir(), now = Date.now(), maxAgeH = maxAgeHours() } = {}) {
  const runs = await readRuns(dir);
  const latest = runs.reduce((best, r) => (!best || r.finishedAt > best.finishedAt ? r : best), null);
  const success = runs.filter((r) => r.status === 'ok')
    .reduce((best, r) => (!best || r.finishedAt > best.finishedAt ? r : best), null);
  let state = 'disabled';
  if (success) state = now - success.finishedAt > maxAgeH * HOUR ? 'stale' : 'ok';
  return {
    state,
    last_success_at: success ? success.finished_at : null,
    last_run_at: latest ? latest.finished_at : null,
    last_run_status: latest ? latest.status : null,
    max_age_hours: maxAgeH,
    runs_checked: runs.length,
  };
}

module.exports = { readBackupStatus };
