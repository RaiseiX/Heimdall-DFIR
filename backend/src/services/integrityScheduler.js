const JOB_NAME = 'integrity';
const NIGHTLY_NAME = 'integrity-nightly';

function integrityJobId(caseId) {
  return `integrity-${String(caseId).toLowerCase()}`;
}

async function enqueueIntegrity(queue, request) {
  const caseId = String(request.caseId).toLowerCase();
  const evidenceId = request.evidenceId ? String(request.evidenceId).toLowerCase() : null;
  const userId = request.userId ?? null;
  const { trigger } = request;
  const jobId = integrityJobId(caseId);
  const existing = await queue.getJob(jobId);
  if (existing) {
    const state = await existing.getState();
    if (state !== 'completed' && state !== 'failed') return { status: 'running', jobId };
    await existing.remove();
  }
  const added = await queue.add(
    JOB_NAME,
    { caseId, evidenceId, userId, trigger },
    { jobId, attempts: 1, removeOnComplete: true, removeOnFail: { count: 50 } },
  );
  const data = added && added.data;
  if (data && ((data.userId ?? null) !== userId || (data.evidenceId ?? null) !== evidenceId)) {
    return { status: 'running', jobId };
  }
  return { status: 'queued', jobId };
}

async function scheduleNightly(queue, cron) {
  const pattern = typeof cron === 'string' ? cron.trim() : '';
  if (!pattern) {
    await queue.removeJobScheduler(NIGHTLY_NAME);
    return false;
  }
  await queue.upsertJobScheduler(
    NIGHTLY_NAME,
    { pattern },
    { name: NIGHTLY_NAME, data: { all: true, trigger: 'scheduled' } },
  );
  return true;
}

async function enqueueAllCases(db, queue) {
  const { rows } = await db.query('SELECT id FROM cases ORDER BY created_at');
  let queued = 0;
  let running = 0;
  for (const row of rows) {
    const res = await enqueueIntegrity(queue, { caseId: row.id, userId: null, trigger: 'scheduled' });
    if (res.status === 'running') running += 1;
    else queued += 1;
  }
  return { queued, running };
}

module.exports = { enqueueIntegrity, scheduleNightly, enqueueAllCases, integrityJobId };
