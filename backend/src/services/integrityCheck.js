const { verifyEvidence } = require('./sourceArchive');
const { appendAuditRow } = require('./auditChain');

const ACTION = 'evidence_integrity_check';

async function runIntegrityCheck({
  db, caseId, evidenceId = null, userId = null, trigger, jobId = null,
  verify = verifyEvidence, record = appendAuditRow, onProgress = () => {}, racines,
}) {
  const params = [caseId];
  let filter = '';
  if (evidenceId) {
    params.push(evidenceId);
    filter = ' AND id = $2';
  }
  const { rows } = await db.query(
    `SELECT id, case_id, evidence_type, file_path, hash_sha256, additional_files
       FROM evidence
      WHERE case_id = $1${filter}
      ORDER BY created_at, id`,
    params,
  );

  const total = rows.length;
  const counts = {};
  let done = 0;

  for (const row of rows) {
    const present = await db.query('SELECT 1 FROM cases WHERE id = $1', [caseId]);
    if (!present.rows || present.rows.length === 0) return { aborted: true, total, done, counts };

    const result = await verify(row, { racines });
    await record(db, {
      userId: userId ?? null,
      action: ACTION,
      entityType: 'evidence',
      entityId: row.id,
      details: {
        case_id: caseId,
        status: result.status,
        expected_sha256: result.expected_sha256,
        computed_sha256: result.computed_sha256,
        target: result.target,
        trigger,
        job_id: jobId,
      },
    });

    done += 1;
    counts[result.status] = (counts[result.status] || 0) + 1;
    onProgress({ done, total, evidenceId: row.id, status: result.status });
  }

  return { aborted: false, total, done, counts };
}

module.exports = { runIntegrityCheck };
