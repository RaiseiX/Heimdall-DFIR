async function withCaseDeletion(pool, caseId, operation) {
  const client = await pool.connect();
  let transactionStarted = false;
  let releaseError;

  try {
    await client.query('BEGIN');
    transactionStarted = true;
    const result = await client.query(
      'SELECT id, legal_hold FROM cases WHERE id = $1 FOR UPDATE',
      [caseId],
    );
    const caseRow = result.rows[0];
    if (!caseRow) {
      throw Object.assign(new Error('Case not found'), { status: 404 });
    }
    if (caseRow.legal_hold) {
      throw Object.assign(new Error('Case is under legal hold'), {
        status: 409,
        code: 'LEGAL_HOLD',
      });
    }

    const value = await operation(client);
    await client.query('COMMIT');
    return value;
  } catch (error) {
    if (transactionStarted) {
      try {
        await client.query('ROLLBACK');
      } catch (rollbackError) {
        releaseError = rollbackError;
      }
    } else {
      releaseError = error;
    }
    throw error;
  } finally {
    if (releaseError) client.release(releaseError);
    else client.release();
  }
}

module.exports = { withCaseDeletion };
