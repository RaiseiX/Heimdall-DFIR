const crypto = require('crypto');

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

function operationKey(operationType, caseId, targetId, generationKey) {
  const base = `${operationType}:${caseId}:${targetId}`;
  if (generationKey == null) return base;
  const generation = crypto.createHash('sha256').update(String(generationKey)).digest('hex');
  return `${base}:${generation}`;
}

function itemKey(item) {
  return crypto.createHash('sha256').update(`${item.kind}\0${item.locator}`).digest('hex');
}

function safeErrorCode(error) {
  const value = error?.code || error?.status || error?.name || 'DELETION_FAILED';
  return String(value).replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 80);
}

async function beginDeletionOperation(pool, input) {
  const key = operationKey(input.operationType, input.caseId, input.targetId, input.generationKey);
  const operationResult = await pool.query(
    `INSERT INTO case_deletion_operations
       (idempotency_key, case_id, case_number, operation_type, target_id, status, requested_by, request_ip, context)
     VALUES ($1, $2, $3, $4, $5, 'running', $6, $7, $8::jsonb)
     ON CONFLICT (idempotency_key) DO UPDATE
       SET updated_at = NOW(), status = CASE
         WHEN case_deletion_operations.status = 'completed' THEN 'completed'
         ELSE 'running'
       END
     RETURNING id, status`,
    [key, input.caseId, input.caseNumber || null, input.operationType, input.targetId,
      input.requestedBy || null, input.requestIp || null, JSON.stringify(input.context || {})],
  );
  const operation = operationResult.rows[0];
  for (const [ordinal, item] of input.items.entries()) {
    const identity = itemKey(item);
    await pool.query(
      `INSERT INTO case_deletion_items (operation_id, item_key, ordinal, kind, locator)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (operation_id, item_key) DO NOTHING`,
      [operation.id, identity, ordinal, item.kind, item.locator],
    );
  }
  const itemResult = await pool.query(
    `SELECT item_key, ordinal, kind, locator, status, method, error_code
     FROM case_deletion_items WHERE operation_id = $1 ORDER BY ordinal, id`,
    [operation.id],
  );
  return {
    id: operation.id,
    status: operation.status,
    items: itemResult.rows.length ? itemResult.rows : input.items.map((item, ordinal) => ({ ...item, item_key: itemKey(item), ordinal, status: 'pending' })),
  };
}

async function markDeletionItem(pool, operationId, identity, status, method = null, errorCode = null) {
  const result = await pool.query(
    `UPDATE case_deletion_items
     SET status = $3, method = $4, error_code = $5, updated_at = NOW()
     WHERE operation_id = $1 AND item_key = $2`,
    [operationId, identity, status, method, errorCode],
  );
  if (result.rowCount !== 1) {
    throw Object.assign(new Error('Deletion journal update failed'), { code: 'DELETION_JOURNAL_FAILED' });
  }
}

async function findCompletedDeletionOperation(pool, input) {
  const values = [input.operationType, input.targetId];
  let requester = '';
  if (input.requestedBy != null) {
    values.push(input.requestedBy);
    requester = ` AND requested_by = $${values.length}`;
  }
  const result = await pool.query(
    `SELECT id, case_id, case_number, context
     FROM case_deletion_operations
     WHERE operation_type = $1 AND target_id = $2 AND status = 'completed'${requester}
     ORDER BY completed_at DESC NULLS LAST, created_at DESC LIMIT 1`,
    values,
  );
  return result.rows[0] || null;
}

async function markDeletionOperation(pool, operationId, status, errorCode = null, context = null) {
  const result = await pool.query(
    `UPDATE case_deletion_operations
     SET status = $2, error_code = $3,
         context = CASE WHEN $4::jsonb IS NULL THEN context ELSE context || $4::jsonb END,
         updated_at = NOW(), completed_at = CASE WHEN $2 = 'completed' THEN NOW() ELSE completed_at END
     WHERE id = $1`,
    [operationId, status, errorCode, context == null ? null : JSON.stringify(context)],
  );
  if (result.rowCount !== 1) {
    throw Object.assign(new Error('Deletion journal update failed'), { code: 'DELETION_JOURNAL_FAILED' });
  }
}

module.exports = {
  withCaseDeletion,
  beginDeletionOperation,
  markDeletionItem,
  markDeletionOperation,
  findCompletedDeletionOperation,
  safeErrorCode,
};
