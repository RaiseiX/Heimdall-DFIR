const ACTION = 'evidence_integrity_check';
const SHA256_HEX = /^[0-9a-fA-F]{64}$/;
const PAST_GAP_RESULT = {
  ok: 'concordant',
  source_not_preserved: 'original non conservé',
  missing: 'fichier absent',
  no_stored_file: 'fichier absent',
  skipped: 'stockage objet',
};

async function latestIntegrityChecks(db, evidenceIds) {
  const out = new Map();
  const ids = Array.isArray(evidenceIds) ? evidenceIds.map(String) : [];
  if (ids.length === 0) return out;
  const { rows } = await db.query(
    `SELECT DISTINCT ON (entity_id) entity_id::text AS evidence_id, details->>'status' AS status,
            details->>'expected_sha256' AS expected_sha256, created_at
       FROM audit_log
      WHERE action = $1 AND entity_type = 'evidence' AND entity_id = ANY($2::uuid[])
      ORDER BY entity_id, created_at DESC, seq DESC`,
    [ACTION, ids],
  );
  for (const r of rows) {
    out.set(String(r.evidence_id), {
      status: r.status,
      checked_at: r.created_at,
      expected_sha256: r.expected_sha256 ?? null,
      last_mismatch_at: null,
    });
  }
  if (out.size === 0) return out;

  const gaps = await db.query(
    `SELECT entity_id::text AS evidence_id, MAX(created_at) AS created_at
       FROM audit_log
      WHERE action = $1 AND entity_type = 'evidence' AND entity_id = ANY($2::uuid[])
        AND details->>'status' = 'mismatch'
      GROUP BY entity_id`,
    [ACTION, ids],
  );
  for (const r of gaps.rows) {
    const entry = out.get(String(r.evidence_id));
    if (entry) entry.last_mismatch_at = r.created_at;
  }
  return out;
}

function formatUtcDateTime(value) {
  if (value == null) return '—';
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  const jj = String(d.getUTCDate()).padStart(2, '0');
  const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mi = String(d.getUTCMinutes()).padStart(2, '0');
  return `${jj}/${mm}/${d.getUTCFullYear()} ${hh}:${mi} UTC`;
}

function isStaleCheck(hash, check) {
  const expected = check.expected_sha256;
  if (typeof expected !== 'string' || !SHA256_HEX.test(expected)) return false;
  return expected.toLowerCase() !== hash.toLowerCase();
}

function integrityLabel(evidence, check) {
  const hash = evidence && evidence.hash_sha256;
  if (typeof hash !== 'string' || !SHA256_HEX.test(hash)) {
    return { text: 'Aucune empreinte SHA-256 enregistrée', tone: 'warn' };
  }
  if (!check || !check.status) {
    return { text: "Empreinte enregistrée, non vérifiée depuis l'acquisition", tone: 'neutral' };
  }
  const when = formatUtcDateTime(check.checked_at);
  if (check.status !== 'mismatch' && check.last_mismatch_at) {
    return {
      text: `Écart constaté le ${formatUtcDateTime(check.last_mismatch_at)} ; dernier contrôle le ${when} : ${PAST_GAP_RESULT[check.status] || 'contrôle impossible'}`,
      tone: 'alert',
    };
  }
  if (check.status !== 'mismatch' && isStaleCheck(hash, check)) {
    return { text: `Contrôle périmé : l'empreinte enregistrée a changé depuis le contrôle du ${when}`, tone: 'warn' };
  }
  switch (check.status) {
    case 'ok':
      return { text: `Empreinte vérifiée le ${when}`, tone: 'ok' };
    case 'mismatch':
      return { text: `Empreinte non concordante (contrôle du ${when})`, tone: 'alert' };
    case 'source_not_preserved':
      return { text: `Original non conservé (contrôle du ${when})`, tone: 'warn' };
    case 'missing':
    case 'no_stored_file':
      return { text: `Fichier absent (contrôle du ${when})`, tone: 'warn' };
    case 'skipped':
      return { text: `Non contrôlée : stockage objet (contrôle du ${when})`, tone: 'neutral' };
    default:
      return { text: `Contrôle impossible (contrôle du ${when})`, tone: 'warn' };
  }
}

function integritySummary(items) {
  const list = Array.isArray(items) ? items : [];
  const count = (tone) => list.filter((i) => i && i.tone === tone).length;
  const parts = [];
  const ok = count('ok');
  const alert = count('alert');
  const warn = count('warn');
  const neutral = count('neutral');
  if (ok) parts.push(`${ok} empreinte(s) concordante(s)`);
  if (alert) parts.push(`${alert} avec écart constaté`);
  if (warn) parts.push(`${warn} non vérifiable(s)`);
  if (neutral) parts.push(`${neutral} non contrôlée(s)`);
  if (parts.length === 0) return 'Aucun contrôle d\'empreinte à signaler.';
  return `Contrôle des empreintes : ${parts.join(', ')}.`;
}

module.exports = { latestIntegrityChecks, integrityLabel, integritySummary, formatUtcDateTime };
