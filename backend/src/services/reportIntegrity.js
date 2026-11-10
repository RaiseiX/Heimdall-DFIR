const ACTION = 'evidence_integrity_check';
const SHA256_HEX = /^[0-9a-fA-F]{64}$/;

async function latestIntegrityChecks(db, evidenceIds) {
  const out = new Map();
  const ids = Array.isArray(evidenceIds) ? evidenceIds.map(String) : [];
  if (ids.length === 0) return out;
  const { rows } = await db.query(
    `SELECT DISTINCT ON (entity_id) entity_id::text AS evidence_id, details->>'status' AS status, created_at
       FROM audit_log
      WHERE action = $1 AND entity_type = 'evidence' AND entity_id = ANY($2::uuid[])
      ORDER BY entity_id, created_at DESC, seq DESC`,
    [ACTION, ids],
  );
  for (const r of rows) out.set(String(r.evidence_id), { status: r.status, checked_at: r.created_at });
  return out;
}

function formatUtcDay(value) {
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  const jj = String(d.getUTCDate()).padStart(2, '0');
  const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
  return `${jj}/${mm}/${d.getUTCFullYear()}`;
}

function integrityLabel(evidence, check) {
  const hash = evidence && evidence.hash_sha256;
  if (typeof hash !== 'string' || !SHA256_HEX.test(hash)) {
    return { text: 'Aucune empreinte SHA-256 enregistrée', tone: 'warn' };
  }
  if (!check || !check.status) {
    return { text: "Empreinte enregistrée, non vérifiée depuis l'acquisition", tone: 'neutral' };
  }
  const day = formatUtcDay(check.checked_at);
  switch (check.status) {
    case 'ok':
      return { text: `Empreinte vérifiée le ${day}`, tone: 'ok' };
    case 'mismatch':
      return { text: `Empreinte non concordante (contrôle du ${day})`, tone: 'alert' };
    case 'source_not_preserved':
      return { text: `Original non conservé (contrôle du ${day})`, tone: 'warn' };
    case 'missing':
    case 'no_stored_file':
      return { text: `Fichier absent (contrôle du ${day})`, tone: 'warn' };
    case 'skipped':
      return { text: `Non contrôlée : stockage objet (contrôle du ${day})`, tone: 'neutral' };
    default:
      return { text: `Contrôle impossible (contrôle du ${day})`, tone: 'warn' };
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
  if (alert) parts.push(`${alert} non concordante(s)`);
  if (warn) parts.push(`${warn} non vérifiable(s)`);
  if (neutral) parts.push(`${neutral} non contrôlée(s)`);
  if (parts.length === 0) return 'Aucun contrôle d\'empreinte à signaler.';
  return `Contrôle des empreintes : ${parts.join(', ')}.`;
}

module.exports = { latestIntegrityChecks, integrityLabel, integritySummary };
