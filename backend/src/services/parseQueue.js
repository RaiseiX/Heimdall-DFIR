const MAX_TENTATIVES = 3;

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS parse_queue (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  case_id      UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  result_id    UUID NOT NULL REFERENCES parser_results(id) ON DELETE CASCADE,
  status       TEXT NOT NULL DEFAULT 'queued'
    CONSTRAINT parse_queue_status_check CHECK (status IN ('queued', 'running', 'done', 'error')),
  attempts     INTEGER NOT NULL DEFAULT 0,
  payload      JSONB NOT NULL,
  error        TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  started_at   TIMESTAMPTZ,
  finished_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_parse_queue_pending
  ON parse_queue (created_at, id) WHERE status IN ('queued', 'running');
`;

const COLONNES = ['id', 'case_id', 'result_id', 'status', 'attempts', 'payload', 'error', 'created_at', 'started_at', 'finished_at'];

async function inscrire(db, { caseId, resultId, payload }) {
  const { rows } = await db.query(
    `INSERT INTO parse_queue (case_id, result_id, payload) VALUES ($1, $2, $3::jsonb) RETURNING id`,
    [caseId, resultId, JSON.stringify(payload)]);
  return rows[0].id;
}

async function demarrer(db, id) {
  await db.query(
    `UPDATE parse_queue SET status = 'running', attempts = attempts + 1, started_at = NOW() WHERE id = $1`,
    [id]);
}

async function terminer(db, id, statut, erreur = null) {
  await db.query(
    `UPDATE parse_queue SET status = $2, error = $3, finished_at = NOW() WHERE id = $1`,
    [id, statut, erreur]);
}

async function aReprendre(db) {
  const { rows } = await db.query(
    `SELECT q.id, q.case_id, q.result_id, q.status, q.attempts, q.payload,
            (pr.output_data ? 'parse_results') AS resultat_ecrit
       FROM parse_queue q
       JOIN parser_results pr ON pr.id = q.result_id
      WHERE q.status IN ('queued', 'running')
      ORDER BY q.created_at, q.id`);
  return rows;
}

function contexteDeReprise(ligne) {
  const { socketId: _socketMorte, ...charge } = ligne.payload || {};
  return {
    ...charge,
    caseId: ligne.case_id,
    resultId: ligne.result_id,
    socketId: `user:${charge.userId}`,
  };
}

async function reprendreParsings({ aReprendre: lire, terminer: clore, purger, lancer, relancerDetection, existe, maxTentatives = MAX_TENTATIVES, logger = console }) {
  const lignes = await lire();
  logger.info(`[parse-queue] reprise au demarrage : ${lignes.length} parsing(s) en file`);
  const cloreSansBloquer = async (id, statut, erreur) => {
    try { await clore(id, statut, erreur); } catch (e) { logger.error(`[parse-queue] cloture ${id} impossible : ${e.message}`); }
  };

  for (const ligne of lignes) {
    const interrompu = ligne.status === 'running';

    if (ligne.resultat_ecrit) {
      await cloreSansBloquer(ligne.id, 'done');
      try { relancerDetection(ligne); } catch (e) { logger.error(`[parse-queue] detection ${ligne.id} : ${e.message}`); }
      continue;
    }

    if (interrompu && ligne.attempts >= maxTentatives) {
      await cloreSansBloquer(ligne.id, 'error', `Parsing interrompu ${ligne.attempts} fois (plafond ${maxTentatives}) : abandonne`);
      continue;
    }

    const collDir = ligne.payload?.collDir;
    if (!collDir || !existe(collDir)) {
      await cloreSansBloquer(ligne.id, 'error', `Collecte introuvable sur le disque : ${collDir}`);
      continue;
    }

    if (interrompu) {
      try {
        await purger(ligne);
      } catch (e) {
        await cloreSansBloquer(ligne.id, 'error', `Purge avant reprise impossible${e.code ? ` (${e.code})` : ''} : ${e.message}`);
        continue;
      }
    }

    lancer(ligne);
  }
}

module.exports = { MAX_TENTATIVES, SCHEMA_SQL, COLONNES, inscrire, demarrer, terminer, aReprendre, contexteDeReprise, reprendreParsings };
