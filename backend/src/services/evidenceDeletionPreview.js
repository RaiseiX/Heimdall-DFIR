const { planEvidenceDeletion } = require('./evidenceDeletionPlan');

const DELAI_MS = 15000;

const entier = v => (v == null ? null : Number(v));

function nombreDeCibles(preuve, resultats) {
  try {
    return planEvidenceDeletion(preuve).length + resultats;
  } catch (_e) {
    return null;
  }
}

async function apercuSuppression(pool, evidenceId, { compterIndex, delaiMs = DELAI_MS } = {}) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    await client.query(`SET LOCAL statement_timeout = ${Number(delaiMs)}`);

    const { rows: [preuve] } = await client.query(
      `SELECT e.id, e.case_id, e.name, e.original_filename, e.file_path, e.file_size, e.evidence_type,
              e.hash_sha256, e.additional_files, e.volweb_evidence_id, e.created_at,
              c.case_number, c.legal_hold
         FROM evidence e JOIN cases c ON c.id = e.case_id
        WHERE e.id = $1`, [evidenceId]);
    if (!preuve) {
      await client.query('COMMIT');
      return null;
    }

    const { rows: [lignes] } = await client.query(
      `SELECT count(*) AS lignes,
              count(*) FILTER (WHERE jsonb_typeof(detections) = 'array' AND jsonb_array_length(detections) > 0) AS detections,
              count(*) FILTER (WHERE cardinality(tags) > 0) AS etiquetees
         FROM collection_timeline WHERE evidence_id = $1`, [evidenceId]);
    const { rows: resultats } = await client.query(
      `SELECT id, parser_name, record_count FROM parser_results WHERE evidence_id = $1 ORDER BY parser_name, id`, [evidenceId]);
    const { rows: [autres] } = await client.query(
      `SELECT (SELECT count(*) FROM yara_scan_results WHERE evidence_id = $1) AS yara,
              (SELECT count(*) FROM timeline_pins WHERE evidence_id = $1) AS epingles,
              (SELECT count(*) FROM evidence_comments WHERE evidence_id = $1) AS commentaires,
              (SELECT count(*) FROM network_connections WHERE evidence_id = $1) AS connexions,
              (SELECT count(*) FROM timeline_bookmarks WHERE case_id = $2) AS favoris,
              (SELECT count(*) FROM hunt_verdicts WHERE case_id = $2) AS verdicts`, [evidenceId, preuve.case_id]);
    await client.query('COMMIT');

    let indexDocs = null;
    try {
      indexDocs = entier(await compterIndex(preuve.case_id, resultats.map(r => String(r.id))));
    } catch (_e) {
      indexDocs = null;
    }

    return {
      preuve: {
        id: preuve.id,
        nom: preuve.original_filename || preuve.name,
        sha256: preuve.hash_sha256 || null,
        importee_le: preuve.created_at ? new Date(preuve.created_at).toISOString() : null,
        affaire: preuve.case_number || null,
        scelle: preuve.legal_hold === true,
        memoire: String(preuve.evidence_type || '').toLowerCase() === 'memory' || preuve.volweb_evidence_id != null,
      },
      supprime: {
        disque_octets: entier(preuve.file_size),
        lignes: entier(lignes.lignes),
        detections: entier(lignes.detections),
        etiquetees: entier(lignes.etiquetees),
        index_docs: indexDocs,
        resultats: resultats.map(r => ({ nom: r.parser_name, lignes: entier(r.record_count) })),
        yara: entier(autres.yara),
        epingles: entier(autres.epingles),
        commentaires: entier(autres.commentaires),
        connexions: entier(autres.connexions),
      },
      conserve: {
        cibles: nombreDeCibles(preuve, resultats.length),
        favoris: entier(autres.favoris),
        verdicts: entier(autres.verdicts),
      },
    };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { apercuSuppression };
