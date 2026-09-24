const express = require('express');
const { pool } = require('../config/database');
const { authenticate } = require('../middleware/auth');
const { canAccessCase } = require('../middleware/caseAccess');
const { apercuSuppression } = require('../services/evidenceDeletionPreview');
const esService = require('../services/elasticsearchService');
const logger = require('../config/logger').default;

const router = express.Router();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function compterIndex(caseId, resultIds) {
  if (!resultIds.length) return 0;
  const reponse = await esService.rawSearch(caseId, {
    size: 0, track_total_hits: true, query: { terms: { result_id: resultIds } },
  });
  const total = reponse?.hits?.total;
  return typeof total === 'number' ? total : (total?.value ?? null);
}

router.get('/:id/deletion-preview', authenticate, async (req, res) => {
  const { id } = req.params;
  if (!UUID.test(id)) return res.status(400).json({ error: 'Identifiant invalide' });
  try {
    const parent = await pool.query('SELECT case_id FROM evidence WHERE id = $1', [id]);
    if (!parent.rows.length) return res.status(404).json({ error: 'Preuve introuvable' });
    if (!await canAccessCase(req.user, parent.rows[0].case_id)) {
      return res.status(403).json({ error: 'Accès refusé : ce cas ne vous est pas attribué.' });
    }
    const apercu = await apercuSuppression(pool, id, { compterIndex });
    if (!apercu) return res.status(404).json({ error: 'Preuve introuvable' });
    return res.json(apercu);
  } catch (err) {
    logger.warn(`[evidence] apercu de suppression indisponible : ${err.message}`);
    return res.status(503).json({ error: 'Aperçu indisponible' });
  }
});

module.exports = router;
module.exports.compterIndex = compterIndex;
