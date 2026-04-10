-- ══════════════════════════════════════════════════════════════════════
-- Migration v2.18 — Isolation des collectes : colonne evidence_id
--
-- Objectif : garantir l'étanchéité absolue entre collectes d'un même cas.
-- Chaque ligne de collection_timeline est désormais liée à l'entrée
-- evidence qui l'a générée via une FK stable (evidence.id).
--
-- IMPORTANT : les lignes existantes conservent evidence_id = NULL jusqu'à
-- qu'elles soient re-parsées. Les requêtes filtrées par evidence_id ne
-- renverront ces lignes que lorsqu'elles auront été réingérées avec le
-- nouveau pipeline.
-- ══════════════════════════════════════════════════════════════════════

ALTER TABLE collection_timeline
  ADD COLUMN IF NOT EXISTS evidence_id UUID REFERENCES evidence(id) ON DELETE CASCADE;

-- Index isolé pour GET /timeline?evidence_id=<uuid>
CREATE INDEX IF NOT EXISTS idx_ct_evidence
  ON collection_timeline(evidence_id);

-- Index composite pour les requêtes de timeline filtrées par collecte + temps
CREATE INDEX IF NOT EXISTS idx_ct_case_ev_ts
  ON collection_timeline(case_id, evidence_id, timestamp);
