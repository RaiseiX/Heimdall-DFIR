-- L'onglet « Processus » d'une collecte lit deux choses dans collection_timeline :
-- le compte de fichiers tenus par chaque processus, et la liste des fichiers
-- supprimés que PLUSIEURS processus tiennent encore ouverts.
--
-- Mesuré le 2026-09-15 sur l'hôte de référence, 4,3 M de lignes, table à 18 Go :
--
--   ressources partagées   3 231 ms  ->  860 ms   (x3,8)
--   arbre des processus    4 819 ms  ->  inchangé
--
-- L'index sert la première parce qu'elle ne retient que les lignes `deleted` :
-- 3 741 sur 89 582. Il ne sert pas la seconde, qui doit lire les 89 582 pour
-- compter — et ce coût est intrinsèque.
--
-- Pourquoi pas un parcours sans lecture du tas : les colonnes d'expression y
-- sont toutes présentes et la carte de visibilité est à 99,3 %, mais Postgres
-- refuse l'Index Only Scan même en pénalisant tous les autres parcours. Un index
-- d'expression ne rend pas la colonne `raw` disponible. Vérifié, pas supposé.
--
-- 89 582 lignes concernées tous dossiers confondus, pour 768 ko d'index.
--
-- CONCURRENTLY parce que la table est en production : la construction a attendu
-- 12 minutes derrière un SELECT de chasse de 43 minutes, sans bloquer personne.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ct_proc_files
    ON collection_timeline (case_id, evidence_id, artifact_type,
                            ((raw->>'pid')), ((raw->>'deleted')))
 WHERE artifact_type IN ('catscale_proc_open_fd', 'catscale_proc_mapped_file');
