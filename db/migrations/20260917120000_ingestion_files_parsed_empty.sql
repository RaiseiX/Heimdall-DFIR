-- db/migrations/20260917120000_ingestion_files_parsed_empty.sql
-- Un quatrieme sort pour un fichier non vide.
--
-- Le ledger en reglait trois : il a produit des lignes (`parsed`), son parseur a
-- echoue (`error`), personne ne l a reclame (`unsupported`). Un artefact que le
-- produit connait, que son parseur a bien lu, et qui ne contenait aucun evenement
-- tombait dans le troisieme — le seul qui affirme une lacune de couverture.
--
-- Mesure sur la collecte de reference (2026-09-15), 4 fichiers sur les 59 classes
-- `unsupported` hors journaux :
--   Logs/last-btmp.txt                      60 o   `btmp begins ...` et rien d autre
--   Podman/podman-image-ls-all.txt          53 o   un en-tete de tableau, zero image
--   Podman/podman-container-ls-all-size.txt 91 o   idem, zero conteneur
--   Persistence/cron-folder.tar.gz         162 o   une archive vide
--
-- Le cas btmp est celui qui coute : zero echec d authentification est une
-- observation forensique, pas un trou dans la lecture. Les deux lectures menent a
-- des conclusions opposees, et `unsupported` imposait la mauvaise.
--
-- `empty` ne couvre pas ce cas : il est pose a l enregistrement, sur les fichiers
-- de zero octet exactement, et n est jamais revisite (catscaleCoverage.ts:86).
--
-- Idempotent : DROP ... IF EXISTS puis ADD, comme
-- 20260814090000_ingestion_files_coverage_status.sql dont ceci etend la liste.
ALTER TABLE ingestion_files DROP CONSTRAINT IF EXISTS ingestion_files_status_check;
ALTER TABLE ingestion_files ADD CONSTRAINT ingestion_files_status_check CHECK (status IN (
  'received','extracting','classified','queued','parsing',
  'parsed','empty','degraded','error','quarantined','skipped_duplicate',
  'unsupported','archive_expanded','parsed_empty'));
