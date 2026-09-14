// Les colonnes sur lesquelles GET /:caseId/timeline accepte de trier.
//
// C'est une frontière de sécurité comme GROUPABLE_COLUMNS : le nom est interpolé
// directement dans le ORDER BY, donc tout ce qui sort de cette liste serait du SQL
// écrit par l'appelant.
//
// C'est aussi un contrat avec le front. Le 2026-09-14, quatre copies de cette
// liste coexistaient — trois côté frontend à quatre entrées, celle-ci à cinq — et
// la divergence avait déjà mordu : `artifact_name`, où atterrit l'identifiant
// syslog du journal, était triable ici sans que le front l'envoie jamais.
//
// Ce qui rend l'écart invisible : la route replie SILENCIEUSEMENT sur `timestamp`
// toute colonne absente d'ici, et le front trie alors la page côté client. Le tri
// paraît fonctionner, alors qu'il ne porte que sur les 500 lignes chargées d'un
// total de six millions. Un test du frontend lit ce fichier et refuse la
// divergence — c'est le seul garde-fou possible entre deux bases de code.
// Élargie le 2026-09-14 à toutes les colonnes réelles de la grille, `detections`
// exclue parce qu'un ORDER BY sur du JSON ne veut rien dire pour un analyste.
//
// Avant, les huit autres n'étaient triées que sur les 500 lignes chargées : la
// route repliait silencieusement sur `timestamp` et le front réordonnait la page.
// Le tri paraissait porter sur six millions de lignes.
//
// Coût mesuré : ~4 s par page pour toute colonne autre que `timestamp`, indexée ou
// non — les index de type (case_id, host_name) sont partiels et ne servent pas un
// tri `NULLS LAST`. Un tri lent mais juste vaut mieux qu'un tri instantané et faux.
//
// Les colonnes dynamiques d'une vue « artefact seul » restent hors de cette liste :
// elles vivent dans `raw` et n'ont pas de colonne à ordonner.
export const SORTABLE_COLUMNS: ReadonlySet<string> = new Set([
  'timestamp',
  'artifact_type',
  'artifact_name',
  'description',
  'source',
  'timestamp_kind',
  'tool',
  'event_id',
  'ext',
  'host_name',
  'user_name',
  'process_name',
  'mitre_technique_id',
]);
