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
export const SORTABLE_COLUMNS: ReadonlySet<string> = new Set([
  'timestamp',
  'artifact_type',
  'artifact_name',
  'description',
  'source',
]);
