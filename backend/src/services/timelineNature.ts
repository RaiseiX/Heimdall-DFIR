// La SuperTimeline mele deux natures de lignes : la chronologie, faite d'evenements
// horodates, et l'inventaire, fait d'objets d'etat projetes depuis catscale_state et
// qui n'ont pas d'horodatage. Sur la collecte Linux de reference, 872 414 des
// 1 213 366 lignes sont de l'inventaire — les deux natures dans une meme liste triee
// par date se lisent mal ensemble.
//
// Deux regles tiennent ce filtre.
//
// D'abord il s'applique aux lignes rendues, jamais au comptage. `countSql` continue
// de rendre `total` et `undated` sur le perimetre complet, donc l'ecran peut toujours
// dire combien de lignes porte la nature qu'il n'affiche pas. Un segment qui masque
// une nature sans annoncer son volume transformerait un filtre en absence de donnees.
//
// Ensuite la valeur du client ne traverse pas la fonction : elle sert de cle dans un
// vocabulaire ferme. Rien de ce qu'un appelant envoie n'est concatene au SQL.

const NATURE_PREDICATE: Readonly<Record<string, string>> = Object.freeze({
  dated:   'timestamp IS NOT NULL',
  undated: 'timestamp IS NULL',
});

export const NATURE_VALUES: ReadonlySet<string> = new Set(Object.keys(NATURE_PREDICATE));

export function natureScopedWhere(where: string, nature: string | null | undefined): string {
  const key = String(nature ?? '').toLowerCase();
  const predicate = Object.prototype.hasOwnProperty.call(NATURE_PREDICATE, key)
    ? NATURE_PREDICATE[key]
    : null;
  return predicate ? `${where} AND ${predicate}` : where;
}
