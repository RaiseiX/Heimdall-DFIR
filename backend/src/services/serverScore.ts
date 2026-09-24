// « Ce noeud recoit-il plus qu'il n'initie ? »
//
// Le score valait > 0 sur 143 noeuds sur 151 — mesure du 2026-08-27 sur CASE-2026-001,
// alors que le seul port de service de toute la collecte est 443. Deux causes, la meme
// erreur : il etait calcule sur des noeuds qui ne peuvent pas etre des machines, et sur
// des degres trop pauvres pour qu'un ratio veuille dire quelque chose.
//
// Une URL n'est jamais un client : elle ne peut qu'etre atteinte, donc son ratio vaut 1
// par construction et ne mesure rien. Sur le cas de reference, cela fabriquait
// 129 « serveurs » a partir d'un historique de navigation. Une collecte n'est pas une
// machine non plus — le code le dit deja ailleurs, « aucun score de role ne doit s'y
// appliquer ».
//
// Et un ratio a besoin d'observations pour etre un ratio. Un noeud vu une seule fois,
// comme destination, rend 1,00 : cela se lit « 100 % serveur » alors que cela dit
// seulement qu'on l'a vu une fois. Une observation unique presentee comme une mesure.
// `null` dit « indisponible » ; « indisponible » se lit, « 1,00 » se croit.

// Ce qui ne peut pas etre une machine ne recoit pas de score de role.
const NOT_A_MACHINE = Object.freeze(new Set(['url', 'domain', 'collection']));

// En deca, une seule observation determine le ratio.
const MIN_OBSERVATIONS = 2;

export interface ScorableNode {
  type?: string | null;
  inDegree?: number | null;
  outDegree?: number | null;
}

// Number(null) vaut 0 : un degre absent se lirait comme un degre nul, et rendrait un
// score la ou il n'y a pas de donnee.
function degree(v: unknown): number | null {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? Math.trunc(n) : null;
}

export function serverScore(node: ScorableNode | null | undefined): number | null {
  if (!node) return null;
  if (NOT_A_MACHINE.has(String(node.type ?? ''))) return null;

  const inDeg = degree(node.inDegree);
  const outDeg = degree(node.outDegree);
  if (inDeg === null || outDeg === null) return null;

  const total = inDeg + outDeg;
  if (total < MIN_OBSERVATIONS) return null;

  return Math.round((inDeg / total) * 100) / 100;
}
