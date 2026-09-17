// Le filtre sur l'empreinte SHA-1, qui rend possible le pivot depuis la carte
// des processus vers la SuperTimeline.
//
// ── Pourquoi le pivot ne pouvait pas passer par `search` ────────────────────
//
// Mesure du 2026-09-17 : 226 696 lignes du cas de reference portent un `sha1`.
// Or `buildSearchFilter` ne regarde que `description`, `source` et
// `artifact_type`. Un pivot `?search=<sha1>` aurait rendu ZERO ligne alors que
// 226 696 en portent une, et l'analyste aurait conclu que le binaire
// n'apparait nulle part ailleurs. Un pivot muet est pire qu'un pivot absent.
//
// Verifie : l'empreinte de Firefox est portee par 91 lignes de ce cas.
//
// ── Pourquoi l'egalite stricte ──────────────────────────────────────────────
//
// Mesure du 2026-09-17, cas de reference, index idx_ct_case_sha1 :
//
//   sha1 = '4d7f…'        ->  2,6 ms   Index Scan
//   sha1 ILIKE '4d7f…'    -> 75,7 ms   index inutilisable
//   lower(sha1) = lower() -> 63,9 ms   index inutilisable
//
// Les 227 684 empreintes stockees sont deja TOUTES en minuscules (zero
// exception). Abaisser la casse du PARAMETRE conserve donc la tolerance a la
// saisie sans toucher a la colonne, et garde l'index.
//
// Note pour plus tard : `buildTextFilter` produit `ILIKE` pour son `equals`.
// Les colonnes `tool`, `host_name`, `user_name` et `ext` ont chacune un index
// btree que leur filtre « egal » n'utilise donc pas non plus.

import { VALID_TEXT_OPS } from '../utils/textFilter';

const PRESENT = 'sha1 IS NOT NULL';

export function buildHashFilter(
  value: string,
  op: string,
): { sql: string; param: string | null } {
  const safeOp = VALID_TEXT_OPS.has(op) ? op : 'equals';
  const bas = String(value ?? '').trim().toLowerCase();

  switch (safeOp) {
    // La negation exige la presence : 3 034 230 lignes CatScale n'ont pas
    // d'empreinte, et « different de X » ne doit pas les deverser.
    case 'not_equals':
      return { sql: `(${PRESENT} AND sha1 <> $N)`, param: bas };

    case 'empty':
      return { sql: 'sha1 IS NULL', param: null };

    case 'not_empty':
      return { sql: PRESENT, param: null };

    // Coller les douze premiers caracteres lus dans un rapport est un usage
    // reel. Un prefixe reste servi par l'index btree ; une sous-chaine, non.
    case 'starts_with':
      return { sql: 'sha1 LIKE $N', param: bas.replace(/[%_]/g, '\\$&') + '%' };

    default:
      return { sql: 'sha1 = $N', param: bas };
  }
}

export function pushHashFilter(
  value: string,
  op: string,
  pi: number,
  conditions: string[],
  params: unknown[],
): number {
  const { sql, param } = buildHashFilter(value, op);
  if (param !== null) {
    conditions.push(sql.replace(/\$N/g, `$${pi}`));
    params.push(param);
    return pi + 1;
  }
  conditions.push(sql);
  return pi;
}
