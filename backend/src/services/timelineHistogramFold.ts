// Repli des lignes rendues par la requete unique de l'histogramme.
//
// La requete classe chaque ligne datee du cas en trois familles : sous la borne
// basse, au-dessus de la borne haute, ou dans un seau de 1 a N. Elle remplace deux
// balayages de 2,1 M lignes par un seul — le comptage par seau et le comptage des
// hors-bornes lisaient exactement le meme ensemble.
//
// Les sentinelles sont negatives pour qu'aucune ne puisse se confondre avec un seau
// valide, et pour que le seau 0 — que `width_bucket` rendrait pour une valeur sous la
// borne — reste une valeur invalide qu'on ignore plutot qu'une valeur qu'on compte.

export const BKT_BEFORE_LO = -1;
export const BKT_AFTER_HI = -2;

export interface HistogramRow {
  bkt: number | string | null | undefined;
  n: number | string | null | undefined;
}

export interface HistogramFold {
  buckets: number[];
  before_lo: number;
  after_hi: number;
}

// Number(null) vaut 0 et Number(undefined) vaut NaN : un seau absent deviendrait le
// seau 0 et son compte s'ajouterait a la barre. On exige un entier fini et rien
// d'autre — une ligne qu'on ne sait pas placer est ecartee, jamais rangee au hasard.
function asInt(v: number | string | null | undefined): number | null {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

export function foldHistogramRows(rows: readonly HistogramRow[], n: number): HistogramFold {
  const size = Math.max(0, Math.trunc(n) || 0);
  const buckets = new Array<number>(size).fill(0);
  let before_lo = 0;
  let after_hi = 0;

  for (const row of rows) {
    const bkt = asInt(row?.bkt);
    const count = asInt(row?.n);
    if (bkt === null || count === null) continue;

    if (bkt === BKT_BEFORE_LO) { before_lo += count; continue; }
    if (bkt === BKT_AFTER_HI) { after_hi += count; continue; }

    const i = bkt - 1;
    if (i >= 0 && i < size) buckets[i] += count;
  }

  return { buckets, before_lo, after_hi };
}
