// Relève les clés de `raw` présentes pour un type d'artefact dans un dossier.
//
// La grille construit les colonnes d'un artefact isolé depuis ces clés. Elle ne
// voyait que la page chargée, ce qui suffit pour un artefact homogène et rate
// presque tout sur un artefact hétérogène. Mesuré le 2026-09-14 :
//
//   catscale_journal  159 clés réelles,  42 vues par le front  → 117 absentes
//   evtx               29 clés réelles,   6 vues               →  23 absentes
//   prefetch           21 clés réelles,   6 vues               →  15 absentes
//   mft, registry, hayabusa, amcache : rien ne manquait — leurs lignes portent
//   toutes les mêmes champs.
//
// Le coût d'un relevé exhaustif dépend entièrement du volume, mesuré aussi :
//
//   scan intégral, catscale_journal (1 820 858 lignes) : 35,8 s → inexploitable
//   scan intégral, evtx               (163 112 lignes) :  1,7 s → et complet
//   TABLESAMPLE 1 %, catscale_journal                  :  0,65 s, 119 clés sur 159
//
// D'où le seuil. En dessous on scanne tout et la réponse est exhaustive ; au-dessus
// on échantillonne et **on le dit**. Une liste partielle présentée comme complète
// serait pire que pas de liste : l'analyste conclurait que le champ n'existe pas.
//
// L'union avec les clés de la page affichée se fait côté client, si bien qu'un
// champ visible à l'écran n'est jamais absent des colonnes, échantillon ou non.

/** Au-delà, le relevé passe en échantillon. evtx (163 112 lignes, 1,7 s) reste
 *  volontairement du côté exhaustif. */
export const FULL_SCAN_MAX_ROWS = 250_000;

/** Proportion échantillonnée au-dessus du seuil. 1 % du journal rend 119 clés sur
 *  159 en 653 ms ; 5 % en rend 129 mais coûte 3,4 s — le gain ne vaut pas le prix. */
export const SAMPLE_PCT = 1;

/** Combien de lignes porte ce type d'artefact — mais seulement assez pour trancher.
 *
 *  Mesuré en production le 2026-09-14 : un `COUNT(*)` exact sur le journal coûte
 *  4 016 ms, la sonde bornée 293 ms. L'endpoint mettait 4,5 s là où le relevé seul
 *  en coûte 0,6 : le compte coûtait plus cher que ce qu'il servait à décider.
 *
 *  Le résultat est exact sous le seuil, et plafonné au-dessus — c'est suffisant,
 *  puisque la seule question est « au-dessus ou en dessous ». La réponse de la
 *  route dit alors `complete: false`, jamais un total faux. */
export function rowCountProbeSql(): string {
  return `SELECT count(*)::int AS n FROM (
            SELECT 1 FROM collection_timeline
             WHERE case_id = $1::uuid AND artifact_type = $2 AND raw IS NOT NULL
             LIMIT ${FULL_SCAN_MAX_ROWS + 1}) x`;
}

export interface RawKeysPlan {
  sql: string;
  complete: boolean;
  /** Proportion réellement balayée, pour que la réponse soit honnête. */
  scannedPct: number;
}

export function rawKeysSql(rowCount: number): RawKeysPlan {
  const n = Number.isFinite(rowCount) ? rowCount : 0;

  if (n <= FULL_SCAN_MAX_ROWS) {
    return {
      complete: true,
      scannedPct: 100,
      sql: `SELECT DISTINCT k AS key
              FROM collection_timeline c, jsonb_object_keys(c.raw) k
             WHERE c.case_id = $1::uuid AND c.artifact_type = $2 AND c.raw IS NOT NULL
             ORDER BY 1`,
    };
  }

  return {
    complete: false,
    scannedPct: SAMPLE_PCT,
    sql: `SELECT DISTINCT k AS key
            FROM collection_timeline c TABLESAMPLE SYSTEM(${SAMPLE_PCT}), jsonb_object_keys(c.raw) k
           WHERE c.case_id = $1::uuid AND c.artifact_type = $2 AND c.raw IS NOT NULL
           ORDER BY 1`,
  };
}
