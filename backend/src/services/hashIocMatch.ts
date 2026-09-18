// Confronter les empreintes de la collecte aux indicateurs du dossier.
//
// ── Ce qui manquait ─────────────────────────────────────────────────────────
//
// Mesure du 2026-09-18 : la base porte 58 692 empreintes SHA-1 distinctes, et
// l'index `idx_ct_case_sha1` les sert. `iocEnrichmentService.ts` sait traiter
// md5, sha1 et sha256 ; `iocs.js` sait produire des motifs STIX
// `file:hashes.'SHA-1'`. Les deux moities existaient, rien ne les reliait.
//
// L'analyste lisait une empreinte et devait la porter ailleurs pour en tirer
// un avis. La question DFIR n'est pourtant pas « quel est le hachage » mais
// « ce binaire devrait-il etre la ».
//
// ── Le piege qui donne sa forme au service ──────────────────────────────────
//
// La collecte ne porte QUE du SHA-1. Mesure du 2026-09-18 sur le dossier de
// reference : 226 696 lignes hachees, **zero** `sha256` et **zero** `md5`, ni
// en colonne ni dans `raw`.
//
// Un analyste qui charge des indicateurs SHA-256 — le format le plus repandu
// des flux de renseignement — obtiendrait zero correspondance et conclurait
// « rien ne correspond ». La verite est « nous ne savons pas comparer ».
//
// D'ou deux requetes et non une : les correspondances, ET le compte de ce que
// le service est structurellement incapable de comparer. Un zero qui ne
// s'explique pas est un mensonge par omission — meme famille que la facette
// tronquee en silence ou le pivot qui rendait zero.

/** Les types d'indicateur que la collecte sait comparer aujourd'hui. */
export const HASH_TYPES_COMPARABLES = ['hash_sha1'] as const;

/** Ceux qu'elle porte en base mais ne peut confronter a aucune donnee. */
export const HASH_TYPES_INCOMPARABLES = ['hash_md5', 'hash_sha256'] as const;

/**
 * Une empreinte par ligne, avec son nombre d'occurrences dans la collecte et un
 * exemple de chemin. L'egalite se fait sur la valeur mise en minuscules et
 * rognee : les empreintes stockees le sont toutes (mesure : 227 684 sur
 * 227 684), mais un indicateur saisi a la main ou importe ne l'est pas.
 */
export function hashIocMatchSql(): string {
  return `
    SELECT ct.sha1,
           count(*)::int                      AS occurrences,
           min(ct.description)                AS sample,
           max(i.severity)                    AS severity,
           bool_or(i.is_malicious)            AS is_malicious,
           min(i.description)                 AS ioc_description
      FROM collection_timeline ct
      JOIN iocs i
        ON i.case_id = ct.case_id
       AND i.ioc_type::text = 'hash_sha1'
       AND lower(btrim(i.value)) = ct.sha1
     WHERE ct.case_id = $1
       AND ct.sha1 IS NOT NULL
     GROUP BY ct.sha1
     ORDER BY count(*) DESC, ct.sha1`;
}

/**
 * Les indicateurs de hachage que la collecte ne peut pas confronter, par type.
 * Sert a expliquer un zero au lieu de le laisser parler tout seul.
 */
export function unmatchableIocsSql(): string {
  return `
    SELECT i.ioc_type::text AS ioc_type, count(*)::int AS total
      FROM iocs i
     WHERE i.case_id = $1
       AND i.ioc_type::text IN (${HASH_TYPES_INCOMPARABLES.map(t => `'${t}'`).join(', ')})
     GROUP BY i.ioc_type
     ORDER BY count(*) DESC`;
}
