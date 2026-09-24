// Le contexte temporel de chaque hote d'un dossier : sait-on a quelle heure
// ses evenements sont ancres ?
//
// ── Ce qui existait deja ────────────────────────────────────────────────────
//
// CatScale collecte `System_Info/host-date-timezone`, le registre le declare
// (`kind: 'host_time'`), et `hostUtcOffset()` en tire un decalage qui alimente
// `SpecContext.hostOffset`. Ce decalage sert deja a `dmesg -T` et a `last`,
// dont les horodatages sont en heure locale sans decalage. Le registre dit
// pourquoi : « defaulting to UTC would shift every event on a European host by
// two hours — a plausible-looking timeline that is wrong everywhere ».
//
// La partie difficile etait donc faite, et je l'avais annoncee absente a tort.
//
// ── Ce qui manquait ─────────────────────────────────────────────────────────
//
// Ce decalage n'etait **jamais montre**. Mesure du 2026-09-18 : 9 hotes dans la
// base, **un seul** porte `catscale_host_time`. Les trois hotes Windows n'en
// ont pas — `host-date-timezone` est un artefact CatScale, donc Linux.
//
// Une chronologie qui mele ces hotes compare des heures dont l'ancrage est
// inconnu, et rien ne le disait. C'est le defaut le plus couteux d'un outil
// d'enquete : il ne produit ni erreur ni absence, mais une **sequence plausible
// et fausse** — donc une causalite fausse.
//
// Ce service ne CORRIGE rien. Corriger demanderait une verite qu'on n'a pas.
// Il rend l'ancrage visible, hote par hote, et distingue trois etats :
// decalage connu, decalage nul (qui est une reponse), decalage inconnu.

// Les memes bornes que `hostUtcOffset` dans catscaleEventTime.ts : au-dela de
// 14 heures ou 59 minutes, la valeur n'est pas un fuseau et doit etre refusee
// plutot que rendue — un decalage invente vaut moins qu'un decalage absent.
const OFFSET_RE = String.raw`([+-])([0-9]{2}):?([0-9]{2})[[:space:]]*$`;

export function hostTimeContextSql(): string {
  return `
    WITH brut AS (
      SELECT host_name,
             regexp_match(description, '${OFFSET_RE}') AS m
        FROM collection_timeline
       WHERE case_id = $1
         AND artifact_type = 'catscale_host_time'
         AND host_name IS NOT NULL
    ),
    tz AS (
      SELECT host_name,
             max(CASE
                   WHEN m IS NOT NULL
                    AND (m[2])::int <= 14
                    AND (m[3])::int <= 59
                   THEN m[1] || m[2] || ':' || m[3]
                 END) AS utc_offset
        FROM brut
       GROUP BY host_name
    ),
    h AS (
      SELECT host_name, count(*)::int AS rows
        FROM collection_timeline
       WHERE case_id = $1 AND host_name IS NOT NULL
       GROUP BY host_name
    )
    SELECT h.host_name,
           h.rows,
           tz.utc_offset,
           (tz.utc_offset IS NOT NULL) AS known
      FROM h
      LEFT JOIN tz ON tz.host_name = h.host_name
     ORDER BY h.rows DESC, h.host_name`;
}
