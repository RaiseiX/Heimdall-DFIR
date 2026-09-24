// Quel statut porte un type d'artefact après parsing.
//
// Extrait de collection.js pour être testable, parce que la règle qu'il applique est
// celle que ce dépôt défend partout ailleurs : un échec ne devient pas un zéro.
//
// Observé en production le 2026-08-24 : MFTECmd a lu un $MFT de 365 031 lignes, puis
// l'insertion a été refusée en bloc sur `collection_timeline_result_id_fkey`. Le
// compteur de lignes écrites est resté à 0, et l'ancienne règle en concluait
// `degraded` — « l'outil a tourné, le CSV ne contenait rien ». Le fichier contenait
// tout. C'est l'écriture qui a échoué.
//
// La distinction compte au-delà du libellé : csvIngestionPlan lit `0 ligne` comme
// « analyse native tentée sans résultat » et déclenche un import CSV de repli. Une
// panne d'écriture déclenchait donc une réingestion d'un fichier dont on ne savait rien.

/**
 * @param {object}   ctx
 * @param {*}        ctx.toolError   erreur de l'outil externe, falsy si tout va bien
 * @param {number}   ctx.normalized  lignes réellement écrites en base
 * @param {string[]} ctx.failures    fichiers dont l'insertion a échoué
 * @returns {'success'|'degraded'|'error'}
 */
function resolveArtifactStatus(ctx) {
  const { toolError = null, normalized = 0, failures = [] } = ctx || {};
  const wrote = Number(normalized) || 0;
  const failed = Array.isArray(failures) ? failures.length : 0;

  // Rien d'écrit et quelque chose a cassé — l'outil ou l'insertion. On ne sait pas ce
  // que le fichier contenait, et c'est précisément ce qu'il faut dire.
  if (wrote === 0 && (failed > 0 || toolError)) return 'error';

  // Des lignes sont arrivées, mais un fichier a été refusé ou l'outil a signalé une
  // erreur : ce qui est en base est incomplet, et l'annoncer `success` reviendrait à
  // faire disparaître un fichier entier derrière un compteur non nul.
  if (failed > 0 || toolError) return 'degraded';

  // Aucun incident. Zéro ligne veut alors dire ce qu'il dit : le CSV était vide.
  return wrote > 0 ? 'success' : 'degraded';
}

module.exports = { resolveArtifactStatus };
