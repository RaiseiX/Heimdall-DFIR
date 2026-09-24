import * as fs from 'fs';

// Comment le prefetch Windows est lu. PECmd n'apparait pas ici, et c'est le sujet.
//
// PECmd refuse de tourner sous Linux — il lui faut RtlDecompressBufferEx de
// ntdll. Verifie le 2026-09-18 dans le conteneur, sur un .pf reel :
//
//   Non-Windows platforms not supported due to the need to load decompression
//   specific Windows libraries! Exiting...
//   REAL_EXIT=0
//
// Message sur stdout, stderr vide, code de sortie ZERO. Un appelant qui teste le
// code de retour conclut « parse reussi, zero prefetch ». Pour un outil
// forensique c'est pire qu'un plantage : la perte de preuve prend l'apparence
// d'un resultat negatif propre.
//
// La route de collecte gardait un repli vers PECmd quand libscca manquait. Les
// deux autres branches du meme if/else etaient deja identiques et appelaient
// python : tout l'enchainement se reduisait a « toujours python », le repli etant
// la seule difference — et un piege. parse_prefetch.py porte de toute facon son
// propre repli (dissect, puis pyscca) et sort en 1, bruyamment, si aucun backend
// n'est disponible.
export const PREFETCH_SCRIPT = '/app/parsers/parse_prefetch.py';

/**
 * Construit l'appel du parseur de prefetch. Un repertoire est balaye (`-d`), un
 * fichier est lu seul (`-f`). Un chemin absent est traite comme un fichier, pour
 * que parse_prefetch.py signale lui-meme qu'il ne le trouve pas plutot que de
 * balayer un repertoire inexistant.
 */
export function prefetchCommand(input: string, outputDir: string, csvName: string): string[] {
  let isDir = false;
  try { isDir = fs.statSync(input).isDirectory(); } catch { /* absent : traite comme un fichier */ }
  return ['python3', PREFETCH_SCRIPT, isDir ? '-d' : '-f', input, '--csv', outputDir, '--csvf', csvName];
}
