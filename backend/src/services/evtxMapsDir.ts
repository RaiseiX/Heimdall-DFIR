import * as fs from 'fs';
import * as path from 'path';

// Ou EvtxECmd trouve ses maps, selon la disposition que l archive amont a livree.
//
// Sans --maps, EvtxECmd rend les EventData sans noms. Mesure le 2026-09-18 sur un
// Security.evtx reel de la collecte : 125 082 lignes portent un PayloadData mappe
// avec --maps, 0 sans. Le compte cible, le type d ouverture de session et l
// utilisateur disparaissent tous — l evenement reste, sa substance non.
//
// Trois dispositions coexistent selon la version de l archive, et la regle qui
// les departage vivait recopiee a trois endroits : entrypoint.sh, deux fois dans
// routes/collection.js, et parserService.ts. Cette derniere copie ne connaissait
// que les deux premieres, et la seule qui existe reellement sur disque est la
// troisieme : tout EVTX passant par le service de parseurs perdait ses champs.
// Une regle, un endroit — c est la seule facon d empecher la copie suivante de
// deriver a son tour.
const LAYOUTS = [
  [] as string[],                  // Maps/
  ['Maps'],                        // Maps/Maps/
  ['EvtxeCmd', 'Maps'],            // Maps/EvtxeCmd/Maps/  <- livraison amont actuelle
];

function holdsMaps(dir: string): boolean {
  try {
    return fs.readdirSync(dir).some(f => f.endsWith('.map') || f.endsWith('.json'));
  } catch {
    return false;
  }
}

/**
 * Rend le repertoire a passer a `--maps`, ou null si aucune disposition ne porte
 * de map. Un niveau vide n arrete pas la recherche : c est exactement la forme du
 * defaut d origine, ou `Maps/` existait sans map et masquait le niveau utile.
 */
export function resolveEvtxMapsDir(zimmermanDir: string): string | null {
  const base = path.join(zimmermanDir, 'Maps');
  if (!fs.existsSync(base)) return null;
  for (const parts of LAYOUTS) {
    const candidate = path.join(base, ...parts);
    if (holdsMaps(candidate)) return candidate;
  }
  return null;
}
