// Un chemin du ledger nomme-t-il un artefact que Cat-Scale ecrit et que le produit
// declare connaitre ?
//
// La couverture avait trois sorts pour un fichier non vide — il a produit des
// lignes, son parseur a echoue, personne ne l a reclame — et il en manquait un.
// `last-btmp.txt` fait 60 octets, dit `btmp begins ...` et rien de plus : le
// parseur l a lu, il n y avait aucun echec d authentification a rapporter. Range
// en `unsupported`, il se lit comme un fichier que personne n a su ouvrir. Or
// zero echec de connexion est une observation, pas une lacune de couverture.
//
// Le catalogue est ce qui separe les deux. Il est deja la, reparti entre le
// registre declaratif et les parseurs dedies ; ceci ne fait que l interroger.
import { ARTIFACT_REGISTRY } from './catscaleArtifactRegistry';
import { BESPOKE_PATTERNS } from './catscaleBespokePatterns';
import { artifactRegex } from './catscaleFiles';

// Le separateur qu ecrit registerArchiveMembers entre une archive et son membre.
const ARCHIVE_MEMBER = ' \u2192 ';

/**
 * Vrai quand `<dossier>/<hote>-<DTG>-<artefact>.<ext>` designe un artefact du
 * catalogue. Le dossier fait partie de la cle : un nom podman depose dans Logs ne
 * designe pas l artefact podman.
 *
 * Un membre d archive rend toujours faux. L artefact catalogue est l archive ;
 * ce qu elle contient est comptabilise par les lignes que ses parseurs produisent,
 * et `var/log/README` n a legitimement aucun parseur.
 */
export function isCatalogedArtifact(relativePath: string): boolean {
  if (relativePath.includes(ARCHIVE_MEMBER)) return false;

  const cut = relativePath.lastIndexOf('/');
  const dir = cut === -1 ? '.' : relativePath.slice(0, cut);
  const name = cut === -1 ? relativePath : relativePath.slice(cut + 1);

  // La meme regle de delimitation que la decouverte de fichiers, importee plutot
  // que reecrite : c est elle qui empeche last-utmp de happer last-utmpdump.
  return [
    ...ARTIFACT_REGISTRY.filter(s => s.dir === dir).map(s => s.pattern),
    ...(BESPOKE_PATTERNS[dir] ?? []),
  ].some(p => artifactRegex(p).test(name));
}
