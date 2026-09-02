// Resolution d'identite des noeuds de la carte reseau.
//
// Releve en direct le 2026-08-25 : /network/:case/graph rend 34 noeuds « machine ». Six ne
// designent aucune machine (`- (-)`, `-:-`, `LOCAL`, `127.0.0.1:0`, `::1`, `127.0.0.1`) et
// cinq machines apparaissent sous deux ou trois orthographes — LAB-FORENSIC en porte trois.
// Le compte honnete est 21, pas 34.
//
// L'enjeu n'est pas cosmetique. Une machine comptee trois fois divise par trois son degre
// apparent, et le degre porte toute mesure de centralite, tout score de role et toute
// detection de pivot. Le classement des noeuds les plus connectes est faux avant d'etre
// affiche. C'est pour cela que le repli s'applique aux extremites des liens AVANT leur
// fusion : replier a l'affichage laisserait les degres faux.
//
// Deux regles tiennent ce module.
//
// Rien n'est perdu. Une orthographe repliee reste dans `aliases`, une adresse routable
// entre parentheses devient un attribut, et tout identifiant ecarte est rendu avec sa
// raison. Un test verifie l'egalite arithmetique entree/sortie.
//
// Rien n'est invente. La boucle locale n'est pas un pair — celle de chaque machine est la
// sienne, et la traiter comme partagee faisait de 127.0.0.1 le troisieme noeud le plus
// connecte du cas, degre 39.

export type NodeKind = 'placeholder' | 'ip' | 'host' | 'url';

export interface NodeIdentity {
  kind: NodeKind;
  key: string | null;
  label: string | null;
  address: string | null;
  reason?: string;
}

export interface Machine {
  key: string;
  label: string;
  aliases: string[];
  addresses: string[];
}

export interface Discarded { id: string; reason: string }

export interface FoldResult {
  canonical: Map<string, string>;
  machines: Machine[];
  addresses: string[];
  urls: string[];
  discarded: Discarded[];
}

// Adresses qui ne designent aucun pair : boucle locale, non specifie, diffusion.
const NON_PEER = new Set(['127.0.0.1', '::1', '0.0.0.0', '255.255.255.255', '::']);
// Chaines de remplissage rencontrees dans la base, tous parseurs confondus.
// `collecte` en fait partie sur mesure : les 142 lignes `sqle` du cas de reference portent
// toutes `host_name = 'COLLECTE'`, ecrit par l'ingestion SQLECmd la ou un nom de machine
// etait attendu. Ce n'est pas une machine, c'est l'aveu qu'on n'en avait pas.
const FILLER = new Set([
  '-', '--', '-:-', '- (-)', 'local', 'localhost', 'n/a', 'na', 'null', 'unknown', '?',
  'collecte', 'collection',
]);

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6 = /^[0-9a-f:]+$/i;

function isNonPeerAddress(s: string): boolean {
  const bare = s.replace(/:\d+$/, '');           // 127.0.0.1:0
  return NON_PEER.has(bare.toLowerCase()) || NON_PEER.has(s.toLowerCase());
}

export function resolveNodeIdentity(raw: string | null | undefined): NodeIdentity {
  const s = String(raw ?? '').trim();
  const nothing = (reason: string): NodeIdentity =>
    ({ kind: 'placeholder', key: null, label: null, address: null, reason });

  if (!s) return nothing('identifiant vide');
  if (FILLER.has(s.toLowerCase())) return nothing('chaine de remplissage, aucune machine designee');
  if (/^https?:\/\//i.test(s)) return { kind: 'url', key: s, label: s, address: null };
  // Postgres rend le type `inet` avec sa longueur de prefixe. Sur /graph-data,
  // `2a01:...:7ffe` et `2a01:...:7ffe/128` figuraient comme deux noeuds distincts de
  // degre 12 chacun. Seul le masque d'hote unique se replie : /24 decrit un reseau,
  // pas une machine, et les confondre serait une autre perte.
  const cidr = s.match(/^(.+)\/(\d{1,3})$/);
  if (cidr) {
    const [, addr, bits] = cidr;
    const hostOnly = (IPV4.test(addr) && bits === '32') || (addr.includes(':') && bits === '128');
    if (hostOnly) return resolveNodeIdentity(addr);
  }

  // Releve en base : 248 lignes portent un chemin de fichier dans `host_name`, ecrit la
  // par un parseur qui n'avait pas de nom de machine sous la main. Un nom d'hote ne
  // contient jamais de separateur de chemin. Teste apres le masque, qui en porte un.
  if (s.includes('/') || s.includes('\\')) return nothing('chemin de fichier, pas un nom de machine');
  // Releve apres deploiement du lot 2 : `chpasswd[10685]:` remontait comme machine
  // collectee. C'est une etiquette de processus syslog — un nom d'hote ne porte pas de
  // crochets. La regle reste etroite : les deux-points seuls ne suffisent pas, sinon
  // toute adresse IPv6 y passerait.
  if (/[[\]]/.test(s)) return nothing('etiquette de processus syslog, pas un nom de machine');
  if (isNonPeerAddress(s)) return nothing('boucle locale ou adresse non routable, jamais un pair');

  // « NOM (adresse) » : la machine est le nom ; l'adresse est un attribut, sauf si elle ne
  // designe personne, auquel cas elle disparait sans emporter le nom avec elle.
  const paren = s.match(/^(.*?)\s*\(([^)]*)\)\s*$/);
  if (paren) {
    const name = paren[1].trim();
    const inner = paren[2].trim();
    if (!name || FILLER.has(name.toLowerCase())) return nothing('nom absent, seul un remplissage entre parentheses');
    const address = inner && !FILLER.has(inner.toLowerCase()) && !isNonPeerAddress(inner) ? inner : null;
    return { kind: 'host', key: name.toUpperCase(), label: name, address };
  }

  if (IPV4.test(s)) return { kind: 'ip', key: s, label: s, address: s };
  // La casse hexadecimale d'une IPv6 ne doit pas creer deux noeuds.
  if (s.includes(':') && IPV6.test(s)) {
    const k = s.toLowerCase();
    return { kind: 'ip', key: k, label: k, address: k };
  }

  return { kind: 'host', key: s.toUpperCase(), label: s, address: null };
}

// Source d'une visite d'URL.
//
// `COLLECTE` n'est pas un noeud synthetique invente a l'affichage : les 142 lignes `sqle`
// portent litteralement `host_name = 'COLLECTE'` en base, ecrit par l'ingestion SQLECmd la
// ou un nom de machine etait attendu. Le graphe le dessinait fidelement, degre 100.
//
// L'attribution existe pourtant : chaque ligne porte un `result_id` qui remonte a une
// collecte reelle — 98 lignes pour LAB_Xtended-lab, 44 pour LAB-FORENSIC_Max.
//
// Mais une collecte peut contenir plusieurs machines : `b5053835` porte Lab-Forensic,
// DESKTOP-57GPUQF et WIN-BR2DIUCC8CK. Attribuer les URL a « la » machine de la collecte
// serait deviner, et deviner est precisement ce que ce chantier refuse. On rattache donc
// a la collecte, on la nomme, et le noeud dit qu'il est une collecte — pas une machine.
export interface UrlSource {
  kind: 'host' | 'collection' | 'none';
  id: string | null;
  label: string | null;
  reason?: string;
}

export function resolveUrlSource(input: {
  hostName?: string | null;
  evidenceId?: string | null;
  evidenceName?: string | null;
}): UrlSource {
  const host = resolveNodeIdentity(input.hostName);
  if (host.kind === 'host') return { kind: 'host', id: host.key, label: host.label };

  const ev = input.evidenceId ? String(input.evidenceId) : '';
  if (!ev) {
    return {
      kind: 'none', id: null, label: null,
      reason: 'ni machine ni collecte identifiable, source non attribuable',
    };
  }
  const name = (input.evidenceName || '').trim();
  return {
    // Prefixe pour qu'une collecte ne puisse jamais entrer en collision avec une
    // machine qui porterait le meme nom.
    kind: 'collection',
    id: `collecte:${ev}`,
    label: name || `collecte ${ev.slice(0, 8)}`,
  };
}

// Les noeuds du graphe sont construits depuis les aretes. Une machine dont les seules
// aretes allaient vers `127.0.0.1` ou une chaine de remplissage disparait donc une fois
// celles-ci ecartees — constate apres deploiement du repli : trois machines sur cinq se
// sont effacees du graphe.
//
// Une machine collectee sans liaison observee doit rester visible et le dire. La faire
// disparaitre echange de la couverture contre de la proprete, ce qu'un analyste ne doit
// jamais subir en silence.
export interface UnlinkedResult {
  nodes: Array<Record<string, unknown>>;
  added: string[];
  skipped: Discarded[];
}

export function addUnlinkedMachines(
  nodes: Array<Record<string, unknown>>,
  collectedHosts: Array<string | null | undefined>,
): UnlinkedResult {
  const out = [...(nodes ?? [])];
  const present = new Set(out.map(n => String(n.id)));
  const added: string[] = [];
  const skipped: Discarded[] = [];
  const seen = new Set<string>();

  for (const raw of collectedHosts ?? []) {
    const id = String(raw ?? '');
    const r = resolveNodeIdentity(id);
    if (r.kind === 'placeholder') { skipped.push({ id, reason: r.reason || 'ecarte' }); continue; }
    if (r.kind !== 'host') continue;
    const key = r.key!;
    // Le repli vaut des deux cotes : sans cela on rajouterait un doublon de ce qu'on
    // vient tout juste de replier.
    if (present.has(key) || seen.has(key)) continue;
    seen.add(key);
    out.push({
      id: key,
      label: r.label,
      type: 'internal',
      connection_count: 0,
      total_bytes: 0,
      is_suspicious: false,
      no_observed_link: true,
    });
    added.push(key);
  }

  added.sort();
  return { nodes: out, added, skipped };
}

export function foldIdentities(ids: Array<string | null | undefined>): FoldResult {
  const canonical = new Map<string, string>();
  const discarded: Discarded[] = [];
  const urls: string[] = [];
  const addrSet = new Set<string>();
  // cle -> orthographes observees, avec leur frequence, pour choisir un libelle stable.
  const hosts = new Map<string, { aliases: Set<string>; labels: Map<string, number>; addresses: Set<string> }>();

  for (const raw of ids ?? []) {
    const id = String(raw ?? '');
    const r = resolveNodeIdentity(id);

    if (r.kind === 'placeholder') { discarded.push({ id, reason: r.reason || 'ecarte' }); continue; }
    if (r.kind === 'url')  { urls.push(r.key!);  canonical.set(id, r.key!); continue; }
    if (r.kind === 'ip')   { addrSet.add(r.key!); canonical.set(id, r.key!); continue; }

    const key = r.key!;
    let h = hosts.get(key);
    if (!h) { h = { aliases: new Set(), labels: new Map(), addresses: new Set() }; hosts.set(key, h); }
    h.aliases.add(id);
    h.labels.set(r.label!, (h.labels.get(r.label!) || 0) + 1);
    if (r.address) h.addresses.add(r.address);
    canonical.set(id, key);
  }

  const machines: Machine[] = [...hosts.entries()]
    .map(([key, h]) => ({
      key,
      // Orthographe la plus observee ; a egalite, l'ordre lexicographique, pour que le
      // libelle ne change pas d'un chargement a l'autre.
      label: [...h.labels.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0][0],
      aliases: [...h.aliases].sort(),
      addresses: [...h.addresses].sort(),
    }))
    .sort((a, b) => a.key.localeCompare(b.key));

  return { canonical, machines, addresses: [...addrSet].sort(), urls, discarded };
}

// Resolveur partage entre les deux constructeurs de graphe.
//
// `network.js` en porte deux : `/graph` et `/graph-data`. Les lots 1, 2 et 5 n'avaient
// ete appliques qu'au premier — or c'est le second que l'interface lit. La carte
// affichait donc encore COLLECTE degre 100, les identites dupliquees et 155 liens
// `undefined`, alors que tout etait corrige a cote.
//
// Un resolveur partage plutot que deux copies : la derive entre les deux chemins est
// ce qui a cause le defaut, pas la logique elle-meme.
export interface IdentityResolver {
  canon(raw: unknown): string | null;
  applyLabels(nodeMap: Map<string, Record<string, unknown>>): void;
  summary(): {
    discarded: Array<{ id: string; reason: string; count: number }>;
    discarded_occurrences: number;
    machines_folded: number;
  };
}

export function createIdentityResolver(): IdentityResolver {
  const discards = new Map<string, { id: string; reason: string; count: number }>();
  const hosts = new Map<string, { labels: Map<string, number>; aliases: Set<string>; addresses: Set<string> }>();

  return {
    canon(raw: unknown): string | null {
      // Un identifiant de collecte est deja canonique : il designe une collecte
      // reelle et nommee, il ne se replie ni ne s'ecarte.
      if (typeof raw === 'string' && raw.startsWith('collecte:')) return raw;

      const r = resolveNodeIdentity(raw as string);
      if (r.kind === 'placeholder') {
        const id = String(raw ?? '');
        const d = discards.get(id) || { id, reason: r.reason || 'ecarte', count: 0 };
        d.count++;
        discards.set(id, d);
        return null;
      }
      if (r.kind === 'host') {
        let h = hosts.get(r.key!);
        if (!h) { h = { labels: new Map(), aliases: new Set(), addresses: new Set() }; hosts.set(r.key!, h); }
        h.labels.set(r.label!, (h.labels.get(r.label!) || 0) + 1);
        h.aliases.add(String(raw));
        if (r.address) h.addresses.add(r.address);
      }
      return r.key;
    },

    applyLabels(nodeMap) {
      hosts.forEach((h, key) => {
        const n = nodeMap.get(key);
        if (!n) return;
        n.label = [...h.labels.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0][0];
        n.aliases = [...h.aliases].sort();
        if (h.addresses.size) n.addresses = [...h.addresses].sort();
      });
    },

    summary() {
      const discarded = [...discards.values()].sort((a, b) => b.count - a.count);
      return {
        discarded,
        // Les occurrences, pas seulement les valeurs distinctes : 127.0.0.1
        // apparaissait 39 fois, et c'est ce nombre qui dit l'ampleur.
        discarded_occurrences: discarded.reduce((n, d) => n + d.count, 0),
        machines_folded: [...hosts.values()].filter(h => h.aliases.size > 1).length,
      };
    },
  };
}


// Compose la forme `Hote (adresse)` que `resolveNodeIdentity` sait replier, pour que
// les plusieurs adresses d'une meme machine collectee tombent sur un seul noeud.
//
// Mesure du 2026-08-26 : les 177 lignes reseau du cas portent toutes `host = Dlinux`,
// et la carte montrait pourtant deux noeuds — l'adresse publique IPv6 et l'adresse
// privee IPv4. Deux etoiles la ou il y a une machine, et aucun degre juste.
//
// La garde vaut decision : 248 lignes du cas portent un chemin de fichier dans
// `host_name`, ecrit la par un parseur sans nom de machine sous la main. Composer
// aveuglement ferait ecarter l'arete entiere par le resolveur — mieux vaut un noeud
// adresse qu'une liaison disparue. La decision « ce nom est-il un hote ? » vit ici et
// nulle part ailleurs.
export function composeHostAddress(
  host: string | null | undefined,
  address: string | null | undefined,
): string | null {
  const h = String(host ?? '').trim();
  const rawA = String(address ?? '').trim();
  if (!h && !rawA) return null;

  // Postgres rend `inet` avec sa longueur de prefixe. Composer l'adresse brute
  // fabriquait `Dlinux (10.98.233.235/32)`, que le resolveur rejetait comme un chemin
  // de fichier : 15 aretes ecartees le 2026-08-27, sous une raison fausse affichee en
  // pied de carte. La normalisation existe deja dans `resolveNodeIdentity` — un masque
  // d'hote unique designe la machine, /24 ou /64 decrit un reseau — on la reutilise
  // plutot que de la reecrire ici.
  // Seule une adresse est une adresse : un nom d'hote arrive dans ce champ par un repli
  // du parseur, et le composer avec lui-meme donnerait `Dlinux (DLINUX)`.
  const ra = rawA ? resolveNodeIdentity(rawA) : null;
  const a = ra && ra.kind === 'ip' ? (ra.address ?? ra.key ?? rawA) : '';

  if (!h) return a || rawA || null;
  // Un prefixe de reseau n'est pas une adresse de machine : on garde l'hote, qui lui
  // est reel, plutot que de fabriquer un identifiant que le resolveur ecartera.
  if (!a) return h;
  if (h === a) return h;

  const r = resolveNodeIdentity(h);
  if (r.kind !== 'host') return a;
  return `${h} (${a})`;
}
