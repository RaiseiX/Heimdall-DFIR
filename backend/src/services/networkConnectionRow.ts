// Une ligne `catscale_network` vers une ligne `network_connections`.
//
// `network_connections` est vide et quatre endpoints sur cinq la lisent — graph-data,
// analytics, beacons, dga-analysis rendent tous des ecrans vides. Pendant ce temps
// `collection_timeline` porte 177 lignes `catscale_network` dont le `raw` est deja
// structure : pid, host, peer, local, netid, proto, state, dst_ip, process, dst_port.
// Rien a extraire d'une chaine de description.
//
// Ce qui est projete et ce qui ne l'est pas est une decision, pas un effet de bord.
// `src_ip` et `dst_ip` sont NOT NULL, et une socket en ecoute n'a pas de pair : la
// projeter comme une connexion serait fabriquer une liaison qui n'a pas eu lieu.
// Chaque rejet porte donc sa raison, pour que l'ecran puisse dire combien de lignes
// il a ecartees et pourquoi — jamais un simple total plus petit.
//
// Mesure du 2026-08-25 sur les 177 lignes : 137 TIME-WAIT, 15 ESTAB, 15 LISTEN,
// 7 UDP UNCONN, 2 UDP ESTAB, 1 ICMP6 UNCONN.

export interface Endpoint { ip: string | null; port: number | null }

export interface ConnectionRow {
  src_ip: string;
  src_port: number | null;
  dst_ip: string;
  dst_port: number | null;
  protocol: string | null;
  // Aucune mesure de volume dans `ss` : NULL dit « non mesure », 0 dirait
  // « mesure a zero ». La difference porte tout le sens sur une carte reseau.
  bytes_sent: null;
  bytes_received: null;
  packet_count: null;
  // Quel processus a ouvert la socket est l'attribut le plus parlant d'une connexion
  // pour un analyste. Mesure du 2026-08-26 : `linkType` rend `web` sur 142 aretes sur
  // 145, quand le processus rend douze valeurs distinctes — claude, firefox-esr,
  // Discord, tailscaled, nordvpnd, docker-proxy... C'est la dimension qui discrimine.
  //
  // Il vivait deja dans `notes`, colle a l'etat par un separateur. Un champ libre ne
  // se relit pas : la carte exposait une cle `processes` restee vide sur les seize
  // aretes machines. NULL quand `ss` n'attribue pas la socket — les dix lignes
  // TIME-WAIT mesurees sont dans ce cas — jamais une chaine vide, qui se lirait comme
  // un processus nomme « rien ».
  process: string | null;
  socket_state: string | null;
  // Le nom de la machine collectee, pour que ses plusieurs adresses se replient sur un
  // seul noeud. Mesure du 2026-08-26 : les 177 lignes du cas portent toutes
  // `host = Dlinux`, et la carte montrait deux noeuds — l'IPv6 publique et l'IPv4
  // privee. `ss` l'ecrit dans `host`, le parseur le recopie dans `Computer`.
  src_host: string | null;
  notes: string;
}

export type ConnectionResult =
  | { ok: true; row: ConnectionRow; reason?: undefined }
  | { ok: false; row?: undefined; reason: string };

// Adresses qui ne designent aucun pair joignable.
const WILDCARD = new Set(['0.0.0.0', '::', '*']);
const LOOPBACK = new Set(['127.0.0.1', '::1']);

// Constate en production apres la premiere projection : 73 des 100 lignes inserees
// etaient `::ffff:127.0.0.1 -> ::ffff:127.0.0.1`, la forme IPv4-mappee de la boucle
// locale. Le detecteur de balayage les a lues comme « Scan/sweep — 1 hote, 73 ports »,
// severite ELEVEE, T1046 — un faux positif produit par une machine qui se parle a
// elle-meme. Un faux positif de cette gravite detruit la confiance dans l'outil plus
// surement qu'une absence de detection.
//
// La normalisation precede tous les tests d'appartenance : `::ffff:a.b.c.d` designe
// exactement `a.b.c.d`, joker et boucle locale compris.
function normalizeIp(ip: string | null): string | null {
  if (!ip) return ip;
  const m = ip.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  return m ? m[1] : ip;
}

// `ss` ecrit trois formes : `10.98.233.235:57674`, `10.98.233.235%wlo1:68` quand la
// route est liee a une interface, et `[2a01:...:7ffe]:33684` en IPv6. Le joker `*`
// remplace l'un ou l'autre des deux membres sur une socket sans pair.
export function parseEndpoint(raw: string | null | undefined): Endpoint {
  const s = String(raw ?? '').trim();
  if (!s) return { ip: null, port: null };

  const toPort = (p: string): number | null => {
    if (!p || p === '*') return null;
    const n = parseInt(p, 10);
    return Number.isFinite(n) ? n : null;
  };

  // IPv6 entre crochets : les deux-points internes appartiennent a l'adresse.
  const bracket = s.match(/^\[([^\]]+)\](?::(.*))?$/);
  if (bracket) {
    const ip = bracket[1].split('%')[0];
    return { ip: ip || null, port: toPort(bracket[2] ?? '') };
  }

  const cut = s.lastIndexOf(':');
  if (cut === -1) return { ip: null, port: null };
  const host = s.slice(0, cut).split('%')[0];
  const port = toPort(s.slice(cut + 1));
  if (!host || host === '*') return { ip: null, port };
  return { ip: host, port };
}

export function connectionFromRaw(raw: Record<string, unknown> | null | undefined): ConnectionResult {
  const r = raw || {};
  const str = (k: string): string | null => {
    const v = (r as Record<string, unknown>)[k];
    return v === null || v === undefined || v === '' ? null : String(v);
  };

  const localRaw = parseEndpoint(str('local'));
  const peerRaw  = parseEndpoint(str('peer'));
  const local = { ip: normalizeIp(localRaw.ip), port: localRaw.port };
  const peer  = { ip: normalizeIp(peerRaw.ip),  port: peerRaw.port };

  // `dst_ip` est deja extrait par le parseur ; `peer` sert de repli et porte le port.
  const dstIp = normalizeIp(str('dst_ip')) || peer.ip;
  if (!dstIp || WILDCARD.has(dstIp)) {
    return { ok: false, reason: 'socket sans pair — en ecoute ou non connectee' };
  }
  if (LOOPBACK.has(dstIp)) {
    return { ok: false, reason: 'boucle locale, jamais un pair du reseau' };
  }
  if (!local.ip || WILDCARD.has(local.ip)) {
    return { ok: false, reason: 'adresse source absente, obligatoire en base' };
  }

  const dstPortRaw = str('dst_port');
  const dstPort = dstPortRaw !== null ? (parseInt(dstPortRaw, 10) || null) : peer.port;
  const state = str('state');
  const proc  = str('process');

  // `notes` reste rendue a l'identique : d'autres surfaces la lisent, et promouvoir
  // ces deux valeurs en colonnes ne doit pas emporter un affichage existant. Elle
  // devient un resume lisible, plus la seule trace de l'information.
  const notes = [state, proc].filter(Boolean).join(' · ');

  return {
    ok: true,
    row: {
      src_ip: local.ip,
      src_port: local.port,
      dst_ip: dstIp,
      dst_port: dstPort,
      protocol: str('proto') || str('netid'),
      bytes_sent: null,
      bytes_received: null,
      packet_count: null,
      process: proc,
      socket_state: state,
      src_host: str('host') || str('Computer'),
      notes,
    },
  };
}
