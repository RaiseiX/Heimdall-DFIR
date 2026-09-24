// Le registre des liaisons.
//
// Une machine et quatorze pairs, ce n'est pas un reseau, c'est une etoile — et une
// etoile est une liste. Mesure du 2026-08-27 sur CASE-2026-001 : 22 noeuds machines,
// une seule machine qui initie, une seule liaison machine a machine. Un graphe a
// disposition libre y coute une mise en page, un zoom et un deplacement pour restituer
// ce qu'une liste triee donne d'un coup d'oeil.
//
// Ce module normalise les lignes rendues par la base et compte ce qu'elles portent.
// Les trois groupements — par processus, par pair, par port — vivent cote ecran, sur
// ces memes lignes : une seule requete les sert tous les trois, et le regroupement est
// une fonction pure qu'on peut lire et tester sans base.

export type Zone = 'internal' | 'external';

export interface RegisterDbRow {
  process?: string | null;
  socket_state?: string | null;
  peer?: string | null;
  port?: number | string | null;
  protocol?: string | null;
  connections?: number | string | null;
}

export interface RegisterRow {
  /** null designe une connexion non attribuee — jamais une chaine vide, qui se lirait
   *  comme un processus nomme « rien ». L'ecran choisit ses mots, et peut la compter. */
  process: string | null;
  socket_state: string | null;
  peer: string;
  port: number | null;
  protocol: string | null;
  zone: Zone;
  connections: number;
}

export interface RegisterTotals {
  connections: number;
  /** un couple pair/port/protocole : trois processus vers le meme pair ne font qu'une liaison */
  links: number;
  peers: number;
  processes: number;
  attributed: number;
  unattributed: number;
  /** pourquoi l'attribution manque, depuis la donnee : `ss` ne rend pas de processus
   *  sur une socket fermee. Compte par etat plutot que laisse en trou. */
  unattributed_states: Array<{ state: string; count: number }>;
  observed_from: string | null;
  observed_to: string | null;
  /** un seul instant distinct est le fait le plus important de cette collecte : c'est
   *  lui qui rend l'analyse de balises impossible. */
  observed_distinct: number;
}

function text(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  const s = String(v).trim();
  return s === '' ? null : s;
}

// Number(null) vaut 0 : une ligne dont le compte manque se presenterait comme une
// liaison observee zero fois, ce qui n'a aucun sens. On exige un entier positif.
function count(v: unknown): number | null {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

export function buildRegisterRows(
  rows: readonly RegisterDbRow[] | null | undefined,
  zoneOf: (peer: string) => Zone,
): RegisterRow[] {
  const out: RegisterRow[] = [];
  for (const r of rows ?? []) {
    const peer = text(r?.peer);
    const n = count(r?.connections);
    // Une ligne sans pair ne decrit aucune liaison ; une ligne sans compte ne dit rien
    // de mesure. Les deux sont ecartees plutot que rendues a moitie.
    if (!peer || n === null) continue;
    out.push({
      process: text(r?.process),
      socket_state: text(r?.socket_state),
      peer,
      port: count(r?.port),
      protocol: text(r?.protocol),
      zone: zoneOf(peer),
      connections: n,
    });
  }
  return out;
}

export function registerTotals(
  rows: readonly RegisterRow[],
  observedAt: readonly (string | null | undefined)[],
): RegisterTotals {
  const links = new Set<string>();
  const peers = new Set<string>();
  const processes = new Set<string>();
  const states = new Map<string, number>();
  let connections = 0;
  let attributed = 0;
  let unattributed = 0;

  for (const r of rows) {
    connections += r.connections;
    links.add(`${r.peer}||${r.port ?? ''}||${r.protocol ?? ''}`);
    peers.add(r.peer);
    if (r.process) {
      processes.add(r.process);
      attributed += r.connections;
    } else {
      unattributed += r.connections;
      const s = r.socket_state || 'inconnu';
      states.set(s, (states.get(s) || 0) + r.connections);
    }
  }

  const instants = [...new Set((observedAt ?? []).map(text).filter((v): v is string => v !== null))].sort();

  return {
    connections,
    links: links.size,
    peers: peers.size,
    processes: processes.size,
    attributed,
    unattributed,
    unattributed_states: [...states.entries()]
      .map(([state, c]) => ({ state, count: c }))
      .sort((a, b) => b.count - a.count || a.state.localeCompare(b.state)),
    observed_from: instants[0] ?? null,
    observed_to: instants[instants.length - 1] ?? null,
    observed_distinct: instants.length,
  };
}
