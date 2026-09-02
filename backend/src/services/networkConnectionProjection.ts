import type { Pool } from 'pg';
import { connectionFromRaw } from './networkConnectionRow';

// Projette les lignes `catscale_network` de la timeline dans `network_connections`.
//
// La table est vide et quatre endpoints sur cinq la lisent : `graph-data`, `analytics`,
// `beacons` et `dga-analysis` rendent tous des ecrans vides pendant que 177 lignes de
// connexions dorment dans `collection_timeline`. Ce service est le pont manquant.
//
// Trois choix qui meritent d'etre ecrits.
//
// **La purge est scopee a la collecte.** Rejouer la projection sur une collecte ne
// doit pas emporter les connexions des autres — c'est le defaut exact qui a fait
// disparaitre 254 lignes Hayabusa d'une collecte voisine.
//
// **Rien n'est ecarte en silence.** Une socket en ecoute n'a pas de pair, la boucle
// locale n'est pas un pair du reseau, une adresse source absente interdit l'insertion
// (`src_ip` est NOT NULL). Chaque rejet est compte par raison et rendu a l'appelant :
// un total plus petit sans explication est une decision transformee en absence.
//
// **Le passage par Node est assume.** L'inventaire se projette en `INSERT ... SELECT`
// a 25 000 lignes/seconde parce que la transformation tient en SQL. Ici il faut lire
// `local` (`10.98.233.235%wlo1:68`, `[2607:6bc0::10]:443`) et decider du rejet — c'est
// de la logique testable, pas une expression SQL. Sur 177 lignes le cout est nul ; si
// une collecte en portait un million, il faudrait revoir ce choix.

const SOURCE_SQL = `
  SELECT raw, timestamp
    FROM collection_timeline
   WHERE case_id = $1
     AND evidence_id = $2
     AND artifact_type = 'catscale_network'`;

const PURGE_SQL = `
  DELETE FROM network_connections
   WHERE case_id = $1
     AND evidence_id = $2`;

const INSERT_SQL = `
  INSERT INTO network_connections
    (case_id, evidence_id, src_ip, src_port, dst_ip, dst_port, protocol,
     bytes_sent, bytes_received, packet_count, first_seen, last_seen,
     process, socket_state, src_host, notes)
  SELECT $1, $2,
         u.src_ip, u.src_port, u.dst_ip, u.dst_port, u.protocol,
         NULL, NULL, NULL, u.seen, u.seen,
         u.process, u.socket_state, u.src_host, u.notes
    FROM unnest(
           $3::text[], $4::int[], $5::text[], $6::int[],
           $7::text[], $8::timestamptz[], $9::text[], $10::text[], $11::text[], $12::text[]
         ) AS u(src_ip, src_port, dst_ip, dst_port, protocol, seen,
                process, socket_state, src_host, notes)`;

export interface ProjectionResult {
  inserted: number;
  skipped: Array<{ reason: string; count: number }>;
  examined: number;
}

export async function projectNetworkConnections(
  pool: Pool,
  caseId: string,
  evidenceId: string,
): Promise<ProjectionResult> {
  if (!caseId || !evidenceId) {
    throw new Error('[networkConnectionProjection] refusing to run without a case and an evidence');
  }

  const src = await pool.query(SOURCE_SQL, [caseId, evidenceId]);

  const srcIps: string[] = [], srcPorts: (number | null)[] = [];
  const dstIps: string[] = [], dstPorts: (number | null)[] = [];
  const protos: (string | null)[] = [], seen: (string | null)[] = [], notes: string[] = [];
  const procs: (string | null)[] = [], states: (string | null)[] = [], srcHosts: (string | null)[] = [];
  const tally = new Map<string, number>();

  for (const row of src.rows) {
    const r = connectionFromRaw(row.raw);
    if (!r.ok) { tally.set(r.reason, (tally.get(r.reason) || 0) + 1); continue; }
    srcIps.push(r.row.src_ip);   srcPorts.push(r.row.src_port);
    dstIps.push(r.row.dst_ip);   dstPorts.push(r.row.dst_port);
    protos.push(r.row.protocol);
    // `ss` est une photographie : premiere et derniere observation sont le meme
    // instant. Ecrire deux dates differentes suggererait une duree qui n'a pas ete
    // mesuree — et c'est cette absence de duree qui rend le beaconing indisponible.
    seen.push(row.timestamp ? new Date(row.timestamp).toISOString() : null);
    procs.push(r.row.process);
    states.push(r.row.socket_state);
    srcHosts.push(r.row.src_host);
    notes.push(r.row.notes);
  }

  await pool.query(PURGE_SQL, [caseId, evidenceId]);
  if (srcIps.length > 0) {
    // Toutes les colonnes traversent le meme unnest : une longueur qui divergerait
    // decalerait silencieusement les valeurs d'une ligne sur l'autre, et une connexion
    // porterait le processus de sa voisine. C'est teste.
    await pool.query(INSERT_SQL, [
      caseId, evidenceId, srcIps, srcPorts, dstIps, dstPorts, protos, seen, procs, states, srcHosts, notes,
    ]);
  }

  return {
    inserted: srcIps.length,
    examined: src.rows.length,
    skipped: [...tally.entries()]
      .map(([reason, count]) => ({ reason, count }))
      .sort((a, b) => b.count - a.count),
  };
}
