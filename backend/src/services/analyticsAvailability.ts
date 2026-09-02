// « Indisponible parce que », jamais « 0 ».
//
// Mesure du 2026-08-27 sur CASE-2026-001 : l'ecran de triage affichait six zeros, dont
// quatre etaient des faux negatifs. Ils se lisent « on a cherche et il n'y a rien »
// alors qu'ils veulent dire « ca n'a pas pu etre mesure » :
//
//   balises  0  ->  les 27 connexions partagent UN SEUL horodatage
//   exfil    0  ->  bytes_sent et bytes_received sont NULL partout, `ss` ne compte pas
//   cloud    0  ->  geo_dst est vide sur les 27 lignes
//   dga      0  ->  aucun IOC de type domaine enregistre sur le cas
//
// Un zero qui veut dire « impossible a mesurer » est un faux negatif presente comme un
// resultat. Dans un outil forensique c'est la pire classe de defaut : pas une fonction
// manquante, une confiance fausse — l'analyste conclut qu'il n'y a pas de balise alors
// que personne n'a pu en chercher.
//
// Chaque etat est deduit de faits comptes en base. Aucune raison n'est ecrite ici en
// toutes lettres : le module rend un code, l'ecran choisit ses mots et sa langue. Les
// chiffres qui justifient l'etat voyagent avec lui, pour que l'ecran puisse dire
// « 5 sur 27 » sans refaire le calcul et sans qu'il puisse diverger.

export type AvailabilityState = 'available' | 'partial' | 'unavailable';

export interface Availability {
  state: AvailabilityState;
  reason: string | null;
  facts: Record<string, number>;
}

export interface AnalyticsFacts {
  /** lignes projetees dans network_connections pour le cas */
  rows?: number | null;
  /** horodatages distincts — un seul veut dire une photographie, pas un film */
  instants?: number | null;
  /** lignes portant un compte d'octets */
  withBytes?: number | null;
  /** lignes portant un pays dans geo_dst */
  withGeo?: number | null;
  /** IOC de type domaine enregistres sur le cas — la source du DGA */
  domainIocs?: number | null;
}

export interface AnalyticsAvailability {
  beacons: Availability;
  exfil: Availability;
  geo: Availability;
  cloud: Availability;
  dga: Availability;
}

const int = (v: unknown): number => {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? Math.trunc(n) : 0;
};

// Disponible, partiel, indisponible : une couverture partielle n'est ni l'un ni
// l'autre, et la confondre avec « disponible » ferait passer une mesure sur cinq
// lignes pour une mesure sur vingt-sept.
function coverage(withIt: number, rows: number, reasonNone: string, reasonPartial: string, facts: Record<string, number>): Availability {
  if (withIt <= 0) return { state: 'unavailable', reason: reasonNone, facts };
  if (withIt < rows) return { state: 'partial', reason: reasonPartial, facts };
  return { state: 'available', reason: null, facts };
}

export function analyticsAvailability(input: AnalyticsFacts | null | undefined): AnalyticsAvailability {
  const rows = int(input?.rows);
  const instants = int(input?.instants);
  const withBytes = int(input?.withBytes);
  const withGeo = int(input?.withGeo);
  const domainIocs = int(input?.domainIocs);

  // Le DGA lit la table `iocs`, pas les connexions : il reste mesurable meme sur un cas
  // sans aucune preuve reseau.
  const dga: Availability = domainIocs > 0
    ? { state: 'available', reason: null, facts: { domainIocs } }
    : { state: 'unavailable', reason: 'no_domain_iocs', facts: { domainIocs } };

  // Sans aucune connexion projetee, rien de ce qui en depend n'est mesurable, et la
  // raison est unique. Rendre « un seul instant » sur zero ligne serait inventer une
  // mesure qui n'a pas eu lieu.
  if (rows === 0) {
    const none: Availability = { state: 'unavailable', reason: 'no_connections', facts: { rows } };
    return { beacons: none, exfil: none, geo: none, cloud: none, dga };
  }

  const geo = coverage(withGeo, rows, 'no_geo_enrichment', 'partial_geo_enrichment', { withGeo, rows });

  return {
    // `ss` est une photographie, pas un film : sans repetition dans le temps, il n'y a
    // pas de periodicite a mesurer.
    beacons: instants > 1
      ? { state: 'available', reason: null, facts: { instants, rows } }
      : { state: 'unavailable', reason: 'single_instant', facts: { instants, rows } },

    // NULL dit « non mesure », 0 dirait « mesure a zero ». La difference porte tout le
    // sens : zero octet exfiltre n'a jamais ete observe.
    exfil: coverage(withBytes, rows, 'no_byte_counts', 'partial_byte_counts', { withBytes, rows }),

    geo,
    // `cloud` se deduit de `geo_dst->>'org'` : sans enrichissement, la categorie ne peut
    // structurellement jamais valoir autre chose que zero. Ce n'est pas un resultat.
    cloud: { ...geo, facts: { ...geo.facts } },

    dga,
  };
}
