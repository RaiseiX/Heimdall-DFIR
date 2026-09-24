// Filet de securite d'execution pour network_connections.
//
// db/init.sql est le schema canonique mais ne tourne qu'a la premiere initialisation
// d'un volume vide ; db/migrations/ couvre les mises a niveau. Cette liste reaffirme
// la forme dont depend la projection, pour qu'un deploiement dont le volume est
// anterieur a la colonne l'obtienne quand meme.
//
// Pourquoi `evidence_id` : la table n'en avait pas. Avec trois collectes dans un cas,
// une connexion ne pouvait pas dire d'ou elle venait — ni etre remplacee au reparsing
// d'une seule collecte sans emporter celles des autres. C'est exactement le defaut
// qui a fait disparaitre 254 lignes Hayabusa.
//
// L'ordre compte : la colonne avant l'index qui s'y appuie.
const NETWORK_CONNECTIONS_STATEMENTS = [
  `ALTER TABLE network_connections
     ADD COLUMN IF NOT EXISTS evidence_id UUID REFERENCES evidence(id) ON DELETE CASCADE`,

  // La projection purge puis reecrit par (case_id, evidence_id) : c'est le couple que
  // l'index doit servir.
  `CREATE INDEX IF NOT EXISTS idx_netconn_case_evidence
     ON network_connections(case_id, evidence_id)`,

  // Pourquoi `process` et `socket_state` : les deux vivaient dans `notes`, colles par
  // un separateur, parce qu'aucune colonne ne les portait. Un champ libre ne se relit
  // pas — la carte exposait une cle `processes` restee vide sur les seize aretes
  // machines, et `buildNetworkGraph` passait `null` en dur pour cette source.
  //
  // Mesure du 2026-08-26 sur CASE-2026-001 : `linkType` rend `web` sur 142 aretes sur
  // 145, quand le processus rend douze valeurs distinctes. C'est la seule dimension de
  // la donnee reseau qui discrimine assez pour porter une couleur.
  // Pourquoi `src_host` : les 177 lignes reseau du cas de reference portent toutes
  // `host = Dlinux`, et la carte montrait deux noeuds — l'IPv6 publique et l'IPv4
  // privee de la meme machine. Deux etoiles la ou il y a une machine, et aucun degre
  // juste. Avec le nom, `composeHostAddress` rend la forme `Hote (adresse)` que le
  // resolveur replie deja, sans perdre les adresses.
  `ALTER TABLE network_connections
     ADD COLUMN IF NOT EXISTS process      TEXT,
     ADD COLUMN IF NOT EXISTS socket_state TEXT,
     ADD COLUMN IF NOT EXISTS src_host     TEXT`,

  // Reprise des lignes deja projetees, pour ne pas exiger un reparsing.
  //
  // Trois gardes, parce qu'on relit un champ libre : seulement les lignes issues de la
  // projection (`evidence_id` non nul), seulement celles dont les colonnes sont encore
  // vides, et seulement la forme que la projection ecrit — `ETAT` ou `ETAT · processus`.
  // Une note libre venue d'un import PCAP ou CSV ne correspond pas et reste intacte.
  `UPDATE network_connections
      SET socket_state = split_part(notes, ' · ', 1),
          process      = NULLIF(split_part(notes, ' · ', 2), '')
    WHERE evidence_id IS NOT NULL
      AND process IS NULL AND socket_state IS NULL
      AND notes ~ '^[A-Z][A-Z0-9-]*( · [^ ].*)?$'`,
];

// Si ces colonnes sont deja la, le lot est saute sans prendre aucun verrou — un
// redemarrage pendant une longue lecture ne peut donc pas bloquer l'ingestion pour
// un travail qui n'existe pas.
const NETWORK_CONNECTIONS_EXPECTED_COLUMNS = ['evidence_id', 'process', 'socket_state', 'src_host'];

module.exports = { NETWORK_CONNECTIONS_STATEMENTS, NETWORK_CONNECTIONS_EXPECTED_COLUMNS };
