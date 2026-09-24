// Les événements attachés à un nœud de la carte réseau.
//
// Extraite de la route pour être exécutable par un test contre un vrai Postgres —
// son défaut ne se voyait pas à la lecture, seulement à l'écran.
//
// ── Le défaut, signalé depuis l'interface le 2026-09-14 ─────────────────────
//
// Le nœud `Dlinux` affichait « 27 connexions » et « Aucun événement trouvé ». La
// requête était bornée à quatre types d'artefacts, tous Windows :
//
//     AND ct.artifact_type IN ('sqle', 'evtx', 'hayabusa', 'srum')
//
// Un hôte Linux n'en produit aucun. Mesuré : `Dlinux` porte 3 034 230 lignes, dont
// **zéro** tombe dans cette liste. L'onglet était vide par construction.
//
// Cette liste ne servait qu'à borner le coût : les conditions de correspondance
// ci-dessous sont déjà génériques. Elle a rouillé — personne ne l'a étendue quand
// le support Linux est arrivé, et rien ne le signalait.
//
// ── Le critère qui la remplace ───────────────────────────────────────────────
//
// De principe plutôt qu'énumératif, pour qu'il ne rouille pas à son tour : un
// panneau de nœud montre des ÉVÉNEMENTS, et une ligne d'inventaire sans
// horodatage n'en est pas un. C'est la même distinction que porte `timestamp_kind`
// dans la SuperTimeline.
//
// Coût mesuré sur la base réelle : 9,6 ms, grâce à l'index (case_id, timestamp
// DESC). Un nœud Windows n'y gagne que 130 lignes — des LNK et des jumplists,
// c'est-à-dire de l'activité utilisateur, pas du bruit.

export function nodeEventsSql(): string {
  return `
      SELECT
        ct.timestamp,
        ct.artifact_type,
        ct.description,
        ct.source,
        ct.host_name,
        ct.user_name,
        ct.event_id,
        ct.mitre_technique_id,
        ct.mitre_tactic,
        NULLIF(TRIM(ct.raw->>'Image'),             '') AS process_name,
        COALESCE(ct.raw->>'DestinationPort', ct.raw->>'RemotePort', ct.raw->>'DstPort') AS dst_port,
        COALESCE(ct.raw->>'Protocol', ct.raw->>'proto', ct.raw->>'Transport')           AS protocol,
        ct.raw->>'URL'   AS url,
        COALESCE(
          ct.raw->>'RemoteHost', ct.raw->>'RemoteAddress',
          ct.raw->>'DestinationHostname', ct.raw->>'dst_host'
        ) AS remote_host,
        ct.src_ip::text AS src_ip,
        ct.dst_ip::text AS dst_ip
      FROM collection_timeline ct
      WHERE ct.case_id = $1
        AND ct.timestamp IS NOT NULL
        AND (
          ct.raw->>'SourceIp'            = $2 OR
          ct.raw->>'DestinationIp'       = $2 OR
          ct.raw->>'DestinationHostname' = $2 OR
          ct.raw->>'RemoteHost'          = $2 OR
          ct.raw->>'RemoteAddress'       = $2 OR
          ct.raw->>'DstIP'               = $2 OR
          ct.raw->>'dst_ip'              = $2 OR
          ct.raw->>'id.resp_h'           = $2 OR
          ct.raw->>'Computer'            = $2 OR
          ct.host_name                   = $2 OR
          ct.src_ip::text                = $2 OR
          ct.dst_ip::text                = $2 OR
          (ct.artifact_type = 'sqle'
           AND ct.raw->>'URL' IS NOT NULL
           AND ct.raw->>'URL' ILIKE '%' || $2 || '%')
        )
      ORDER BY ct.timestamp DESC
      LIMIT $3`;
}
