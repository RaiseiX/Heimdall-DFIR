export const EVENEMENTS_WINDOWS = [4624, 4625, 4648, 4768, 4769, 4771, 4776];
export const SOURCES_LINUX = ['catscale_auth', 'catscale_logon', 'catscale_failed_login'];
export const GROUPES_MAX = 20000;

const COMPTES_SYSTEME = new Set(['system', 'local service', 'network service', 'anonymous logon', '-', '']);
const SOURCES_VIDES = new Set(['-', '', '::1', '127.0.0.1', '0.0.0.0', 'localhost']);
const TYPES_SERVICE = new Set(['0', '5']);

function champPayload(nom: string): string {
  return `substring(raw->>'Payload' from '"@Name":\\s*"${nom}",\\s*"#text":\\s*"([^"]*)"')`;
}

export function authGraphSql(): string {
  return `
    SELECT artifact_type, event_id, machine, utilisateur, domaine, ip, poste, type_logon,
           statut_code, serveur_cible, service, categorie,
           COUNT(*)::int AS nb, MIN(timestamp) AS premier, MAX(timestamp) AS dernier
      FROM (
        SELECT artifact_type, event_id,
               NULLIF(COALESCE(raw->>'Computer', host_name), '') AS machine,
               CASE WHEN artifact_type = 'evtx'
                    THEN COALESCE(${champPayload('TargetUserName')}, NULLIF(raw->>'UserName', ''))
                    ELSE COALESCE(raw->>'username', raw->>'user', user_name) END AS utilisateur,
               CASE WHEN artifact_type = 'evtx' THEN ${champPayload('TargetDomainName')} END AS domaine,
               CASE WHEN artifact_type = 'evtx' THEN ${champPayload('IpAddress')}
                    ELSE COALESCE(raw->>'source_ip', raw->>'from', src_ip::text) END AS ip,
               CASE WHEN artifact_type = 'evtx'
                    THEN COALESCE(${champPayload('WorkstationName')}, ${champPayload('Workstation')}, NULLIF(raw->>'RemoteHost', '')) END AS poste,
               CASE WHEN artifact_type = 'evtx'
                    THEN COALESCE(${champPayload('LogonType')}, substring(raw->>'PayloadData1' from 'LogonType (\\d+)')) END AS type_logon,
               CASE WHEN artifact_type = 'evtx' THEN ${champPayload('Status')} END AS statut_code,
               CASE WHEN artifact_type = 'evtx' AND event_id = 4648 THEN ${champPayload('TargetServerName')} END AS serveur_cible,
               CASE WHEN artifact_type = 'evtx' AND event_id = 4769 THEN ${champPayload('ServiceName')} END AS service,
               CASE WHEN artifact_type <> 'evtx' THEN COALESCE(raw->>'category', raw->>'type') END AS categorie,
               timestamp
          FROM collection_timeline
         WHERE case_id = $1
           AND evidence_id = $2
           AND ((artifact_type = 'evtx' AND event_id = ANY($3::int[])) OR artifact_type = ANY($4::text[]))
      ) e
     GROUP BY artifact_type, event_id, machine, utilisateur, domaine, ip, poste, type_logon,
              statut_code, serveur_cible, service, categorie
     LIMIT ${GROUPES_MAX + 1}`;
}

export type Statut = 'succes' | 'echec' | 'explicite' | 'inconnu';

export interface GroupeBrut {
  artifact_type: string;
  event_id: number | null;
  machine: string | null;
  utilisateur: string | null;
  domaine: string | null;
  ip: string | null;
  poste: string | null;
  type_logon: string | null;
  statut_code: string | null;
  serveur_cible: string | null;
  service: string | null;
  categorie: string | null;
  nb: number;
  premier: string | Date | null;
  dernier: string | Date | null;
}

export interface Authentification {
  utilisateur: string;
  machine: string;
  source: string | null;
  typeLogon: string | null;
  statut: Statut;
  eventId: number | null;
  artifactType: string;
  nb: number;
  premier: string | null;
  dernier: string | null;
}

export type RaisonIgnoree = 'compte_machine' | 'compte_systeme' | 'sans_identite' | 'logon_service' | 'hors_perimetre';

function texte(v: unknown): string {
  return v === null || v === undefined ? '' : String(v).trim();
}

function iso(v: string | Date | null): string | null {
  if (!v) return null;
  const d = v instanceof Date ? v : new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

export function normaliserSource(valeur: string | null): string | null {
  let s = texte(valeur);
  const hote = /^(.*?)\s*\(([^)]*)\)\s*$/.exec(s);
  if (hote) s = texte(hote[2]) && !SOURCES_VIDES.has(texte(hote[2]).toLowerCase()) ? texte(hote[2]) : texte(hote[1]);
  if (s.toLowerCase().startsWith('::ffff:')) s = s.slice(7);
  return SOURCES_VIDES.has(s.toLowerCase()) ? null : s;
}

function nomMachine(valeur: string | null): string {
  const s = texte(valeur).replace(/\$$/, '');
  return s.includes('/') ? texte(s.split('/').pop()) : s;
}

export function identite(utilisateur: string | null, domaine: string | null): string | null {
  const u = texte(utilisateur);
  if (!u) return null;
  if (u.includes('\\')) {
    const [d, n] = u.split('\\', 2);
    return texte(n) ? `${texte(d).toUpperCase()}\\${texte(n)}` : null;
  }
  const arobase = u.indexOf('@');
  if (arobase > 0) return `${u.slice(arobase + 1).toUpperCase()}\\${u.slice(0, arobase)}`;
  const d = texte(domaine);
  return d && d !== '-' ? `${d.toUpperCase()}\\${u}` : u;
}

export function raisonIgnoree(ident: string | null): RaisonIgnoree | null {
  if (!ident) return 'sans_identite';
  const nom = ident.includes('\\') ? ident.split('\\')[1] : ident;
  if (nom.endsWith('$')) return 'compte_machine';
  const bas = nom.toLowerCase();
  if (COMPTES_SYSTEME.has(bas) || /^(dwm|umfd)-\d+$/.test(bas)) return 'compte_systeme';
  return null;
}

export function statutDe(g: Pick<GroupeBrut, 'artifact_type' | 'event_id' | 'statut_code' | 'categorie'>): Statut | null {
  if (g.artifact_type === 'evtx') {
    const code = texte(g.statut_code).toLowerCase();
    switch (g.event_id) {
      case 4624: return 'succes';
      case 4625: return 'echec';
      case 4771: return 'echec';
      case 4648: return 'explicite';
      case 4768:
      case 4769:
      case 4776:
        if (!code) return 'inconnu';
        return /^0x0+$/.test(code) ? 'succes' : 'echec';
      default: return null;
    }
  }
  const c = texte(g.categorie);
  if (g.artifact_type === 'catscale_auth') {
    if (c === 'ssh_login') return 'succes';
    if (c === 'ssh_failed' || c === 'ssh_invalid') return 'echec';
    return null;
  }
  if (g.artifact_type === 'catscale_logon') return c === 'logon' ? 'succes' : null;
  if (g.artifact_type === 'catscale_failed_login') return 'echec';
  return null;
}

export function interpreter(g: GroupeBrut, { inclureServices = false } = {}): { auth: Authentification | null; raison: RaisonIgnoree | null } {
  const statut = statutDe(g);
  if (!statut) return { auth: null, raison: 'hors_perimetre' };
  const ident = identite(g.utilisateur, g.domaine);
  const raison = raisonIgnoree(ident);
  if (raison) return { auth: null, raison };
  const typeLogon = texte(g.type_logon) || null;
  if (!inclureServices && typeLogon && TYPES_SERVICE.has(typeLogon)) return { auth: null, raison: 'logon_service' };

  let machine = nomMachine(g.machine);
  let source = normaliserSource(g.ip) || normaliserSource(g.poste);
  if (g.artifact_type === 'evtx' && g.event_id === 4648) {
    const cible = nomMachine(g.serveur_cible);
    source = nomMachine(g.machine) || null;
    machine = cible && !SOURCES_VIDES.has(cible.toLowerCase()) ? cible : nomMachine(g.machine);
  }
  if (g.artifact_type === 'evtx' && g.event_id === 4769) {
    const service = nomMachine(g.service);
    if (service && service.toLowerCase() !== 'krbtgt') machine = service;
  }
  if (!machine) return { auth: null, raison: 'sans_identite' };

  return {
    auth: {
      utilisateur: ident as string,
      machine,
      source,
      typeLogon,
      statut,
      eventId: g.event_id,
      artifactType: g.artifact_type,
      nb: Number(g.nb) || 0,
      premier: iso(g.premier),
      dernier: iso(g.dernier),
    },
    raison: null,
  };
}

interface Compteurs { succes: number; echec: number; explicite: number; inconnu: number }

function vides(): Compteurs {
  return { succes: 0, echec: 0, explicite: 0, inconnu: 0 };
}

function etendre(courant: { premier: string | null; dernier: string | null }, a: Authentification) {
  if (a.premier && (!courant.premier || a.premier < courant.premier)) courant.premier = a.premier;
  if (a.dernier && (!courant.dernier || a.dernier > courant.dernier)) courant.dernier = a.dernier;
}

export function construireGraphe(groupes: GroupeBrut[], options: { inclureServices?: boolean } = {}) {
  const tronque = groupes.length > GROUPES_MAX;
  const retenus = tronque ? groupes.slice(0, GROUPES_MAX) : groupes;
  const ignores: Record<RaisonIgnoree, number> = {
    compte_machine: 0, compte_systeme: 0, sans_identite: 0, logon_service: 0, hors_perimetre: 0,
  };
  const noeuds = new Map<string, any>();
  const aretes = new Map<string, any>();

  const noeud = (type: 'utilisateur' | 'machine', libelle: string) => {
    const id = `${type === 'utilisateur' ? 'u' : 'm'}:${libelle.toLowerCase()}`;
    if (!noeuds.has(id)) {
      noeuds.set(id, { id, type, libelle, total: 0, ...vides(), voisins: new Set<string>(), premier: null, dernier: null });
    }
    return noeuds.get(id);
  };

  for (const g of retenus) {
    const { auth, raison } = interpreter(g, options);
    if (!auth) {
      if (raison) ignores[raison] += Number(g.nb) || 0;
      continue;
    }
    const u = noeud('utilisateur', auth.utilisateur);
    const m = noeud('machine', auth.machine);
    const cle = `${u.id}|${m.id}`;
    if (!aretes.has(cle)) {
      aretes.set(cle, {
        id: cle, source: u.id, cible: m.id, utilisateur: u.libelle, machine: m.libelle,
        total: 0, ...vides(), typesLogon: {}, sources: {}, eventIds: {}, artifactTypes: new Set<string>(),
        premier: null, dernier: null,
      });
    }
    const a = aretes.get(cle);
    for (const n of [u, m, a]) {
      n.total += auth.nb;
      n[auth.statut] += auth.nb;
      etendre(n, auth);
    }
    u.voisins.add(m.id);
    m.voisins.add(u.id);
    if (auth.typeLogon) a.typesLogon[auth.typeLogon] = (a.typesLogon[auth.typeLogon] || 0) + auth.nb;
    if (auth.source) a.sources[auth.source] = (a.sources[auth.source] || 0) + auth.nb;
    if (auth.eventId !== null && auth.eventId !== undefined) a.eventIds[auth.eventId] = (a.eventIds[auth.eventId] || 0) + auth.nb;
    a.artifactTypes.add(auth.artifactType);
  }

  const listeNoeuds = [...noeuds.values()].map(({ voisins, ...n }) => ({ ...n, degre: voisins.size }));
  const listeAretes = [...aretes.values()]
    .map(({ artifactTypes, ...a }) => ({ ...a, artifactTypes: [...artifactTypes].sort() }))
    .sort((x, y) => y.echec - x.echec || y.total - x.total);

  return {
    noeuds: listeNoeuds,
    aretes: listeAretes,
    stats: {
      utilisateurs: listeNoeuds.filter((n) => n.type === 'utilisateur').length,
      machines: listeNoeuds.filter((n) => n.type === 'machine').length,
      aretes: listeAretes.length,
      evenements: listeAretes.reduce((s, a) => s + a.total, 0),
      echecs: listeAretes.reduce((s, a) => s + a.echec, 0),
      ignores,
    },
    tronque,
  };
}
