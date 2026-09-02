// Type d'un lien de la carte reseau.
//
// Les 116 liens portaient tous `type: undefined`. Sans type, ni la couleur par service
// ni le score de role ne sont possibles, et un lien vers un controleur de domaine se
// dessine exactement comme un lien vers un site web.
//
// Vocabulaire ferme et court : un type qu'on ne sait pas nommer vaut mieux qu'un type
// invente. `unknown` en fait partie a part entiere — l'ecran peut le nommer, ce qu'il
// ne pourrait pas faire d'un `undefined`.

export const LINK_TYPES = [
  'web', 'directory', 'file', 'remote', 'database', 'dns', 'mail',
  'messaging', 'ephemeral', 'other', 'unknown',
] as const;

export type LinkType = typeof LINK_TYPES[number];

// `directory` est separe du reste parce que c'est lui qui porte l'inference de role :
// Kerberos 88, LDAP 389 et LDAPS 636 sont ce qui distingue un controleur de domaine
// d'un serveur quelconque. Les noyer dans « autre » supprimerait la seule inference
// de role de la carte.
const BY_PORT: Readonly<Record<number, LinkType>> = Object.freeze({
  80: 'web', 443: 'web', 8080: 'web', 8443: 'web', 8000: 'web',
  88: 'directory', 389: 'directory', 636: 'directory', 464: 'directory', 3268: 'directory',
  21: 'file', 139: 'file', 445: 'file', 2049: 'file', 548: 'file',
  22: 'remote', 23: 'remote', 3389: 'remote', 5900: 'remote', 5985: 'remote', 5986: 'remote',
  1433: 'database', 3306: 'database', 5432: 'database', 1521: 'database', 27017: 'database', 6379: 'database',
  53: 'dns',
  25: 'mail', 110: 'mail', 143: 'mail', 465: 'mail', 587: 'mail', 993: 'mail', 995: 'mail',
  1883: 'messaging', 8883: 'messaging', 5222: 'messaging', 5223: 'messaging',
});

// Plage ephemere de Linux (`ip_local_port_range` par defaut). Un port ephemere en
// destination signale une connexion observee depuis l'autre bout, pas un service :
// le nommer evite de le compter comme un service inconnu de plus.
const EPHEMERAL_FROM = 32768;

export function linkType(port?: number | string | null, protocol?: string | null): LinkType {
  const n = port === null || port === undefined || port === '' ? NaN : Number(port);
  if (Number.isFinite(n) && n > 0) {
    const known = BY_PORT[n];
    if (known) return known;
    if (n >= EPHEMERAL_FROM) return 'ephemeral';
    return 'other';
  }

  const p = String(protocol ?? '').trim().toLowerCase();
  if (p === 'http' || p === 'https') return 'web';
  return 'unknown';
}
