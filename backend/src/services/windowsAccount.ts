type Source = 'nom' | 'sid' | 'rid' | 'inconnu';

export interface CompteWindows {
  libelle: string;
  source: Source;
}

const BIEN_CONNUS: Record<string, string> = {
  'S-1-0-0': 'NOBODY',
  'S-1-1-0': 'Everyone',
  'S-1-5-7': 'ANONYMOUS LOGON',
  'S-1-5-11': 'Authenticated Users',
  'S-1-5-17': 'IUSR',
  'S-1-5-18': 'SYSTEM',
  'S-1-5-19': 'LOCAL SERVICE',
  'S-1-5-20': 'NETWORK SERVICE',
  'S-1-5-32-544': 'Administrators',
  'S-1-5-32-545': 'Users',
};

const RID_CONNUS: Record<string, string> = {
  '500': 'Administrator',
  '501': 'Guest',
  '502': 'krbtgt',
  '512': 'Domain Admins',
  '513': 'Domain Users',
  '515': 'Domain Computers',
  '516': 'Domain Controllers',
  '519': 'Enterprise Admins',
};

export function nomExploitable(nom?: string | null): boolean {
  if (typeof nom !== 'string') return false;
  return nom.split('\\').map(s => s.trim()).some(p => p !== '' && p !== '-');
}

export function compteWindows(sid?: string | null, nom?: string | null): CompteWindows {
  if (nomExploitable(nom)) return { libelle: String(nom), source: 'nom' };

  const s = typeof sid === 'string' ? sid.trim().toUpperCase() : '';
  if (!s) return { libelle: '', source: 'inconnu' };

  if (BIEN_CONNUS[s]) return { libelle: BIEN_CONNUS[s], source: 'sid' };

  const rid = /^S-1-5-21-\d+-\d+-\d+-(\d+)$/.exec(s);
  if (rid && RID_CONNUS[rid[1]]) return { libelle: RID_CONNUS[rid[1]], source: 'rid' };

  return { libelle: s, source: 'sid' };
}
