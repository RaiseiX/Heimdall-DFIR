
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as readline from 'readline';
import { v4 as uuidv4 } from 'uuid';

const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || '/app/uploads');
const YARA_BIN   = 'yara';
const YARA_TIMEOUT_MS = 300_000; // 5 min — large RAM dumps need time, but must not block event loop

export interface YaraMatch {
  identifier: string;
  offset:     number;
  data:        string;
  file:       string | null;
}

export interface YaraScanResult {
  matched: boolean;
  strings: YaraMatch[];
  error?:  string;
}

function writeTmpRule(content: string): string {
  const tmpPath = path.join(os.tmpdir(), `fl_yara_${uuidv4()}.yar`);
  fs.writeFileSync(tmpPath, content, { encoding: 'utf8' });
  return tmpPath;
}

// Async spawn wrapper — never blocks the event loop
function spawnAsync(args: string[], timeoutMs: number): Promise<{ stdout: string; stderr: string; status: number | null }> {
  return new Promise((resolve, reject) => {
    const child = spawn(YARA_BIN, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
    child.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`yara timeout after ${timeoutMs}ms`));
    }, timeoutMs);
    child.on('close', (code: number | null) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, status: code });
    });
    child.on('error', (err: Error) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

type LanceurCompilation = (args: string[], timeoutMs: number) => Promise<{ stdout: string; stderr: string; status: number | null }>;

export async function validateRule(
  content: string,
  { lancer = spawnAsync as LanceurCompilation } = {},
): Promise<{ valid: boolean; error?: string; indisponible?: true }> {
  let tmpPath: string | null = null;
  try {
    tmpPath = writeTmpRule(content);
    const result = await lancer([tmpPath, '/dev/null'], 10_000);
    if (result.status === 0) return { valid: true };
    const stderr = (result.stderr || '').trim();
    return { valid: false, error: stderr || 'Règle YARA invalide' };
  } catch (e: any) {
    return { valid: false, error: `yara indisponible : ${e.message}`, indisponible: true };
  } finally {
    if (tmpPath) try { fs.unlinkSync(tmpPath); } catch {}
  }
}

export function parseYaraOutput(stdout: string): YaraMatch[] {
  const matches: YaraMatch[] = [];
  let currentFile: string | null = null;
  for (const line of String(stdout ?? '').split('\n')) {
    const m = line.match(/^0x([0-9a-f]+):(\$\S+):\s*(.+)$/i);
    if (m) {
      matches.push({
        identifier: m[2],
        offset:     parseInt(m[1], 16),
        data:       m[3].trim(),
        file:       currentFile,
      });
      continue;
    }
    const header = line.match(/^(\S+)\s+(\/\S.*)$/);
    if (header) currentFile = header[2].trim();
  }
  return matches;
}

export const SCAN_ROOTS = [
  UPLOAD_DIR,
  path.resolve(process.env.COLLECTIONS_DIR || '/app/collections'),
  path.resolve(process.env.EVIDENCE_DIR || '/app/evidence'),
];

export function isAllowedScanPath(target: string, roots: string[]): boolean {
  if (typeof target !== 'string' || target.length === 0) return false;
  if (!Array.isArray(roots) || roots.length === 0) return false;
  const resolved = path.resolve(target);
  return roots.some((root) => {
    const r = path.resolve(root);
    return resolved === r || resolved.startsWith(r + path.sep);
  });
}

export type YaraScanStatus = 'clean' | 'matches' | 'partial' | 'failed';

export interface YaraScanOutcome {
  status:  YaraScanStatus;
  message: string;
}

export function yaraScanOutcome(input: {
  rulesChecked: number;
  rulesErrored: number;
  matchCount:   number;
}): YaraScanOutcome {
  const { rulesChecked, rulesErrored, matchCount } = input;
  if (matchCount > 0) {
    return { status: 'matches', message: `${matchCount} correspondance${matchCount > 1 ? 's' : ''}` };
  }
  if (rulesChecked === 0) {
    return { status: 'failed', message: 'Aucune règle YARA active — rien n\'a été scanné' };
  }
  if (rulesErrored >= rulesChecked) {
    return { status: 'failed', message: `Scan impossible — les ${rulesChecked} règles ont toutes échoué, aucun octet n'a été lu` };
  }
  if (rulesErrored > 0) {
    return { status: 'partial', message: `Scan partiel — ${rulesErrored} règle${rulesErrored > 1 ? 's' : ''} sur ${rulesChecked} n'ont pas pu être exécutées` };
  }
  return { status: 'clean', message: `Aucune correspondance — ${rulesChecked} règles exécutées` };
}

export async function scanEvidence(
  evidencePath: string,
  ruleContent:  string,
): Promise<YaraScanResult> {

  const resolved = path.resolve(evidencePath);
  if (!isAllowedScanPath(resolved, SCAN_ROOTS)) {
    return { matched: false, strings: [], error: 'Chemin hors de la zone autorisée' };
  }
  if (!fs.existsSync(resolved)) {
    return { matched: false, strings: [], error: 'Fichier evidence introuvable' };
  }

  let isDir = false;
  try { isDir = fs.statSync(resolved).isDirectory(); } catch { isDir = false; }

  let tmpPath: string | null = null;
  try {
    tmpPath = writeTmpRule(ruleContent);
    const args = isDir ? ['-r', '-s', tmpPath, resolved] : ['-s', tmpPath, resolved];
    const result = await spawnAsync(args, YARA_TIMEOUT_MS);

    if (!result) {
      return { matched: false, strings: [], error: 'Pas de résultat' };
    }

    const stdout = result.stdout || '';

    if (result.status === 0 && stdout.trim().length > 0) {
      return { matched: true, strings: parseYaraOutput(stdout) };
    }
    return { matched: false, strings: [] };
  } catch (e: any) {
    return { matched: false, strings: [], error: String(e.message) };
  } finally {
    if (tmpPath) try { fs.unlinkSync(tmpPath); } catch {}
  }
}

export const YARA_MAX_FILE_BYTES = 500 * 1024 * 1024;
const YARA_PASSE_TIMEOUT_MS = 30 * 60 * 1000;
const MAX_CHAINES_PAR_REGLE = 50;
const MAX_STDERR = 2_000_000;

export interface RegleYara { id: string; name: string; content: string }

export interface ResultatPasseYara {
  correspondances:  Map<number, YaraMatch[]>;
  regles_en_erreur: number[];
  regles_lentes:    number[];
  fichiers_sautes:  number;
  erreur?:          string;
  saute?:           string;
}

type Lanceur = (args: string[], delaiMs: number, surLigne: (l: string) => void)
  => Promise<{ status: number | null; stderr: string }>;

export function lecteurSortieYara(maxChaines = MAX_CHAINES_PAR_REGLE) {
  const parRegle = new Map<number, YaraMatch[]>();
  let courante: number | null = null;
  let fichier: string | null = null;
  return {
    ligne(l: string) {
      const tete = /^r(\d+):\S+\s+(.+)$/.exec(l);
      if (tete) {
        courante = Number(tete[1]);
        fichier = tete[2];
        if (!parRegle.has(courante)) parRegle.set(courante, []);
        return;
      }
      const chaine = /^0x([0-9a-f]+):(\$\S*):\s?(.*)$/i.exec(l);
      if (!chaine || courante === null) return;
      const liste = parRegle.get(courante)!;
      if (liste.length < maxChaines) {
        liste.push({ identifier: chaine[2], offset: parseInt(chaine[1], 16), data: chaine[3].trim(), file: fichier });
      }
    },
    resultat: () => parRegle,
  };
}

function indexesSelon(motif: RegExp, stderr: string, fichiers: string[]): number[] {
  const accusees = new Set<number>();
  for (const ligne of stderr.split('\n')) {
    if (!motif.test(ligne)) continue;
    const i = fichiers.findIndex(f => ligne.includes(`${f}(`));
    if (i >= 0) accusees.add(i);
  }
  return [...accusees].sort((a, b) => a - b);
}

export function indexesReglesEnErreur(stderr: string, fichiers: string[]): number[] {
  return indexesSelon(/^error: |\(\d+\): error: /, stderr, fichiers);
}

export function indexesReglesLentes(stderr: string, fichiers: string[]): number[] {
  return indexesSelon(/^warning: |\(\d+\): warning: /, stderr, fichiers);
}

function lancerYara(args: string[], delaiMs: number, surLigne: (l: string) => void): Promise<{ status: number | null; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(YARA_BIN, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const lignes = readline.createInterface({ input: child.stdout });
    lignes.on('line', surLigne);
    let stderr = '';
    child.stderr.on('data', (d: Buffer) => { if (stderr.length < MAX_STDERR) stderr += d.toString(); });
    const minuteur = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`yara timeout after ${delaiMs}ms`));
    }, delaiMs);
    child.on('close', (code: number | null) => {
      clearTimeout(minuteur);
      lignes.close();
      resolve({ status: code, stderr });
    });
    child.on('error', (err: Error) => {
      clearTimeout(minuteur);
      reject(err);
    });
  });
}

export async function scanEvidenceWithRules(
  evidencePath: string,
  regles: RegleYara[],
  { lancer = lancerYara as Lanceur, racines = SCAN_ROOTS, maxOctets = YARA_MAX_FILE_BYTES, delaiMs = YARA_PASSE_TIMEOUT_MS } = {},
): Promise<ResultatPasseYara> {
  const vide = (): ResultatPasseYara => ({ correspondances: new Map(), regles_en_erreur: [], regles_lentes: [], fichiers_sautes: 0 });
  const cible = path.resolve(evidencePath);
  if (!isAllowedScanPath(cible, racines)) return { ...vide(), erreur: 'Chemin hors de la zone autorisée' };

  let stat: fs.Stats;
  try { stat = fs.statSync(cible); } catch { return { ...vide(), erreur: 'Fichier evidence introuvable' }; }
  const dossier = stat.isDirectory();
  if (!dossier && stat.size > maxOctets) {
    return { ...vide(), saute: `fichier > ${Math.round(maxOctets / (1024 * 1024))} Mo` };
  }
  if (regles.length === 0) return vide();

  const lot = uuidv4();
  const fichiers = regles.map((r, i) => {
    const f = path.join(os.tmpdir(), `fl_yara_${lot}_${i}.yar`);
    fs.writeFileSync(f, r.content, { encoding: 'utf8' });
    return f;
  });
  const enErreur = new Set<number>();
  const lentes = new Set<number>();
  const ecartee = (i: number) => enErreur.has(i) || lentes.has(i);
  const regleArgs = () => fichiers.flatMap((f, i) => (ecartee(i) ? [] : [`r${i}:${f}`]));
  const trie = (e: Set<number>) => [...e].sort((a, b) => a - b);
  const bilan = () => ({ regles_en_erreur: trie(enErreur), regles_lentes: trie(lentes) });

  try {
    for (;;) {
      if (enErreur.size + lentes.size >= regles.length) {
        return { ...vide(), ...bilan(), erreur: 'Aucune règle YARA exécutable' };
      }
      let essai: { status: number | null; stderr: string };
      try {
        essai = await lancer(['-e', ...regleArgs(), '/dev/null'], delaiMs, () => {});
      } catch (e: any) {
        return { ...vide(), ...bilan(), erreur: String(e.message) };
      }
      const stderr = essai.stderr || '';
      const nouvellesErreurs = indexesReglesEnErreur(stderr, fichiers).filter(i => !ecartee(i));
      const nouvellesLentes = indexesReglesLentes(stderr, fichiers).filter(i => !ecartee(i));
      nouvellesErreurs.forEach(i => enErreur.add(i));
      nouvellesLentes.forEach(i => lentes.add(i));
      if (nouvellesErreurs.length || nouvellesLentes.length) continue;
      if (essai.status !== 0) {
        return { ...vide(), ...bilan(), erreur: stderr.split('\n').find(Boolean) || `yara a quitté avec le code ${essai.status}` };
      }
      break;
    }

    const lecteur = lecteurSortieYara();
    const args = ['-e', '-s', ...(dossier ? ['-r', '-z', String(maxOctets)] : []), ...regleArgs(), cible];
    let res: { status: number | null; stderr: string };
    try {
      res = await lancer(args, delaiMs, l => lecteur.ligne(l));
    } catch (e: any) {
      return { correspondances: lecteur.resultat(), ...bilan(), fichiers_sautes: 0, erreur: String(e.message) };
    }
    const lignesErr = (res.stderr || '').split('\n');
    const resultat: ResultatPasseYara = {
      correspondances: lecteur.resultat(),
      ...bilan(),
      fichiers_sautes: lignesErr.filter(l => l.startsWith('skipping ')).length,
    };
    if (res.status !== 0) {
      resultat.erreur = lignesErr.find(l => l && !l.startsWith('skipping ')) || `yara a quitté avec le code ${res.status}`;
    }
    return resultat;
  } finally {
    for (const f of fichiers) { try { fs.unlinkSync(f); } catch {} }
  }
}
