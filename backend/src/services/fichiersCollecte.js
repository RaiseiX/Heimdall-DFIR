const fs = require('fs');

const CHEMIN_MAX = 4096;
const LISTE_MAX = 50000;
const PROFONDEUR_MAX = 64;
const SEPARATEUR = Buffer.from('/');
const utf8Strict = new TextDecoder('utf-8', { fatal: true });

function erreur(code) {
  return Object.assign(new Error(code), { code });
}

function estUtf8(octets) {
  try { utf8Strict.decode(octets); return true; } catch { return false; }
}

function cheminRelatif({ chemin, octets } = {}) {
  const avecChemin = typeof chemin === 'string';
  const avecOctets = typeof octets === 'string';
  if (avecChemin === avecOctets) throw erreur('chemin');
  if (avecOctets && (!/^(?:[0-9a-f]{2})+$/i.test(octets) || octets.length > CHEMIN_MAX * 2)) throw erreur('chemin');
  const rel = avecOctets ? Buffer.from(octets, 'hex') : Buffer.from(chemin, 'utf8');
  if (!rel.length || rel.length > CHEMIN_MAX || rel.includes(0) || rel[0] === SEPARATEUR[0]) throw erreur('chemin');
  if (rel.toString('latin1').split('/').some(s => s === '' || s === '.' || s === '..')) throw erreur('chemin');
  return rel;
}

async function racineReelle(racine) {
  return Buffer.from(await fs.promises.realpath(racine));
}

async function resoudre(racine, rel) {
  const base = await racineReelle(racine);
  const absolu = Buffer.concat([base, SEPARATEUR, rel]);
  let st;
  try {
    st = await fs.promises.lstat(absolu);
  } catch (e) {
    if (e.code === 'ENOENT' || e.code === 'ENOTDIR') throw erreur('introuvable');
    throw e;
  }
  if (st.isSymbolicLink()) throw erreur('lien');
  if (!st.isFile()) throw erreur('special');
  const reel = await fs.promises.realpath(absolu, { encoding: 'buffer' });
  const prefixe = Buffer.concat([base, SEPARATEUR]);
  if (!reel.subarray(0, prefixe.length).equals(prefixe)) throw erreur('hors_racine');
  if (st.nlink > 1) throw erreur('lien_dur');
  return reel;
}

async function listerFichiers(racine, { statutDe, max = LISTE_MAX, filtre = '' } = {}) {
  const base = await racineReelle(racine);
  const aiguille = String(filtre || '').toLowerCase();
  const fichiers = [];
  let total = 0;

  const parcourir = async (rel, profondeur) => {
    if (profondeur > PROFONDEUR_MAX) return;
    let entrees;
    try {
      entrees = await fs.promises.readdir(rel.length ? Buffer.concat([base, SEPARATEUR, rel]) : base, { withFileTypes: true, encoding: 'buffer' });
    } catch {
      return;
    }
    for (const e of entrees) {
      const r = rel.length ? Buffer.concat([rel, SEPARATEUR, e.name]) : Buffer.from(e.name);
      if (e.isDirectory()) { await parcourir(r, profondeur + 1); continue; }
      const chemin = r.toString('utf8');
      if (aiguille && !chemin.toLowerCase().includes(aiguille)) continue;
      total++;
      if (fichiers.length >= max) continue;
      const entree = estUtf8(r) ? { chemin } : { chemin, octets: r.toString('hex') };
      if (e.isSymbolicLink()) fichiers.push({ ...entree, type: 'lien' });
      else if (!e.isFile()) fichiers.push({ ...entree, type: 'special' });
      else {
        const st = await fs.promises.lstat(Buffer.concat([base, SEPARATEUR, r]));
        fichiers.push({ ...entree, type: 'fichier', taille: st.size, mtime: st.mtime.toISOString(), ...statutDe(chemin) });
      }
    }
  };

  await parcourir(Buffer.alloc(0), 0);
  fichiers.sort((a, b) => (a.chemin < b.chemin ? -1 : a.chemin > b.chemin ? 1 : 0));
  return { fichiers, total, tronque: total > fichiers.length };
}

function statutParMotifs(types, correspond) {
  return rel => {
    const trouve = types.find(([, motifs]) => motifs.some(m => correspond(rel, m)));
    return { lu: trouve ? trouve[0] : null };
  };
}

function statutParRegistre(lignes, cle) {
  const index = new Map(lignes.map(l => [l.relative_path, l]));
  return rel => {
    const l = index.get(cle(rel));
    if (!l) return { lu: null, statut: null };
    const lu = l.status === 'parsed' || l.status === 'parsed_empty';
    return { lu: lu ? (l.detected_type || l.parser_name || 'catscale') : null, statut: l.status };
  };
}

module.exports = { cheminRelatif, resoudre, listerFichiers, statutParMotifs, statutParRegistre };
