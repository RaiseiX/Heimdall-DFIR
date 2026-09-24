const fs = require('fs');
const os = require('os');
const path = require('path');
const { parse } = require('csv-parse/sync');

const SEPARATEUR = Buffer.from('/');
const utf8Strict = new TextDecoder('utf-8', { fatal: true });

function estUtf8(octets) {
  try { utf8Strict.decode(octets); return true; } catch { return false; }
}

function fichiersNonUtf8(dossier, extension) {
  const suffixe = extension.toLowerCase();
  const trouves = [];
  const parcourir = rep => {
    let entrees;
    try { entrees = fs.readdirSync(rep, { withFileTypes: true, encoding: 'buffer' }); } catch { return; }
    for (const e of entrees) {
      const chemin = Buffer.concat([rep, SEPARATEUR, e.name]);
      if (e.isDirectory()) parcourir(chemin);
      else if (e.isFile() && !estUtf8(chemin)
        && chemin.subarray(-suffixe.length).toString('latin1').toLowerCase() === suffixe) trouves.push(chemin);
    }
  };
  parcourir(Buffer.from(dossier));
  return trouves.sort(Buffer.compare);
}

function preparerAlias(fichiers, dossierAlias, extension) {
  fs.mkdirSync(dossierAlias, { recursive: true });
  return fichiers.map((octets, i) => {
    const alias = path.join(dossierAlias, `${i}${extension}`);
    const st = fs.statSync(octets);
    fs.symlinkSync(octets, alias);
    fs.lutimesSync(alias, st.atime, st.mtime);
    return { alias, chemin: octets.toString('utf8'), octets: octets.toString('hex') };
  });
}

function cellule(valeur) {
  return /[",\r\n]/.test(valeur) ? `"${valeur.replace(/"/g, '""')}"` : valeur;
}

function retablirCheminsSource(csv, alias, { colonne = 'SourceFile', colonneOctets = 'SourceFileBytes' } = {}) {
  const texte = fs.readFileSync(csv, 'utf8');
  const bom = texte.startsWith('﻿') ? '﻿' : '';
  const fin = texte.includes('\r\n') ? '\r\n' : '\n';
  const [entete, ...lignes] = parse(texte.slice(bom.length), { relax_column_count: true });
  const index = entete.indexOf(colonne);
  const parAlias = new Map(alias.map(a => [a.alias, a]));
  const sortie = [[...entete, colonneOctets], ...lignes.map(l => {
    const a = parAlias.get(l[index]);
    if (!a) return [...l, ''];
    const copie = [...l];
    copie[index] = a.chemin;
    return [...copie, a.octets];
  })];
  fs.writeFileSync(csv, bom + sortie.map(l => l.map(cellule).join(',')).join(fin) + fin);
}

async function reprendreNomsNonUtf8({ dossier, extension, csv, lancer, tmp = os.tmpdir() }) {
  const fichiers = fichiersNonUtf8(dossier, extension);
  if (fichiers.length === 0) return { repris: [] };
  const dossierAlias = fs.mkdtempSync(path.join(tmp, 'heimdall-alias-'));
  try {
    const alias = preparerAlias(fichiers, dossierAlias, extension);
    await lancer(dossierAlias);
    retablirCheminsSource(csv, alias);
    return { repris: alias.map(a => a.chemin) };
  } finally {
    fs.rmSync(dossierAlias, { recursive: true, force: true });
  }
}

const CSV_LNK_NON_UTF8 = 'lnk_nonutf8_results.csv';

function reprendreLnkNonUtf8({ dossier, sortie, zimmermanDir, lancerOutil }) {
  return reprendreNomsNonUtf8({
    dossier,
    extension: '.lnk',
    csv: path.join(sortie, CSV_LNK_NON_UTF8),
    lancer: dossierAlias => lancerOutil(['dotnet', path.join(zimmermanDir, 'LECmd.dll'), '-d', dossierAlias, '--csv', sortie, '--csvf', CSV_LNK_NON_UTF8]),
  });
}

module.exports = { fichiersNonUtf8, preparerAlias, retablirCheminsSource, reprendreNomsNonUtf8, reprendreLnkNonUtf8 };
