const DECLARATION = /^[ \t]*((?:(?:private|global)\s+)*)rule\s+(\w+)/gm;
const PREMIERE_REGLE = /^[ \t]*(?:(?:private|global)\s+)*rule\s/m;
const TOURS_MAX = 6;

function definitionRegle(content, nom) {
  const m = new RegExp(`^[ \\t]*((?:(?:private|global)\\s+)*)rule\\s+${nom}\\b`, 'm').exec(content);
  if (!m || /global/.test(m[1])) return null;
  const debutDeclaration = m.index + m[0].length - m[0].trimStart().length;
  const debut = content.indexOf('{', m.index);
  if (debut < 0) return null;
  let profondeur = 0;
  for (let i = debut; i < content.length; i++) {
    if (content[i] === '{') profondeur++;
    else if (content[i] === '}' && --profondeur === 0) {
      const texte = content.slice(debutDeclaration, i + 1);
      return /private/.test(m[1]) ? texte : `private ${texte}`;
    }
  }
  return null;
}

function identifiantsManquants(erreur) {
  return [...new Set([...String(erreur || '').matchAll(/undefined identifier "(\w+)"/g)].map(m => m[1]))];
}

function nomDe(definition) {
  return /rule\s+(\w+)/.exec(definition)[1];
}

function ordreDesDependances(definitions) {
  const noms = definitions.map(nomDe);
  const dependances = definitions.map((d, i) => noms.filter((n, j) => j !== i && new RegExp(`\\b${n}\\b`).test(d)));
  const poses = new Set();
  const ordre = [];
  const restant = definitions.map((_, i) => i);
  while (restant.length) {
    const k = restant.findIndex(i => dependances[i].every(n => poses.has(n)));
    const [i] = restant.splice(k < 0 ? 0 : k, 1);
    ordre.push(definitions[i]);
    poses.add(noms[i]);
  }
  return ordre;
}

function insererDefinitions(content, definitions) {
  const m = PREMIERE_REGLE.exec(content);
  const i = m ? m.index : 0;
  return `${content.slice(0, i)}${ordreDesDependances(definitions).join('\n\n')}\n\n${content.slice(i)}`;
}

function indexerDefinitions(regles) {
  const index = new Map();
  for (const r of regles) {
    for (const [, prefixe, nom] of r.content.matchAll(DECLARATION)) {
      if (/global/.test(prefixe)) continue;
      const texte = definitionRegle(r.content, nom);
      if (!texte) continue;
      if (!index.has(nom)) index.set(nom, new Map());
      const formes = index.get(nom);
      if (!formes.has(texte)) formes.set(texte, []);
      formes.get(texte).push(r.name);
    }
  }
  return index;
}

async function reparerUne(regle, erreur, definitions, valider) {
  let manquants = identifiantsManquants(erreur);
  const ajoutees = [];
  const origine = [];
  const textes = [];
  for (let tour = 0; tour < TOURS_MAX; tour++) {
    for (const nom of manquants) {
      if (ajoutees.includes(nom)) return { raison: erreur };
      const formes = definitions.get(nom);
      if (!formes) return { raison: `${nom} absent du catalogue` };
      if (formes.size > 1) return { raison: `définitions divergentes de ${nom}` };
      const [[texte, auteurs]] = [...formes];
      ajoutees.push(nom);
      origine.push(auteurs[0]);
      textes.push(texte);
    }
    const contenu = insererDefinitions(regle.content, textes);
    const verification = await valider(contenu);
    if (verification.valid) return { contenu, ajoutees, origine };
    erreur = verification.error;
    manquants = identifiantsManquants(erreur);
    if (manquants.length === 0) return { raison: erreur };
  }
  return { raison: erreur };
}

async function reparerReglesPrivees({ lister, valider, enregistrer, journaliser, appliquer = false }) {
  const regles = await lister();
  const definitions = indexerDefinitions(regles);
  const reparables = [];
  const nonReparables = [];
  const contenus = new Map();

  for (const r of regles.filter(x => !x.is_active)) {
    const v = await valider(r.content);
    if (v.valid || v.indisponible || identifiantsManquants(v.error).length === 0) continue;
    const issue = await reparerUne(r, v.error, definitions, valider);
    if (issue.raison) { nonReparables.push({ id: r.id, name: r.name, raison: issue.raison }); continue; }
    reparables.push({ id: r.id, name: r.name, ajoutees: issue.ajoutees, origine: issue.origine });
    contenus.set(r.id, issue.contenu);
  }

  const bilan = { reparables, non_reparables: nonReparables, reparees: [] };
  if (!appliquer || reparables.length === 0) return bilan;
  for (const r of reparables) await enregistrer(r.id, contenus.get(r.id));
  await journaliser({ reparees: reparables, non_reparables: nonReparables });
  return { ...bilan, reparees: reparables.map(r => r.id) };
}

module.exports = { definitionRegle, identifiantsManquants, insererDefinitions, reparerReglesPrivees };
