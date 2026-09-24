export const SECTIONS_RAPPORT = [
  'executive_summary', 'key_findings', 'ioc_analysis',
  'mitre_analysis', 'timeline_narrative', 'recommendations',
];

export const NOTE_ANALYSTE = 'analyst_note';

export function decouperEntrees(markdown) {
  const texte = String(markdown || '').replace(/\r\n/g, '\n');
  const morceaux = texte.split(/^(?=## )/m);
  const entrees = [];
  morceaux.forEach((morceau, i) => {
    const propre = morceau.trim();
    if (!propre) return;
    const titre = propre.startsWith('## ') ? propre.split('\n', 1)[0].slice(3).trim() : null;
    entrees.push({ id: `e${i}`, titre, texte: propre });
  });
  return entrees;
}

export function separateur(existant) {
  if (!existant) return '';
  if (existant.endsWith('\n\n')) return '';
  return existant.endsWith('\n') ? '\n' : '\n\n';
}

export function insererDansSection(doc, cle, texte) {
  const bloc = String(texte || '').trim();
  if (!doc || !bloc) return false;
  const y = doc.getText(cle);
  doc.transact(() => {
    y.insert(y.length, separateur(y.toString()) + bloc);
  });
  return true;
}

export function preRemplir(doc, narratif, { forcer = [] } = {}) {
  const remplies = [];
  const conservees = [];
  if (!doc || !narratif) return { remplies, conservees };
  doc.transact(() => {
    for (const cle of SECTIONS_RAPPORT) {
      const propose = String(narratif[cle] || '').trim();
      if (!propose) continue;
      const y = doc.getText(cle);
      const actuel = y.toString();
      if (actuel === propose) continue;
      if (actuel.trim() && !forcer.includes(cle)) { conservees.push(cle); continue; }
      y.delete(0, y.length);
      y.insert(0, propose);
      remplies.push(cle);
    }
    if (remplies.length) doc.getMap('meta').set('ia_utilisee', true);
  });
  return { remplies, conservees };
}

export function narratifDuDoc(doc) {
  if (!doc) return null;
  const narratif = {};
  let present = false;
  for (const cle of SECTIONS_RAPPORT) {
    const texte = doc.getText(cle).toString();
    narratif[cle] = texte;
    if (texte.trim()) present = true;
  }
  return present ? narratif : null;
}

export function iaUtilisee(doc) {
  return Boolean(doc && doc.getMap('meta').get('ia_utilisee') === true);
}

export function noteAnalyste(doc) {
  return doc ? doc.getText(NOTE_ANALYSTE).toString().trim() : '';
}
