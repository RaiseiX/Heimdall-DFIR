const entier = (v) => {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
};

const somme = (...valeurs) => {
  const nombres = valeurs.map(entier);
  return nombres.some((n) => n === null) ? null : nombres.reduce((a, b) => a + b, 0);
};

export function lignesSupprimees(apercu, { collecte = false } = {}) {
  const s = apercu?.supprime || {};
  const lignes = entier(s.lignes);
  const resultats = Array.isArray(s.resultats) ? s.resultats : null;
  return [
    { cle: collecte ? 'disque_collecte' : 'disque_fichier', octets: entier(s.disque_octets) },
    {
      cle: 'lignes',
      nombre: lignes,
      detail: lignes ? { detections: entier(s.detections) ?? 0, etiquetees: entier(s.etiquetees) ?? 0 } : null,
    },
    { cle: 'index', nombre: entier(s.index_docs) },
    {
      cle: 'resultats',
      nombre: resultats ? resultats.length : null,
      resultats: resultats ? resultats.map((r) => ({ nom: String(r.nom ?? ''), lignes: entier(r.lignes) })) : [],
    },
    { cle: 'yara', nombre: entier(s.yara) },
    { cle: 'connexions', nombre: entier(s.connexions) },
    { cle: 'analyste', nombre: somme(s.epingles, s.commentaires) },
    { cle: 'fiche', empreinte: apercu?.preuve?.sha256 || null },
  ];
}

export function lignesConservees(apercu) {
  const c = apercu?.conserve || {};
  const favoris = somme(c.favoris, c.verdicts);
  const lignes = [
    { cle: 'audit' },
    { cle: 'journal', cibles: entier(c.cibles) },
    { cle: 'favoris', nombre: favoris, detail: favoris > 0 },
  ];
  if (apercu?.preuve?.memoire) lignes.push({ cle: 'volweb' });
  return lignes;
}

export function issueDeLEchec(erreur) {
  const donnees = erreur?.response?.data || {};
  if (donnees.code === 'LEGAL_HOLD') return { type: 'scelle' };
  if (donnees.code === 'DELETION_INCOMPLETE') {
    const cible = donnees.cible && typeof donnees.cible.type === 'string'
      ? { type: donnees.cible.type, code: String(donnees.cible.code ?? '') }
      : null;
    return { type: 'incomplet', operation: donnees.operation_id ?? null, cible };
  }
  return { type: 'erreur', message: donnees.error || erreur?.message || String(erreur) };
}

export function empreinteCourte(sha256) {
  if (!sha256) return null;
  const s = String(sha256);
  return s.length > 16 ? `${s.slice(0, 16)}…` : s;
}
