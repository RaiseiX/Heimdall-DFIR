function liste(valeur) {
  if (Array.isArray(valeur)) return valeur;
  if (typeof valeur === 'string' && valeur) return [valeur];
  return [];
}

function uniques(valeurs) {
  return [...new Set(valeurs)];
}

function plateformeDeCollecte(detectes, plateformeDe) {
  const vues = new Set(detectes.map(plateformeDe).filter(Boolean));
  return vues.size === 1 ? [...vues][0] : null;
}

function perimetreDeParsing({ demandes, detectes, catalogue, plateformeDe } = {}) {
  const cat = Array.isArray(catalogue) ? catalogue : [];
  const connu = new Set(cat);
  const plat = typeof plateformeDe === 'function' ? plateformeDe : () => null;
  const vus = Array.isArray(detectes) ? detectes : [];
  const plateforme = plateformeDeCollecte(vus, plat);

  if (demandes === 'all') {
    const masques = plateforme
      ? cat.filter((cle) => {
          const p = plat(cle);
          return p !== null && p !== plateforme;
        })
      : [];
    const ecarte = new Set(masques);
    return { aParser: cat.filter((cle) => !ecarte.has(cle)), masques, plateforme, raison: null };
  }

  const demandees = liste(demandes);
  if (demandees.length) {
    return {
      aParser: uniques(demandees).filter((cle) => connu.has(cle)),
      masques: [],
      plateforme,
      raison: null,
    };
  }

  const depuisDetection = uniques(vus).filter((cle) => connu.has(cle));
  if (depuisDetection.length) {
    return { aParser: depuisDetection, masques: [], plateforme, raison: null };
  }

  return { aParser: [], masques: [], plateforme, raison: 'aucun-artefact-detecte' };
}

module.exports = { perimetreDeParsing, plateformeDeCollecte };
