const LIBELLES = {
  ia: {
    badge: 'ENRICHI PAR ANALYSE IA',
    synthese: 'Synthèse exécutive — IA',
    titre: "Analyse de l'incident — IA",
    intro: 'Analyse rédigée automatiquement à partir des artefacts, détections, IOCs et événements repérés du dossier.',
    remediation: 'Remédiation recommandée — IA',
  },
  assiste: {
    badge: 'RÉDIGÉ AVEC ASSISTANCE IA',
    synthese: 'Synthèse exécutive',
    titre: "Analyse de l'incident",
    intro: "Texte rédigé par l'analyste à partir d'un brouillon proposé par l'IA.",
    remediation: 'Remédiation recommandée',
  },
  analyste: {
    badge: null,
    synthese: 'Synthèse exécutive',
    titre: "Analyse de l'incident",
    intro: "Analyse rédigée par l'analyste.",
    remediation: 'Remédiation recommandée',
  },
};

function origineDuNarratif({ fourni, assiste, genere }) {
  if (genere) return 'ia';
  if (!fourni) return null;
  return assiste === false ? 'analyste' : 'assiste';
}

function libellesNarratif(origine) {
  return LIBELLES[origine] || LIBELLES.ia;
}

module.exports = { origineDuNarratif, libellesNarratif, LIBELLES };
