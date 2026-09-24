async function desactiverReglesCassees({ lister, valider, desactiver, journaliser, appliquer = false }) {
  const regles = await lister();
  const cassees = [];
  const nonVerifiees = [];
  for (const r of regles) {
    const v = await valider(r.content);
    if (v.valid) continue;
    const ligne = { id: r.id, name: r.name, erreur: v.error };
    (v.indisponible ? nonVerifiees : cassees).push(ligne);
  }

  const bilan = { verifiees: regles.length, cassees, non_verifiees: nonVerifiees, desactivees: [] };
  if (!appliquer || cassees.length === 0) return bilan;

  const desactivees = (await desactiver(cassees.map(r => r.id))).map(String);
  await journaliser({
    desactivees: cassees.filter(r => desactivees.includes(String(r.id))),
    non_verifiees: nonVerifiees,
  });
  return { ...bilan, desactivees };
}

module.exports = { desactiverReglesCassees };
