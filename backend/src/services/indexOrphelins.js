async function orphelinsDeLIndex({ caseId, compterParResultat, idsConnus }) {
  const index = await compterParResultat(caseId);
  const connus = await idsConnus(caseId);
  const orphelins = index.par_resultat
    .filter(r => !connus.has(String(r.result_id)))
    .sort((a, b) => b.docs - a.docs);
  const docsOrphelins = orphelins.reduce((n, r) => n + r.docs, 0);
  const docsConnus = index.par_resultat.filter(r => connus.has(String(r.result_id))).reduce((n, r) => n + r.docs, 0);
  return { orphelins, docs_orphelins: docsOrphelins, docs_connus: docsConnus, sans_resultat: index.sans_resultat };
}

async function purgerOrphelins({ caseId, compterParResultat, idsConnus, verrou, supprimer, journaliser, appliquer = false }) {
  const releve = await orphelinsDeLIndex({ caseId, compterParResultat, idsConnus });
  if (!appliquer || releve.orphelins.length === 0) return { ...releve, applique: false, supprimes: [], echecs: [] };

  return verrou(caseId, async client => {
    const { rows } = await client.query('SELECT id FROM parser_results WHERE case_id = $1', [caseId]);
    const connusSousVerrou = new Set(rows.map(r => String(r.id)));
    const aSupprimer = releve.orphelins.filter(r => !connusSousVerrou.has(String(r.result_id)));

    const supprimes = [];
    const echecs = [];
    for (const r of aSupprimer) {
      try {
        await supprimer(caseId, r.result_id, { strict: true });
        supprimes.push(r.result_id);
      } catch (e) {
        echecs.push({ result_id: r.result_id, erreur: e.message });
      }
    }
    const docs = aSupprimer.filter(r => supprimes.includes(r.result_id)).reduce((n, r) => n + r.docs, 0);
    await journaliser({ supprimes, docs, echecs, sans_resultat: releve.sans_resultat });
    return { ...releve, applique: true, supprimes, echecs };
  });
}

module.exports = { orphelinsDeLIndex, purgerOrphelins };
