export async function lancerGeneration(api, caseId, opts, messageDefaut) {
  try {
    const { data } = await api.generate(caseId, opts);
    return { reportId: data.report?.id ?? null, termine: true, erreur: '' };
  } catch (e) {
    return { reportId: null, termine: false, erreur: e?.response?.data?.error || messageDefaut };
  }
}

export async function telechargerRapport(api, reportId, messageDefaut) {
  if (!reportId) return { blob: null, erreur: '' };
  try {
    const { data } = await api.download(reportId);
    return { blob: data, erreur: '' };
  } catch (e) {
    return { blob: null, erreur: e?.response?.data?.error || messageDefaut };
  }
}
