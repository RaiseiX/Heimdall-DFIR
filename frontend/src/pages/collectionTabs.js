export const COLLECTION_TAB_GROUPS = [
  {
    id: 'collected',
    tabs: [
      { id: 'evidence', label: 'Evidence' },
      { id: 'coverage', label: 'Coverage' },
      { id: 'files',    label: 'Files' },
      { id: 'artifacts', label: 'Artifacts' },
      { id: 'logs',     label: 'Logs' },
    ],
  },
  {
    id: 'analysis',
    tabs: [
      { id: 'timeline',   label: 'Super Timeline' },
      { id: 'detections', label: 'Detections' },
      { id: 'iocs',       label: 'IOCs' },
      { id: 'network',    label: 'Network' },
      { id: 'auth',       label: 'Auth' },
      { id: 'processes',  label: 'Processes' },
      { id: 'mitre',      label: 'MITRE' },
      { id: 'threathunt', label: 'Threat Hunting' },
      { id: 'hayabusa',   label: 'Hayabusa' },
    ],
  },
  {
    id: 'tools',
    tabs: [
      { id: 'cyberchef', label: 'CyberChef' },
      { id: 'volweb',    label: 'VolWeb' },
      { id: 'audit',     label: 'Audit' },
    ],
  },
];

export const EXTERNAL_TABS = new Set(['volweb']);

export function collectionTabs() {
  return COLLECTION_TAB_GROUPS.flatMap(g => g.tabs.map(tab => ({ ...tab, groupe: g.id })));
}

export function repartirOnglets(onglets, largeurDisponible, mesurer, { actifId, largeurPlus = 0, largeurSeparateur = 0 } = {}) {
  const actif = actifId == null ? null : onglets.find(o => o.id === actifId) || null;
  const separer = (visibles) => {
    const gardes = new Set(visibles.map(o => o.id));
    return { visibles, plus: onglets.filter(o => !gardes.has(o.id)) };
  };
  const largeurDe = (liste) => liste.reduce((n, o, i) => (
    n + mesurer(o) + (i > 0 && liste[i - 1].groupe !== o.groupe ? largeurSeparateur : 0)
  ), 0);

  if (!(largeurDisponible > 0)) return separer(actif ? [actif] : []);

  if (largeurDe(onglets) <= largeurDisponible) return separer([...onglets]);

  const budget = largeurDisponible - Math.max(largeurPlus, 0);
  const debut = [];
  for (const o of onglets) {
    if (largeurDe([...debut, o]) > budget) break;
    debut.push(o);
  }

  if (!actif || debut.some(o => o.id === actif.id)) return separer(debut);

  while (debut.length > 0 && largeurDe([...debut, actif]) > budget) debut.pop();
  return separer([...debut, actif]);
}
