const SCHEMA_OPTIONS = Object.freeze({
  mft: Object.freeze([
    Object.freeze({ cle: 'recover_slack', type: 'boolean', defaut: false, drapeau: '--rs' }),
    Object.freeze({ cle: 'include_resident_data', type: 'boolean', defaut: false, drapeau: '--ir' }),
  ]),
  catscale: Object.freeze([
    Object.freeze({ cle: 'exhaustive_fs_timeline', type: 'boolean', defaut: false }),
  ]),
});

function optionsParDefaut() {
  const sortie = {};
  for (const [type, options] of Object.entries(SCHEMA_OPTIONS)) {
    sortie[type] = Object.fromEntries(options.map((o) => [o.cle, o.defaut]));
  }
  return sortie;
}

function booleen(valeur) {
  return valeur === true || valeur === 'true';
}

function assainirOptions(brut) {
  const sortie = optionsParDefaut();
  if (!brut || typeof brut !== 'object' || Array.isArray(brut)) return sortie;
  for (const [type, options] of Object.entries(SCHEMA_OPTIONS)) {
    const demande = brut[type];
    if (!demande || typeof demande !== 'object' || Array.isArray(demande)) continue;
    for (const o of options) {
      if (o.type === 'boolean' && Object.prototype.hasOwnProperty.call(demande, o.cle)) sortie[type][o.cle] = booleen(demande[o.cle]);
    }
  }
  return sortie;
}

function drapeauxDe(artifactType, options) {
  const schema = SCHEMA_OPTIONS[artifactType];
  const valeurs = options && options[artifactType];
  if (!schema || !valeurs) return [];
  return schema.filter((o) => o.drapeau && valeurs[o.cle] === true).map((o) => o.drapeau);
}

module.exports = { SCHEMA_OPTIONS, optionsParDefaut, assainirOptions, drapeauxDe };
