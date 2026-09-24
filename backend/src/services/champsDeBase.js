const { extractDescription } = require('./timelineNormalizeCore');

const SOURCE_AMCACHE = ['ProgramName', 'ApplicationName', 'LnkName', 'Source'];
const SUFFIXE_EMPREINTE = /\|[0-9a-f]{8,}$/i;

function premiereValeur(record, colonnes) {
  for (const c of colonnes) {
    const v = (record[c] || '').toString().trim();
    if (v) return v;
  }
  return '';
}

function champsDeBase(clean, artifactType, config) {
  const description = extractDescription(clean, config.descriptionColumns);
  if (artifactType !== 'amcache') return { description, source: clean[config.sourceColumn] || '' };
  return {
    description: description.replace(SUFFIXE_EMPREINTE, '').trim(),
    source: premiereValeur(clean, SOURCE_AMCACHE),
  };
}

module.exports = { champsDeBase };
