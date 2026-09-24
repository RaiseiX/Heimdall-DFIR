const TOLERANCE_DOLLAR_MIN = 3;

const CACHE = new Map();

function echapper(segment) {
  return segment.replace(/[.+^${}()|[\]\\]/g, '\\$&');
}

function segmentEnRegex(segment) {
  return echapper(segment).replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]');
}

function corpsEnRegex(segments) {
  let sortie = '';
  for (let i = 0; i < segments.length; i++) {
    const dernier = i === segments.length - 1;
    if (segments[i] === '**') {
      sortie += dernier ? '.*' : '(?:[^/]+/)*';
    } else {
      sortie += segmentEnRegex(segments[i]);
      if (!dernier) sortie += '/';
    }
  }
  return sortie;
}

function varianteSansDollar(segments) {
  const dernier = segments[segments.length - 1];
  if (!dernier.startsWith('$') || !dernier.includes('*')) return null;
  const prefixe = dernier.slice(1, dernier.indexOf('*'));
  if (prefixe.length < TOLERANCE_DOLLAR_MIN) return null;
  return [...segments.slice(0, -1), dernier.slice(1)];
}

function compiler(motif) {
  const segments = motif.toLowerCase().replace(/\\/g, '/').split('/').filter(Boolean);
  if (!segments.length) return [];

  const variantes = [segments];
  const sansDollar = varianteSansDollar(segments);
  if (sansDollar) variantes.push(sansDollar);

  return variantes.map((v) => {
    const ancre = v[0] === '**' ? '' : '(?:[^/]+/)*';
    return new RegExp('^' + ancre + corpsEnRegex(v) + '$');
  });
}

function regexDuMotif(motif) {
  let compile = CACHE.get(motif);
  if (!compile) {
    compile = compiler(motif);
    CACHE.set(motif, compile);
  }
  return compile;
}

function cheminCorrespond(chemin, motif) {
  if (typeof chemin !== 'string' || typeof motif !== 'string') return false;
  if (!chemin || !motif) return false;

  const cible = chemin.toLowerCase().replace(/\\/g, '/').replace(/^\/+/, '');
  if (!cible) return false;

  const regex = regexDuMotif(motif);
  for (const r of regex) {
    if (r.test(cible)) return true;
  }
  return false;
}

module.exports = { cheminCorrespond };
