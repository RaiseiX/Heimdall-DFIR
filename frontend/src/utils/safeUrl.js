const PLAGES = [[0x00, 0x20], [0x7f, 0xa0], [0x1680, 0x1680], [0x180e, 0x180e], [0x2000, 0x200f], [0x2028, 0x202f], [0x205f, 0x2064], [0x3000, 0x3000], [0xfeff, 0xfeff]];
const INTERDITS = new RegExp('[' + PLAGES.map(([a, b]) => String.fromCharCode(a) + '-' + String.fromCharCode(b)).join('') + ']');
const ABSOLU = /^https?:\/\/[^/\\]/i;

export function lienSur(valeur, { autoriserRelatif = true } = {}) {
  if (typeof valeur !== 'string' || !valeur || INTERDITS.test(valeur)) return null;
  const origine = window.location.origin;
  if (ABSOLU.test(valeur)) {
    try {
      const u = new URL(valeur, origine);
      return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
    } catch {
      return null;
    }
  }
  if (autoriserRelatif && valeur[0] === '/' && valeur[1] !== '/' && valeur[1] !== '\\') {
    try {
      const u = new URL(valeur, origine);
      if (u.origin !== origine) return null;
      const chemin = u.pathname + u.search + u.hash;
      if (!chemin.startsWith('/') || chemin[1] === '/' || chemin[1] === '\\') return null;
      if (new URL(chemin, origine).origin !== origine) return null;
      return chemin;
    } catch {
      return null;
    }
  }
  return null;
}
