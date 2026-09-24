const { AsyncLocalStorage } = require('async_hooks');

const TAILLE_MAX = 5000;
const DEMARRAGE = new Date().toISOString();
const SOURCE = /^\[([^\]\n]{1,40})\]\s?([\s\S]*)$/;

function creerJournaux({ max = TAILLE_MAX, demarrage = DEMARRAGE } = {}) {
  const parCas = new Map();
  return {
    ajouter(caseId, entree) {
      let journal = parCas.get(caseId);
      if (!journal) { journal = { seq: 0, lignes: [] }; parCas.set(caseId, journal); }
      const ligne = { ...entree, seq: ++journal.seq, demarrage };
      journal.lignes.push(ligne);
      if (journal.lignes.length > max) journal.lignes.splice(0, journal.lignes.length - max);
      return ligne;
    },
    lire(caseId, depuis = 0) {
      const journal = parCas.get(caseId);
      return journal ? journal.lignes.filter(l => l.seq > depuis) : [];
    },
  };
}

function decouperSource(texte) {
  const m = SOURCE.exec(texte);
  return m ? { source: m[1], message: m[2] } : { source: '', message: texte };
}

const contexte = new AsyncLocalStorage();
const journaux = creerJournaux();

function executerDansJournal(ctx, travail) {
  return contexte.run({ ...ctx, enEmission: false }, travail);
}

function capter(niveau, texte) {
  try {
    const ctx = contexte.getStore();
    if (!ctx || ctx.enEmission) return null;
    const { source, message } = decouperSource(String(texte ?? ''));
    const ligne = journaux.ajouter(ctx.caseId, { ts: new Date().toISOString(), niveau, source, message, preuve: ctx.preuve ?? null });
    if (ctx.emettre) {
      ctx.enEmission = true;
      try { ctx.emettre(ligne); } catch (_e) { } finally { ctx.enEmission = false; }
    }
    return ligne;
  } catch (_e) {
    return null;
  }
}

function lireJournal(caseId, depuis = 0) {
  return journaux.lire(caseId, depuis);
}

module.exports = { TAILLE_MAX, creerJournaux, decouperSource, executerDansJournal, capter, lireJournal };
