function creerFileParCas() {
  const files = new Map();
  return {
    enchainer(cle, travail) {
      const precedent = files.get(cle) || Promise.resolve();
      const courant = precedent.then(() => travail());
      const fin = courant.then(() => {}, () => {});
      files.set(cle, fin);
      fin.then(() => { if (files.get(cle) === fin) files.delete(cle); });
      return courant;
    },
    occupe(cle) {
      return files.has(cle);
    },
  };
}

module.exports = { creerFileParCas };
