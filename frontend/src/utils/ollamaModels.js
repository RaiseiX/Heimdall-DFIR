export const normalizeModelName = (name) =>
  String(name ?? '').trim().toLowerCase().replace(/:latest$/, '');

const asList = (installed) =>
  installed instanceof Set ? [...installed] : Array.isArray(installed) ? installed : [];

export const resolveInstalledName = (catalogId, installed) => {
  const wanted = normalizeModelName(catalogId);
  if (!wanted) return null;
  return asList(installed).find(name => normalizeModelName(name) === wanted) ?? null;
};

export const isModelInstalled = (catalogId, installed) =>
  resolveInstalledName(catalogId, installed) !== null;
