
const STORAGE_KEY = 'heimdall_artifact_columns_v1';

export function getColumnPref(artifactType) {
  try {
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
    return stored[artifactType] || null;
  } catch {
    return null;
  }
}

export function setColumnPref(artifactType, virtual) {
  try {
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
    stored[artifactType] = virtual;
    localStorage.setItem(STORAGE_KEY, JSON.stringify(stored));
  } catch {}
}

export function resetColumnPref(artifactType) {
  try {
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
    delete stored[artifactType];
    localStorage.setItem(STORAGE_KEY, JSON.stringify(stored));
  } catch {}
}

export function getEffectiveVirtual(artifactType, profiles) {
  const pref = getColumnPref(artifactType);
  if (pref) return pref;
  return profiles[artifactType]?.virtual || [];
}
