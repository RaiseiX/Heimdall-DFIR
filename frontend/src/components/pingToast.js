const montes = new Map();

function cle(caseId) {
  return String(caseId).toLowerCase();
}

export function signalerChatMonte(caseId) {
  if (!caseId) return () => {};
  const k = cle(caseId);
  montes.set(k, (montes.get(k) || 0) + 1);
  let actif = true;
  return () => {
    if (!actif) return;
    actif = false;
    const restant = (montes.get(k) || 0) - 1;
    if (restant > 0) montes.set(k, restant);
    else montes.delete(k);
  };
}

export function chatMonte(caseId) {
  if (!caseId) return false;
  return (montes.get(cle(caseId)) || 0) > 0;
}

export function doitAfficherToastPing(caseId) {
  return !chatMonte(caseId);
}
