export function currentUser() {
  try { return JSON.parse(localStorage.getItem('heimdall_user') || '{}'); }
  catch { return {}; }
}
export function isAdmin() {
  return currentUser().role === 'admin';
}
