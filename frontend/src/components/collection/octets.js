export function fmtOctets(b) {
  const n = Number(b);
  if (!Number.isFinite(n) || n <= 0) return '0 B';
  const k = 1024, u = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(k)), u.length - 1);
  return `${(n / Math.pow(k, i)).toFixed(1)} ${u[i]}`;
}
