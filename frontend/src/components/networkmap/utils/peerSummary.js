
import { isCleartextPort, portService } from './registerGroups';

export function peerSummary(nodeId, edges, { maxProcesses = 3 } = {}) {
  const ports = new Set();
  const processes = [];
  let connections = 0;

  for (const el of edges || []) {
    const d = el?.data;
    if (!d || (d.source !== nodeId && d.target !== nodeId)) continue;

    for (const p of d.ports || []) {
      const n = Number(p);
      if (Number.isFinite(n)) ports.add(n);
    }
    for (const proc of d.processes || []) {
      if (proc && !processes.includes(proc)) processes.push(proc);
    }
    connections += Number(d.connection_count) || 0;
  }

  return {
    ports: [...ports].sort((a, b) => a - b),
    processes: processes.slice(0, maxProcesses),
    truncated: processes.length > maxProcesses ? processes.length - maxProcesses : false,
    connections,
  };
}

export function edgeIsCleartext(ports) {
  return (ports || []).some(isCleartextPort);
}

const INFRASTRUCTURE = Object.freeze(new Set([53, 67, 68, 123]));
const ENCRYPTED      = Object.freeze(new Set([22, 443, 465, 636, 993, 995, 8443]));

export function portClass(port) {
  const n = Number(port);
  if (!Number.isFinite(n)) return null;
  if (isCleartextPort(n)) return 'cleartext';
  if (INFRASTRUCTURE.has(n)) return 'infrastructure';
  if (ENCRYPTED.has(n)) return 'encrypted';
  if (portService(n)) return 'notable';
  return null;
}

const RANK = Object.freeze(['cleartext', 'notable', 'encrypted', 'infrastructure']);

export function edgeClass(ports) {
  let best = null;
  for (const p of ports || []) {
    const c = portClass(p);
    if (!c) continue;
    if (best === null || RANK.indexOf(c) < RANK.indexOf(best)) best = c;
  }
  return best;
}

export function nodePortClass(nodeId, edges) {
  const counts = new Map();
  for (const e of edges || []) {
    if (e?.source !== nodeId && e?.target !== nodeId) continue;
    const c = edgeClass(e.ports);
    if (!c) continue;
    counts.set(c, (counts.get(c) || 0) + 1);
  }
  let best = null;
  for (const [c, n] of counts) {
    if (best === null) { best = c; continue; }
    const top = counts.get(best);
    if (n > top || (n === top && RANK.indexOf(c) < RANK.indexOf(best))) best = c;
  }
  return best;
}
