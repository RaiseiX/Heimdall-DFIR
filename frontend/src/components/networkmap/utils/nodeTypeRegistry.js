// frontend/src/components/networkmap/utils/nodeTypeRegistry.js
import { NODE_TYPES } from '../../../constants/nodeTypes';

// ── Private / special IPv4 ranges ────────────────────────────────────────────
const PRIVATE_RANGES_V4 = [
  /^10\./,                                          // RFC1918 10.0.0.0/8
  /^172\.(1[6-9]|2\d|3[01])\./,                    // RFC1918 172.16.0.0/12
  /^192\.168\./,                                    // RFC1918 192.168.0.0/16
  /^127\./,                                         // Loopback 127.0.0.0/8
  /^169\.254\./,                                    // APIPA link-local 169.254.0.0/16
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,     // CGN RFC6598 100.64.0.0/10
  /^(22[4-9]|23\d)\./,                              // Multicast 224.0.0.0/4
  /^0\.0\.0\.0$/,                                   // Unspecified
  /^255\.255\.255\.255$/,                            // Broadcast
];

const PRIVATE_TLD = /\.(lab|local|lan|corp|internal|intranet|home|localdomain|test|priv)$/i;

// ── IP category (special address space beyond RFC1918) ────────────────────────
export function getIPCategory(ip) {
  const s = (ip || '').replace(/^::ffff:/i, '').replace(/:\d+$/, '');
  if (s === '::1' || /^127\./.test(s))                      return 'LOOPBACK';
  if (/^169\.254\./.test(s))                                return 'APIPA';
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(s)) return 'CGN';
  if (/^(22[4-9]|23\d)\./.test(s))                         return 'MCAST';
  if (/^0\.0\.0\.0$/.test(s))                               return 'UNSPEC';
  if (/^255\.255\.255\.255$/.test(s))                       return 'BCAST';
  if (/^fe[89ab][0-9a-f]:/i.test(s))                       return 'LLA';
  if (/^f[cd][0-9a-f]{2}:/i.test(s))                       return 'ULA';
  if (s.includes(':') && !s.includes('.'))                  return 'IPv6';
  return null;
}

// ── Port → service badge mapping ──────────────────────────────────────────────
const PORT_ROLES = [
  { ports: [80, 8080, 8000, 3000, 8008, 8888],            badge: 'HTTP',     color: '#6b8ccf' },
  { ports: [443, 8443, 4443],                              badge: 'HTTPS',    color: '#6abf8e' },
  { ports: [22],                                            badge: 'SSH',      color: '#8b7fff' },
  { ports: [3389],                                          badge: 'RDP',      color: '#e69654' },
  { ports: [445, 139, 135],                                badge: 'SMB',      color: '#e69654' },
  { ports: [53],                                            badge: 'DNS',      color: '#5f97b8' },
  { ports: [25, 465, 587, 143, 993, 110, 995],            badge: 'MAIL',     color: '#c9a86a' },
  { ports: [3306, 5432, 1433, 27017, 6379, 1521, 5984],  badge: 'DB',       color: '#c9a86a' },
  { ports: [21, 990],                                      badge: 'FTP',      color: '#7e93bf' },
  { ports: [23],                                           badge: 'TELNET',   color: '#e0556d' },
  { ports: [5900, 5901],                                   badge: 'VNC',      color: '#e69654' },
  { ports: [161, 162],                                     badge: 'SNMP',     color: '#7e93bf' },
  { ports: [389, 636],                                     badge: 'LDAP',     color: '#6b8ccf' },
  { ports: [88],                                           badge: 'Kerberos', color: '#8b7fff' },
];

export function getPortBadges(ports) {
  if (!ports?.length) return [];
  const portSet = new Set(ports.map(Number));
  return PORT_ROLES
    .filter(r => r.ports.some(p => portSet.has(p)))
    .map(r => ({ badge: r.badge, color: r.color }));
}

export function isInternal(ip) {
  const s = (ip || '').replace(/^::ffff:/i, '').replace(/:\d+$/, '');
  // ── IPv6 special ──────────────────────────────────────────────────────
  if (s === '::1')                       return true; // loopback
  if (/^fe[89ab][0-9a-f]:/i.test(s))    return true; // link-local fe80::/10
  if (/^f[cd][0-9a-f]{2}:/i.test(s))    return true; // ULA fc00::/7
  // ── IPv4 ─────────────────────────────────────────────────────────────
  return PRIVATE_RANGES_V4.some(re => re.test(s));
}

function extractParenIP(id) {
  const m = String(id || '').match(/\((\d+\.\d+\.\d+\.\d+)\)/);
  return m ? m[1] : null;
}

// ── OS fingerprint from port evidence ────────────────────────────────────────
export function getOSHint(ports) {
  const p = new Set((ports || []).map(Number));
  const win = (p.has(445)?60:0) + (p.has(135)?40:0) + (p.has(3389)?40:0) +
              (p.has(88)?30:0)  + ((p.has(5985)||p.has(5986))?50:0) +
              (p.has(139)?25:0) + ((p.has(137)||p.has(138))?15:0);
  const lin = (p.has(22)?50:0) + (p.has(111)?40:0) + (p.has(2049)?40:0) + (p.has(631)?25:0);
  const net = ((p.has(161)||p.has(162))?60:0) + (p.has(179)?75:0) +
              ((p.has(520)||p.has(521))?50:0) + ((p.has(1812)||p.has(1813))?45:0);
  const max = Math.max(win, lin, net);
  if (max < 40) return null;
  if (net === max && net >= 60) return 'network_device';
  if (win === max && win >= 60) return 'windows';
  if (lin === max && lin >= 50) return 'linux';
  return null;
}

// ── Multi-signal scoring rules ────────────────────────────────────────────────
const TYPE_RULES = [
  { typeId: 'domain_controller', threshold: 70, signals: [
    { w: 85, label: 'hostname:dc',          test: (id)    => /\b(dc\d*|pdc|bdc|addc|domainctrl|domaincontroller)\b/i.test(id) },
    { w: 70, label: 'port:Kerberos(88)',    test: (_,p)   => p.has(88) },
    { w: 55, label: 'port:LDAP(389/636)',   test: (_,p)   => p.has(389) || p.has(636) },
    { w: 65, label: 'port:GlobalCatalog',   test: (_,p)   => p.has(3268) || p.has(3269) },
    { w: 20, label: 'port:RPC(135)',        test: (_,p)   => p.has(135) },
  ]},
  { typeId: 'firewall', threshold: 60, signals: [
    { w: 90, label: 'hostname:fw',          test: (id)    => /\b(fw\d*|firewall|pfsense|fortinet|asa|checkpoint|fortigate|juniper)\b/i.test(id) },
    { w: 60, label: 'port:IPsec(500)',      test: (_,p)   => p.has(500) || p.has(4500) },
    { w: 45, label: 'port:OpenVPN(1194)',   test: (_,p)   => p.has(1194) },
  ]},
  { typeId: 'vpn', threshold: 60, signals: [
    { w: 85, label: 'hostname:vpn',         test: (id)    => /\b(vpn|openvpn|wireguard|pptp)\b/i.test(id) },
    { w: 70, label: 'port:OpenVPN(1194)',   test: (_,p)   => p.has(1194) },
    { w: 65, label: 'port:WireGuard(51820)',test: (_,p)   => p.has(51820) || p.has(51821) },
    { w: 55, label: 'port:IPsec(500)',      test: (_,p)   => p.has(500) || p.has(4500) },
    { w: 50, label: 'port:PPTP(1723)',      test: (_,p)   => p.has(1723) },
  ]},
  { typeId: 'router', threshold: 60, signals: [
    { w: 85, label: 'hostname:router',      test: (id)    => /\b(rtr\d*|router|rt\d+)\b/i.test(id) },
    { w: 75, label: 'port:BGP(179)',        test: (_,p)   => p.has(179) },
    { w: 50, label: 'port:RIP(520)',        test: (_,p)   => p.has(520) || p.has(521) },
    { w: 30, label: 'port:SNMP(161)',       test: (_,p)   => p.has(161) || p.has(162) },
  ]},
  { typeId: 'switch', threshold: 60, signals: [
    { w: 85, label: 'hostname:switch',      test: (id)    => /\b(sw\d+|switch)\b/i.test(id) },
    { w: 25, label: 'port:SNMP(161)',       test: (_,p)   => p.has(161) || p.has(162) },
  ]},
  { typeId: 'proxy', threshold: 60, signals: [
    { w: 90, label: 'hostname:proxy',       test: (id)    => /\b(proxy|squid|bluecoat|zscaler|ironport)\b/i.test(id) },
    { w: 65, label: 'port:proxy(3128)',     test: (_,p)   => p.has(3128) || p.has(8118) },
  ]},
  { typeId: 'waf', threshold: 60, signals: [
    { w: 90, label: 'hostname:waf',         test: (id)    => /\b(waf|f5|imperva|cloudflare|modsec)\b/i.test(id) },
  ]},
  { typeId: 'ids_ips', threshold: 60, signals: [
    { w: 90, label: 'hostname:ids',         test: (id)    => /\b(ids|ips|snort|suricata|sourcefire)\b/i.test(id) },
  ]},
  { typeId: 'load_balancer', threshold: 60, signals: [
    { w: 85, label: 'hostname:lb',          test: (id)    => /\b(lb\d*|haproxy|loadbalancer|balancer)\b/i.test(id) },
    { w: 40, label: 'port:http+https',      test: (_,p)   => p.has(80) && p.has(443) },
  ]},
  { typeId: 'cloud', threshold: 60, signals: [
    { w: 90, label: 'hostname:cloud',       test: (id)    => /\b(aws|azure|gcp|cloud|ec2|s3)\b/i.test(id) || /\.(amazonaws|azure|googlecloud|digitalocean)\.com$/.test(id) },
  ]},
  { typeId: 'container', threshold: 60, signals: [
    { w: 90, label: 'hostname:container',   test: (id)    => /\b(k8s|docker|pod|container)\b/i.test(id) },
  ]},
  { typeId: 'printer', threshold: 60, signals: [
    { w: 85, label: 'hostname:printer',     test: (id)    => /\b(print|prn|mfp|xerox|hp\d)\b/i.test(id) },
    { w: 70, label: 'port:printing(9100)',  test: (_,p)   => p.has(9100) || p.has(515) || p.has(631) },
  ]},
  { typeId: 'iot', threshold: 60, signals: [
    { w: 90, label: 'hostname:iot',         test: (id)    => /\b(iot|cam\d*|camera|sensor|scada|plc)\b/i.test(id) },
    { w: 65, label: 'port:MQTT(1883)',      test: (_,p)   => p.has(1883) || p.has(8883) },
  ]},
  { typeId: 'laptop', threshold: 60, signals: [
    { w: 85, label: 'hostname:laptop',      test: (id)    => /\b(laptop|nb\d*|note|mobile)\b/i.test(id) },
  ]},
  { typeId: 'workstation', threshold: 55, signals: [
    { w: 80, label: 'hostname:workstation', test: (id)    => /\b(ws\d*|workstation|desk|pc\d+|wkstn)\b/i.test(id) },
    { w: 35, label: 'behavior:client',      test: (_,__,b)=> (b?.serverScore ?? 0.5) < 0.25 },
  ]},
  { typeId: 'server', threshold: 35, signals: [
    { w: 60, label: 'hostname:server',      test: (id)    => /\b(srv\d*|server|svr|svc)\b/i.test(id) },
    { w: 40, label: 'behavior:server',      test: (_,__,b)=> (b?.serverScore ?? 0.5) > 0.65 },
    { w: 30, label: 'port:services',        test: (_,p)   => p.has(22)||p.has(80)||p.has(443)||p.has(3306)||p.has(5432)||p.has(53) },
  ]},
];

// ── Full classification with confidence + matched signals ─────────────────────
export function classifyNode(node, ports = [], behavior = {}) {
  const id      = String(node.id || '').toLowerCase();
  const type    = String(node.type || '');
  const portSet = new Set((ports || []).map(Number));

  // Deterministic — no scoring needed
  if (node.is_suspicious || type === 'ioc')
    return { typeId: 'ioc',         confidence: 'HIGH', signals: ['is_suspicious'] };
  if (/^::ffff:/i.test(id))
    return { typeId: isInternal(id) ? 'server' : 'external_ip', confidence: 'HIGH', signals: ['ipv6_mapped'] };
  if (type === 'url')
    return { typeId: 'domain',      confidence: 'HIGH', signals: ['type:url'] };
  if (type === 'domain') {
    if (PRIVATE_TLD.test(id))        return { typeId: 'server',      confidence: 'HIGH', signals: ['type:domain', 'private_tld'] };
    if (/^\d+\.\d+\.\d+\.\d+:\d+$/.test(id) || extractParenIP(id)) {
      const pip = extractParenIP(id);
      return { typeId: isInternal(id) || isInternal(pip||'') ? 'server' : 'external_ip', confidence: 'HIGH', signals: ['type:domain', 'embedded_ip'] };
    }
    return { typeId: 'domain',       confidence: 'HIGH', signals: ['type:domain'] };
  }
  if (type === 'external')
    return { typeId: 'external_ip', confidence: 'HIGH', signals: ['type:external'] };

  // Multi-signal scoring
  let best = null;
  for (const rule of TYPE_RULES) {
    let score = 0; const matched = [];
    for (const s of rule.signals) {
      if (s.test(id, portSet, behavior)) { score += s.w; matched.push(s.label); }
    }
    if (score >= rule.threshold && (!best || score > best.score)) {
      best = { typeId: rule.typeId, score, signals: matched };
    }
  }
  if (best) {
    const confidence = best.score >= 80 ? 'HIGH' : best.score >= 50 ? 'MEDIUM' : 'LOW';
    return { typeId: best.typeId, confidence, signals: best.signals };
  }

  // Behavioral fallback
  if (type === 'internal' || isInternal(node.id)) {
    const ss = behavior.serverScore ?? 0.5;
    if (ss > 0.65) return { typeId: 'server',      confidence: 'LOW', signals: ['behavior:server_score=' + ss] };
    if (ss < 0.25) return { typeId: 'workstation', confidence: 'LOW', signals: ['behavior:client_score=' + ss] };
    return { typeId: 'server', confidence: 'LOW', signals: ['default:internal'] };
  }
  return { typeId: 'external_ip', confidence: 'HIGH', signals: ['default:external'] };
}

// Backward-compatible wrapper
export function detectNodeType(node, ports = [], behavior = {}) {
  return classifyNode(node, ports, behavior).typeId;
}

// Get the color for a node (used for edge coloring, etc.)
export function nodeColor(typeId) {
  return (NODE_TYPES[typeId] || NODE_TYPES.server).color;
}

// Compute badges for a node
export function nodeBadges(node) {
  const badges = [];
  if (node.is_suspicious)      badges.push('ioc');
  if (node.beacon_score > 70)  badges.push('beacon');
  if (node.dga_score > 60)     badges.push('dga');
  if (detectNodeType(node) === 'domain_controller') badges.push('admin');
  return badges;
}
