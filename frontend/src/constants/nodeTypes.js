// frontend/src/constants/nodeTypes.js
export const NODE_TYPES = {
  server: {
    id: 'server', label: 'Server', color: '#6b8ccf',
    svgPath: `<rect x="3" y="4" width="18" height="4" rx="1.5" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <rect x="3" y="10" width="18" height="4" rx="1.5" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <rect x="3" y="16" width="18" height="4" rx="1.5" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <circle cx="18.5" cy="6" r="1" fill="COLOR"/>
              <circle cx="18.5" cy="12" r="1" fill="COLOR"/>
              <circle cx="18.5" cy="18" r="1" fill="COLOR"/>`,
  },
  workstation: {
    id: 'workstation', label: 'Workstation', color: '#8aa2d6',
    svgPath: `<rect x="2" y="3" width="20" height="14" rx="2" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <path d="M8 20h8M12 17v3" stroke="COLOR" stroke-width="1.6" stroke-linecap="round"/>
              <rect x="4" y="5" width="16" height="10" rx="1" fill="COLOR" fill-opacity="0.15"/>`,
  },
  laptop: {
    id: 'laptop', label: 'Laptop', color: '#9fb2dd',
    svgPath: `<rect x="3" y="4" width="18" height="13" rx="2" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <path d="M1 20h22" stroke="COLOR" stroke-width="1.6" stroke-linecap="round"/>
              <rect x="5" y="6" width="14" height="9" rx="1" fill="COLOR" fill-opacity="0.12"/>`,
  },
  domain_controller: {
    id: 'domain_controller', label: 'Domain Controller', color: '#8b7fff',
    svgPath: `<rect x="3" y="4" width="18" height="4" rx="1.5" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <rect x="3" y="10" width="18" height="4" rx="1.5" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <rect x="3" y="16" width="18" height="4" rx="1.5" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <circle cx="18.5" cy="6" r="1" fill="COLOR"/>
              <path d="M10 1l1.5 3.5L15 5l-2.5 2.5.5 3.5L10 9.5 7 11l.5-3.5L5 5l3.5-.5z" fill="COLOR" fill-opacity="0.9"/>`,
  },
  external_ip: {
    id: 'external_ip', label: 'External IP', color: '#e69654',
    svgPath: `<circle cx="12" cy="12" r="9" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <path d="M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18" fill="none" stroke="COLOR" stroke-width="1.2"/>
              <path d="M3 12h18" stroke="COLOR" stroke-width="1.2"/>`,
  },
  domain: {
    id: 'domain', label: 'Domain', color: '#c489c4',
    svgPath: `<circle cx="12" cy="12" r="9" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <path d="M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18M3 12h18" fill="none" stroke="COLOR" stroke-width="1.2"/>
              <path d="M3 8h18M3 16h18" stroke="COLOR" stroke-width="1.2"/>`,
  },
  user: {
    id: 'user', label: 'User', color: '#b29ad6',
    svgPath: `<circle cx="12" cy="8" r="4" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <path d="M4 20c0-4 3.6-7 8-7s8 3 8 7" fill="none" stroke="COLOR" stroke-width="1.6" stroke-linecap="round"/>`,
  },
  ioc: {
    id: 'ioc', label: 'IOC / C2', color: '#e0556d',
    svgPath: `<path d="M12 2L2 20h20L12 2z" fill="none" stroke="COLOR" stroke-width="1.8"/>
              <line x1="12" y1="9" x2="12" y2="14" stroke="COLOR" stroke-width="2" stroke-linecap="round"/>
              <circle cx="12" cy="17" r="1.2" fill="COLOR"/>`,
  },
  firewall: {
    id: 'firewall', label: 'Firewall', color: '#c9a86a',
    svgPath: `<path d="M12 2l7 4v6c0 4-3 7.5-7 9-4-1.5-7-5-7-9V6l7-4z" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <path d="M10 12c0-2 1-3 2-4 1 1.5.5 3 1 4s2 1.5 1 3c-1-1-1.5-2-2-2s-1 1-2 2c-1-1.5-.5-2 0-3z" fill="COLOR" fill-opacity="0.7"/>`,
  },
  proxy: {
    id: 'proxy', label: 'Proxy', color: '#7e93bf',
    svgPath: `<circle cx="7" cy="12" r="4" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <circle cx="17" cy="12" r="4" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <path d="M11 12h2M9 10l-2 2 2 2M15 10l2 2-2 2" stroke="COLOR" stroke-width="1.4" stroke-linecap="round"/>`,
  },
  router: {
    id: 'router', label: 'Router', color: '#5fa899',
    svgPath: `<circle cx="12" cy="12" r="8" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <path d="M12 4v4M12 16v4M4 12h4M16 12h4" stroke="COLOR" stroke-width="1.4" stroke-linecap="round"/>
              <circle cx="12" cy="12" r="2.5" fill="COLOR" fill-opacity="0.8"/>`,
  },
  switch: {
    id: 'switch', label: 'Switch', color: '#5f97b8',
    svgPath: `<rect x="2" y="8" width="20" height="8" rx="2" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <path d="M6 12h12M8 10l-2 2 2 2M16 10l2 2-2 2" stroke="COLOR" stroke-width="1.4" stroke-linecap="round"/>`,
  },
  ids_ips: {
    id: 'ids_ips', label: 'IDS / IPS', color: '#d98c8c',
    svgPath: `<circle cx="12" cy="12" r="9" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <circle cx="12" cy="12" r="4" fill="none" stroke="COLOR" stroke-width="1.2"/>
              <circle cx="12" cy="12" r="1.5" fill="COLOR"/>
              <path d="M12 3v2M12 19v2M3 12h2M19 12h2" stroke="COLOR" stroke-width="1.4" stroke-linecap="round"/>`,
  },
  waf: {
    id: 'waf', label: 'WAF', color: '#a98fcc',
    svgPath: `<path d="M12 2l7 4v6c0 4-3 7.5-7 9-4-1.5-7-5-7-9V6l7-4z" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <circle cx="12" cy="11" r="3.5" fill="none" stroke="COLOR" stroke-width="1.2"/>
              <path d="M9 14a6 6 0 0 1 6 0" fill="none" stroke="COLOR" stroke-width="1.2"/>`,
  },
  load_balancer: {
    id: 'load_balancer', label: 'Load Balancer', color: '#6fb0a0',
    svgPath: `<circle cx="12" cy="5" r="2.5" fill="none" stroke="COLOR" stroke-width="1.4"/>
              <circle cx="5" cy="18" r="2.5" fill="none" stroke="COLOR" stroke-width="1.4"/>
              <circle cx="19" cy="18" r="2.5" fill="none" stroke="COLOR" stroke-width="1.4"/>
              <path d="M12 7.5v3M10 11l-3.5 4.8M14 11l3.5 4.8" stroke="COLOR" stroke-width="1.4" stroke-linecap="round"/>`,
  },
  vpn: {
    id: 'vpn', label: 'VPN Gateway', color: '#8f9ad0',
    svgPath: `<rect x="5" y="11" width="14" height="9" rx="2" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <path d="M8 11V7a4 4 0 0 1 8 0v4" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <circle cx="12" cy="15.5" r="1.5" fill="COLOR"/>`,
  },
  cloud: {
    id: 'cloud', label: 'Cloud Asset', color: '#74a6d4',
    svgPath: `<path d="M18 10a6 6 0 0 0-11.5-2A4 4 0 1 0 6 16h12a4 4 0 0 0 0-8z" fill="none" stroke="COLOR" stroke-width="1.6"/>`,
  },
  container: {
    id: 'container', label: 'Container', color: '#6fa4c0',
    svgPath: `<path d="M21 8l-9-5-9 5v8l9 5 9-5V8z" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <path d="M12 3v18M3 8l9 5 9-5" stroke="COLOR" stroke-width="1.2"/>`,
  },
  printer: {
    id: 'printer', label: 'Printer', color: '#8892a8',
    svgPath: `<rect x="4" y="8" width="16" height="10" rx="1" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <path d="M8 8V4h8v4" fill="none" stroke="COLOR" stroke-width="1.4"/>
              <rect x="8" y="13" width="8" height="4" fill="none" stroke="COLOR" stroke-width="1.2"/>`,
  },
  iot: {
    id: 'iot', label: 'IoT Device', color: '#cba06a',
    svgPath: `<circle cx="12" cy="12" r="3" fill="none" stroke="COLOR" stroke-width="1.6"/>
              <path d="M6.3 6.3a8 8 0 0 0 0 11.4M17.7 6.3a8 8 0 0 1 0 11.4" fill="none" stroke="COLOR" stroke-width="1.4" stroke-linecap="round"/>
              <path d="M9.2 9.2a4 4 0 0 0 0 5.6M14.8 9.2a4 4 0 0 1 0 5.6" fill="none" stroke="COLOR" stroke-width="1.2" stroke-linecap="round"/>`,
  },
};

export const NODE_BADGES = {
  ioc:     { color: '#e0556d', label: '⚠' },
  beacon:  { color: '#e69654', label: '◎' },
  pivot:   { color: '#c9a86a', label: '★' },
  admin:   { color: '#8b7fff', label: '👑' },
  dga:     { color: '#c489c4', label: '⁉' },
};

// Colorblind-safe palette (Wong 2011) mapped to node types
export const NODE_COLORS_CB = {
  server:            '#0072B2',
  workstation:       '#56B4E9',
  laptop:            '#009E73',
  domain_controller: '#F0E442',
  external_ip:       '#E69F00',
  domain:            '#CC79A7',
  user:              '#CC79A7',
  ioc:               '#D55E00',
  firewall:          '#D55E00',
  proxy:             '#E69F00',
  router:            '#009E73',
  switch:            '#0072B2',
  ids_ips:           '#56B4E9',
  waf:               '#CC79A7',
  load_balancer:     '#009E73',
  vpn:               '#F0E442',
  cloud:             '#56B4E9',
  container:         '#0072B2',
  printer:           '#888888',
  iot:               '#E69F00',
};

export function buildNodeSvg(typeId, colorOverride) {
  if (!typeId || typeof typeId !== 'string' || !NODE_TYPES[typeId]) typeId = 'server';
  const type = NODE_TYPES[typeId];
  const icon = type.svgPath.replace(/COLOR/g, '#ffffff');
  // SVG size matches node size exactly (no browser default-size guessing).
  // Icon (24×24 coords) is scaled, then offset to center inside the node box.
  const S = 64;                       // node + svg size (must match cytoscapeConfig node width/height)
  const scale = 1.75;                 // 24 × 1.75 = 42px icon
  const off = ((S - 24 * scale) / 2).toFixed(1); // center the scaled icon
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${S}" height="${S}" viewBox="0 0 ${S} ${S}"><g transform="translate(${off},${off}) scale(${scale})">${icon}</g></svg>`;
  return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
}
