// frontend/src/components/networkmap/utils/cytoscapeConfig.js
import { NODE_TYPES, NODE_COLORS_CB, buildNodeSvg } from '../../../constants/nodeTypes';

// Build the full Cytoscape stylesheet array.
// Accepts optional nodeColorOverrides map and colorblindMode flag so that
// per-type color customization is baked in atomically (not patched incrementally).
export function buildCytoscapeStyle(nodeColorOverrides = {}, colorblindMode = false) {
  const styles = [
    // ── Default node ────────────────────────────────────────────────
    {
      selector: 'node',
      style: {
        'width': 64,
        'height': 64,
        'shape': 'ellipse',
        // Cytoscape draws the colored circle — background-color is the fill tint
        'background-color': '#6b8ccf',
        'background-opacity': 0.22,
        // Icon: 'none' forces explicit 100% size - the 24x24 SVG scales to fill the 54x54 node
        // so the icon center (12,12) maps to the node center (27,27). Centered by math.
        'background-image': buildNodeSvg('server'),
        'background-fit': 'none',
        'background-clip': 'node',
        'border-width': 2.5,
        'border-color': '#6b8ccf',
        'label': 'data(label)',
        'font-family': 'monospace',
        'font-size': 11,
        'font-weight': 600,
        'color': '#ffffff',
        'text-valign': 'bottom',
        'text-margin-y': 6,
        'text-max-width': 140,
        'text-wrap': 'ellipsis',
        'text-background-color': '#0a0c11',
        'text-background-opacity': 0.72,
        'text-background-padding': '3px',
        'text-background-shape': 'roundrectangle',
        'z-index': 10,
      },
    },
    // ── Selected node ────────────────────────────────────────────────
    {
      selector: 'node:selected',
      style: {
        'border-width': 3.5,
        'border-color': '#8b7fff',
        'border-style': 'solid',
        'background-opacity': 0.38,
        'overlay-opacity': 0,  // overlay is always rectangular — kill it, use border instead
      },
    },
    // ── Zone node (analyst-drawn region, rendered as Cytoscape element) ─
    {
      selector: 'node.zone',
      style: {
        'shape': 'roundrectangle',
        'width': 'data(w)',
        'height': 'data(h)',
        'background-color': 'data(color)',
        'background-opacity': 0.05,
        'border-width': 1.5,
        'border-style': 'dashed',
        'border-color': 'data(color)',
        'border-opacity': 0.5,
        'label': '',
        'z-index': 0,
        'background-image': 'none',
        'events': 'no',
      },
    },
    // ── Zone label (separate 1px node at graph coords — position scales with zoom) ─
    {
      selector: 'node.zone-label',
      style: {
        'width': 1,
        'height': 1,
        'background-opacity': 0,
        'border-width': 0,
        'label': 'data(label)',
        'font-size': 11,
        'font-weight': 600,
        'font-family': 'monospace',
        'color': '#ffffff',
        'text-valign': 'center',
        'text-halign': 'center',
        'text-wrap': 'wrap',
        'text-max-width': 220,
        'text-background-color': '#0a0c11',
        'text-background-opacity': 0.9,
        'text-background-padding': '4px',
        'text-background-shape': 'rectangle',
        'z-index': 2,
        'background-image': 'none',
        'events': 'no',
        'overlay-opacity': 0,
      },
    },
    // ── Cluster (compound) node ──────────────────────────────────────
    {
      selector: '.cluster',
      style: {
        'shape': 'roundrectangle',
        'background-color': '#6b8ccf08',
        'border-width': 1,
        'border-style': 'dashed',
        'border-color': '#222a3a',
        'label': 'data(label)',
        'font-size': 18,
        'color': '#ffffff',
        'font-weight': 700,
        'text-valign': 'top',
        'text-halign': 'center',
        'text-max-width': '300px',
        'text-wrap': 'none',
        'padding': 18,
        'background-image': 'none',
        'z-index': 1,
      },
    },
    // ── Collapsed hub (leaf children folded away) ────────────────────
    {
      selector: 'node.has-collapsed',
      style: {
        'border-style': 'dotted',
        'border-width': 4,
        'underlay-color': '#8b7fff',
        'underlay-padding': 5,
        'underlay-opacity': 0.18,
      },
    },
    // ── Suspicious node ──────────────────────────────────────────────
    {
      selector: '.suspicious',
      style: {
        'border-color': '#e0556d',
        'border-width': 2.5,
        'border-style': 'dashed',
      },
    },
    // ── Beacon node ──────────────────────────────────────────────────
    {
      selector: '.beacon',
      style: {
        'border-color': '#e69654',
        'border-width': 2.5,
        'border-style': 'dashed',
        'overlay-opacity': 0,
      },
    },
    // ── IOC hit node (matches a malicious case IOC) ──────────────────
    {
      selector: 'node[_iocHit]',
      style: {
        'border-color': '#e0556d',
        'border-width': 4,
        'underlay-color': '#e0556d',
        'underlay-padding': 7,
        'underlay-opacity': 0.35,
      },
    },
    // ── Normal edge ──────────────────────────────────────────────────
    {
      selector: '.normal-edge',
      style: {
        'width': 'mapData(connection_count, 1, 100, 1, 4)',
        'line-color': '#6b8ccf40',
        'target-arrow-color': '#6b8ccf40',
        'target-arrow-shape': 'triangle',
        'arrow-scale': 0.8,
        'curve-style': 'bezier',
        'opacity': 0.7,
        'label': 'data(label)',
        'font-size': '8px',
        'font-family': 'monospace',
        'color': '#6b8ccf',
        'text-opacity': 0.75,
        'text-background-color': '#0a0c11',
        'text-background-opacity': 0.85,
        'text-background-padding': '2px',
        'text-background-shape': 'roundrectangle',
        'edge-text-rotation': 'autorotate',
      },
    },
    // ── Suspicious edge ──────────────────────────────────────────────
    {
      selector: '.suspicious-edge',
      style: {
        'width': 2.5,
        'line-color': '#e0556d',
        'target-arrow-color': '#e0556d',
        'target-arrow-shape': 'triangle',
        'line-style': 'dashed',
        'line-dash-pattern': [6, 4],
        'curve-style': 'bezier',
        'opacity': 0.85,
        'label': 'data(label)',
        'font-size': '8px',
        'font-family': 'monospace',
        'color': '#e0556d',
        'text-opacity': 0.9,
        'text-background-color': '#0a0c11',
        'text-background-opacity': 0.9,
        'text-background-padding': '2px',
        'text-background-shape': 'roundrectangle',
        'edge-text-rotation': 'autorotate',
      },
    },
    // ── Edge hover ───────────────────────────────────────────────────
    {
      selector: 'edge:selected',
      style: {
        'line-color': '#8b7fff',
        'target-arrow-color': '#8b7fff',
        'width': 3,
        'opacity': 1,
        'z-index': 20,
        'text-opacity': 1,
        'color': '#a9b8ff',
      },
    },
  ];

  // Per-type: colored fill + icon + border
  // Priority: manual override > colorblind palette > default type color
  Object.values(NODE_TYPES).forEach(type => {
    const color = nodeColorOverrides[type.id]
      || (colorblindMode ? NODE_COLORS_CB[type.id] : null)
      || type.color;
    styles.push({
      selector: `node.${type.id}`,
      style: {
        'background-color': color,
        'background-opacity': 0.22,
        'background-image': buildNodeSvg(type.id),
        'border-color': color,
      },
    });
    styles.push({
      selector: `node.${type.id}:selected`,
      style: {
        'background-opacity': 0.40,
        'border-color': color,
        'border-width': 3.5,
      },
    });
  });

  return styles;
}

// Cytoscape layout options
export const LAYOUT_COSE = {
  name: 'cose-bilkent',
  animate: false,            // no animation — much faster for large graphs
  nodeRepulsion: 350000,     // high repulsion to spread domain/IP nodes apart
  idealEdgeLength: 160,
  edgeElasticity: 0.1,
  nestingFactor: 0.1,
  gravity: 0.4,
  numIter: 2500,
  randomize: true,
  fit: true,
  padding: 60,
  nodeDimensionsIncludeLabels: true,
};

// Hierarchical layered tree, left → right (root hub on the left, children fan
// out to the right). Reads like an expandable tree / org-chart on its side.
export const LAYOUT_DAGRE = {
  name: 'dagre',
  rankDir: 'LR',
  ranker: 'network-simplex',   // cleaner, more balanced layering than tight-tree
  nodeSep: 80,                 // vertical gap between siblings — must exceed node height (64px)
  rankSep: 180,                // horizontal gap between levels; extra room for IP/domain labels
  edgeSep: 20,
  align: 'UL',                 // align nodes to upper-left within each rank for consistent reading
  animate: true,
  animationDuration: 450,
  fit: true,
  padding: 70,
  nodeDimensionsIncludeLabels: true,
};

// Radial: hub (most connections) sits in the centre, peers fan out on rings.
// Ideal for the hub-and-spoke shape of a host talking to many domains/IPs.
export const LAYOUT_CONCENTRIC = {
  name: 'concentric',
  animate: true,
  animationDuration: 450,
  fit: true,
  padding: 70,
  minNodeSpacing: 60,
  avoidOverlap: true,
  concentric: node => node.degree(),   // higher degree → inner ring
  levelWidth: () => 2,
  nodeDimensionsIncludeLabels: true,
};

// Hierarchical tree: roots at top, children layered below (breadth-first).
// roots is injected at run time (highest-degree node) by NetworkExplorer.
export const LAYOUT_BREADTHFIRST = {
  name: 'breadthfirst',
  animate: true,
  animationDuration: 450,
  directed: false,
  fit: true,
  padding: 55,
  spacingFactor: 1.35,
  circle: false,
  grid: false,
  avoidOverlap: true,
  nodeDimensionsIncludeLabels: true,
};
