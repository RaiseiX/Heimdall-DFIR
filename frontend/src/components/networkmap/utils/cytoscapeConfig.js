import { NODE_TYPES, NODE_COLORS_CB, buildNodeSvg } from '../../../constants/nodeTypes';

export const PORT_CLASSES = Object.freeze([
  { id: 'cleartext',      color: '#e0556d', cb: '#D55E00', opacity: 0.9 },
  { id: 'notable',        color: '#c9a86a', cb: '#E69F00', opacity: 0.8 },
  { id: 'encrypted',      color: '#6abf8e', cb: '#0072B2', opacity: 0.7 },
  { id: 'infrastructure', color: '#8b7fff', cb: '#CC79A7', opacity: 0.7 },
]);

export function portColor(id, colorblindMode = false) {
  const c = PORT_CLASSES.find(p => p.id === id);
  if (!c) return null;
  return colorblindMode ? c.cb : c.color;
}

export function buildCytoscapeStyle(nodeColorOverrides = {}, colorblindMode = false) {
  const styles = [
    {
      selector: 'node',
      style: {
        'width':  'mapData(connection_count, 0, 20, 9, 26)',
        'height': 'mapData(connection_count, 0, 20, 9, 26)',
        'shape': 'ellipse',
        'background-color': '#6b8ccf',
        'background-opacity': 0.9,
        'background-image': 'none',
        'border-width': 0,
        'border-color': '#6b8ccf',
        'label': 'data(label)',
        'font-family': 'monospace',
        'font-size': 10,
        'color': '#dde0e8',
        'text-valign': 'center',
        'text-halign': 'right',
        'text-margin-x': 8,
        'text-max-width': 340,
        'text-wrap': 'ellipsis',
        'text-background-opacity': 0,
        'z-index': 10,
      },
    },
    {
      selector: 'node.internal, node.collection, node.workstation, node.laptop, node.server, node.domain_controller',
      style: {
        'background-opacity': 0,
        'border-width': 1.6,
      },
    },
    {
      selector: 'node:selected',
      style: {
        'border-width': 3.5,
        'border-color': '#8b7fff',
        'border-style': 'solid',
        'background-opacity': 0.38,
        'overlay-opacity': 0,
      },
    },
    {
      selector: 'node[_display]',
      style: {
        'label': 'data(_display)',
        'text-wrap': 'wrap',
        'text-max-width': 300,
        'font-size': 10,
      },
    },
    {
      selector: 'node.hub',
      style: {
        'text-halign': 'center',
        'text-valign': 'bottom',
        'text-margin-x': 0,
        'text-margin-y': 8,
      },
    },
    {
      selector: '.band-hidden',
      style: { 'display': 'none' },
    },
    {
      selector: 'node.band-rule',
      style: {
        'shape': 'rectangle',
        'width': 1,
        'height': 'data(h)',
        'background-color': '#222a3a',
        'background-opacity': 1,
        'background-image': 'none',
        'border-width': 0,
        'label': '',
        'z-index': 0,
        'events': 'no',
        'overlay-opacity': 0,
      },
    },
    {
      selector: 'node.band-label',
      style: {
        'width': 1,
        'height': 1,
        'background-opacity': 0,
        'background-image': 'none',
        'border-width': 0,
        'label': 'data(label)',
        'font-size': 11,
        'font-family': 'monospace',
        'font-weight': 600,
        'color': '#7e8697',
        'text-valign': 'center',
        'text-halign': 'right',
        'text-margin-x': 8,
        'z-index': 2,
        'events': 'no',
        'overlay-opacity': 0,
      },
    },
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
    {
      selector: '.suspicious',
      style: {
        'border-color': '#e0556d',
        'border-width': 2.5,
      },
    },
    {
      selector: '.beacon',
      style: {
        'border-color': '#e69654',
        'border-width': 2.5,
        'overlay-opacity': 0,
      },
    },
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
    {
      selector: '.normal-edge',
      style: {
        'width': 'data(_w)',
        'line-color': '#6b8ccf40',
        'target-arrow-color': '#6b8ccf40',
        'target-arrow-shape': 'triangle',
        'arrow-scale': 0.8,
        'curve-style': 'unbundled-bezier',
        'control-point-distances': 'data(_cpd)',
        'control-point-weights': 'data(_cpw)',
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
    {
      selector: '.suspicious-edge',
      style: {
        'width': 'data(_w)',
        'line-color': '#e0556d',
        'target-arrow-color': '#e0556d',
        'target-arrow-shape': 'triangle',
        'line-style': 'dashed',
        'line-dash-pattern': [6, 4],
        'curve-style': 'unbundled-bezier',
        'control-point-distances': 'data(_cpd)',
        'control-point-weights': 'data(_cpw)',
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
    ...PORT_CLASSES.map(({ id, opacity }) => {
      const c = portColor(id, colorblindMode);
      return {
        selector: `.port-${id}`,
        style: { 'line-color': c, 'target-arrow-color': c, 'color': c, 'opacity': opacity },
      };
    }),
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

  Object.values(NODE_TYPES).forEach(type => {
    const color = nodeColorOverrides[type.id]
      || (colorblindMode ? NODE_COLORS_CB[type.id] : null)
      || type.color;
    styles.push({
      selector: `node.${type.id}`,
      style: {
        'background-color': color,
        'border-color': color,
      },
    });
    styles.push({
      selector: `node.${type.id}:selected`,
      style: {
        'border-color': color,
      },
    });
  });

  PORT_CLASSES.forEach(({ id }) => {
    const color = portColor(id, colorblindMode);
    styles.push({
      selector: `node.port-node-${id}`,
      style: {
        'background-color': color,
        'border-color': color,
      },
    });
  });

  styles.push({
    selector: 'node[_zoneDeclared]',
    style: {
      'border-style': 'dashed',
    },
  });

  return styles;
}

export const LAYOUT_COSE = {
  name: 'cose-bilkent',
  animate: false,
  nodeRepulsion: 350000,
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

export const LAYOUT_DAGRE = {
  name: 'dagre',
  rankDir: 'LR',
  ranker: 'network-simplex',
  nodeSep: 80,
  rankSep: 180,
  edgeSep: 20,
  align: 'UL',
  animate: true,
  animationDuration: 450,
  fit: true,
  padding: 70,
  nodeDimensionsIncludeLabels: true,
};

export const LAYOUT_CONCENTRIC = {
  name: 'concentric',
  animate: true,
  animationDuration: 450,
  fit: true,
  padding: 70,
  minNodeSpacing: 60,
  avoidOverlap: true,
  concentric: node => node.degree(),
  levelWidth: () => 2,
  nodeDimensionsIncludeLabels: true,
};

