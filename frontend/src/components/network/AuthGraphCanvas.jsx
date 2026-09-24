import { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
import coseBilkent from 'cytoscape-cose-bilkent';
import { couleursDuTheme } from '../networkmap/utils/themeColors';

cytoscape.use(coseBilkent);

function style(c) {
  return [
    { selector: 'node', style: { label: 'data(label)', 'font-family': 'monospace', 'font-size': 10, color: c.text, 'text-valign': 'bottom', 'text-margin-y': 4, width: 18, height: 18 } },
    { selector: 'node[type = "utilisateur"]', style: { shape: 'ellipse', 'background-color': c.accent } },
    { selector: 'node[type = "machine"]', style: { shape: 'round-rectangle', 'background-color': c.purple } },
    { selector: 'node[echec > 0]', style: { 'border-width': 2, 'border-color': c.danger } },
    { selector: 'edge', style: { width: 'mapData(poids, 0, 12, 1, 6)', 'line-color': c.muted, 'target-arrow-shape': 'triangle', 'target-arrow-color': c.muted, 'curve-style': 'bezier', opacity: 0.7 } },
    { selector: 'edge[echec > 0]', style: { 'line-color': c.danger, 'target-arrow-color': c.danger } },
    { selector: ':selected', style: { 'overlay-opacity': 0.15, 'overlay-color': c.accent, opacity: 1 } },
  ];
}

export default function AuthGraphCanvas({ elements, selection, onSelect, libelle }) {
  const conteneur = useRef(null);
  const cyRef = useRef(null);

  useEffect(() => {
    if (!conteneur.current) return undefined;
    const cy = cytoscape({
      container: conteneur.current,
      elements,
      style: style(couleursDuTheme()),
      layout: { name: elements.length > 400 ? 'grid' : 'cose-bilkent', animate: false, fit: true, padding: 24 },
      wheelSensitivity: 0.2,
    });
    cy.on('tap', 'edge', (e) => onSelect?.(e.target.id()));
    cy.on('tap', (e) => { if (e.target === cy) onSelect?.(null); });
    cyRef.current = cy;
    return () => { cy.destroy(); cyRef.current = null; };
  }, [elements, onSelect]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().unselect();
    if (selection) cy.getElementById(selection).select();
  }, [selection]);

  return <div ref={conteneur} role="img" aria-label={libelle} style={{ width: '100%', height: '100%', minHeight: 320 }} />;
}
