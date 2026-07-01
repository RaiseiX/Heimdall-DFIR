// frontend/src/components/networkmap/CorrelationBadgeLayer.jsx
import { useState, useEffect } from 'react';

// Renders numbered HTML badges over correlated nodes (those seen in 2+ evidences).
// Must be rendered inside NetworkExplorer so it shares cyRef.
// pointer-events: none — all clicks pass through to Cytoscape canvas.
export default function CorrelationBadgeLayer({ cyRef, correlatedNodes }) {
  const [positions, setPositions] = useState({});

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !correlatedNodes?.length) {
      setPositions({});
      return;
    }

    const recompute = () => {
      const pos = {};
      for (const { id } of correlatedNodes) {
        const node = cy.$id(id);
        if (node.length && node.style('display') !== 'none') {
          pos[id] = node.renderedPosition();
        }
      }
      setPositions(pos);
    };

    recompute();
    cy.on('pan zoom layoutstop', recompute);
    cy.on('drag', 'node', recompute);

    return () => {
      cy.off('pan zoom layoutstop', recompute);
      cy.off('drag', 'node', recompute);
    };
  }, [cyRef, correlatedNodes]);

  if (!correlatedNodes?.length) return null;

  return (
    <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none', zIndex: 5 }}>
      {correlatedNodes.map(({ id, count, suspicious }) => {
        const pos = positions[id];
        if (!pos) return null;
        const color = suspicious ? 'var(--fl-danger)' : 'var(--fl-accent)';
        return (
          <div
            key={id}
            style={{
              position: 'absolute',
              // Node radius = 19px (38px diameter / 2). Badge at top-right edge.
              left: pos.x + 14,
              top:  pos.y - 19,
              width: 14,
              height: 14,
              borderRadius: '50%',
              background: color,
              border: '1.5px solid #0a0c11',
              color: '#fff',
              fontSize: 7,
              fontWeight: 700,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
            }}
          >
            {count}
          </div>
        );
      })}
    </div>
  );
}
