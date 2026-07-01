// frontend/src/components/networkmap/NetworkExplorer.jsx
import { useEffect, useRef, useCallback, useState } from 'react';
import { Share2, CircleDot, GitBranch } from 'lucide-react';
import cytoscape from 'cytoscape';
import coseBilkent from 'cytoscape-cose-bilkent';
import dagre from 'cytoscape-dagre';
import { buildCytoscapeStyle, LAYOUT_COSE, LAYOUT_CONCENTRIC, LAYOUT_DAGRE } from './utils/cytoscapeConfig';
import { ZONE_DEFS_NORMAL, ZONE_DEFS_CB } from './ZoneOverlay';
import ZoneOverlay from './ZoneOverlay';
import CorrelationBadgeLayer from './CorrelationBadgeLayer';

cytoscape.use(coseBilkent);
cytoscape.use(dagre);

export default function NetworkExplorer({
  elements,
  onNodeSelect,
  onNodeDeselect,
  selectedNodeId,
  zones,
  drawingZoneType,
  onZoneDrawn,
  onZoneUpdate,
  onZoneDelete,
  nodeColorOverrides,
  colorblindMode,
  manualNodes,
  placingAsset,
  onAssetPlaced,
  savedPositions,
  onPositionsSave,
  correlatedNodes,
  onCyReady,
}) {
  const containerRef        = useRef(null);
  const cyRef               = useRef(null);
  // Refs allow the stale-closure tap handler to access latest placement state
  const placingAssetRef     = useRef(placingAsset);
  const onAssetPlacedRef    = useRef(onAssetPlaced);
  // Refs for zoom handler — always current without triggering re-renders
  const zonesRef            = useRef(zones);
  const colorblindModeRef   = useRef(colorblindMode);
  // Refs for position persistence — updated each render, readable from init-effect handlers
  const savedPositionsRef   = useRef(savedPositions);
  const onPositionsSaveRef  = useRef(onPositionsSave);
  const dragSaveTimerRef    = useRef(null);
  useEffect(() => { placingAssetRef.current    = placingAsset;    }, [placingAsset]);
  useEffect(() => { onAssetPlacedRef.current   = onAssetPlaced;   }, [onAssetPlaced]);
  useEffect(() => { zonesRef.current           = zones;           }, [zones]);
  useEffect(() => { colorblindModeRef.current  = colorblindMode;  }, [colorblindMode]);
  useEffect(() => { savedPositionsRef.current  = savedPositions;  }, [savedPositions]);
  useEffect(() => { onPositionsSaveRef.current = onPositionsSave; }, [onPositionsSave]);

  // ── Initialize Cytoscape ────────────────────────────────────────────
  useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container: containerRef.current,
      elements: [],
      style: buildCytoscapeStyle(nodeColorOverrides || {}, colorblindMode),
      userZoomingEnabled: true,
      userPanningEnabled: true,
      boxSelectionEnabled: false,
      autoungrabifiedNodes: false,
      minZoom: 0.1,
      maxZoom: 6,
    });
    cyRef.current = cy;
    onCyReady?.(cy);

    // Fold / unfold a hub's leaf children (nodes connected only to it).
    // Hidden leaves + their edges are stored on the hub so we can restore them.
    const toggleCollapse = (node) => {
      const stored = node.data('_collapsedLeaves');
      if (stored && stored.length) {
        stored.forEach(id => {
          const n = cy.$id(id);
          n.style('display', 'element');
          n.connectedEdges().style('display', 'element');
        });
        node.removeData('_collapsedLeaves');
        node.removeClass('has-collapsed');
      } else {
        const leaves = node.openNeighborhood().nodes(':visible').filter(n =>
          !n.hasClass('manual') && !n.hasClass('zone') && !n.hasClass('zone-label') &&
          n.connectedEdges(':visible').connectedNodes(':visible')
            .every(x => x.id() === n.id() || x.id() === node.id())
        );
        if (!leaves.length) return;
        const ids = leaves.map(n => n.id());
        leaves.connectedEdges().style('display', 'none');
        leaves.style('display', 'none');
        node.data('_collapsedLeaves', ids);
        node.addClass('has-collapsed');
      }
    };

    // Click on node → select. Double-click (≤350 ms on the same node) → fold/unfold.
    let lastTap = { id: null, t: 0 };
    cy.on('tap', 'node:not(.cluster)', e => {
      const node = e.target;
      if (node.hasClass('cluster') || node.hasClass('zone')) return;
      cy.nodes().removeClass('selected-highlight');
      node.addClass('selected-highlight');
      onNodeSelect?.(node.data());
      const now = Date.now();
      if (lastTap.id === node.id() && now - lastTap.t < 350) {
        toggleCollapse(node);
        lastTap = { id: null, t: 0 };
      } else {
        lastTap = { id: node.id(), t: now };
      }
    });

    // Click on cluster → toggle collapse
    cy.on('tap', '.cluster', e => {
      const cluster = e.target;
      const collapsed = cluster.data('collapsed');
      if (!collapsed) {
        cluster.data('collapsed', true);
        cluster.children().style('display', 'none');
      } else {
        cluster.data('collapsed', false);
        cluster.children().style('display', 'element');
      }
    });

    // Click background → place asset (if in placement mode) or deselect
    cy.on('tap', e => {
      if (e.target === cy) {
        if (placingAssetRef.current) {
          onAssetPlacedRef.current?.(e.position);
          return;
        }
        cy.nodes().removeClass('selected-highlight');
        onNodeDeselect?.();
      }
    });

    // Reposition zone labels on zoom so text-top always lands inside the zone.
    // anchor_y = zone.y + (textHalfH_px + padding_px) / zoom
    // → text_top_screen = zone.y_screen + padding (zoom-independent).
    cy.on('zoom', () => {
      const zoom_ = cy.zoom();
      (zonesRef.current || []).forEach(zone => {
        const n = cy.$id(`zone-label:${zone.id}`);
        if (!n.length) return;
        const label = n.data('label') || '';
        const lineCount = (label.match(/\n/g) || []).length + 1;
        const textHalfH = lineCount * 7; // ~14px line-height → half = 7px
        n.position({ x: zone.x + zone.w / 2, y: zone.y + (textHalfH + 8) / zoom_ });
      });
    });

    // Save positions after user drags a graph node (debounced 400 ms)
    cy.on('dragfree', 'node:not(.manual, .zone, .zone-label)', () => {
      clearTimeout(dragSaveTimerRef.current);
      dragSaveTimerRef.current = setTimeout(() => {
        const positions = {};
        cy.nodes().not('.manual, .zone, .zone-label').forEach(n => {
          positions[n.id()] = { x: n.position('x'), y: n.position('y') };
        });
        onPositionsSaveRef.current?.(positions);
      }, 400);
    });

    return () => { cy.destroy(); cyRef.current = null; onCyReady?.(null); };
  }, []); // only on mount

  // Resize Cytoscape when the container gains dimensions (handles flex/absolute layouts
  // where height isn't resolved synchronously at mount time)
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    let fitted = container.offsetHeight > 0;
    const ro = new ResizeObserver(() => {
      const cy = cyRef.current;
      if (!cy) return;
      cy.resize();
      if (!fitted && container.offsetHeight > 0) {
        fitted = true;
        cy.fit(undefined, 40);
      }
    });
    ro.observe(container);
    return () => ro.disconnect();
  }, []);

  // ── Update elements when data changes ──────────────────────────────
  const prevNodeIdsRef = useRef(new Set());

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    // Empty elements → clear all non-permanent nodes (filter wiped everything)
    if (!elements?.length) {
      prevNodeIdsRef.current = new Set();
      cy.elements().not('.manual, .zone, .zone-label').remove();
      return;
    }

    // Compare node ID sets — if identical, it's an annotation-only change (zone drawn,
    // type override, filter label); update data/classes in place without re-running layout.
    const newNodeIds = new Set(
      elements.filter(e => !e.data?.source && !e.data?._zone).map(e => e.data?.id).filter(Boolean)
    );
    const prevIds = prevNodeIdsRef.current;
    const sameStructure =
      newNodeIds.size === prevIds.size && [...newNodeIds].every(id => prevIds.has(id));
    prevNodeIdsRef.current = newNodeIds;

    if (sameStructure && cy.nodes().length > 0) {
      cy.batch(() => {
        elements.forEach(el => {
          if (!el.data?.id) return;
          const ele = cy.$id(el.data.id);
          if (ele.length) {
            ele.data(el.data);
            if (el.classes != null) ele.classes(el.classes);
          }
        });
      });
      return;
    }

    cy.batch(() => {
      cy.elements().not('.manual, .zone, .zone-label').remove();
      cy.add(elements);
    });

    // Restore persisted positions if they cover the entire current graph — no layout needed.
    // Fall back to cose-bilkent layout for any graph where positions are missing (first load,
    // new nodes added, filter changed), then save the result so the next load is instant.
    const graphNodes = cy.nodes().not('.manual, .zone, .zone-label');
    const saved = savedPositionsRef.current || {};
    const allSaved = graphNodes.length > 0 && graphNodes.every(n => saved[n.id()]);

    if (allSaved) {
      cy.batch(() => { graphNodes.forEach(n => n.position({ ...saved[n.id()] })); });
      cy.fit(undefined, 40);
    } else {
      const layout = cy.layout(LAYOUT_COSE);
      layout.one('layoutstop', () => {
        const positions = {};
        cy.nodes().not('.manual, .zone, .zone-label').forEach(n => {
          positions[n.id()] = { x: n.position('x'), y: n.position('y') };
        });
        onPositionsSaveRef.current?.(positions);
      });
      layout.run();
    }
  }, [elements]);

  // ── Apply node color overrides dynamically (no layout re-run) ───────
  // Uses cy.style(fullStylesheet) — an atomic full-stylesheet replacement — instead of
  // incremental .selector().style().update() calls, which are unreliable in Cytoscape v3
  // when called in a loop (each .update() can flush partial state before the next rule lands).
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.style(buildCytoscapeStyle(nodeColorOverrides || {}, colorblindMode));
  }, [nodeColorOverrides, colorblindMode]);

  // ── Highlight selected node from external control ──────────────────
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes().removeClass('selected-highlight');
    if (selectedNodeId) {
      const node = cy.$(`node[id="${selectedNodeId}"]`);
      if (node.length) {
        node.addClass('selected-highlight');
        cy.animate({ center: { eles: node }, zoom: Math.max(cy.zoom(), 1.2) }, { duration: 300 });
      }
    }
  }, [selectedNodeId]);

  // ── Sync manually placed nodes (instance colors via inline style) ───
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const nodes = manualNodes || [];

    // Remove stale manual nodes
    cy.nodes('.manual').forEach(n => {
      if (!nodes.find(m => m.id === n.id())) cy.remove(n);
    });

    nodes.forEach(mn => {
      const existing = cy.$id(mn.id);
      if (existing.length) {
        existing.data({ label: mn.label || mn.typeId, colorOverride: mn.colorOverride });
        existing.position({ ...mn.position });
      } else {
        const el = cy.add({
          group: 'nodes',
          data: {
            id: mn.id,
            label: mn.label || mn.typeId,
            nodeType: mn.typeId,
            _manual: true,
            colorOverride: mn.colorOverride || null,
          },
          classes: [mn.typeId, 'manual'].join(' '),
          position: { ...mn.position },
        });
        el.lock(); // immune to layout
      }

      // Instance color: inline style overrides stylesheet class rules
      const node = cy.$id(mn.id);
      if (mn.colorOverride) {
        node.style({
          'background-color': mn.colorOverride,
          'background-opacity': 0.22,
          'border-color': mn.colorOverride,
        });
      } else {
        node.removeStyle('background-color background-opacity border-color');
      }
    });
  }, [manualNodes]);

  // ── Render zones as Cytoscape elements — perfectly in sync, zero lag ──
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const ZONE_DEFS = colorblindMode ? ZONE_DEFS_CB : ZONE_DEFS_NORMAL;
    const zoneList = zones || [];

    // Remove stale zone rect + label elements
    cy.nodes('.zone').forEach(n => {
      if (!zoneList.find(z => `zone:${z.id}` === n.id())) cy.remove(n);
    });
    cy.nodes('.zone-label').forEach(n => {
      if (!zoneList.find(z => `zone-label:${z.id}` === n.id())) cy.remove(n);
    });

    zoneList.forEach(zone => {
      const def = ZONE_DEFS[zone.type];
      if (!def) return;
      const cyId    = `zone:${zone.id}`;
      const labelId = `zone-label:${zone.id}`;
      const cx      = zone.x + zone.w / 2;
      const cy_     = zone.y + zone.h / 2;
      const label = zone.description
        ? `${def.label}\n${zone.description}`
        : def.label;
      // Convert text half-height (screen px) to graph units at current zoom.
      // Text is centered on anchor → anchor_y = zone.y + (textHalfH + 8px_padding) / zoom
      // → text_top_screen = zone_top_screen + 8px, always inside.
      const lineCount  = (label.match(/\n/g) || []).length + 1;
      const textHalfH  = lineCount * 7;
      const labelPos   = { x: cx, y: zone.y + (textHalfH + 8) / cy.zoom() };

      // Zone rectangle (no label)
      const existing = cy.$id(cyId);
      if (existing.length) {
        existing.data({ w: zone.w, h: zone.h, color: def.color });
        existing.position({ x: cx, y: cy_ });
      } else {
        const el = cy.add({
          group: 'nodes',
          data: { id: cyId, w: zone.w, h: zone.h, color: def.color, _zone: true },
          classes: 'zone',
          position: { x: cx, y: cy_ },
        });
        el.lock();
      }

      // Zone label (separate 1px invisible node — position recalculated on zoom via cy.on('zoom'))
      const existingLabel = cy.$id(labelId);
      if (existingLabel.length) {
        existingLabel.data({ label, color: def.color });
        existingLabel.position(labelPos);
      } else {
        const lbl = cy.add({
          group: 'nodes',
          data: { id: labelId, label, color: def.color, _zone: true },
          classes: 'zone-label',
          position: labelPos,
        });
        lbl.lock();
      }
    });
  }, [zones, colorblindMode]);

  // ── Disable cy interaction while drawing zones or placing assets ─────
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const blocked = !!drawingZoneType || !!placingAsset;
    cy.userPanningEnabled(!blocked);
    cy.userZoomingEnabled(!blocked);
  }, [drawingZoneType, placingAsset]);

  // ── Zoom controls ───────────────────────────────────────────────────
  const zoomIn  = useCallback(() => cyRef.current?.zoom({ level: cyRef.current.zoom() * 1.3, renderedPosition: { x: containerRef.current.offsetWidth / 2, y: containerRef.current.offsetHeight / 2 } }), []);
  const zoomOut = useCallback(() => cyRef.current?.zoom({ level: cyRef.current.zoom() / 1.3, renderedPosition: { x: containerRef.current.offsetWidth / 2, y: containerRef.current.offsetHeight / 2 } }), []);
  const fitAll  = useCallback(() => cyRef.current?.fit(undefined, 40), []);

  // ── Layout switcher ─────────────────────────────────────────────────
  // Re-run a layout on demand over the graph nodes only (manual/zone nodes stay locked).
  // Persisted positions are updated so the chosen layout survives a reload.
  const [layoutMode, setLayoutMode] = useState('organic');
  const runLayout = useCallback((mode) => {
    const cy = cyRef.current;
    if (!cy) return;
    const graphNodes = cy.nodes().not('.manual, .zone, .zone-label');
    if (!graphNodes.length) return;

    let opts;
    if (mode === 'radial') {
      opts = { ...LAYOUT_CONCENTRIC };
    } else if (mode === 'hierarchical') {
      // Layered top-down tree (dagre): external/hub at the top, internal nodes descending.
      opts = { ...LAYOUT_DAGRE };
    } else {
      opts = { ...LAYOUT_COSE, animate: true, animationDuration: 450 };
    }

    // Layout the graph nodes *with the edges that connect them* — dagre/breadthfirst
    // build their ranking from edges; a node-only collection collapses to one row.
    const eles = graphNodes.union(graphNodes.edgesWith(graphNodes));
    const layout = eles.layout(opts);
    layout.one('layoutstop', () => {
      const positions = {};
      cy.nodes().not('.manual, .zone, .zone-label').forEach(n => {
        positions[n.id()] = { x: n.position('x'), y: n.position('y') };
      });
      onPositionsSaveRef.current?.(positions);
    });
    layout.run();
  }, []);

  const selectLayout = useCallback((mode) => { setLayoutMode(mode); runLayout(mode); }, [runLayout]);

  const LAYOUTS = [
    { id: 'organic',      label: 'Organique',    icon: Share2 },
    { id: 'radial',       label: 'Radial',       icon: CircleDot },
    { id: 'hierarchical', label: 'Hierarchical', icon: GitBranch },
  ];

  return (
    <div style={{ flex: 1, position: 'relative', background: '#0a0c11', overflow: 'hidden' }}>
      {/* Cytoscape container */}
      <div ref={containerRef} style={{ width: '100%', height: '100%', cursor: placingAsset ? 'crosshair' : 'default' }} />

      {/* Layout switcher — organic / radial / hierarchical.
          Centred at top so it never collides with corner overlays (stats left, search right). */}
      <div style={{
        position: 'absolute', top: 12, left: '50%', transform: 'translateX(-50%)', zIndex: 10,
        display: 'flex', gap: 2, padding: 3,
        background: '#0e1118', border: '1px solid #1a1f2c', borderRadius: 8,
        boxShadow: '0 2px 12px rgba(0,0,0,0.4)',
      }}>
        {LAYOUTS.map(({ id, label, icon: Icon }) => {
          const active = layoutMode === id;
          return (
            <button key={id} onClick={() => selectLayout(id)} title={`Disposition ${label}`}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '5px 10px', borderRadius: 6, cursor: 'pointer',
                fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 11,
                background: active ? 'color-mix(in srgb, var(--fl-purple) 20%, transparent)' : 'transparent',
                border: `1px solid ${active ? 'color-mix(in srgb, var(--fl-purple) 38%, transparent)' : 'transparent'}`,
                color: active ? 'var(--fl-purple)' : '#8089a0',
                transition: 'all 0.12s',
              }}
              onMouseEnter={e => { if (!active) { e.currentTarget.style.background = '#161b27'; e.currentTarget.style.color = '#c2c8d4'; } }}
              onMouseLeave={e => { if (!active) { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = '#8089a0'; } }}
            >
              <Icon size={13} />
              {label}
            </button>
          );
        })}
      </div>

      {/* Zone overlay — positioned absolutely over canvas */}
      <ZoneOverlay
        cyRef={cyRef}
        zones={zones ?? []}
        drawingZoneType={drawingZoneType}
        onZoneDrawn={onZoneDrawn}
        onZoneUpdate={onZoneUpdate}
        onZoneDelete={onZoneDelete}
        colorblindMode={colorblindMode}
      />

      {/* Correlation badges — HTML overlay for nodes seen in 2+ evidences */}
      <CorrelationBadgeLayer cyRef={cyRef} correlatedNodes={correlatedNodes} />

      {/* Zoom controls */}
      <div style={{ position: 'absolute', bottom: 12, left: 12, display: 'flex', flexDirection: 'column', gap: 2, zIndex: 10 }}>
        {[
          { label: '+', title: 'Zoom in',  fn: zoomIn  },
          { label: '−', title: 'Zoom out', fn: zoomOut },
          { label: '⊡', title: 'Fit all',  fn: fitAll  },
        ].map(({ label, title, fn }) => (
          <button key={label} onClick={fn} title={title} style={{
            width: 26, height: 26, background: '#0e1118', border: '1px solid #1a1f2c',
            borderRadius: 3, color: 'var(--fl-purple)', cursor: 'pointer', fontSize: 13,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>{label}</button>
        ))}
      </div>
    </div>
  );
}
