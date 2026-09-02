import { useEffect, useRef, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import cytoscape from 'cytoscape';
import coseBilkent from 'cytoscape-cose-bilkent';
import dagre from 'cytoscape-dagre';
import { buildCytoscapeStyle, LAYOUT_COSE } from './utils/cytoscapeConfig';
import { isDegenerateLayout } from './utils/layoutHealth';
import { zoneBands } from './utils/zoneBands';
import { edgeBow } from './utils/edgeBow';
import { zonesLayout } from './utils/zonesLayout';
import { peerSummary } from './utils/peerSummary';
import { ZONE_DEFS_NORMAL, ZONE_DEFS_CB } from './ZoneOverlay';
import ZoneOverlay from './ZoneOverlay';

cytoscape.use(coseBilkent);
cytoscape.use(dagre);

const NON_GRAPH = '.manual, .zone, .zone-label, .band-rule, .band-label';

const HUB_DEGREE = 3;

const READABLE_ZOOM = 0.75;

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
  onCyReady,
  layoutMode = 'zones',
  relayoutNonce = 0,
  zoneDeclarations,
  machinesWithoutLink,
}) {
  const { t } = useTranslation();
  const containerRef        = useRef(null);
  const cyRef               = useRef(null);
  const declarationsRef     = useRef(zoneDeclarations);
  const machinesWithoutLinkRef = useRef(machinesWithoutLink);
  const layoutModeRef       = useRef(layoutMode);
  useEffect(() => { declarationsRef.current = zoneDeclarations; }, [zoneDeclarations]);
  useEffect(() => { machinesWithoutLinkRef.current = machinesWithoutLink; }, [machinesWithoutLink]);
  useEffect(() => { layoutModeRef.current = layoutMode; }, [layoutMode]);
  const placingAssetRef     = useRef(placingAsset);
  const onAssetPlacedRef    = useRef(onAssetPlaced);
  const zonesRef            = useRef(zones);
  const colorblindModeRef   = useRef(colorblindMode);
  const savedPositionsRef   = useRef(savedPositions);
  const onPositionsSaveRef  = useRef(onPositionsSave);
  const dragSaveTimerRef    = useRef(null);
  useEffect(() => { placingAssetRef.current    = placingAsset;    }, [placingAsset]);
  useEffect(() => { onAssetPlacedRef.current   = onAssetPlaced;   }, [onAssetPlaced]);
  useEffect(() => { zonesRef.current           = zones;           }, [zones]);
  useEffect(() => { colorblindModeRef.current  = colorblindMode;  }, [colorblindMode]);
  useEffect(() => { savedPositionsRef.current  = savedPositions;  }, [savedPositions]);
  useEffect(() => { onPositionsSaveRef.current = onPositionsSave; }, [onPositionsSave]);

  const hideNamedElsewhere = useCallback((cy) => {
    if (!cy) return;
    const named = new Set(machinesWithoutLinkRef.current || []);
    cy.batch(() => {
      cy.nodes().not(NON_GRAPH).forEach(n => n.toggleClass('band-hidden', named.has(n.id())));
    });
  }, []);

  const applyEdgeBowsRef = useRef(null);
  const applyEdgeBows = useCallback((cy) => {
    if (!cy) return;
    cy.batch(() => {
      cy.edges().forEach(e => {
        const s = e.source().position();
        const t = e.target().position();
        const bow = edgeBow(s.x, s.y, t.x, t.y);
        e.data('_cpd', bow.distances);
        e.data('_cpw', bow.weights);
      });
    });
  }, []);
  useEffect(() => { applyEdgeBowsRef.current = applyEdgeBows; }, [applyEdgeBows]);

  const refreshDerived = useCallback((cy) => {
    if (!cy) return;
    applyDisplayLabelsRef.current?.(cy);
    hideNamedElsewhere(cy);
    applyEdgeBows(cy);
  }, [hideNamedElsewhere, applyEdgeBows]);

  const applyDisplayLabelsRef = useRef(null);

  const applyDisplayLabels = useCallback((cy) => {
    if (!cy) return;

    const incident = new Map();
    cy.edges().forEach(e => {
      const d = { data: e.data() };
      for (const end of [e.data('source'), e.data('target')]) {
        if (!incident.has(end)) incident.set(end, []);
        incident.get(end).push(d);
      }
    });

    cy.batch(() => {
      cy.nodes().not(NON_GRAPH).forEach(n => {
        const s = peerSummary(n.id(), incident.get(n.id()) || []);
        const degree = (incident.get(n.id()) || []).length;
        const correlation = Number(n.data('correlationCount')) || 0;

        const network = degree > HUB_DEGREE
          ? `${t('networkMap.register.peers_count', { count: degree })} · ${t('networkMap.connections_count', { count: s.connections })}`
          : [
            s.ports.map(p => `:${p}`).join(' '),
            s.processes.join(', ') + (s.truncated ? ` +${s.truncated}` : ''),
            s.connections ? t('networkMap.graph.conn', { count: s.connections }) : '',
          ].filter(Boolean).join(' · ');

        const sub = [
          (s.connections || s.ports.length) ? network : '',
          correlation >= 2 ? t('networkMap.graph.correlated', { count: correlation }) : '',
        ].filter(Boolean).join(' · ');

        n.toggleClass('hub', degree > HUB_DEGREE);
        if (!sub) { n.removeData('_display'); return; }
        n.data('_display', `${n.data('label') || n.id()}\n${sub}`);
      });
    });
  }, [t]);
  useEffect(() => { applyDisplayLabelsRef.current = applyDisplayLabels; }, [applyDisplayLabels]);

  const applyBands = useCallback((cy) => {
    if (!cy) return;
    cy.remove(cy.nodes('.band-rule, .band-label'));

    const graphNodes = cy.nodes().not(NON_GRAPH);
    if (!graphNodes.length) return;

    const bands = zoneBands(graphNodes.map(n => ({ data: n.data() })), declarationsRef.current);
    if (!bands.length) return;

    let hub = null;
    let best = 1;
    graphNodes.forEach(n => { const d = n.degree(false); if (d > best) { best = d; hub = n.id(); } });

    const geo = zonesLayout(bands, { hub, omit: new Set(machinesWithoutLinkRef.current || []) });
    cy.batch(() => {
      graphNodes.forEach(n => n.toggleClass('band-hidden', !geo.positions[n.id()]));
      for (const [id, p] of Object.entries(geo.positions)) cy.$id(id).position(p);
    });

    const pad = 90;
    const height = Math.max(geo.bottom - geo.top, 1) + pad * 2;
    const midY = (geo.top + geo.bottom) / 2;
    const extra = [];
    geo.bands.forEach((b, i) => {
      if (i > 0) {
        const prev = geo.bands[i - 1];
        extra.push({
          data: { id: `band-rule-${b.zone}`, h: height },
          classes: 'band-rule',
          position: { x: (prev.x1 + b.x0) / 2, y: midY },
          grabbable: false, selectable: false,
        });
      }
      extra.push({
        data: { id: `band-label-${b.zone}`, label: t(`networkMap.band.zone_title_${b.zone}`) },
        classes: 'band-label',
        position: { x: b.x0 - 24, y: geo.top - 44 },
        grabbable: false, selectable: false,
      });
    });
    cy.add(extra);

    applyEdgeBows(cy);

    cy.fit(undefined, 60);
    if (cy.zoom() < READABLE_ZOOM) {
      cy.zoom({ level: READABLE_ZOOM, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
      const anchor = hub ? cy.$id(hub) : cy.nodes().not(NON_GRAPH).first();
      if (anchor && anchor.length) cy.center(anchor);
    }
  }, [t, applyEdgeBows]);

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

    cy.on('zoom', () => {
      const zoom_ = cy.zoom();
      (zonesRef.current || []).forEach(zone => {
        const n = cy.$id(`zone-label:${zone.id}`);
        if (!n.length) return;
        const label = n.data('label') || '';
        const lineCount = (label.match(/\n/g) || []).length + 1;
        const textHalfH = lineCount * 7;
        n.position({ x: zone.x + zone.w / 2, y: zone.y + (textHalfH + 8) / zoom_ });
      });
    });

    cy.on('dragfree', 'node:not(.manual, .zone, .zone-label)', () => {
      clearTimeout(dragSaveTimerRef.current);
      dragSaveTimerRef.current = setTimeout(() => {
        const positions = {};
        cy.nodes().not(NON_GRAPH).forEach(n => {
          positions[n.id()] = { x: n.position('x'), y: n.position('y') };
        });
        applyEdgeBowsRef.current?.(cy);
        onPositionsSaveRef.current?.(positions);
      }, 400);
    });

    return () => { cy.destroy(); cyRef.current = null; onCyReady?.(null); };
  }, []);

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

  const prevNodeIdsRef = useRef(new Set());

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    if (!elements?.length) {
      prevNodeIdsRef.current = new Set();
      cy.elements().not('.manual, .zone, .zone-label').remove();
      return;
    }

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
      refreshDerived(cy);
      return;
    }

    cy.batch(() => {
      cy.elements().not('.manual, .zone, .zone-label').remove();
      cy.add(elements);
    });

    const graphNodes = cy.nodes().not(NON_GRAPH);
    const saved = savedPositionsRef.current || {};
    const allSaved = graphNodes.length > 0 && graphNodes.every(n => saved[n.id()]);

    const restorable = allSaved
      ? Object.fromEntries(graphNodes.map(n => [n.id(), saved[n.id()]]))
      : null;

    applyDisplayLabels(cy);
    hideNamedElsewhere(cy);

    if (layoutModeRef.current === 'zones') {
      applyBands(cy);
      const positions = {};
      cy.nodes().not(NON_GRAPH).forEach(n => {
        positions[n.id()] = { x: n.position('x'), y: n.position('y') };
      });
      onPositionsSaveRef.current?.(positions);
      return;
    }

    if (restorable && !isDegenerateLayout(restorable)) {
      cy.batch(() => { graphNodes.forEach(n => n.position({ ...saved[n.id()] })); });
      applyEdgeBows(cy);
      cy.fit(undefined, 40);
    } else {
      const layout = cy.layout(LAYOUT_COSE);
      layout.one('layoutstop', () => {
        applyEdgeBows(cy);
        const positions = {};
        cy.nodes().not(NON_GRAPH).forEach(n => {
          positions[n.id()] = { x: n.position('x'), y: n.position('y') };
        });
        onPositionsSaveRef.current?.(positions);
      });
      layout.run();
    }
  }, [elements, applyDisplayLabels, applyBands, hideNamedElsewhere, applyEdgeBows, refreshDerived]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.style(buildCytoscapeStyle(nodeColorOverrides || {}, colorblindMode));
  }, [nodeColorOverrides, colorblindMode]);

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

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const nodes = manualNodes || [];

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
        el.lock();
      }

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

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const ZONE_DEFS = colorblindMode ? ZONE_DEFS_CB : ZONE_DEFS_NORMAL;
    const zoneList = zones || [];

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
      const lineCount  = (label.match(/\n/g) || []).length + 1;
      const textHalfH  = lineCount * 7;
      const labelPos   = { x: cx, y: zone.y + (textHalfH + 8) / cy.zoom() };

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

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const blocked = !!drawingZoneType || !!placingAsset;
    cy.userPanningEnabled(!blocked);
    cy.userZoomingEnabled(!blocked);
  }, [drawingZoneType, placingAsset]);

  const zoomIn  = useCallback(() => cyRef.current?.zoom({ level: cyRef.current.zoom() * 1.3, renderedPosition: { x: containerRef.current.offsetWidth / 2, y: containerRef.current.offsetHeight / 2 } }), []);
  const zoomOut = useCallback(() => cyRef.current?.zoom({ level: cyRef.current.zoom() / 1.3, renderedPosition: { x: containerRef.current.offsetWidth / 2, y: containerRef.current.offsetHeight / 2 } }), []);
  const fitAll  = useCallback(() => cyRef.current?.fit(undefined, 40), []);

  const runLayout = useCallback((mode) => {
    const cy = cyRef.current;
    if (!cy) return;
    const graphNodes = cy.nodes().not(NON_GRAPH);
    if (!graphNodes.length) return;

    if (mode === 'zones') {
      applyBands(cy);
      const positions = {};
      cy.nodes().not(NON_GRAPH).forEach(n => {
        positions[n.id()] = { x: n.position('x'), y: n.position('y') };
      });
      onPositionsSaveRef.current?.(positions);
      return;
    }

    const opts = { ...LAYOUT_COSE, animate: true, animationDuration: 450 };

    const eles = graphNodes.union(graphNodes.edgesWith(graphNodes));
    const layout = eles.layout(opts);
    layout.one('layoutstop', () => {
      cy.remove(cy.nodes('.band-rule, .band-label'));
      hideNamedElsewhere(cy);
      applyEdgeBows(cy);

      const positions = {};
      cy.nodes().not(NON_GRAPH).forEach(n => {
        positions[n.id()] = { x: n.position('x'), y: n.position('y') };
      });
      onPositionsSaveRef.current?.(positions);
    });
    layout.run();
  }, [applyBands, hideNamedElsewhere, applyEdgeBows]);

  const lastLayoutRef = useRef(null);
  useEffect(() => {
    const asked = `${layoutMode}|${relayoutNonce}`;
    if (lastLayoutRef.current === null) { lastLayoutRef.current = asked; return; }
    if (lastLayoutRef.current === asked) return;
    lastLayoutRef.current = asked;
    runLayout(layoutMode);
  }, [layoutMode, relayoutNonce, runLayout]);

  return (
    <div style={{ flex: 1, position: 'relative', background: '#0a0c11', overflow: 'hidden' }}>
      <div ref={containerRef} style={{ width: '100%', height: '100%', cursor: placingAsset ? 'crosshair' : 'default' }} />

      {(machinesWithoutLink || []).length > 0 && (
        <div style={{ position: 'absolute', top: 12, left: 14, zIndex: 5, pointerEvents: 'none', maxWidth: 240 }}>
          <div style={{ fontSize: 11, color: 'var(--fl-muted)', lineHeight: 1.5 }}>
            {t('networkMap.graph.without_link', { count: machinesWithoutLink.length })}
          </div>
          {machinesWithoutLink.map(name => (
            <div key={name} style={{ display: 'flex', alignItems: 'center', gap: 7, marginTop: 4 }}>
              <span style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--fl-border3)', flexShrink: 0 }} />
              <span style={{
                fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontSize: 10,
                color: 'var(--fl-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              }}>{name}</span>
            </div>
          ))}
        </div>
      )}

      <ZoneOverlay
        cyRef={cyRef}
        zones={zones ?? []}
        drawingZoneType={drawingZoneType}
        onZoneDrawn={onZoneDrawn}
        onZoneUpdate={onZoneUpdate}
        onZoneDelete={onZoneDelete}
        colorblindMode={colorblindMode}
      />

      <div style={{ position: 'absolute', bottom: 12, left: 12, display: 'flex', flexDirection: 'column', gap: 2, zIndex: 10 }}>
        {[
          { label: '+', title: 'Zoom in',  fn: zoomIn  },
          { label: '−', title: 'Zoom out', fn: zoomOut },
          { label: '⊡', title: 'Fit all',  fn: fitAll  },
        ].map(({ label, title, fn }) => (
          <button key={label} onClick={fn} title={title} style={{
            width: 26, height: 26, background: 'var(--fl-panel)', border: '1px solid var(--fl-border)',
            borderRadius: 3, color: 'var(--fl-muted)', cursor: 'pointer', fontSize: 13,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>{label}</button>
        ))}
      </div>
    </div>
  );
}
