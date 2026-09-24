import { useRef, useState, useCallback } from 'react';

export const ZONE_CLES = {
  internet: 'networkMap.zone_internet',
  dmz:      'networkMap.zone_dmz',
  lan:      'networkMap.zone_lan',
  cloud:    'networkMap.zone_cloud',
};

export const ZONE_DEFS_NORMAL = {
  internet: { cle: ZONE_CLES.internet, color: 'var(--fl-danger)' },
  dmz:      { cle: ZONE_CLES.dmz,      color: 'var(--fl-warn)' },
  lan:      { cle: ZONE_CLES.lan,      color: 'var(--fl-purple)' },
  cloud:    { cle: ZONE_CLES.cloud,    color: 'var(--fl-purple)' },
};

export const ZONE_DEFS_CB = {
  internet: { cle: ZONE_CLES.internet, color: '#D55E00' },
  dmz:      { cle: ZONE_CLES.dmz,      color: '#E69F00' },
  lan:      { cle: ZONE_CLES.lan,      color: '#0072B2' },
  cloud:    { cle: ZONE_CLES.cloud,    color: '#56B4E9' },
};

export default function ZoneOverlay({ cyRef, zones, drawingZoneType, onZoneDrawn, onZoneUpdate, onZoneDelete, colorblindMode }) {
  const containerRef = useRef(null);
  const [drawing, setDrawing] = useState(null);

  const ZONE_DEFS = colorblindMode ? ZONE_DEFS_CB : ZONE_DEFS_NORMAL;

  const handleDrawMouseDown = useCallback(e => {
    if (!drawingZoneType) return;
    const rect = containerRef.current.getBoundingClientRect();
    const sx = e.clientX - rect.left;
    const sy = e.clientY - rect.top;
    setDrawing({ startSx: sx, startSy: sy, curSx: sx, curSy: sy });
  }, [drawingZoneType]);

  const handleDrawMouseMove = useCallback(e => {
    if (!drawing) return;
    const rect = containerRef.current.getBoundingClientRect();
    setDrawing(d => ({ ...d, curSx: e.clientX - rect.left, curSy: e.clientY - rect.top }));
  }, [drawing]);

  const handleDrawMouseUp = useCallback(() => {
    if (!drawing || !drawingZoneType) return;
    const cy = cyRef.current;
    if (!cy) { setDrawing(null); return; }

    const minSx = Math.min(drawing.startSx, drawing.curSx);
    const minSy = Math.min(drawing.startSy, drawing.curSy);
    const wSx   = Math.abs(drawing.curSx - drawing.startSx);
    const hSy   = Math.abs(drawing.curSy - drawing.startSy);
    if (wSx < 20 || hSy < 20) { setDrawing(null); return; }

    const zoom = cy.zoom();
    const pan  = cy.pan();
    const gx = (minSx - pan.x) / zoom;
    const gy = (minSy - pan.y) / zoom;
    const gw = wSx / zoom;
    const gh = hSy / zoom;

    onZoneDrawn({ id: crypto.randomUUID(), type: drawingZoneType, x: gx, y: gy, w: gw, h: gh });
    setDrawing(null);
  }, [drawing, drawingZoneType, cyRef, onZoneDrawn]);

  let drawRect = null;
  if (drawing) {
    drawRect = {
      left:   Math.min(drawing.startSx, drawing.curSx),
      top:    Math.min(drawing.startSy, drawing.curSy),
      width:  Math.abs(drawing.curSx - drawing.startSx),
      height: Math.abs(drawing.curSy - drawing.startSy),
    };
  }

  if (!drawingZoneType && !drawing) return null;

  return (
    <div ref={containerRef} style={{ position: 'absolute', inset: 0, pointerEvents: 'none', zIndex: 5 }}>
      {drawRect && (
        <div style={{
          position: 'absolute',
          left: drawRect.left, top: drawRect.top,
          width: drawRect.width, height: drawRect.height,
          border: `2px dashed ${ZONE_DEFS[drawingZoneType]?.color ?? '#fff'}`,
          borderRadius: 4,
          background: `color-mix(in srgb, ${ZONE_DEFS[drawingZoneType]?.color ?? '#fff'} 3%, transparent)`,
          pointerEvents: 'none',
          boxSizing: 'border-box',
        }} />
      )}

      <div
        style={{ position: 'absolute', inset: 0, cursor: 'crosshair', pointerEvents: 'all', zIndex: 10 }}
        onMouseDown={handleDrawMouseDown}
        onMouseMove={handleDrawMouseMove}
        onMouseUp={handleDrawMouseUp}
      />
    </div>
  );
}
