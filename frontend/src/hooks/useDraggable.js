import { useState, useCallback, useRef } from 'react';

export function useDraggable(storageKey, defaults = { x: null, y: null }) {
  const [position, setPosition] = useState(() => {
    try {
      const saved = localStorage.getItem(storageKey);
      if (saved) return JSON.parse(saved);
    } catch  }
    return defaults;
  });

  const dragging = useRef(false);

  const clamp = (pos, w, h) => {
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    return {
      x: Math.min(Math.max(pos.x, 0), vw - (w || 300)),
      y: Math.min(Math.max(pos.y, 0), vh - (h || 200)),
    };
  };

  const savePosition = useCallback((pos, w, h) => {
    const clamped = clamp(pos, w, h);
    setPosition(clamped);
    try { localStorage.setItem(storageKey, JSON.stringify(clamped)); } catch {}
  }, [storageKey]);

  const getDragHandleProps = useCallback((width, height) => ({
    onMouseDown: (e) => {
      if (e.target.closest('button, input, select, textarea')) return;
      e.preventDefault();

      dragging.current = true;

      let startX = e.clientX;
      let startY = e.clientY;
      let startLeft, startTop;

      setPosition(prev => {
        if (prev && prev.x !== null) {
          startLeft = prev.x;
          startTop  = prev.y;
        } else {
          startLeft = window.innerWidth  - (width  || 520) - 24;
          startTop  = window.innerHeight - (height || 640) - 24;
        }
        return prev;
      });

      const onMouseMove = (ev) => {
        if (!dragging.current) return;
        const newPos = {
          x: startLeft + (ev.clientX - startX),
          y: startTop  + (ev.clientY - startY),
        };
        savePosition(newPos, width, height);
      };

      const onMouseUp = () => {
        dragging.current = false;
        document.removeEventListener('mousemove', onMouseMove);
        document.removeEventListener('mouseup', onMouseUp);
        document.body.style.userSelect = '';
        document.body.style.cursor = '';
      };

      document.body.style.userSelect = 'none';
      document.body.style.cursor = 'grabbing';
      document.addEventListener('mousemove', onMouseMove);
      document.addEventListener('mouseup', onMouseUp);
    },
    style: { cursor: 'grab' },
  }), [savePosition]);

  return { position, getDragHandleProps };
}
