import { useState, useCallback } from 'react';

export function useResizable(storageKey, defaults = { width: 480, height: 600 }) {
  const [size, setSize] = useState(() => {
    try {
      const saved = localStorage.getItem(storageKey);
      return saved ? JSON.parse(saved) : defaults;
    } catch {
      return defaults;
    }
  });
  const [isFullscreen, setIsFullscreen] = useState(false);

  const saveSize = useCallback((newSize) => {
    const clamped = {
      width:  Math.min(Math.max(newSize.width,  380), window.innerWidth  * 0.95),
      height: Math.min(Math.max(newSize.height, 500), window.innerHeight * 0.95),
    };
    setSize(clamped);
    try { localStorage.setItem(storageKey, JSON.stringify(clamped)); } catch {}
  }, [storageKey]);

  const toggleFullscreen = useCallback(() => {
    setIsFullscreen(prev => !prev);
  }, []);

  const getResizeHandleProps = useCallback((direction) => ({
    onMouseDown: (e) => {
      e.preventDefault();
      const startX = e.clientX;
      const startY = e.clientY;
      const startW = size.width;
      const startH = size.height;

      const onMouseMove = (ev) => {
        const newSize = { ...size };
        if (direction === 'left' || direction === 'both') {
          newSize.width = startW - (ev.clientX - startX);
        }
        if (direction === 'top' || direction === 'both') {
          newSize.height = startH - (ev.clientY - startY);
        }
        saveSize(newSize);
      };

      const onMouseUp = () => {
        document.removeEventListener('mousemove', onMouseMove);
        document.removeEventListener('mouseup', onMouseUp);
      };

      document.addEventListener('mousemove', onMouseMove);
      document.addEventListener('mouseup', onMouseUp);
    },
  }), [size, saveSize]);

  return { size, isFullscreen, toggleFullscreen, getResizeHandleProps };
}
