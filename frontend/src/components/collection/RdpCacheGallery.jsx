import { useState, useEffect } from 'react';
import { collectionAPI } from '../../utils/api';
import { Monitor, X } from 'lucide-react';

const MONO = 'var(--f-mono, "JetBrains Mono", monospace)';

// Auth'd images can't be loaded via a plain <img src> (no Bearer header), so each
// tile is fetched as a blob through the api client and rendered from an object URL.
function RdpImg({ caseId, name, onClick, style }) {
  const [url, setUrl] = useState(null);
  useEffect(() => {
    let obj; let alive = true;
    collectionAPI.rdpCacheImage(caseId, name)
      .then(r => { if (alive) { obj = URL.createObjectURL(r.data); setUrl(obj); } })
      .catch(() => {});
    return () => { alive = false; if (obj) URL.revokeObjectURL(obj); };
  }, [caseId, name]);
  if (!url) return <div style={{ ...style, background: 'var(--fl-card)', border: '1px solid var(--fl-border2)' }} />;
  return <img src={url} alt={name} onClick={onClick}
    style={{ ...style, cursor: onClick ? 'zoom-in' : 'default', display: 'block', objectFit: 'cover' }} />;
}

export default function RdpCacheGallery({ caseId }) {
  const [images, setImages] = useState([]);
  const [lightbox, setLightbox] = useState(null);

  useEffect(() => {
    collectionAPI.rdpCacheList(caseId).then(r => setImages(r.data?.images || [])).catch(() => {});
  }, [caseId]);

  if (!images.length) return null;
  const collages = images.filter(n => /collage/i.test(n));
  const tiles = images.filter(n => !/collage/i.test(n));
  const shown = tiles.slice(0, 240);

  return (
    <div style={{ marginTop: 20, background: 'var(--fl-panel)', border: '1px solid var(--fl-border)', borderRadius: 8, overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 16px', borderBottom: '1px solid var(--fl-border2)' }}>
        <Monitor size={13} style={{ color: 'var(--fl-accent)' }} />
        <span style={{ fontSize: 11, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fl-dim)' }}>
          RDP Bitmap Cache - reconstructed sessions
        </span>
        <span style={{ flex: 1 }} />
        <span style={{ fontSize: 10.5, fontFamily: MONO, color: 'var(--fl-subtle)', fontFeatureSettings: '"tnum"' }}>
          {tiles.length.toLocaleString('en-US')} tiles
        </span>
      </div>

      <div style={{ padding: 16 }}>
        {collages.length > 0 && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 9.5, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-muted)', marginBottom: 8 }}>
              Collage (reconstructed screen)
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
              {collages.map(c => (
                <RdpImg key={c} caseId={caseId} name={c} onClick={() => setLightbox(c)}
                  style={{ maxWidth: '100%', maxHeight: 360, borderRadius: 6, border: '1px solid var(--fl-border)' }} />
              ))}
            </div>
          </div>
        )}

        {shown.length > 0 && (
          <>
            <div style={{ fontSize: 9.5, fontFamily: MONO, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fl-muted)', marginBottom: 8 }}>
              Tiles {tiles.length > shown.length ? `(${shown.length} of ${tiles.length})` : ''}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(64px, 1fr))', gap: 4 }}>
              {shown.map(n => (
                <RdpImg key={n} caseId={caseId} name={n} onClick={() => setLightbox(n)}
                  style={{ width: '100%', aspectRatio: '1', borderRadius: 3, border: '1px solid var(--fl-border2)' }} />
              ))}
            </div>
          </>
        )}
      </div>

      {lightbox && (
        <div onClick={() => setLightbox(null)} style={{ position: 'fixed', inset: 0, zIndex: 3000, background: 'rgba(0,0,0,0.85)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 32 }}>
          <button onClick={() => setLightbox(null)} style={{ position: 'absolute', top: 18, right: 18, background: 'var(--fl-card)', border: '1px solid var(--fl-border)', borderRadius: 6, color: 'var(--fl-dim)', cursor: 'pointer', padding: 8, display: 'inline-flex' }}>
            <X size={16} />
          </button>
          <RdpImg caseId={caseId} name={lightbox} style={{ maxWidth: '92vw', maxHeight: '88vh', borderRadius: 6, objectFit: 'contain' }} />
        </div>
      )}
    </div>
  );
}
