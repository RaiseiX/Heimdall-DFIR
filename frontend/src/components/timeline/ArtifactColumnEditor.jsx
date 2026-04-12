
import { useState, useEffect } from 'react';
import { X, ChevronUp, ChevronDown, RotateCcw, Check, Eye, EyeOff } from 'lucide-react';
import { ARTIFACT_ALL_FIELDS, ARTIFACT_PROFILES } from '../../utils/artifactProfiles';
import { getColumnPref, setColumnPref, resetColumnPref } from '../../utils/columnPreferences';

export default function ArtifactColumnEditor({ artifactType, open, onClose, onApply }) {
  const [activeItems, setActiveItems]     = useState([]);
  const [availableItems, setAvailableItems] = useState([]);

  useEffect(() => {
    if (!open || !artifactType) return;

    const allFields      = ARTIFACT_ALL_FIELDS[artifactType] || [];
    const defaultVirtual = ARTIFACT_PROFILES[artifactType]?.virtual || [];
    const currentVirtual = getColumnPref(artifactType) || defaultVirtual;

    const activeKeys = new Set(currentVirtual.map(f => f.key));

    setActiveItems(currentVirtual.filter(f => allFields.some(af => af.key === f.key)));

    setAvailableItems(allFields.filter(f => !activeKeys.has(f.key)));
  }, [open, artifactType]);

  const toggleToActive = (item) => {
    setAvailableItems(prev => prev.filter(f => f.key !== item.key));
    setActiveItems(prev => [...prev, item]);
  };

  const toggleToAvailable = (item) => {
    setActiveItems(prev => prev.filter(f => f.key !== item.key));
    setAvailableItems(prev => [item, ...prev]);
  };

  const moveUp = (index) => {
    if (index === 0) return;
    setActiveItems(prev => {
      const next = [...prev];
      [next[index - 1], next[index]] = [next[index], next[index - 1]];
      return next;
    });
  };

  const moveDown = (index) => {
    setActiveItems(prev => {
      if (index === prev.length - 1) return prev;
      const next = [...prev];
      [next[index], next[index + 1]] = [next[index + 1], next[index]];
      return next;
    });
  };

  const handleReset = () => {
    resetColumnPref(artifactType);
    const allFields      = ARTIFACT_ALL_FIELDS[artifactType] || [];
    const defaultVirtual = ARTIFACT_PROFILES[artifactType]?.virtual || [];
    const activeKeys     = new Set(defaultVirtual.map(f => f.key));
    setActiveItems(defaultVirtual.filter(f => allFields.some(af => af.key === f.key)));
    setAvailableItems(allFields.filter(f => !activeKeys.has(f.key)));
  };

  const handleApply = () => {
    setColumnPref(artifactType, activeItems);
    onApply(activeItems);
    onClose();
  };

  if (!open) return null;

  const BADGE = {
    background: 'var(--fl-card)',
    color: 'var(--fl-accent)',
    border: '1px solid #4d82c040',
    borderRadius: 4,
    fontFamily: 'monospace',
    fontSize: 9,
    padding: '1px 5px',
    flexShrink: 0,
  };

  return (
    <>
      
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.35)', zIndex: 999,
        }}
      />

      <div style={{
        position: 'fixed', top: 0, right: 0, bottom: 0, width: 360,
        background: 'var(--fl-bg)', borderLeft: '1px solid var(--fl-panel)',
        zIndex: 1000, display: 'flex', flexDirection: 'column',
        boxShadow: '-12px 0 40px rgba(0,0,0,0.6)',
      }}>

        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '12px 16px', borderBottom: '1px solid var(--fl-panel)',
          background: 'var(--fl-panel)', flexShrink: 0,
        }}>
          <div>
            <div style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 700, color: 'var(--fl-text)' }}>
              Colonnes — <span style={{ color: 'var(--fl-accent)' }}>{artifactType}</span>
            </div>
            <div style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-muted)', marginTop: 2 }}>
              Choisissez les champs du premier plan
            </div>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fl-dim)', padding: 4 }}
          >
            <X size={15} />
          </button>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: '14px 16px' }}>

          <div style={{ marginBottom: 18 }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8,
              fontFamily: 'monospace', fontSize: 10, fontWeight: 700,
              color: 'var(--fl-accent)', textTransform: 'uppercase', letterSpacing: '0.08em',
            }}>
              <Eye size={11} />
              Premier plan
              <span style={{ ...BADGE, marginLeft: 2 }}>{activeItems.length}</span>
            </div>

            {activeItems.length === 0 && (
              <div style={{
                padding: '14px', textAlign: 'center', fontFamily: 'monospace', fontSize: 10,
                color: 'var(--fl-muted)', border: '1px dashed var(--fl-card)', borderRadius: 6,
              }}>
                Aucun champ actif — cliquez sur un champ ci-dessous
              </div>
            )}

            {activeItems.map((item, idx) => (
              <div key={item.key} style={{
                display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4,
                padding: '6px 8px 6px 10px', background: 'var(--fl-bg)',
                borderRadius: 5, border: '1px solid var(--fl-card)',
              }}>
                
                <span style={{
                  fontFamily: 'monospace', fontSize: 9, color: 'var(--fl-muted)',
                  width: 14, textAlign: 'right', flexShrink: 0,
                }}>
                  {idx + 1}
                </span>

                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {item.label}
                  </div>
                  <div style={{ fontFamily: 'monospace', fontSize: 9, color: 'var(--fl-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {item.key}
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 1, flexShrink: 0 }}>
                  <button
                    onClick={() => moveUp(idx)}
                    disabled={idx === 0}
                    title="Monter"
                    style={{
                      background: 'none', border: 'none', padding: '2px 3px', cursor: idx === 0 ? 'default' : 'pointer',
                      color: idx === 0 ? 'var(--fl-card)' : 'var(--fl-accent)', borderRadius: 3,
                    }}
                  >
                    <ChevronUp size={12} />
                  </button>
                  <button
                    onClick={() => moveDown(idx)}
                    disabled={idx === activeItems.length - 1}
                    title="Descendre"
                    style={{
                      background: 'none', border: 'none', padding: '2px 3px',
                      cursor: idx === activeItems.length - 1 ? 'default' : 'pointer',
                      color: idx === activeItems.length - 1 ? 'var(--fl-card)' : 'var(--fl-accent)', borderRadius: 3,
                    }}
                  >
                    <ChevronDown size={12} />
                  </button>
                  <button
                    onClick={() => toggleToAvailable(item)}
                    title="Déplacer en second plan"
                    style={{
                      background: 'none', border: 'none', padding: '2px 4px',
                      cursor: 'pointer', color: 'var(--fl-subtle)', borderRadius: 3,
                    }}
                  >
                    <EyeOff size={11} />
                  </button>
                </div>
              </div>
            ))}
          </div>

          <div style={{ borderTop: '1px solid var(--fl-sep)', marginBottom: 14 }} />

          <div>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8,
              fontFamily: 'monospace', fontSize: 10, fontWeight: 700,
              color: 'var(--fl-subtle)', textTransform: 'uppercase', letterSpacing: '0.08em',
            }}>
              <EyeOff size={11} />
              Second plan
              <span style={{ ...BADGE, color: 'var(--fl-muted)', background: 'var(--fl-bg)', borderColor: 'var(--fl-sep)', marginLeft: 2 }}>
                {availableItems.length}
              </span>
            </div>

            {availableItems.length === 0 && (
              <div style={{
                padding: '14px', textAlign: 'center', fontFamily: 'monospace', fontSize: 10, color: 'var(--fl-muted)',
              }}>
                Tous les champs sont en premier plan
              </div>
            )}

            {availableItems.map((item) => (
              <div
                key={item.key}
                onClick={() => toggleToActive(item)}
                title="Ajouter au premier plan"
                style={{
                  display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4,
                  padding: '6px 8px 6px 10px', background: '#090d13',
                  borderRadius: 5, border: '1px solid #0f1921',
                  cursor: 'pointer', transition: 'border-color 0.15s',
                }}
                onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--fl-card)'}
                onMouseLeave={e => e.currentTarget.style.borderColor = '#0f1921'}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--fl-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {item.label}
                  </div>
                  <div style={{ fontFamily: 'monospace', fontSize: 9, color: '#1e2d3d', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {item.key}
                  </div>
                </div>
                <Eye size={11} style={{ color: 'var(--fl-muted)', flexShrink: 0 }} />
              </div>
            ))}
          </div>
        </div>

        <div style={{
          display: 'flex', gap: 8, padding: '12px 16px',
          borderTop: '1px solid var(--fl-panel)', background: 'var(--fl-panel)', flexShrink: 0,
        }}>
          <button
            onClick={handleReset}
            style={{
              display: 'flex', alignItems: 'center', gap: 5, padding: '6px 12px',
              background: 'none', border: '1px solid var(--fl-border)', borderRadius: 5,
              cursor: 'pointer', color: 'var(--fl-dim)', fontFamily: 'monospace', fontSize: 11,
            }}
          >
            <RotateCcw size={11} /> Réinitialiser
          </button>
          <button
            onClick={handleApply}
            style={{
              flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
              padding: '6px 12px', background: '#1f6feb', border: '1px solid #388bfd40',
              borderRadius: 5, cursor: 'pointer', color: '#ffffff',
              fontFamily: 'monospace', fontSize: 11, fontWeight: 700,
            }}
          >
            <Check size={12} /> Appliquer
          </button>
        </div>
      </div>
    </>
  );
}
