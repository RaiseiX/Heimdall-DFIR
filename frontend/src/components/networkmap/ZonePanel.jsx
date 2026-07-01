import { useState } from 'react';
import { NODE_TYPES, NODE_COLORS_CB } from '../../constants/nodeTypes';
import { ZONE_DEFS_NORMAL, ZONE_DEFS_CB } from './ZoneOverlay';

const TABS = [
  { key: 'zones',    label: 'ZONES'    },
  { key: 'assets',   label: 'ASSETS'   },
  { key: 'regles',   label: 'RULES'   },
  { key: 'couleurs', label: 'COLORS' },
];

export default function ZonePanel({
  zones, drawingZoneType, onStartDraw, onCancelDraw, onDeleteZone, onZoneUpdate,
  colorblindMode, onToggleColorblind,
  nodeColorOverrides, onNodeColorChange, onNodeColorReset,
  placingAsset, onStartPlace, onCancelPlace,
  subnetRules = [], onSubnetRuleAdd, onSubnetRuleDelete,
}) {
  const [tab, setTab] = useState('zones');
  const [rCidr,  setRCidr]  = useState('');
  const [rLabel, setRLabel] = useState('');
  const [rColor, setRColor] = useState('var(--fl-purple)');

  function handleAddRule() {
    const cidr = rCidr.trim();
    if (!cidr || !rLabel.trim()) return;
    onSubnetRuleAdd?.({ id: `sr-${Date.now()}`, cidr, label: rLabel.trim(), color: rColor });
    setRCidr(''); setRLabel(''); setRColor('var(--fl-purple)');
  }

  // ── ASSETS tab local state ──
  const [assetTypeId,       setAssetTypeId]       = useState('server');
  const [assetLabel,        setAssetLabel]         = useState('');
  const [assetColorOverride, setAssetColorOverride] = useState(null); // null = use type default

  const ZONE_DEFS = Object.entries(colorblindMode ? ZONE_DEFS_CB : ZONE_DEFS_NORMAL)
    .map(([type, def]) => ({ type, ...def }));
  const nodeTypes = Object.values(NODE_TYPES);

  // Effective color for the asset being configured: instance override > CB > type default
  const typeDefaultColor = (colorblindMode ? NODE_COLORS_CB[assetTypeId] : null)
    || nodeColorOverrides?.[assetTypeId]
    || NODE_TYPES[assetTypeId]?.color
    || 'var(--fl-purple)';
  const assetDisplayColor = assetColorOverride || typeDefaultColor;

  function handleTypeChange(typeId) {
    setAssetTypeId(typeId);
    setAssetColorOverride(null); // reset instance color when type changes
  }

  function handlePlace() {
    onStartPlace?.({
      typeId: assetTypeId,
      label: assetLabel.trim(),
      colorOverride: assetColorOverride,
    });
  }

  return (
    <div style={{
      width: 224, flexShrink: 0,
      background: 'var(--fl-panel)',
      borderRight: '1px solid var(--fl-border)',
      display: 'flex', flexDirection: 'column',
      overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{ padding: '11px 13px 0', borderBottom: '1px solid var(--fl-border)', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 9 }}>
          <div style={{ fontSize: 9.5, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.14em', fontWeight: 600 }}>
            Network map
          </div>
          <button
            onClick={onToggleColorblind}
            title={colorblindMode ? 'Disable color-blind mode' : 'Enable color-blind palette (Wong 2011)'}
            style={{
              background: colorblindMode ? '#0072B218' : 'none',
              border: `1px solid ${colorblindMode ? '#0072B240' : 'var(--fl-border)'}`,
              borderRadius: 4, color: colorblindMode ? '#56B4E9' : 'var(--fl-muted)',
              fontSize: 11, cursor: 'pointer', padding: '3px 7px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', lineHeight: 1,
            }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = '#0072B260'; e.currentTarget.style.color = '#56B4E9'; }}
            onMouseLeave={e => {
              e.currentTarget.style.borderColor = colorblindMode ? '#0072B240' : 'var(--fl-border)';
              e.currentTarget.style.color = colorblindMode ? '#56B4E9' : 'var(--fl-muted)';
            }}
          >◑</button>
        </div>
        {/* Sub-tabs */}
        <div style={{ display: 'flex', gap: 2 }}>
          {TABS.map(t => (
            <button key={t.key} onClick={() => setTab(t.key)} style={{
              flex: 1, padding: '6px 2px', background: 'none', border: 'none',
              borderBottom: tab === t.key ? '2px solid var(--fl-accent)' : '2px solid transparent',
              color: tab === t.key ? 'var(--fl-text)' : 'var(--fl-muted)',
              fontSize: 9.5, fontWeight: tab === t.key ? 600 : 400,
              fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer', letterSpacing: '0.04em',
              transition: 'color 0.15s',
            }}>{t.label}</button>
          ))}
        </div>
      </div>

      {/* ── ZONES tab ── */}
      {tab === 'zones' && (
        <div style={{ flex: 1, overflowY: 'auto', padding: '10px 11px', display: 'flex', flexDirection: 'column', gap: 9 }}>

          {/* Draw buttons — one per type */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            {ZONE_DEFS.map(def => {
              const isDrawing = drawingZoneType === def.type;
              return (
                <div key={def.type} style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                  <div style={{ width: 9, height: 9, borderRadius: 2, background: def.color, flexShrink: 0 }} />
                  {isDrawing ? (
                    <button onClick={onCancelDraw} style={{ flex: 1, padding: '6px 8px', borderRadius: 5, background: 'var(--fl-raised)', border: '1px solid var(--fl-border3)', color: 'var(--fl-dim)', fontSize: 10.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer' }}>
                      Cancel
                    </button>
                  ) : (
                    <button
                      onClick={() => onStartDraw(def.type)}
                      style={{ flex: 1, textAlign: 'left', padding: '6px 8px', borderRadius: 5, background: `color-mix(in srgb, ${def.color} 7%, transparent)`, border: `1px solid color-mix(in srgb, ${def.color} 19%, transparent)`, color: def.color, fontSize: 10.5, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer', transition: 'background 0.15s' }}
                      onMouseEnter={e => { e.currentTarget.style.background = `color-mix(in srgb, ${def.color} 13%, transparent)`; }}
                      onMouseLeave={e => { e.currentTarget.style.background = `color-mix(in srgb, ${def.color} 7%, transparent)`; }}
                    >✛ {def.label}</button>
                  )}
                </div>
              );
            })}
          </div>

          {/* Drawn zones — one card per instance */}
          {zones.length > 0 && (
            <div style={{ borderTop: '1px solid var(--fl-border)', paddingTop: 9, display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div style={{ fontSize: 9, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 2, fontWeight: 600 }}>
                {zones.length} zone{zones.length > 1 ? 's' : ''} drawn{zones.length > 1 ? 's' : ''}
              </div>
              {zones.map(zone => {
                const def = ZONE_DEFS.find(d => d.type === zone.type);
                if (!def) return null;
                return (
                  <div key={zone.id} style={{ borderRadius: 3, border: `1px solid color-mix(in srgb, ${def.color} 19%, transparent)`, background: '#0a0f18', padding: '5px 7px' }}>
                    {/* Header: type badge + delete + redraw */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 4 }}>
                      <div style={{ width: 8, height: 8, borderRadius: 2, background: def.color, flexShrink: 0 }} />
                      <span style={{ fontSize: 10, color: def.color, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', flex: 1 }}>{def.label}</span>
                      <button
                        title="Redraw (resize)"
                        onClick={() => { onDeleteZone(zone.id); onStartDraw(zone.type); }}
                        style={{ background: 'none', border: 'none', color: 'var(--fl-muted)', fontSize: 9, cursor: 'pointer', padding: '1px 3px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}
                        onMouseEnter={e => { e.currentTarget.style.color = def.color; }}
                        onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; }}
                      >↺</button>
                      <button
                        title="Delete"
                        onClick={() => onDeleteZone(zone.id)}
                        style={{ background: 'none', border: 'none', color: 'var(--fl-muted)', fontSize: 9, cursor: 'pointer', padding: '1px 3px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}
                        onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-danger)'; }}
                        onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; }}
                      >✕</button>
                    </div>
                    {/* Description */}
                    <textarea
                      value={zone.description || ''}
                      onChange={e => onZoneUpdate?.(zone.id, { description: e.target.value })}
                      placeholder="Zone description…"
                      rows={2}
                      style={{
                        width: '100%', background: 'var(--fl-bg)', border: `1px solid color-mix(in srgb, ${def.color} 13%, transparent)`,
                        borderRadius: 2, color: 'var(--fl-dim)', fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                        padding: '3px 5px', outline: 'none', resize: 'none', boxSizing: 'border-box',
                        lineHeight: 1.4,
                      }}
                    />
                  </div>
                );
              })}
            </div>
          )}
          {colorblindMode && (
            <div style={{ marginTop: 4, padding: '4px 6px', fontSize: 9, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', borderTop: '1px solid var(--fl-card)', lineHeight: 1.4 }}>
              Wong palette (2011)
            </div>
          )}
        </div>
      )}

      {/* ── ASSETS tab ── */}
      {tab === 'assets' && (
        <div style={{ flex: 1, overflowY: 'auto', padding: '8px 8px', display: 'flex', flexDirection: 'column', gap: 8 }}>

          {/* Type selector */}
          <div>
            <div style={{ fontSize: 9, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>Type</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <div style={{ width: 10, height: 10, borderRadius: 2, background: typeDefaultColor, flexShrink: 0 }} />
              <select
                value={assetTypeId}
                onChange={e => handleTypeChange(e.target.value)}
                style={{
                  flex: 1, background: 'var(--fl-card)', border: '1px solid var(--fl-raised)',
                  borderRadius: 3, color: 'var(--fl-dim)', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                  padding: '2px 4px', cursor: 'pointer', outline: 'none',
                }}
              >
                {nodeTypes.map(t => (
                  <option key={t.id} value={t.id} style={{ background: 'var(--fl-bg)', color: 'var(--fl-dim)' }}>
                    {t.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Label input */}
          <div>
            <div style={{ fontSize: 9, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>Label</div>
            <input
              type="text"
              value={assetLabel}
              onChange={e => setAssetLabel(e.target.value)}
              placeholder={NODE_TYPES[assetTypeId]?.label || assetTypeId}
              style={{
                width: '100%', background: 'var(--fl-card)', border: '1px solid var(--fl-raised)',
                borderRadius: 3, color: 'var(--fl-dim)', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)',
                padding: '3px 5px', outline: 'none', boxSizing: 'border-box',
              }}
            />
          </div>

          {/* Instance color */}
          <div>
            <div style={{ fontSize: 9, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>
              Instance color
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <label style={{ position: 'relative', cursor: 'pointer', flexShrink: 0 }}>
                <div style={{ width: 18, height: 18, borderRadius: 3, background: assetDisplayColor, border: `2px solid color-mix(in srgb, ${assetDisplayColor} 50%, transparent)` }} />
                <input
                  type="color"
                  value={assetDisplayColor}
                  onChange={e => setAssetColorOverride(e.target.value)}
                  style={{ position: 'absolute', opacity: 0, width: 0, height: 0, top: 0, left: 0 }}
                />
              </label>
              <span style={{ fontSize: 10, color: assetDisplayColor, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', flex: 1 }}>
                {assetDisplayColor}
              </span>
              {assetColorOverride && (
                <button
                  onClick={() => setAssetColorOverride(null)}
                  title="Use the type default color"
                  style={{ background: 'none', border: 'none', color: 'var(--fl-muted)', fontSize: 9, cursor: 'pointer', padding: '0 2px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}
                  onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-danger)'; }}
                  onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; }}
                >↺</button>
              )}
            </div>
            {!assetColorOverride && (
              <div style={{ fontSize: 9, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', marginTop: 2 }}>
                Type default color
              </div>
            )}
          </div>

          {/* Place / Cancel */}
          <div style={{ marginTop: 4 }}>
            {placingAsset ? (
              <>
                <div style={{ fontSize: 9, color: 'var(--fl-purple)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', marginBottom: 6, lineHeight: 1.5 }}>
                  ✛ Click on the map to place
                </div>
                <button
                  onClick={onCancelPlace}
                  style={{ width: '100%', padding: '4px', borderRadius: 3, background: 'var(--fl-raised)', border: '1px solid var(--fl-subtle)', color: 'var(--fl-muted)', fontSize: 9, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer' }}
                >
                  Cancel
                </button>
              </>
            ) : (
              <button
                onClick={handlePlace}
                style={{ width: '100%', padding: '5px', borderRadius: 3, background: `color-mix(in srgb, ${assetDisplayColor} 8%, transparent)`, border: `1px solid color-mix(in srgb, ${assetDisplayColor} 25%, transparent)`, color: assetDisplayColor, fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: 'pointer' }}
                onMouseEnter={e => { e.currentTarget.style.background = `color-mix(in srgb, ${assetDisplayColor} 15%, transparent)`; }}
                onMouseLeave={e => { e.currentTarget.style.background = `color-mix(in srgb, ${assetDisplayColor} 8%, transparent)`; }}
              >
                ✛ Place on the map
              </button>
            )}
          </div>
        </div>
      )}

      {/* ── RULES tab ── */}
      {tab === 'regles' && (
        <div style={{ flex: 1, overflowY: 'auto', padding: '8px 8px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ fontSize: 9, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', lineHeight: 1.5 }}>
            Associate a network segment with a CIDR. Nodes in the range display a badge.
          </div>

          {/* Add form */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            <input
              type="text" value={rCidr} onChange={e => setRCidr(e.target.value)}
              placeholder="CIDR (ex: 192.168.1.0/24)"
              style={{ width: '100%', background: 'var(--fl-card)', border: '1px solid var(--fl-raised)', borderRadius: 3, color: 'var(--fl-dim)', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '3px 5px', outline: 'none', boxSizing: 'border-box' }}
            />
            <input
              type="text" value={rLabel} onChange={e => setRLabel(e.target.value)}
              placeholder="Nom du segment (ex: Serveurs)"
              style={{ width: '100%', background: 'var(--fl-card)', border: '1px solid var(--fl-raised)', borderRadius: 3, color: 'var(--fl-dim)', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', padding: '3px 5px', outline: 'none', boxSizing: 'border-box' }}
            />
            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <label style={{ position: 'relative', cursor: 'pointer', flexShrink: 0 }}>
                <div style={{ width: 18, height: 18, borderRadius: 3, background: rColor, border: `2px solid color-mix(in srgb, ${rColor} 50%, transparent)` }} />
                <input type="color" value={rColor} onChange={e => setRColor(e.target.value)} style={{ position: 'absolute', opacity: 0, width: 0, height: 0 }} />
              </label>
              <button
                onClick={handleAddRule}
                disabled={!rCidr.trim() || !rLabel.trim()}
                style={{ flex: 1, padding: '4px', borderRadius: 3, background: rCidr.trim() && rLabel.trim() ? `color-mix(in srgb, ${rColor} 13%, transparent)` : 'var(--fl-card)', border: `1px solid ${rCidr.trim() && rLabel.trim() ? rColor + '50' : 'var(--fl-raised)'}`, color: rCidr.trim() && rLabel.trim() ? rColor : 'var(--fl-muted)', fontSize: 10, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', cursor: rCidr.trim() && rLabel.trim() ? 'pointer' : 'default' }}
              >✛ Add</button>
            </div>
          </div>

          {/* Rule list */}
          {subnetRules.length > 0 && (
            <div style={{ borderTop: '1px solid var(--fl-card)', paddingTop: 6, display: 'flex', flexDirection: 'column', gap: 4 }}>
              {subnetRules.map(rule => (
                <div key={rule.id} style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '4px 6px', borderRadius: 3, background: '#0a0f18', border: `1px solid color-mix(in srgb, ${rule.color} 19%, transparent)` }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: rule.color, flexShrink: 0 }} />
                  <div style={{ flex: 1, overflow: 'hidden' }}>
                    <div style={{ fontSize: 10, color: rule.color, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', fontWeight: 700, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{rule.label}</div>
                    <div style={{ fontSize: 9, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}>{rule.cidr}</div>
                  </div>
                  <button
                    onClick={() => onSubnetRuleDelete?.(rule.id)}
                    style={{ background: 'none', border: 'none', color: 'var(--fl-muted)', fontSize: 9, cursor: 'pointer', padding: '1px 3px', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', flexShrink: 0 }}
                    onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-danger)'; }}
                    onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; }}
                  >✕</button>
                </div>
              ))}
            </div>
          )}
          {subnetRules.length === 0 && (
            <div style={{ fontSize: 9, color: 'var(--fl-subtle)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', textAlign: 'center', padding: '8px 0' }}>
              No rules defined
            </div>
          )}
        </div>
      )}

      {/* ── COLORS tab ── */}
      {tab === 'couleurs' && (
        <div style={{ flex: 1, overflowY: 'auto', padding: '6px 8px' }}>
          <div style={{ fontSize: 9, color: 'var(--fl-muted)', fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', marginBottom: 6, lineHeight: 1.5 }}>
            Click a color to edit.{'\n'}
            <span style={{ color: 'var(--fl-subtle)' }}>↺ to reset.</span>
          </div>
          {nodeTypes.map(type => {
            const cbColor  = colorblindMode ? (NODE_COLORS_CB[type.id] || type.color) : null;
            const override = nodeColorOverrides?.[type.id];
            const current  = override || cbColor || type.color;
            const isCustom = !!override;

            return (
              <div key={type.id} style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '3px 0', borderBottom: '1px solid var(--fl-panel)' }}>
                <label style={{ position: 'relative', cursor: 'pointer', flexShrink: 0 }}>
                  <div style={{ width: 14, height: 14, borderRadius: 2, background: current, border: `1px solid color-mix(in srgb, ${current} 50%, transparent)` }} />
                  <input
                    type="color"
                    value={current}
                    onChange={e => onNodeColorChange(type.id, e.target.value)}
                    style={{ position: 'absolute', opacity: 0, width: 0, height: 0, top: 0, left: 0 }}
                  />
                </label>
                <span style={{ fontSize: 10, color: current, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {type.label}
                </span>
                {isCustom && (
                  <button
                    onClick={() => onNodeColorReset(type.id)}
                    title="Reset color"
                    style={{ background: 'none', border: 'none', color: 'var(--fl-muted)', fontSize: 9, cursor: 'pointer', padding: '1px 2px', flexShrink: 0, fontFamily: 'var(--f-mono, "JetBrains Mono", monospace)' }}
                    onMouseEnter={e => { e.currentTarget.style.color = 'var(--fl-danger)'; }}
                    onMouseLeave={e => { e.currentTarget.style.color = 'var(--fl-muted)'; }}
                  >↺</button>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
